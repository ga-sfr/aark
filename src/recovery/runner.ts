import { randomUUID } from "node:crypto";
import { lstat, opendir, realpath } from "node:fs/promises";
import path from "node:path";
import { captureCommand, commandExists } from "../core/command.js";
import { acquireExclusiveLock, assertNoSymlinkComponents, atomicWriteFile, atomicWriteJson, ensurePrivateDirectory, nearestExistingParent, readDirectoryNamesBounded, readJson, safeJoin } from "../core/fs-safe.js";
import type { ExclusiveLock } from "../core/fs-safe.js";
import { filesystemEnforcesUnixModes, mountForPath, mountForPathFrom, mountIsNetworkBacked, mountIsReadOnly, mounts } from "../core/mounts.js";
import type { MountRecord } from "../core/mounts.js";
import type { JsonValue } from "../core/types.js";
import { assertStorageCapacity, directoryLogicalBytes, StorageQuotaError, storagePolicyFromGiB } from "../core/storage.js";
import type { RecoveryConfig, RecoveryPlan, RecoveryRunStatus, RecoveryStep } from "./types.js";
import { buildRecoveryPlan } from "./plan.js";
import { inspectSourceSafety, stableBlockDeviceKeys } from "./source-safety.js";
import type { SourceSafety } from "./source-safety.js";
import { renderRecoveryRedactedReport, renderRecoverySensitiveReport } from "./report.js";

const PHOTOREC_SWITCHES = new Set(["/log", "/logname", "/d", "/cmd"]);
const MAX_RECOVERY_OUTPUT_TREE_DEPTH = 256;
const RECOVERY_LOCK_FILENAME = ".aark-recovery.lock";
const LEGACY_RECOVERY_LOCK_FILENAME = ".agetnic-recovery.lock";
const RECOVERY_LOCK_FILENAMES = [RECOVERY_LOCK_FILENAME, LEGACY_RECOVERY_LOCK_FILENAME] as const;

class RecoveryQuotaStop extends Error {
  public override readonly name = "RecoveryQuotaStop";

  public constructor(public readonly resumable: boolean, cause: unknown) {
    super(resumable
      ? "recovery paused at the configured storage boundary; the ddrescue mapfile permits a safe retry"
      : "recovery stopped at the configured storage boundary; the interrupted engine is not guaranteed resumable", { cause });
  }
}

async function acquireRecoveryLocks(directory: string): Promise<ExclusiveLock[]> {
  const locks: ExclusiveLock[] = [];
  try {
    for (const filename of [...RECOVERY_LOCK_FILENAMES].sort()) {
      locks.push(await acquireExclusiveLock(directory, filename));
    }
    return locks;
  } catch (error) {
    const releaseErrors: unknown[] = [];
    for (const lock of [...locks].reverse()) {
      try { await lock.release(); } catch (releaseError) { releaseErrors.push(releaseError); }
    }
    if (releaseErrors.length > 0) {
      throw new AggregateError([error, ...releaseErrors], "recovery lock acquisition failed and acquired locks could not all be released");
    }
    throw error;
  }
}

async function releaseRecoveryLocks(locks: ExclusiveLock[]): Promise<void> {
  const errors: unknown[] = [];
  for (const lock of [...locks].reverse()) {
    try { await lock.release(); } catch (error) { errors.push(error); }
  }
  if (errors.length > 0) throw new AggregateError(errors, "recovery operation locks could not all be released");
}

function storageQuota(error: unknown): StorageQuotaError | undefined {
  let current: unknown = error;
  for (let depth = 0; depth < 8 && current !== undefined; depth += 1) {
    if (current instanceof StorageQuotaError) return current;
    current = current instanceof Error && "cause" in current ? current.cause : undefined;
  }
  return undefined;
}

function redactArg(arg: string, plan: RecoveryPlan): string {
  if (arg === plan.source) return "<SOURCE>";
  if (arg === plan.analysisSource) return "<ANALYSIS_SOURCE>";
  if (arg === plan.destination) return "<CASE_ROOT>";
  if (arg.startsWith(`${plan.destination}${path.sep}`)) return `<CASE_ROOT>/${path.relative(plan.destination, arg)}`;
  if (path.isAbsolute(arg) && !PHOTOREC_SWITCHES.has(arg)) return "<LOCAL_PATH>";
  return arg;
}

function redactedStep(step: RecoveryStep, plan: RecoveryPlan): Record<string, JsonValue> {
  return {
    id: step.id,
    title: step.title,
    executable: step.executable,
    args: step.args.map((arg) => redactArg(arg, plan)),
    stdoutFile: step.stdoutFile === undefined ? null : redactArg(step.stdoutFile, plan),
    outputs: step.outputs.map((output) => redactArg(output, plan)),
    provenance: step.provenance,
    sourceMutationExpected: false,
    destinationWritesExpected: step.destinationWritesExpected,
    optional: step.optional,
    partialSuccessExitCodes: step.partialSuccessExitCodes ?? [],
    notes: step.notes,
  };
}

export function redactedPlan(plan: RecoveryPlan): Record<string, JsonValue> {
  return {
    version: plan.version,
    caseId: "<CASE_ID>",
    source: "<SOURCE>",
    analysisSource: "<ANALYSIS_SOURCE>",
    destination: "<CASE_ROOT>",
    requireReadOnlySource: plan.requireReadOnlySource,
    storage: {
      minFreeGiB: plan.storage.minFreeGiB,
      minFreePercent: plan.storage.minFreePercent,
      maxOutputGiB: plan.storage.maxOutputGiB ?? null,
    },
    steps: plan.steps.map((step) => redactedStep(step, plan)),
    warnings: plan.warnings,
  };
}

function inside(root: string, candidate: string): boolean {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  return relative === "" || (relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

function sameStrings(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function sensitiveErrorDetail(error: unknown): string {
  const messages: string[] = [];
  let current: unknown = error;
  for (let depth = 0; depth < 5 && current !== undefined; depth += 1) {
    const message = current instanceof Error ? current.message : String(current);
    if (message !== "" && messages.at(-1) !== message) messages.push(message);
    current = current instanceof Error && "cause" in current ? current.cause : undefined;
  }
  return messages.join("; caused by: ") || "unknown failure";
}

function mountIdentity(record: MountRecord): string {
  return JSON.stringify({
    source: record.source,
    target: path.resolve(record.target),
    filesystem: record.filesystem.toLowerCase(),
    options: [...record.options].sort(),
  });
}

async function assertSourceSafetyCurrent(
  requested: string,
  destination: string,
  expected: Awaited<ReturnType<typeof inspectSourceSafety>>,
  requireReadOnly: boolean,
  label: string,
  allowDestinationResident = false,
): Promise<void> {
  const current = await inspectSourceSafety(requested, destination);
  if (
    current.kind !== expected.kind
    || current.resolvedSource !== expected.resolvedSource
    || current.bytes !== expected.bytes
    || !sameStrings(current.sourceTopDevices, expected.sourceTopDevices)
    || !sameStrings(current.destinationDevices, expected.destinationDevices)
    || JSON.stringify(current.sourceDeviceIdentities) !== JSON.stringify(expected.sourceDeviceIdentities)
    || JSON.stringify(current.destinationDeviceIdentities) !== JSON.stringify(expected.destinationDeviceIdentities)
    || current.destinationFilesystemDevice !== expected.destinationFilesystemDevice
    || current.destinationMountSource !== expected.destinationMountSource
    || current.destinationBackingKind !== expected.destinationBackingKind
    || current.destinationBackingKind === "network"
    || (current.destinationOnSourceDevice && !allowDestinationResident)
    || (current.kind === "block-device" && !current.deviceComparisonCertain)
    || (requireReadOnly && current.kind === "block-device" && (!current.kernelReadOnly || current.writableMounts.length > 0))
    || JSON.stringify(current.regularFileIdentity) !== JSON.stringify(expected.regularFileIdentity)
    || JSON.stringify(current.blockDeviceIdentity) !== JSON.stringify(expected.blockDeviceIdentity)
  ) throw new Error(`${label} or destination safety state changed after preflight`);
}

function destinationPaths(step: RecoveryStep, root: string): string[] {
  return [...new Set([
    ...step.createsDirectories,
    ...step.outputs,
    ...(step.stdoutFile === undefined ? [] : [step.stdoutFile]),
    ...step.args.filter((argument) => path.isAbsolute(argument) && inside(root, argument)),
  ].map((value) => path.resolve(value)))];
}

function expectedOutputKind(step: RecoveryStep, output: string): "file" | "directory" {
  return (step.stdoutFile !== undefined && output === path.resolve(step.stdoutFile)) || step.id.startsWith("image-") ? "file" : "directory";
}

async function directoryIsEmpty(directory: string): Promise<boolean> {
  const handle = await opendir(directory);
  try {
    return await handle.read() === null;
  } finally {
    await handle.close().catch(() => undefined);
  }
}

function matchesPlanWithDefaultStorage(stored: unknown, current: RecoveryPlan | Record<string, JsonValue>): boolean {
  if (JSON.stringify(stored) === JSON.stringify(current)) return true;
  const storage = "storage" in current ? current.storage : undefined;
  if (
    typeof storage !== "object"
    || storage === null
    || Array.isArray(storage)
    || (storage as Record<string, unknown>).minFreeGiB !== 5
    || (storage as Record<string, unknown>).minFreePercent !== 5
    || ((storage as Record<string, unknown>).maxOutputGiB !== undefined && (storage as Record<string, unknown>).maxOutputGiB !== null)
  ) return false;
  const legacy = { ...current } as Record<string, unknown>;
  delete legacy.storage;
  return JSON.stringify(stored) === JSON.stringify(legacy);
}

function matchesPlanIgnoringStorage(stored: unknown, current: RecoveryPlan | Record<string, JsonValue>): boolean {
  if (typeof stored !== "object" || stored === null || Array.isArray(stored)) return false;
  const storedWithoutStorage = { ...(stored as Record<string, unknown>) };
  const currentWithoutStorage = { ...current } as Record<string, unknown>;
  delete storedWithoutStorage.storage;
  delete currentWithoutStorage.storage;
  return JSON.stringify(storedWithoutStorage) === JSON.stringify(currentWithoutStorage);
}

type RecoveryOutputSnapshot =
  | { kind: "missing" }
  | { kind: "file"; device: number; inode: number; size: number; modifiedMs: number; changedMs: number }
  | { kind: "directory"; hasRegularFile: boolean }
  | { kind: "other" };

async function containsRegularFile(
  root: string,
  signal?: AbortSignal,
  ancestors = new Set<string>(),
  depth = 0,
): Promise<boolean> {
  if (signal?.aborted === true) throw new Error("recovery output verification was interrupted");
  if (depth > MAX_RECOVERY_OUTPUT_TREE_DEPTH) throw new Error("recovery output exceeds the bounded directory-depth limit");
  const currentMetadata = await lstat(root);
  if (currentMetadata.isSymbolicLink()) return false;
  if (currentMetadata.isFile()) return true;
  if (!currentMetadata.isDirectory()) return false;
  const key = `${currentMetadata.dev}:${currentMetadata.ino}`;
  if (ancestors.has(key)) throw new Error("recovery output contains a recursive directory identity");
  ancestors.add(key);
  try {
    const directory = await opendir(root);
    for await (const entry of directory) {
      if (Boolean(signal?.aborted)) throw new Error("recovery output verification was interrupted");
      if (await containsRegularFile(path.join(root, entry.name), signal, ancestors, depth + 1)) return true;
    }
    return false;
  } finally {
    ancestors.delete(key);
  }
}

async function recoveryOutputSnapshot(output: string, signal?: AbortSignal): Promise<RecoveryOutputSnapshot> {
  try {
    const metadata = await lstat(output);
    if (metadata.isFile()) {
      return { kind: "file", device: metadata.dev, inode: metadata.ino, size: metadata.size, modifiedMs: metadata.mtimeMs, changedMs: metadata.ctimeMs };
    }
    if (metadata.isDirectory()) return { kind: "directory", hasRegularFile: await containsRegularFile(output, signal) };
    return { kind: "other" };
  } catch (error) {
    const code = error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
    if (code === "ENOENT") return { kind: "missing" };
    throw error;
  }
}

async function snapshotRecoveryOutputs(step: RecoveryStep, signal?: AbortSignal): Promise<Map<string, RecoveryOutputSnapshot>> {
  const snapshots = new Map<string, RecoveryOutputSnapshot>();
  for (const output of new Set(step.outputs.map((value) => path.resolve(value)))) {
    snapshots.set(output, await recoveryOutputSnapshot(output, signal));
  }
  return snapshots;
}

async function stepProducedNewOutput(step: RecoveryStep, before: Map<string, RecoveryOutputSnapshot>, signal?: AbortSignal): Promise<boolean> {
  for (const output of new Set(step.outputs.map((value) => path.resolve(value)))) {
    const prior = before.get(output) ?? { kind: "missing" };
    const current = await recoveryOutputSnapshot(output, signal);
    if (current.kind === "file") {
      if (
        prior.kind !== "file"
        || prior.device !== current.device
        || prior.inode !== current.inode
        || prior.size !== current.size
        || prior.modifiedMs !== current.modifiedMs
        || prior.changedMs !== current.changedMs
      ) return true;
    }
    if (current.kind === "directory") {
      if (current.hasRegularFile && (prior.kind !== "directory" || !prior.hasRegularFile)) return true;
    }
  }
  return false;
}

export function recoveryStepStatus(
  step: RecoveryStep,
  exitCode: number,
  producedNewOutput: boolean,
): "completed" | "completed-with-warnings" | "failed" {
  if (exitCode === 0) return "completed";
  if (producedNewOutput && step.partialSuccessExitCodes?.includes(exitCode) === true) return "completed-with-warnings";
  return "failed";
}

async function assertStepOutputsSafe(
  step: RecoveryStep,
  sourceSafety: SourceSafety,
  analysisSafety: SourceSafety | undefined,
  requireExists: boolean,
  requireEmptyDirectories = false,
): Promise<void> {
  const seenFiles = new Map<string, string>();
  const protectedFiles = [sourceSafety.regularFileIdentity, analysisSafety?.regularFileIdentity]
    .filter((identity): identity is NonNullable<SourceSafety["regularFileIdentity"]> => identity !== null && identity !== undefined);
  for (const output of new Set(step.outputs.map((value) => path.resolve(value)))) {
    let metadata: Awaited<ReturnType<typeof lstat>>;
    try {
      metadata = await lstat(output);
    } catch (error) {
      const code = error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
      if (code === "ENOENT" && !requireExists) continue;
      if (code === "ENOENT") throw new Error(`recovery stage ${step.id} reported success without creating every planned output`);
      throw error;
    }
    if (metadata.isSymbolicLink()) throw new Error(`recovery stage ${step.id} output became a symbolic link`);
    const kind = expectedOutputKind(step, output);
    if (kind === "file" && !metadata.isFile()) throw new Error(`recovery stage ${step.id} requires a regular-file output`);
    if (kind === "directory" && !metadata.isDirectory()) throw new Error(`recovery stage ${step.id} requires a directory output`);
    if (kind === "directory" && requireEmptyDirectories && !(await directoryIsEmpty(output))) {
      throw new Error(`recovery stage ${step.id} directory output must be empty before execution`);
    }
    if (!metadata.isFile()) continue;
    if (metadata.nlink !== 1) throw new Error(`recovery stage ${step.id} file output must not have hard-link aliases`);
    if (protectedFiles.some((identity) => identity.device === metadata.dev && identity.inode === metadata.ino)) {
      throw new Error(`recovery stage ${step.id} output aliases a protected source or analysis file`);
    }
    const identity = `${metadata.dev}:${metadata.ino}`;
    const prior = seenFiles.get(identity);
    if (prior !== undefined && prior !== output) throw new Error(`recovery stage ${step.id} has two output paths that alias the same file`);
    seenFiles.set(identity, output);
  }
}

async function validateMountedReadOnlyRoot(root: string): Promise<string> {
  const metadata = await lstat(root);
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) throw new Error("mountedReadOnlyRoot must be a real directory, not a symbolic link");
  const resolved = await realpath(root);
  const mounted = await mountForPath(resolved);
  if (await mountIsNetworkBacked(mounted)) throw new Error("mountedReadOnlyRoot must not be on a network filesystem or block transport");
  if (!mountIsReadOnly(mounted)) throw new Error("mountedReadOnlyRoot is not on a read-only mount");
  return resolved;
}

async function validateMountedReadOnlyInput(root: string, input: string): Promise<string> {
  const resolvedInput = path.resolve(input);
  await assertNoSymlinkComponents(root, resolvedInput);
  const mounted = await mountForPath(resolvedInput);
  if (await mountIsNetworkBacked(mounted)) throw new Error("a mounted recovery input must not cross a network-backed mount");
  if (!mountIsReadOnly(mounted)) throw new Error("a mounted recovery input crossed onto a writable mount");
  try {
    const metadata = await lstat(resolvedInput);
    if (metadata.isSymbolicLink() || !metadata.isFile() || await realpath(resolvedInput) !== resolvedInput) {
      throw new Error("an existing mounted recovery input must be a canonical regular file");
    }
  } catch (error) {
    const code = error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
    if (code !== "ENOENT") throw error;
    // Optional residual files are not present on every Windows installation.
  }
  return resolvedInput;
}

function assertResumeDeviceIdentity(stored: unknown, current: SourceSafety): void {
  if (typeof stored !== "object" || stored === null || Array.isArray(stored)) {
    throw new Error("resumable recovery state lacks its prior source/device safety identity");
  }
  const expected = stored as Partial<SourceSafety>;
  if (expected.kind !== current.kind || expected.destinationBackingKind !== current.destinationBackingKind) {
    throw new Error("source or destination backing kind changed since the resumable recovery checkpoint");
  }
  if (current.destinationBackingKind === "block-device") {
    if (!Array.isArray(expected.destinationDeviceIdentities)) {
      throw new Error("resumable recovery state predates stable destination disk identities; create and review a new case instead");
    }
    const expectedDestination = stableBlockDeviceKeys(expected.destinationDeviceIdentities);
    const currentDestination = stableBlockDeviceKeys(current.destinationDeviceIdentities);
    if (expectedDestination.length < 1 || currentDestination.length < 1 || !sameStrings(expectedDestination, currentDestination)) {
      throw new Error("destination disk identity changed or is not stably identifiable at recovery resume");
    }
  } else if (
    expected.destinationBackingKind !== current.destinationBackingKind
    || expected.destinationFilesystemDevice !== current.destinationFilesystemDevice
    || expected.destinationMountSource !== current.destinationMountSource
  ) {
    throw new Error("destination filesystem identity changed since the resumable checkpoint");
  }
  if (current.kind === "regular-file") {
    if (JSON.stringify(expected.regularFileIdentity) !== JSON.stringify(current.regularFileIdentity)) {
      throw new Error("recovery image identity changed since the resumable checkpoint");
    }
    const expectedSource = Array.isArray(expected.sourceDeviceIdentities)
      ? stableBlockDeviceKeys(expected.sourceDeviceIdentities)
      : [];
    const currentSource = stableBlockDeviceKeys(current.sourceDeviceIdentities);
    if (expectedSource.length > 0 || currentSource.length > 0) {
      if (expectedSource.length < 1 || currentSource.length < 1 || !sameStrings(expectedSource, currentSource)) {
        throw new Error("recovery image backing-disk identity changed since the resumable checkpoint");
      }
    }
    return;
  }
  if (!Array.isArray(expected.sourceDeviceIdentities) || !Array.isArray(expected.destinationDeviceIdentities)) {
    throw new Error("resumable block-device state predates stable disk identities; create and review a new recovery case instead");
  }
  const expectedSource = stableBlockDeviceKeys(expected.sourceDeviceIdentities);
  const currentSource = stableBlockDeviceKeys(current.sourceDeviceIdentities);
  if (expectedSource.length < 1 || currentSource.length < 1) {
    throw new Error("a stable source disk identity is required for block-device recovery resume");
  }
  if (!sameStrings(expectedSource, currentSource)) {
    throw new Error("source disk identity changed since the resumable checkpoint");
  }
}

async function validateCaseDestination(destination: string, plan: RecoveryPlan, lockHeld = false, currentSafety?: SourceSafety): Promise<void> {
  let metadata: Awaited<ReturnType<typeof lstat>>;
  try {
    metadata = await lstat(destination);
  } catch (error) {
    const code = error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
    if (code === "ENOENT") return;
    throw error;
  }
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) throw new Error("destination must be a real case directory, not a symbolic link");
  const resolved = await realpath(destination);
  const mounted = await mountForPath(resolved);
  if (mounted !== undefined && path.resolve(mounted.target) === path.resolve(resolved)) {
    throw new Error("destination must be a case subdirectory, not a filesystem mount root");
  }
  const entries = await readDirectoryNamesBounded(destination, 64);
  const lockEntries = entries.filter((entry) => RECOVERY_LOCK_FILENAMES.includes(entry as typeof RECOVERY_LOCK_FILENAMES[number]));
  if (lockHeld && (
    lockEntries.length !== RECOVERY_LOCK_FILENAMES.length
    || RECOVERY_LOCK_FILENAMES.some((filename) => !lockEntries.includes(filename))
  )) throw new Error("a held recovery compatibility lock disappeared or conflicted during destination validation");
  if (!lockHeld && lockEntries.length > 0) {
    throw new Error("the recovery case has an exclusive lock; another process may be active or a prior process may have stopped abruptly");
  }
  const caseEntries = entries.filter((entry) => entry !== RECOVERY_LOCK_FILENAME && entry !== LEGACY_RECOVERY_LOCK_FILENAME);
  if (caseEntries.length > 0) {
    if (!entries.includes("case-sensitive.json") || !entries.includes("plan-redacted.json")) {
      throw new Error("existing non-empty destination is not a fully initialized AARK recovery case");
    }
    for (const filename of ["case-sensitive.json", "plan-redacted.json"]) {
      const marker = await lstat(safeJoin(destination, filename));
      if (marker.isSymbolicLink() || !marker.isFile() || marker.nlink !== 1) throw new Error("existing recovery case markers must be single-link regular, non-symbolic-link files");
    }
    const state = await readJson<{ status?: unknown; plan?: unknown; results?: unknown; sourceSafety?: unknown }>(safeJoin(destination, "case-sensitive.json"));
    if (state.status === "running") throw new Error("existing recovery state is still marked running; inspect the case before attempting another run");
    if (!["paused", "complete", "complete-with-warnings", "failed", "interrupted"].includes(String(state.status))) {
      throw new Error("existing recovery state does not contain a recognized terminal status");
    }
    const lastResult = Array.isArray(state.results) ? state.results.at(-1) : undefined;
    const quotaResume = state.status === "paused"
      && typeof lastResult === "object"
      && lastResult !== null
      && !Array.isArray(lastResult)
      && (lastResult as Record<string, unknown>).status === "paused-disk-quota-resumable"
      && (lastResult as Record<string, unknown>).executable === "ddrescue";
    if (!matchesPlanWithDefaultStorage(state.plan, plan) && !(quotaResume && matchesPlanIgnoringStorage(state.plan, plan))) {
      throw new Error("existing recovery case belongs to a different source, destination, case ID, or plan");
    }
    const storedRedactedPlan = await readJson<unknown>(safeJoin(destination, "plan-redacted.json"));
    const currentRedactedPlan = redactedPlan(plan);
    if (!matchesPlanWithDefaultStorage(storedRedactedPlan, currentRedactedPlan) && !(quotaResume && matchesPlanIgnoringStorage(storedRedactedPlan, currentRedactedPlan))) {
      throw new Error("existing recovery case has a mismatched or corrupted redacted plan marker");
    }
    if (!quotaResume) {
      throw new Error("an existing recovery case can only be reused for its explicitly resumable ddrescue quota pause; choose a new destination for another run");
    }
    if (currentSafety === undefined) throw new Error("resumable recovery requires a current source/device safety snapshot");
    assertResumeDeviceIdentity(state.sourceSafety, currentSafety);
  }
}

export async function runRecoveryPlan(
  config: RecoveryConfig,
  plan: RecoveryPlan,
  cliExecute: boolean,
  signal?: AbortSignal,
): Promise<Record<string, JsonValue>> {
  if (!config.execute || !cliExecute) throw new Error("execution requires execute=true in the case config and --execute on the CLI");
  const canonicalPlan = buildRecoveryPlan(config);
  if (JSON.stringify(plan) !== JSON.stringify(canonicalPlan)) {
    throw new Error("refusing to execute a recovery plan that does not exactly match the supplied configuration");
  }
  const storagePolicy = storagePolicyFromGiB(plan.storage.minFreeGiB, plan.storage.minFreePercent, plan.storage.maxOutputGiB);
  await assertStorageCapacity(await nearestExistingParent(plan.destination), storagePolicy);
  const safety = await inspectSourceSafety(config.source, plan.destination);
  if (inside(plan.destination, safety.resolvedSource)) {
    throw new Error("the canonical recovery source must not be stored inside its case destination");
  }
  if (safety.destinationMountSource === null) throw new Error("could not determine the mount backing the recovery destination");
  if (safety.destinationBackingKind === "network") throw new Error("network-mounted recovery destinations are not allowed");
  if (safety.destinationOnSourceDevice) throw new Error("destination is on the source device");
  if (safety.kind === "block-device" && !safety.deviceComparisonCertain) {
    throw new Error("destination safety preflight could not prove that the destination is independent of the source device");
  }
  if (config.requireReadOnlySource && safety.kind === "block-device" && (!safety.kernelReadOnly || safety.writableMounts.length > 0)) {
    throw new Error(`source safety preflight failed: ${safety.reasons.join("; ")}`);
  }
  const analysisGeneratedByPlan = config.image.enabled
    && path.resolve(plan.analysisSource) === path.resolve(config.image.path);
  const evidenceRoot = path.join(plan.destination, "evidence");
  let analysisDestinationResident = analysisGeneratedByPlan;
  let analysisSafety: Awaited<ReturnType<typeof inspectSourceSafety>> | undefined;
  if (
    config.analysisSource !== undefined
    && path.resolve(config.analysisSource) !== path.resolve(config.source)
    && !analysisGeneratedByPlan
  ) {
    analysisSafety = await inspectSourceSafety(config.analysisSource, plan.destination);
    analysisDestinationResident = inside(evidenceRoot, analysisSafety.resolvedSource);
    if (inside(plan.destination, analysisSafety.resolvedSource) && !analysisDestinationResident) {
      throw new Error("the canonical case-local analysisSource escaped its reserved evidence directory");
    }
    if (analysisSafety.destinationMountSource === null) throw new Error("could not determine the mount backing the recovery destination");
    if (analysisSafety.destinationBackingKind === "network") throw new Error("network-mounted recovery destinations are not allowed");
    if (analysisSafety.destinationOnSourceDevice && !analysisDestinationResident) throw new Error("destination is on the analysis-source device");
    if (analysisSafety.kind === "block-device" && !analysisSafety.deviceComparisonCertain) {
      throw new Error("could not prove that the destination is independent of the analysis-source device");
    }
    if (config.requireReadOnlySource && analysisSafety.kind === "block-device" && (!analysisSafety.kernelReadOnly || analysisSafety.writableMounts.length > 0)) {
      throw new Error("analysisSource block device is not read-only or has a writable mount");
    }
  }
  const mountedReadOnlyRoot = config.mountedReadOnlyRoot === undefined
    ? undefined
    : await validateMountedReadOnlyRoot(config.mountedReadOnlyRoot);
  await validateCaseDestination(plan.destination, plan, false, safety);
  await ensurePrivateDirectory(plan.destination);
  for (const controlPath of [
    plan.destination,
    safeJoin(plan.destination, "runs"),
    safeJoin(plan.destination, "logs"),
    safeJoin(plan.destination, "case-sensitive.json"),
    safeJoin(plan.destination, "plan-redacted.json"),
    safeJoin(plan.destination, "manifest-redacted.json"),
    safeJoin(plan.destination, "final-report-sensitive.md"),
    safeJoin(plan.destination, "final-report-redacted.md"),
  ]) await assertNoSymlinkComponents(plan.destination, controlPath);
  for (const recoveryStep of plan.steps) {
    for (const output of destinationPaths(recoveryStep, plan.destination)) {
      await assertNoSymlinkComponents(plan.destination, output);
    }
  }
  const locks = await acquireRecoveryLocks(plan.destination);
  let runFailure: unknown;
  try {
  await validateCaseDestination(plan.destination, plan, true, safety);
  const targetMount = await mountForPath(plan.destination);
  if (targetMount === undefined || await mountIsNetworkBacked(targetMount)) {
    throw new Error("recovery destination no longer has a verifiable local mount");
  }
  const destinationMetadata = await lstat(plan.destination);
  const destinationCanonical = await realpath(plan.destination);
  if (!destinationMetadata.isDirectory() || destinationCanonical !== path.resolve(plan.destination)) {
    throw new Error("recovery destination changed while its lock was acquired");
  }
  const destinationMountIdentity = mountIdentity(targetMount);
  const assertDestinationControlCurrent = async (): Promise<void> => {
    for (const lock of locks) await lock.assertHeld();
    const currentMetadata = await lstat(plan.destination);
    const currentCanonical = await realpath(plan.destination);
    const currentMounts = await mounts();
    const currentMount = mountForPathFrom(currentMounts, plan.destination);
    const nestedMount = currentMounts.some((record) => {
      const target = path.resolve(record.target);
      return target !== destinationCanonical && inside(destinationCanonical, target);
    });
    if (
      !currentMetadata.isDirectory()
      || currentMetadata.isSymbolicLink()
      || currentMetadata.dev !== destinationMetadata.dev
      || currentMetadata.ino !== destinationMetadata.ino
      || currentCanonical !== destinationCanonical
      || currentMount === undefined
      || mountIdentity(currentMount) !== destinationMountIdentity
      || nestedMount
    ) throw new Error("recovery destination, mount, or exclusive lock changed during execution");
  };
  const assertRecoveryCapacity = async (): Promise<void> => {
    // Check free space before and after the potentially long logical-size walk,
    // so a very large recovery tree cannot delay reserve enforcement until the
    // walk has finished.
    await assertStorageCapacity(plan.destination, storagePolicy);
    if (storagePolicy.maximumOutputBytes !== undefined) {
      const outputBytes = await directoryLogicalBytes(plan.destination, signal);
      await assertStorageCapacity(plan.destination, storagePolicy, outputBytes);
    }
  };
  const permissionsEnforced = filesystemEnforcesUnixModes(targetMount);
  const startedAt = new Date().toISOString();
  const runId = `${startedAt.replace(/[^0-9A-Za-z]/g, "-")}-${randomUUID()}`;
  const runStatePath = safeJoin(plan.destination, "runs", `${runId}-sensitive.json`);
  const sensitiveRun = {
    version: 1,
    runId,
    status: "running" as "running" | RecoveryRunStatus,
    startedAt,
    updatedAt: startedAt,
    finishedAt: null as string | null,
    plan,
    sourceSafety: safety,
    results: [] as Array<Record<string, JsonValue>>,
    currentStep: null as string | null,
    failure: null as null | { name: string; message: string },
  };
  const redactedResults: Array<Record<string, JsonValue>> = [];
  const writeCaseFile = async (filename: string, data: Uint8Array | string, mode = 0o600): Promise<void> => {
    await assertDestinationControlCurrent();
    await atomicWriteFile(filename, data, mode);
    await assertDestinationControlCurrent();
  };
  const writeCaseJson = async (filename: string, value: unknown, mode = 0o600): Promise<void> => {
    await assertDestinationControlCurrent();
    await atomicWriteJson(filename, value, mode);
    await assertDestinationControlCurrent();
  };
  const persistState = async (): Promise<void> => {
    sensitiveRun.updatedAt = new Date().toISOString();
    await writeCaseJson(runStatePath, sensitiveRun);
    await writeCaseJson(safeJoin(plan.destination, "case-sensitive.json"), sensitiveRun);
  };
  await assertRecoveryCapacity();
  const renderedPlan = redactedPlan(plan);
  await writeCaseJson(safeJoin(plan.destination, "runs", `${runId}-plan-redacted.json`), renderedPlan, 0o644);
  await writeCaseJson(safeJoin(plan.destination, "plan-redacted.json"), renderedPlan, 0o644);
  await persistState();

  const finalize = async (status: RecoveryRunStatus, failure?: unknown): Promise<Record<string, JsonValue>> => {
    const finishedAt = new Date().toISOString();
    const failureMessage = failure === undefined ? undefined : sensitiveErrorDetail(failure);
    sensitiveRun.status = status;
    sensitiveRun.finishedAt = finishedAt;
    sensitiveRun.currentStep = null;
    sensitiveRun.failure = failureMessage === undefined
      ? null
      : { name: failure instanceof Error ? failure.name : "Error", message: failureMessage };
    const sensitiveReport = renderRecoverySensitiveReport(
      plan,
      sensitiveRun.results,
      safety,
      permissionsEnforced,
      finishedAt,
      status,
      runId,
      failureMessage,
    );
    const redactedReport = renderRecoveryRedactedReport(plan, sensitiveRun.results, permissionsEnforced, finishedAt, status, runId);
    await writeCaseFile(safeJoin(plan.destination, "runs", `${runId}-final-report-sensitive.md`), sensitiveReport);
    await writeCaseFile(safeJoin(plan.destination, "runs", `${runId}-final-report-redacted.md`), redactedReport, 0o644);
    await writeCaseFile(safeJoin(plan.destination, "final-report-sensitive.md"), sensitiveReport);
    await writeCaseFile(safeJoin(plan.destination, "final-report-redacted.md"), redactedReport, 0o644);
    const complete = status === "complete" || status === "complete-with-warnings";
    const manifest: Record<string, JsonValue> = {
      tool: "aark",
      layer: "recovery",
      runId,
      status,
      complete,
      finishedAt,
      caseId: "<CASE_ID>",
      sourcePathsAndToolLogsRedacted: true,
      sourceReadOnlyRequired: config.requireReadOnlySource,
      destinationUnixPermissionsEnforced: permissionsEnforced,
      reports: {
        sensitive: "final-report-sensitive.md",
        redacted: "final-report-redacted.md",
      },
      results: redactedResults,
      warnings: [
        ...plan.warnings,
        ...(!permissionsEnforced ? ["Destination filesystem is not known to enforce per-file Unix modes; physically secure or encrypt it."] : []),
        ...(!complete ? ["The recovery run did not complete; inspect the local sensitive run state and report."] : []),
      ],
    };
    await writeCaseJson(safeJoin(plan.destination, "runs", `${runId}-manifest-redacted.json`), manifest, 0o644);
    await writeCaseJson(safeJoin(plan.destination, "manifest-redacted.json"), manifest, 0o644);
    await persistState();
    return manifest;
  };

  try {
    for (const recoveryStep of plan.steps) {
      if (signal?.aborted === true) throw new Error("recovery interrupted");
      await assertDestinationControlCurrent();
      await assertSourceSafetyCurrent(config.source, plan.destination, safety, config.requireReadOnlySource, "source");
      if (config.mountedReadOnlyRoot !== undefined && mountedReadOnlyRoot !== undefined) {
        if (await validateMountedReadOnlyRoot(config.mountedReadOnlyRoot) !== mountedReadOnlyRoot) {
          throw new Error("mountedReadOnlyRoot canonical path changed after preflight");
        }
      }
      if (!recoveryStep.id.startsWith("image-") && path.resolve(plan.analysisSource) !== path.resolve(plan.source)) {
        analysisSafety ??= await inspectSourceSafety(plan.analysisSource, plan.destination);
        await assertSourceSafetyCurrent(plan.analysisSource, plan.destination, analysisSafety, config.requireReadOnlySource, "analysisSource", analysisDestinationResident);
      }
      const stderrLog = safeJoin(plan.destination, "logs", runId, `${recoveryStep.id}.stderr-sensitive.log`);
      const stdoutLog = recoveryStep.stdoutFile === undefined
        ? safeJoin(plan.destination, "logs", runId, `${recoveryStep.id}.stdout-sensitive.log`)
        : undefined;
      const temporaryDirectory = safeJoin(plan.destination, "logs", runId, `${recoveryStep.id}.tmp-sensitive`);
      sensitiveRun.currentStep = recoveryStep.id;
      await persistState();
      try {
        await assertRecoveryCapacity();
        await assertStepOutputsSafe(recoveryStep, safety, analysisSafety, false, true);
        for (const directory of recoveryStep.createsDirectories) await ensurePrivateDirectory(directory);
        if (!(await commandExists(recoveryStep.executable))) {
          const status = recoveryStep.optional ? "skipped-missing-optional-tool" : "failed-missing-required-tool";
          const result = { id: recoveryStep.id, status, durationMs: 0 };
          sensitiveRun.currentStep = null;
          sensitiveRun.results.push(result);
          redactedResults.push(result);
          await persistState();
          if (!recoveryStep.optional) throw new Error(`required executable is missing: ${recoveryStep.executable}`);
          continue;
        }
        const outputSnapshot = recoveryStep.partialSuccessExitCodes === undefined
          ? undefined
          : await snapshotRecoveryOutputs(recoveryStep, signal);
        const commandStdout = recoveryStep.stdoutFile ?? stdoutLog;
        if (commandStdout === undefined) throw new Error("recovery step has no safe stdout destination");
        await assertNoSymlinkComponents(plan.destination, stderrLog);
        if (stdoutLog !== undefined) await assertNoSymlinkComponents(plan.destination, stdoutLog);
        await assertNoSymlinkComponents(plan.destination, temporaryDirectory);
        const mountedInput = recoveryStep.id.startsWith("residual-memory-") || recoveryStep.id === "deleted-registry-cells"
          ? recoveryStep.args.at(-1)
          : undefined;
        let mountedExecutionInput: string | undefined;
        const executionArgs: string[] = [];
        for (const argument of recoveryStep.args) {
          if (argument === plan.source) {
            executionArgs.push(safety.resolvedSource);
          } else if (argument === plan.analysisSource && analysisSafety !== undefined) {
            executionArgs.push(analysisSafety.resolvedSource);
          } else if (
            argument === mountedInput
            && config.mountedReadOnlyRoot !== undefined
            && mountedReadOnlyRoot !== undefined
            && inside(config.mountedReadOnlyRoot, argument)
          ) {
            const canonicalInput = path.resolve(mountedReadOnlyRoot, path.relative(config.mountedReadOnlyRoot, argument));
            mountedExecutionInput = await validateMountedReadOnlyInput(mountedReadOnlyRoot, canonicalInput);
            executionArgs.push(mountedExecutionInput);
          } else {
            executionArgs.push(argument);
          }
        }
        let lastExtendedSafetyCheck = Date.now();
        const completed = await captureCommand(recoveryStep.executable, executionArgs, {
          stdoutFile: commandStdout,
          cwd: recoveryStep.workingDirectory ?? path.dirname(stderrLog),
          stderrFile: stderrLog,
          temporaryDirectory,
          ...(signal === undefined ? {} : { signal }),
          safetyCheck: async () => {
            await assertDestinationControlCurrent();
            await assertRecoveryCapacity();
            const now = Date.now();
            if (now - lastExtendedSafetyCheck >= 5_000) {
              lastExtendedSafetyCheck = now;
              await assertSourceSafetyCurrent(config.source, plan.destination, safety, config.requireReadOnlySource, "source");
              if (analysisSafety !== undefined) {
                await assertSourceSafetyCurrent(plan.analysisSource, plan.destination, analysisSafety, config.requireReadOnlySource, "analysisSource", analysisDestinationResident);
              }
              if (config.mountedReadOnlyRoot !== undefined && mountedReadOnlyRoot !== undefined) {
                if (await validateMountedReadOnlyRoot(config.mountedReadOnlyRoot) !== mountedReadOnlyRoot) {
                  throw new Error("mountedReadOnlyRoot canonical path changed during a recovery stage");
                }
                if (
                  mountedExecutionInput !== undefined
                  && await validateMountedReadOnlyInput(mountedReadOnlyRoot, mountedExecutionInput) !== mountedExecutionInput
                ) throw new Error("mounted recovery input changed during a recovery stage");
              }
            }
          },
          safetyCheckIntervalMs: 1_000,
          maxCaptureBytes: 64 * 1024,
        });
        await assertDestinationControlCurrent();
        await assertSourceSafetyCurrent(config.source, plan.destination, safety, config.requireReadOnlySource, "source");
        if (analysisSafety !== undefined) {
          await assertSourceSafetyCurrent(plan.analysisSource, plan.destination, analysisSafety, config.requireReadOnlySource, "analysisSource", analysisDestinationResident);
        }
        if (config.mountedReadOnlyRoot !== undefined && mountedReadOnlyRoot !== undefined) {
          if (await validateMountedReadOnlyRoot(config.mountedReadOnlyRoot) !== mountedReadOnlyRoot) {
            throw new Error("mountedReadOnlyRoot canonical path changed during a recovery stage");
          }
          if (
            mountedExecutionInput !== undefined
            && await validateMountedReadOnlyInput(mountedReadOnlyRoot, mountedExecutionInput) !== mountedExecutionInput
          ) throw new Error("mounted recovery input changed during a recovery stage");
        }
        await assertRecoveryCapacity();
        const effectiveTermination = completed.terminationReason ?? (Boolean(signal?.aborted) ? "abort" : null);
        const producedNewOutput = effectiveTermination === null && completed.exitCode !== 0 && outputSnapshot !== undefined
          ? await stepProducedNewOutput(recoveryStep, outputSnapshot, signal)
          : false;
        const stepStatus = effectiveTermination === null
          ? recoveryStepStatus(recoveryStep, completed.exitCode, producedNewOutput)
          : effectiveTermination === "abort" ? "interrupted-before-completion" : "failed-before-completion";
        const completedOutput = stepStatus === "completed" || stepStatus === "completed-with-warnings";
        await assertStepOutputsSafe(recoveryStep, safety, analysisSafety, completedOutput);
        sensitiveRun.results.push({
          id: recoveryStep.id,
          status: stepStatus,
          exitCode: completed.exitCode,
          signal: completed.signal,
          terminationReason: effectiveTermination,
          durationMs: completed.durationMs,
          executable: recoveryStep.executable,
          args: executionArgs,
          ...(stdoutLog === undefined ? {} : { stdoutLog }),
          stderrLog,
        });
        redactedResults.push({
          id: recoveryStep.id,
          status: stepStatus,
          exitCode: completed.exitCode,
          signal: completed.signal,
          terminationReason: effectiveTermination,
          durationMs: completed.durationMs,
        });
        sensitiveRun.currentStep = null;
        await persistState();
        if (effectiveTermination !== null) {
          throw new Error(effectiveTermination === "abort" ? "recovery interrupted" : `recovery step terminated before completion: ${recoveryStep.id}`);
        }
        if (stepStatus === "failed" && !recoveryStep.optional) throw new Error(`recovery step failed: ${recoveryStep.id}`);
      } catch (error) {
        const quota = storageQuota(error);
        if (quota !== undefined && !sensitiveRun.results.some((result) => result.id === recoveryStep.id)) {
          const resumable = recoveryStep.executable === "ddrescue";
          const status = resumable ? "paused-disk-quota-resumable" : "failed-disk-quota";
          sensitiveRun.results.push({
            id: recoveryStep.id,
            status,
            error: sensitiveErrorDetail(error),
            executable: recoveryStep.executable,
            args: recoveryStep.args,
            ...(stdoutLog === undefined ? {} : { stdoutLog }),
            stderrLog,
          });
          redactedResults.push({ id: recoveryStep.id, status });
          sensitiveRun.currentStep = null;
          await persistState();
          throw new RecoveryQuotaStop(resumable, quota);
        }
        if (!sensitiveRun.results.some((result) => result.id === recoveryStep.id)) {
          sensitiveRun.results.push({
            id: recoveryStep.id,
            status: "failed-before-completion",
            error: sensitiveErrorDetail(error),
            executable: recoveryStep.executable,
            args: recoveryStep.args,
            ...(stdoutLog === undefined ? {} : { stdoutLog }),
            stderrLog,
          });
          redactedResults.push({ id: recoveryStep.id, status: "failed-before-completion" });
          sensitiveRun.currentStep = null;
          await persistState();
        }
        throw error;
      }
    }
    if (signal?.aborted === true) throw new Error("recovery interrupted");
    await assertSourceSafetyCurrent(config.source, plan.destination, safety, config.requireReadOnlySource, "source");
    if (analysisSafety !== undefined) {
      await assertSourceSafetyCurrent(plan.analysisSource, plan.destination, analysisSafety, config.requireReadOnlySource, "analysisSource", analysisDestinationResident);
    }
  } catch (error) {
    if (error instanceof RecoveryQuotaStop && error.resumable) {
      return await finalize("paused", error);
    }
    const status: RecoveryRunStatus = signal?.aborted === true ? "interrupted" : "failed";
    try {
      await finalize(status, error);
    } catch (reportError) {
      throw new AggregateError([error, reportError], "recovery failed and its final failure report could not be fully written");
    }
    throw error;
  }
  const hasWarnings = redactedResults.some((result) => result.status !== "completed");
  try {
    return await finalize(hasWarnings ? "complete-with-warnings" : "complete");
  } catch (error) {
    try {
      await finalize("failed", error);
    } catch (reportError) {
      throw new AggregateError([error, reportError], "recovery completion failed and its final failure report could not be fully written");
    }
    throw error;
  }
  } catch (error) {
    runFailure = error;
    throw error;
  } finally {
    try {
      await releaseRecoveryLocks(locks);
    } catch (releaseError) {
      if (runFailure !== undefined) throw new AggregateError([runFailure, releaseError], "recovery failed and its exclusive case locks could not be released");
      throw releaseError;
    }
  }
}
