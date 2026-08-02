import { randomUUID } from "node:crypto";
import { lstat, readdir, realpath } from "node:fs/promises";
import path from "node:path";
import { captureCommand, commandExists } from "../core/command.js";
import { acquireExclusiveLock, assertNoSymlinkComponents, atomicWriteFile, atomicWriteJson, ensurePrivateDirectory, readJson, safeJoin } from "../core/fs-safe.js";
import { filesystemEnforcesUnixModes, mountForPath, mountForPathFrom, mountIsNetworkBacked, mountIsReadOnly, mounts } from "../core/mounts.js";
import type { MountRecord } from "../core/mounts.js";
import type { JsonValue } from "../core/types.js";
import type { RecoveryConfig, RecoveryPlan, RecoveryRunStatus, RecoveryStep } from "./types.js";
import { buildRecoveryPlan } from "./plan.js";
import { inspectSourceSafety } from "./source-safety.js";
import type { SourceSafety } from "./source-safety.js";
import { renderRecoveryRedactedReport, renderRecoverySensitiveReport } from "./report.js";

const PHOTOREC_SWITCHES = new Set(["/log", "/logname", "/d", "/cmd"]);

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
    steps: plan.steps.map((step) => redactedStep(step, plan)),
    warnings: plan.warnings,
  };
}

function inside(root: string, candidate: string): boolean {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
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
): Promise<void> {
  const current = await inspectSourceSafety(requested, destination);
  if (
    current.kind !== expected.kind
    || current.resolvedSource !== expected.resolvedSource
    || current.bytes !== expected.bytes
    || !sameStrings(current.sourceTopDevices, expected.sourceTopDevices)
    || !sameStrings(current.destinationDevices, expected.destinationDevices)
    || current.destinationMountSource !== expected.destinationMountSource
    || current.destinationBackingKind !== expected.destinationBackingKind
    || current.destinationBackingKind === "network"
    || current.destinationOnSourceDevice
    || (current.kind === "block-device" && !current.deviceComparisonCertain)
    || (requireReadOnly && current.kind === "block-device" && (!current.kernelReadOnly || current.writableMounts.length > 0))
    || JSON.stringify(current.regularFileIdentity) !== JSON.stringify(expected.regularFileIdentity)
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

type RecoveryOutputSnapshot =
  | { kind: "missing" }
  | { kind: "file"; device: number; inode: number; size: number; modifiedMs: number }
  | { kind: "directory"; entries: Set<string> }
  | { kind: "other" };

async function recoveryOutputSnapshot(output: string): Promise<RecoveryOutputSnapshot> {
  try {
    const metadata = await lstat(output);
    if (metadata.isFile()) {
      return { kind: "file", device: metadata.dev, inode: metadata.ino, size: metadata.size, modifiedMs: metadata.mtimeMs };
    }
    if (metadata.isDirectory()) return { kind: "directory", entries: new Set(await readdir(output)) };
    return { kind: "other" };
  } catch (error) {
    const code = error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
    if (code === "ENOENT") return { kind: "missing" };
    throw error;
  }
}

async function snapshotRecoveryOutputs(step: RecoveryStep): Promise<Map<string, RecoveryOutputSnapshot>> {
  const snapshots = new Map<string, RecoveryOutputSnapshot>();
  for (const output of new Set(step.outputs.map((value) => path.resolve(value)))) {
    snapshots.set(output, await recoveryOutputSnapshot(output));
  }
  return snapshots;
}

async function stepProducedNewOutput(step: RecoveryStep, before: Map<string, RecoveryOutputSnapshot>): Promise<boolean> {
  for (const output of new Set(step.outputs.map((value) => path.resolve(value)))) {
    const prior = before.get(output) ?? { kind: "missing" };
    const current = await recoveryOutputSnapshot(output);
    if (current.kind === "file") {
      if (
        prior.kind !== "file"
        || prior.device !== current.device
        || prior.inode !== current.inode
        || prior.size !== current.size
        || prior.modifiedMs !== current.modifiedMs
      ) return true;
    }
    if (current.kind === "directory") {
      const priorEntries = prior.kind === "directory" ? prior.entries : new Set<string>();
      for (const entry of current.entries) {
        if (priorEntries.has(entry)) continue;
        const metadata = await lstat(path.join(output, entry));
        if (!metadata.isSymbolicLink() && metadata.isFile()) return true;
      }
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

async function validateCaseDestination(destination: string, plan: RecoveryPlan, lockHeld = false): Promise<void> {
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
  const entries = await readdir(destination);
  const hasLock = entries.includes(".agetnic-recovery.lock");
  if (lockHeld && !hasLock) throw new Error("the held recovery lock disappeared during destination validation");
  if (!lockHeld && hasLock) {
    throw new Error("the recovery case has an exclusive lock; another process may be active or a prior process may have stopped abruptly");
  }
  const caseEntries = entries.filter((entry) => entry !== ".agetnic-recovery.lock");
  if (caseEntries.length > 0) {
    if (!entries.includes("case-sensitive.json") || !entries.includes("plan-redacted.json")) {
      throw new Error("existing non-empty destination is not a fully initialized AARK recovery case");
    }
    for (const filename of ["case-sensitive.json", "plan-redacted.json"]) {
      const marker = await lstat(safeJoin(destination, filename));
      if (marker.isSymbolicLink() || !marker.isFile()) throw new Error("existing recovery case markers must be regular, non-symbolic-link files");
    }
    const state = await readJson<{ status?: unknown; plan?: unknown }>(safeJoin(destination, "case-sensitive.json"));
    if (state.status === "running") throw new Error("existing recovery state is still marked running; inspect the case before attempting another run");
    if (!["complete", "complete-with-warnings", "failed", "interrupted"].includes(String(state.status))) {
      throw new Error("existing recovery state does not contain a recognized terminal status");
    }
    if (JSON.stringify(state.plan) !== JSON.stringify(plan)) {
      throw new Error("existing recovery case belongs to a different source, destination, case ID, or plan");
    }
    const storedRedactedPlan = await readJson<unknown>(safeJoin(destination, "plan-redacted.json"));
    if (JSON.stringify(storedRedactedPlan) !== JSON.stringify(redactedPlan(plan))) {
      throw new Error("existing recovery case has a mismatched or corrupted redacted plan marker");
    }
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
  let analysisSafety: Awaited<ReturnType<typeof inspectSourceSafety>> | undefined;
  if (
    config.analysisSource !== undefined
    && path.resolve(config.analysisSource) !== path.resolve(config.source)
    && !analysisGeneratedByPlan
  ) {
    analysisSafety = await inspectSourceSafety(config.analysisSource, plan.destination);
    const evidenceRoot = path.join(plan.destination, "evidence");
    if (inside(plan.destination, analysisSafety.resolvedSource) && !inside(evidenceRoot, analysisSafety.resolvedSource)) {
      throw new Error("the canonical case-local analysisSource escaped its reserved evidence directory");
    }
    if (analysisSafety.destinationMountSource === null) throw new Error("could not determine the mount backing the recovery destination");
    if (analysisSafety.destinationBackingKind === "network") throw new Error("network-mounted recovery destinations are not allowed");
    if (analysisSafety.destinationOnSourceDevice) throw new Error("destination is on the analysis-source device");
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
  await validateCaseDestination(plan.destination, plan);
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
  const lock = await acquireExclusiveLock(plan.destination, ".agetnic-recovery.lock");
  let runFailure: unknown;
  try {
  await validateCaseDestination(plan.destination, plan, true);
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
    await lock.assertHeld();
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
        await assertSourceSafetyCurrent(plan.analysisSource, plan.destination, analysisSafety, config.requireReadOnlySource, "analysisSource");
      }
      const stderrLog = safeJoin(plan.destination, "logs", runId, `${recoveryStep.id}.stderr-sensitive.log`);
      const stdoutLog = recoveryStep.stdoutFile === undefined
        ? safeJoin(plan.destination, "logs", runId, `${recoveryStep.id}.stdout-sensitive.log`)
        : undefined;
      const temporaryDirectory = safeJoin(plan.destination, "logs", runId, `${recoveryStep.id}.tmp-sensitive`);
      sensitiveRun.currentStep = recoveryStep.id;
      await persistState();
      try {
        await assertStepOutputsSafe(recoveryStep, safety, analysisSafety, false);
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
          : await snapshotRecoveryOutputs(recoveryStep);
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
        const completed = await captureCommand(recoveryStep.executable, executionArgs, {
          stdoutFile: commandStdout,
          cwd: recoveryStep.workingDirectory ?? path.dirname(stderrLog),
          stderrFile: stderrLog,
          temporaryDirectory,
          ...(signal === undefined ? {} : { signal }),
          safetyCheck: assertDestinationControlCurrent,
          safetyCheckIntervalMs: 5_000,
          maxCaptureBytes: 64 * 1024,
        });
        await assertDestinationControlCurrent();
        await assertSourceSafetyCurrent(config.source, plan.destination, safety, config.requireReadOnlySource, "source");
        if (analysisSafety !== undefined) {
          await assertSourceSafetyCurrent(plan.analysisSource, plan.destination, analysisSafety, config.requireReadOnlySource, "analysisSource");
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
        const producedNewOutput = completed.exitCode !== 0 && outputSnapshot !== undefined
          ? await stepProducedNewOutput(recoveryStep, outputSnapshot)
          : false;
        const stepStatus = recoveryStepStatus(recoveryStep, completed.exitCode, producedNewOutput);
        if (stepStatus !== "failed") await assertStepOutputsSafe(recoveryStep, safety, analysisSafety, true);
        sensitiveRun.results.push({
          id: recoveryStep.id,
          status: stepStatus,
          exitCode: completed.exitCode,
          signal: completed.signal,
          terminationReason: completed.terminationReason,
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
          terminationReason: completed.terminationReason,
          durationMs: completed.durationMs,
        });
        sensitiveRun.currentStep = null;
        await persistState();
        if (stepStatus === "failed" && !recoveryStep.optional) throw new Error(`recovery step failed: ${recoveryStep.id}`);
      } catch (error) {
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
      await assertSourceSafetyCurrent(plan.analysisSource, plan.destination, analysisSafety, config.requireReadOnlySource, "analysisSource");
    }
  } catch (error) {
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
      await lock.release();
    } catch (releaseError) {
      if (runFailure !== undefined) throw new AggregateError([runFailure, releaseError], "recovery failed and its exclusive case lock could not be released");
      throw releaseError;
    }
  }
}
