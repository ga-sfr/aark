import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import type { Stats } from "node:fs";
import { lstat, mkdir, open, opendir, readlink, realpath, rename, rm, statfs } from "node:fs/promises";
import path from "node:path";
import { isDeepStrictEqual } from "node:util";
import {
  acquireExclusiveLock,
  assertNoSymlinkComponents,
  atomicWriteFile,
  atomicWriteJson,
  ensurePrivateDirectory,
  MAX_WALK_DIRECTORIES,
  MAX_WALK_DIRECTORY_ENTRIES,
  MAX_WALK_PENDING_ENTRIES,
  readDirectoryNamesBounded,
  readJson,
  safeJoin,
  syncDirectory,
  walkRegularFiles,
} from "./core/fs-safe.js";
import type { ExclusiveLock, WalkedFile } from "./core/fs-safe.js";
import { filesystemIsNetwork, mountForPathFrom, mountIsNetworkBacked, mounts } from "./core/mounts.js";
import type { MountRecord } from "./core/mounts.js";
import {
  loadCompletedInventory,
  loadScanState,
  readScanManifest,
  verifyResumeArtifacts,
} from "./mining/resume.js";
import type { ScanState } from "./mining/resume.js";
import type { SensitiveScanInventory } from "./mining/types.js";
import { resolveMiningOutputs } from "./mining/batch.js";

const RECOVERY_LOCK_FILENAMES = [".aark-recovery.lock", ".agetnic-recovery.lock"] as const;
const MINING_LOCK_FILENAMES = [".aark-mining.lock", ".agetnic-mining.lock"] as const;
const CLEANUP_SENSITIVE_REPORT = "cleanup-final-report-sensitive.md";
const CLEANUP_REDACTED_REPORT = "cleanup-final-report-redacted.md";
const CLEANUP_REDACTED_MANIFEST = "cleanup-manifest-redacted.json";
const RETAINED_SOURCE_DIRECTORY = "retained-sensitive-source-files";
const MAX_CASE_STATE_BYTES = 16 * 1024 * 1024;
const MAX_CLEANUP_FAILURE_BYTES = 8 * 1024;
const MAX_RETAINED_CONTROL_BYTES = 256 * 1024 * 1024;
const TOKEN = /^[a-f0-9]{64}$/;
const RUN_ID = /^[0-9A-Za-z][0-9A-Za-z._-]{0,255}$/;
const CLEANUP_QUARANTINE_PREFIX = ".aark-cleanup-pending-";
const BATCH_LOCK_FILENAME = ".aark-batch.lock";
const MAX_CLEANUP_MINING_OUTPUTS = 10_000;

export interface CleanupOptions {
  caseDirectory: string;
  miningOutputs: string[];
  includeEvidence?: boolean;
  signal?: AbortSignal;
}

export interface CleanupRunOptions extends CleanupOptions {
  approvalToken: string;
  execute: boolean;
  confirmDeleteRecoveredCopy: boolean;
  confirmDeleteEvidence?: boolean;
}

export interface CleanupPlanResult {
  version: 1;
  tool: "aark";
  layer: "cleanup";
  status: "ready";
  destructive: true;
  valuesPrinted: false;
  pathsRedacted: true;
  recoveryStatus: "complete" | "complete-with-warnings";
  miningScansVerified: number;
  scannedFilesVerified: string;
  findingsRetained: string;
  markerOnlyFindingsWithoutArtifacts: string;
  artifactFilesRetained: string;
  sourceFilesRetained: string;
  sourceFileLogicalBytesRetained: string;
  deletion: {
    directories: number;
    filesystemEntries: string;
    regularFiles: string;
    logicalBytes: string;
    allocatedBytes: string;
    expectedFreeSpaceGainMinimumBytes: string;
    expectedFreeSpaceGainMaximumBytes: string;
    allocationUnitBytes: string;
    allocationUnitSource: "statfs-block-size";
    recoveredCopyLogicalBytes: string;
    evidenceCopyLogicalBytes: string;
    intermediateLogicalBytes: string;
    recoveredCopyIncluded: boolean;
    evidenceCopyIncluded: boolean;
    evidenceCopyPresent: boolean;
    intermediateLogsAndRunsIncluded: boolean;
  };
  retained: {
    recoveryFinalReports: true;
    cleanupFinalReports: true;
    miningFinalReports: true;
    exactFindingArtifacts: true;
    wholeFindingSourceFiles: true;
    minimalIntegrityMetadata: true;
    evidenceCopy: boolean;
  };
  approvalToken: string;
  approvalRequired: true;
  requirements: string[];
}

interface RootSnapshot {
  path: string;
  device: number;
  inode: number;
  mount: string;
}

interface DirectoryIdentity {
  path: string;
  device: number;
  inode: number;
}

interface TargetSnapshot {
  name: "recovery" | "evidence" | "logs" | "runs";
  path: string;
  device: number;
  inode: number;
  modifiedMs: number;
  changedMs: number;
  filesystemEntries: bigint;
  regularFiles: bigint;
  logicalBytes: bigint;
  allocatedBytes: bigint;
  minimumReclaimableAllocatedBytes: bigint;
  hardLinkAllocations: HardLinkAllocation[];
  contentDigest: string;
  deletionDigest: string;
  requiresScanCoverage: boolean;
  retainedSourceFiles: RetainedSourceFile[];
}

interface HardLinkAllocation {
  device: number;
  inode: number;
  allocatedBytes: bigint;
  links: number;
  selectedLinks: number;
}

interface RetainedSourceFile {
  originalPath: string;
  relativePath: string;
  device: number;
  inode: number;
  mode: number;
  links: number;
  bytes: number;
  allocatedBytes: bigint;
  modifiedMs: number;
  changedMs: number;
}

interface VerifiedMiningOutput {
  root: RootSnapshot;
  state: ScanState;
  scannedFiles: number;
  findings: number;
  markerOnlyFindings: number;
  artifactFiles: number;
  sourceFiles: string[];
  controlDigest: string;
}

interface CoverageIndex {
  files: Set<string>;
  directories: Set<string>;
}

interface FindingSourceIndex {
  paths: Set<string>;
  entryIdentities: Set<string>;
}

interface VerifiedRecoveryCase {
  status: "complete" | "complete-with-warnings";
  runId: string;
  controlDigest: string;
}

interface RecoveryCaseState {
  version?: unknown;
  runId?: unknown;
  status?: unknown;
  startedAt?: unknown;
  finishedAt?: unknown;
  currentStep?: unknown;
  failure?: unknown;
  plan?: unknown;
  results?: unknown;
}

interface InternalCleanupPlan {
  public: CleanupPlanResult;
  caseRoot: RootSnapshot;
  retainedSourceBase: RootSnapshot | undefined;
  recovery: VerifiedRecoveryCase;
  mining: VerifiedMiningOutput[];
  coverage: CoverageIndex;
  findingSources: FindingSourceIndex;
  targets: TargetSnapshot[];
  introducedLocks: Set<string>;
  batchRoots: string[];
  retentionMetadataReserveBytes: bigint;
}

function interrupted(signal: AbortSignal | undefined): void {
  if (signal?.aborted === true) throw new Error("cleanup verification was interrupted");
}

function inside(root: string, candidate: string): boolean {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  return relative === "" || (relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

function mountIdentity(record: MountRecord): string {
  return JSON.stringify({
    source: record.source,
    target: path.resolve(record.target),
    filesystem: record.filesystem.toLowerCase(),
    options: [...record.options].sort(),
  });
}

function boundedString(value: unknown, maximumBytes = 4 * 1024): value is string {
  return typeof value === "string" && Buffer.byteLength(value) <= maximumBytes;
}

function errorCode(error: unknown): string | undefined {
  return error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
}

function bytewiseLexical(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function entryKind(metadata: Stats): "directory" | "file" | "symlink" | "block-device" | "character-device" | "fifo" | "socket" | "other" {
  if (metadata.isDirectory()) return "directory";
  if (metadata.isFile()) return "file";
  if (metadata.isSymbolicLink()) return "symlink";
  if (metadata.isBlockDevice()) return "block-device";
  if (metadata.isCharacterDevice()) return "character-device";
  if (metadata.isFIFO()) return "fifo";
  if (metadata.isSocket()) return "socket";
  return "other";
}

function assertBoundedEntryMetadata(metadata: Stats): void {
  for (const value of [metadata.dev, metadata.ino, metadata.mode, metadata.nlink, metadata.uid, metadata.gid, metadata.rdev, metadata.blocks, metadata.mtimeMs, metadata.ctimeMs]) {
    if (!Number.isFinite(value) || value < 0) throw new Error("cleanup target contains filesystem metadata outside valid numeric bounds");
  }
  if (!Number.isSafeInteger(metadata.size) || metadata.size < 0) {
    throw new Error("cleanup target contains an entry whose size exceeds safe numeric bounds");
  }
  if (!Number.isSafeInteger(metadata.blocks) || metadata.blocks < 0) {
    throw new Error("cleanup target contains allocated-block accounting outside safe numeric bounds");
  }
}

function sameEntryMetadata(left: Stats, right: Stats): boolean {
  return entryKind(left) === entryKind(right)
    && left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.nlink === right.nlink
    && left.uid === right.uid
    && left.gid === right.gid
    && left.rdev === right.rdev
    && left.size === right.size
    && left.mtimeMs === right.mtimeMs
    && left.ctimeMs === right.ctimeMs;
}

function deletionDigestLine(relative: string, kind: ReturnType<typeof entryKind>, metadata: Stats, linkTarget?: string): string {
  return `${JSON.stringify({
    path: relative,
    kind,
    device: metadata.dev,
    inode: metadata.ino,
    mode: metadata.mode,
    links: metadata.nlink,
    owner: metadata.uid,
    group: metadata.gid,
    deviceType: metadata.rdev,
    bytes: kind === "directory" ? null : metadata.size,
    blocks: kind === "directory" ? null : metadata.blocks,
    modifiedMs: kind === "directory" ? null : metadata.mtimeMs,
    changedMs: kind === "directory" || kind === "file" && metadata.nlink > 1 ? null : metadata.ctimeMs,
    ...(linkTarget === undefined ? {} : { linkTarget }),
  })}\n`;
}

function boundedFailure(error: unknown): string | undefined {
  if (error === undefined) return undefined;
  const value = error instanceof Error ? error.message : String(error);
  const bytes = Buffer.from(value, "utf8");
  if (bytes.length <= MAX_CLEANUP_FAILURE_BYTES) return value;
  const suffix = "...[truncated]";
  return `${bytes.subarray(0, MAX_CLEANUP_FAILURE_BYTES - Buffer.byteLength(suffix)).toString("utf8").replace(/\uFFFD+$/u, "")}${suffix}`;
}

async function existingRealDirectory(input: string, label: string): Promise<string> {
  const resolved = path.resolve(input);
  const metadata = await lstat(resolved);
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) throw new Error(`${label} must be a real directory`);
  if (await realpath(resolved) !== resolved) throw new Error(`${label} must be supplied by its canonical path`);
  return resolved;
}

async function pathExists(filename: string): Promise<boolean> {
  try {
    await lstat(filename);
    return true;
  } catch (error) {
    if (errorCode(error) === "ENOENT") return false;
    throw error;
  }
}

async function assertRegularControlFile(root: string, filename: string): Promise<void> {
  const target = safeJoin(root, filename);
  await assertNoSymlinkComponents(root, target);
  const metadata = await lstat(target);
  if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.nlink !== 1 || await realpath(target) !== target) {
    throw new Error("required cleanup control input must remain a single-link canonical regular file");
  }
}

interface ControlFingerprint {
  filename: string;
  bytes: number;
  sha256: string;
}

async function stableControlFingerprint(
  root: string,
  filename: string,
  signal?: AbortSignal,
): Promise<ControlFingerprint> {
  interrupted(signal);
  await assertRegularControlFile(root, filename);
  const target = safeJoin(root, filename);
  const handle = await open(target, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat();
    if (
      !before.isFile()
      || before.nlink !== 1
      || !Number.isSafeInteger(before.size)
      || before.size < 0
      || before.size > MAX_RETAINED_CONTROL_BYTES
    ) throw new Error("retained cleanup control input is not a bounded single-link regular file");
    const digest = createHash("sha256");
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let offset = 0;
    while (offset < before.size) {
      interrupted(signal);
      const read = await handle.read(buffer, 0, Math.min(buffer.length, before.size - offset), offset);
      if (read.bytesRead === 0) throw new Error("retained cleanup control input ended while it was being hashed");
      digest.update(buffer.subarray(0, read.bytesRead));
      offset += read.bytesRead;
    }
    const probe = Buffer.allocUnsafe(1);
    const extra = await handle.read(probe, 0, 1, offset);
    const after = await handle.stat();
    const current = await lstat(target);
    if (
      extra.bytesRead !== 0
      || !after.isFile()
      || after.nlink !== 1
      || before.dev !== after.dev
      || before.ino !== after.ino
      || before.size !== after.size
      || before.mtimeMs !== after.mtimeMs
      || before.ctimeMs !== after.ctimeMs
      || current.isSymbolicLink()
      || !current.isFile()
      || current.nlink !== 1
      || current.dev !== after.dev
      || current.ino !== after.ino
      || current.size !== after.size
      || current.mtimeMs !== after.mtimeMs
      || current.ctimeMs !== after.ctimeMs
      || await realpath(target) !== target
    ) throw new Error("retained cleanup control input changed while it was being hashed");
    return { filename, bytes: after.size, sha256: digest.digest("hex") };
  } finally {
    await handle.close();
  }
}

function digestControlFingerprints(fingerprints: ControlFingerprint[]): string {
  return createHash("sha256").update(JSON.stringify(fingerprints)).digest("hex");
}

async function rootSnapshot(
  root: string,
  records: MountRecord[],
  networkCache: Map<string, Promise<boolean>>,
  label: string,
): Promise<RootSnapshot> {
  const canonical = await existingRealDirectory(root, label);
  const metadata = await lstat(canonical);
  const mounted = mountForPathFrom(records, canonical);
  if (mounted === undefined) throw new Error(`could not determine the mount backing ${label}`);
  const identity = mountIdentity(mounted);
  let network = networkCache.get(identity);
  if (network === undefined) {
    network = filesystemIsNetwork(mounted) ? Promise.resolve(true) : mountIsNetworkBacked(mounted);
    networkCache.set(identity, network);
  }
  if (await network) throw new Error(`${label} must be on a local filesystem and block transport`);
  if (path.resolve(mounted.target) === canonical) throw new Error(`${label} must be a dedicated subdirectory, not a mount root`);
  if (records.some((record) => {
    const target = path.resolve(record.target);
    return target !== canonical && inside(canonical, target);
  })) throw new Error(`${label} must not contain nested mounts`);
  return { path: canonical, device: metadata.dev, inode: metadata.ino, mount: identity };
}

async function assertRootCurrent(expected: RootSnapshot): Promise<void> {
  const records = await mounts();
  const cache = new Map<string, Promise<boolean>>();
  const current = await rootSnapshot(expected.path, records, cache, "protected cleanup directory");
  if (current.device !== expected.device || current.inode !== expected.inode || current.mount !== expected.mount) {
    throw new Error("a protected cleanup directory or its mount changed during verification");
  }
}

async function assertNoOperationLocks(root: string, filenames: readonly string[]): Promise<void> {
  for (const filename of filenames) {
    if (await pathExists(safeJoin(root, filename))) {
      throw new Error("an operation lock already exists; another process may be active or a prior process may have stopped abruptly");
    }
  }
}

async function assertNoCleanupQuarantine(caseRoot: string): Promise<void> {
  const entries = await readDirectoryNamesBounded(caseRoot, 256);
  if (entries.some((entry) => entry.startsWith(CLEANUP_QUARANTINE_PREFIX))) {
    throw new Error("the case contains an unfinished cleanup quarantine; inspect it locally before another cleanup attempt");
  }
}

function retainedSourceRunRoot(caseRoot: string, approvalToken: string): string {
  return safeJoin(caseRoot, RETAINED_SOURCE_DIRECTORY, approvalToken);
}

function sameRootSnapshot(left: RootSnapshot, right: RootSnapshot): boolean {
  return left.path === right.path
    && left.device === right.device
    && left.inode === right.inode
    && left.mount === right.mount;
}

async function directoryContainsIdentity(ancestor: DirectoryIdentity, candidate: DirectoryIdentity): Promise<boolean> {
  let cursor = path.resolve(candidate.path);
  while (true) {
    const metadata = await lstat(cursor);
    if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
      throw new Error("a protected cleanup directory ancestry changed during overlap verification");
    }
    if (metadata.dev === ancestor.device && metadata.ino === ancestor.inode) return true;
    const parent = path.dirname(cursor);
    if (parent === cursor) return false;
    cursor = parent;
  }
}

async function directoryTreesOverlap(left: DirectoryIdentity, right: DirectoryIdentity): Promise<boolean> {
  return await directoryContainsIdentity(left, right) || await directoryContainsIdentity(right, left);
}

async function retainedSourceBaseSnapshot(caseRoot: RootSnapshot): Promise<RootSnapshot | undefined> {
  const base = safeJoin(caseRoot.path, RETAINED_SOURCE_DIRECTORY);
  await assertNoSymlinkComponents(caseRoot.path, base);
  if (!await pathExists(base)) return undefined;
  const records = await mounts();
  const existing = await rootSnapshot(base, records, new Map<string, Promise<boolean>>(), "retained source-file directory");
  if (existing.mount !== caseRoot.mount) {
    throw new Error("retained source-file directory must remain on the recovery case filesystem");
  }
  return existing;
}

async function assertRetainedSourceDestinationAvailable(
  caseRoot: RootSnapshot,
  expectedBase: RootSnapshot | undefined,
  approvalToken: string,
): Promise<void> {
  await assertRootCurrent(caseRoot);
  const currentBase = await retainedSourceBaseSnapshot(caseRoot);
  if (
    (expectedBase === undefined) !== (currentBase === undefined)
    || (expectedBase !== undefined && currentBase !== undefined && !sameRootSnapshot(expectedBase, currentBase))
  ) throw new Error("the retained source-file directory changed after cleanup approval");
  const runRoot = retainedSourceRunRoot(caseRoot.path, approvalToken);
  await assertNoSymlinkComponents(caseRoot.path, runRoot);
  if (await pathExists(runRoot)) throw new Error("the approved retained source-file destination already exists");
  await assertRootCurrent(caseRoot);
  if (expectedBase === undefined) {
    if (await retainedSourceBaseSnapshot(caseRoot) !== undefined) {
      throw new Error("the retained source-file directory changed after cleanup approval");
    }
  } else {
    await assertRootCurrent(expectedBase);
  }
}

function recoveryPlanRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("recovery case contains an invalid plan");
  return value as Record<string, unknown>;
}

async function verifyRecoveryCase(caseRoot: string, signal?: AbortSignal): Promise<VerifiedRecoveryCase> {
  interrupted(signal);
  const retainedControls = [
    "case-sensitive.json",
    "plan-redacted.json",
    "manifest-redacted.json",
    "final-report-sensitive.md",
    "final-report-redacted.md",
  ] as const;
  for (const filename of retainedControls) await assertRegularControlFile(caseRoot, filename);

  const state = await readJson<RecoveryCaseState>(safeJoin(caseRoot, "case-sensitive.json"), MAX_CASE_STATE_BYTES);
  const plan = recoveryPlanRecord(state.plan);
  const status = String(state.status);
  if (
    state.version !== 1
    || !boundedString(state.runId, 256)
    || !RUN_ID.test(state.runId)
    || !["complete", "complete-with-warnings"].includes(status)
    || !boundedString(state.startedAt, 128)
    || !boundedString(state.finishedAt, 128)
    || state.currentStep !== null
    || state.failure !== null
    || !Array.isArray(state.results)
    || plan.version !== 1
    || plan.destination !== caseRoot
    || !Array.isArray(plan.steps)
  ) throw new Error("cleanup requires a terminal successful AARK recovery case");
  if (state.results.length !== plan.steps.length) {
    throw new Error("completed recovery state does not account for every planned stage");
  }
  const stateResults = state.results as unknown[];
  let hasWarnings = false;
  for (let index = 0; index < plan.steps.length; index += 1) {
    const step = recoveryPlanRecord(plan.steps[index]);
    const result = recoveryPlanRecord(stateResults[index]);
    const stepId = step.id;
    const resultStatus = result.status;
    if (
      !boundedString(stepId, 128)
      || !/^[a-z0-9][a-z0-9.-]{0,127}$/.test(stepId)
      || typeof step.optional !== "boolean"
      || result.id !== stepId
      || !["completed", "completed-with-warnings", "failed", "skipped-missing-optional-tool"].includes(String(resultStatus))
      || (resultStatus !== "completed" && step.optional !== true)
    ) throw new Error("completed recovery state contains an invalid or unaccounted stage result");
    if (resultStatus !== "completed") hasWarnings = true;
  }
  if ((status === "complete-with-warnings") !== hasWarnings) {
    throw new Error("completed recovery status does not match its stage outcomes");
  }

  const manifest = await readJson<Record<string, unknown>>(safeJoin(caseRoot, "manifest-redacted.json"));
  const manifestResults = Array.isArray(manifest.results) ? manifest.results : [];
  if (
    manifest.tool !== "aark"
    || manifest.layer !== "recovery"
    || manifest.runId !== state.runId
    || manifest.status !== status
    || manifest.complete !== true
    || manifest.finishedAt !== state.finishedAt
    || manifestResults.length !== stateResults.length
    || manifestResults.some((entry, index) => {
      const result = typeof entry === "object" && entry !== null && !Array.isArray(entry) ? entry as Record<string, unknown> : {};
      const sensitive = recoveryPlanRecord(stateResults[index]);
      return result.id !== sensitive.id || result.status !== sensitive.status;
    })
  ) throw new Error("recovery state and final redacted manifest do not describe the same completed run");

  const fingerprints: ControlFingerprint[] = [];
  for (const filename of retainedControls) {
    interrupted(signal);
    const current = await stableControlFingerprint(caseRoot, filename, signal);
    const perRun = await stableControlFingerprint(caseRoot, path.join("runs", `${state.runId}-${filename === "case-sensitive.json" ? "sensitive.json" : filename}`), signal);
    if (current.bytes !== perRun.bytes || current.sha256 !== perRun.sha256) {
      throw new Error("retained recovery controls do not match the completed run copies");
    }
    fingerprints.push(current);
  }
  return {
    status: status as "complete" | "complete-with-warnings",
    runId: state.runId,
    controlDigest: digestControlFingerprints(fingerprints),
  };
}

function checkpointForState(state: ScanState): NonNullable<SensitiveScanInventory["resumeCheckpoint"]> {
  return {
    runId: state.runId,
    status: state.status,
    inventoryComplete: state.inventoryComplete,
    semantic: { ...state.semantic, inputs: [...state.semantic.inputs] },
    inputRoots: state.inputRoots.map((root) => ({ ...root })),
    manifest: { ...state.manifest },
    cursor: { ...state.cursor },
    progress: { ...state.progress },
  };
}

function fileIsAuthorized(filename: string, roots: ScanState["inputRoots"]): boolean {
  return roots.some((root) => root.kind === "file"
    ? filename === root.path
    : filename !== root.path && inside(root.path, filename));
}

function buildCoverageIndex(roots: ScanState["inputRoots"]): CoverageIndex {
  const files = new Set<string>();
  const directories = new Set<string>();
  for (const root of roots) (root.kind === "file" ? files : directories).add(root.path);
  return { files, directories };
}

function entryIdentity(
  parentDevice: number,
  parentInode: number,
  device: number,
  inode: number,
): string {
  return JSON.stringify([parentDevice, parentInode, device, inode]);
}

async function buildFindingSourceIndex(sourceFiles: string[], signal?: AbortSignal): Promise<FindingSourceIndex> {
  const paths = new Set(sourceFiles);
  const entryIdentities = new Set<string>();
  for (const source of paths) {
    interrupted(signal);
    const metadata = await lstat(source);
    const parent = await lstat(path.dirname(source));
    assertBoundedEntryMetadata(metadata);
    assertBoundedEntryMetadata(parent);
    if (
      metadata.isSymbolicLink()
      || !metadata.isFile()
      || parent.isSymbolicLink()
      || !parent.isDirectory()
      || await realpath(source) !== source
    ) throw new Error("a finding source is no longer a canonical regular file");
    entryIdentities.add(entryIdentity(parent.dev, parent.ino, metadata.dev, metadata.ino));
  }
  return { paths, entryIdentities };
}

function indexedFileIsAuthorized(filename: string, coverage: CoverageIndex): boolean {
  if (coverage.files.has(filename)) return true;
  let cursor = path.dirname(filename);
  while (true) {
    if (coverage.directories.has(cursor)) return true;
    const parent = path.dirname(cursor);
    if (parent === cursor) return false;
    cursor = parent;
  }
}

function assertCompletedInventoryMatchesState(inventory: SensitiveScanInventory, state: ScanState): void {
  const occurrences = inventory.findings.reduce((sum, finding) => sum + finding.occurrences.length, 0);
  const artifactFiles = inventory.findings.reduce((sum, finding) => sum + finding.artifactFiles.length, 0);
  if (
    state.status !== "complete"
    || state.resumable
    || !state.inventoryComplete
    || state.pauseReason !== undefined
    || state.cursor.fileIndex !== state.manifest.entries
    || state.cursor.phase !== "stream"
    || state.cursor.nextOffset !== 0
    || state.progress.phase !== "finalizing"
    || state.progress.filesTotal !== state.manifest.entries
    || state.progress.filesVisited !== state.manifest.entries
    || state.progress.filesScanned !== state.manifest.entries
    || state.progress.scanErrors !== 0
    || inventory.status !== "complete"
    || inventory.complete !== true
    || inventory.outputRoot !== state.semantic.output
    || !isDeepStrictEqual(inventory.inputRoots, state.semantic.inputs)
    || inventory.findings.length !== state.progress.uniqueFindings
    || occurrences !== state.progress.occurrences
    || inventory.errors.length !== 0
    || inventory.errorsOmitted !== 0
    || inventory.failureMessage !== undefined
    || inventory.resumeCheckpoint === undefined
    || !isDeepStrictEqual(inventory.resumeCheckpoint, checkpointForState(state))
    || inventory.findings.some((finding) => finding.occurrences.some((occurrence) => (
      occurrence.provenance !== state.semantic.provenance
      || !fileIsAuthorized(occurrence.sourcePath, state.inputRoots)
    )))
    || !Number.isSafeInteger(artifactFiles)
  ) throw new Error("cleanup requires an exact error-free completed mining checkpoint");
}

async function assertInputRootsCurrent(state: ScanState, signal?: AbortSignal): Promise<void> {
  const records = await mounts();
  const networkCache = new Map<string, Promise<boolean>>();
  for (const expected of state.inputRoots) {
    interrupted(signal);
    if (path.resolve(expected.path) !== expected.path) throw new Error("completed mining input root is not canonical");
    const metadata = await lstat(expected.path);
    if (metadata.isSymbolicLink() || (expected.kind === "file" ? !metadata.isFile() : !metadata.isDirectory())) {
      throw new Error("completed mining input root changed kind");
    }
    if (await realpath(expected.path) !== expected.path) throw new Error("completed mining input root changed canonical path");
    const mounted = mountForPathFrom(records, expected.path);
    if (mounted === undefined) throw new Error("could not determine the mount backing a completed mining input");
    const identity = mountIdentity(mounted);
    let network = networkCache.get(identity);
    if (network === undefined) {
      network = filesystemIsNetwork(mounted) ? Promise.resolve(true) : mountIsNetworkBacked(mounted);
      networkCache.set(identity, network);
    }
    if (
      metadata.dev !== expected.device
      || metadata.ino !== expected.inode
      || identity !== expected.mount
      || await network
    ) throw new Error("completed mining input root identity or mount changed after scanning");
  }
}

function sameWalkedFile(left: WalkedFile, right: WalkedFile): boolean {
  return left.path === right.path
    && left.bytes === right.bytes
    && left.device === right.device
    && left.inode === right.inode
    && left.modifiedMs === right.modifiedMs
    && left.changedMs === right.changedMs;
}

async function verifyLiveManifest(state: ScanState, output: string, ignoredPaths: Set<string>, signal?: AbortSignal): Promise<void> {
  await assertInputRootsCurrent(state, signal);
  const expected = readScanManifest(output, state.manifest, signal)[Symbol.asyncIterator]();
  const networkCache = new Map<string, Promise<boolean>>();
  const walked = walkRegularFiles(state.semantic.inputs, {
    ...(signal === undefined ? {} : { signal }),
    onError: (_source, error) => { throw new Error("a completed mining input can no longer be enumerated exactly", { cause: error }); },
    shouldEnterDirectory: async (directory) => {
      const records = await mounts();
      const mounted = mountForPathFrom(records, directory);
      if (mounted === undefined) return false;
      const identity = mountIdentity(mounted);
      let network = networkCache.get(identity);
      if (network === undefined) {
        network = filesystemIsNetwork(mounted) ? Promise.resolve(true) : mountIsNetworkBacked(mounted);
        networkCache.set(identity, network);
      }
      return !(await network);
    },
  })[Symbol.asyncIterator]();
  const nextLive = async (): Promise<IteratorResult<WalkedFile>> => {
    while (true) {
      const next = await walked.next();
      if (next.done === true || !ignoredPaths.has(next.value.path)) return next;
    }
  };
  try {
    while (true) {
      interrupted(signal);
      const expectedEntry = await expected.next();
      const liveEntry = await nextLive();
      if (expectedEntry.done === true || liveEntry.done === true) {
        if (expectedEntry.done !== liveEntry.done) throw new Error("completed mining input file set changed after scanning");
        break;
      }
      if (!sameWalkedFile(expectedEntry.value, liveEntry.value)) {
        throw new Error("completed mining input file identity, size, time, or order changed after scanning");
      }
      const records = await mounts();
      const mounted = mountForPathFrom(records, liveEntry.value.path);
      if (mounted === undefined) throw new Error("could not determine the mount backing a completed mining file");
      const identity = mountIdentity(mounted);
      let network = networkCache.get(identity);
      if (network === undefined) {
        network = filesystemIsNetwork(mounted) ? Promise.resolve(true) : mountIsNetworkBacked(mounted);
        networkCache.set(identity, network);
      }
      if (await network) throw new Error("a completed mining file moved onto a network-backed mount");
    }
  } finally {
    await expected.return?.(undefined);
    await walked.return?.(undefined);
  }
  await assertInputRootsCurrent(state, signal);
}

async function verifyMiningOutput(
  root: RootSnapshot,
  signal?: AbortSignal,
): Promise<VerifiedMiningOutput> {
  interrupted(signal);
  for (const filename of [
    "scan-state-sensitive.json",
    "scan-files-sensitive.ndjson",
    "inventory-sensitive.json",
    "manifest-redacted.json",
    "final-report-sensitive.md",
    "final-report-redacted.md",
  ]) await assertRegularControlFile(root.path, filename);
  const state = await loadScanState(root.path, signal);
  const inventory = await loadCompletedInventory(root.path, state.inventory, signal);
  assertCompletedInventoryMatchesState(inventory, state);
  await verifyResumeArtifacts(root.path, inventory, signal);
  await assertRootCurrent(root);
  const controlFingerprints: ControlFingerprint[] = [];
  for (const filename of [
    "scan-state-sensitive.json",
    "inventory-sensitive.json",
    "manifest-redacted.json",
    "final-report-sensitive.md",
    "final-report-redacted.md",
  ]) controlFingerprints.push(await stableControlFingerprint(root.path, filename, signal));
  return {
    root,
    state,
    scannedFiles: state.manifest.entries,
    findings: inventory.findings.length,
    markerOnlyFindings: inventory.findings.filter((finding) => finding.confidence === "marker-only").length,
    artifactFiles: inventory.findings.reduce((sum, finding) => sum + finding.artifactFiles.length, 0),
    sourceFiles: [...new Set(inventory.findings.flatMap((finding) => finding.occurrences.map((occurrence) => occurrence.sourcePath)))].sort(bytewiseLexical),
    controlDigest: digestControlFingerprints(controlFingerprints),
  };
}

async function targetSnapshot(
  caseRoot: RootSnapshot,
  name: TargetSnapshot["name"],
  requiresScanCoverage: boolean,
  coverage: CoverageIndex,
  findingSources: FindingSourceIndex,
  signal?: AbortSignal,
  explicitTarget?: string,
  coveragePathRoot?: string,
): Promise<TargetSnapshot | undefined> {
  interrupted(signal);
  const target = explicitTarget === undefined ? safeJoin(caseRoot.path, name) : safeJoin(caseRoot.path, path.relative(caseRoot.path, explicitTarget));
  let before: Awaited<ReturnType<typeof lstat>>;
  try {
    before = await lstat(target);
  } catch (error) {
    if (errorCode(error) === "ENOENT") return undefined;
    throw error;
  }
  if (before.isSymbolicLink() || !before.isDirectory() || await realpath(target) !== target) {
    throw new Error("cleanup deletion targets must remain real canonical directories");
  }
  let filesystemEntries = 0n;
  let regularFiles = 0n;
  let logicalBytes = 0n;
  let allocatedBytes = 0n;
  let minimumReclaimableAllocatedBytes = 0n;
  const allocatedIdentities = new Set<string>();
  const hardLinkAllocations = new Map<string, HardLinkAllocation>();
  const retainedSourceFiles: RetainedSourceFile[] = [];
  const directoryIdentities = new Map<string, { device: number; inode: number }>();
  const contentHash = createHash("sha256");
  const deletionHash = createHash("sha256");
  type Work = { phase: "enter"; filename: string } | { phase: "exit"; filename: string; relative: string; before: Stats };
  const pending: Work[] = [{ phase: "enter", filename: target }];
  let pendingEntries = 1;
  let directories = 0;
  const targetMounts = await mounts();
  while (pending.length > 0) {
    interrupted(signal);
    const work = pending.pop();
    if (work === undefined) break;
    if (work.phase === "exit") {
      const afterDirectory = await lstat(work.filename);
      assertBoundedEntryMetadata(afterDirectory);
      if (!sameEntryMetadata(work.before, afterDirectory)) {
        throw new Error("cleanup deletion target changed while it was being measured");
      }
      if (work.filename !== target) {
        contentHash.update(`${JSON.stringify({
          path: work.relative,
          kind: "directory",
          device: afterDirectory.dev,
          inode: afterDirectory.ino,
          mode: afterDirectory.mode,
          links: afterDirectory.nlink,
          owner: afterDirectory.uid,
          group: afterDirectory.gid,
          bytes: afterDirectory.size,
          modifiedMs: afterDirectory.mtimeMs,
          changedMs: afterDirectory.ctimeMs,
        })}\n`);
        deletionHash.update(deletionDigestLine(work.relative, "directory", afterDirectory));
      }
      continue;
    }

    pendingEntries -= 1;
    const metadata = await lstat(work.filename);
    assertBoundedEntryMetadata(metadata);
    const relative = path.relative(target, work.filename);
    const kind = entryKind(metadata);
    const allocationIdentity = `${metadata.dev}:${metadata.ino}`;
    const entryAllocatedBytes = BigInt(metadata.blocks) * 512n;
    if (kind === "file" && metadata.nlink > 1) {
      const existing = hardLinkAllocations.get(allocationIdentity);
      if (existing === undefined) {
        hardLinkAllocations.set(allocationIdentity, {
          device: metadata.dev,
          inode: metadata.ino,
          allocatedBytes: entryAllocatedBytes,
          links: metadata.nlink,
          selectedLinks: 1,
        });
      } else {
        if (existing.allocatedBytes !== entryAllocatedBytes || existing.links !== metadata.nlink) {
          throw new Error("cleanup target hard-link metadata changed during verification");
        }
        existing.selectedLinks += 1;
        if (existing.selectedLinks > existing.links) throw new Error("cleanup target contains more hard links than the inode reports");
      }
    }
    if (!allocatedIdentities.has(allocationIdentity)) {
      allocatedIdentities.add(allocationIdentity);
      allocatedBytes += entryAllocatedBytes;
      if (kind !== "file" || metadata.nlink === 1) minimumReclaimableAllocatedBytes += entryAllocatedBytes;
    }
    if (work.filename !== target) filesystemEntries += 1n;

    if (kind === "directory") {
      directoryIdentities.set(work.filename, { device: metadata.dev, inode: metadata.ino });
      directories += 1;
      if (directories > MAX_WALK_DIRECTORIES) {
        throw new Error(`cleanup target exceeds the ${MAX_WALK_DIRECTORIES}-directory verification limit`);
      }
      const mounted = mountForPathFrom(targetMounts, work.filename);
      if (mounted === undefined || mountIdentity(mounted) !== caseRoot.mount) {
        throw new Error("cleanup target crosses a mount boundary");
      }
      const directory = await opendir(work.filename);
      const children: string[] = [];
      try {
        for await (const entry of directory) {
          interrupted(signal);
          if (children.length >= MAX_WALK_DIRECTORY_ENTRIES) {
            throw new Error(`cleanup target directory exceeds the ${MAX_WALK_DIRECTORY_ENTRIES}-entry verification limit`);
          }
          children.push(path.join(work.filename, entry.name));
        }
      } finally {
        await directory.close().catch((error: unknown) => {
          if (errorCode(error) !== "ERR_DIR_CLOSED") throw error;
        });
      }
      if (pendingEntries + children.length > MAX_WALK_PENDING_ENTRIES) {
        throw new Error(`cleanup target exceeds the ${MAX_WALK_PENDING_ENTRIES}-entry verification frontier limit`);
      }
      pendingEntries += children.length;
      children.sort((left, right) => bytewiseLexical(right, left));
      pending.push({ phase: "exit", filename: work.filename, relative, before: metadata });
      for (const child of children) pending.push({ phase: "enter", filename: child });
      continue;
    }

    let linkTarget: string | undefined;
    if (kind === "symlink") linkTarget = await readlink(work.filename);
    const current = await lstat(work.filename);
    assertBoundedEntryMetadata(current);
    if (!sameEntryMetadata(metadata, current)) {
      throw new Error("cleanup deletion target changed while it was being measured");
    }
    let retained = false;
    if (kind === "file") {
      regularFiles += 1n;
      logicalBytes += BigInt(metadata.size);
      const coveragePath = coveragePathRoot === undefined
        ? work.filename
        : path.join(coveragePathRoot, relative);
      if (requiresScanCoverage && !indexedFileIsAuthorized(coveragePath, coverage)) {
        throw new Error("at least one recovered-data file is not covered by an error-free completed mining scan");
      }
      const parentIdentity = directoryIdentities.get(path.dirname(work.filename));
      if (parentIdentity === undefined) {
        throw new Error("cleanup target traversal lost a parent-directory identity");
      }
      if (
        findingSources.paths.has(coveragePath)
        || findingSources.entryIdentities.has(entryIdentity(
          parentIdentity.device,
          parentIdentity.inode,
          metadata.dev,
          metadata.ino,
        ))
      ) {
        retained = true;
        retainedSourceFiles.push({
          originalPath: coveragePath,
          relativePath: relative,
          device: metadata.dev,
          inode: metadata.ino,
          mode: metadata.mode,
          links: metadata.nlink,
          bytes: metadata.size,
          allocatedBytes: entryAllocatedBytes,
          modifiedMs: metadata.mtimeMs,
          changedMs: metadata.ctimeMs,
        });
      }
    }
    contentHash.update(`${JSON.stringify({
      path: relative,
      kind,
      device: metadata.dev,
      inode: metadata.ino,
      mode: metadata.mode,
      links: metadata.nlink,
      owner: metadata.uid,
      group: metadata.gid,
      deviceType: metadata.rdev,
      bytes: metadata.size,
      modifiedMs: metadata.mtimeMs,
      changedMs: metadata.ctimeMs,
      ...(linkTarget === undefined ? {} : { linkTarget }),
    })}\n`);
    if (!retained) deletionHash.update(deletionDigestLine(relative, kind, metadata, linkTarget));
  }
  const after = await lstat(target);
  if (
    after.isSymbolicLink()
    || !after.isDirectory()
    || before.dev !== after.dev
    || before.ino !== after.ino
    || before.mtimeMs !== after.mtimeMs
    || before.ctimeMs !== after.ctimeMs
    || await realpath(target) !== target
  ) throw new Error("cleanup deletion target changed while it was being measured");
  return {
    name,
    path: target,
    device: after.dev,
    inode: after.ino,
    modifiedMs: after.mtimeMs,
    changedMs: after.ctimeMs,
    filesystemEntries,
    regularFiles,
    logicalBytes,
    allocatedBytes,
    minimumReclaimableAllocatedBytes,
    hardLinkAllocations: [...hardLinkAllocations.values()]
      .sort((left, right) => left.device - right.device || left.inode - right.inode),
    contentDigest: contentHash.digest("hex"),
    deletionDigest: deletionHash.digest("hex"),
    requiresScanCoverage,
    retainedSourceFiles,
  };
}

function targetIdentity(target: TargetSnapshot): Record<string, unknown> {
  return {
    name: target.name,
    path: target.path,
    device: target.device,
    inode: target.inode,
    modifiedMs: target.modifiedMs,
    changedMs: target.changedMs,
    filesystemEntries: target.filesystemEntries.toString(),
    regularFiles: target.regularFiles.toString(),
    logicalBytes: target.logicalBytes.toString(),
    allocatedBytes: target.allocatedBytes.toString(),
    minimumReclaimableAllocatedBytes: target.minimumReclaimableAllocatedBytes.toString(),
    hardLinkAllocations: target.hardLinkAllocations.map((allocation) => ({ ...allocation, allocatedBytes: allocation.allocatedBytes.toString() })),
    contentDigest: target.contentDigest,
    deletionDigest: target.deletionDigest,
    requiresScanCoverage: target.requiresScanCoverage,
    retainedSourceFiles: target.retainedSourceFiles.map((source) => ({ ...source, allocatedBytes: source.allocatedBytes.toString() })),
  };
}

function approvalToken(
  caseRoot: RootSnapshot,
  retainedSourceBase: RootSnapshot | undefined,
  recovery: VerifiedRecoveryCase,
  mining: VerifiedMiningOutput[],
  targets: TargetSnapshot[],
  includeEvidence: boolean,
  allocationUnitBytes: bigint,
  retentionMetadataReserveBytes: bigint,
): string {
  const material = {
    version: 1,
    case: { ...caseRoot, recovery },
    retainedSourceBase: retainedSourceBase ?? null,
    includeEvidence,
    allocationUnitBytes: allocationUnitBytes.toString(),
    retentionMetadataReserveBytes: retentionMetadataReserveBytes.toString(),
    mining: mining.map((item) => ({
      root: item.root,
      runId: item.state.runId,
      manifest: item.state.manifest,
      inventory: item.state.inventory,
      progress: item.state.progress,
      controlDigest: item.controlDigest,
    })),
    targets: targets.map(targetIdentity),
  };
  const serialized = JSON.stringify(material);
  if (Buffer.byteLength(serialized) > MAX_RETAINED_CONTROL_BYTES) {
    throw new Error("cleanup approval control state exceeds its bounded size; split the cleanup target set");
  }
  return createHash("sha256").update(serialized).digest("hex");
}

function normalizeOptions(options: CleanupOptions): { caseDirectory: string; miningOutputs: string[]; includeEvidence: boolean; signal?: AbortSignal } {
  if (options.miningOutputs.length < 1 || options.miningOutputs.length > MAX_CLEANUP_MINING_OUTPUTS) {
    throw new Error(`cleanup requires from 1 through ${MAX_CLEANUP_MINING_OUTPUTS} completed mining output directories`);
  }
  const caseDirectory = path.resolve(options.caseDirectory);
  const miningOutputs = [...new Set(options.miningOutputs.map((value) => path.resolve(value)))].sort(bytewiseLexical);
  if (miningOutputs.length !== options.miningOutputs.length) throw new Error("cleanup mining output directories must be unique");
  if (miningOutputs.some((output) => output === caseDirectory)) throw new Error("a mining output cannot also be the recovery case root");
  const outputSet = new Set(miningOutputs);
  for (const output of miningOutputs) {
    let parent = path.dirname(output);
    while (parent !== output) {
      if (outputSet.has(parent)) throw new Error("cleanup mining output directories must not contain one another");
      const next = path.dirname(parent);
      if (next === parent) break;
      parent = next;
    }
  }
  return {
    caseDirectory,
    miningOutputs,
    includeEvidence: options.includeEvidence === true,
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  };
}

async function resolveCleanupOptions(options: CleanupOptions): Promise<{
  normalized: ReturnType<typeof normalizeOptions>;
  batchRoots: string[];
}> {
  const references = normalizeOptions(options);
  const resolved = await resolveMiningOutputs(references.miningOutputs, MAX_CLEANUP_MINING_OUTPUTS);
  const directOutputs = resolved.outputs.filter((output) => !resolved.batchRoots.some((root) => inside(root, output)));
  if (directOutputs.length > 128) throw new Error("cleanup supports at most 128 independent mining outputs; use native batch workflow roots for larger sets");
  return {
    normalized: normalizeOptions({
      caseDirectory: references.caseDirectory,
      miningOutputs: resolved.outputs,
      includeEvidence: references.includeEvidence,
      ...(references.signal === undefined ? {} : { signal: references.signal }),
    }),
    batchRoots: resolved.batchRoots,
  };
}

async function buildInternalPlan(options: CleanupOptions, heldLocks?: ExclusiveLock[], batchRoots: string[] = []): Promise<InternalCleanupPlan> {
  const normalized = normalizeOptions(options);
  interrupted(normalized.signal);
  const records = await mounts();
  const networkCache = new Map<string, Promise<boolean>>();
  const caseRoot = await rootSnapshot(normalized.caseDirectory, records, networkCache, "recovery case root");
  await assertNoCleanupQuarantine(caseRoot.path);
  const retainedSourceBasePath = safeJoin(caseRoot.path, RETAINED_SOURCE_DIRECTORY);
  const miningRoots: RootSnapshot[] = [];
  for (const output of normalized.miningOutputs) {
    miningRoots.push(await rootSnapshot(output, records, networkCache, "mining output"));
  }
  for (const root of miningRoots) {
    if (inside(retainedSourceBasePath, root.path) || inside(root.path, retainedSourceBasePath)) {
      throw new Error("a retained mining output overlaps the reserved retained source-file directory");
    }
    for (const name of ["recovery", "evidence", "logs", "runs"] as const) {
      const target = safeJoin(caseRoot.path, name);
      if (inside(target, root.path) || inside(root.path, target)) {
        throw new Error("a retained mining output overlaps an AARK-managed cleanup deletion target");
      }
    }
  }
  if (heldLocks === undefined) {
    await assertNoOperationLocks(caseRoot.path, RECOVERY_LOCK_FILENAMES);
    for (const root of miningRoots) await assertNoOperationLocks(root.path, MINING_LOCK_FILENAMES);
    for (const root of batchRoots) await assertNoOperationLocks(root, [BATCH_LOCK_FILENAME]);
  } else {
    for (const lock of heldLocks) await lock.assertHeld();
  }
  // Exclude only lock inodes this cleanup invocation actually owns. Batch
  // cleanup intentionally holds the parent controller lock rather than tens
  // of thousands of child locks; an unexpected child mining lock must remain
  // visible to exact live-manifest verification.
  const introducedLocks = new Set<string>(heldLocks?.map((lock) => lock.path) ?? []);

  const recoveryCase = await verifyRecoveryCase(caseRoot.path, normalized.signal);
  const mining: VerifiedMiningOutput[] = [];
  for (const root of miningRoots) mining.push(await verifyMiningOutput(root, normalized.signal));
  const coverage = buildCoverageIndex(mining.flatMap((item) => item.state.inputRoots));
  const findingSources = await buildFindingSourceIndex(
    mining.flatMap((item) => item.sourceFiles),
    normalized.signal,
  );

  const targets: TargetSnapshot[] = [];
  const recovery = await targetSnapshot(caseRoot, "recovery", true, coverage, findingSources, normalized.signal);
  if (recovery !== undefined) targets.push(recovery);
  const evidencePresent = await pathExists(safeJoin(caseRoot.path, "evidence"));
  if (normalized.includeEvidence) {
    const evidence = await targetSnapshot(caseRoot, "evidence", true, coverage, findingSources, normalized.signal);
    if (evidence !== undefined) targets.push(evidence);
  }
  for (const name of ["logs", "runs"] as const) {
    const target = await targetSnapshot(caseRoot, name, false, coverage, findingSources, normalized.signal);
    if (target !== undefined) targets.push(target);
  }
  if (recovery === undefined && !targets.some((target) => target.name === "evidence")) {
    throw new Error("the completed case has no selected recovered-data copy to clean up");
  }
  const retainedPaths = new Set(targets.flatMap((target) => target.retainedSourceFiles.map((source) => source.originalPath)));
  for (const source of findingSources.paths) {
    if (targets.some((target) => source !== target.path && inside(target.path, source)) && !retainedPaths.has(source)) {
      throw new Error("a finding-containing source file selected for cleanup could not be retained intact");
    }
  }
  for (const root of miningRoots) {
    for (const target of targets) {
      if (await directoryTreesOverlap(root, target)) {
        throw new Error("a retained mining output aliases an AARK-managed cleanup deletion target");
      }
    }
  }
  // Make the exact live-manifest comparison the final input-data pass. This
  // catches a selected file that changes while its cleanup snapshot is being
  // built without doubling the full input walk for multi-terabyte scans.
  for (const item of mining) {
    await verifyLiveManifest(item.state, item.root.path, introducedLocks, normalized.signal);
    await assertRootCurrent(item.root);
  }
  await assertRootCurrent(caseRoot);
  for (const root of miningRoots) await assertRootCurrent(root);
  if (heldLocks !== undefined) {
    for (const lock of heldLocks) await lock.assertHeld();
  } else {
    await assertNoOperationLocks(caseRoot.path, RECOVERY_LOCK_FILENAMES);
    for (const root of miningRoots) await assertNoOperationLocks(root.path, MINING_LOCK_FILENAMES);
  }

  const scannedFiles = mining.reduce((sum, item) => sum + BigInt(item.scannedFiles), 0n);
  const findings = mining.reduce((sum, item) => sum + BigInt(item.findings), 0n);
  const markerOnlyFindings = mining.reduce((sum, item) => sum + BigInt(item.markerOnlyFindings), 0n);
  const artifacts = mining.reduce((sum, item) => sum + BigInt(item.artifactFiles), 0n);
  const retainedSources = targets.flatMap((target) => target.retainedSourceFiles);
  const retainedSourceFiles = BigInt(retainedSources.length);
  const retainedSourceBytes = retainedSources.reduce((sum, source) => sum + BigInt(source.bytes), 0n);
  const deletedEntries = targets.reduce((sum, target) => sum + target.filesystemEntries - BigInt(target.retainedSourceFiles.length), 0n);
  const deletedFiles = targets.reduce((sum, target) => sum + target.regularFiles - BigInt(target.retainedSourceFiles.length), 0n);
  const deletedBytes = targets.reduce(
    (sum, target) => sum + target.logicalBytes - target.retainedSourceFiles.reduce((retained, source) => retained + BigInt(source.bytes), 0n),
    0n,
  );
  let maximumReclaimableAllocatedBytes = targets.reduce((sum, target) => sum + target.allocatedBytes, 0n);
  let minimumBeforeMetadata = targets.reduce((sum, target) => sum + target.minimumReclaimableAllocatedBytes, 0n);
  const crossTargetHardLinks = new Map<string, HardLinkAllocation>();
  for (const target of targets) {
    for (const allocation of target.hardLinkAllocations) {
      const identity = `${allocation.device}:${allocation.inode}`;
      const existing = crossTargetHardLinks.get(identity);
      if (existing !== undefined) {
        throw new Error("hard links spanning separate cleanup targets cannot be deleted safely in sequence; rebuild the case without cross-target hard links");
      }
      crossTargetHardLinks.set(identity, allocation);
      if (allocation.selectedLinks < allocation.links) {
        maximumReclaimableAllocatedBytes -= allocation.allocatedBytes;
      } else {
        minimumBeforeMetadata += allocation.allocatedBytes;
      }
    }
  }
  const retainedAllocationIdentities = new Set<string>();
  for (const source of retainedSources) {
    const identity = `${source.device}:${source.inode}`;
    if (retainedAllocationIdentities.has(identity)) continue;
    retainedAllocationIdentities.add(identity);
    const hardLink = crossTargetHardLinks.get(identity);
    if (hardLink === undefined || hardLink.selectedLinks === hardLink.links) {
      maximumReclaimableAllocatedBytes -= source.allocatedBytes;
      minimumBeforeMetadata -= source.allocatedBytes;
    }
  }
  const allocationUnitBytes = (await statfs(caseRoot.path, { bigint: true })).bsize;
  if (allocationUnitBytes < 1n) throw new Error("cleanup filesystem reported an invalid allocation unit");
  const retainedDirectories = new Set<string>();
  for (const target of targets) {
    if (target.retainedSourceFiles.length > 0) retainedDirectories.add(target.name);
    for (const source of target.retainedSourceFiles) {
      let parent = path.dirname(source.relativePath);
      while (parent !== "." && parent !== path.parse(parent).root) {
        retainedDirectories.add(`${target.name}:${parent}`);
        const next = path.dirname(parent);
        if (next === parent) break;
        parent = next;
      }
    }
  }
  const roundedAllocation = (bytes: number): bigint => (BigInt(bytes) + allocationUnitBytes - 1n) / allocationUnitBytes * allocationUnitBytes;
  const sensitiveReportEstimate = Buffer.byteLength(JSON.stringify({
    caseDirectory: caseRoot.path,
    miningOutputs: miningRoots.map((root) => root.path),
    selectedDirectories: targets.map((target) => target.path),
    retainedDirectory: retainedSourceRunRoot(caseRoot.path, "0".repeat(64)),
  })) + 64 * 1024;
  const reportAllocationReserve = roundedAllocation(sensitiveReportEstimate)
    + 2n * roundedAllocation(64 * 1024);
  const retentionMetadataReserve = BigInt(retainedSources.length + retainedDirectories.size + 4) * allocationUnitBytes
    + reportAllocationReserve;
  const minimumReclaimableAllocatedBytes = minimumBeforeMetadata > retentionMetadataReserve
    ? minimumBeforeMetadata - retentionMetadataReserve
    : 0n;
  const deletableTargetBytes = (target: TargetSnapshot | undefined): bigint => target === undefined
    ? 0n
    : target.logicalBytes - target.retainedSourceFiles.reduce((sum, source) => sum + BigInt(source.bytes), 0n);
  const recoveredBytes = deletableTargetBytes(targets.find((target) => target.name === "recovery"));
  const evidenceBytes = deletableTargetBytes(targets.find((target) => target.name === "evidence"));
  const intermediateBytes = targets
    .filter((target) => target.name === "logs" || target.name === "runs")
    .reduce((sum, target) => sum + deletableTargetBytes(target), 0n);
  const retainedSourceBase = await retainedSourceBaseSnapshot(caseRoot);
  for (const root of miningRoots) {
    if (
      await directoryContainsIdentity(root, caseRoot)
      || (retainedSourceBase !== undefined && await directoryTreesOverlap(root, retainedSourceBase))
    ) throw new Error("a retained mining output aliases the reserved retained source-file directory");
  }
  const token = approvalToken(
    caseRoot,
    retainedSourceBase,
    recoveryCase,
    mining,
    targets,
    normalized.includeEvidence,
    allocationUnitBytes,
    retentionMetadataReserve,
  );
  if (retainedSourceFiles > 0n) {
    await assertRetainedSourceDestinationAvailable(caseRoot, retainedSourceBase, token);
  }
  const publicPlan: CleanupPlanResult = {
    version: 1,
    tool: "aark",
    layer: "cleanup",
    status: "ready",
    destructive: true,
    valuesPrinted: false,
    pathsRedacted: true,
    recoveryStatus: recoveryCase.status,
    miningScansVerified: mining.length,
    scannedFilesVerified: scannedFiles.toString(),
    findingsRetained: findings.toString(),
    markerOnlyFindingsWithoutArtifacts: markerOnlyFindings.toString(),
    artifactFilesRetained: artifacts.toString(),
    sourceFilesRetained: retainedSourceFiles.toString(),
    sourceFileLogicalBytesRetained: retainedSourceBytes.toString(),
    deletion: {
      directories: targets.length,
      filesystemEntries: deletedEntries.toString(),
      regularFiles: deletedFiles.toString(),
      logicalBytes: deletedBytes.toString(),
      allocatedBytes: maximumReclaimableAllocatedBytes.toString(),
      expectedFreeSpaceGainMinimumBytes: minimumReclaimableAllocatedBytes.toString(),
      expectedFreeSpaceGainMaximumBytes: maximumReclaimableAllocatedBytes.toString(),
      allocationUnitBytes: allocationUnitBytes.toString(),
      allocationUnitSource: "statfs-block-size",
      recoveredCopyLogicalBytes: recoveredBytes.toString(),
      evidenceCopyLogicalBytes: evidenceBytes.toString(),
      intermediateLogicalBytes: intermediateBytes.toString(),
      recoveredCopyIncluded: recovery !== undefined,
      evidenceCopyIncluded: targets.some((target) => target.name === "evidence"),
      evidenceCopyPresent: evidencePresent,
      intermediateLogsAndRunsIncluded: targets.some((target) => target.name === "logs" || target.name === "runs"),
    },
    retained: {
      recoveryFinalReports: true,
      cleanupFinalReports: true,
      miningFinalReports: true,
      exactFindingArtifacts: true,
      wholeFindingSourceFiles: true,
      minimalIntegrityMetadata: true,
      evidenceCopy: evidencePresent && !targets.some((target) => target.name === "evidence"),
    },
    approvalToken: token,
    approvalRequired: true,
    requirements: [
      "Show this aggregate, path-redacted plan to the end user and obtain explicit approval before cleanup run.",
      "Pass the exact approval token plus --execute and --confirm-delete-recovered-copy.",
      "Keep every complete source file associated with a mining finding in the dedicated retained source-file tree.",
      ...(markerOnlyFindings > 0n ? ["Marker-only findings have no exact exported artifact; their complete containing files are retained, but review them before cleanup if neighboring directory context is needed."] : []),
      ...(normalized.includeEvidence ? ["Deleting the evidence copy additionally requires --confirm-delete-evidence."] : []),
    ],
  };
  return {
    public: publicPlan,
    caseRoot,
    retainedSourceBase,
    recovery: recoveryCase,
    mining,
    coverage,
    findingSources,
    targets,
    introducedLocks,
    batchRoots,
    retentionMetadataReserveBytes: retentionMetadataReserve,
  };
}

export async function planCleanup(options: CleanupOptions): Promise<CleanupPlanResult> {
  const resolved = await resolveCleanupOptions(options);
  return (await buildInternalPlan(resolved.normalized, undefined, resolved.batchRoots)).public;
}

function reportText(
  plan: InternalCleanupPlan,
  status: "authorized-in-progress" | "complete" | "failed-partial" | "interrupted-partial",
  completedTargets: string[],
  failure?: unknown,
): { sensitive: string; redacted: string; manifest: Record<string, unknown> } {
  const generatedAt = new Date().toISOString();
  const failureMessage = boundedFailure(failure);
  const common = [
    `- Status: ${status}`,
    `- Generated: ${generatedAt}`,
    `- Approved plan token: ${plan.public.approvalToken}`,
    `- Completed deletions: ${completedTargets.length} of ${plan.targets.length} selected directories`,
    `- Planned filesystem entries: ${plan.public.deletion.filesystemEntries}`,
    `- Planned regular files: ${plan.public.deletion.regularFiles}`,
    `- Planned logical bytes: ${plan.public.deletion.logicalBytes}`,
    `- Planned allocated bytes: ${plan.public.deletion.allocatedBytes}`,
    `- Expected free-space gain: ${plan.public.deletion.expectedFreeSpaceGainMinimumBytes} through ${plan.public.deletion.expectedFreeSpaceGainMaximumBytes} bytes`,
    `- Filesystem allocation unit: ${plan.public.deletion.allocationUnitBytes} bytes (${plan.public.deletion.allocationUnitSource})`,
    `- Mining scans verified: ${plan.public.miningScansVerified}`,
    `- Exact finding artifacts retained: ${plan.public.artifactFilesRetained}`,
    `- Whole finding-containing source files retained: ${plan.public.sourceFilesRetained}`,
    `- Whole source-file logical bytes retained: ${plan.public.sourceFileLogicalBytesRetained}`,
    `- Marker-only findings without artifacts: ${plan.public.markerOnlyFindingsWithoutArtifacts}`,
  ];
  const sensitive = [
    "# AARK cleanup final report",
    "",
    "> Sensitive local report: it records local case, mining-output, and deletion paths. Do not publish it.",
    "",
    ...common,
    `- Recovery case: \`${JSON.stringify(plan.caseRoot.path).replace(/`/g, "\\u0060")}\``,
    `- Retained mining outputs: ${plan.mining.map((item) => `\`${JSON.stringify(item.root.path).replace(/`/g, "\\u0060")}\``).join(", ")}`,
    ...(plan.public.sourceFilesRetained === "0" ? [] : [
      `- Retained whole-source root: \`${JSON.stringify(retainedSourceRunRoot(plan.caseRoot.path, plan.public.approvalToken)).replace(/`/g, "\\u0060")}\``,
    ]),
    `- Selected directories: ${plan.targets.map((target) => `\`${JSON.stringify(target.path).replace(/`/g, "\\u0060")}\``).join(", ")}`,
    `- Completely removed directories: ${completedTargets.length === 0 ? "none" : completedTargets.map((target) => `\`${JSON.stringify(target).replace(/`/g, "\\u0060")}\``).join(", ")}`,
    ...(failureMessage === undefined ? [] : [`- Failure detail: \`${JSON.stringify(failureMessage).replace(/`/g, "\\u0060")}\``]),
    "",
    "The retained mining outputs contain final reports, exact finding artifacts, and the bounded integrity metadata required to map and verify those artifacts. Complete source files associated with findings were moved intact into the dedicated retained whole-source tree before bulk recovery data was removed. Root recovery reports and redacted manifests remain in the case.",
    "",
  ].join("\n");
  const redacted = [
    "# AARK cleanup final report (redacted)",
    "",
    "> This report omits all local paths, finding values, categories, fingerprints, and failure details.",
    "",
    ...common,
    "",
    "Exact finding artifacts, complete finding-containing source files, final reports, and their minimal integrity metadata were retained locally. No recovered value was printed or uploaded.",
    "",
  ].join("\n");
  return {
    sensitive,
    redacted,
    manifest: {
      version: 1,
      tool: "aark",
      layer: "cleanup",
      status,
      generatedAt,
      pathsRedacted: true,
      valuesRedacted: true,
      approvedPlanToken: plan.public.approvalToken,
      selectedDirectories: plan.targets.length,
      completedDeletions: completedTargets.length,
      plannedFilesystemEntries: plan.public.deletion.filesystemEntries,
      plannedRegularFiles: plan.public.deletion.regularFiles,
      plannedLogicalBytes: plan.public.deletion.logicalBytes,
      miningScansVerified: plan.public.miningScansVerified,
      artifactFilesRetained: plan.public.artifactFilesRetained,
      sourceFilesRetained: plan.public.sourceFilesRetained,
      sourceFileLogicalBytesRetained: plan.public.sourceFileLogicalBytesRetained,
      markerOnlyFindingsWithoutArtifacts: plan.public.markerOnlyFindingsWithoutArtifacts,
      reports: { sensitive: CLEANUP_SENSITIVE_REPORT, redacted: CLEANUP_REDACTED_REPORT },
    },
  };
}

async function writeCleanupReports(
  plan: InternalCleanupPlan,
  locks: ExclusiveLock[],
  status: "authorized-in-progress" | "complete" | "failed-partial" | "interrupted-partial",
  completedTargets: string[],
  failure?: unknown,
): Promise<void> {
  for (const lock of locks) await lock.assertHeld();
  await assertRootCurrent(plan.caseRoot);
  const reports = reportText(plan, status, completedTargets, failure);
  await atomicWriteFile(safeJoin(plan.caseRoot.path, CLEANUP_SENSITIVE_REPORT), reports.sensitive, 0o600);
  await atomicWriteFile(safeJoin(plan.caseRoot.path, CLEANUP_REDACTED_REPORT), reports.redacted, 0o644);
  await atomicWriteJson(safeJoin(plan.caseRoot.path, CLEANUP_REDACTED_MANIFEST), reports.manifest, 0o644);
  for (const lock of locks) await lock.assertHeld();
  await assertRootCurrent(plan.caseRoot);
}

async function createRetainedSourceRunDirectory(
  plan: InternalCleanupPlan,
  locks: ExclusiveLock[],
): Promise<RootSnapshot | undefined> {
  const retainedCount = plan.targets.reduce((sum, target) => sum + target.retainedSourceFiles.length, 0);
  if (retainedCount === 0) return undefined;
  for (const lock of locks) await lock.assertHeld();
  await assertRootCurrent(plan.caseRoot);
  await assertRetainedSourceDestinationAvailable(
    plan.caseRoot,
    plan.retainedSourceBase,
    plan.public.approvalToken,
  );
  const base = safeJoin(plan.caseRoot.path, RETAINED_SOURCE_DIRECTORY);
  if (plan.retainedSourceBase === undefined) {
    try {
      await mkdir(base, { mode: 0o700 });
    } catch (error) {
      if (errorCode(error) === "EEXIST") {
        throw new Error("the retained source-file directory changed after cleanup approval", { cause: error });
      }
      throw error;
    }
  } else {
    await assertRootCurrent(plan.retainedSourceBase);
  }
  await ensurePrivateDirectory(base);
  const records = await mounts();
  const currentBase = await rootSnapshot(base, records, new Map<string, Promise<boolean>>(), "retained source-file directory");
  if (currentBase.mount !== plan.caseRoot.mount) {
    throw new Error("retained source-file directory crossed the recovery case filesystem");
  }
  if (plan.retainedSourceBase !== undefined && !sameRootSnapshot(currentBase, plan.retainedSourceBase)) {
    throw new Error("the retained source-file directory changed after cleanup approval");
  }
  const runRoot = retainedSourceRunRoot(plan.caseRoot.path, plan.public.approvalToken);
  await mkdir(runRoot, { mode: 0o700 });
  await ensurePrivateDirectory(runRoot);
  await syncDirectory(base);
  await syncDirectory(plan.caseRoot.path);
  const created = await rootSnapshot(runRoot, records, new Map<string, Promise<boolean>>(), "retained source-file run directory");
  if (created.mount !== plan.caseRoot.mount) throw new Error("retained source-file run directory crossed the recovery case filesystem");
  for (const lock of locks) await lock.assertHeld();
  await assertRootCurrent(plan.caseRoot);
  return created;
}

async function moveRetainedSourceFile(
  plan: InternalCleanupPlan,
  target: TargetSnapshot,
  source: RetainedSourceFile,
  quarantine: string,
  retainedRunRoot: RootSnapshot,
  locks: ExclusiveLock[],
  mutatedInodes: Set<string>,
): Promise<void> {
  if (safeJoin(target.path, source.relativePath) !== source.originalPath) {
    throw new Error("retained source-file mapping escaped its approved cleanup target");
  }
  const quarantinedSource = safeJoin(quarantine, source.relativePath);
  await assertNoSymlinkComponents(quarantine, quarantinedSource);
  const before = await lstat(quarantinedSource);
  const identity = `${source.device}:${source.inode}`;
  const changedByEarlierRetainedMove = mutatedInodes.has(identity);
  if (
    before.isSymbolicLink()
    || !before.isFile()
    || before.dev !== source.device
    || before.ino !== source.inode
    || before.mode !== source.mode
    || before.nlink !== source.links
    || before.size !== source.bytes
    || before.mtimeMs !== source.modifiedMs
    || (!changedByEarlierRetainedMove && before.ctimeMs !== source.changedMs)
    || await realpath(quarantinedSource) !== quarantinedSource
  ) throw new Error("a finding-containing source file changed before it could be retained");

  await assertRootCurrent(retainedRunRoot);
  const destination = safeJoin(retainedRunRoot.path, target.name, source.relativePath);
  await ensurePrivateDirectory(path.dirname(destination));
  await assertNoSymlinkComponents(retainedRunRoot.path, destination);
  if (await pathExists(destination)) throw new Error("a retained source-file destination unexpectedly already exists");
  for (const lock of locks) await lock.assertHeld();
  await assertRootCurrent(plan.caseRoot);
  await assertRootCurrent(retainedRunRoot);
  await rename(quarantinedSource, destination);
  mutatedInodes.add(identity);
  await syncDirectory(path.dirname(quarantinedSource));
  await syncDirectory(path.dirname(destination));
  const retained = await lstat(destination);
  if (
    retained.isSymbolicLink()
    || !retained.isFile()
    || retained.dev !== source.device
    || retained.ino !== source.inode
    || retained.mode !== source.mode
    || retained.nlink !== source.links
    || retained.size !== source.bytes
    || retained.mtimeMs !== source.modifiedMs
    || await realpath(destination) !== destination
  ) throw new Error("a finding-containing source file was not retained intact after its protected move");
  if (await pathExists(quarantinedSource)) throw new Error("a retained source file remained in the cleanup quarantine after its protected move");
  await assertRootCurrent(retainedRunRoot);
}

async function assertCleanupQuarantineSafe(
  plan: InternalCleanupPlan,
  target: TargetSnapshot,
  quarantine: string,
  locks: ExclusiveLock[],
): Promise<void> {
  for (const lock of locks) await lock.assertHeld();
  await assertRootCurrent(plan.caseRoot);
  const canonical = await existingRealDirectory(quarantine, "cleanup quarantine");
  const metadata = await lstat(canonical);
  if (metadata.dev !== target.device || metadata.ino !== target.inode) {
    throw new Error("cleanup quarantine identity changed before recursive deletion");
  }
  const records = await mounts();
  const mounted = mountForPathFrom(records, canonical);
  if (mounted === undefined || mountIdentity(mounted) !== plan.caseRoot.mount) {
    throw new Error("cleanup quarantine changed mount before recursive deletion");
  }
  if (path.resolve(mounted.target) === canonical || records.some((entry) => {
    const targetPath = path.resolve(entry.target);
    return targetPath !== canonical && inside(canonical, targetPath);
  })) throw new Error("cleanup quarantine became a mount root or acquired a nested mount before deletion");
}

async function assertTargetCurrent(
  plan: InternalCleanupPlan,
  target: TargetSnapshot,
  locks: ExclusiveLock[],
  signal?: AbortSignal,
): Promise<void> {
  interrupted(signal);
  for (const lock of locks) await lock.assertHeld();
  await assertRootCurrent(plan.caseRoot);
  const metadata = await lstat(target.path);
  if (
    metadata.isSymbolicLink()
    || !metadata.isDirectory()
    || metadata.dev !== target.device
    || metadata.ino !== target.inode
    || metadata.mtimeMs !== target.modifiedMs
    || metadata.ctimeMs !== target.changedMs
    || await realpath(target.path) !== target.path
  ) throw new Error("a cleanup deletion target changed after approval");
  for (const lock of locks) await lock.assertHeld();
  await assertRootCurrent(plan.caseRoot);
}

async function assertTargetRemoved(target: TargetSnapshot): Promise<void> {
  try {
    await lstat(target.path);
  } catch (error) {
    if (errorCode(error) === "ENOENT") return;
    throw error;
  }
  throw new Error("a cleanup deletion target was recreated before deletion could be recorded as complete");
}

async function removeApprovedTarget(
  plan: InternalCleanupPlan,
  target: TargetSnapshot,
  locks: ExclusiveLock[],
  retainedRunRoot: RootSnapshot | undefined,
  mutatedInodes: Set<string>,
  signal?: AbortSignal,
): Promise<void> {
  await assertTargetCurrent(plan, target, locks, signal);
  const quarantine = safeJoin(plan.caseRoot.path, `${CLEANUP_QUARANTINE_PREFIX}${target.name}-${randomUUID()}`);
  await assertNoSymlinkComponents(plan.caseRoot.path, quarantine);
  if (await pathExists(quarantine)) throw new Error("cleanup quarantine path unexpectedly already exists");
  for (const lock of locks) await lock.assertHeld();
  await rename(target.path, quarantine);
  await syncDirectory(plan.caseRoot.path);
  const moved = await lstat(quarantine);
  if (
    moved.isSymbolicLink()
    || !moved.isDirectory()
    || moved.dev !== target.device
    || moved.ino !== target.inode
    || await realpath(quarantine) !== quarantine
  ) {
    throw new Error("cleanup target changed during protected quarantine; the quarantined tree was not deleted");
  }
  if (await pathExists(target.path)) {
    throw new Error("cleanup target was recreated during protected quarantine; the quarantined tree was not deleted");
  }
  const quarantined = await targetSnapshot(
    plan.caseRoot,
    target.name,
    target.requiresScanCoverage,
    plan.coverage,
    plan.findingSources,
    signal,
    quarantine,
    target.path,
  );
  if (
    quarantined === undefined
    || quarantined.device !== target.device
    || quarantined.inode !== target.inode
    || quarantined.filesystemEntries !== target.filesystemEntries
    || quarantined.regularFiles !== target.regularFiles
    || quarantined.logicalBytes !== target.logicalBytes
    || quarantined.allocatedBytes !== target.allocatedBytes
    || quarantined.minimumReclaimableAllocatedBytes !== target.minimumReclaimableAllocatedBytes
    || !isDeepStrictEqual(quarantined.hardLinkAllocations, target.hardLinkAllocations)
    || quarantined.contentDigest !== target.contentDigest
    || quarantined.deletionDigest !== target.deletionDigest
    || quarantined.requiresScanCoverage !== target.requiresScanCoverage
    || !isDeepStrictEqual(quarantined.retainedSourceFiles, target.retainedSourceFiles)
  ) {
    throw new Error("cleanup target contents changed after approval; the quarantined tree was not deleted");
  }
  for (const lock of locks) await lock.assertHeld();
  await assertRootCurrent(plan.caseRoot);
  if (target.retainedSourceFiles.length > 0 && retainedRunRoot === undefined) {
    throw new Error("cleanup did not initialize the approved retained source-file directory");
  }
  for (const source of [...target.retainedSourceFiles].sort((left, right) => bytewiseLexical(left.originalPath, right.originalPath))) {
    interrupted(signal);
    await moveRetainedSourceFile(plan, target, source, quarantine, retainedRunRoot as RootSnapshot, locks, mutatedInodes);
  }
  const deletionSnapshot = await targetSnapshot(
    plan.caseRoot,
    target.name,
    target.requiresScanCoverage,
    plan.coverage,
    plan.findingSources,
    signal,
    quarantine,
    target.path,
  );
  if (deletionSnapshot === undefined || deletionSnapshot.deletionDigest !== target.deletionDigest
    || deletionSnapshot.retainedSourceFiles.length !== 0) {
    throw new Error("cleanup quarantine changed after finding sources were retained; the remainder was not deleted");
  }
  await assertCleanupQuarantineSafe(plan, target, quarantine, locks);
  await rm(quarantine, { recursive: true, force: false, maxRetries: 0 });
  await syncDirectory(plan.caseRoot.path);
  if (await pathExists(quarantine)) throw new Error("cleanup quarantine still exists after recursive deletion");
  await assertTargetRemoved(target);
}

async function acquireCleanupLocks(caseDirectory: string, miningOutputs: string[], batchRoots: string[]): Promise<ExclusiveLock[]> {
  const requests = [
    ...RECOVERY_LOCK_FILENAMES.map((filename) => ({ root: caseDirectory, filename })),
    ...batchRoots.map((root) => ({ root, filename: BATCH_LOCK_FILENAME })),
    ...miningOutputs
      .filter((output) => !batchRoots.some((root) => inside(root, output)))
      .flatMap((root) => MINING_LOCK_FILENAMES.map((filename) => ({ root, filename }))),
  ].sort((left, right) => bytewiseLexical(left.root, right.root) || bytewiseLexical(left.filename, right.filename));
  const locks: ExclusiveLock[] = [];
  try {
    for (const request of requests) locks.push(await acquireExclusiveLock(request.root, request.filename));
    return locks;
  } catch (error) {
    const releaseErrors: unknown[] = [];
    for (const lock of [...locks].reverse()) {
      try { await lock.release(); } catch (releaseError) { releaseErrors.push(releaseError); }
    }
    if (releaseErrors.length > 0) throw new AggregateError([error, ...releaseErrors], "cleanup lock acquisition failed and acquired locks could not all be released");
    throw error;
  }
}

async function releaseCleanupLocks(locks: ExclusiveLock[]): Promise<void> {
  const errors: unknown[] = [];
  for (const lock of [...locks].reverse()) {
    try { await lock.release(); } catch (error) { errors.push(error); }
  }
  if (errors.length > 0) throw new AggregateError(errors, "cleanup operation locks could not all be released");
}

export async function runCleanup(options: CleanupRunOptions): Promise<Record<string, unknown>> {
  if (!options.execute || !options.confirmDeleteRecoveredCopy) {
    throw new Error("cleanup deletion requires both --execute and --confirm-delete-recovered-copy");
  }
  if (options.includeEvidence === true && options.confirmDeleteEvidence !== true) {
    throw new Error("evidence-copy deletion additionally requires --confirm-delete-evidence");
  }
  if (!TOKEN.test(options.approvalToken)) throw new Error("cleanup requires the exact 64-character approval token from cleanup plan");
  const resolved = await resolveCleanupOptions(options);
  const normalized = resolved.normalized;
  for (const root of [normalized.caseDirectory, ...normalized.miningOutputs]) {
    await existingRealDirectory(root, "cleanup root");
  }
  await assertNoOperationLocks(normalized.caseDirectory, RECOVERY_LOCK_FILENAMES);
  for (const root of normalized.miningOutputs) await assertNoOperationLocks(root, MINING_LOCK_FILENAMES);
  for (const root of resolved.batchRoots) await assertNoOperationLocks(root, [BATCH_LOCK_FILENAME]);
  const locks = await acquireCleanupLocks(normalized.caseDirectory, normalized.miningOutputs, resolved.batchRoots);
  let operationError: unknown;
  try {
    const lockedResolution = await resolveCleanupOptions(options);
    if (!isDeepStrictEqual(lockedResolution.normalized, normalized)
      || !isDeepStrictEqual(lockedResolution.batchRoots, resolved.batchRoots)) {
      throw new Error("cleanup mining batch expansion changed while operation locks were acquired");
    }
    const plan = await buildInternalPlan(lockedResolution.normalized, locks, lockedResolution.batchRoots);
    if (plan.public.approvalToken !== options.approvalToken) {
      throw new Error("cleanup inputs changed after planning; run cleanup plan again and obtain fresh approval");
    }
    const cleanupFilesystem = await statfs(plan.caseRoot.path, { bigint: true });
    if (cleanupFilesystem.bavail * cleanupFilesystem.bsize < plan.retentionMetadataReserveBytes) {
      throw new Error("cleanup lacks free space for retained-source metadata and final reports before deletion");
    }
    const completedTargets: string[] = [];
    try {
      await writeCleanupReports(plan, locks, "authorized-in-progress", completedTargets);
      const retainedRunRoot = await createRetainedSourceRunDirectory(plan, locks);
      const mutatedInodes = new Set<string>();
      for (const target of plan.targets) {
        interrupted(normalized.signal);
        await removeApprovedTarget(plan, target, locks, retainedRunRoot, mutatedInodes, normalized.signal);
        completedTargets.push(target.path);
      }
      await writeCleanupReports(plan, locks, "complete", completedTargets);
    } catch (error) {
      const status = normalized.signal?.aborted === true ? "interrupted-partial" : "failed-partial";
      try {
        await writeCleanupReports(plan, locks, status, completedTargets, error);
      } catch (reportError) {
        throw new AggregateError([error, reportError], "cleanup failed and its partial-deletion report could not be written");
      }
      throw error;
    }
    return {
      version: 1,
      tool: "aark",
      layer: "cleanup",
      status: "complete",
      deletedDirectories: completedTargets.length,
      deletedFilesystemEntries: plan.public.deletion.filesystemEntries,
      deletedRegularFiles: plan.public.deletion.regularFiles,
      deletedLogicalBytes: plan.public.deletion.logicalBytes,
      plannedMaximumReclaimableAllocatedBytes: plan.public.deletion.allocatedBytes,
      expectedFreeSpaceGainMinimumBytes: plan.public.deletion.expectedFreeSpaceGainMinimumBytes,
      expectedFreeSpaceGainMaximumBytes: plan.public.deletion.expectedFreeSpaceGainMaximumBytes,
      miningScansVerified: plan.public.miningScansVerified,
      artifactFilesRetained: plan.public.artifactFilesRetained,
      sourceFilesRetained: plan.public.sourceFilesRetained,
      sourceFileLogicalBytesRetained: plan.public.sourceFileLogicalBytesRetained,
      evidenceCopyDeleted: plan.public.deletion.evidenceCopyIncluded,
      valuesPrinted: false,
      reports: { sensitive: CLEANUP_SENSITIVE_REPORT, redacted: CLEANUP_REDACTED_REPORT },
    };
  } catch (error) {
    operationError = error;
    throw error;
  } finally {
    try {
      await releaseCleanupLocks(locks);
    } catch (releaseError) {
      if (operationError !== undefined) throw new AggregateError([operationError, releaseError], "cleanup failed and its operation locks could not all be released");
      throw releaseError;
    }
  }
}
