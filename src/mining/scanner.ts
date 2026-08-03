import { constants } from "node:fs";
import { availableParallelism } from "node:os";
import { lstat, open, realpath } from "node:fs/promises";
import path from "node:path";
import { performance } from "node:perf_hooks";
import type { Candidate } from "../core/types.js";
import { acquireExclusiveLock, nearestExistingParent, readDirectoryNamesBounded, walkRegularFiles } from "../core/fs-safe.js";
import type { ExclusiveLock, WalkedFile } from "../core/fs-safe.js";
import { filesystemIsNetwork, mountForPathFrom, mountIsNetworkBacked, mounts } from "../core/mounts.js";
import type { MountRecord } from "../core/mounts.js";
import {
  assertStorageCapacity,
  directoryLogicalBytes,
  StorageBudget,
  StorageQuotaError,
  storagePolicyFromGiB,
} from "../core/storage.js";
import type { StoragePolicy } from "../core/storage.js";
import { ArtifactStore } from "./artifacts.js";
import type { DetectionContext } from "./detectors/types.js";
import {
  createScanManifest,
  loadResumeInventory,
  loadScanState,
  newScanState,
  readScanManifest,
  SCAN_FILES_FILENAME,
  SCAN_STATE_FILENAME,
  verifyResumeArtifacts,
  writeScanState,
} from "./resume.js";
import type {
  FrozenScanFile,
  ScanCursor,
  ScanOperationalOptions,
  ScanSemanticOptions,
  ScanState,
} from "./resume.js";
import type { MiningOptions, MiningPerformance, MiningProgress, MiningRunStatus, SensitiveScanInventory } from "./types.js";
import { isBoundedJsonValue, isSafeDetectorIdentifier, MAX_CANDIDATE_BYTES_PER_DETECTOR_JOB, MAX_DERIVED_ARTIFACT_BYTES_PER_CANDIDATE, MAX_INPUT_ROOTS, MAX_STREAMING_CANDIDATE_BYTES_PER_DETECTOR_JOB } from "./limits.js";
import { MAX_DPAPI_BLOB_BYTES } from "./validators/dpapi.js";
import { STREAMING_DETECTOR_NAMES } from "./worker-protocol.js";
import type { DetectorBatchResult, DetectorJobKind } from "./worker-protocol.js";
import { DetectorWorkerPool } from "./worker-pool.js";

const MINIMUM_SAFE_OVERLAP = MAX_DPAPI_BLOB_BYTES + 1024 * 1024;
const DEEP_SCAN_SLICE_BYTES = 1024 * 1024;
const DEEP_SCAN_OVERLAP_BYTES = 256;
const MAX_BUFFERED_SCAN_WINDOWS_BYTES = 256 * 1024 * 1024;
const MAX_BUFFERED_SMALL_FILES_BYTES = 64 * 1024 * 1024;
const PERIODIC_SAFETY_INTERVAL_MS = 30_000;
const PERIODIC_SAFETY_BYTES = 1024 * 1024 * 1024;
const CHECKPOINT_INTERVAL_MS = 60_000;
const MINING_LOCK_FILENAME = ".aark-mining.lock";
const LEGACY_MINING_LOCK_FILENAME = ".agetnic-mining.lock";
const MINING_LOCK_FILENAMES = [MINING_LOCK_FILENAME, LEGACY_MINING_LOCK_FILENAME] as const;
const PROVENANCE_VALUES = new Set([
  "deleted-metadata",
  "unallocated-carve",
  "unallocated-stream",
  "shadow-copy",
  "residual-memory",
  "allocated-reference",
  "unknown",
]);

interface PathSafetySnapshot {
  path: string;
  device: number;
  inode: number;
  kind: "file" | "directory";
  mount: string;
}

interface OutputSafetySnapshot extends PathSafetySnapshot {
  kind: "directory";
  lockDevice: number;
  lockInode: number;
}

interface NormalizedMiningOptions extends MiningOptions {
  workers: number;
  minimumFreeGiB: number;
  minimumFreePercent: number;
}

export interface MiningResumeOptions {
  output: string;
  workers?: number;
  minimumFreeGiB?: number;
  minimumFreePercent?: number;
  maximumOutputGiB?: number;
  signal?: AbortSignal;
  progress?: (progress: MiningProgress) => void;
}

interface DetectorWork {
  kind: DetectorJobKind;
  data: Buffer;
  context: DetectionContext;
}

interface DetectorWorkResult extends DetectorWork {
  batches: DetectorBatchResult[];
}

interface WorkerMetricsSnapshot {
  jobsSubmitted: number;
  payloadCopies: number;
  payloadBytesCopied: number;
  maximumQueueDepth: number;
  maximumActiveJobs: number;
  maximumActiveBytes: number;
}

class MiningMetrics {
  public inventoryTraversalMs = 0;
  public rootValidationCalls = 0;
  public rootValidationMs = 0;
  public fileValidationCalls = 0;
  public fileValidationMs = 0;
  public readCalls = 0;
  public bytesRead = 0;
  public readMs = 0;
  public deterministicCommitMs = 0;
  public artifactPublications = 0;
  public artifactLogicalBytes = 0;
  public artifactPublicationMs = 0;
  public checkpoints = 0;
  public checkpointBytes = 0;
  public checkpointMs = 0;
  public periodicSafetyChecks = 0;
  public periodicSafetyCheckMs = 0;
  public maximumOutstandingFiles = 0;
  public maximumOutstandingFileBytes = 0;
  public completeFileBuffersReused = 0;
  private readonly started = performance.now();

  public artifactPublished(logicalBytes: number, elapsedMs: number): void {
    this.artifactPublications += 1;
    this.artifactLogicalBytes += logicalBytes;
    this.artifactPublicationMs += elapsedMs;
  }

  public snapshot(worker?: WorkerMetricsSnapshot): MiningPerformance {
    const rounded = (value: number): number => Math.round(value * 1_000) / 1_000;
    return {
      elapsedMs: rounded(performance.now() - this.started),
      inventoryTraversalMs: rounded(this.inventoryTraversalMs),
      rootValidationCalls: this.rootValidationCalls,
      rootValidationMs: rounded(this.rootValidationMs),
      fileValidationCalls: this.fileValidationCalls,
      fileValidationMs: rounded(this.fileValidationMs),
      readCalls: this.readCalls,
      bytesRead: this.bytesRead,
      readMs: rounded(this.readMs),
      workerJobs: worker?.jobsSubmitted ?? 0,
      workerPayloadCopies: worker?.payloadCopies ?? 0,
      workerPayloadBytes: worker?.payloadBytesCopied ?? 0,
      maximumWorkerQueueDepth: worker?.maximumQueueDepth ?? 0,
      maximumActiveWorkerJobs: worker?.maximumActiveJobs ?? 0,
      maximumActiveWorkerBytes: worker?.maximumActiveBytes ?? 0,
      deterministicCommitMs: rounded(this.deterministicCommitMs),
      artifactPublications: this.artifactPublications,
      artifactLogicalBytes: this.artifactLogicalBytes,
      artifactPublicationMs: rounded(this.artifactPublicationMs),
      checkpoints: this.checkpoints,
      checkpointBytes: this.checkpointBytes,
      checkpointMs: rounded(this.checkpointMs),
      periodicSafetyChecks: this.periodicSafetyChecks,
      periodicSafetyCheckMs: rounded(this.periodicSafetyCheckMs),
      maximumOutstandingFiles: this.maximumOutstandingFiles,
      maximumOutstandingFileBytes: this.maximumOutstandingFileBytes,
      completeFileBuffersReused: this.completeFileBuffersReused,
    };
  }
}

interface ScanRuntime {
  options: NormalizedMiningOptions;
  policy: StoragePolicy;
  inputSafety: PathSafetySnapshot[];
  outputSafety: OutputSafetySnapshot;
  lockPath: string;
  locks: ExclusiveLock[];
  store: ArtifactStore;
  budget: StorageBudget;
  pool: DetectorWorkerPool;
  state: ScanState;
  progress: MiningProgress;
  isNetworkMount: (record: MountRecord) => Promise<boolean>;
  metrics: MiningMetrics;
}

class ArtifactWriteError extends Error {
  public override readonly name = "ArtifactWriteError";
}

class ScanControlError extends Error {
  public override readonly name = "ScanControlError";
}

class ScanPauseError extends Error {
  public override readonly name = "ScanPauseError";
}

function inside(parent: string, child: string): boolean {
  const relative = path.relative(path.resolve(parent), path.resolve(child));
  return relative === "" || (relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

function interrupted(signal: AbortSignal | undefined): boolean {
  return signal?.aborted === true;
}

function detectorWorkCancelled(error: unknown, signal: AbortSignal | undefined): boolean {
  return interrupted(signal)
    && error instanceof Error
    && (error.message === "detector work was cancelled" || error.message === "detector worker pool is closed");
}

function manifestVerificationInterrupted(error: unknown, signal: AbortSignal | undefined): boolean {
  return interrupted(signal)
    && error instanceof Error
    && error.message === "scan manifest verification was interrupted";
}

function mountIdentity(record: MountRecord): string {
  return JSON.stringify({
    source: record.source,
    target: path.resolve(record.target),
    filesystem: record.filesystem.toLowerCase(),
    options: [...record.options].sort(),
  });
}

async function pathSafetySnapshot(input: string, records: MountRecord[]): Promise<PathSafetySnapshot> {
  const metadata = await lstat(input);
  if (metadata.isSymbolicLink() || (!metadata.isDirectory() && !metadata.isFile())) {
    throw new Error("protected mining path must remain a regular file or real directory");
  }
  if (await realpath(input) !== input) throw new Error("protected mining path changed from its canonical location");
  const mounted = mountForPathFrom(records, input);
  if (mounted === undefined) throw new Error("could not determine the mount backing a protected mining path");
  if (filesystemIsNetwork(mounted)) throw new Error("protected mining path moved to a network filesystem");
  return {
    path: input,
    device: metadata.dev,
    inode: metadata.ino,
    kind: metadata.isDirectory() ? "directory" : "file",
    mount: mountIdentity(mounted),
  };
}

async function inspectRuntimeInputRoots(
  expected: PathSafetySnapshot[],
  recordChangedFileRoot: (snapshot: PathSafetySnapshot, error: unknown) => void,
): Promise<{ records: MountRecord[]; changedFileRoots: Set<string> }> {
  const records = await mounts();
  const changedFileRoots = new Set<string>();
  for (const snapshot of expected) {
    try {
      const current = await pathSafetySnapshot(snapshot.path, records);
      if (
        current.device !== snapshot.device
        || current.inode !== snapshot.inode
        || current.kind !== snapshot.kind
        || current.mount !== snapshot.mount
      ) throw new Error("a mining input root or its mount changed after preflight");
    } catch (error) {
      if (snapshot.kind !== "file") {
        throw new ScanControlError("a directory input root or its mount changed after preflight", { cause: error });
      }
      changedFileRoots.add(snapshot.path);
      recordChangedFileRoot(snapshot, error);
    }
  }
  return { records, changedFileRoots };
}

async function assertPauseInputRootsCurrent(expected: PathSafetySnapshot[]): Promise<void> {
  const inspection = await inspectRuntimeInputRoots(expected, () => undefined);
  if (inspection.changedFileRoots.size > 0) {
    throw new ScanControlError("an explicit file input root changed, so the scan cannot publish a resumable pause");
  }
}

async function outputSafetySnapshot(output: string, lockPath: string): Promise<OutputSafetySnapshot> {
  const records = await mounts();
  const current = await pathSafetySnapshot(output, records);
  if (current.kind !== "directory") throw new Error("mining output must remain a real directory");
  const mounted = mountForPathFrom(records, output);
  if (mounted === undefined || path.resolve(mounted.target) === output) {
    throw new Error("mining output must remain a dedicated local subdirectory, not a mount root");
  }
  if (records.some((record) => {
    const target = path.resolve(record.target);
    return target !== output && inside(output, target);
  })) throw new Error("nested mounts inside the mining output are not allowed");
  const lock = await lstat(lockPath);
  if (lock.isSymbolicLink() || !lock.isFile()) throw new Error("mining output lock changed after acquisition");
  return { ...current, kind: "directory", lockDevice: lock.dev, lockInode: lock.ino };
}

async function assertOutputSafetyCurrent(expected: OutputSafetySnapshot, lockPath: string): Promise<void> {
  const current = await outputSafetySnapshot(expected.path, lockPath);
  if (
    current.device !== expected.device
    || current.inode !== expected.inode
    || current.mount !== expected.mount
    || current.lockDevice !== expected.lockDevice
    || current.lockInode !== expected.lockInode
  ) throw new Error("mining output, mount, or exclusive lock changed after preflight");
}

async function assertRuntimeOutputCurrent(runtime: Pick<ScanRuntime, "outputSafety" | "lockPath" | "locks">): Promise<void> {
  for (const lock of runtime.locks) await lock.assertHeld();
  await assertOutputSafetyCurrent(runtime.outputSafety, runtime.lockPath);
}

async function acquireMiningLocks(directory: string): Promise<ExclusiveLock[]> {
  const locks: ExclusiveLock[] = [];
  try {
    for (const filename of [...MINING_LOCK_FILENAMES].sort()) {
      locks.push(await acquireExclusiveLock(directory, filename));
    }
    return locks;
  } catch (error) {
    const releaseErrors: unknown[] = [];
    for (const lock of [...locks].reverse()) {
      try { await lock.release(); } catch (releaseError) { releaseErrors.push(releaseError); }
    }
    if (releaseErrors.length > 0) {
      throw new AggregateError([error, ...releaseErrors], "mining lock acquisition failed and acquired locks could not all be released");
    }
    throw error;
  }
}

async function releaseMiningLocks(locks: ExclusiveLock[]): Promise<void> {
  const errors: unknown[] = [];
  for (const lock of [...locks].reverse()) {
    try { await lock.release(); } catch (error) { errors.push(error); }
  }
  if (errors.length > 0) throw new AggregateError(errors, "mining operation locks could not all be released");
}

async function canonicalCreationPath(output: string): Promise<string> {
  try {
    return await realpath(output);
  } catch (error) {
    const code = error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
    if (code !== "ENOENT") throw error;
    const existing = await nearestExistingParent(output);
    return path.resolve(await realpath(existing), path.relative(existing, output));
  }
}

async function assertFreshSafeOutput(inputs: string[], output: string): Promise<{ inputs: string[]; output: string }> {
  try {
    const metadata = await lstat(output);
    if (metadata.isSymbolicLink()) throw new Error("mining output must not be a symbolic link");
    if (!metadata.isDirectory()) throw new Error("mining output exists and is not a directory");
    if ((await readDirectoryNamesBounded(output, 1)).length !== 0) throw new Error("mining output directory must be new or empty");
  } catch (error) {
    const code = error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
    if (code !== "ENOENT") throw error;
  }

  const canonicalInputs: Array<{ path: string; directory: boolean }> = [];
  for (const input of inputs) {
    const metadata = await lstat(input);
    if (metadata.isSymbolicLink()) throw new Error("symbolic-link input roots are not allowed");
    if (!metadata.isDirectory() && !metadata.isFile()) throw new Error("mining input roots must be regular files or directories");
    const canonicalInput = await realpath(input);
    const canonicalMetadata = await lstat(canonicalInput);
    if (canonicalMetadata.dev !== metadata.dev || canonicalMetadata.ino !== metadata.ino || canonicalMetadata.isDirectory() !== metadata.isDirectory() || canonicalMetadata.isFile() !== metadata.isFile()) {
      throw new Error("mining input changed while its canonical path was being established");
    }
    canonicalInputs.push({ path: canonicalInput, directory: metadata.isDirectory() });
  }
  const canonicalOutput = await canonicalCreationPath(output);
  for (const input of canonicalInputs) {
    if (input.directory && inside(input.path, canonicalOutput)) throw new Error("mining output cannot be inside a scanned input directory");
    if (input.path === canonicalOutput) throw new Error("mining output cannot be an input");
  }
  const deduplicated = canonicalInputs.filter((candidate, index, all) =>
    all.findIndex((item) => item.path === candidate.path) === index
    && !all.some((parent) => parent.directory && parent.path !== candidate.path && inside(parent.path, candidate.path)));
  return { inputs: deduplicated.map((item) => item.path), output: canonicalOutput };
}

async function assertLockedFreshOutput(output: string): Promise<void> {
  const metadata = await lstat(output);
  if (metadata.isSymbolicLink() || !metadata.isDirectory() || await realpath(output) !== output) {
    throw new Error("locked mining output must remain a real canonical directory");
  }
  const entries = await readDirectoryNamesBounded(output, MINING_LOCK_FILENAMES.length + 1);
  if (
    entries.length !== MINING_LOCK_FILENAMES.length
    || MINING_LOCK_FILENAMES.some((filename) => !entries.includes(filename))
  ) {
    throw new Error("mining output changed between emptiness validation and exclusive lock acquisition");
  }
}

async function assertLockedResumeOutput(output: string): Promise<void> {
  const metadata = await lstat(output);
  if (metadata.isSymbolicLink() || !metadata.isDirectory() || await realpath(output) !== output) {
    throw new Error("resumed mining output must remain a real canonical directory");
  }
  const allowed = new Set([
    MINING_LOCK_FILENAME,
    LEGACY_MINING_LOCK_FILENAME,
    "artifacts",
    "inventory-sensitive.json",
    "manifest-redacted.json",
    "final-report-sensitive.md",
    "final-report-redacted.md",
    SCAN_FILES_FILENAME,
    SCAN_STATE_FILENAME,
  ]);
  const entries = await readDirectoryNamesBounded(output, allowed.size + 1);
  if (
    MINING_LOCK_FILENAMES.some((filename) => !entries.includes(filename))
    || entries.some((entry) => !allowed.has(entry))
  ) {
    throw new Error("resumed mining output contains unexpected control or artifact entries");
  }
}

function validateWorkerCount(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > 4) throw new Error("workers must be an integer from 1 through 4");
  return value;
}

function validatedOptions(input: MiningOptions): NormalizedMiningOptions {
  const options: NormalizedMiningOptions = {
    ...input,
    inputs: input.inputs.map((value) => path.resolve(value)),
    output: path.resolve(input.output),
    workers: validateWorkerCount(input.workers ?? Math.min(4, Math.max(1, availableParallelism() - 1))),
    minimumFreeGiB: input.minimumFreeGiB ?? 5,
    minimumFreePercent: input.minimumFreePercent ?? 5,
  };
  if (options.inputs.length === 0) throw new Error("at least one mining input is required");
  if (options.inputs.length > MAX_INPUT_ROOTS) throw new Error(`mining accepts at most ${MAX_INPUT_ROOTS} input roots per scan`);
  if (!PROVENANCE_VALUES.has(options.provenance)) throw new Error("mining provenance is not recognized");
  for (const [label, value] of [["chunkBytes", options.chunkBytes], ["overlapBytes", options.overlapBytes], ["wholeFileBytes", options.wholeFileBytes]] as const) {
    if (!Number.isSafeInteger(value) || value < 1) throw new Error(`${label} must be a positive integer`);
  }
  if (options.chunkBytes < MINIMUM_SAFE_OVERLAP || options.chunkBytes > 128 * 1024 * 1024) throw new Error("chunkBytes must be between 17 MiB and 128 MiB");
  if (options.overlapBytes < MINIMUM_SAFE_OVERLAP || options.overlapBytes > options.chunkBytes) throw new Error("overlapBytes must be between 17 MiB and chunkBytes so every supported streaming format can cross a chunk boundary");
  if (options.wholeFileBytes > 256 * 1024 * 1024) throw new Error("wholeFileBytes must not exceed 256 MiB");
  storagePolicyFromGiB(options.minimumFreeGiB, options.minimumFreePercent, options.maximumOutputGiB);
  return options;
}

function semanticOptions(options: NormalizedMiningOptions): ScanSemanticOptions {
  return {
    inputs: [...options.inputs],
    output: options.output,
    provenance: options.provenance,
    chunkBytes: options.chunkBytes,
    overlapBytes: options.overlapBytes,
    wholeFileBytes: options.wholeFileBytes,
    deepKeySchedules: options.deepKeySchedules === true,
  };
}

function operationalOptions(options: NormalizedMiningOptions): ScanOperationalOptions {
  return {
    workers: options.workers,
    minimumFreeGiB: options.minimumFreeGiB,
    minimumFreePercent: options.minimumFreePercent,
    ...(options.maximumOutputGiB === undefined ? {} : { maximumOutputGiB: options.maximumOutputGiB }),
  };
}

function normalizeCandidate(candidate: Candidate): Candidate {
  return {
    ...candidate,
    value: Buffer.from(candidate.value),
    validation: { method: candidate.validation.method, checks: { ...candidate.validation.checks } },
    ...(candidate.derivedArtifacts === undefined ? {} : {
      derivedArtifacts: candidate.derivedArtifacts.map((item) => ({ ...item, data: Buffer.from(item.data) })),
    }),
    ...(candidate.sensitiveMetadata === undefined ? {} : { sensitiveMetadata: { ...candidate.sensitiveMetadata } }),
  };
}

function derivedArtifactsAreBounded(value: unknown): boolean {
  if (value === undefined) return true;
  if (!Array.isArray(value) || value.length > 16) return false;
  let bytes = 0;
  for (const artifact of value) {
    if (
      typeof artifact !== "object"
      || artifact === null
      || typeof artifact.filename !== "string"
      || !(artifact.data instanceof Uint8Array)
      || (artifact.mode !== undefined && !Number.isSafeInteger(artifact.mode))
      || artifact.data.byteLength > MAX_DERIVED_ARTIFACT_BYTES_PER_CANDIDATE - bytes
    ) return false;
    bytes += artifact.data.byteLength;
  }
  return true;
}

async function commitDetectorResults(
  result: DetectorWorkResult,
  sourcePath: string,
  provenance: MiningOptions["provenance"],
  store: ArtifactStore,
  signal?: AbortSignal,
): Promise<boolean> {
  let clean = true;
  for (const batch of result.batches) {
    let returnedCandidateBytes = 0;
    const returnedCandidateByteLimit = batch.detector === "structured-artifacts"
      ? MAX_CANDIDATE_BYTES_PER_DETECTOR_JOB
      : MAX_STREAMING_CANDIDATE_BYTES_PER_DETECTOR_JOB;
    if (interrupted(signal)) throw new ScanPauseError("scan paused");
    if (batch.error !== undefined) {
      store.recordError(sourcePath, `detector:${batch.detector}`, new Error(batch.error));
      clean = false;
    }
    for (const rawCandidate of batch.candidates) {
      if (interrupted(signal)) throw new ScanPauseError("scan paused");
      try {
        if (
          typeof rawCandidate !== "object"
          || rawCandidate === null
          || !isSafeDetectorIdentifier(rawCandidate.category)
          || !["authenticated", "high", "medium", "marker-only"].includes(rawCandidate.confidence)
          || typeof rawCandidate.extension !== "string"
          || rawCandidate.extension.length < 1
          || rawCandidate.extension.length > 64
          || !(rawCandidate.value instanceof Uint8Array)
          || typeof rawCandidate.validation !== "object"
          || rawCandidate.validation === null
          || !isSafeDetectorIdentifier(rawCandidate.validation.method)
          || typeof rawCandidate.validation.checks !== "object"
          || rawCandidate.validation.checks === null
          || Array.isArray(rawCandidate.validation.checks)
          || !isBoundedJsonValue(rawCandidate.validation.checks)
          || (rawCandidate.sensitiveMetadata !== undefined && (
            typeof rawCandidate.sensitiveMetadata !== "object"
            || rawCandidate.sensitiveMetadata === null
            || Array.isArray(rawCandidate.sensitiveMetadata)
            || !isBoundedJsonValue(rawCandidate.sensitiveMetadata)
          ))
          || !derivedArtifactsAreBounded(rawCandidate.derivedArtifacts)
        ) throw new Error("detector worker returned an invalid candidate");
        let candidateBytes = rawCandidate.value.byteLength;
        for (const artifact of rawCandidate.derivedArtifacts ?? []) candidateBytes += artifact.data.byteLength;
        if (candidateBytes > returnedCandidateByteLimit - returnedCandidateBytes) {
          throw new Error("detector worker exceeded its aggregate candidate byte limit");
        }
        returnedCandidateBytes += candidateBytes;
        const candidate = normalizeCandidate(rawCandidate);
        const relativeOffset = candidate.offset - result.context.baseOffset;
        const candidateEnd = relativeOffset + candidate.length;
        if (
          !Number.isSafeInteger(relativeOffset)
          || relativeOffset < 0
          || !Number.isSafeInteger(candidate.length)
          || candidate.length < 1
          || !Number.isSafeInteger(candidateEnd)
          || candidateEnd > result.data.length
        ) throw new Error("validator returned a candidate outside the scanned window");
        if (!result.data.subarray(relativeOffset, candidateEnd).equals(candidate.value)) {
          throw new Error("validator candidate bytes do not match its recorded source offset");
        }
        await store.add(sourcePath, provenance, candidate);
      } catch (error) {
        if (error instanceof StorageQuotaError) throw error;
        store.recordError(sourcePath, `artifact:${batch.detector}`, error);
        throw new ArtifactWriteError("could not safely persist a recovered artifact", { cause: error });
      }
    }
  }
  return clean;
}

async function runDetectorWork(pool: DetectorWorkerPool, work: DetectorWork[], signal?: AbortSignal): Promise<DetectorWorkResult[]> {
  const results = new Array<DetectorWorkResult>(work.length);
  let next = 0;
  const consumers = Array.from({ length: Math.min(pool.size, work.length) }, async () => {
    while (true) {
      const index = next++;
      const item = work[index];
      if (item === undefined) return;
      let batches: DetectorBatchResult[];
      try {
        batches = await pool.run(item.kind, item.data, item.context);
      } catch (error) {
        if (detectorWorkCancelled(error, signal)) throw new ScanPauseError("scan paused", { cause: error });
        throw new ScanControlError("detector worker execution failed", { cause: error });
      }
      results[index] = { ...item, batches };
    }
  });
  await Promise.all(consumers);
  return results;
}

async function* runDetectorWorkOrdered(
  pool: DetectorWorkerPool,
  work: DetectorWork[],
  signal?: AbortSignal,
): AsyncGenerator<DetectorWorkResult> {
  // Keep one queued job beyond the active worker count. This provides useful
  // load balancing without allowing every chunk/family result in a buffered
  // batch to accumulate in the main thread before deterministic commit.
  const maximumOutstanding = Math.min(work.length, pool.size + 1);
  const outstanding = new Map<number, Promise<DetectorWorkResult>>();
  let nextToSchedule = 0;
  const fill = (): void => {
    while (outstanding.size < maximumOutstanding && nextToSchedule < work.length) {
      const index = nextToSchedule++;
      const item = work[index];
      if (item === undefined) throw new Error("detector work ordering became inconsistent");
      const pending = pool.run(item.kind, item.data, item.context)
        .then((batches) => ({ ...item, batches }))
        .catch((error: unknown) => {
          if (detectorWorkCancelled(error, signal)) throw new ScanPauseError("scan paused", { cause: error });
          throw new ScanControlError("detector worker execution failed", { cause: error });
        });
      // The generator awaits each promise in order. Attach a rejection handler
      // immediately for later jobs that can fail before their turn is reached.
      void pending.catch(() => undefined);
      outstanding.set(index, pending);
    }
  };
  fill();
  for (let index = 0; index < work.length; index += 1) {
    const pending = outstanding.get(index);
    if (pending === undefined) throw new Error("detector work ordering became inconsistent");
    const result = await pending;
    outstanding.delete(index);
    fill();
    yield result;
  }
}

async function commitDetectorWorkInBatches(
  runtime: ScanRuntime,
  work: DetectorWork[],
  sourcePath: string,
  assertSourceCurrent: () => Promise<void>,
): Promise<boolean> {
  let clean = true;
  for (let start = 0; start < work.length; start += runtime.pool.size) {
    if (interrupted(runtime.options.signal)) {
      await assertSourceCurrent();
      throw new ScanPauseError("scan paused");
    }
    const results = await runDetectorWork(
      runtime.pool,
      work.slice(start, start + runtime.pool.size),
      runtime.options.signal,
    );
    await assertSourceCurrent();
    for (const result of results) {
      const commitStarted = performance.now();
      try {
        clean = await commitDetectorResults(
          result,
          sourcePath,
          runtime.options.provenance,
          runtime.store,
          runtime.options.signal,
        ) && clean;
      } finally {
        runtime.metrics.deterministicCommitMs += performance.now() - commitStarted;
      }
    }
  }
  return clean;
}

function workForWindow(data: Buffer, context: DetectionContext, deep: boolean, deepPrimaryStart = 0): DetectorWork[] {
  const work: DetectorWork[] = [{ kind: "streaming", data, context }];
  if (!deep) return work;
  const scanStart = deepPrimaryStart === 0 ? 0 : Math.max(0, deepPrimaryStart - DEEP_SCAN_OVERLAP_BYTES);
  let primaryStart = scanStart;
  while (primaryStart < data.length) {
    const start = primaryStart === scanStart ? scanStart : primaryStart - DEEP_SCAN_OVERLAP_BYTES;
    const end = Math.min(primaryStart + DEEP_SCAN_SLICE_BYTES, data.length);
    work.push({
      kind: "deep-key-schedules",
      data: data.subarray(start, end),
      context: { ...context, baseOffset: context.baseOffset + start, deepKeySchedules: true },
    });
    primaryStart = end;
  }
  return work;
}

async function assertOpenedFilePathCurrent(
  filename: string,
  handle: Awaited<ReturnType<typeof open>>,
  opened: Awaited<ReturnType<Awaited<ReturnType<typeof open>>["stat"]>>,
): Promise<void> {
  let descriptorPath: string;
  let pathMetadata: Awaited<ReturnType<typeof lstat>>;
  let canonicalPath: string;
  try {
    [descriptorPath, pathMetadata, canonicalPath] = await Promise.all([
      realpath(`/proc/self/fd/${handle.fd}`),
      lstat(filename),
      realpath(filename),
    ]);
  } catch (error) {
    throw new Error("scan input path is no longer stably addressable", { cause: error });
  }
  if (
    descriptorPath !== filename
    || canonicalPath !== filename
    || pathMetadata.isSymbolicLink()
    || !pathMetadata.isFile()
    || pathMetadata.dev !== opened.dev
    || pathMetadata.ino !== opened.ino
  ) throw new Error("scan input path changed or crossed a symbolic-link component");
}

function assertFileSnapshot(file: FrozenScanFile, metadata: Awaited<ReturnType<Awaited<ReturnType<typeof open>>["stat"]>>): void {
  if (
    !metadata.isFile()
    || metadata.dev !== file.device
    || metadata.ino !== file.inode
    || metadata.size !== file.bytes
    || metadata.mtimeMs !== file.modifiedMs
    || metadata.ctimeMs !== file.changedMs
  ) throw new Error("scan input changed from its frozen file manifest snapshot");
}

async function readExact(
  handle: Awaited<ReturnType<typeof open>>,
  start: number,
  bytes: number,
  metrics: MiningMetrics,
): Promise<Buffer> {
  const started = performance.now();
  const data = Buffer.allocUnsafe(bytes);
  let consumed = 0;
  try {
    while (consumed < bytes) {
      const result = await handle.read(data, consumed, bytes - consumed, start + consumed);
      if (result.bytesRead === 0) break;
      consumed += result.bytesRead;
    }
    if (consumed !== bytes) throw new Error("scan input ended before its frozen file size");
    return data;
  } finally {
    metrics.readCalls += 1;
    metrics.bytesRead += consumed;
    metrics.readMs += performance.now() - started;
  }
}

type OpenFileHandle = Awaited<ReturnType<typeof open>>;
type OpenFileStat = Awaited<ReturnType<OpenFileHandle["stat"]>>;

interface PreparedSmallFile {
  file: FrozenScanFile;
  data: Buffer;
  handle: OpenFileHandle;
  opened: OpenFileStat;
  batches: DetectorBatchResult[];
}

type SmallFileOutcome =
  | { prepared: PreparedSmallFile }
  | { file: FrozenScanFile; error: unknown };

async function assertPreparedFileCurrent(runtime: ScanRuntime, prepared: Pick<PreparedSmallFile, "file" | "handle" | "opened">): Promise<void> {
  const started = performance.now();
  try {
    const current = await prepared.handle.stat();
    assertFileSnapshot(prepared.file, current);
    await assertOpenedFilePathCurrent(prepared.file.path, prepared.handle, prepared.opened);
  } finally {
    runtime.metrics.fileValidationCalls += 1;
    runtime.metrics.fileValidationMs += performance.now() - started;
  }
}

async function assertPreparedFileSnapshotCurrent(runtime: ScanRuntime, prepared: Pick<PreparedSmallFile, "file" | "handle">): Promise<void> {
  const started = performance.now();
  try {
    assertFileSnapshot(prepared.file, await prepared.handle.stat());
  } finally {
    runtime.metrics.fileValidationCalls += 1;
    runtime.metrics.fileValidationMs += performance.now() - started;
  }
}

async function prepareSmallFile(runtime: ScanRuntime, file: FrozenScanFile): Promise<SmallFileOutcome> {
  let handle: OpenFileHandle | undefined;
  try {
    handle = await open(file.path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const opened = await handle.stat();
    const preparedIdentity = { file, handle, opened };
    await assertPreparedFileCurrent(runtime, preparedIdentity);
    const data = await readExact(handle, 0, file.bytes, runtime.metrics);
    // Catch mutation during the read before spending worker time. The full
    // descriptor/canonical-path check is repeated immediately before commit.
    await assertPreparedFileSnapshotCurrent(runtime, preparedIdentity);
    const context: DetectionContext = {
      sourcePath: file.path,
      baseOffset: 0,
      wholeFile: false,
      deepKeySchedules: false,
    };
    let batches: DetectorBatchResult[];
    try {
      batches = await runtime.pool.run("small-file", data, context);
    } catch (error) {
      if (detectorWorkCancelled(error, runtime.options.signal)) throw new ScanPauseError("scan paused", { cause: error });
      throw new ScanControlError("detector worker execution failed", { cause: error });
    }
    return { prepared: { file, data, handle, opened, batches } };
  } catch (error) {
    await handle?.close().catch(() => undefined);
    return { file, error };
  }
}

function beginManifestFile(runtime: ScanRuntime, file: FrozenScanFile): void {
  const continuing = file.index === runtime.state.cursor.fileIndex
    && runtime.progress.filesVisited > file.index;
  if (!continuing) runtime.progress.filesVisited += 1;
}

async function completeManifestFile(runtime: ScanRuntime, file: FrozenScanFile, completelyScanned: boolean): Promise<void> {
  if (completelyScanned) runtime.progress.filesScanned += 1;
  runtime.state.cursor = { fileIndex: file.index + 1, phase: "stream", nextOffset: 0 };
  runtime.progress.phase = "stream";
  await publishProgress(runtime);
}

async function processSmallFileBatch(
  runtime: ScanRuntime,
  files: FrozenScanFile[],
  maybeCheckpoint: (force?: boolean) => Promise<void>,
): Promise<void> {
  const bytes = files.reduce((sum, file) => sum + file.bytes, 0);
  runtime.metrics.maximumOutstandingFiles = Math.max(runtime.metrics.maximumOutstandingFiles, files.length);
  runtime.metrics.maximumOutstandingFileBytes = Math.max(runtime.metrics.maximumOutstandingFileBytes, bytes);
  const pendingOutcomes = files.map(async (file) => await prepareSmallFile(runtime, file));
  const closedHandles = new Set<OpenFileHandle>();
  try {
    for (const pending of pendingOutcomes) {
      const outcome = await pending;
      // Observe a worker/control failure before honoring a concurrent signal;
      // otherwise a crash already present in this ordered slot could be
      // mislabeled as a resumable cancellation.
      if (!("prepared" in outcome) && outcome.error instanceof ScanControlError) {
        await runtime.pool.close(true).catch(() => undefined);
        throw outcome.error;
      }
      if (interrupted(runtime.options.signal)) throw new ScanPauseError("scan paused");
      const file = "prepared" in outcome ? outcome.prepared.file : outcome.file;
      beginManifestFile(runtime, file);
      let completelyScanned = false;
      if ("prepared" in outcome) {
        try {
          await assertPreparedFileCurrent(runtime, outcome.prepared);
          const result: DetectorWorkResult = {
            kind: "small-file",
            data: outcome.prepared.data,
            context: {
              sourcePath: file.path,
              baseOffset: 0,
              wholeFile: false,
              deepKeySchedules: false,
            },
            batches: outcome.prepared.batches.slice(0, STREAMING_DETECTOR_NAMES.length),
          };
          const commitStarted = performance.now();
          try {
            completelyScanned = await commitDetectorResults(
              result,
              file.path,
              runtime.options.provenance,
              runtime.store,
              runtime.options.signal,
            );
          } finally {
            runtime.metrics.deterministicCommitMs += performance.now() - commitStarted;
          }
          await assertPreparedFileCurrent(runtime, outcome.prepared);
          runtime.state.cursor = { fileIndex: file.index, phase: "stream", nextOffset: file.bytes };
          runtime.progress.bytesScanned += file.bytes;
          await publishProgress(runtime);
          await maybeCheckpoint();
          await assertPreparedFileCurrent(runtime, outcome.prepared);
          runtime.state.cursor = { fileIndex: file.index, phase: "whole-file", nextOffset: 0 };
          if (interrupted(runtime.options.signal)) throw new ScanPauseError("scan paused");
          const structuredBatch = outcome.prepared.batches[STREAMING_DETECTOR_NAMES.length];
          if (structuredBatch === undefined) {
            throw new ScanControlError("small-file worker omitted its structured detector result");
          }
          const structuredStarted = performance.now();
          try {
            completelyScanned = await commitDetectorResults({
              kind: "structured",
              data: outcome.prepared.data,
              context: {
                sourcePath: file.path,
                baseOffset: 0,
                wholeFile: true,
                deepKeySchedules: false,
              },
              batches: [structuredBatch],
            }, file.path, runtime.options.provenance, runtime.store, runtime.options.signal) && completelyScanned;
          } finally {
            runtime.metrics.deterministicCommitMs += performance.now() - structuredStarted;
          }
          runtime.metrics.completeFileBuffersReused += 1;
          await assertPreparedFileCurrent(runtime, outcome.prepared);
          await outcome.prepared.handle.close();
          closedHandles.add(outcome.prepared.handle);
        } catch (error) {
          if (error instanceof ArtifactWriteError || error instanceof ScanControlError || quotaReason(error) !== undefined || interrupted(runtime.options.signal)) {
            await runtime.pool.close(true).catch(() => undefined);
            throw error;
          }
          runtime.store.recordError(file.path, "read-or-scan", error);
          completelyScanned = false;
        }
      } else {
        runtime.store.recordError(file.path, "read-or-scan", outcome.error);
      }
      await completeManifestFile(runtime, file, completelyScanned);
      await maybeCheckpoint();
    }
  } finally {
    const settled = await Promise.all(pendingOutcomes);
    await Promise.all(settled.flatMap((outcome) => (
      "prepared" in outcome && !closedHandles.has(outcome.prepared.handle)
        ? [outcome.prepared.handle.close().catch(() => undefined)]
        : []
    )));
  }
}

function sameRootSnapshots(left: PathSafetySnapshot[], right: ScanState["inputRoots"]): boolean {
  return left.length === right.length && left.every((item, index) => {
    const expected = right[index];
    return expected !== undefined
      && item.path === expected.path
      && item.device === expected.device
      && item.inode === expected.inode
      && item.kind === expected.kind
      && item.mount === expected.mount;
  });
}

function manifestFileIsAuthorized(filename: string, roots: PathSafetySnapshot[]): boolean {
  return roots.some((root) => root.kind === "file"
    ? filename === root.path
    : filename !== root.path && inside(root.path, filename));
}

function assertResumeInventoryMatchesState(inventory: SensitiveScanInventory, state: ScanState): void {
  const occurrences = inventory.findings.reduce((sum, finding) => sum + finding.occurrences.length, 0);
  const scanErrors = inventory.errors.length + inventory.errorsOmitted;
  if (
    inventory.findings.length !== state.progress.uniqueFindings
    || occurrences !== state.progress.occurrences
    || scanErrors !== state.progress.scanErrors
    || JSON.stringify(inventory.resumeCheckpoint) !== JSON.stringify(inventoryCheckpoint(state))
    || inventory.findings.some((finding) => finding.occurrences.some((occurrence) => (
      occurrence.provenance !== state.semantic.provenance
      || !manifestFileIsAuthorized(occurrence.sourcePath, state.inputRoots)
    )))
  ) throw new Error("paused inventory counts, occurrences, or checkpoint do not match the resumable scan state");
}

function inventoryCheckpoint(state: ScanState): NonNullable<SensitiveScanInventory["resumeCheckpoint"]> {
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

async function publishProgress(runtime: ScanRuntime): Promise<void> {
  Object.assign(runtime.progress, runtime.store.counts());
  try {
    runtime.options.progress?.({ ...runtime.progress });
  } catch (error) {
    throw new ScanControlError("progress callback failed", { cause: error });
  }
}

async function createFrozenInputManifest(
  options: NormalizedMiningOptions,
  isNetworkMount: (record: MountRecord) => Promise<boolean>,
  store: ArtifactStore,
  budget: StorageBudget,
  progress: MiningProgress,
  assertSafeOutput: () => Promise<void>,
  metrics: MiningMetrics,
): Promise<ScanState["manifest"]> {
  const traversalStarted = performance.now();
  progress.phase = "inventory";
  progress.filesTotal = 0;
  let currentMounts = await mounts();
  let mountsUpdatedAt = Date.now();
  const walked = walkRegularFiles(options.inputs, {
    ...(options.signal === undefined ? {} : { signal: options.signal }),
    onError: (sourcePath, error) => store.recordError(sourcePath, "walk-entry", error),
    shouldEnterDirectory: async (directory) => {
      if (Date.now() - mountsUpdatedAt >= PERIODIC_SAFETY_INTERVAL_MS) {
        currentMounts = await mounts();
        mountsUpdatedAt = Date.now();
      }
      const mounted = mountForPathFrom(currentMounts, directory);
      return mounted !== undefined && !(await isNetworkMount(mounted));
    },
  });
  async function* tracked(): AsyncGenerator<WalkedFile> {
    for await (const file of walked) {
      if (interrupted(options.signal)) throw new ScanPauseError("scan paused during input inventory");
      progress.filesTotal = (progress.filesTotal ?? 0) + 1;
      if (progress.filesTotal % 1_000 === 0) {
        Object.assign(progress, store.counts());
        try {
          options.progress?.({ ...progress });
        } catch (error) {
          throw new ScanControlError("progress callback failed", { cause: error });
        }
      }
      yield file;
    }
    if (interrupted(options.signal)) throw new ScanPauseError("scan paused during input inventory");
  }
  try {
    const manifest = await createScanManifest(options.output, tracked(), budget, assertSafeOutput);
    Object.assign(progress, store.counts());
    return manifest;
  } catch (error) {
    if (
      interrupted(options.signal)
      && error instanceof Error
      && error.message === "regular-file walk was paused"
    ) throw new ScanPauseError("scan paused during input inventory", { cause: error });
    throw error;
  } finally {
    metrics.inventoryTraversalMs += performance.now() - traversalStarted;
  }
}

async function* emptyManifestFiles(): AsyncGenerator<WalkedFile> {
  return;
}

async function finalizeInventoryPause(
  options: NormalizedMiningOptions,
  state: ScanState,
  store: ArtifactStore,
  budget: StorageBudget,
  progress: MiningProgress,
  reason: NonNullable<ScanState["pauseReason"]>,
  metrics: MiningMetrics,
): Promise<Record<string, unknown>> {
  progress.phase = "inventory";
  return await finalizeCleanPause(options, state, store, budget, progress, reason, `scan paused during input inventory: ${reason}`, metrics);
}

async function finalizeCleanPause(
  options: NormalizedMiningOptions,
  state: ScanState,
  store: ArtifactStore,
  budget: StorageBudget,
  progress: MiningProgress,
  reason: NonNullable<ScanState["pauseReason"]>,
  message = `scan paused: ${reason}`,
  metrics?: MiningMetrics,
  pool?: DetectorWorkerPool,
): Promise<Record<string, unknown>> {
  Object.assign(progress, store.counts());
  state.status = "paused";
  state.resumable = true;
  state.pauseReason = reason;
  state.updatedAt = new Date().toISOString();
  state.progress = { ...progress };
  const inventory = await store.finalize("paused", progress, message, true, inventoryCheckpoint(state));
  state.inventory = { filename: "inventory-sensitive.json", ...inventory };
  await writeScanState(options.output, state, budget, true);
  return resultObject("paused", progress, state, options.deepKeySchedules === true, metrics, pool);
}

async function persistCheckpoint(runtime: ScanRuntime): Promise<void> {
  const started = performance.now();
  runtime.state.updatedAt = new Date().toISOString();
  runtime.state.progress = { ...runtime.progress };
  try {
    const inventory = await runtime.store.checkpoint(runtime.progress, inventoryCheckpoint(runtime.state));
    runtime.state.inventory = { filename: "inventory-sensitive.json", ...inventory };
    await writeScanState(runtime.options.output, runtime.state, runtime.budget);
    runtime.metrics.checkpointBytes += inventory.bytes;
  } finally {
    runtime.metrics.checkpoints += 1;
    runtime.metrics.checkpointMs += performance.now() - started;
  }
}

async function verifyCompletedManifestFiles(output: string, state: ScanState, inputRoots: PathSafetySnapshot[], signal?: AbortSignal): Promise<void> {
  let cursorFileSeen = state.cursor.fileIndex === state.manifest.entries;
  for await (const file of readScanManifest(output, state.manifest, signal)) {
    if (interrupted(signal)) throw new Error("scan manifest verification was interrupted");
    // Manifest creation visits each lexical path once. Its count and SHA-256
    // are integrity-linked to both resume documents, so verification need not
    // retain every path in memory merely to rediscover generation-time uniqueness.
    if (!manifestFileIsAuthorized(file.path, inputRoots)) {
      throw new Error("scan manifest contains a path outside the authorized input roots");
    }
    if (file.index === state.cursor.fileIndex) {
      cursorFileSeen = true;
      if (
        state.cursor.phase === "stream"
        && (
          state.cursor.nextOffset > file.bytes
          || (state.cursor.nextOffset !== file.bytes && state.cursor.nextOffset % state.semantic.chunkBytes !== 0)
        )
      ) throw new Error("scan resume cursor is not aligned with its frozen input file");
    }
    if (file.index > state.cursor.fileIndex || (file.index === state.cursor.fileIndex && state.cursor.nextOffset === 0 && state.cursor.phase === "stream")) continue;
    let metadata: Awaited<ReturnType<typeof lstat>>;
    let canonicalPath: string;
    try {
      [metadata, canonicalPath] = await Promise.all([lstat(file.path), realpath(file.path)]);
    } catch (error) {
      throw new Error("a completed or partial resume input is no longer stably addressable", { cause: error });
    }
    if (metadata.isSymbolicLink() || !metadata.isFile() || canonicalPath !== file.path) {
      throw new Error("a completed resume input is no longer a canonical regular file");
    }
    if (metadata.dev !== file.device || metadata.ino !== file.inode || metadata.size !== file.bytes || metadata.mtimeMs !== file.modifiedMs || metadata.ctimeMs !== file.changedMs) {
      throw new Error("a completed or partial resume input changed after its checkpoint");
    }
  }
  if (!cursorFileSeen) throw new Error("scan resume cursor does not reference its frozen input manifest");
}

async function processFile(runtime: ScanRuntime, file: FrozenScanFile, cursor: ScanCursor, maybeCheckpoint: (force?: boolean) => Promise<void>): Promise<boolean> {
  const handle = await open(file.path, constants.O_RDONLY | constants.O_NOFOLLOW);
  let clean = true;
  let completeFileData: Buffer | undefined;
  try {
    const assertSourceCurrent = async (): Promise<void> => {
      const started = performance.now();
      try {
        const current = await handle.stat();
        assertFileSnapshot(file, current);
        await assertOpenedFilePathCurrent(file.path, handle, current);
      } finally {
        runtime.metrics.fileValidationCalls += 1;
        runtime.metrics.fileValidationMs += performance.now() - started;
      }
    };
    await assertSourceCurrent();
    if (cursor.phase === "stream") {
      let offset = cursor.nextOffset;
      while (offset < file.bytes) {
        if (interrupted(runtime.options.signal)) {
          await assertSourceCurrent();
          throw new ScanPauseError("scan paused");
        }
        if (runtime.options.deepKeySchedules === true) {
          const primaryOffset = offset;
          const primaryEnd = Math.min(file.bytes, primaryOffset + runtime.options.chunkBytes);
          const windowStart = primaryOffset === 0 ? 0 : Math.max(0, primaryOffset - runtime.options.overlapBytes);
          const data = await readExact(handle, windowStart, primaryEnd - windowStart, runtime.metrics);
          if (cursor.nextOffset === 0 && windowStart === 0 && primaryEnd === file.bytes) completeFileData = data;
          const context: DetectionContext = { sourcePath: file.path, baseOffset: windowStart, wholeFile: false, deepKeySchedules: false };
          clean = await commitDetectorWorkInBatches(
            runtime,
            workForWindow(data, context, true, primaryOffset - windowStart),
            file.path,
            assertSourceCurrent,
          ) && clean;
          await assertSourceCurrent();
          if (interrupted(runtime.options.signal)) throw new ScanPauseError("scan paused");
          offset = primaryEnd;
          runtime.state.cursor = { fileIndex: file.index, phase: "stream", nextOffset: offset };
          runtime.progress.bytesScanned += primaryEnd - primaryOffset;
          await publishProgress(runtime);
          await maybeCheckpoint();
          await assertSourceCurrent();
          continue;
        }
        const offsets: number[] = [];
        const bufferedParallelism = Math.max(
          1,
          Math.floor(MAX_BUFFERED_SCAN_WINDOWS_BYTES / (runtime.options.chunkBytes + runtime.options.overlapBytes)),
        );
        const parallelChunks = Math.min(runtime.options.workers, bufferedParallelism);
        for (let index = 0; index < parallelChunks && offset + index * runtime.options.chunkBytes < file.bytes; index += 1) {
          offsets.push(offset + index * runtime.options.chunkBytes);
        }
        const windows = await Promise.all(offsets.map(async (primaryOffset) => {
          const primaryEnd = Math.min(file.bytes, primaryOffset + runtime.options.chunkBytes);
          const windowStart = primaryOffset === 0 ? 0 : Math.max(0, primaryOffset - runtime.options.overlapBytes);
          const data = await readExact(handle, windowStart, primaryEnd - windowStart, runtime.metrics);
          if (cursor.nextOffset === 0 && windowStart === 0 && primaryEnd === file.bytes) completeFileData = data;
          const context: DetectionContext = { sourcePath: file.path, baseOffset: windowStart, wholeFile: false, deepKeySchedules: false };
          return { primaryOffset, primaryEnd, data, context };
        }));
        await assertSourceCurrent();
        const orderedWork = windows.flatMap((window) => workForWindow(window.data, window.context, false));
        let completedWork = 0;
        for await (const result of runDetectorWorkOrdered(runtime.pool, orderedWork, runtime.options.signal)) {
          await assertSourceCurrent();
          if (interrupted(runtime.options.signal)) throw new ScanPauseError("scan paused");
          const commitStarted = performance.now();
          try {
            clean = await commitDetectorResults(result, file.path, runtime.options.provenance, runtime.store, runtime.options.signal) && clean;
          } finally {
            runtime.metrics.deterministicCommitMs += performance.now() - commitStarted;
          }
          completedWork += 1;
          const analyzedChunk = windows[completedWork - 1];
          if (analyzedChunk === undefined) throw new Error("detector chunk ordering became inconsistent");
          await assertSourceCurrent();
          if (interrupted(runtime.options.signal)) throw new ScanPauseError("scan paused");
          offset = analyzedChunk.primaryEnd;
          runtime.state.cursor = { fileIndex: file.index, phase: "stream", nextOffset: offset };
          runtime.progress.bytesScanned += analyzedChunk.primaryEnd - analyzedChunk.primaryOffset;
          await publishProgress(runtime);
          await maybeCheckpoint();
          await assertSourceCurrent();
        }
        if (completedWork !== orderedWork.length) throw new Error("detector work did not complete its ordered batch");
        await assertSourceCurrent();
      }
      runtime.state.cursor = { fileIndex: file.index, phase: "whole-file", nextOffset: 0 };
    }
    if (file.bytes <= runtime.options.wholeFileBytes) {
      await assertSourceCurrent();
      if (interrupted(runtime.options.signal)) throw new ScanPauseError("scan paused");
      const data = completeFileData ?? await readExact(handle, 0, file.bytes, runtime.metrics);
      if (completeFileData !== undefined) runtime.metrics.completeFileBuffersReused += 1;
      const context: DetectionContext = {
        sourcePath: file.path,
        baseOffset: 0,
        wholeFile: true,
        deepKeySchedules: runtime.options.deepKeySchedules === true,
      };
      const [result] = await runDetectorWork(runtime.pool, [{ kind: "structured", data, context }], runtime.options.signal);
      if (result === undefined) throw new Error("structured detector worker returned no result");
      await assertSourceCurrent();
      const commitStarted = performance.now();
      try {
        clean = await commitDetectorResults(result, file.path, runtime.options.provenance, runtime.store, runtime.options.signal) && clean;
      } finally {
        runtime.metrics.deterministicCommitMs += performance.now() - commitStarted;
      }
    }
    await assertSourceCurrent();
    return clean;
  } finally {
    await handle.close();
  }
}

function resultObject(
  status: MiningRunStatus,
  progress: MiningProgress,
  state: ScanState,
  deep: boolean,
  metrics?: MiningMetrics,
  pool?: DetectorWorkerPool,
): Record<string, unknown> {
  const complete = status === "complete" || status === "complete-with-errors";
  return {
    status,
    complete,
    resumable: status === "paused" && state.resumable,
    ...(state.pauseReason === undefined ? {} : { pauseReason: state.pauseReason }),
    allFilesScannedWithoutErrors: status === "complete",
    filesTotal: progress.filesTotal ?? state.manifest.entries,
    filesVisited: progress.filesVisited,
    filesScanned: progress.filesScanned,
    bytesScanned: progress.bytesScanned,
    uniqueFindings: progress.uniqueFindings,
    occurrences: progress.occurrences,
    scanErrors: progress.scanErrors,
    deepKeySchedules: deep,
    workers: state.operational.workers,
    valuesPrinted: false,
    reports: { sensitive: "final-report-sensitive.md", redacted: "final-report-redacted.md" },
    ...(metrics === undefined ? {} : { performance: metrics.snapshot(pool?.metrics()) }),
    ...(status === "paused" ? { resumeCommand: "aark mine resume --output <OUTPUT_DIRECTORY>" } : {}),
  };
}

function quotaReason(error: unknown): ScanState["pauseReason"] | undefined {
  let current: unknown = error;
  for (let depth = 0; depth < 8 && current !== undefined; depth += 1) {
    if (current instanceof StorageQuotaError) return current.reason;
    current = current instanceof Error && "cause" in current ? current.cause : undefined;
  }
  return undefined;
}

async function runManifest(runtime: ScanRuntime): Promise<Record<string, unknown>> {
  let lastCheckpoint = Date.now();
  let filesAtCheckpoint = runtime.progress.filesVisited;
  let bytesAtCheckpoint = runtime.progress.bytesScanned;
  let lastSafetyCheck = 0;
  let bytesAtSafetyCheck = runtime.progress.bytesScanned;
  let cachedInputInspection: { records: MountRecord[]; changedFileRoots: Set<string> } | undefined;
  let inputInspectedAt = 0;
  const recordedChangedFileRoots = new Set<string>();
  const inspectInputs = async (force = false): Promise<{ records: MountRecord[]; changedFileRoots: Set<string> }> => {
    if (!force && cachedInputInspection !== undefined && Date.now() - inputInspectedAt < PERIODIC_SAFETY_INTERVAL_MS) {
      return cachedInputInspection;
    }
    const started = performance.now();
    try {
      cachedInputInspection = await inspectRuntimeInputRoots(
        runtime.inputSafety,
        (snapshot, error) => {
          if (recordedChangedFileRoots.has(snapshot.path)) return;
          recordedChangedFileRoots.add(snapshot.path);
          runtime.store.recordError(snapshot.path, "input-root", error);
        },
      );
      inputInspectedAt = Date.now();
      return cachedInputInspection;
    } finally {
      runtime.metrics.rootValidationCalls += 1;
      runtime.metrics.rootValidationMs += performance.now() - started;
    }
  };
  const inspectRuntimeSafety = async (force = false): Promise<void> => {
    const due = force
      || Date.now() - lastSafetyCheck >= PERIODIC_SAFETY_INTERVAL_MS
      || runtime.progress.bytesScanned - bytesAtSafetyCheck >= PERIODIC_SAFETY_BYTES;
    if (!due) return;
    const started = performance.now();
    try {
      await inspectInputs(true);
      await assertRuntimeOutputCurrent(runtime);
      await assertStorageCapacity(runtime.options.output, runtime.policy, runtime.budget.outputBytes());
      lastSafetyCheck = Date.now();
      bytesAtSafetyCheck = runtime.progress.bytesScanned;
    } finally {
      runtime.metrics.periodicSafetyChecks += 1;
      runtime.metrics.periodicSafetyCheckMs += performance.now() - started;
    }
  };
  const maybeCheckpoint = async (force = false): Promise<void> => {
    await inspectRuntimeSafety(false);
    const madeProgress = runtime.progress.filesVisited !== filesAtCheckpoint
      || runtime.progress.bytesScanned !== bytesAtCheckpoint;
    if (force || (madeProgress && Date.now() - lastCheckpoint >= CHECKPOINT_INTERVAL_MS)) {
      await inspectRuntimeSafety(true);
      await persistCheckpoint(runtime);
      lastCheckpoint = Date.now();
      filesAtCheckpoint = runtime.progress.filesVisited;
      bytesAtCheckpoint = runtime.progress.bytesScanned;
    }
  };
  const abortPool = (): void => { void runtime.pool.close(true).catch(() => undefined); };
  runtime.options.signal?.addEventListener("abort", abortPool, { once: true });
  const skipManifestFile = async (file: FrozenScanFile, operation?: string, error?: unknown): Promise<void> => {
    beginManifestFile(runtime, file);
    if (operation !== undefined) runtime.store.recordError(file.path, operation, error);
    await completeManifestFile(runtime, file, false);
    await maybeCheckpoint();
  };
  const fileIsOnAcceptedMount = async (
    file: FrozenScanFile,
    inspection: { records: MountRecord[]; changedFileRoots: Set<string> },
  ): Promise<boolean> => {
    if (inspection.changedFileRoots.has(file.path)) return false;
    const fileMount = mountForPathFrom(inspection.records, file.path);
    return fileMount !== undefined && !(await runtime.isNetworkMount(fileMount));
  };
  const processRegularManifestFile = async (file: FrozenScanFile): Promise<void> => {
    const inspection = await inspectInputs(false);
    if (inspection.changedFileRoots.has(file.path)) {
      await skipManifestFile(file);
      return;
    }
    if (!(await fileIsOnAcceptedMount(file, inspection))) {
      await skipManifestFile(file, "walk-entry", new Error("refusing to scan a network-mounted file"));
      return;
    }
    beginManifestFile(runtime, file);
    runtime.progress.phase = runtime.state.cursor.phase;
    let completelyScanned = false;
    try {
      completelyScanned = await processFile(runtime, file, runtime.state.cursor, maybeCheckpoint);
    } catch (error) {
      if (error instanceof ArtifactWriteError || error instanceof ScanControlError || quotaReason(error) !== undefined || interrupted(runtime.options.signal)) throw error;
      runtime.store.recordError(file.path, "read-or-scan", error);
    }
    await completeManifestFile(runtime, file, completelyScanned);
    await maybeCheckpoint();
    if (interrupted(runtime.options.signal)) throw new ScanPauseError("scan paused");
  };
  const processCandidateSmallBatch = async (files: FrozenScanFile[]): Promise<void> => {
    if (files.length === 0) return;
    const inspection = await inspectInputs(false);
    let accepted: FrozenScanFile[] = [];
    const flushAccepted = async (): Promise<void> => {
      if (accepted.length === 0) return;
      const current = accepted;
      accepted = [];
      await processSmallFileBatch(runtime, current, maybeCheckpoint);
    };
    for (const file of files) {
      if (inspection.changedFileRoots.has(file.path)) {
        await flushAccepted();
        await skipManifestFile(file);
      } else if (!(await fileIsOnAcceptedMount(file, inspection))) {
        await flushAccepted();
        await skipManifestFile(file, "walk-entry", new Error("refusing to scan a network-mounted file"));
      } else {
        accepted.push(file);
      }
    }
    await flushAccepted();
    if (interrupted(runtime.options.signal)) throw new ScanPauseError("scan paused");
  };
  try {
    runtime.state.status = "in-progress";
    runtime.state.resumable = false;
    delete runtime.state.pauseReason;
    await inspectRuntimeSafety(true);
    await persistCheckpoint(runtime);
    let pendingSmallFiles: FrozenScanFile[] = [];
    let pendingSmallBytes = 0;
    const flushSmallFiles = async (): Promise<void> => {
      if (pendingSmallFiles.length === 0) return;
      const current = pendingSmallFiles;
      pendingSmallFiles = [];
      pendingSmallBytes = 0;
      await processCandidateSmallBatch(current);
    };
    for await (const file of readScanManifest(runtime.options.output, runtime.state.manifest, runtime.options.signal)) {
      if (file.index < runtime.state.cursor.fileIndex) continue;
      if (interrupted(runtime.options.signal)) throw new ScanPauseError("scan paused");
      if (!manifestFileIsAuthorized(file.path, runtime.inputSafety)) {
        throw new ScanControlError("scan manifest contains a file outside the authorized input roots");
      }
      const startsAtBeginning = file.index !== runtime.state.cursor.fileIndex
        || (runtime.state.cursor.phase === "stream" && runtime.state.cursor.nextOffset === 0);
      const smallFileEligible = startsAtBeginning
        && runtime.options.deepKeySchedules !== true
        && file.bytes <= runtime.options.chunkBytes
        && file.bytes <= runtime.options.wholeFileBytes
        && file.bytes <= MAX_BUFFERED_SMALL_FILES_BYTES;
      if (!smallFileEligible) {
        await flushSmallFiles();
        await processRegularManifestFile(file);
        continue;
      }
      if (
        pendingSmallFiles.length >= runtime.options.workers
        || (pendingSmallFiles.length > 0 && pendingSmallBytes + file.bytes > MAX_BUFFERED_SMALL_FILES_BYTES)
      ) await flushSmallFiles();
      pendingSmallFiles.push(file);
      pendingSmallBytes += file.bytes;
      if (pendingSmallFiles.length >= runtime.options.workers) await flushSmallFiles();
    }
    await flushSmallFiles();
    if (interrupted(runtime.options.signal)) throw new ScanPauseError("scan paused");
    await inspectRuntimeSafety(true);
    await runtime.pool.close();
  } catch (error) {
    let failure = error;
    const manifestInterrupted = manifestVerificationInterrupted(error, runtime.options.signal);
    const candidateReason = error instanceof ScanPauseError || manifestInterrupted
      ? "signal"
      : quotaReason(error);
    if (candidateReason !== undefined) {
      try {
        const pauseInspection = await inspectInputs(true);
        if (pauseInspection.changedFileRoots.size > 0) {
          throw new ScanControlError("an explicit file input root changed, so the scan cannot publish a resumable pause");
        }
        // A root identity check cannot see a changed child. Validate the exact
        // completed/partial manifest prefix before claiming the checkpoint can
        // be resumed; future files remain intentionally outside that claim.
        await verifyCompletedManifestFiles(
          runtime.options.output,
          runtime.state,
          runtime.inputSafety,
        );
      } catch (validationError) {
        failure = validationError;
      }
    }
    const reason = failure === error ? candidateReason : undefined;
    Object.assign(runtime.progress, runtime.store.counts());
    if (reason !== undefined) {
      await runtime.pool.close(true).catch(() => undefined);
      runtime.state.status = "paused";
      runtime.state.resumable = true;
      runtime.state.pauseReason = reason;
      runtime.state.updatedAt = new Date().toISOString();
      runtime.state.progress = { ...runtime.progress };
      const inventory = await runtime.store.finalize("paused", runtime.progress, `scan paused: ${reason}`, true, inventoryCheckpoint(runtime.state));
      runtime.state.inventory = { filename: "inventory-sensitive.json", ...inventory };
      await writeScanState(runtime.options.output, runtime.state, runtime.budget, true);
      return resultObject("paused", runtime.progress, runtime.state, runtime.options.deepKeySchedules === true, runtime.metrics, runtime.pool);
    }
    runtime.store.recordError("<scan>", "scan-run", failure);
    await runtime.pool.close(true).catch(() => undefined);
    Object.assign(runtime.progress, runtime.store.counts());
    runtime.state.status = "failed";
    runtime.state.resumable = false;
    runtime.state.updatedAt = new Date().toISOString();
    runtime.state.progress = { ...runtime.progress };
    try {
      const inventory = await runtime.store.finalize("failed", runtime.progress, failure instanceof Error ? failure.message : String(failure), true, inventoryCheckpoint(runtime.state));
      runtime.state.inventory = { filename: "inventory-sensitive.json", ...inventory };
      await writeScanState(runtime.options.output, runtime.state, runtime.budget, true);
    } catch (reportError) {
      throw new AggregateError([failure, reportError], "scan failed and final report generation also failed");
    }
    throw failure;
  } finally {
    runtime.options.signal?.removeEventListener("abort", abortPool);
  }

  Object.assign(runtime.progress, runtime.store.counts());
  runtime.progress.phase = "finalizing";
  const status = runtime.progress.scanErrors === 0 ? "complete" : "complete-with-errors";
  runtime.state.status = status;
  runtime.state.resumable = false;
  delete runtime.state.pauseReason;
  runtime.state.updatedAt = new Date().toISOString();
  runtime.state.progress = { ...runtime.progress };
  try {
    const inventory = await runtime.store.finalize(status, runtime.progress, undefined, false, inventoryCheckpoint(runtime.state));
    runtime.state.inventory = { filename: "inventory-sensitive.json", ...inventory };
    await writeScanState(runtime.options.output, runtime.state, runtime.budget);
    return resultObject(status, runtime.progress, runtime.state, runtime.options.deepKeySchedules === true, runtime.metrics, runtime.pool);
  } catch (error) {
    let failure = error;
    const candidateReason = quotaReason(error);
    if (candidateReason !== undefined) {
      try {
        await assertPauseInputRootsCurrent(runtime.inputSafety);
        await verifyCompletedManifestFiles(runtime.options.output, runtime.state, runtime.inputSafety);
      } catch (validationError) {
        failure = validationError;
      }
    }
    if (failure === error && candidateReason !== undefined) {
      return await finalizeCleanPause(runtime.options, runtime.state, runtime.store, runtime.budget, runtime.progress, candidateReason, undefined, runtime.metrics, runtime.pool);
    }
    runtime.store.recordError("<scan>", "finalize", failure);
    Object.assign(runtime.progress, runtime.store.counts());
    runtime.state.status = "failed";
    runtime.state.resumable = false;
    delete runtime.state.pauseReason;
    runtime.state.updatedAt = new Date().toISOString();
    runtime.state.progress = { ...runtime.progress };
    try {
      const inventory = await runtime.store.finalize("failed", runtime.progress, failure instanceof Error ? failure.message : String(failure), true, inventoryCheckpoint(runtime.state));
      runtime.state.inventory = { filename: "inventory-sensitive.json", ...inventory };
      await writeScanState(runtime.options.output, runtime.state, runtime.budget, true);
    } catch (reportError) {
      throw new AggregateError([failure, reportError], "scan completion failed and its final failure report could not be fully written");
    }
    throw failure;
  }
}

async function mountSetup(inputs: string[], outputParent: string): Promise<{
  inputSafety: PathSafetySnapshot[];
  isNetworkMount: (record: MountRecord) => Promise<boolean>;
}> {
  const mountSnapshot = await mounts();
  const networkMountCache = new Map<string, Promise<boolean>>();
  const isNetworkMount = async (record: MountRecord): Promise<boolean> => {
    const key = mountIdentity(record);
    let result = networkMountCache.get(key);
    if (result === undefined) {
      result = mountIsNetworkBacked(record);
      networkMountCache.set(key, result);
    }
    return await result;
  };
  const inputSafety: PathSafetySnapshot[] = [];
  for (const inputRoot of inputs) {
    const inputMount = mountForPathFrom(mountSnapshot, inputRoot);
    if (inputMount === undefined) throw new Error("could not determine the mount backing a mining input");
    if (await isNetworkMount(inputMount)) throw new Error("network-mounted mining inputs are not allowed");
    inputSafety.push(await pathSafetySnapshot(inputRoot, mountSnapshot));
  }
  const outputMount = mountForPathFrom(mountSnapshot, outputParent);
  if (outputMount === undefined) throw new Error("could not determine the mount backing the mining output");
  if (await isNetworkMount(outputMount)) throw new Error("network-mounted mining outputs are not allowed");
  return { inputSafety, isNetworkMount };
}

export async function scanSensitiveMaterial(input: MiningOptions): Promise<Record<string, unknown>> {
  const metrics = new MiningMetrics();
  const validated = validatedOptions(input);
  const canonical = await assertFreshSafeOutput(validated.inputs, validated.output);
  const options = { ...validated, ...canonical };
  const policy = storagePolicyFromGiB(options.minimumFreeGiB, options.minimumFreePercent, options.maximumOutputGiB);
  const outputParent = await nearestExistingParent(options.output);
  await assertStorageCapacity(outputParent, policy);
  const setup = await mountSetup(options.inputs, outputParent);
  const locks = await acquireMiningLocks(options.output);
  const lock = locks.find((candidate) => path.basename(candidate.path) === MINING_LOCK_FILENAME);
  if (lock === undefined) {
    await releaseMiningLocks(locks);
    throw new Error("current mining operation lock was not acquired");
  }
  let runFailure: unknown;
  try {
    await assertLockedFreshOutput(options.output);
    const outputSafety = await outputSafetySnapshot(options.output, lock.path);
    const assertSafeOutput = async (): Promise<void> => {
      for (const held of locks) await held.assertHeld();
      await assertOutputSafetyCurrent(outputSafety, lock.path);
    };
    // A fresh output contains only the operation locks at this point. Do not
    // let an already-aborted signal prevent creation of the clean, resumable
    // inventory-phase pause that the caller requested.
    const budget = new StorageBudget(options.output, policy, await directoryLogicalBytes(options.output));
    const store = new ArtifactStore(options.output, options.inputs, options.deepKeySchedules === true, assertSafeOutput, budget, metrics);
    await store.initialize();
    const progress: MiningProgress = {
      phase: "inventory",
      filesTotal: 0,
      filesVisited: 0,
      filesScanned: 0,
      bytesScanned: 0,
      uniqueFindings: 0,
      occurrences: 0,
      scanErrors: 0,
    };
    let manifest: ScanState["manifest"];
    try {
      manifest = await createFrozenInputManifest(options, setup.isNetworkMount, store, budget, progress, assertSafeOutput, metrics);
    } catch (error) {
      let failure = error;
      const candidateReason = error instanceof ScanPauseError ? "signal" : quotaReason(error);
      if (candidateReason !== undefined) {
        try {
          await assertPauseInputRootsCurrent(setup.inputSafety);
        } catch (validationError) {
          failure = validationError;
        }
      }
      const reason = failure === error ? candidateReason : undefined;
      const emptyManifest = await createScanManifest(options.output, emptyManifestFiles(), budget, assertSafeOutput);
      const state = newScanState(semanticOptions(options), operationalOptions(options), emptyManifest, {
        filename: "inventory-sensitive.json",
        bytes: 0,
        sha256: "0".repeat(64),
      }, progress, setup.inputSafety);
      state.inventoryComplete = false;
      if (reason !== undefined) return await finalizeInventoryPause(options, state, store, budget, progress, reason, metrics);
      store.recordError("<scan>", "input-inventory", failure);
      Object.assign(progress, store.counts());
      state.status = "failed";
      state.resumable = false;
      state.updatedAt = new Date().toISOString();
      state.progress = { ...progress };
      try {
        const failedInventory = await store.finalize("failed", progress, failure instanceof Error ? failure.message : String(failure), true, inventoryCheckpoint(state));
        state.inventory = { filename: "inventory-sensitive.json", ...failedInventory };
        await writeScanState(options.output, state, budget, true);
      } catch (reportError) {
        throw new AggregateError([failure, reportError], "input inventory failed and final report generation also failed");
      }
      throw failure;
    }
    progress.filesTotal = manifest.entries;
    progress.phase = "stream";
    const state = newScanState(semanticOptions(options), operationalOptions(options), manifest, {
      filename: "inventory-sensitive.json",
      bytes: 0,
      sha256: "0".repeat(64),
    }, progress, setup.inputSafety);
    let pool: DetectorWorkerPool;
    try {
      const inventory = await store.checkpoint(progress, inventoryCheckpoint(state));
      state.inventory = { filename: "inventory-sensitive.json", ...inventory };
      await writeScanState(options.output, state, budget);
      await verifyCompletedManifestFiles(options.output, state, setup.inputSafety, options.signal);
      pool = new DetectorWorkerPool(options.workers);
    } catch (error) {
      let failure = error;
      const candidateReason = manifestVerificationInterrupted(error, options.signal) ? "signal" : quotaReason(error);
      if (candidateReason !== undefined) {
        try {
          await assertPauseInputRootsCurrent(setup.inputSafety);
        } catch (validationError) {
          failure = validationError;
        }
      }
      const reason = failure === error ? candidateReason : undefined;
      if (reason !== undefined) {
        return await finalizeCleanPause(options, state, store, budget, progress, reason, undefined, metrics);
      }
      store.recordError("<scan>", "manifest-or-worker-start", failure);
      Object.assign(progress, store.counts());
      state.status = "failed";
      state.resumable = false;
      state.updatedAt = new Date().toISOString();
      state.progress = { ...progress };
      try {
        const failedInventory = await store.finalize("failed", progress, failure instanceof Error ? failure.message : String(failure), true, inventoryCheckpoint(state));
        state.inventory = { filename: "inventory-sensitive.json", ...failedInventory };
        await writeScanState(options.output, state, budget, true);
      } catch (reportError) {
        throw new AggregateError([failure, reportError], "scan startup verification failed and final report generation also failed");
      }
      throw failure;
    }
    return await runManifest({
      options,
      policy,
      inputSafety: setup.inputSafety,
      outputSafety,
      lockPath: lock.path,
      locks,
      store,
      budget,
      pool,
      state,
      progress,
      isNetworkMount: setup.isNetworkMount,
      metrics,
    });
  } catch (error) {
    runFailure = error;
    throw error;
  } finally {
    try {
      await releaseMiningLocks(locks);
    } catch (releaseError) {
      if (runFailure !== undefined) throw new AggregateError([runFailure, releaseError], "scan failed and its exclusive output locks could not be released");
      throw releaseError;
    }
  }
}

function resumeOptions(state: ScanState, input: MiningResumeOptions): NormalizedMiningOptions {
  const operational: ScanOperationalOptions = {
    workers: validateWorkerCount(input.workers ?? state.operational.workers),
    minimumFreeGiB: input.minimumFreeGiB ?? state.operational.minimumFreeGiB,
    minimumFreePercent: input.minimumFreePercent ?? state.operational.minimumFreePercent,
    ...(input.maximumOutputGiB === undefined
      ? (state.operational.maximumOutputGiB === undefined ? {} : { maximumOutputGiB: state.operational.maximumOutputGiB })
      : { maximumOutputGiB: input.maximumOutputGiB }),
  };
  return validatedOptions({
    ...state.semantic,
    ...operational,
    output: input.output,
    ...(input.signal === undefined ? {} : { signal: input.signal }),
    ...(input.progress === undefined ? {} : { progress: input.progress }),
  });
}

export async function resumeSensitiveMaterial(input: MiningResumeOptions): Promise<Record<string, unknown>> {
  const metrics = new MiningMetrics();
  const output = path.resolve(input.output);
  const metadata = await lstat(output);
  if (metadata.isSymbolicLink() || !metadata.isDirectory() || await realpath(output) !== output) {
    throw new Error("resume output must be an existing canonical directory");
  }
  const locks = await acquireMiningLocks(output);
  const lock = locks.find((candidate) => path.basename(candidate.path) === MINING_LOCK_FILENAME);
  if (lock === undefined) {
    await releaseMiningLocks(locks);
    throw new Error("current mining operation lock was not acquired");
  }
  let runFailure: unknown;
  try {
    await assertLockedResumeOutput(output);
    const state = await loadScanState(output, input.signal);
    if (state.status !== "paused" || !state.resumable) throw new Error("only a cleanly paused AARK scan can be resumed");
    const options = resumeOptions(state, { ...input, output });
    const policy = storagePolicyFromGiB(options.minimumFreeGiB, options.minimumFreePercent, options.maximumOutputGiB);
    const setup = await mountSetup(options.inputs, output);
    if (!sameRootSnapshots(setup.inputSafety, state.inputRoots)) throw new Error("input root identity or mount changed since the paused scan");
    const outputSafety = await outputSafetySnapshot(output, lock.path);
    const assertSafeOutput = async (): Promise<void> => {
      for (const held of locks) await held.assertHeld();
      await assertOutputSafetyCurrent(outputSafety, lock.path);
    };
    const budget = new StorageBudget(output, policy, await directoryLogicalBytes(output, options.signal));
    const inventory: SensitiveScanInventory = await loadResumeInventory(output, state.inventory, options.signal);
    if (JSON.stringify(inventory.inputRoots) !== JSON.stringify(state.semantic.inputs)) {
      throw new Error("paused inventory input roots do not match the resumable scan state");
    }
    assertResumeInventoryMatchesState(inventory, state);
    await verifyResumeArtifacts(output, inventory, options.signal);
    state.operational = operationalOptions(options);
    state.updatedAt = new Date().toISOString();
    const store = new ArtifactStore(output, options.inputs, options.deepKeySchedules === true, assertSafeOutput, budget, metrics);
    store.restore(inventory);
    const progress: MiningProgress = { ...state.progress };
    try {
      await assertStorageCapacity(output, policy, budget.outputBytes());
    } catch (error) {
      if (error instanceof StorageQuotaError) return await finalizeCleanPause(options, state, store, budget, progress, error.reason, undefined, metrics);
      throw error;
    }
    if (!state.inventoryComplete) {
      for await (const _entry of readScanManifest(output, state.manifest, options.signal)) {
        throw new Error("an incomplete input inventory must reference an empty scan manifest");
      }
      try {
        state.manifest = await createFrozenInputManifest(options, setup.isNetworkMount, store, budget, progress, assertSafeOutput, metrics);
        state.inventoryComplete = true;
        state.cursor = { fileIndex: 0, phase: "stream", nextOffset: 0 };
        progress.filesTotal = state.manifest.entries;
        progress.phase = "stream";
        if (interrupted(options.signal)) {
          await assertPauseInputRootsCurrent(setup.inputSafety);
          return await finalizeInventoryPause(options, state, store, budget, progress, "signal", metrics);
        }
        state.status = "paused";
        state.resumable = true;
        state.updatedAt = new Date().toISOString();
        state.progress = { ...progress };
        const checkpoint = await store.finalize("paused", progress, "input inventory rebuilt; detector execution has not started", false, inventoryCheckpoint(state));
        state.inventory = { filename: "inventory-sensitive.json", ...checkpoint };
        await writeScanState(output, state, budget);
      } catch (error) {
        const reason = error instanceof ScanPauseError ? "signal" : quotaReason(error);
        if (reason === undefined) throw error;
        await assertPauseInputRootsCurrent(setup.inputSafety);
        return await finalizeInventoryPause(options, state, store, budget, progress, reason, metrics);
      }
    }
    try {
      await verifyCompletedManifestFiles(output, state, setup.inputSafety, options.signal);
    } catch (error) {
      if (manifestVerificationInterrupted(error, options.signal)) {
        await assertPauseInputRootsCurrent(setup.inputSafety);
        return await finalizeCleanPause(options, state, store, budget, progress, "signal", undefined, metrics);
      }
      throw error;
    }
    const runtime: ScanRuntime = {
      options,
      policy,
      inputSafety: setup.inputSafety,
      outputSafety,
      lockPath: lock.path,
      locks,
      store,
      budget,
      pool: new DetectorWorkerPool(options.workers),
      state,
      progress,
      isNetworkMount: setup.isNetworkMount,
      metrics,
    };
    return await runManifest(runtime);
  } catch (error) {
    runFailure = error;
    throw error;
  } finally {
    try {
      await releaseMiningLocks(locks);
    } catch (releaseError) {
      if (runFailure !== undefined) throw new AggregateError([runFailure, releaseError], "resume failed and its exclusive output locks could not be released");
      throw releaseError;
    }
  }
}
