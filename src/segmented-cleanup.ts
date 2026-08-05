import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import type { Stats } from "node:fs";
import { lstat, mkdir, open, opendir, realpath, rename, rm, statfs } from "node:fs/promises";
import path from "node:path";
import { isDeepStrictEqual } from "node:util";
import {
  acquireExclusiveLock,
  assertNoSymlinkComponents,
  atomicWriteFile,
  atomicWriteJson,
  ensurePrivateDirectory,
  nearestExistingParent,
  readDirectoryNamesBounded,
  safeJoin,
  syncDirectory,
} from "./core/fs-safe.js";
import type { ExclusiveLock } from "./core/fs-safe.js";
import { mountForPathFrom, mountIsNetworkBacked, mounts } from "./core/mounts.js";
import type { MountRecord } from "./core/mounts.js";
import {
  loadScanState,
  loadTerminalInventory,
  readScanManifest,
  verifyResumeArtifacts,
} from "./mining/resume.js";
import type { FrozenScanFile, ScanState } from "./mining/resume.js";
import type { SensitiveScanInventory } from "./mining/types.js";
import { resolveMiningOutputs } from "./mining/batch.js";

const TOKEN = /^[a-f0-9]{64}$/u;
const SEGMENT_LOCK = ".aark-segment-cleanup.lock";
const MINING_LOCKS = [".aark-mining.lock", ".agetnic-mining.lock"] as const;
const MAX_SEGMENTS = 10_000;
const MAX_MINING_OUTPUTS = 10_000;
const MAX_DIRECTORY_ENTRIES = 100_000;
const MAX_PENDING_ENTRIES = 200_000;
const MAX_DIRECTORIES = 200_000;
const HASH_BUFFER_BYTES = 8 * 1024 * 1024;
const MAX_SEGMENT_CONTROL_BYTES = 256 * 1024 * 1024;

export type ErrorSourceDisposition = "retain" | "delete";

export interface SegmentedCleanupOptions {
  segments: string[];
  activeSegments?: string[];
  miningOutputs: string[];
  retentionDirectory: string;
  errorSourceDisposition?: ErrorSourceDisposition;
  signal?: AbortSignal;
}

export interface SegmentedCleanupRunOptions extends SegmentedCleanupOptions {
  approvalToken: string;
  execute: boolean;
  confirmDeleteSegments: boolean;
  confirmDeleteErrorSources?: boolean;
}

export interface SegmentedCleanupPlanResult {
  version: 1;
  tool: "aark";
  layer: "segmented-cleanup";
  status: "ready";
  destructive: true;
  pathsRedacted: true;
  valuesPrinted: false;
  selectedClosedSegments: number;
  activeSegmentsPreserved: number;
  miningScansVerified: number;
  findingSourceFilesRetained: string;
  scanErrorSourceFiles: string;
  scanErrorSourceDisposition: ErrorSourceDisposition;
  deletion: {
    filesystemEntries: string;
    regularFiles: string;
    logicalBytes: string;
    allocatedBytes: string;
    expectedFreeSpaceGainMinimumBytes: string;
    expectedFreeSpaceGainMaximumBytes: string;
    allocationUnitBytes: string;
  };
  approvalToken: string;
  approvalRequired: true;
  requirements: string[];
}

interface ProtectedSource {
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
  sha256: string;
  finding: boolean;
  scanError: boolean;
}

interface HardLinkAllocation {
  device: number;
  inode: number;
  allocatedBytes: bigint;
  links: number;
  selectedLinks: number;
}

interface SegmentSnapshot {
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
  protectedSources: ProtectedSource[];
}

interface ActiveIdentity {
  path: string;
  device: number;
  inode: number;
}

interface VerifiedScan {
  output: string;
  runId: string;
  status: "complete" | "complete-with-errors";
  manifest: ScanState["manifest"];
  inventory: ScanState["inventory"];
}

interface Coverage {
  files: Map<string, FrozenScanFile>;
  findingSources: Set<string>;
  errorSources: Set<string>;
  scans: VerifiedScan[];
}

interface NormalizedOptions {
  segments: string[];
  activeSegments: string[];
  miningOutputs: string[];
  retentionDirectory: string;
  errorSourceDisposition: ErrorSourceDisposition;
  signal?: AbortSignal;
}

interface InternalPlan {
  public: SegmentedCleanupPlanResult;
  normalized: NormalizedOptions;
  segments: SegmentSnapshot[];
  active: ActiveIdentity[];
  scans: VerifiedScan[];
  coverage: Coverage;
  batchRoots: string[];
  retentionFilesystemDevice: number;
  retentionMountIdentity: string;
  retentionMetadataReserveBytes: bigint;
}

function interrupted(signal: AbortSignal | undefined): void {
  if (signal?.aborted === true) throw new Error("segmented cleanup verification was interrupted");
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

function errorCode(error: unknown): string | undefined {
  return error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
}

function normalizedList(values: string[], minimum: number, maximum: number, label: string): string[] {
  if (values.length < minimum || values.length > maximum) throw new Error(`${label} requires from ${minimum} through ${maximum} paths`);
  const result = [...new Set(values.map((value) => path.resolve(value)))].sort();
  if (result.length !== values.length) throw new Error(`${label} paths must be unique`);
  const paths = new Set(result);
  for (const candidate of result) {
    let parent = path.dirname(candidate);
    while (parent !== candidate) {
      if (paths.has(parent)) throw new Error(`${label} paths must not contain one another`);
      const next = path.dirname(parent);
      if (next === parent) break;
      parent = next;
    }
  }
  return result;
}

function normalize(options: SegmentedCleanupOptions): NormalizedOptions {
  const segments = normalizedList(options.segments, 1, MAX_SEGMENTS, "segmented cleanup");
  const activeSegments = normalizedList(options.activeSegments ?? [], 0, MAX_SEGMENTS, "active segment list");
  const miningOutputs = normalizedList(options.miningOutputs, 1, MAX_MINING_OUTPUTS, "segmented cleanup mining outputs");
  const retentionDirectory = path.resolve(options.retentionDirectory);
  if (retentionDirectory === path.parse(retentionDirectory).root) throw new Error("segment retention directory must be dedicated");
  for (const selected of segments) {
    if (inside(retentionDirectory, selected) || inside(selected, retentionDirectory)) {
      throw new Error("segment retention directory must not overlap a selected segment");
    }
    if (activeSegments.some((active) => inside(selected, active) || inside(active, selected))) {
      throw new Error("an active segment overlaps a selected closed segment");
    }
    if (miningOutputs.some((output) => inside(selected, output) || inside(output, selected))) {
      throw new Error("a retained mining output overlaps a selected segment");
    }
  }
  if (miningOutputs.some((output) => inside(retentionDirectory, output) || inside(output, retentionDirectory))) {
    throw new Error("retention directory and mining outputs must not contain one another");
  }
  for (const active of activeSegments) {
    if (inside(retentionDirectory, active) || inside(active, retentionDirectory)) {
      throw new Error("segment retention directory must not overlap an active segment");
    }
    if (miningOutputs.some((output) => inside(active, output) || inside(output, active))) {
      throw new Error("retained mining outputs must not overlap an active segment");
    }
  }
  const errorSourceDisposition = options.errorSourceDisposition ?? "retain";
  if (errorSourceDisposition !== "retain" && errorSourceDisposition !== "delete") throw new Error("scan-error source disposition must be retain or delete");
  return {
    segments,
    activeSegments,
    miningOutputs,
    retentionDirectory,
    errorSourceDisposition,
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  };
}

async function canonicalDirectory(filename: string, label: string): Promise<Stats> {
  const metadata = await lstat(filename);
  if (metadata.isSymbolicLink() || !metadata.isDirectory() || await realpath(filename) !== filename) {
    throw new Error(`${label} must be a canonical real directory`);
  }
  return metadata;
}

function recordMatches(
  record: FrozenScanFile,
  metadata: Awaited<ReturnType<typeof lstat>>,
  allowedChangedInodes?: ReadonlySet<string>,
): boolean {
  return metadata.isFile() && !metadata.isSymbolicLink()
    && record.device === metadata.dev && record.inode === metadata.ino && record.bytes === metadata.size
    && record.modifiedMs === metadata.mtimeMs
    && (record.changedMs === metadata.ctimeMs || allowedChangedInodes?.has(`${metadata.dev}:${metadata.ino}`) === true);
}

function sameFileMetadata(left: Awaited<ReturnType<typeof lstat>>, right: Awaited<ReturnType<typeof lstat>>): boolean {
  return right.isFile() && !right.isSymbolicLink()
    && left.dev === right.dev && left.ino === right.ino && left.mode === right.mode && left.nlink === right.nlink
    && left.size === right.size && left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs;
}

async function stableFileSha256(
  filename: string,
  expected: { device: number; inode: number; bytes: number },
  signal?: AbortSignal,
): Promise<string> {
  const handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.dev !== expected.device || before.ino !== expected.inode || before.size !== expected.bytes
      || !sameFileMetadata(before, await lstat(filename)) || await realpath(filename) !== filename) {
      throw new Error("a protected segment source changed before integrity hashing");
    }
    const digest = createHash("sha256");
    const buffer = Buffer.allocUnsafe(HASH_BUFFER_BYTES);
    let offset = 0;
    while (offset < before.size) {
      interrupted(signal);
      const read = await handle.read(buffer, 0, Math.min(buffer.length, before.size - offset), offset);
      if (read.bytesRead === 0) throw new Error("a protected segment source ended during integrity hashing");
      digest.update(buffer.subarray(0, read.bytesRead));
      offset += read.bytesRead;
    }
    const probe = Buffer.allocUnsafe(1);
    if ((await handle.read(probe, 0, 1, offset)).bytesRead !== 0) throw new Error("a protected segment source grew during integrity hashing");
    const after = await handle.stat();
    if (!sameFileMetadata(before, after) || !sameFileMetadata(after, await lstat(filename)) || await realpath(filename) !== filename) {
      throw new Error("a protected segment source changed during integrity hashing");
    }
    return digest.digest("hex");
  } finally {
    await handle.close();
  }
}

async function noMiningLock(output: string): Promise<void> {
  const entries = new Set(await readDirectoryNamesBounded(output, 100_000));
  if (MINING_LOCKS.some((name) => entries.has(name))) throw new Error("a selected mining output still has an operation lock");
}

async function noBatchLock(output: string): Promise<void> {
  const entries = new Set(await readDirectoryNamesBounded(output, 100_000));
  if (entries.has(".aark-batch.lock")) throw new Error("a selected mining batch workflow still has an operation lock");
}

async function assertLocalControlTree(root: string, mountTable: MountRecord[], label: string): Promise<void> {
  await canonicalDirectory(root, label);
  const mounted = mountForPathFrom(mountTable, root);
  if (mounted === undefined || await mountIsNetworkBacked(mounted)) throw new Error(`${label} must remain on a local filesystem`);
  if (path.resolve(mounted.target) === root || mountTable.some((entry) => {
    const target = path.resolve(entry.target);
    return target !== root && inside(root, target);
  })) throw new Error(`${label} must not be a mount root or contain a nested mount`);
}

function selectedFile(segments: string[], filename: string): boolean {
  return segments.some((segment) => filename !== segment && inside(segment, filename));
}

function scanSourceAuthorized(filename: string, roots: ScanState["inputRoots"]): boolean {
  return roots.some((root) => root.kind === "file"
    ? filename === root.path
    : filename !== root.path && inside(root.path, filename));
}

function assertInventoryMatchesState(inventory: SensitiveScanInventory, state: ScanState): void {
  const occurrences = inventory.findings.reduce((sum, finding) => sum + finding.occurrences.length, 0);
  const checkpoint = inventory.resumeCheckpoint;
  if (
    inventory.status !== state.status
    || !inventory.complete
    || state.resumable
    || !state.inventoryComplete
    || state.pauseReason !== undefined
    || state.cursor.fileIndex !== state.manifest.entries
    || state.cursor.phase !== "stream"
    || state.cursor.nextOffset !== 0
    || state.progress.phase !== "finalizing"
    || state.progress.filesTotal !== state.manifest.entries
    || state.progress.filesVisited !== state.manifest.entries
    || (state.status === "complete") !== (state.progress.scanErrors === 0)
    || (state.status === "complete-with-errors") !== (state.progress.scanErrors > 0)
    || inventory.outputRoot !== state.semantic.output
    || !isDeepStrictEqual(inventory.inputRoots, state.semantic.inputs)
    || inventory.findings.length !== state.progress.uniqueFindings
    || occurrences !== state.progress.occurrences
    || inventory.errors.length + inventory.errorsOmitted !== state.progress.scanErrors
    || inventory.failureMessage !== undefined
    || inventory.findings.some((finding) => finding.occurrences.some((occurrence) => (
      occurrence.provenance !== state.semantic.provenance
      || !scanSourceAuthorized(occurrence.sourcePath, state.inputRoots)
    )))
    || checkpoint === undefined
    || checkpoint.runId !== state.runId
    || checkpoint.status !== state.status
    || checkpoint.inventoryComplete !== state.inventoryComplete
    || !isDeepStrictEqual(checkpoint.semantic, state.semantic)
    || !isDeepStrictEqual(checkpoint.inputRoots, state.inputRoots)
    || !isDeepStrictEqual(checkpoint.manifest, state.manifest)
    || !isDeepStrictEqual(checkpoint.cursor, state.cursor)
    || !isDeepStrictEqual(checkpoint.progress, state.progress)
  ) throw new Error("terminal mining inventory does not match its segmented-cleanup checkpoint");
}

async function buildCoverage(options: NormalizedOptions, miningOutputLocksHeld: ReadonlySet<string>): Promise<Coverage> {
  const files = new Map<string, FrozenScanFile>();
  const findingSources = new Set<string>();
  const errorSources = new Set<string>();
  const scans: VerifiedScan[] = [];
  for (const output of options.miningOutputs) {
    interrupted(options.signal);
    await canonicalDirectory(output, "mining output");
    if (!miningOutputLocksHeld.has(output)) await noMiningLock(output);
    const state = await loadScanState(output, options.signal);
    if (state.status !== "complete" && state.status !== "complete-with-errors") {
      throw new Error("segmented cleanup requires terminal mining scans");
    }
    const inventory = await loadTerminalInventory(output, state, options.signal);
    assertInventoryMatchesState(inventory, state);
    await verifyResumeArtifacts(output, inventory, options.signal);
    if (inventory.errorsOmitted !== 0) throw new Error("a mining scan omitted error-source paths, so segmented cleanup cannot safely classify every file");
    for (const finding of inventory.findings) {
      for (const occurrence of finding.occurrences) {
        if (selectedFile(options.segments, occurrence.sourcePath)) findingSources.add(occurrence.sourcePath);
      }
    }
    for (const scanError of inventory.errors) {
      if (!path.isAbsolute(scanError.sourcePath) || path.resolve(scanError.sourcePath) !== scanError.sourcePath) {
        throw new Error("a mining error is not bound to an absolute source file; segmented cleanup refuses the ambiguous scan");
      }
      if (selectedFile(options.segments, scanError.sourcePath)) errorSources.add(scanError.sourcePath);
    }
    for await (const frozen of readScanManifest(output, state.manifest, options.signal)) {
      if (!selectedFile(options.segments, frozen.path)) continue;
      const existing = files.get(frozen.path);
      if (existing !== undefined && !isDeepStrictEqual(existing, frozen)) throw new Error("mining manifests disagree about a selected segment file");
      files.set(frozen.path, frozen);
    }
    scans.push({ output, runId: state.runId, status: state.status, manifest: state.manifest, inventory: state.inventory });
  }
  for (const filename of findingSources) {
    if (!files.has(filename)) throw new Error("a finding source is absent from the supplied terminal scan manifests");
  }
  if (options.errorSourceDisposition === "retain") {
    for (const filename of errorSources) {
      if (!files.has(filename)) throw new Error("a retained scan-error source is not a manifest-covered regular file");
    }
  }
  return { files, findingSources, errorSources, scans };
}

function metadataDigestLine(relative: string, metadata: Awaited<ReturnType<typeof lstat>>): string {
  return `${JSON.stringify({
    path: relative,
    kind: metadata.isDirectory() ? "directory" : "file",
    device: metadata.dev,
    inode: metadata.ino,
    mode: metadata.mode,
    links: metadata.nlink,
    owner: metadata.uid,
    group: metadata.gid,
    bytes: metadata.size,
    blocks: metadata.blocks,
    modifiedMs: metadata.mtimeMs,
    changedMs: metadata.ctimeMs,
  })}\n`;
}

function deletionDigestLine(relative: string, metadata: Awaited<ReturnType<typeof lstat>>): string {
  return `${JSON.stringify({
    path: relative,
    kind: metadata.isDirectory() ? "directory" : "file",
    device: metadata.dev,
    inode: metadata.ino,
    mode: metadata.mode,
    links: metadata.nlink,
    owner: metadata.uid,
    group: metadata.gid,
    bytes: metadata.isFile() ? metadata.size : null,
    blocks: metadata.isFile() ? metadata.blocks : null,
    modifiedMs: metadata.isFile() ? metadata.mtimeMs : null,
    // Moving a protected hard-link name updates the shared inode ctime, and
    // removing a child updates its parent directory times. Other fields plus
    // whole-file hashes remain bound across that authorized mutation.
    changedMs: metadata.isFile() && metadata.nlink === 1 ? metadata.ctimeMs : null,
  })}\n`;
}

async function snapshotSegment(
  actualRoot: string,
  logicalRoot: string,
  coverage: Coverage,
  disposition: ErrorSourceDisposition,
  signal?: AbortSignal,
  mountTable?: MountRecord[],
  allowedChangedInodes?: ReadonlySet<string>,
): Promise<SegmentSnapshot> {
  const before = await canonicalDirectory(actualRoot, "selected segment");
  const records = mountTable ?? await mounts();
  const rootMount = mountForPathFrom(records, actualRoot);
  if (rootMount === undefined || await mountIsNetworkBacked(rootMount)) throw new Error("selected segment must remain on a local filesystem");
  if (path.resolve(rootMount.target) === actualRoot || records.some((mounted) => {
    const target = path.resolve(mounted.target);
    return target !== actualRoot && inside(actualRoot, target);
  })) throw new Error("selected segment must not be a mount root or contain a nested mount");
  const content = createHash("sha256");
  const deletionContent = createHash("sha256");
  const pending = [actualRoot];
  const visitedDirectories = new Set<string>();
  const allocatedIdentities = new Set<string>();
  const hardLinkAllocationsByIdentity = new Map<string, HardLinkAllocation>();
  let filesystemEntries = 0n;
  let regularFiles = 0n;
  let logicalBytes = 0n;
  let allocatedBytes = 0n;
  let minimumReclaimableAllocatedBytes = 0n;
  const protectedSources: ProtectedSource[] = [];
  while (pending.length > 0) {
    interrupted(signal);
    if (pending.length > MAX_PENDING_ENTRIES) throw new Error("segment verification exceeds its bounded traversal frontier");
    const filename = pending.pop();
    if (filename === undefined) break;
    const metadata = await lstat(filename);
    if (metadata.isSymbolicLink()) throw new Error("selected segments must not contain symbolic links");
    if (!metadata.isFile() && !metadata.isDirectory()) throw new Error("selected segments must contain only regular files and directories");
    if (!Number.isSafeInteger(metadata.blocks) || metadata.blocks < 0 || !Number.isSafeInteger(metadata.size) || metadata.size < 0
      || !Number.isSafeInteger(metadata.nlink) || metadata.nlink < 1) {
      throw new Error("selected segment contains filesystem accounting outside safe numeric bounds");
    }
    const relative = path.relative(actualRoot, filename);
    const logicalPath = relative === "" ? logicalRoot : path.join(logicalRoot, relative);
    if (filename !== actualRoot) filesystemEntries += 1n;
    const identity = `${metadata.dev}:${metadata.ino}`;
    const entryAllocated = BigInt(metadata.blocks) * 512n;
    if (metadata.isFile() && metadata.nlink > 1) {
      const existing = hardLinkAllocationsByIdentity.get(identity);
      if (existing === undefined) {
        hardLinkAllocationsByIdentity.set(identity, {
          device: metadata.dev,
          inode: metadata.ino,
          allocatedBytes: entryAllocated,
          links: metadata.nlink,
          selectedLinks: 1,
        });
      } else {
        if (existing.allocatedBytes !== entryAllocated || existing.links !== metadata.nlink) {
          throw new Error("selected segment hard-link metadata changed during verification");
        }
        existing.selectedLinks += 1;
        if (existing.selectedLinks > existing.links) throw new Error("selected segment contains more hard links than the inode reports");
      }
    }
    if (!allocatedIdentities.has(identity)) {
      allocatedIdentities.add(identity);
      allocatedBytes += entryAllocated;
      if (!metadata.isFile() || metadata.nlink === 1) minimumReclaimableAllocatedBytes += entryAllocated;
    }
    // Renaming the selected root into quarantine may legitimately update the
    // root directory's ctime. Child entries remain token-bound below.
    if (filename !== actualRoot) content.update(metadataDigestLine(relative, metadata));
    if (metadata.isDirectory()) {
      if (filename !== actualRoot) deletionContent.update(deletionDigestLine(relative, metadata));
      if (visitedDirectories.has(identity)) throw new Error("selected segment contains a recursive directory identity");
      visitedDirectories.add(identity);
      if (visitedDirectories.size > MAX_DIRECTORIES) throw new Error("selected segment exceeds its directory verification limit");
      const directory = await opendir(filename);
      const children: string[] = [];
      for await (const entry of directory) {
        if (children.length >= MAX_DIRECTORY_ENTRIES) throw new Error("selected segment directory exceeds its entry verification limit");
        children.push(path.join(filename, entry.name));
      }
      children.sort().reverse();
      pending.push(...children);
      continue;
    }
    regularFiles += 1n;
    logicalBytes += BigInt(metadata.size);
    const frozen = coverage.files.get(logicalPath);
    if (frozen === undefined || !recordMatches(frozen, metadata, allowedChangedInodes)) {
      throw new Error("a selected segment file is not exactly covered by a supplied terminal mining scan");
    }
    const finding = coverage.findingSources.has(logicalPath);
    const scanError = coverage.errorSources.has(logicalPath);
    const protectedSource = finding || (scanError && disposition === "retain");
    if (protectedSource) {
      protectedSources.push({
        originalPath: logicalPath,
        relativePath: relative,
        device: metadata.dev,
        inode: metadata.ino,
        mode: metadata.mode,
        links: metadata.nlink,
        bytes: metadata.size,
        allocatedBytes: entryAllocated,
        modifiedMs: metadata.mtimeMs,
        changedMs: metadata.ctimeMs,
        sha256: await stableFileSha256(filename, { device: metadata.dev, inode: metadata.ino, bytes: metadata.size }, signal),
        finding,
        scanError,
      });
    } else {
      deletionContent.update(deletionDigestLine(relative, metadata));
    }
  }
  const after = await lstat(actualRoot);
  if (after.dev !== before.dev || after.ino !== before.ino || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs
    || await realpath(actualRoot) !== actualRoot) throw new Error("selected segment changed while it was snapshotted");
  return {
    path: logicalRoot,
    device: after.dev,
    inode: after.ino,
    modifiedMs: after.mtimeMs,
    changedMs: after.ctimeMs,
    filesystemEntries,
    regularFiles,
    logicalBytes,
    allocatedBytes,
    minimumReclaimableAllocatedBytes,
    hardLinkAllocations: [...hardLinkAllocationsByIdentity.values()]
      .sort((left, right) => left.device - right.device || left.inode - right.inode),
    contentDigest: content.digest("hex"),
    deletionDigest: deletionContent.digest("hex"),
    protectedSources: protectedSources.sort((left, right) => left.originalPath.localeCompare(right.originalPath)),
  };
}

function snapshotTokenValue(snapshot: SegmentSnapshot): Record<string, unknown> {
  return {
    ...snapshot,
    filesystemEntries: snapshot.filesystemEntries.toString(),
    regularFiles: snapshot.regularFiles.toString(),
    logicalBytes: snapshot.logicalBytes.toString(),
    allocatedBytes: snapshot.allocatedBytes.toString(),
    minimumReclaimableAllocatedBytes: snapshot.minimumReclaimableAllocatedBytes.toString(),
    hardLinkAllocations: snapshot.hardLinkAllocations.map((allocation) => ({ ...allocation, allocatedBytes: allocation.allocatedBytes.toString() })),
    protectedSources: snapshot.protectedSources.map((source) => ({ ...source, allocatedBytes: source.allocatedBytes.toString() })),
  };
}

function sameQuarantinedSnapshot(actual: SegmentSnapshot, expected: SegmentSnapshot): boolean {
  return actual.path === expected.path
    && actual.device === expected.device
    && actual.inode === expected.inode
    && actual.filesystemEntries === expected.filesystemEntries
    && actual.regularFiles === expected.regularFiles
    && actual.logicalBytes === expected.logicalBytes
    && actual.allocatedBytes === expected.allocatedBytes
    && actual.minimumReclaimableAllocatedBytes === expected.minimumReclaimableAllocatedBytes
    && isDeepStrictEqual(actual.hardLinkAllocations, expected.hardLinkAllocations)
    && actual.contentDigest === expected.contentDigest
    && actual.deletionDigest === expected.deletionDigest
    && isDeepStrictEqual(actual.protectedSources, expected.protectedSources);
}

async function buildInternalPlan(options: SegmentedCleanupOptions, heldLocks?: readonly ExclusiveLock[]): Promise<InternalPlan> {
  const references = normalize(options);
  const resolvedMining = await resolveMiningOutputs(references.miningOutputs, MAX_MINING_OUTPUTS);
  const normalized: NormalizedOptions = { ...references, miningOutputs: resolvedMining.outputs };
  const directOutputs = normalized.miningOutputs.filter((output) => !resolvedMining.batchRoots.some((root) => inside(root, output)));
  if (directOutputs.length > 128) throw new Error("segmented cleanup supports at most 128 independent mining outputs; use native batch workflow roots for larger sets");
  const heldPaths = new Set(heldLocks?.map((lock) => lock.path) ?? []);
  for (const lock of heldLocks ?? []) await lock.assertHeld();
  for (const root of resolvedMining.batchRoots) {
    if (!heldPaths.has(safeJoin(root, ".aark-batch.lock"))) await noBatchLock(root);
  }
  const mountTable = await mounts();
  const retentionParent = await nearestExistingParent(normalized.retentionDirectory);
  const retentionMetadata = await canonicalDirectory(retentionParent, "segment retention directory or its nearest parent");
  await assertNoSymlinkComponents(retentionParent, normalized.retentionDirectory);
  const retentionMount = mountForPathFrom(mountTable, retentionParent);
  if (retentionMount === undefined || await mountIsNetworkBacked(retentionMount)) throw new Error("segment retention directory must be on a local filesystem");
  if (retentionParent === normalized.retentionDirectory && path.resolve(retentionMount.target) === normalized.retentionDirectory) {
    throw new Error("segment retention directory must be a dedicated subdirectory, not a mount root");
  }
  if (mountTable.some((entry) => {
    const target = path.resolve(entry.target);
    return target !== normalized.retentionDirectory && inside(normalized.retentionDirectory, target);
  })) throw new Error("segment retention directory must not contain nested mounts");
  const retentionMountIdentity = mountIdentity(retentionMount);
  const active: ActiveIdentity[] = [];
  for (const activePath of normalized.activeSegments) {
    const metadata = await canonicalDirectory(activePath, "active segment");
    active.push({ path: activePath, device: metadata.dev, inode: metadata.ino });
  }
  for (const root of [...resolvedMining.batchRoots, ...normalized.miningOutputs]) {
    await assertLocalControlTree(root, mountTable, "mining output");
  }
  const lockedDirectOutputs = new Set(directOutputs.filter((output) => (
    MINING_LOCKS.every((filename) => heldPaths.has(safeJoin(output, filename)))
  )));
  const coverage = await buildCoverage(normalized, lockedDirectOutputs);
  const snapshots: SegmentSnapshot[] = [];
  for (const segment of normalized.segments) {
    const metadata = await canonicalDirectory(segment, "selected segment");
    if (metadata.dev !== retentionMetadata.dev) throw new Error("selected segments and their retained-source directory must share a filesystem");
    const segmentMount = mountForPathFrom(mountTable, segment);
    if (segmentMount === undefined || await mountIsNetworkBacked(segmentMount)) throw new Error("selected segments must be on a local filesystem");
    if (mountIdentity(segmentMount) !== retentionMountIdentity) {
      throw new Error("selected segments and their retained-source directory must share the same mount");
    }
    snapshots.push(await snapshotSegment(segment, segment, coverage, normalized.errorSourceDisposition, normalized.signal, mountTable));
  }
  const protectedSources = snapshots.flatMap((snapshot) => snapshot.protectedSources);
  let maximumReclaimableAllocatedBytes = snapshots.reduce((sum, snapshot) => sum + snapshot.allocatedBytes, 0n);
  let minimumBeforeMetadata = snapshots.reduce((sum, snapshot) => sum + snapshot.minimumReclaimableAllocatedBytes, 0n);
  const crossTargetHardLinks = new Map<string, HardLinkAllocation>();
  for (const snapshot of snapshots) {
    for (const allocation of snapshot.hardLinkAllocations) {
      const identity = `${allocation.device}:${allocation.inode}`;
      const existing = crossTargetHardLinks.get(identity);
      if (existing !== undefined) {
        throw new Error("hard links spanning selected segments cannot be cleaned independently; select one common parent segment or rescan after each cleanup");
      }
      crossTargetHardLinks.set(identity, allocation);
      if (allocation.selectedLinks < allocation.links) {
        // A known link outside this selected segment keeps the inode alive, so
        // even the upper gain estimate must exclude its data blocks.
        maximumReclaimableAllocatedBytes -= allocation.allocatedBytes;
      } else {
        minimumBeforeMetadata += allocation.allocatedBytes;
      }
    }
  }
  const retainedAllocations = new Set<string>();
  for (const source of protectedSources) {
    const identity = `${source.device}:${source.inode}`;
    if (retainedAllocations.has(identity)) continue;
    retainedAllocations.add(identity);
    const hardLink = crossTargetHardLinks.get(identity);
    if (hardLink === undefined || hardLink.selectedLinks === hardLink.links) {
      maximumReclaimableAllocatedBytes -= source.allocatedBytes;
      minimumBeforeMetadata -= source.allocatedBytes;
    }
  }
  const filesystem = await statfs(retentionParent, { bigint: true });
  if (filesystem.bsize < 1n) throw new Error("segmented cleanup filesystem reported an invalid allocation unit");
  const retainedDirectories = new Set<string>();
  for (let index = 0; index < snapshots.length; index += 1) {
    retainedDirectories.add(`segment-${index + 1}`);
    for (const source of snapshots[index]?.protectedSources ?? []) {
      let parent = path.dirname(source.relativePath);
      while (parent !== "." && parent !== path.parse(parent).root) {
        retainedDirectories.add(`segment-${index + 1}:${parent}`);
        const next = path.dirname(parent);
        if (next === parent) break;
        parent = next;
      }
    }
  }
  retainedDirectories.add("retained-segment-source-files");
  retainedDirectories.add("retained-segment-source-files:<token-run>");
  // The lower gain estimate reserves one allocation unit for every retained
  // file entry and created directory. It also reserves rounded allocations
  // for both token-scoped and top-level reports; the sensitive report can be
  // large because it records every selected path locally.
  const roundedAllocation = (bytes: number): bigint => (BigInt(bytes) + filesystem.bsize - 1n) / filesystem.bsize * filesystem.bsize;
  const sensitiveReportBytes = Buffer.byteLength(JSON.stringify({
    selected: snapshots.map((snapshot) => snapshot.path),
    active: active.map((segment) => segment.path),
  })) + 16 * 1024;
  const smallReportBytes = 32 * 1024;
  const reportAllocationReserve = 2n * roundedAllocation(sensitiveReportBytes)
    + 4n * roundedAllocation(smallReportBytes);
  const retentionMetadataReserve = BigInt(protectedSources.length + retainedDirectories.size + 4) * filesystem.bsize
    + reportAllocationReserve;
  const tokenMaterial = {
    version: 1,
    segments: snapshots.map(snapshotTokenValue),
    active,
    scans: coverage.scans,
    retentionDirectory: normalized.retentionDirectory,
    retentionFilesystemDevice: retentionMetadata.dev,
    retentionMountIdentity,
    allocationUnitBytes: filesystem.bsize.toString(),
    retentionMetadataReserveBytes: retentionMetadataReserve.toString(),
    errorSourceDisposition: normalized.errorSourceDisposition,
  };
  const serializedTokenMaterial = JSON.stringify(tokenMaterial);
  if (Buffer.byteLength(serializedTokenMaterial) > MAX_SEGMENT_CONTROL_BYTES) {
    throw new Error("segmented cleanup approval control state exceeds its bounded size; split the selected segment set");
  }
  const approvalToken = createHash("sha256").update(serializedTokenMaterial).digest("hex");
  const expectedMinimumGain = minimumBeforeMetadata > retentionMetadataReserve
    ? minimumBeforeMetadata - retentionMetadataReserve
    : 0n;
  const errorFiles = coverage.errorSources.size;
  const publicPlan: SegmentedCleanupPlanResult = {
    version: 1,
    tool: "aark",
    layer: "segmented-cleanup",
    status: "ready",
    destructive: true,
    pathsRedacted: true,
    valuesPrinted: false,
    selectedClosedSegments: snapshots.length,
    activeSegmentsPreserved: active.length,
    miningScansVerified: coverage.scans.length,
    findingSourceFilesRetained: new Set(protectedSources.filter((source) => source.finding).map((source) => source.originalPath)).size.toString(),
    scanErrorSourceFiles: errorFiles.toString(),
    scanErrorSourceDisposition: normalized.errorSourceDisposition,
    deletion: {
      filesystemEntries: snapshots.reduce((sum, snapshot) => sum + snapshot.filesystemEntries - BigInt(snapshot.protectedSources.length), 0n).toString(),
      regularFiles: snapshots.reduce((sum, snapshot) => sum + snapshot.regularFiles - BigInt(snapshot.protectedSources.length), 0n).toString(),
      logicalBytes: snapshots.reduce((sum, snapshot) => sum + snapshot.logicalBytes
        - snapshot.protectedSources.reduce((retained, source) => retained + BigInt(source.bytes), 0n), 0n).toString(),
      allocatedBytes: maximumReclaimableAllocatedBytes.toString(),
      expectedFreeSpaceGainMinimumBytes: expectedMinimumGain.toString(),
      expectedFreeSpaceGainMaximumBytes: maximumReclaimableAllocatedBytes.toString(),
      allocationUnitBytes: filesystem.bsize.toString(),
    },
    approvalToken,
    approvalRequired: true,
    requirements: [
      "Obtain explicit end-user approval for this exact token before deleting selected closed segments.",
      "Every finding-containing source file is moved intact into the dedicated retained-source tree before segment deletion.",
      "Active segments are identity-checked for exclusion and are never locked, moved, or deleted.",
      ...(normalized.errorSourceDisposition === "retain"
        ? ["Scan-error source files default to retention and are moved intact before deletion."]
        : ["The plan explicitly selects scan-error source files for deletion; run also requires --confirm-delete-error-sources."]),
    ],
  };
  return {
    public: publicPlan,
    normalized,
    segments: snapshots,
    active,
    scans: coverage.scans,
    coverage,
    batchRoots: resolvedMining.batchRoots,
    retentionFilesystemDevice: retentionMetadata.dev,
    retentionMountIdentity,
    retentionMetadataReserveBytes: retentionMetadataReserve,
  };
}

export async function planSegmentedCleanup(options: SegmentedCleanupOptions): Promise<SegmentedCleanupPlanResult> {
  return (await buildInternalPlan(options)).public;
}

async function acquireLocks(plan: InternalPlan): Promise<ExclusiveLock[]> {
  const requests = [
    { root: plan.normalized.retentionDirectory, filename: SEGMENT_LOCK },
    ...plan.batchRoots.map((root) => ({ root, filename: ".aark-batch.lock" })),
    ...plan.normalized.miningOutputs
      .filter((output) => !plan.batchRoots.some((root) => inside(root, output)))
      .flatMap((root) => MINING_LOCKS.map((filename) => ({ root, filename }))),
  ].sort((left, right) => left.root.localeCompare(right.root) || left.filename.localeCompare(right.filename));
  const locks: ExclusiveLock[] = [];
  try {
    for (const request of requests) locks.push(await acquireExclusiveLock(request.root, request.filename));
    return locks;
  } catch (error) {
    for (const lock of [...locks].reverse()) await lock.release().catch(() => undefined);
    throw error;
  }
}

async function releaseLocks(locks: ExclusiveLock[]): Promise<void> {
  const failures: unknown[] = [];
  for (const lock of [...locks].reverse()) {
    try { await lock.release(); } catch (error) { failures.push(error); }
  }
  if (failures.length > 0) throw new AggregateError(failures, "segmented cleanup locks could not all be released");
}

async function exists(filename: string): Promise<boolean> {
  try { await lstat(filename); return true; } catch (error) {
    if (errorCode(error) === "ENOENT") return false;
    throw error;
  }
}

async function assertActiveIdentities(active: ActiveIdentity[]): Promise<void> {
  for (const expected of active) {
    const current = await canonicalDirectory(expected.path, "active segment");
    if (current.dev !== expected.device || current.ino !== expected.inode) throw new Error("an active segment identity changed after planning");
  }
}

async function assertRetentionCurrent(plan: InternalPlan): Promise<void> {
  const metadata = await canonicalDirectory(plan.normalized.retentionDirectory, "segment retention directory");
  const records = await mounts();
  const mounted = mountForPathFrom(records, plan.normalized.retentionDirectory);
  if (metadata.dev !== plan.retentionFilesystemDevice || mounted === undefined
    || mountIdentity(mounted) !== plan.retentionMountIdentity) {
    throw new Error("segment retention directory or mount changed after approval");
  }
  if (path.resolve(mounted.target) === plan.normalized.retentionDirectory || records.some((entry) => {
    const target = path.resolve(entry.target);
    return target !== plan.normalized.retentionDirectory && inside(plan.normalized.retentionDirectory, target);
  })) throw new Error("segment retention directory became a mount root or acquired a nested mount");
}

async function moveProtectedSource(
  quarantine: string,
  destinationRoot: string,
  source: ProtectedSource,
  signal: AbortSignal | undefined,
  safetyCheck: () => Promise<void>,
  mutatedInodes: Set<string>,
): Promise<void> {
  await safetyCheck();
  const currentPath = safeJoin(quarantine, source.relativePath);
  const before = await lstat(currentPath);
  const identity = `${source.device}:${source.inode}`;
  const changedByEarlierProtectedMove = mutatedInodes.has(identity);
  if (before.isSymbolicLink() || !before.isFile() || before.dev !== source.device || before.ino !== source.inode
    || before.mode !== source.mode || before.nlink !== source.links || before.size !== source.bytes
    || before.mtimeMs !== source.modifiedMs
    || (!changedByEarlierProtectedMove && before.ctimeMs !== source.changedMs)
    || await realpath(currentPath) !== currentPath) {
    throw new Error("a protected segment source changed before retention");
  }
  const destination = safeJoin(destinationRoot, source.relativePath);
  await ensurePrivateDirectory(path.dirname(destination));
  await assertNoSymlinkComponents(destinationRoot, destination);
  if (await exists(destination)) throw new Error("a protected segment retention destination already exists");
  await safetyCheck();
  await rename(currentPath, destination);
  mutatedInodes.add(identity);
  await syncDirectory(path.dirname(currentPath));
  await syncDirectory(path.dirname(destination));
  const after = await lstat(destination);
  if (after.dev !== source.device || after.ino !== source.inode || after.size !== source.bytes || await realpath(destination) !== destination) {
    throw new Error("a protected segment source was not retained intact");
  }
  if (await stableFileSha256(destination, { device: source.device, inode: source.inode, bytes: source.bytes }, signal) !== source.sha256) {
    throw new Error("a protected segment source failed whole-file integrity verification after retention");
  }
  await safetyCheck();
}

async function assertDeletionTreeSafe(plan: InternalPlan, quarantine: string, expected: SegmentSnapshot): Promise<void> {
  const metadata = await canonicalDirectory(quarantine, "segmented cleanup quarantine");
  if (metadata.dev !== expected.device || metadata.ino !== expected.inode) {
    throw new Error("segmented cleanup quarantine identity changed before deletion");
  }
  const records = await mounts();
  const mounted = mountForPathFrom(records, quarantine);
  if (mounted === undefined || await mountIsNetworkBacked(mounted) || mountIdentity(mounted) !== plan.retentionMountIdentity) {
    throw new Error("segmented cleanup quarantine changed mount or filesystem before deletion");
  }
  if (path.resolve(mounted.target) === quarantine || records.some((entry) => {
    const target = path.resolve(entry.target);
    return target !== quarantine && inside(quarantine, target);
  })) throw new Error("segmented cleanup quarantine became a mount root or acquired a nested mount before deletion");
}

async function report(
  plan: InternalPlan,
  runRoot: string,
  status: "authorized-in-progress" | "complete" | "failed-partial" | "interrupted-partial",
  completed: number,
  failure?: unknown,
): Promise<void> {
  const common = [
    `- Status: ${status}`,
    `- Approved token: ${plan.public.approvalToken}`,
    `- Completed segment deletions: ${completed} of ${plan.segments.length}`,
    `- Finding source files retained: ${plan.public.findingSourceFilesRetained}`,
    `- Scan-error source disposition: ${plan.public.scanErrorSourceDisposition}`,
    `- Planned allocated bytes: ${plan.public.deletion.allocatedBytes}`,
  ];
  const failureMessage = failure instanceof Error ? failure.message.slice(0, 8 * 1024) : undefined;
  const redacted = [
    "# AARK segmented cleanup report", "", ...common, "- Paths and recovered values are omitted.", "",
  ].join("\n");
  const sensitive = [
    "# AARK segmented cleanup report", "", "> Sensitive local report. Do not publish.", "", ...common,
    `- Selected segments: ${plan.segments.map((segment) => JSON.stringify(segment.path)).join(", ")}`,
    `- Preserved active segments: ${plan.active.map((segment) => JSON.stringify(segment.path)).join(", ") || "none"}`,
    ...(failureMessage === undefined ? [] : [`- Failure: ${JSON.stringify(failureMessage)}`]), "",
  ].join("\n");
  const manifest = {
    version: 1,
    tool: "aark",
    layer: "segmented-cleanup",
    status,
    approvedPlanToken: plan.public.approvalToken,
    selectedSegments: plan.segments.length,
    activeSegmentsPreserved: plan.active.length,
    completedDeletions: completed,
    findingSourceFilesRetained: plan.public.findingSourceFilesRetained,
    scanErrorSourceFiles: plan.public.scanErrorSourceFiles,
    scanErrorSourceDisposition: plan.public.scanErrorSourceDisposition,
    valuesPrinted: false,
    pathsRedacted: true,
  };
  // Token-scoped reports are the durable history. Top-level copies remain a
  // convenient pointer to the most recent segmented cleanup result.
  await atomicWriteFile(safeJoin(runRoot, "cleanup-report-redacted.md"), redacted, 0o644);
  await atomicWriteFile(safeJoin(runRoot, "cleanup-report-sensitive.md"), sensitive);
  await atomicWriteJson(safeJoin(runRoot, "cleanup-manifest-redacted.json"), manifest, 0o644);
  await atomicWriteFile(safeJoin(plan.normalized.retentionDirectory, "segmented-cleanup-report-redacted.md"), redacted, 0o644);
  await atomicWriteFile(safeJoin(plan.normalized.retentionDirectory, "segmented-cleanup-report-sensitive.md"), sensitive);
  await atomicWriteJson(safeJoin(plan.normalized.retentionDirectory, "segmented-cleanup-manifest-redacted.json"), manifest, 0o644);
}

export async function runSegmentedCleanup(options: SegmentedCleanupRunOptions): Promise<Record<string, unknown>> {
  if (!options.execute || !options.confirmDeleteSegments) throw new Error("segmented cleanup requires --execute and --confirm-delete-segments");
  if (!TOKEN.test(options.approvalToken)) throw new Error("segmented cleanup requires the exact plan approval token");
  if (options.errorSourceDisposition === "delete" && options.confirmDeleteErrorSources !== true) {
    throw new Error("deleting scan-error source files additionally requires --confirm-delete-error-sources");
  }
  const initial = await buildInternalPlan(options);
  if (initial.public.approvalToken !== options.approvalToken) throw new Error("segmented cleanup inputs changed after approval");
  await ensurePrivateDirectory(initial.normalized.retentionDirectory);
  const retention = await lstat(initial.normalized.retentionDirectory);
  if (retention.dev !== initial.retentionFilesystemDevice) throw new Error("segment retention directory changed filesystems after planning");
  await assertRetentionCurrent(initial);
  const runRoot = safeJoin(initial.normalized.retentionDirectory, "retained-segment-source-files", options.approvalToken);
  if (await exists(runRoot)) throw new Error("this segmented cleanup token already has a retained-source run directory");
  const locks = await acquireLocks(initial);
  let operationError: unknown;
  try {
    const plan = await buildInternalPlan(options, locks);
    if (plan.public.approvalToken !== options.approvalToken) throw new Error("segmented cleanup inputs changed while locks were acquired");
    const cleanupFilesystem = await statfs(plan.normalized.retentionDirectory, { bigint: true });
    if (cleanupFilesystem.bavail * cleanupFilesystem.bsize < plan.retentionMetadataReserveBytes) {
      throw new Error("segmented cleanup lacks free space for retained-source metadata and final reports before deletion");
    }
    const assertControlSafe = async (): Promise<void> => {
      for (const lock of locks) await lock.assertHeld();
      await assertRetentionCurrent(plan);
    };
    const assertRuntimeSafe = async (): Promise<void> => {
      await assertControlSafe();
      await assertActiveIdentities(plan.active);
    };
    await assertRuntimeSafe();
    const retainedSourcesRoot = safeJoin(plan.normalized.retentionDirectory, "retained-segment-source-files");
    // Validate or create the fixed parent first. A recursive mkdir on the
    // token path could otherwise follow a pre-existing parent symlink before
    // the post-creation private-directory check had a chance to reject it.
    await ensurePrivateDirectory(retainedSourcesRoot);
    await assertRuntimeSafe();
    await mkdir(runRoot, { mode: 0o700 });
    await ensurePrivateDirectory(runRoot);
    await assertRuntimeSafe();
    let completed = 0;
    const mutatedInodes = new Set<string>();
    try {
      await report(plan, runRoot, "authorized-in-progress", completed);
      for (let index = 0; index < plan.segments.length; index += 1) {
        interrupted(plan.normalized.signal);
        await assertRuntimeSafe();
        const expected = plan.segments[index];
        if (expected === undefined) throw new Error("segmented cleanup lost an approved target snapshot");
        const current = await canonicalDirectory(expected.path, "selected segment");
        if (current.dev !== expected.device || current.ino !== expected.inode || current.mtimeMs !== expected.modifiedMs || current.ctimeMs !== expected.changedMs) {
          throw new Error("a selected segment changed after approval");
        }
        const quarantine = path.join(path.dirname(expected.path), `.aark-segment-cleanup-pending-${randomUUID()}`);
        await assertNoSymlinkComponents(path.dirname(expected.path), quarantine);
        if (await exists(quarantine)) throw new Error("segmented cleanup quarantine unexpectedly already exists");
        await rename(expected.path, quarantine);
        await syncDirectory(path.dirname(expected.path));
        if (await exists(expected.path)) throw new Error("a selected segment was recreated during quarantine");
        const quarantined = await snapshotSegment(quarantine, expected.path, plan.coverage, plan.normalized.errorSourceDisposition, plan.normalized.signal);
        if (!sameQuarantinedSnapshot(quarantined, expected)) {
          throw new Error("a quarantined segment no longer matches its approved snapshot");
        }
        const segmentRetention = safeJoin(runRoot, `segment-${String(index + 1).padStart(6, "0")}`);
        await ensurePrivateDirectory(segmentRetention);
        for (const source of expected.protectedSources) {
          interrupted(plan.normalized.signal);
          await moveProtectedSource(quarantine, segmentRetention, source, plan.normalized.signal, assertControlSafe, mutatedInodes);
        }
        await assertRuntimeSafe();
        const deletionSnapshot = await snapshotSegment(
          quarantine,
          expected.path,
          plan.coverage,
          plan.normalized.errorSourceDisposition,
          plan.normalized.signal,
          undefined,
          mutatedInodes,
        );
        if (deletionSnapshot.deletionDigest !== expected.deletionDigest || deletionSnapshot.protectedSources.length !== 0) {
          throw new Error("segmented cleanup quarantine changed after protected sources were retained; the remainder was not deleted");
        }
        await assertDeletionTreeSafe(plan, quarantine, expected);
        await rm(quarantine, { recursive: true, force: false, maxRetries: 0 });
        await syncDirectory(path.dirname(quarantine));
        if (await exists(quarantine) || await exists(expected.path)) throw new Error("a selected segment remained or was recreated after deletion");
        completed += 1;
      }
      await assertRuntimeSafe();
      await report(plan, runRoot, "complete", completed);
    } catch (error) {
      try {
        await assertRuntimeSafe();
        await report(plan, runRoot, plan.normalized.signal?.aborted === true ? "interrupted-partial" : "failed-partial", completed, error);
      } catch (reportError) {
        throw new AggregateError([error, reportError], "segmented cleanup failed and its partial report could not be published safely");
      }
      throw error;
    }
    return {
      version: 1,
      tool: "aark",
      layer: "segmented-cleanup",
      status: "complete",
      deletedSegments: completed,
      deletedLogicalBytes: plan.public.deletion.logicalBytes,
      plannedMaximumReclaimableAllocatedBytes: plan.public.deletion.allocatedBytes,
      expectedFreeSpaceGainMinimumBytes: plan.public.deletion.expectedFreeSpaceGainMinimumBytes,
      expectedFreeSpaceGainMaximumBytes: plan.public.deletion.expectedFreeSpaceGainMaximumBytes,
      findingSourceFilesRetained: plan.public.findingSourceFilesRetained,
      scanErrorSourceFiles: plan.public.scanErrorSourceFiles,
      scanErrorSourceDisposition: plan.public.scanErrorSourceDisposition,
      activeSegmentsPreserved: plan.public.activeSegmentsPreserved,
      valuesPrinted: false,
      pathsRedacted: true,
    };
  } catch (error) {
    operationError = error;
    throw error;
  } finally {
    try { await releaseLocks(locks); } catch (releaseError) {
      if (operationError !== undefined) throw new AggregateError([operationError, releaseError], "segmented cleanup failed and its locks could not be released");
      throw releaseError;
    }
  }
}
