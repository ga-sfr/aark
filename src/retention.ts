import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { chmod, lstat, open, opendir, realpath, rename, statfs, unlink } from "node:fs/promises";
import path from "node:path";
import {
  acquireExclusiveLock,
  assertNoSymlinkComponents,
  atomicWriteFile,
  atomicWriteJson,
  ensurePrivateDirectory,
  nearestExistingParent,
  readDirectoryNamesBounded,
  readJson,
  safeJoin,
  syncDirectory,
} from "./core/fs-safe.js";
import { mountForPathFrom, mountIsNetworkBacked, mountIsReadOnly, mounts } from "./core/mounts.js";
import type { MountRecord } from "./core/mounts.js";
import { assertStorageCapacity, directoryLogicalBytes, storagePolicyFromGiB, StorageBudget, StorageQuotaError } from "./core/storage.js";
import { loadScanState, loadVerifiedCompletedInventory, readScanManifest } from "./mining/resume.js";
import type { FrozenScanFile, ScanState } from "./mining/resume.js";
import { resolveMiningOutputs } from "./mining/batch.js";

const RETENTION_LOCK = ".aark-retention.lock";
const TOKEN = /^[a-f0-9]{64}$/u;
const MAX_RETENTION_OUTPUTS = 10_000;
const MAX_RETENTION_SOURCES = 100_000;
const MAX_RETENTION_CONTROL_BYTES = 256 * 1024 * 1024;
const COPY_BUFFER_BYTES = 8 * 1024 * 1024;
const SAFETY_CHECK_BYTES = 1024 * 1024 * 1024;
const SAFETY_CHECK_INTERVAL_MS = 30_000;
const MAX_RETENTION_OBJECT_ENTRIES = 1_000_000;
const RETENTION_ALLOWED_ENTRIES = new Set([
  RETENTION_LOCK,
  "objects",
  "retention-progress-redacted.json",
  "retention-mapping-sensitive.json",
  "retention-manifest-redacted.json",
  "retention-final-report-redacted.md",
]);

export interface RetentionOptions {
  miningOutputs: string[];
  destination: string;
  requireReadOnlySources?: boolean;
  minimumFreeGiB?: number;
  minimumFreePercent?: number;
  maximumOutputGiB?: number;
  signal?: AbortSignal;
  progress?: (progress: RetentionProgress) => void;
}

export interface RetentionRunOptions extends RetentionOptions {
  planToken: string;
}

export interface RetentionProgress {
  filesCompleted: number;
  filesTotal: number;
  bytesCopied: string;
  objectsCreated: number;
  objectsReused: number;
}

export interface RetentionPlanResult {
  version: 1;
  tool: "aark";
  layer: "retention";
  status: "ready";
  destructive: false;
  pathsRedacted: true;
  valuesPrinted: false;
  miningScansVerified: number;
  sourceFiles: string;
  sourceLogicalBytes: string;
  sourceAllocatedBytes: string;
  contentObjects: string;
  deduplicatedLogicalBytes: string;
  deduplicatedAllocatedBytes: string;
  allSourcesReadOnly: boolean;
  planToken: string;
  approvalRequired: false;
  resumable: true;
}

interface SourceRecord {
  path: string;
  device: number;
  inode: number;
  mode: number;
  links: number;
  bytes: number;
  allocatedBytes: bigint;
  modifiedMs: number;
  changedMs: number;
  sha256: string;
  readOnlyMount: boolean;
  mount: string;
}

interface VerifiedMiningScan {
  output: string;
  runId: string;
  manifest: ScanState["manifest"];
  inventory: ScanState["inventory"];
}

interface RetentionDestinationSnapshot {
  path: string;
  device: number;
  inode: number;
  mount: string;
}

interface InternalRetentionPlan {
  public: RetentionPlanResult;
  destination: string;
  sources: SourceRecord[];
  scans: VerifiedMiningScan[];
  storage: { minimumFreeGiB: number; minimumFreePercent: number; maximumOutputGiB?: number };
  allocationUnitBytes: bigint;
  signal?: AbortSignal;
  progress?: (progress: RetentionProgress) => void;
}

function interrupted(signal: AbortSignal | undefined): void {
  if (signal?.aborted === true) throw new Error("retention was interrupted");
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

async function destinationSnapshot(destination: string): Promise<RetentionDestinationSnapshot> {
  const canonical = await realpath(destination);
  if (canonical !== destination) throw new Error("retention destination must remain a canonical real directory");
  const metadata = await lstat(destination);
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) throw new Error("retention destination must remain a real directory");
  const records = await mounts();
  const mounted = mountForPathFrom(records, destination);
  if (mounted === undefined || await mountIsNetworkBacked(mounted)) {
    throw new Error("retention destination must remain on a verifiable local filesystem");
  }
  if (path.resolve(mounted.target) === destination || records.some((record) => {
    const target = path.resolve(record.target);
    return target !== destination && inside(destination, target);
  })) throw new Error("retention destination must be a dedicated subdirectory without nested mounts");
  return { path: destination, device: metadata.dev, inode: metadata.ino, mount: mountIdentity(mounted) };
}

async function assertDestinationCurrent(expected: RetentionDestinationSnapshot): Promise<void> {
  const current = await destinationSnapshot(expected.path);
  if (current.device !== expected.device || current.inode !== expected.inode || current.mount !== expected.mount) {
    throw new Error("retention destination directory or mount changed while the operation was running");
  }
}

async function assertRetentionDirectoryEntries(destination: string): Promise<void> {
  try {
    const entries = await readDirectoryNamesBounded(destination, RETENTION_ALLOWED_ENTRIES.size + 1);
    if (entries.some((entry) => !RETENTION_ALLOWED_ENTRIES.has(entry))) {
      throw new Error("retention destination contains an unexpected top-level entry; use a dedicated directory");
    }
  } catch (error) {
    if (errorCode(error) !== "ENOENT") throw error;
  }
}

async function existingRetentionPlanToken(destination: string): Promise<string | undefined> {
  let token: string | undefined;
  for (const filename of ["retention-mapping-sensitive.json", "retention-manifest-redacted.json"] as const) {
    let document: Record<string, unknown>;
    try {
      document = await readJson<Record<string, unknown>>(
        safeJoin(destination, filename),
        MAX_RETENTION_CONTROL_BYTES + 2 * 1024 * 1024,
      );
    } catch (error) {
      if (errorCode(error) === "ENOENT") continue;
      const cause = error instanceof Error && "cause" in error ? error.cause : undefined;
      if (errorCode(cause) === "ENOENT") continue;
      throw error;
    }
    if (document.version !== 1 || document.tool !== "aark" || document.layer !== "retention"
      || document.status !== "complete" || typeof document.planToken !== "string" || !TOKEN.test(document.planToken)) {
      throw new Error("existing retention control state is invalid");
    }
    if (token !== undefined && token !== document.planToken) {
      throw new Error("existing retention control files disagree about their bound plan");
    }
    token = document.planToken;
  }
  return token;
}

async function assertSourceMountCurrent(filename: string, expectedMount: string, requireReadOnly: boolean): Promise<void> {
  const records = await mounts();
  const current = mountForPathFrom(records, filename);
  if (current === undefined || mountIdentity(current) !== expectedMount || await mountIsNetworkBacked(current)) {
    throw new Error("a retention source mount changed while it was being verified or copied");
  }
  if (requireReadOnly && !mountIsReadOnly(current)) throw new Error("a retention source mount is no longer read-only");
}

async function assertSourcesCurrentBeforePublication(
  sources: SourceRecord[],
  signal: AbortSignal | undefined,
  destinationSafetyCheck: () => Promise<void>,
): Promise<void> {
  let mountTable = await mounts();
  let networkCache = new Map<string, Promise<boolean>>();
  const networkBacked = async (mounted: MountRecord): Promise<boolean> => {
    const identity = mountIdentity(mounted);
    let pending = networkCache.get(identity);
    if (pending === undefined) {
      pending = mountIsNetworkBacked(mounted);
      networkCache.set(identity, pending);
    }
    return await pending;
  };
  let lastSafetyAt = Date.now();
  for (let index = 0; index < sources.length; index += 1) {
    interrupted(signal);
    const source = sources[index];
    if (source === undefined) continue;
    const now = Date.now();
    if (index > 0 && (index % 1_024 === 0 || now - lastSafetyAt >= SAFETY_CHECK_INTERVAL_MS)) {
      await destinationSafetyCheck();
      mountTable = await mounts();
      networkCache = new Map<string, Promise<boolean>>();
      lastSafetyAt = now;
    }
    const mounted = mountForPathFrom(mountTable, source.path);
    if (mounted === undefined || mountIdentity(mounted) !== source.mount || await networkBacked(mounted)
      || source.readOnlyMount && !mountIsReadOnly(mounted)) {
      throw new Error("a retention source mount changed before retention completion");
    }
    const metadata = await lstat(source.path);
    if (metadata.isSymbolicLink() || !metadata.isFile()
      || metadata.dev !== source.device || metadata.ino !== source.inode
      || metadata.mode !== source.mode || metadata.nlink !== source.links
      || metadata.size !== source.bytes || metadata.mtimeMs !== source.modifiedMs || metadata.ctimeMs !== source.changedMs
      || await realpath(source.path) !== source.path) {
      throw new Error("a retention source changed before retention completion");
    }
  }
  await destinationSafetyCheck();
}

async function prepareObjectsRoot(objectsRoot: string, safetyCheck: () => Promise<void>): Promise<void> {
  await safetyCheck();
  const shards = await readDirectoryNamesBounded(objectsRoot, 257);
  let entries = 0;
  let lastSafetyAt = Date.now();
  for (const shard of shards) {
    if (!/^[a-f0-9]{2}$/u.test(shard)) throw new Error("retention object store contains an invalid shard entry");
    const shardRoot = safeJoin(objectsRoot, shard);
    const shardMetadata = await lstat(shardRoot);
    if (shardMetadata.isSymbolicLink() || !shardMetadata.isDirectory() || await realpath(shardRoot) !== shardRoot) {
      throw new Error("retention object shard must be a canonical real directory");
    }
    let removedTemporary = false;
    const directory = await opendir(shardRoot);
    for await (const entry of directory) {
      entries += 1;
      if (entries > MAX_RETENTION_OBJECT_ENTRIES) throw new Error("retention object store exceeds its bounded entry limit");
      const now = Date.now();
      if (entries % 1_024 === 0 || now - lastSafetyAt >= SAFETY_CHECK_INTERVAL_MS) {
        await safetyCheck();
        lastSafetyAt = now;
      }
      const filename = safeJoin(shardRoot, entry.name);
      const metadata = await lstat(filename);
      if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.nlink !== 1) {
        throw new Error("retention object store entries must be single-link regular files");
      }
      if (/^[a-f0-9]{64}$/u.test(entry.name) && entry.name.startsWith(shard)) continue;
      if (/^[a-f0-9]{64}\.tmp-[1-9][0-9]*-[a-f0-9-]{36}$/u.test(entry.name) && entry.name.startsWith(shard)) {
        await safetyCheck();
        const current = await lstat(filename);
        if (current.dev !== metadata.dev || current.ino !== metadata.ino || current.nlink !== 1 || !current.isFile()) {
          throw new Error("an orphan retention temporary object changed before cleanup");
        }
        await unlink(filename);
        removedTemporary = true;
        continue;
      }
      throw new Error("retention object store contains an unexpected object entry");
    }
    if (removedTemporary) await syncDirectory(shardRoot);
  }
  await safetyCheck();
}

function errorCode(error: unknown): string | undefined {
  return error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
}

function safeNumber(value: number | undefined, fallback: number, label: string, maximum = 1_000_000): number {
  const actual = value ?? fallback;
  if (!Number.isFinite(actual) || actual < 0 || actual > maximum) throw new Error(`${label} is outside its supported range`);
  return actual;
}

function normalize(options: RetentionOptions): {
  miningOutputs: string[];
  destination: string;
  requireReadOnlySources: boolean;
  storage: { minimumFreeGiB: number; minimumFreePercent: number; maximumOutputGiB?: number };
  signal?: AbortSignal;
  progress?: (progress: RetentionProgress) => void;
} {
  if (options.miningOutputs.length < 1 || options.miningOutputs.length > MAX_RETENTION_OUTPUTS) {
    throw new Error(`retention requires from 1 through ${MAX_RETENTION_OUTPUTS} completed mining outputs`);
  }
  const miningOutputs = [...new Set(options.miningOutputs.map((item) => path.resolve(item)))].sort();
  if (miningOutputs.length !== options.miningOutputs.length) throw new Error("retention mining outputs must be unique");
  const outputSet = new Set(miningOutputs);
  for (const output of miningOutputs) {
    let parent = path.dirname(output);
    while (parent !== output) {
      if (outputSet.has(parent)) throw new Error("retention mining outputs must not contain one another");
      const next = path.dirname(parent);
      if (next === parent) break;
      parent = next;
    }
  }
  const destination = path.resolve(options.destination);
  if (destination === path.parse(destination).root) throw new Error("retention destination must be a dedicated directory");
  for (const output of miningOutputs) {
    if (inside(destination, output) || inside(output, destination)) {
      throw new Error("retention destination and mining outputs must not contain one another");
    }
  }
  return {
    miningOutputs,
    destination,
    requireReadOnlySources: options.requireReadOnlySources !== false,
    storage: {
      minimumFreeGiB: safeNumber(options.minimumFreeGiB, 5, "minimum free GiB"),
      minimumFreePercent: safeNumber(options.minimumFreePercent, 5, "minimum free percent", 100),
      ...(options.maximumOutputGiB === undefined ? {} : {
        maximumOutputGiB: safeNumber(options.maximumOutputGiB, 0, "maximum output GiB"),
      }),
    },
    ...(options.signal === undefined ? {} : { signal: options.signal }),
    ...(options.progress === undefined ? {} : { progress: options.progress }),
  };
}

function fileAuthorized(filename: string, roots: ScanState["inputRoots"]): boolean {
  return roots.some((root) => root.kind === "file"
    ? filename === root.path
    : filename !== root.path && inside(root.path, filename));
}

function sameFrozenFile(record: FrozenScanFile, metadata: Awaited<ReturnType<typeof lstat>>): boolean {
  return metadata.isFile()
    && !metadata.isSymbolicLink()
    && record.device === metadata.dev
    && record.inode === metadata.ino
    && record.bytes === metadata.size
    && record.modifiedMs === metadata.mtimeMs
    && record.changedMs === metadata.ctimeMs;
}

async function stableSourceRecord(
  filename: string,
  readOnlyMount: boolean,
  sourceMount: string,
  signal?: AbortSignal,
  safetyCheck?: () => Promise<void>,
): Promise<SourceRecord> {
  const handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    await safetyCheck?.();
    const before = await handle.stat();
    const linkedBefore = await lstat(filename);
    if (!before.isFile() || before.nlink < 1 || !sameMetadata(before, linkedBefore)) {
      throw new Error("retention source must remain a linked regular file");
    }
    const digest = createHash("sha256");
    const buffer = Buffer.allocUnsafe(COPY_BUFFER_BYTES);
    let offset = 0;
    let lastSafetyOffset = 0;
    let lastSafetyAt = Date.now();
    while (offset < before.size) {
      interrupted(signal);
      const read = await handle.read(buffer, 0, Math.min(buffer.length, before.size - offset), offset);
      if (read.bytesRead === 0) throw new Error("retention source ended before its recorded size");
      digest.update(buffer.subarray(0, read.bytesRead));
      offset += read.bytesRead;
      const now = Date.now();
      if (safetyCheck !== undefined
        && (offset - lastSafetyOffset >= SAFETY_CHECK_BYTES || now - lastSafetyAt >= SAFETY_CHECK_INTERVAL_MS)) {
        await safetyCheck();
        lastSafetyOffset = offset;
        lastSafetyAt = now;
      }
    }
    const probe = Buffer.allocUnsafe(1);
    if ((await handle.read(probe, 0, 1, offset)).bytesRead !== 0) throw new Error("retention source grew while it was hashed");
    const after = await handle.stat();
    const linkedAfter = await lstat(filename);
    if (!sameMetadata(before, after) || !sameMetadata(after, linkedAfter)) {
      throw new Error("retention source changed while it was hashed");
    }
    if (!Number.isSafeInteger(after.blocks) || after.blocks < 0 || !Number.isSafeInteger(after.size) || after.size < 0) {
      throw new Error("retention source filesystem accounting exceeds safe numeric bounds");
    }
    await safetyCheck?.();
    return {
      path: filename,
      device: after.dev,
      inode: after.ino,
      mode: after.mode,
      links: after.nlink,
      bytes: after.size,
      allocatedBytes: BigInt(after.blocks) * 512n,
      modifiedMs: after.mtimeMs,
      changedMs: after.ctimeMs,
      sha256: digest.digest("hex"),
      readOnlyMount,
      mount: sourceMount,
    };
  } finally {
    await handle.close();
  }
}

function sameMetadata(left: Awaited<ReturnType<typeof lstat>>, right: Awaited<ReturnType<typeof lstat>>): boolean {
  return right.isFile()
    && !right.isSymbolicLink()
    && left.dev === right.dev
    && left.ino === right.ino
    && left.nlink === right.nlink
    && left.size === right.size
    && left.mtimeMs === right.mtimeMs
    && left.ctimeMs === right.ctimeMs;
}

async function buildInternalPlan(options: RetentionOptions): Promise<InternalRetentionPlan> {
  const normalized = normalize(options);
  const resolvedMining = await resolveMiningOutputs(normalized.miningOutputs, MAX_RETENTION_OUTPUTS);
  interrupted(normalized.signal);
  const mountTable = await mounts();
  const destinationParent = await nearestExistingParent(normalized.destination);
  const destinationMount = mountForPathFrom(mountTable, destinationParent);
  if (destinationMount === undefined || await mountIsNetworkBacked(destinationMount)) {
    throw new Error("retention destination must be on a verifiable local filesystem");
  }
  const policy = storagePolicyFromGiB(
    normalized.storage.minimumFreeGiB,
    normalized.storage.minimumFreePercent,
    normalized.storage.maximumOutputGiB,
  );
  await assertStorageCapacity(destinationParent, policy);
  const destinationFilesystem = await statfs(destinationParent, { bigint: true });
  if (destinationFilesystem.bsize < 1n) throw new Error("retention destination reported an invalid allocation unit");
  const allocationUnitBytes = destinationFilesystem.bsize;
  await assertRetentionDirectoryEntries(normalized.destination);
  try {
    await destinationSnapshot(normalized.destination);
  } catch (error) {
    if (errorCode(error) !== "ENOENT") throw error;
  }

  const sourcesByPath = new Map<string, { scanState: ScanState; manifestRecord?: FrozenScanFile }>();
  const scans: VerifiedMiningScan[] = [];
  for (const output of resolvedMining.outputs) {
    interrupted(normalized.signal);
    const canonicalOutput = await realpath(output);
    if (canonicalOutput !== output) throw new Error("mining output must be a canonical real directory");
    const outputMount = mountForPathFrom(mountTable, output);
    if (outputMount === undefined || await mountIsNetworkBacked(outputMount)) throw new Error("mining output must be local");
    const state = await loadScanState(output, normalized.signal);
    if (state.status !== "complete" || state.resumable || !state.inventoryComplete) {
      throw new Error("retention requires exact, error-free completed mining scans");
    }
    const inventory = await loadVerifiedCompletedInventory(output, state, normalized.signal);
    const wanted = new Set(inventory.findings.flatMap((finding) => finding.occurrences.map((occurrence) => occurrence.sourcePath)));
    for (const filename of wanted) {
      if (!fileAuthorized(filename, state.inputRoots)) throw new Error("a finding source escaped its mining input roots");
      const existing = sourcesByPath.get(filename);
      if (existing !== undefined && JSON.stringify(existing.scanState.inputRoots) !== JSON.stringify(state.inputRoots)) {
        throw new Error("the same finding source has conflicting scan-root provenance");
      }
      sourcesByPath.set(filename, { scanState: state });
      if (sourcesByPath.size > MAX_RETENTION_SOURCES) throw new Error("retention source-file set exceeds its bounded control limit; split the retention workflow");
    }
    for await (const record of readScanManifest(output, state.manifest, normalized.signal)) {
      const wantedSource = sourcesByPath.get(record.path);
      if (wantedSource !== undefined && wanted.has(record.path)) wantedSource.manifestRecord = record;
    }
    scans.push({ output, runId: state.runId, manifest: state.manifest, inventory: state.inventory });
  }

  const sources: SourceRecord[] = [];
  for (const [filename, reference] of [...sourcesByPath.entries()].sort(([left], [right]) => left.localeCompare(right))) {
    interrupted(normalized.signal);
    if (reference.manifestRecord === undefined) throw new Error("a finding source is missing from its verified scan manifest");
    const metadata = await lstat(filename);
    if (!sameFrozenFile(reference.manifestRecord, metadata) || await realpath(filename) !== filename) {
      throw new Error("a finding source changed after its completed scan");
    }
    if (inside(normalized.destination, filename) || inside(filename, normalized.destination)) {
      throw new Error("retention destination and finding sources must not contain one another");
    }
    const sourceMount = mountForPathFrom(mountTable, filename);
    if (sourceMount === undefined || await mountIsNetworkBacked(sourceMount)) throw new Error("finding sources must be on local filesystems");
    const readOnlyMount = mountIsReadOnly(sourceMount);
    if (normalized.requireReadOnlySources && !readOnlyMount) {
      throw new Error("retention requires finding sources to be mounted read-only");
    }
    const expectedMount = mountIdentity(sourceMount);
    sources.push(await stableSourceRecord(
      filename,
      readOnlyMount,
      expectedMount,
      normalized.signal,
      async () => await assertSourceMountCurrent(filename, expectedMount, normalized.requireReadOnlySources),
    ));
  }

  const objects = new Map<string, number>();
  for (const source of sources) objects.set(source.sha256, source.bytes);
  const tokenMaterial = {
    version: 1,
    destination: normalized.destination,
    destinationMount: mountIdentity(destinationMount),
    allocationUnitBytes: allocationUnitBytes.toString(),
    requireReadOnlySources: normalized.requireReadOnlySources,
    storage: normalized.storage,
    scans,
    sources: sources.map((source) => ({ ...source, allocatedBytes: source.allocatedBytes.toString() })),
  };
  const serializedTokenMaterial = JSON.stringify(tokenMaterial);
  if (Buffer.byteLength(serializedTokenMaterial) > MAX_RETENTION_CONTROL_BYTES) {
    throw new Error("retention control mapping exceeds its bounded size limit; split the retention workflow");
  }
  const planToken = createHash("sha256").update(serializedTokenMaterial).digest("hex");
  const existingToken = await existingRetentionPlanToken(normalized.destination);
  if (existingToken !== undefined && existingToken !== planToken) {
    throw new Error("retention destination is already bound to a different completed plan; use a new dedicated directory");
  }
  const allocatedIdentities = new Set<string>();
  const sourceAllocatedBytes = sources.reduce((sum, source) => {
    const identity = `${source.device}:${source.inode}`;
    if (allocatedIdentities.has(identity)) return sum;
    allocatedIdentities.add(identity);
    return sum + source.allocatedBytes;
  }, 0n);
  const publicPlan: RetentionPlanResult = {
    version: 1,
    tool: "aark",
    layer: "retention",
    status: "ready",
    destructive: false,
    pathsRedacted: true,
    valuesPrinted: false,
    miningScansVerified: scans.length,
    sourceFiles: sources.length.toString(),
    sourceLogicalBytes: sources.reduce((sum, source) => sum + BigInt(source.bytes), 0n).toString(),
    sourceAllocatedBytes: sourceAllocatedBytes.toString(),
    contentObjects: objects.size.toString(),
    deduplicatedLogicalBytes: [...objects.values()].reduce((sum, bytes) => sum + BigInt(bytes), 0n).toString(),
    deduplicatedAllocatedBytes: [...objects.values()].reduce(
      (sum, bytes) => sum + (BigInt(bytes) + allocationUnitBytes - 1n) / allocationUnitBytes * allocationUnitBytes,
      0n,
    ).toString(),
    allSourcesReadOnly: sources.every((source) => source.readOnlyMount),
    planToken,
    approvalRequired: false,
    resumable: true,
  };
  return {
    public: publicPlan,
    destination: normalized.destination,
    sources,
    scans,
    storage: normalized.storage,
    allocationUnitBytes,
    ...(normalized.signal === undefined ? {} : { signal: normalized.signal }),
    ...(normalized.progress === undefined ? {} : { progress: normalized.progress }),
  };
}

export async function planRetention(options: RetentionOptions): Promise<RetentionPlanResult> {
  return (await buildInternalPlan(options)).public;
}

async function verifyObject(filename: string, expected: SourceRecord, signal?: AbortSignal, safetyCheck?: () => Promise<void>): Promise<void> {
  const actual = await stableSourceRecord(filename, false, expected.mount, signal, safetyCheck);
  if (actual.links !== 1 || await realpath(filename) !== filename || actual.bytes !== expected.bytes || actual.sha256 !== expected.sha256) {
    throw new Error("an existing retained content object failed integrity verification");
  }
}

async function copyObject(
  source: SourceRecord,
  destination: string,
  signal?: AbortSignal,
  safetyCheck?: (remainingBytes: bigint) => Promise<void>,
): Promise<void> {
  const parent = path.dirname(destination);
  await safetyCheck?.(BigInt(source.bytes));
  await ensurePrivateDirectory(parent);
  await assertNoSymlinkComponents(parent, destination);
  const temporary = `${destination}.tmp-${process.pid}-${randomUUID()}`;
  const input = await open(source.path, constants.O_RDONLY | constants.O_NOFOLLOW);
  let output: Awaited<ReturnType<typeof open>> | undefined;
  let temporaryIdentity: { device: number; inode: number } | undefined;
  let published = false;
  try {
    const inputBefore = await input.stat();
    if (!sameMetadata(inputBefore, await lstat(source.path)) || inputBefore.dev !== source.device || inputBefore.ino !== source.inode) {
      throw new Error("retention source changed before copying");
    }
    output = await open(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    const outputBefore = await output.stat();
    if (!outputBefore.isFile() || outputBefore.nlink !== 1) throw new Error("retention temporary object must be a single-link regular file");
    temporaryIdentity = { device: outputBefore.dev, inode: outputBefore.ino };
    const digest = createHash("sha256");
    const buffer = Buffer.allocUnsafe(COPY_BUFFER_BYTES);
    let offset = 0;
    let lastSafetyOffset = 0;
    let lastSafetyAt = Date.now();
    while (offset < source.bytes) {
      interrupted(signal);
      const read = await input.read(buffer, 0, Math.min(buffer.length, source.bytes - offset), offset);
      if (read.bytesRead === 0) throw new Error("retention source ended during copying");
      digest.update(buffer.subarray(0, read.bytesRead));
      let written = 0;
      while (written < read.bytesRead) {
        const result = await output.write(buffer, written, read.bytesRead - written, offset + written);
        if (result.bytesWritten === 0) throw new Error("retention destination made no write progress");
        written += result.bytesWritten;
      }
      offset += read.bytesRead;
      const now = Date.now();
      if (safetyCheck !== undefined
        && (offset - lastSafetyOffset >= SAFETY_CHECK_BYTES || now - lastSafetyAt >= SAFETY_CHECK_INTERVAL_MS)) {
        await safetyCheck(BigInt(source.bytes - offset));
        lastSafetyOffset = offset;
        lastSafetyAt = now;
      }
    }
    if (digest.digest("hex") !== source.sha256) throw new Error("retention source content changed during copying");
    if (!sameMetadata(inputBefore, await input.stat()) || !sameMetadata(inputBefore, await lstat(source.path))) {
      throw new Error("retention source metadata changed during copying");
    }
    await safetyCheck?.(0n);
    await output.sync();
    await output.close();
    output = undefined;
    await chmod(temporary, 0o600).catch((error: unknown) => {
      if (!["ENOSYS", "EOPNOTSUPP", "ENOTSUP"].includes(errorCode(error) ?? "")) throw error;
    });
    try {
      await lstat(destination);
      throw new Error("retained content object appeared concurrently");
    } catch (error) {
      if (errorCode(error) !== "ENOENT") throw error;
    }
    await safetyCheck?.(0n);
    await rename(temporary, destination);
    published = true;
    await syncDirectory(parent);
    const current = await lstat(destination);
    if (current.isSymbolicLink() || !current.isFile() || current.nlink !== 1 || temporaryIdentity === undefined
      || current.dev !== temporaryIdentity.device || current.ino !== temporaryIdentity.inode) {
      throw new Error("retained content object changed during publication");
    }
    await safetyCheck?.(0n);
  } finally {
    await input.close().catch(() => undefined);
    await output?.close().catch(() => undefined);
    if (!published && temporaryIdentity !== undefined) {
      try {
        const current = await lstat(temporary);
        if (current.dev === temporaryIdentity.device && current.ino === temporaryIdentity.inode) await unlink(temporary);
      } catch {
        // Missing or substituted temporary paths are not safe cleanup targets.
      }
    }
  }
}

export async function runRetention(options: RetentionRunOptions): Promise<Record<string, unknown>> {
  if (!TOKEN.test(options.planToken)) throw new Error("retention requires the exact plan token from retain plan");
  const initial = await buildInternalPlan(options);
  if (initial.public.planToken !== options.planToken) throw new Error("retention inputs changed after planning; create a fresh retention plan");
  await ensurePrivateDirectory(initial.destination);
  const lock = await acquireExclusiveLock(initial.destination, RETENTION_LOCK, { reclaimDeadOwner: true });
  let operationError: unknown;
  let activePlan: InternalRetentionPlan | undefined;
  let activeDestination: RetentionDestinationSnapshot | undefined;
  let latestProgress: RetentionProgress | undefined;
  try {
    const plan = await buildInternalPlan(options);
    activePlan = plan;
    if (plan.public.planToken !== options.planToken) throw new Error("retention inputs changed while its operation lock was acquired");
    const destination = await destinationSnapshot(plan.destination);
    activeDestination = destination;
    const policy = storagePolicyFromGiB(plan.storage.minimumFreeGiB, plan.storage.minimumFreePercent, plan.storage.maximumOutputGiB);
    const assertDestinationSafe = async (): Promise<void> => {
      interrupted(plan.signal);
      await lock.assertHeld();
      await assertDestinationCurrent(destination);
    };
    await assertDestinationSafe();
    const objectsRoot = safeJoin(plan.destination, "objects");
    await ensurePrivateDirectory(objectsRoot);
    await assertDestinationSafe();
    await prepareObjectsRoot(objectsRoot, assertDestinationSafe);
    const currentOutputBytes = await directoryLogicalBytes(plan.destination, plan.signal);
    const budget = new StorageBudget(plan.destination, policy, currentOutputBytes);
    const freeSpacePolicy = storagePolicyFromGiB(plan.storage.minimumFreeGiB, plan.storage.minimumFreePercent);
    const roundedAllocation = (bytes: bigint): bigint => bytes === 0n
      ? 0n
      : (bytes + plan.allocationUnitBytes - 1n) / plan.allocationUnitBytes * plan.allocationUnitBytes;
    const assertCopySafe = async (remainingBytes: bigint): Promise<void> => {
      await assertDestinationSafe();
      await assertStorageCapacity(plan.destination, freeSpacePolicy, 0n, roundedAllocation(remainingBytes));
      await budget.beforeWrite(remainingBytes);
    };
    await assertCopySafe(0n);
    const existingVerified = new Set<string>();
    const missingObjects = new Map<string, number>();
    for (const source of plan.sources) {
      if (existingVerified.has(source.sha256) || missingObjects.has(source.sha256)) continue;
      const object = safeJoin(objectsRoot, source.sha256.slice(0, 2), source.sha256);
      try {
        await lstat(object);
        await verifyObject(object, source, plan.signal, async () => await assertCopySafe(0n));
        existingVerified.add(source.sha256);
      } catch (error) {
        if (errorCode(error) !== "ENOENT") throw error;
        missingObjects.set(source.sha256, source.bytes);
      }
    }
    const controlEstimate = Buffer.byteLength(JSON.stringify({
      scans: plan.scans,
      sources: plan.sources.map((source) => ({
        sourcePath: source.path,
        sourceIdentity: { device: source.device, inode: source.inode, bytes: source.bytes, modifiedMs: source.modifiedMs, changedMs: source.changedMs },
        sha256: source.sha256,
        object: path.join("objects", source.sha256.slice(0, 2), source.sha256),
      })),
    })) + 1024 * 1024;
    if (controlEstimate > MAX_RETENTION_CONTROL_BYTES) throw new Error("retention output control mapping exceeds its bounded size limit");
    const newObjectBytes = [...missingObjects.values()].reduce((sum, bytes) => sum + BigInt(bytes), 0n);
    const newObjectAllocatedBytes = [...missingObjects.values()].reduce(
      (sum, bytes) => sum + roundedAllocation(BigInt(bytes)),
      0n,
    );
    const existingShards = new Set(await readDirectoryNamesBounded(objectsRoot, 257));
    const newShards = new Set([...missingObjects.keys()]
      .map((digest) => digest.slice(0, 2))
      .filter((shard) => !existingShards.has(shard)));
    // Object data is cluster-rounded above. Conservatively reserve another
    // allocation unit for every new object directory entry, every new shard,
    // and each independent progress/mapping/manifest/report file. Directory
    // formats differ, but this bound avoids materially understating metadata
    // growth for huge sets of tiny or zero-byte files on large-cluster media.
    const controlAllocatedBytes = roundedAllocation(BigInt(controlEstimate))
      + BigInt(missingObjects.size + newShards.size + 4) * plan.allocationUnitBytes;
    await assertStorageCapacity(
      plan.destination,
      freeSpacePolicy,
      0n,
      newObjectAllocatedBytes + controlAllocatedBytes,
    );
    // The maximum-output contract is expressed in logical bytes. Keep that
    // check separate from the cluster-rounded free-space reservation above.
    await assertStorageCapacity(plan.destination, policy, currentOutputBytes, newObjectBytes + BigInt(controlEstimate));
    const progress: RetentionProgress = {
      filesCompleted: 0,
      filesTotal: plan.sources.length,
      bytesCopied: "0",
      objectsCreated: 0,
      objectsReused: 0,
    };
    latestProgress = progress;
    let copiedBytes = 0n;
    const published = new Set<string>();
    for (const source of plan.sources) {
      interrupted(plan.signal);
      await assertCopySafe(0n);
      const relativeObject = path.join(source.sha256.slice(0, 2), source.sha256);
      const object = safeJoin(objectsRoot, relativeObject);
      if (!published.has(source.sha256)) {
        if (existingVerified.has(source.sha256)) {
          progress.objectsReused += 1;
        } else {
          await budget.beforeWrite(BigInt(source.bytes));
          await copyObject(source, object, plan.signal, async (remainingBytes) => {
            await assertCopySafe(remainingBytes);
            await assertSourceMountCurrent(source.path, source.mount, source.readOnlyMount);
          });
          budget.committedWrite(BigInt(source.bytes));
          copiedBytes += BigInt(source.bytes);
          progress.objectsCreated += 1;
        }
        published.add(source.sha256);
      }
      progress.filesCompleted += 1;
      progress.bytesCopied = copiedBytes.toString();
      plan.progress?.({ ...progress });
      await assertCopySafe(0n);
      await atomicWriteJson(safeJoin(plan.destination, "retention-progress-redacted.json"), {
        version: 1,
        tool: "aark",
        layer: "retention",
        status: "running",
        updatedAt: new Date().toISOString(),
        ...progress,
        valuesPrinted: false,
        pathsRedacted: true,
      }, 0o644);
    }
    const mapping = {
      version: 1,
      tool: "aark",
      layer: "retention",
      status: "complete",
      planToken: plan.public.planToken,
      finishedAt: new Date().toISOString(),
      scans: plan.scans,
      sources: plan.sources.map((source) => ({
        sourcePath: source.path,
        sourceIdentity: { device: source.device, inode: source.inode, bytes: source.bytes, modifiedMs: source.modifiedMs, changedMs: source.changedMs },
        sha256: source.sha256,
        object: path.join("objects", source.sha256.slice(0, 2), source.sha256),
      })),
    };
    // Reused objects do not read their source again during the copy loop, and
    // a copied source could still change before its mapping is published.
    // Revalidate every source identity plus periodically refreshed mount state
    // at this final commit boundary.
    await assertSourcesCurrentBeforePublication(plan.sources, plan.signal, async () => await assertCopySafe(0n));
    await assertCopySafe(0n);
    await atomicWriteJson(safeJoin(plan.destination, "retention-mapping-sensitive.json"), mapping);
    const manifest = {
      version: 1,
      tool: "aark",
      layer: "retention",
      status: "complete",
      complete: true,
      valuesPrinted: false,
      pathsRedacted: true,
      planToken: plan.public.planToken,
      miningScansVerified: plan.public.miningScansVerified,
      sourceFilesRetained: plan.public.sourceFiles,
      contentObjects: plan.public.contentObjects,
      copiedLogicalBytes: copiedBytes.toString(),
      allSourcesReadOnly: plan.public.allSourcesReadOnly,
      mapping: "retention-mapping-sensitive.json",
    };
    await assertCopySafe(0n);
    await atomicWriteJson(safeJoin(plan.destination, "retention-manifest-redacted.json"), manifest, 0o644);
    await assertCopySafe(0n);
    await atomicWriteFile(safeJoin(plan.destination, "retention-final-report-redacted.md"), [
      "# AARK retention report",
      "",
      "- Status: complete",
      `- Mining scans verified: ${plan.public.miningScansVerified}`,
      `- Whole source files retained: ${plan.public.sourceFiles}`,
      `- Content-addressed objects: ${plan.public.contentObjects}`,
      `- Newly copied logical bytes: ${copiedBytes}`,
      "- Paths and recovered values are omitted.",
      "",
    ].join("\n"), 0o644);
    await assertCopySafe(0n);
    return manifest;
  } catch (error) {
    if ((options.signal?.aborted === true || error instanceof StorageQuotaError)
      && activePlan !== undefined && activeDestination !== undefined) {
      try {
        await lock.assertHeld();
        await assertDestinationCurrent(activeDestination);
        const progress = latestProgress ?? {
          filesCompleted: 0,
          filesTotal: activePlan.sources.length,
          bytesCopied: "0",
          objectsCreated: 0,
          objectsReused: 0,
        };
        const paused = {
          version: 1,
          tool: "aark",
          layer: "retention",
          status: "paused",
          complete: false,
          resumable: true,
          planToken: activePlan.public.planToken,
          pauseReason: error instanceof StorageQuotaError ? error.reason : "signal",
          ...progress,
          valuesPrinted: false,
          pathsRedacted: true,
        };
        await atomicWriteJson(safeJoin(activePlan.destination, "retention-progress-redacted.json"), paused, 0o644);
        return paused;
      } catch (reportError) {
        operationError = new AggregateError([error, reportError], "retention paused but its resumable checkpoint could not be published safely");
        throw operationError;
      }
    }
    operationError = error;
    throw error;
  } finally {
    try {
      await lock.release();
    } catch (releaseError) {
      if (operationError !== undefined) throw new AggregateError([operationError, releaseError], "retention failed and its lock could not be released");
      throw releaseError;
    }
  }
}
