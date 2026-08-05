import { constants } from "node:fs";
import { createHash, randomUUID } from "node:crypto";
import { lstat, open, realpath, rename, unlink } from "node:fs/promises";
import path from "node:path";
import { StringDecoder } from "node:string_decoder";
import { isDeepStrictEqual } from "node:util";
import type { Provenance } from "../core/types.js";
import { sha256Hex } from "../core/crypto.js";
import { assertNoSymlinkComponents, atomicWriteJson, readDirectoryNamesBounded, safeJoin, syncDirectory } from "../core/fs-safe.js";
import { assertStorageCapacity, storagePolicyFromGiB } from "../core/storage.js";
import type { StorageBudget } from "../core/storage.js";
import type { WalkedFile } from "../core/fs-safe.js";
import {
  isBoundedJsonValue,
  isSafeDetectorIdentifier,
  MAX_RECORDED_ERROR_FIELD_BYTES,
  MAX_RECORDED_OCCURRENCES,
  MAX_RECORDED_SCAN_ERRORS,
  MAX_SENSITIVE_INVENTORY_BYTES,
  MAX_UNIQUE_FINDINGS,
  MAX_INPUT_ROOTS,
} from "./limits.js";
import type { MiningProgress, MiningRunStatus, SensitiveScanInventory } from "./types.js";
import { MAX_DPAPI_BLOB_BYTES } from "./validators/dpapi.js";

export const SCAN_FILES_FILENAME = "scan-files-sensitive.ndjson";
export const SCAN_STATE_FILENAME = "scan-state-sensitive.json";
const MAX_CONTROL_PATH_BYTES = 4 * 1024;
const MAX_ARTIFACT_RELATIVE_PATH_BYTES = 512;
const MINIMUM_STREAMING_OVERLAP_BYTES = MAX_DPAPI_BLOB_BYTES + 1024 * 1024;
const MAX_STREAMING_CHUNK_BYTES = 128 * 1024 * 1024;
const MAX_WHOLE_FILE_BYTES = 256 * 1024 * 1024;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const PROVENANCE = new Set([
  "deleted-metadata",
  "unallocated-carve",
  "unallocated-stream",
  "shadow-copy",
  "residual-memory",
  "allocated-reference",
  "unknown",
]);

function boundedString(value: unknown, maximumBytes: number): value is string {
  return typeof value === "string" && Buffer.byteLength(value) <= maximumBytes;
}

function validStoragePolicy(operational: Record<string, unknown>): boolean {
  if (
    typeof operational.minimumFreeGiB !== "number"
    || typeof operational.minimumFreePercent !== "number"
    || (operational.maximumOutputGiB !== undefined && typeof operational.maximumOutputGiB !== "number")
  ) return false;
  try {
    storagePolicyFromGiB(
      operational.minimumFreeGiB,
      operational.minimumFreePercent,
      operational.maximumOutputGiB,
    );
    return true;
  } catch {
    return false;
  }
}

export interface FrozenScanFile extends WalkedFile {
  index: number;
}

export interface ScanSemanticOptions {
  inputs: string[];
  output: string;
  provenance: Provenance;
  chunkBytes: number;
  overlapBytes: number;
  wholeFileBytes: number;
  deepKeySchedules: boolean;
}

export interface ScanOperationalOptions {
  workers: number;
  minimumFreeGiB: number;
  minimumFreePercent: number;
  maximumOutputGiB?: number;
}

export interface ScanCursor {
  fileIndex: number;
  phase: "stream" | "whole-file";
  nextOffset: number;
}

export interface ScanState {
  version: 1;
  tool: "aark";
  layer: "mining-resume";
  runId: string;
  status: MiningRunStatus;
  resumable: boolean;
  inventoryComplete: boolean;
  pauseReason?: "signal" | "free-space-reserve" | "output-cap";
  startedAt: string;
  updatedAt: string;
  semantic: ScanSemanticOptions;
  operational: ScanOperationalOptions;
  inputRoots: Array<{ path: string; device: number; inode: number; kind: "file" | "directory"; mount: string }>;
  manifest: { filename: typeof SCAN_FILES_FILENAME; entries: number; bytes: number; sha256: string };
  inventory: { filename: "inventory-sensitive.json"; bytes: number; sha256: string };
  cursor: ScanCursor;
  progress: MiningProgress;
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as Record<string, unknown>;
}

function frozenFile(value: unknown, expectedIndex: number): FrozenScanFile {
  const item = record(value, "scan manifest entry");
  if (
    item.index !== expectedIndex
    || typeof item.path !== "string"
    || !path.isAbsolute(item.path)
    || path.resolve(item.path) !== item.path
    || !Number.isSafeInteger(item.bytes)
    || Number(item.bytes) < 0
    || !Number.isSafeInteger(item.device)
    || !Number.isSafeInteger(item.inode)
    || typeof item.modifiedMs !== "number"
    || !Number.isFinite(item.modifiedMs)
    || typeof item.changedMs !== "number"
    || !Number.isFinite(item.changedMs)
  ) throw new Error("scan manifest contains an invalid file snapshot");
  return item as unknown as FrozenScanFile;
}

export async function createScanManifest(
  output: string,
  files: AsyncIterable<WalkedFile>,
  budget: StorageBudget,
  assertOutputSafe: () => Promise<void>,
): Promise<ScanState["manifest"]> {
  const destination = safeJoin(output, SCAN_FILES_FILENAME);
  const temporary = safeJoin(output, `.${SCAN_FILES_FILENAME}.tmp-${process.pid}-${randomUUID()}`);
  await assertNoSymlinkComponents(output, destination);
  await assertNoSymlinkComponents(output, temporary);
  let replacingBytes = 0n;
  let priorDestination: { device: number; inode: number; bytes: number; modifiedMs: number; changedMs: number } | undefined;
  try {
    const existing = await lstat(destination);
    if (existing.isSymbolicLink() || !existing.isFile() || existing.nlink !== 1) throw new Error("scan manifest must remain a single-link regular file");
    replacingBytes = BigInt(existing.size);
    priorDestination = {
      device: existing.dev,
      inode: existing.ino,
      bytes: existing.size,
      modifiedMs: existing.mtimeMs,
      changedMs: existing.ctimeMs,
    };
  } catch (error) {
    const code = error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
    if (code !== "ENOENT") throw error;
  }
  const handle = await open(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  let opened: Awaited<ReturnType<typeof handle.stat>>;
  try {
    opened = await handle.stat();
  } catch (error) {
    await handle.close().catch(() => undefined);
    throw error;
  }
  const openedIdentity = { device: opened.dev, inode: opened.ino };
  const hash = createHash("sha256");
  let entries = 0;
  let bytes = 0;
  let bufferedBytes = 0;
  let buffered: Buffer[] = [];
  let published = false;
  const flush = async (): Promise<void> => {
    if (bufferedBytes === 0) return;
    await assertOutputSafe();
    await assertStorageCapacity(
      output,
      budget.policy,
      budget.outputBytes() - replacingBytes + BigInt(bytes - bufferedBytes),
      BigInt(bufferedBytes),
    );
    const data = Buffer.concat(buffered, bufferedBytes);
    let written = 0;
    while (written < data.length) {
      const result = await handle.write(data, written, data.length - written, null);
      if (result.bytesWritten === 0) throw new Error("scan manifest write made no progress");
      written += result.bytesWritten;
    }
    buffered = [];
    bufferedBytes = 0;
  };
  try {
    if (!opened.isFile() || opened.nlink !== 1) {
      throw new Error("scan manifest temporary output must be a single-link regular file");
    }
    for await (const file of files) {
      const line = Buffer.from(`${JSON.stringify({ index: entries, ...file })}\n`, "utf8");
      if (line.length > 64 * 1024) throw new Error("scan manifest entry exceeds its size limit");
      buffered.push(line);
      bufferedBytes += line.length;
      hash.update(line);
      bytes += line.length;
      entries += 1;
      if (bufferedBytes >= 1024 * 1024) await flush();
    }
    await flush();
    await handle.sync();
    await assertOutputSafe();
    const currentTemporary = await lstat(temporary);
    if (
      currentTemporary.isSymbolicLink()
      || !currentTemporary.isFile()
      || currentTemporary.nlink !== 1
      || currentTemporary.dev !== opened.dev
      || currentTemporary.ino !== opened.ino
    ) throw new Error("scan manifest temporary path changed before publication");
    try {
      const current = await lstat(destination);
      if (
        priorDestination === undefined
        || current.isSymbolicLink()
        || !current.isFile()
        || current.nlink !== 1
        || current.dev !== priorDestination.device
        || current.ino !== priorDestination.inode
        || current.size !== priorDestination.bytes
        || current.mtimeMs !== priorDestination.modifiedMs
        || current.ctimeMs !== priorDestination.changedMs
      ) throw new Error("scan manifest destination changed before publication");
    } catch (error) {
      const code = error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
      if (!(code === "ENOENT" && priorDestination === undefined)) throw error;
    }
    await rename(temporary, destination);
    published = true;
    const currentDestination = await lstat(destination);
    if (
      currentDestination.isSymbolicLink()
      || !currentDestination.isFile()
      || currentDestination.nlink !== 1
      || currentDestination.dev !== opened.dev
      || currentDestination.ino !== opened.ino
    ) throw new Error("scan manifest path changed during publication");
    await handle.close();
    budget.committedWrite(BigInt(bytes), replacingBytes);
    await syncDirectory(output);
    await assertOutputSafe();
  } finally {
    await handle.close().catch(() => undefined);
    if (!published) {
      try {
        const current = await lstat(temporary);
        if (current.dev === openedIdentity.device && current.ino === openedIdentity.inode) await unlink(temporary);
      } catch {
        // Missing or substituted temporary paths are not safe cleanup targets.
      }
    }
  }
  return { filename: SCAN_FILES_FILENAME, entries, bytes, sha256: hash.digest("hex") };
}

function assertNotAborted(signal: AbortSignal | undefined, operation: string): void {
  if (signal?.aborted === true) throw new Error(`${operation} was interrupted`);
}

async function stableFileBytes(filename: string, maximumBytes?: number, signal?: AbortSignal): Promise<Buffer> {
  assertNotAborted(signal, "resume control verification");
  const handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.nlink !== 1 || !Number.isSafeInteger(before.size) || before.size < 0) {
      throw new Error("resume control input must be a single-link regular file");
    }
    if (maximumBytes !== undefined && before.size > maximumBytes) throw new Error("resume control input exceeds its size limit");
    const data = Buffer.allocUnsafe(before.size);
    let offset = 0;
    while (offset < data.length) {
      assertNotAborted(signal, "resume control verification");
      const result = await handle.read(data, offset, data.length - offset, offset);
      if (result.bytesRead === 0) break;
      offset += result.bytesRead;
    }
    const after = await handle.stat();
    const current = await lstat(filename);
    if (
      offset !== before.size
      || before.dev !== after.dev
      || before.ino !== after.ino
      || after.nlink !== 1
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
      || await realpath(filename) !== path.resolve(filename)
    ) {
      throw new Error("resume control input changed while it was read");
    }
    return data;
  } finally {
    await handle.close();
  }
}

async function stableFileIntegrity(
  filename: string,
  maximumBytes: number,
  signal?: AbortSignal,
): Promise<{ bytes: number; sha256: string }> {
  assertNotAborted(signal, "resume artifact verification");
  const handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.nlink !== 1 || !Number.isSafeInteger(before.size) || before.size < 0 || before.size > maximumBytes) {
      throw new Error("resume artifact must be a bounded single-link regular file");
    }
    const hash = createHash("sha256");
    const buffer = Buffer.allocUnsafe(Math.min(1024 * 1024, Math.max(1, before.size)));
    let consumed = 0;
    while (consumed < before.size) {
      assertNotAborted(signal, "resume artifact verification");
      const result = await handle.read(buffer, 0, Math.min(buffer.length, before.size - consumed), consumed);
      if (result.bytesRead === 0) break;
      hash.update(buffer.subarray(0, result.bytesRead));
      consumed += result.bytesRead;
    }
    const probe = Buffer.allocUnsafe(1);
    const extra = await handle.read(probe, 0, 1, consumed);
    const after = await handle.stat();
    const current = await lstat(filename);
    if (
      consumed !== before.size
      || extra.bytesRead !== 0
      || before.dev !== after.dev
      || before.ino !== after.ino
      || after.nlink !== 1
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
      || await realpath(filename) !== path.resolve(filename)
    ) throw new Error("resume artifact changed while its integrity was verified");
    return { bytes: consumed, sha256: hash.digest("hex") };
  } finally {
    await handle.close();
  }
}

export async function* readScanManifest(output: string, expected: ScanState["manifest"], signal?: AbortSignal): AsyncGenerator<FrozenScanFile> {
  assertNotAborted(signal, "scan manifest verification");
  const filename = safeJoin(output, expected.filename);
  await assertNoSymlinkComponents(output, filename);
  const handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  const hash = createHash("sha256");
  const decoder = new StringDecoder("utf8");
  let pending = "";
  let index = 0;
  let consumed = 0;
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.nlink !== 1 || before.size !== expected.bytes) throw new Error("scan manifest identity or size does not match resume state");
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    while (consumed < expected.bytes) {
      assertNotAborted(signal, "scan manifest verification");
      const result = await handle.read(buffer, 0, Math.min(buffer.length, expected.bytes - consumed), consumed);
      if (result.bytesRead === 0) break;
      const chunk = buffer.subarray(0, result.bytesRead);
      consumed += result.bytesRead;
      hash.update(chunk);
      pending += decoder.write(chunk);
      while (true) {
        const newline = pending.indexOf("\n");
        if (newline < 0) break;
        const line = pending.slice(0, newline);
        pending = pending.slice(newline + 1);
        if (Buffer.byteLength(line) > 64 * 1024) throw new Error("scan manifest entry exceeds its size limit");
        assertNotAborted(signal, "scan manifest verification");
        let parsed: unknown;
        try {
          parsed = JSON.parse(line) as unknown;
        } catch (error) {
          throw new Error("scan manifest contains invalid JSON", { cause: error });
        }
        yield frozenFile(parsed, index++);
      }
      if (Buffer.byteLength(pending) > 64 * 1024) throw new Error("scan manifest entry exceeds its size limit");
    }
    const probe = Buffer.allocUnsafe(1);
    const extra = await handle.read(probe, 0, 1, consumed);
    pending += decoder.end();
    if (pending !== "") throw new Error("scan manifest does not end at a record boundary");
    const after = await handle.stat();
    const current = await lstat(filename);
    if (
      extra.bytesRead !== 0
      || before.dev !== after.dev
      || before.ino !== after.ino
      || after.nlink !== 1
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
      || await realpath(filename) !== path.resolve(filename)
    ) {
      throw new Error("scan manifest changed while it was read");
    }
  } finally {
    await handle.close();
  }
  if (index !== expected.entries || consumed !== expected.bytes || hash.digest("hex") !== expected.sha256) {
    throw new Error("scan manifest count or hash does not match resume state");
  }
}

export async function writeScanState(output: string, state: ScanState, budget?: StorageBudget, emergency = false): Promise<void> {
  const destination = safeJoin(output, SCAN_STATE_FILENAME);
  const serialized = `${JSON.stringify(state, null, 2)}\n`;
  let replacingBytes = 0n;
  try {
    const metadata = await lstat(destination);
    if (metadata.isSymbolicLink() || !metadata.isFile()) throw new Error("scan state must remain a regular file");
    replacingBytes = BigInt(metadata.size);
  } catch (error) {
    const code = error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
    if (code !== "ENOENT") throw error;
  }
  const bytes = BigInt(Buffer.byteLength(serialized));
  if (!emergency) await budget?.beforeWrite(bytes, replacingBytes);
  await atomicWriteJson(destination, state);
  budget?.committedWrite(bytes, replacingBytes);
}

export async function loadScanState(output: string, signal?: AbortSignal): Promise<ScanState> {
  const filename = safeJoin(output, SCAN_STATE_FILENAME);
  await assertNoSymlinkComponents(output, filename);
  const data = await stableFileBytes(filename, 16 * 1024 * 1024, signal);
  let parsed: unknown;
  try {
    parsed = JSON.parse(data.toString("utf8")) as unknown;
  } catch (error) {
    throw new Error("scan state is not valid JSON", { cause: error });
  }
  const stateRecord = record(parsed, "scan state");
  const semantic = record(stateRecord.semantic, "scan state semantic options");
  const operational = record(stateRecord.operational, "scan state operational options");
  const manifest = record(stateRecord.manifest, "scan state manifest");
  const inventory = record(stateRecord.inventory, "scan state inventory");
  const cursor = record(stateRecord.cursor, "scan state cursor");
  const progress = record(stateRecord.progress, "scan state progress");
  const inputRoots = stateRecord.inputRoots;
  const semanticInputs = Array.isArray(semantic.inputs) ? semantic.inputs : [];
  const nonNegativeSafe = (value: unknown): boolean => Number.isSafeInteger(value) && Number(value) >= 0;
  const nonNegativeFinite = (value: unknown): boolean => typeof value === "number" && Number.isFinite(value) && value >= 0;
  const hash = (value: unknown): boolean => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
  const status = String(stateRecord.status);
  if (
    stateRecord.version !== 1
    || stateRecord.tool !== "aark"
    || stateRecord.layer !== "mining-resume"
    || typeof stateRecord.runId !== "string"
    || !UUID.test(stateRecord.runId)
    || !["in-progress", "paused", "complete", "complete-with-errors", "failed", "interrupted"].includes(status)
    || typeof stateRecord.resumable !== "boolean"
    || typeof stateRecord.inventoryComplete !== "boolean"
    || (stateRecord.pauseReason !== undefined && !["signal", "free-space-reserve", "output-cap"].includes(String(stateRecord.pauseReason)))
    || (status === "paused" && (stateRecord.resumable !== true || stateRecord.pauseReason === undefined))
    || (status !== "paused" && (stateRecord.resumable !== false || stateRecord.pauseReason !== undefined))
    || !boundedString(stateRecord.startedAt, 128)
    || !boundedString(stateRecord.updatedAt, 128)
    || !Array.isArray(semantic.inputs)
    || semanticInputs.length < 1
    || semanticInputs.length > MAX_INPUT_ROOTS
    || semanticInputs.some((entry) => !boundedString(entry, MAX_CONTROL_PATH_BYTES) || !path.isAbsolute(entry) || path.resolve(entry) !== entry)
    || new Set(semanticInputs).size !== semanticInputs.length
    || semantic.output !== output
    || typeof semantic.provenance !== "string"
    || !PROVENANCE.has(semantic.provenance)
    || !nonNegativeSafe(semantic.chunkBytes)
    || Number(semantic.chunkBytes) < MINIMUM_STREAMING_OVERLAP_BYTES
    || Number(semantic.chunkBytes) > MAX_STREAMING_CHUNK_BYTES
    || !nonNegativeSafe(semantic.overlapBytes)
    || Number(semantic.overlapBytes) < MINIMUM_STREAMING_OVERLAP_BYTES
    || Number(semantic.overlapBytes) > Number(semantic.chunkBytes)
    || !nonNegativeSafe(semantic.wholeFileBytes)
    || Number(semantic.wholeFileBytes) < 1
    || Number(semantic.wholeFileBytes) > MAX_WHOLE_FILE_BYTES
    || typeof semantic.deepKeySchedules !== "boolean"
    || !nonNegativeSafe(operational.workers)
    || Number(operational.workers) < 1
    || Number(operational.workers) > 4
    || !nonNegativeFinite(operational.minimumFreeGiB)
    || !nonNegativeFinite(operational.minimumFreePercent)
    || (operational.maximumOutputGiB !== undefined && !nonNegativeFinite(operational.maximumOutputGiB))
    || !validStoragePolicy(operational)
    || !Array.isArray(inputRoots)
    || inputRoots.length !== semanticInputs.length
    || inputRoots.some((entry, index) => {
      const root = typeof entry === "object" && entry !== null && !Array.isArray(entry) ? entry as Record<string, unknown> : {};
      return !boundedString(root.path, MAX_CONTROL_PATH_BYTES) || root.path !== semanticInputs[index] || !path.isAbsolute(root.path) || path.resolve(root.path) !== root.path || !nonNegativeSafe(root.device) || !nonNegativeSafe(root.inode)
        || !["file", "directory"].includes(String(root.kind)) || !boundedString(root.mount, MAX_CONTROL_PATH_BYTES);
    })
    || manifest.filename !== SCAN_FILES_FILENAME
    || !nonNegativeSafe(manifest.entries)
    || !nonNegativeSafe(manifest.bytes)
    || !hash(manifest.sha256)
    || (stateRecord.inventoryComplete === false && (manifest.entries !== 0 || manifest.bytes !== 0))
    || inventory.filename !== "inventory-sensitive.json"
    || !nonNegativeSafe(inventory.bytes)
    || !hash(inventory.sha256)
    || !nonNegativeSafe(cursor.fileIndex)
    || Number(cursor.fileIndex) > Number(manifest.entries)
    || !["stream", "whole-file"].includes(String(cursor.phase))
    || !nonNegativeSafe(cursor.nextOffset)
    || (cursor.phase === "whole-file" && cursor.nextOffset !== 0)
    || (Number(cursor.fileIndex) === Number(manifest.entries) && (cursor.phase !== "stream" || cursor.nextOffset !== 0))
    || (progress.phase !== undefined && !["inventory", "stream", "whole-file", "finalizing"].includes(String(progress.phase)))
    || !nonNegativeSafe(progress.filesVisited)
    || !nonNegativeSafe(progress.filesScanned)
    || !nonNegativeSafe(progress.bytesScanned)
    || !nonNegativeSafe(progress.uniqueFindings)
    || !nonNegativeSafe(progress.occurrences)
    || !nonNegativeSafe(progress.scanErrors)
    || (progress.filesTotal !== undefined && !nonNegativeSafe(progress.filesTotal))
    || Number(progress.filesScanned) > Number(progress.filesVisited)
    || Number(progress.filesVisited) > Number(manifest.entries)
    || Number(progress.filesScanned) > Number(cursor.fileIndex)
    || (stateRecord.inventoryComplete === true && progress.filesTotal !== manifest.entries)
    || (stateRecord.inventoryComplete === false && (
      cursor.fileIndex !== 0
      || cursor.phase !== "stream"
      || cursor.nextOffset !== 0
      || progress.phase !== "inventory"
      || progress.filesVisited !== 0
      || progress.filesScanned !== 0
      || progress.bytesScanned !== 0
      || progress.uniqueFindings !== 0
      || progress.occurrences !== 0
    ))
    || (stateRecord.inventoryComplete === true && (
      Number(progress.filesVisited) < Number(cursor.fileIndex)
      || Number(progress.filesVisited) > Number(cursor.fileIndex) + (Number(cursor.fileIndex) < Number(manifest.entries) ? 1 : 0)
      || ((cursor.phase === "whole-file" || Number(cursor.nextOffset) > 0) && Number(progress.filesVisited) !== Number(cursor.fileIndex) + 1)
    ))
  ) throw new Error("scan state is invalid or does not match the requested output");
  return parsed as ScanState;
}

async function loadMiningInventory(
  output: string,
  expected: ScanState["inventory"],
  requiredStatus: "paused" | "complete" | "complete-with-errors",
  signal?: AbortSignal,
): Promise<SensitiveScanInventory> {
  const filename = safeJoin(output, expected.filename);
  await assertNoSymlinkComponents(output, filename);
  const data = await stableFileBytes(filename, MAX_SENSITIVE_INVENTORY_BYTES, signal);
  if (data.length !== expected.bytes || sha256Hex(data) !== expected.sha256) throw new Error("sensitive inventory does not match the resumable checkpoint");
  let parsed: unknown;
  try {
    parsed = JSON.parse(data.toString("utf8")) as unknown;
  } catch (error) {
    throw new Error("sensitive inventory is not valid JSON", { cause: error });
  }
  const document = record(parsed, "sensitive inventory");
  const findings = Array.isArray(document.findings) ? document.findings : [];
  const errors = Array.isArray(document.errors) ? document.errors : [];
  const inputRoots = Array.isArray(document.inputRoots) ? document.inputRoots : [];
  const checkpoint = record(document.resumeCheckpoint, "sensitive inventory resume checkpoint");
  const checkpointSemantic = record(checkpoint.semantic, "sensitive inventory checkpoint semantic options");
  const checkpointManifest = record(checkpoint.manifest, "sensitive inventory checkpoint manifest");
  const checkpointCursor = record(checkpoint.cursor, "sensitive inventory checkpoint cursor");
  const checkpointProgress = record(checkpoint.progress, "sensitive inventory checkpoint progress");
  const nonNegativeSafe = (value: unknown): boolean => Number.isSafeInteger(value) && Number(value) >= 0;
  const hash = (value: unknown): boolean => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
  if (
    document.version !== 1
    || document.tool !== "aark"
    || document.layer !== "mining"
    || document.outputRoot !== output
    || document.status !== requiredStatus
    || document.complete !== (requiredStatus === "complete" || requiredStatus === "complete-with-errors")
    || !boundedString(document.startedAt, 128)
    || !boundedString(document.updatedAt, 128)
    || !boundedString(document.finishedAt, 128)
    || (document.failureMessage !== undefined && (
      typeof document.failureMessage !== "string"
      || Buffer.byteLength(document.failureMessage) > MAX_RECORDED_ERROR_FIELD_BYTES
    ))
    || !Array.isArray(document.inputRoots)
    || inputRoots.length < 1
    || inputRoots.length > MAX_INPUT_ROOTS
    || inputRoots.some((entry) => !boundedString(entry, MAX_CONTROL_PATH_BYTES) || !path.isAbsolute(entry) || path.resolve(entry) !== entry)
    || new Set(inputRoots).size !== inputRoots.length
    || !Array.isArray(document.findings)
    || !Array.isArray(document.errors)
    || findings.length > MAX_UNIQUE_FINDINGS
    || errors.length > MAX_RECORDED_SCAN_ERRORS
    || !nonNegativeSafe(document.errorsOmitted)
    || typeof checkpoint.runId !== "string"
    || !UUID.test(checkpoint.runId)
    || checkpoint.status !== requiredStatus
    || typeof checkpoint.inventoryComplete !== "boolean"
    || !isBoundedJsonValue(checkpointSemantic)
    || !Array.isArray(checkpoint.inputRoots)
    || !isBoundedJsonValue(checkpoint.inputRoots)
    || checkpointManifest.filename !== SCAN_FILES_FILENAME
    || !nonNegativeSafe(checkpointManifest.entries)
    || !nonNegativeSafe(checkpointManifest.bytes)
    || !hash(checkpointManifest.sha256)
    || !nonNegativeSafe(checkpointCursor.fileIndex)
    || !["stream", "whole-file"].includes(String(checkpointCursor.phase))
    || !nonNegativeSafe(checkpointCursor.nextOffset)
    || (checkpointCursor.phase === "whole-file" && checkpointCursor.nextOffset !== 0)
    || (checkpointProgress.phase !== undefined && !["inventory", "stream", "whole-file", "finalizing"].includes(String(checkpointProgress.phase)))
    || !nonNegativeSafe(checkpointProgress.filesVisited)
    || !nonNegativeSafe(checkpointProgress.filesScanned)
    || !nonNegativeSafe(checkpointProgress.bytesScanned)
    || !nonNegativeSafe(checkpointProgress.uniqueFindings)
    || !nonNegativeSafe(checkpointProgress.occurrences)
    || !nonNegativeSafe(checkpointProgress.scanErrors)
    || (checkpointProgress.filesTotal !== undefined && !nonNegativeSafe(checkpointProgress.filesTotal))
  ) {
    throw new Error("sensitive inventory is not the required AARK mining checkpoint");
  }
  let occurrenceCount = 0;
  const findingKeys = new Set<string>();
  const occurrenceKeys = new Set<string>();
  for (let index = 0; index < findings.length; index += 1) {
    const finding = record(findings[index], "sensitive inventory finding");
    const validation = record(finding.validation, "sensitive inventory finding validation");
    const artifactFiles = Array.isArray(finding.artifactFiles) ? finding.artifactFiles : [];
    const artifactIntegrity = Array.isArray(finding.artifactIntegrity) ? finding.artifactIntegrity : [];
    const occurrences = Array.isArray(finding.occurrences) ? finding.occurrences : [];
    occurrenceCount += occurrences.length;
    if (!Number.isSafeInteger(occurrenceCount) || occurrenceCount > MAX_RECORDED_OCCURRENCES) {
      throw new Error("sensitive inventory contains too many finding occurrences");
    }
    if (
      finding.id !== index + 1
      || !isSafeDetectorIdentifier(finding.category)
      || !["authenticated", "high", "medium", "marker-only"].includes(String(finding.confidence))
      || !nonNegativeSafe(finding.bytes)
      || Number(finding.bytes) < 1
      || !hash(finding.sha256)
      || !isSafeDetectorIdentifier(validation.method)
      || typeof validation.checks !== "object"
      || validation.checks === null
      || Array.isArray(validation.checks)
      || !isBoundedJsonValue(validation.checks)
      || !Array.isArray(finding.artifactFiles)
      || artifactFiles.length > 17
      || artifactFiles.some((entry) => !boundedString(entry, MAX_ARTIFACT_RELATIVE_PATH_BYTES))
      || !Array.isArray(finding.artifactIntegrity)
      || artifactIntegrity.length > 17
      || artifactFiles.length !== artifactIntegrity.length
      || !Array.isArray(finding.occurrences)
      || occurrences.length < 1
      || (finding.sensitiveMetadata !== undefined && (
        typeof finding.sensitiveMetadata !== "object"
        || finding.sensitiveMetadata === null
        || Array.isArray(finding.sensitiveMetadata)
        || !isBoundedJsonValue(finding.sensitiveMetadata)
      ))
      || (finding.confidence === "marker-only" ? artifactFiles.length !== 0 : artifactFiles.length < 1)
    ) throw new Error("sensitive inventory contains an invalid finding");
    const findingKey = `${String(finding.category)}\0${String(finding.sha256)}`;
    if (findingKeys.has(findingKey)) throw new Error("sensitive inventory contains duplicate findings");
    findingKeys.add(findingKey);
    for (let artifactIndex = 0; artifactIndex < artifactIntegrity.length; artifactIndex += 1) {
      const entry = artifactIntegrity[artifactIndex];
      const integrity = record(entry, "sensitive inventory artifact integrity");
      if (
        !boundedString(integrity.path, MAX_ARTIFACT_RELATIVE_PATH_BYTES)
        || integrity.path !== artifactFiles[artifactIndex]
        || !nonNegativeSafe(integrity.bytes)
        || !hash(integrity.sha256)
      ) {
        throw new Error("sensitive inventory contains invalid artifact integrity metadata");
      }
    }
    if (finding.confidence !== "marker-only") {
      const primary = record(artifactIntegrity[0], "sensitive inventory primary artifact integrity");
      if (primary.bytes !== finding.bytes || primary.sha256 !== finding.sha256) {
        throw new Error("sensitive inventory primary artifact does not match its finding fingerprint");
      }
    }
    for (const entry of occurrences) {
      const occurrence = record(entry, "sensitive inventory occurrence");
      if (
        !boundedString(occurrence.sourcePath, MAX_CONTROL_PATH_BYTES)
        || !path.isAbsolute(occurrence.sourcePath)
        || path.resolve(occurrence.sourcePath) !== occurrence.sourcePath
        || !nonNegativeSafe(occurrence.offset)
        || occurrence.length !== finding.bytes
        || !["deleted-metadata", "unallocated-carve", "unallocated-stream", "shadow-copy", "residual-memory", "allocated-reference", "unknown"].includes(String(occurrence.provenance))
      ) throw new Error("sensitive inventory contains an invalid finding occurrence");
      const occurrenceKey = `${findingKey}\0${String(occurrence.sourcePath)}\0${String(occurrence.offset)}`;
      if (occurrenceKeys.has(occurrenceKey)) throw new Error("sensitive inventory contains duplicate finding occurrences");
      occurrenceKeys.add(occurrenceKey);
    }
  }
  for (const entry of errors) {
    const scanError = record(entry, "sensitive inventory scan error");
    if (
      typeof scanError.sourcePath !== "string"
      || Buffer.byteLength(scanError.sourcePath) > MAX_RECORDED_ERROR_FIELD_BYTES
      || typeof scanError.operation !== "string"
      || Buffer.byteLength(scanError.operation) > 256
      || typeof scanError.message !== "string"
      || Buffer.byteLength(scanError.message) > MAX_RECORDED_ERROR_FIELD_BYTES
    ) {
      throw new Error("sensitive inventory contains an invalid scan error");
    }
  }
  return parsed as SensitiveScanInventory;
}

export async function loadResumeInventory(output: string, expected: ScanState["inventory"], signal?: AbortSignal): Promise<SensitiveScanInventory> {
  return await loadMiningInventory(output, expected, "paused", signal);
}

export async function loadCompletedInventory(output: string, expected: ScanState["inventory"], signal?: AbortSignal): Promise<SensitiveScanInventory> {
  const inventory = await loadMiningInventory(output, expected, "complete", signal);
  if (inventory.errors.length !== 0 || inventory.errorsOmitted !== 0 || inventory.failureMessage !== undefined) {
    throw new Error("completed mining inventory contains errors or a failure message");
  }
  return inventory;
}

function exactCheckpointForState(state: ScanState): NonNullable<SensitiveScanInventory["resumeCheckpoint"]> {
  return {
    runId: state.runId,
    status: state.status,
    inventoryComplete: state.inventoryComplete,
    semantic: state.semantic,
    inputRoots: state.inputRoots,
    manifest: state.manifest,
    cursor: state.cursor,
    progress: state.progress,
  };
}

function occurrenceIsAuthorized(filename: string, roots: ScanState["inputRoots"]): boolean {
  return roots.some((root) => {
    if (root.kind === "file") return filename === root.path;
    const relative = path.relative(root.path, filename);
    return relative !== "" && relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
  });
}

export function assertExactCompletedInventory(inventory: SensitiveScanInventory, state: ScanState): void {
  const occurrences = inventory.findings.reduce((sum, finding) => sum + finding.occurrences.length, 0);
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
    || !isDeepStrictEqual(inventory.resumeCheckpoint, exactCheckpointForState(state))
    || inventory.findings.some((finding) => finding.occurrences.some((occurrence) => (
      occurrence.provenance !== state.semantic.provenance
      || !occurrenceIsAuthorized(occurrence.sourcePath, state.inputRoots)
    )))
  ) throw new Error("operation requires an exact error-free completed mining checkpoint");
}

export async function loadVerifiedCompletedInventory(
  output: string,
  state: ScanState,
  signal?: AbortSignal,
): Promise<SensitiveScanInventory> {
  const inventory = await loadCompletedInventory(output, state.inventory, signal);
  assertExactCompletedInventory(inventory, state);
  await verifyResumeArtifacts(output, inventory, signal);
  return inventory;
}

export async function loadTerminalInventory(output: string, state: ScanState, signal?: AbortSignal): Promise<SensitiveScanInventory> {
  if (state.status !== "complete" && state.status !== "complete-with-errors") {
    throw new Error("terminal mining inventory requires a completed scan state");
  }
  const inventory = await loadMiningInventory(output, state.inventory, state.status, signal);
  if (inventory.failureMessage !== undefined) throw new Error("terminal mining inventory contains a failure message");
  return inventory;
}

export async function verifyResumeArtifacts(output: string, inventory: SensitiveScanInventory, signal?: AbortSignal): Promise<void> {
  const artifactsRoot = safeJoin(output, "artifacts");
  await assertNoSymlinkComponents(output, artifactsRoot);
  const expectedDirectories = new Set<string>();
  for (const finding of inventory.findings) {
    assertNotAborted(signal, "resume artifact verification");
    const directoryName = `finding-${String(finding.id).padStart(6, "0")}`;
    if (finding.artifactFiles.length > 0) expectedDirectories.add(directoryName);
    if (finding.artifactFiles.length !== finding.artifactIntegrity.length) throw new Error("resume inventory artifact metadata is incomplete");
    const expectedFiles = new Set(finding.artifactIntegrity.map((integrity) => path.basename(integrity.path)));
    if (expectedFiles.size !== finding.artifactIntegrity.length) throw new Error("resume inventory contains duplicate artifact filenames");
    for (const integrity of finding.artifactIntegrity) {
      assertNotAborted(signal, "resume artifact verification");
      if (!finding.artifactFiles.includes(integrity.path) || path.dirname(integrity.path) !== path.join("artifacts", directoryName)) {
        throw new Error("resume inventory contains an invalid artifact path");
      }
      const filename = safeJoin(output, integrity.path);
      await assertNoSymlinkComponents(output, filename);
      const actual = await stableFileIntegrity(filename, 256 * 1024 * 1024, signal);
      if (actual.bytes !== integrity.bytes || actual.sha256 !== integrity.sha256) throw new Error("resume artifact does not match its recorded integrity metadata");
    }
    if (expectedFiles.size > 0) {
      const actualFiles = await readDirectoryNamesBounded(safeJoin(artifactsRoot, directoryName), 18);
      if (actualFiles.length !== expectedFiles.size || actualFiles.some((entry) => !expectedFiles.has(entry))) {
        throw new Error("resume artifact directory contains unexpected or missing files");
      }
    }
  }
  const actualDirectories = await readDirectoryNamesBounded(artifactsRoot, MAX_UNIQUE_FINDINGS + 1);
  if (actualDirectories.some((entry) => !expectedDirectories.has(entry)) || actualDirectories.length !== expectedDirectories.size) {
    throw new Error("resume artifact tree contains unexpected or missing directories");
  }
}

export function newScanState(
  semantic: ScanSemanticOptions,
  operational: ScanOperationalOptions,
  manifest: ScanState["manifest"],
  inventory: ScanState["inventory"],
  progress: MiningProgress,
  inputRoots: ScanState["inputRoots"],
): ScanState {
  const now = new Date().toISOString();
  return {
    version: 1,
    tool: "aark",
    layer: "mining-resume",
    runId: randomUUID(),
    status: "in-progress",
    resumable: false,
    inventoryComplete: true,
    startedAt: now,
    updatedAt: now,
    semantic,
    operational,
    inputRoots,
    manifest,
    inventory,
    cursor: { fileIndex: 0, phase: "stream", nextOffset: 0 },
    progress: { ...progress },
  };
}
