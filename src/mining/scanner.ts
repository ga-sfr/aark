import { constants } from "node:fs";
import { lstat, open, readdir, realpath } from "node:fs/promises";
import path from "node:path";
import type { Candidate } from "../core/types.js";
import { acquireExclusiveLock, nearestExistingParent, walkRegularFiles } from "../core/fs-safe.js";
import type { WalkedFile } from "../core/fs-safe.js";
import { filesystemIsNetwork, mountForPathFrom, mountIsNetworkBacked, mounts } from "../core/mounts.js";
import type { MountRecord } from "../core/mounts.js";
import { ArtifactStore } from "./artifacts.js";
import { detectCryptographicKeys, detectDeepKeySchedules } from "./detectors/keys.js";
import { detectConfigurationSecrets } from "./detectors/config-secrets.js";
import { detectProviderCredentials } from "./detectors/providers.js";
import { detectStructuredArtifacts } from "./detectors/structured.js";
import type { DetectionContext, Detector } from "./detectors/types.js";
import { detectWalletSecrets } from "./detectors/wallets.js";
import type { MiningOptions, MiningProgress } from "./types.js";
import { MAX_DPAPI_BLOB_BYTES } from "./validators/dpapi.js";

const STREAM_DETECTORS: Array<{ name: string; detector: Detector }> = [
  { name: "cryptographic-keys", detector: detectCryptographicKeys },
  { name: "configuration-secrets", detector: detectConfigurationSecrets },
  { name: "wallet-secrets", detector: detectWalletSecrets },
  { name: "provider-credentials", detector: detectProviderCredentials },
];
const MINIMUM_SAFE_OVERLAP = MAX_DPAPI_BLOB_BYTES + 1024 * 1024;
const DEEP_SCAN_SLICE_BYTES = 1024 * 1024;
const DEEP_SCAN_OVERLAP_BYTES = 256;

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

class ArtifactWriteError extends Error {
  public override readonly name = "ArtifactWriteError";
}

class ScanControlError extends Error {
  public override readonly name = "ScanControlError";
}

function inside(parent: string, child: string): boolean {
  const relative = path.relative(path.resolve(parent), path.resolve(child));
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function interrupted(signal: AbortSignal | undefined): boolean {
  return signal?.aborted === true;
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

async function assertInputRootsCurrent(expected: PathSafetySnapshot[]): Promise<MountRecord[]> {
  const records = await mounts();
  for (const snapshot of expected) {
    const current = await pathSafetySnapshot(snapshot.path, records);
    if (
      current.device !== snapshot.device
      || current.inode !== snapshot.inode
      || current.kind !== snapshot.kind
      || current.mount !== snapshot.mount
    ) throw new Error("a mining input root or its mount changed after preflight");
  }
  return records;
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
    if ((await readdir(output)).length !== 0) throw new Error("mining output directory must be new or empty");
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
    const canonicalInput = input.path;
    if (input.directory && inside(canonicalInput, canonicalOutput)) throw new Error("mining output cannot be inside a scanned input directory");
    if (canonicalInput === canonicalOutput) throw new Error("mining output cannot be an input");
  }

  const deduplicated = canonicalInputs.filter((candidate, index, all) =>
    all.findIndex((item) => item.path === candidate.path) === index
    && !all.some((parent) => parent.directory && parent.path !== candidate.path && inside(parent.path, candidate.path)));
  return { inputs: deduplicated.map((item) => item.path), output: canonicalOutput };
}

async function assertLockedFreshOutput(output: string): Promise<void> {
  const metadata = await lstat(output);
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) throw new Error("locked mining output must remain a real directory");
  if (await realpath(output) !== output) throw new Error("mining output canonical path changed while its lock was acquired");
  const entries = await readdir(output);
  if (entries.length !== 1 || entries[0] !== ".agetnic-mining.lock") {
    throw new Error("mining output changed between emptiness validation and exclusive lock acquisition");
  }
  const lock = await lstat(path.join(output, ".agetnic-mining.lock"));
  if (lock.isSymbolicLink() || !lock.isFile()) throw new Error("mining output lock is not a regular file");
}

async function runDetectors(
  data: Buffer,
  context: DetectionContext,
  sourcePath: string,
  options: MiningOptions,
  store: ArtifactStore,
  detectors: Array<{ name: string; detector: Detector }>,
): Promise<boolean> {
  let clean = true;
  for (const { name, detector } of detectors) {
    let candidates: Candidate[];
    try {
      candidates = detector(data, context);
    } catch (error) {
      store.recordError(sourcePath, `detector:${name}`, error);
      clean = false;
      continue;
    }
    for (const candidate of candidates) {
      try {
        const relativeOffset = candidate.offset - context.baseOffset;
        const candidateEnd = relativeOffset + candidate.length;
        if (
          !Number.isSafeInteger(relativeOffset)
          || relativeOffset < 0
          || !Number.isSafeInteger(candidate.length)
          || candidate.length < 1
          || !Number.isSafeInteger(candidateEnd)
          || candidateEnd > data.length
        ) {
          throw new Error("validator returned a candidate outside the scanned window");
        }
        if (!data.subarray(relativeOffset, candidateEnd).equals(candidate.value)) {
          throw new Error("validator candidate bytes do not match its recorded source offset");
        }
        await store.add(sourcePath, options.provenance, candidate);
      } catch (error) {
        store.recordError(sourcePath, `artifact:${name}`, error);
        throw new ArtifactWriteError("could not safely persist a recovered artifact", { cause: error });
      }
    }
  }
  return clean;
}

async function runDeepKeyScheduleSlices(
  data: Buffer,
  context: DetectionContext,
  sourcePath: string,
  options: MiningOptions,
  store: ArtifactStore,
): Promise<boolean> {
  let clean = true;
  let primaryStart = 0;
  while (primaryStart < data.length) {
    if (options.signal?.aborted === true) throw new Error("scan interrupted");
    const start = primaryStart === 0 ? 0 : primaryStart - DEEP_SCAN_OVERLAP_BYTES;
    const end = Math.min(primaryStart + DEEP_SCAN_SLICE_BYTES, data.length);
    const slice = data.subarray(start, end);
    clean = await runDetectors(
      slice,
      { ...context, baseOffset: context.baseOffset + start, deepKeySchedules: true },
      sourcePath,
      options,
      store,
      [{ name: "deep-key-schedules", detector: detectDeepKeySchedules }],
    ) && clean;
    primaryStart = end;
    if (primaryStart === data.length) break;
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
  return clean;
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

async function scanStream(
  file: WalkedFile,
  options: MiningOptions,
  store: ArtifactStore,
  onChunk: (bytes: number) => Promise<void>,
): Promise<{ file: WalkedFile; detectorsClean: boolean }> {
  const filename = file.path;
  let tail = Buffer.alloc(0);
  let consumed = 0;
  let detectorsClean = true;
  const handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat();
    if (
      !before.isFile()
      || before.dev !== file.device
      || before.ino !== file.inode
      || before.size !== file.bytes
      || before.mtimeMs !== file.modifiedMs
      || before.ctimeMs !== file.changedMs
      || !Number.isSafeInteger(before.size)
      || before.size < 0
    ) throw new Error("scan input changed after directory enumeration");
    await assertOpenedFilePathCurrent(filename, handle, before);
    const stream = handle.createReadStream({
      autoClose: false,
      highWaterMark: options.chunkBytes,
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
    for await (const item of stream) {
      if (options.signal?.aborted === true) throw new Error("scan interrupted");
      const chunk = Buffer.isBuffer(item) ? item : Buffer.from(item);
      const data = tail.length === 0 ? chunk : Buffer.concat([tail, chunk]);
      const baseOffset = consumed - tail.length;
      const context = { sourcePath: filename, baseOffset, wholeFile: false, deepKeySchedules: false };
      detectorsClean = await runDetectors(data, context, filename, options, store, STREAM_DETECTORS) && detectorsClean;
      if (options.deepKeySchedules === true) detectorsClean = await runDeepKeyScheduleSlices(data, context, filename, options, store) && detectorsClean;
      consumed += chunk.length;
      await onChunk(chunk.length);
      tail = data.length <= options.overlapBytes ? Buffer.from(data) : Buffer.from(data.subarray(data.length - options.overlapBytes));
    }
    const after = await handle.stat();
    if (
      consumed !== before.size
      || before.dev !== after.dev
      || before.ino !== after.ino
      || before.size !== after.size
      || before.mtimeMs !== after.mtimeMs
      || before.ctimeMs !== after.ctimeMs
    ) throw new Error("scan input changed during streaming validation");
    await assertOpenedFilePathCurrent(filename, handle, after);
    return {
      file: {
        path: filename,
        bytes: before.size,
        device: before.dev,
        inode: before.ino,
        modifiedMs: before.mtimeMs,
        changedMs: before.ctimeMs,
      },
      detectorsClean,
    };
  } finally {
    await handle.close();
  }
}

async function readWholeFileBounded(file: WalkedFile, maximumBytes: number): Promise<Buffer | null> {
  const filename = file.path;
  const handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat();
    if (
      !before.isFile()
      || before.dev !== file.device
      || before.ino !== file.inode
      || before.size !== file.bytes
      || before.mtimeMs !== file.modifiedMs
      || before.ctimeMs !== file.changedMs
    ) throw new Error("scan input changed between streaming and whole-file validation");
    await assertOpenedFilePathCurrent(filename, handle, before);
    if (before.size > maximumBytes) return null;
    const data = Buffer.allocUnsafe(before.size);
    let consumed = 0;
    while (consumed < data.length) {
      const result = await handle.read(data, consumed, data.length - consumed, consumed);
      if (result.bytesRead === 0) break;
      consumed += result.bytesRead;
    }
    const probe = Buffer.allocUnsafe(1);
    const extra = await handle.read(probe, 0, 1, consumed);
    const after = await handle.stat();
    if (
      consumed !== before.size
      || extra.bytesRead !== 0
      || after.dev !== before.dev
      || after.ino !== before.ino
      || after.size !== before.size
      || after.mtimeMs !== before.mtimeMs
      || after.ctimeMs !== before.ctimeMs
    ) {
      throw new Error("scan input changed during whole-file validation");
    }
    await assertOpenedFilePathCurrent(filename, handle, after);
    return data;
  } finally {
    await handle.close();
  }
}

function validatedOptions(input: MiningOptions): MiningOptions {
  const options = {
    ...input,
    inputs: input.inputs.map((value) => path.resolve(value)),
    output: path.resolve(input.output),
  };
  if (options.inputs.length === 0) throw new Error("at least one mining input is required");
  for (const [label, value] of [["chunkBytes", options.chunkBytes], ["overlapBytes", options.overlapBytes], ["wholeFileBytes", options.wholeFileBytes]] as const) {
    if (!Number.isSafeInteger(value) || value < 1) throw new Error(`${label} must be a positive integer`);
  }
  if (options.chunkBytes < MINIMUM_SAFE_OVERLAP || options.chunkBytes > 128 * 1024 * 1024) throw new Error("chunkBytes must be between 17 MiB and 128 MiB");
  if (options.overlapBytes < MINIMUM_SAFE_OVERLAP || options.overlapBytes > options.chunkBytes) throw new Error("overlapBytes must be between 17 MiB and chunkBytes so every supported streaming format can cross a chunk boundary");
  if (options.wholeFileBytes > 256 * 1024 * 1024) throw new Error("wholeFileBytes must not exceed 256 MiB");
  return options;
}

export async function scanSensitiveMaterial(input: MiningOptions): Promise<Record<string, unknown>> {
  const validated = validatedOptions(input);
  const canonical = await assertFreshSafeOutput(validated.inputs, validated.output);
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
  for (const inputRoot of canonical.inputs) {
    const inputMount = mountForPathFrom(mountSnapshot, inputRoot);
    if (inputMount === undefined) throw new Error("could not determine the mount backing a mining input");
    if (await isNetworkMount(inputMount)) throw new Error("network-mounted mining inputs are not allowed");
    inputSafety.push(await pathSafetySnapshot(inputRoot, mountSnapshot));
  }
  const outputMount = mountForPathFrom(mountSnapshot, await nearestExistingParent(canonical.output));
  if (outputMount === undefined) throw new Error("could not determine the mount backing the mining output");
  if (await isNetworkMount(outputMount)) throw new Error("network-mounted mining outputs are not allowed");
  if (path.resolve(outputMount.target) === canonical.output) {
    throw new Error("mining output must be a dedicated subdirectory, not a filesystem mount root");
  }
  const options = { ...validated, ...canonical };
  const lock = await acquireExclusiveLock(options.output, ".agetnic-mining.lock");
  let runFailure: unknown;
  try {
  await assertLockedFreshOutput(options.output);
  const outputSafety = await outputSafetySnapshot(options.output, lock.path);
  const assertSafeOutput = async (): Promise<void> => assertOutputSafetyCurrent(outputSafety, lock.path);
  const store = new ArtifactStore(options.output, options.inputs, options.deepKeySchedules === true, assertSafeOutput);
  await store.initialize();
  const progress: MiningProgress = { filesVisited: 0, filesScanned: 0, bytesScanned: 0, uniqueFindings: 0, occurrences: 0, scanErrors: 0 };
  let lastCheckpoint = Date.now();
  const publishProgress = (): void => {
    try {
      options.progress?.({ ...progress });
    } catch (error) {
      throw new ScanControlError("progress callback failed", { cause: error });
    }
  };
  const checkpoint = async (): Promise<void> => {
    try {
      await store.checkpoint(progress);
    } catch (error) {
      throw new ScanControlError("could not persist the mining checkpoint", { cause: error });
    }
  };
  const updateProgress = async (bytes: number): Promise<void> => {
    try {
      await assertSafeOutput();
    } catch (error) {
      throw new ScanControlError("mining output safety changed during scanning", { cause: error });
    }
    progress.bytesScanned += bytes;
    Object.assign(progress, store.counts());
    publishProgress();
    if (Date.now() - lastCheckpoint >= 60_000) {
      await checkpoint();
      lastCheckpoint = Date.now();
    }
  };

  try {
    if (interrupted(options.signal)) throw new Error("scan interrupted");
    for await (const file of walkRegularFiles(options.inputs, {
      onError: (sourcePath, error) => store.recordError(sourcePath, "walk-entry", error),
      shouldEnterDirectory: async (directory) => {
        const currentMounts = await mounts();
        const mounted = mountForPathFrom(currentMounts, directory);
        return mounted !== undefined && !(await isNetworkMount(mounted));
      },
    })) {
      if (interrupted(options.signal)) throw new Error("scan interrupted");
      const currentMounts = await assertInputRootsCurrent(inputSafety);
      const fileMount = mountForPathFrom(currentMounts, file.path);
      if (fileMount === undefined || await isNetworkMount(fileMount)) {
        store.recordError(file.path, "walk-entry", new Error("refusing to scan a network-mounted file"));
        continue;
      }
      progress.filesVisited += 1;
      let completelyScanned = false;
      try {
        const streamed = await scanStream(file, options, store, updateProgress);
        let detectorsClean = streamed.detectorsClean;
        if (file.bytes <= options.wholeFileBytes) {
          const data = await readWholeFileBounded(streamed.file, options.wholeFileBytes);
          if (data !== null) {
            detectorsClean = await runDetectors(
              data,
              { sourcePath: file.path, baseOffset: 0, wholeFile: true, deepKeySchedules: options.deepKeySchedules === true },
              file.path,
              options,
              store,
              [{ name: "structured-artifacts", detector: detectStructuredArtifacts }],
            ) && detectorsClean;
          }
        }
        completelyScanned = detectorsClean;
      } catch (error) {
        if (error instanceof ArtifactWriteError || error instanceof ScanControlError) throw error;
        if (interrupted(options.signal)) throw error;
        store.recordError(file.path, "read-or-scan", error);
      }
      if (completelyScanned) progress.filesScanned += 1;
      Object.assign(progress, store.counts());
      publishProgress();
      if (progress.filesVisited % 25 === 0) {
        await checkpoint();
        lastCheckpoint = Date.now();
      }
    }
    if (interrupted(options.signal)) throw new Error("scan interrupted");
    try {
      await assertInputRootsCurrent(inputSafety);
    } catch (error) {
      store.recordError("<inputs>", "final-input-safety", error);
    }
    await assertSafeOutput();
  } catch (error) {
    store.recordError("<scan>", "scan-run", error);
    Object.assign(progress, store.counts());
    const status = interrupted(options.signal) ? "interrupted" : "failed";
    try {
      await store.finalize(status, progress, error instanceof Error ? error.message : String(error));
    } catch (reportError) {
      throw new AggregateError([error, reportError], "scan failed and final report generation also failed");
    }
    throw error;
  }

  Object.assign(progress, store.counts());
  const status = progress.scanErrors === 0 ? "complete" : "complete-with-errors";
  try {
    await store.finalize(status, progress);
  } catch (error) {
    store.recordError("<scan>", "finalize", error);
    Object.assign(progress, store.counts());
    try {
      await store.finalize("failed", progress, error instanceof Error ? error.message : String(error));
    } catch (reportError) {
      throw new AggregateError([error, reportError], "scan completion failed and its final failure report could not be fully written");
    }
    throw error;
  }
  return {
    status,
    complete: true,
    allFilesScannedWithoutErrors: status === "complete",
    filesVisited: progress.filesVisited,
    filesScanned: progress.filesScanned,
    bytesScanned: progress.bytesScanned,
    uniqueFindings: progress.uniqueFindings,
    occurrences: progress.occurrences,
    scanErrors: progress.scanErrors,
    deepKeySchedules: options.deepKeySchedules === true,
    valuesPrinted: false,
    reports: {
      sensitive: "final-report-sensitive.md",
      redacted: "final-report-redacted.md",
    },
  };
  } catch (error) {
    runFailure = error;
    throw error;
  } finally {
    try {
      await lock.release();
    } catch (releaseError) {
      if (runFailure !== undefined) throw new AggregateError([runFailure, releaseError], "scan failed and its exclusive output lock could not be released");
      throw releaseError;
    }
  }
}
