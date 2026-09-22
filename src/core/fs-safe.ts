import { createHash, randomUUID } from "node:crypto";
import type { BigIntStats } from "node:fs";
import { constants, open, opendir, rename, stat, lstat, chmod, mkdir, unlink } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import path from "node:path";

export type FilesystemIdentity = number | string;

export interface StableStat {
  raw: BigIntStats;
  device: FilesystemIdentity;
  inode: FilesystemIdentity;
  bytes: number;
  modifiedMs: number;
  changedMs: number;
}

function identityValue(value: bigint): FilesystemIdentity {
  if (value < 0n) throw new Error("filesystem identity is negative");
  const numeric = Number(value);
  return Number.isSafeInteger(numeric) ? numeric : value.toString(10);
}

function stableStat(raw: BigIntStats): StableStat {
  const bytes = Number(raw.size);
  const modifiedMs = Number(raw.mtimeNs) / 1_000_000;
  const changedMs = Number(raw.ctimeNs) / 1_000_000;
  if (!Number.isSafeInteger(bytes) || bytes < 0 || !Number.isFinite(modifiedMs) || !Number.isFinite(changedMs)) {
    throw new Error("filesystem metadata is outside supported numeric bounds");
  }
  return {
    raw,
    device: identityValue(raw.dev),
    inode: identityValue(raw.ino),
    bytes,
    modifiedMs,
    changedMs,
  };
}

export async function stableLstat(filename: string): Promise<StableStat> {
  return stableStat(await lstat(filename, { bigint: true }));
}

export async function stableHandleStat(handle: FileHandle): Promise<StableStat> {
  return stableStat(await handle.stat({ bigint: true }));
}

// exFAT can change the directory-entry-based identity on rename. Keep the
// original handle open and compare the destination against that live handle,
// never merely against size or a newly reopened destination.
export async function renameWithHeldIdentity(source: string, destination: string, expected: StableStat): Promise<StableStat> {
  const handle = await open(source, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = await stableHandleStat(handle);
    const current = await stableLstat(source);
    for (const entry of [opened, current]) {
      if (entry.raw.isSymbolicLink() || entry.device !== expected.device || entry.inode !== expected.inode
        || entry.bytes !== expected.bytes || entry.modifiedMs !== expected.modifiedMs || entry.changedMs !== expected.changedMs
        || entry.raw.mode !== expected.raw.mode || entry.raw.nlink !== expected.raw.nlink) {
        throw new Error("protected rename source changed before moving");
      }
    }
    await rename(source, destination);
    const live = await stableHandleStat(handle);
    const moved = await stableLstat(destination);
    if (moved.raw.isSymbolicLink() || moved.device !== live.device || moved.inode !== live.inode
      || moved.bytes !== live.bytes || moved.modifiedMs !== live.modifiedMs || moved.changedMs !== live.changedMs
      || moved.bytes !== expected.bytes || moved.modifiedMs !== expected.modifiedMs
      || moved.raw.mode !== expected.raw.mode || moved.raw.nlink !== expected.raw.nlink
      || moved.raw.isDirectory() !== expected.raw.isDirectory() || moved.raw.isFile() !== expected.raw.isFile()
      || (process.platform !== "win32" && (moved.device !== expected.device || moved.inode !== expected.inode))) {
      throw new Error("protected rename destination does not match the original live handle");
    }
    return moved;
  } finally { await handle.close(); }
}

async function verifyPublishedFile(filename: string, expectedBytes: number, expectedSha256: string): Promise<void> {
  const handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await stableHandleStat(handle);
    const currentBefore = await stableLstat(filename);
    if (
      !before.raw.isFile()
      || before.raw.nlink !== 1n
      || before.device !== currentBefore.device
      || before.inode !== currentBefore.inode
      || before.bytes !== expectedBytes
    ) throw new Error("published output is not the expected stable regular file");
    const digest = createHash("sha256");
    const buffer = Buffer.allocUnsafe(Math.min(1024 * 1024, Math.max(1, expectedBytes)));
    let consumed = 0;
    while (consumed < expectedBytes) {
      const result = await handle.read(buffer, 0, Math.min(buffer.length, expectedBytes - consumed), consumed);
      if (result.bytesRead === 0) break;
      digest.update(buffer.subarray(0, result.bytesRead));
      consumed += result.bytesRead;
    }
    const extra = await handle.read(buffer, 0, 1, consumed);
    const after = await stableHandleStat(handle);
    const currentAfter = await stableLstat(filename);
    if (
      consumed !== expectedBytes
      || extra.bytesRead !== 0
      || digest.digest("hex") !== expectedSha256
      || before.device !== after.device
      || before.inode !== after.inode
      || before.bytes !== after.bytes
      || before.modifiedMs !== after.modifiedMs
      || before.changedMs !== after.changedMs
      || after.device !== currentAfter.device
      || after.inode !== currentAfter.inode
      || after.bytes !== currentAfter.bytes
      || after.modifiedMs !== currentAfter.modifiedMs
      || after.changedMs !== currentAfter.changedMs
    ) throw new Error("published output changed during verification");
  } finally {
    await handle.close();
  }
}

export interface WalkedFile {
  path: string;
  bytes: number;
  device: FilesystemIdentity;
  inode: FilesystemIdentity;
  modifiedMs: number;
  changedMs: number;
}

export interface WalkOptions {
  onError?: (input: string, error: unknown) => void;
  shouldEnterDirectory?: (input: string) => boolean | Promise<boolean>;
  signal?: AbortSignal;
  maximumDirectoryEntries?: number;
  maximumPendingEntries?: number;
  maximumDirectories?: number;
}

export const MAX_WALK_DIRECTORY_ENTRIES = 100_000;
export const MAX_WALK_PENDING_ENTRIES = 100_000;
export const MAX_WALK_DIRECTORIES = 100_000;

export interface ExclusiveLock {
  path: string;
  assertHeld: () => Promise<void>;
  release: () => Promise<void>;
}

function bytewiseLexical(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function unsupportedModeOperation(error: unknown): boolean {
  const code = error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
  return code === "ENOSYS" || code === "EOPNOTSUPP" || code === "ENOTSUP";
}

export async function ensurePrivateDirectory(directory: string): Promise<void> {
  const resolved = path.resolve(directory);
  const filesystemRoot = path.parse(resolved).root;
  await assertNoSymlinkComponents(filesystemRoot, resolved);
  await mkdir(resolved, { recursive: true, mode: 0o700 });
  await assertNoSymlinkComponents(filesystemRoot, resolved);
  const metadata = await lstat(resolved);
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) throw new Error("private output directory must be a real directory, not a symbolic link");
  try {
    await chmod(resolved, 0o700);
  } catch (error) {
    if (!unsupportedModeOperation(error)) throw error;
    // Some non-Unix filesystems do not implement mode changes; reports warn when mode enforcement is unknown.
  }
}

export async function syncDirectory(directory: string): Promise<void> {
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    handle = await open(directory, constants.O_RDONLY);
    await handle.sync();
  } catch (error) {
    const code = error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
    if (
      code !== "EINVAL"
      && code !== "EOPNOTSUPP"
      && code !== "ENOTSUP"
      && code !== "ENOSYS"
      && !(process.platform === "win32" && code === "EPERM")
    ) throw error;
    // Directory fsync is not implemented by every destination filesystem.
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

export async function acquireExclusiveLock(directory: string, filename: string): Promise<ExclusiveLock> {
  if (filename !== path.basename(filename) || !/^\.[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(filename)) {
    throw new Error("lock filename must be a safe hidden basename");
  }
  const root = path.resolve(directory);
  await ensurePrivateDirectory(root);
  const lockPath = safeJoin(root, filename);
  await assertNoSymlinkComponents(root, lockPath);
  let handle: Awaited<ReturnType<typeof open>>;
  try {
    handle = await open(lockPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  } catch (error) {
    const code = error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
    if (code === "EEXIST") throw new Error("an exclusive operation lock already exists; another process may be active or a prior process may have stopped abruptly", { cause: error });
    throw error;
  }
  let openedLock: StableStat;
  try {
    openedLock = await stableHandleStat(handle);
  } catch (error) {
    await handle.close().catch(() => undefined);
    throw error;
  }
  if (!openedLock.raw.isFile() || openedLock.raw.nlink !== 1n) {
    await handle.close().catch(() => undefined);
    try {
      const current = await stableLstat(lockPath);
      if (current.device === openedLock.device && current.inode === openedLock.inode) {
        await unlink(lockPath);
        await syncDirectory(root).catch(() => undefined);
      }
    } catch {
      // Missing or substituted lock paths are not safe cleanup targets.
    }
    throw new Error("exclusive lock must be a single-link regular file");
  }
  try {
    await handle.writeFile(`${JSON.stringify({ pid: process.pid, startedAt: new Date().toISOString() })}\n`);
    await handle.sync();
    await syncDirectory(root);
  } catch (error) {
    await handle.close().catch(() => undefined);
    const removed = await stableLstat(lockPath).then(async (current) => {
      if (current.device !== openedLock.device || current.inode !== openedLock.inode) return false;
      await unlink(lockPath);
      return true;
    }, () => false).catch(() => false);
    if (removed) await syncDirectory(root).catch(() => undefined);
    throw error;
  }

  let released = false;
  const assertHeld = async (): Promise<void> => {
    if (released) throw new Error("exclusive lock was already released");
    let opened: StableStat;
    let current: StableStat;
    try {
      opened = await stableHandleStat(handle);
      current = await stableLstat(lockPath);
    } catch (error) {
      throw new Error("exclusive lock path is no longer verifiable", { cause: error });
    }
    if (
      opened.device !== current.device
      || opened.inode !== current.inode
      || opened.raw.nlink !== 1n
      || current.raw.nlink !== 1n
      || !current.raw.isFile()
      || current.raw.isSymbolicLink()
    ) {
      throw new Error("exclusive lock path changed while the operation was running");
    }
  };
  return {
    path: lockPath,
    assertHeld,
    release: async (): Promise<void> => {
      if (released) return;
      try {
        await assertHeld();
      } catch (error) {
        await handle.close().catch(() => undefined);
        throw error;
      }
      let releaseError: unknown;
      try {
        await unlink(lockPath);
        released = true;
        await syncDirectory(root);
      } catch (error) {
        releaseError = error;
      }
      try {
        await handle.close();
      } catch (error) {
        releaseError ??= error;
      }
      if (releaseError !== undefined) throw releaseError;
    },
  };
}

export async function atomicWriteFile(destination: string, data: Uint8Array | string, mode = 0o600): Promise<void> {
  const parent = path.dirname(destination);
  await ensurePrivateDirectory(parent);
  await assertNoSymlinkComponents(parent, destination);
  let priorDestination: StableStat | undefined;
  try {
    const existing = await stableLstat(destination);
    if (existing.raw.isSymbolicLink() || !existing.raw.isFile() || existing.raw.nlink !== 1n) {
      throw new Error("atomic output destination must remain a single-link regular file");
    }
    priorDestination = existing;
  } catch (error) {
    const code = error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
    if (code !== "ENOENT") throw error;
  }
  const assertDestinationUnchanged = async (): Promise<void> => {
    try {
      const current = await stableLstat(destination);
      if (
        priorDestination === undefined
        || current.raw.isSymbolicLink()
        || !current.raw.isFile()
        || current.raw.nlink !== 1n
        || current.device !== priorDestination.device
        || current.inode !== priorDestination.inode
        || current.bytes !== priorDestination.bytes
        || current.modifiedMs !== priorDestination.modifiedMs
        || current.changedMs !== priorDestination.changedMs
      ) throw new Error("atomic output destination changed before publication");
    } catch (error) {
      const code = error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
      if (code === "ENOENT" && priorDestination === undefined) return;
      throw error;
    }
  };
  const temporary = `${destination}.tmp-${process.pid}-${randomUUID()}`;
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  let identity: { device: FilesystemIdentity; inode: FilesystemIdentity } | undefined;
  let renamed = false;
  try {
    handle = await open(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, mode);
    const opened = await handle.stat();
    const openedStable = await stableHandleStat(handle);
    identity = { device: openedStable.device, inode: openedStable.inode };
    if (!opened.isFile() || opened.nlink !== 1) throw new Error("atomic temporary output must be a single-link regular file");
    await handle.writeFile(data);
    try {
      await handle.chmod(mode);
    } catch (error) {
      if (!unsupportedModeOperation(error)) throw error;
      // Non-Unix destination filesystems may not implement chmod; the manifest warns about mode enforcement.
    }
    await handle.sync();
    const currentTemporary = await stableLstat(temporary);
    if (
      currentTemporary.raw.isSymbolicLink()
      || !currentTemporary.raw.isFile()
      || currentTemporary.raw.nlink !== 1n
      || currentTemporary.device !== identity.device
      || currentTemporary.inode !== identity.inode
    ) throw new Error("atomic temporary output path changed before publication");
    await assertDestinationUnchanged();
    const expectedBytes = typeof data === "string" ? Buffer.byteLength(data) : data.byteLength;
    const expectedSha256 = createHash("sha256").update(data).digest("hex");
    if (process.platform === "win32") {
      await handle?.close();
      handle = undefined;
    }
    await rename(temporary, destination);
    renamed = true;
    if (process.platform === "win32") {
      await verifyPublishedFile(destination, expectedBytes, expectedSha256);
    } else {
      const currentDestination = await stableLstat(destination);
      if (
        currentDestination.raw.isSymbolicLink()
        || !currentDestination.raw.isFile()
        || currentDestination.raw.nlink !== 1n
        || currentDestination.device !== identity.device
        || currentDestination.inode !== identity.inode
      ) throw new Error("atomic output path changed during publication");
      await handle?.close();
      handle = undefined;
    }
    await syncDirectory(parent);
  } finally {
    await handle?.close().catch(() => undefined);
    if (!renamed && identity !== undefined) {
      try {
        const current = await stableLstat(temporary);
        if (current.device === identity.device && current.inode === identity.inode) await unlink(temporary);
      } catch {
        // Missing or substituted temporary paths are not safe cleanup targets.
      }
    }
  }
}

export async function atomicWriteJson(destination: string, value: unknown, mode = 0o600): Promise<void> {
  await atomicWriteFile(destination, `${JSON.stringify(value, null, 2)}\n`, mode);
}

export function safeJoin(root: string, ...parts: string[]): string {
  const resolvedRoot = path.resolve(root);
  const result = path.resolve(resolvedRoot, ...parts);
  const relative = path.relative(resolvedRoot, result);
  if (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error("refusing path traversal outside output root");
  }
  return result;
}

export async function assertNoSymlinkComponents(root: string, target: string): Promise<void> {
  const resolvedRoot = path.resolve(root);
  const resolvedTarget = safeJoin(resolvedRoot, path.relative(resolvedRoot, path.resolve(target)));
  const relative = path.relative(resolvedRoot, resolvedTarget);
  const components = relative === "" ? [] : relative.split(path.sep);
  let cursor = resolvedRoot;
  for (let index = -1; index < components.length; index += 1) {
    if (index >= 0) cursor = path.join(cursor, components[index] ?? "");
    try {
      const metadata = await lstat(cursor);
      if (metadata.isSymbolicLink()) throw new Error("a symbolic-link output component is not allowed");
      if (index < components.length - 1 && !metadata.isDirectory()) throw new Error("a non-directory output component blocks the target path");
    } catch (error) {
      const code = error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
      if (code === "ENOENT") return;
      throw error;
    }
  }
}

export async function nearestExistingParent(input: string): Promise<string> {
  let cursor = path.resolve(input);
  while (true) {
    try {
      await stat(cursor);
      return cursor;
    } catch (error) {
      const code = error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
      if (code !== "ENOENT" && code !== "ENOTDIR") throw error;
      const parent = path.dirname(cursor);
      if (parent === cursor) throw new Error("no existing parent could be resolved for the requested path");
      cursor = parent;
    }
  }
}

export async function readJson<T>(filename: string, maximumBytes = 16 * 1024 * 1024): Promise<T> {
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1) throw new Error("JSON size limit must be a positive integer");
  const handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n) throw new Error("JSON input must be a single-link regular, non-symbolic-link file");
    if (!Number.isSafeInteger(Number(before.size)) || before.size < 0n || before.size > BigInt(maximumBytes)) {
      throw new Error("JSON input exceeds its bounded size limit");
    }
    const data = Buffer.allocUnsafe(Number(before.size));
    let consumed = 0;
    while (consumed < data.length) {
      const result = await handle.read(data, consumed, data.length - consumed, consumed);
      if (result.bytesRead === 0) break;
      consumed += result.bytesRead;
    }
    const probe = Buffer.allocUnsafe(1);
    const extra = await handle.read(probe, 0, 1, consumed);
    const after = await handle.stat({ bigint: true });
    const current = await lstat(filename, { bigint: true });
    if (
      BigInt(consumed) !== before.size
      || extra.bytesRead !== 0
      || before.dev !== after.dev
      || before.ino !== after.ino
      || after.nlink !== 1n
      || before.size !== after.size
      || before.mtimeNs !== after.mtimeNs
      || before.ctimeNs !== after.ctimeNs
      || current.isSymbolicLink()
      || !current.isFile()
      || current.nlink !== 1n
      || current.dev !== after.dev
      || current.ino !== after.ino
      || current.size !== after.size
      || current.mtimeNs !== after.mtimeNs
      || current.ctimeNs !== after.ctimeNs
    ) throw new Error("JSON input changed while it was being read");
    try {
      return JSON.parse(data.toString("utf8")) as T;
    } catch (error) {
      throw new Error("JSON input is not valid JSON", { cause: error });
    }
  } finally {
    await handle.close();
  }
}

export async function readDirectoryNamesBounded(directory: string, maximumEntries: number): Promise<string[]> {
  if (!Number.isSafeInteger(maximumEntries) || maximumEntries < 0) {
    throw new Error("directory entry limit must be a non-negative safe integer");
  }
  const names: string[] = [];
  const handle = await opendir(directory);
  for await (const entry of handle) {
    if (names.length >= maximumEntries) throw new Error("directory contains more entries than its bounded control layout permits");
    names.push(entry.name);
  }
  return names;
}

export async function* walkRegularFiles(roots: string[], options: WalkOptions = {}): AsyncGenerator<WalkedFile> {
  const aborted = (): boolean => options.signal?.aborted === true;
  const maximumDirectoryEntries = options.maximumDirectoryEntries ?? MAX_WALK_DIRECTORY_ENTRIES;
  const maximumPendingEntries = options.maximumPendingEntries ?? MAX_WALK_PENDING_ENTRIES;
  const maximumDirectories = options.maximumDirectories ?? MAX_WALK_DIRECTORIES;
  if (!Number.isSafeInteger(maximumDirectoryEntries) || maximumDirectoryEntries < 1 || maximumDirectoryEntries > MAX_WALK_DIRECTORY_ENTRIES) {
    throw new Error(`maximumDirectoryEntries must be an integer from 1 through ${MAX_WALK_DIRECTORY_ENTRIES}`);
  }
  if (!Number.isSafeInteger(maximumPendingEntries) || maximumPendingEntries < 1 || maximumPendingEntries > MAX_WALK_PENDING_ENTRIES) {
    throw new Error(`maximumPendingEntries must be an integer from 1 through ${MAX_WALK_PENDING_ENTRIES}`);
  }
  if (!Number.isSafeInteger(maximumDirectories) || maximumDirectories < 1 || maximumDirectories > MAX_WALK_DIRECTORIES) {
    throw new Error(`maximumDirectories must be an integer from 1 through ${MAX_WALK_DIRECTORIES}`);
  }
  const rootPaths = new Set(roots.map((root) => path.resolve(root)));
  const pending = [...rootPaths].sort((left, right) => bytewiseLexical(right, left));
  const visitedDirectories = new Set<string>();
  while (pending.length > 0) {
    if (aborted()) throw new Error("regular-file walk was paused");
    const current = pending.pop();
    if (current === undefined) break;
    let stable: StableStat;
    try {
      stable = await stableLstat(current);
    } catch (error) {
      if (aborted() || rootPaths.has(current)) throw error;
      options.onError?.(current, error);
      continue;
    }
    const metadata = stable.raw;
    if (metadata.isSymbolicLink()) continue;
    if (metadata.isFile()) {
      yield {
        path: current,
        bytes: stable.bytes,
        device: stable.device,
        inode: stable.inode,
        modifiedMs: stable.modifiedMs,
        changedMs: stable.changedMs,
      };
      continue;
    }
    if (!metadata.isDirectory()) continue;
    const directoryKey = JSON.stringify([stable.device, stable.inode]);
    if (visitedDirectories.has(directoryKey)) continue;
    if (visitedDirectories.size >= maximumDirectories) {
      const error = new Error(`input tree exceeds the ${maximumDirectories}-directory deterministic-walk limit; scan smaller subdirectories separately`);
      if (rootPaths.has(current)) throw error;
      options.onError?.(current, error);
      continue;
    }
    if (await options.shouldEnterDirectory?.(current) === false) {
      options.onError?.(current, new Error("refusing to cross a disallowed directory boundary"));
      continue;
    }
    let directory: Awaited<ReturnType<typeof opendir>>;
    try {
      directory = await opendir(current);
    } catch (error) {
      if (aborted() || rootPaths.has(current)) throw error;
      options.onError?.(current, error);
      continue;
    }
    // A rejected or unreadable alias must not suppress a later usable local
    // alias of the same inode. Mark it only once the directory is open.
    visitedDirectories.add(directoryKey);
    try {
      const children: string[] = [];
      for await (const entry of directory) {
        if (aborted()) throw new Error("regular-file walk was paused");
        if (entry.isSymbolicLink()) continue;
        if (children.length >= maximumDirectoryEntries) {
          throw new Error(`directory exceeds the ${maximumDirectoryEntries}-entry deterministic-walk limit; scan smaller subdirectories separately`);
        }
        children.push(path.join(current, entry.name));
      }
      if (pending.length + children.length > maximumPendingEntries) {
        throw new Error(`directory would exceed the ${maximumPendingEntries}-entry deterministic-walk frontier limit; scan smaller subdirectories separately`);
      }
      children.sort((left, right) => bytewiseLexical(right, left));
      for (const child of children) pending.push(child);
    } catch (error) {
      if (aborted() || rootPaths.has(current)) throw error;
      options.onError?.(current, error);
    }
  }
}
