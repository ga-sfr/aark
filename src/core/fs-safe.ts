import { randomUUID } from "node:crypto";
import { constants, open, opendir, rename, stat, lstat, chmod, mkdir, unlink } from "node:fs/promises";
import path from "node:path";

export interface WalkedFile {
  path: string;
  bytes: number;
  device: number;
  inode: number;
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
  let openedLock: Awaited<ReturnType<typeof handle.stat>>;
  try {
    openedLock = await handle.stat();
  } catch (error) {
    await handle.close().catch(() => undefined);
    throw error;
  }
  if (!openedLock.isFile() || openedLock.nlink !== 1) {
    await handle.close().catch(() => undefined);
    try {
      const current = await lstat(lockPath);
      if (current.dev === openedLock.dev && current.ino === openedLock.ino) {
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
    const removed = await lstat(lockPath).then(async (current) => {
      if (current.dev !== openedLock.dev || current.ino !== openedLock.ino) return false;
      await unlink(lockPath);
      return true;
    }, () => false).catch(() => false);
    if (removed) await syncDirectory(root).catch(() => undefined);
    throw error;
  }

  let released = false;
  const assertHeld = async (): Promise<void> => {
    if (released) throw new Error("exclusive lock was already released");
    let opened: Awaited<ReturnType<typeof handle.stat>>;
    let current: Awaited<ReturnType<typeof lstat>>;
    try {
      opened = await handle.stat();
      current = await lstat(lockPath);
    } catch (error) {
      throw new Error("exclusive lock path is no longer verifiable", { cause: error });
    }
    if (opened.dev !== current.dev || opened.ino !== current.ino || opened.nlink !== 1 || current.nlink !== 1 || !current.isFile() || current.isSymbolicLink()) {
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
  let priorDestination: { device: number; inode: number; bytes: number; modifiedMs: number; changedMs: number } | undefined;
  try {
    const existing = await lstat(destination);
    if (existing.isSymbolicLink() || !existing.isFile() || existing.nlink !== 1) {
      throw new Error("atomic output destination must remain a single-link regular file");
    }
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
  const assertDestinationUnchanged = async (): Promise<void> => {
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
      ) throw new Error("atomic output destination changed before publication");
    } catch (error) {
      const code = error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
      if (code === "ENOENT" && priorDestination === undefined) return;
      throw error;
    }
  };
  const temporary = `${destination}.tmp-${process.pid}-${randomUUID()}`;
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  let identity: { device: number; inode: number } | undefined;
  let renamed = false;
  try {
    handle = await open(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, mode);
    const opened = await handle.stat();
    identity = { device: opened.dev, inode: opened.ino };
    if (!opened.isFile() || opened.nlink !== 1) throw new Error("atomic temporary output must be a single-link regular file");
    await handle.writeFile(data);
    try {
      await handle.chmod(mode);
    } catch (error) {
      if (!unsupportedModeOperation(error)) throw error;
      // Non-Unix destination filesystems may not implement chmod; the manifest warns about mode enforcement.
    }
    await handle.sync();
    const currentTemporary = await lstat(temporary);
    if (
      currentTemporary.isSymbolicLink()
      || !currentTemporary.isFile()
      || currentTemporary.nlink !== 1
      || currentTemporary.dev !== identity.device
      || currentTemporary.ino !== identity.inode
    ) throw new Error("atomic temporary output path changed before publication");
    await assertDestinationUnchanged();
    await rename(temporary, destination);
    renamed = true;
    const currentDestination = await lstat(destination);
    if (
      currentDestination.isSymbolicLink()
      || !currentDestination.isFile()
      || currentDestination.nlink !== 1
      || currentDestination.dev !== identity.device
      || currentDestination.ino !== identity.inode
    ) throw new Error("atomic output path changed during publication");
    await handle.close();
    handle = undefined;
    await syncDirectory(parent);
  } finally {
    await handle?.close().catch(() => undefined);
    if (!renamed && identity !== undefined) {
      try {
        const current = await lstat(temporary);
        if (current.dev === identity.device && current.ino === identity.inode) await unlink(temporary);
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
    const before = await handle.stat();
    if (!before.isFile() || before.nlink !== 1) throw new Error("JSON input must be a single-link regular, non-symbolic-link file");
    if (!Number.isSafeInteger(before.size) || before.size < 0 || before.size > maximumBytes) {
      throw new Error("JSON input exceeds its bounded size limit");
    }
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
    let metadata: Awaited<ReturnType<typeof lstat>>;
    try {
      metadata = await lstat(current);
    } catch (error) {
      if (aborted() || rootPaths.has(current)) throw error;
      options.onError?.(current, error);
      continue;
    }
    if (metadata.isSymbolicLink()) continue;
    if (
      !Number.isFinite(metadata.dev)
      || metadata.dev < 0
      || !Number.isFinite(metadata.ino)
      || metadata.ino < 0
      || !Number.isFinite(metadata.mtimeMs)
      || !Number.isFinite(metadata.ctimeMs)
    ) {
      const error = new Error("filesystem entry identity or timestamps are outside valid numeric bounds");
      if (rootPaths.has(current)) throw error;
      options.onError?.(current, error);
      continue;
    }
    if (metadata.isFile()) {
      if (!Number.isSafeInteger(metadata.size) || metadata.size < 0) {
        const error = new Error("regular-file size exceeds safe numeric bounds");
        if (rootPaths.has(current)) throw error;
        options.onError?.(current, error);
        continue;
      }
      yield {
        path: current,
        bytes: metadata.size,
        device: metadata.dev,
        inode: metadata.ino,
        modifiedMs: metadata.mtimeMs,
        changedMs: metadata.ctimeMs,
      };
      continue;
    }
    if (!metadata.isDirectory()) continue;
    const directoryKey = `${metadata.dev}:${metadata.ino}`;
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
