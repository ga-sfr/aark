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
}

export interface ExclusiveLock {
  path: string;
  assertHeld: () => Promise<void>;
  release: () => Promise<void>;
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
    if (code !== "EINVAL" && code !== "EOPNOTSUPP" && code !== "ENOTSUP" && code !== "ENOSYS") throw error;
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
  try {
    await handle.writeFile(`${JSON.stringify({ pid: process.pid, startedAt: new Date().toISOString() })}\n`);
    await handle.sync();
    await syncDirectory(root);
  } catch (error) {
    await handle.close().catch(() => undefined);
    const removed = await unlink(lockPath).then(() => true, () => false);
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
  await ensurePrivateDirectory(path.dirname(destination));
  const temporary = `${destination}.tmp-${process.pid}-${randomUUID()}`;
  let published = false;
  try {
    const handle = await open(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, mode);
    try {
      await handle.writeFile(data);
      await handle.sync();
    } finally {
      await handle.close();
    }
    try {
      await chmod(temporary, mode);
    } catch (error) {
      if (!unsupportedModeOperation(error)) throw error;
      // Non-Unix destination filesystems may not implement chmod; the manifest warns about mode enforcement.
    }
    await rename(temporary, destination);
    published = true;
    await syncDirectory(path.dirname(destination));
  } finally {
    if (!published) await unlink(temporary).catch(() => undefined);
  }
}

export async function atomicWriteJson(destination: string, value: unknown, mode = 0o600): Promise<void> {
  await atomicWriteFile(destination, `${JSON.stringify(value, null, 2)}\n`, mode);
}

export function safeJoin(root: string, ...parts: string[]): string {
  const resolvedRoot = path.resolve(root);
  const result = path.resolve(resolvedRoot, ...parts);
  const descendantPrefix = resolvedRoot.endsWith(path.sep) ? resolvedRoot : `${resolvedRoot}${path.sep}`;
  if (result !== resolvedRoot && !result.startsWith(descendantPrefix)) {
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
    if (!before.isFile()) throw new Error("JSON input must be a regular, non-symbolic-link file");
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
    if (
      consumed !== before.size
      || extra.bytesRead !== 0
      || before.dev !== after.dev
      || before.ino !== after.ino
      || before.size !== after.size
      || before.mtimeMs !== after.mtimeMs
      || before.ctimeMs !== after.ctimeMs
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

export async function* walkRegularFiles(roots: string[], options: WalkOptions = {}): AsyncGenerator<WalkedFile> {
  const rootPaths = new Set(roots.map((root) => path.resolve(root)));
  const pending = [...rootPaths];
  const visitedDirectories = new Set<string>();
  while (pending.length > 0) {
    const current = pending.pop();
    if (current === undefined) break;
    let metadata: Awaited<ReturnType<typeof lstat>>;
    try {
      metadata = await lstat(current);
    } catch (error) {
      if (rootPaths.has(current)) throw error;
      options.onError?.(current, error);
      continue;
    }
    if (metadata.isSymbolicLink()) continue;
    if (metadata.isFile()) {
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
    if (await options.shouldEnterDirectory?.(current) === false) {
      options.onError?.(current, new Error("refusing to cross a disallowed directory boundary"));
      continue;
    }
    let directory: Awaited<ReturnType<typeof opendir>>;
    try {
      directory = await opendir(current);
    } catch (error) {
      if (rootPaths.has(current)) throw error;
      options.onError?.(current, error);
      continue;
    }
    // A rejected or unreadable alias must not suppress a later usable local
    // alias of the same inode. Mark it only once the directory is open.
    visitedDirectories.add(directoryKey);
    try {
      for await (const entry of directory) {
        if (!entry.isSymbolicLink()) pending.push(path.join(current, entry.name));
      }
    } catch (error) {
      if (rootPaths.has(current)) throw error;
      options.onError?.(current, error);
    }
  }
}
