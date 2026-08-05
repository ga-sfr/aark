import type { BigIntStats } from "node:fs";
import { lstat, opendir, statfs } from "node:fs/promises";
import path from "node:path";

const GIBIBYTE = 1024n ** 3n;
const MAX_OUTPUT_TREE_DEPTH = 256;
const MAX_USAGE_DIRECTORY_ENTRIES = 100_000;
const MAX_USAGE_PENDING_ENTRIES = 200_000;
const MAX_USAGE_DIRECTORIES = 200_000;

function fixedPointInteger(value: number, scale: number, label: string): number {
  const scaled = Math.round(value * scale);
  const tolerance = Number.EPSILON * Math.max(1, Math.abs(value)) * 8;
  if (!Number.isFinite(value) || value < 0 || !Number.isSafeInteger(scaled) || Math.abs(value - scaled / scale) > tolerance) {
    throw new Error(label);
  }
  return scaled;
}

export interface StoragePolicy {
  minimumFreeBytes: bigint;
  minimumFreePercent: number;
  maximumOutputBytes?: bigint;
}

export interface StorageCapacity {
  availableBytes: bigint;
  totalBytes: bigint;
  reservedBytes: bigint;
  outputBytes: bigint;
  plannedBytes: bigint;
}

export interface DirectoryUsage {
  logicalBytes: bigint;
  allocatedBytes: bigint;
  minimumReclaimableAllocatedBytes: bigint;
  regularFiles: bigint;
  directories: bigint;
  otherEntries: bigint;
  hardLinkedRegularFiles: bigint;
  allocationUnitBytes: bigint;
  allocationUnitSource: "statfs-block-size";
}

export class StorageQuotaError extends Error {
  public override readonly name = "StorageQuotaError";

  public constructor(
    public readonly reason: "free-space-reserve" | "output-cap",
    public readonly capacity: StorageCapacity,
  ) {
    super(reason === "free-space-reserve"
      ? "output filesystem reached its configured free-space reserve"
      : "operation reached its configured output-size cap");
  }
}

function percentBasisPoints(value: number): bigint {
  if (value > 100) {
    throw new Error("minimum free percent must be from 0 through 100 with at most two decimal places");
  }
  return BigInt(fixedPointInteger(value, 100, "minimum free percent must be from 0 through 100 with at most two decimal places"));
}

export function gibibytesToBytes(value: number, label: string): bigint {
  const scaled = fixedPointInteger(value, 1000, `${label} must be a non-negative number with at most three decimal places`);
  return BigInt(scaled) * GIBIBYTE / 1000n;
}

export function storagePolicyFromGiB(
  minimumFreeGiB = 5,
  minimumFreePercent = 5,
  maximumOutputGiB?: number,
): StoragePolicy {
  const policy: StoragePolicy = {
    minimumFreeBytes: gibibytesToBytes(minimumFreeGiB, "minimum free GiB"),
    minimumFreePercent,
  };
  percentBasisPoints(minimumFreePercent);
  if (maximumOutputGiB !== undefined) {
    const maximumOutputBytes = gibibytesToBytes(maximumOutputGiB, "maximum output GiB");
    if (maximumOutputBytes < 1n) throw new Error("maximum output GiB must be greater than zero");
    policy.maximumOutputBytes = maximumOutputBytes;
  }
  return policy;
}

export async function storageCapacity(target: string, policy: StoragePolicy, outputBytes = 0n, plannedBytes = 0n): Promise<StorageCapacity> {
  if (outputBytes < 0n || plannedBytes < 0n) throw new Error("storage byte counts must not be negative");
  const information = await statfs(target, { bigint: true });
  const totalBytes = information.blocks * information.bsize;
  const availableBytes = information.bavail * information.bsize;
  const percentBytes = (totalBytes * percentBasisPoints(policy.minimumFreePercent) + 9_999n) / 10_000n;
  const reservedBytes = policy.minimumFreeBytes > percentBytes ? policy.minimumFreeBytes : percentBytes;
  return { availableBytes, totalBytes, reservedBytes, outputBytes, plannedBytes };
}

export async function assertStorageCapacity(
  target: string,
  policy: StoragePolicy,
  outputBytes = 0n,
  plannedBytes = 0n,
): Promise<StorageCapacity> {
  const capacity = await storageCapacity(target, policy, outputBytes, plannedBytes);
  if (capacity.availableBytes - capacity.plannedBytes < capacity.reservedBytes) {
    throw new StorageQuotaError("free-space-reserve", capacity);
  }
  if (policy.maximumOutputBytes !== undefined && outputBytes + plannedBytes > policy.maximumOutputBytes) {
    throw new StorageQuotaError("output-cap", capacity);
  }
  return capacity;
}

export class StorageBudget {
  public constructor(
    public readonly target: string,
    public readonly policy: StoragePolicy,
    private logicalBytes: bigint,
  ) {
    if (logicalBytes < 0n) throw new Error("initial logical output bytes must not be negative");
  }

  public outputBytes(): bigint {
    return this.logicalBytes;
  }

  public async beforeWrite(newBytes: bigint, replacingBytes = 0n): Promise<StorageCapacity> {
    if (newBytes < 0n || replacingBytes < 0n || replacingBytes > this.logicalBytes) {
      throw new Error("invalid storage write accounting");
    }
    const capacity = await storageCapacity(this.target, this.policy, this.logicalBytes, newBytes);
    if (capacity.availableBytes - newBytes < capacity.reservedBytes) {
      throw new StorageQuotaError("free-space-reserve", capacity);
    }
    const projected = this.logicalBytes - replacingBytes + newBytes;
    if (this.policy.maximumOutputBytes !== undefined && projected > this.policy.maximumOutputBytes) {
      throw new StorageQuotaError("output-cap", { ...capacity, outputBytes: projected });
    }
    return capacity;
  }

  public committedWrite(newBytes: bigint, replacingBytes = 0n): void {
    if (newBytes < 0n || replacingBytes < 0n || replacingBytes > this.logicalBytes) {
      throw new Error("invalid committed storage write accounting");
    }
    this.logicalBytes = this.logicalBytes - replacingBytes + newBytes;
  }
}

export async function directoryLogicalBytes(root: string, signal?: AbortSignal): Promise<bigint> {
  const resolvedRoot = path.resolve(root);
  const ancestors = new Set<string>();
  const assertNotAborted = (): void => {
    if (signal?.aborted === true) throw new Error("output tree size walk was interrupted");
  };
  const visit = async (current: string, depth: number): Promise<bigint> => {
    assertNotAborted();
    if (depth > MAX_OUTPUT_TREE_DEPTH) throw new Error("output tree exceeds the bounded directory-depth limit");
    let metadata: BigIntStats;
    try {
      metadata = await lstat(current, { bigint: true });
    } catch (error) {
      const code = error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
      // Recovery tools commonly publish through rename or remove temporary
      // entries while the quota monitor is walking. A vanished entry consumes
      // no current output bytes and will be reconsidered on the next poll.
      if (code === "ENOENT" || code === "ENOTDIR") return 0n;
      throw error;
    }
    if (metadata.isSymbolicLink() || metadata.isFile()) return metadata.size;
    if (!metadata.isDirectory()) return 0n;
    const directoryKey = `${metadata.dev}:${metadata.ino}`;
    if (ancestors.has(directoryKey)) throw new Error("output tree contains a recursive directory identity");
    ancestors.add(directoryKey);
    let total = 0n;
    try {
      const directory = await opendir(current);
      for await (const entry of directory) {
        assertNotAborted();
        total += await visit(path.join(current, entry.name), depth + 1);
      }
    } catch (error) {
      const code = error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
      if (code !== "ENOENT" && code !== "ENOTDIR") throw error;
    } finally {
      ancestors.delete(directoryKey);
    }
    return total;
  };
  return await visit(resolvedRoot, 0);
}

/**
 * Measure both apparent file bytes and blocks currently allocated by a tree.
 * The lower reclaimable bound excludes multiply-linked regular-file data,
 * because another link outside the selected tree may keep those blocks alive.
 */
export async function directoryUsage(root: string, signal?: AbortSignal): Promise<DirectoryUsage> {
  const resolvedRoot = path.resolve(root);
  const filesystem = await statfs(resolvedRoot, { bigint: true });
  const result: DirectoryUsage = {
    logicalBytes: 0n,
    allocatedBytes: 0n,
    minimumReclaimableAllocatedBytes: 0n,
    regularFiles: 0n,
    directories: 0n,
    otherEntries: 0n,
    hardLinkedRegularFiles: 0n,
    allocationUnitBytes: filesystem.bsize,
    allocationUnitSource: "statfs-block-size",
  };
  const pending: Array<{ filename: string; depth: number }> = [{ filename: resolvedRoot, depth: 0 }];
  const visitedDirectories = new Set<string>();
  const allocatedIdentities = new Set<string>();
  while (pending.length > 0) {
    if (signal?.aborted === true) throw new Error("directory usage walk was interrupted");
    const current = pending.pop();
    if (current === undefined) break;
    if (current.depth > MAX_OUTPUT_TREE_DEPTH) throw new Error("output tree exceeds the bounded directory-depth limit");
    const metadata = await lstat(current.filename, { bigint: true });
    const identity = `${metadata.dev}:${metadata.ino}`;
    const allocated = metadata.blocks * 512n;
    if (!allocatedIdentities.has(identity)) {
      allocatedIdentities.add(identity);
      result.allocatedBytes += allocated;
      if (!metadata.isFile() || metadata.nlink === 1n) result.minimumReclaimableAllocatedBytes += allocated;
    }
    if (metadata.isFile()) {
      result.regularFiles += 1n;
      result.logicalBytes += metadata.size;
      if (metadata.nlink > 1n) result.hardLinkedRegularFiles += 1n;
      continue;
    }
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      result.otherEntries += 1n;
      continue;
    }
    if (visitedDirectories.has(identity)) throw new Error("output tree contains a recursive directory identity");
    visitedDirectories.add(identity);
    if (visitedDirectories.size > MAX_USAGE_DIRECTORIES) throw new Error("directory usage walk exceeds its directory limit");
    result.directories += 1n;
    const directory = await opendir(current.filename);
    const children: string[] = [];
    for await (const entry of directory) {
      if (children.length >= MAX_USAGE_DIRECTORY_ENTRIES) throw new Error("directory usage walk exceeds its per-directory entry limit");
      children.push(path.join(current.filename, entry.name));
    }
    if (pending.length + children.length > MAX_USAGE_PENDING_ENTRIES) throw new Error("directory usage walk exceeds its pending-entry limit");
    children.sort().reverse();
    for (const child of children) pending.push({ filename: child, depth: current.depth + 1 });
  }
  return result;
}
