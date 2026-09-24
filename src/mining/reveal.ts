import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import path from "node:path";
import { assertNoSymlinkComponents, safeJoin } from "../core/fs-safe.js";
import { sha256Hex } from "../core/crypto.js";
import { MAX_SENSITIVE_INVENTORY_BYTES } from "./limits.js";
import type { SensitiveScanInventory } from "./types.js";

const MAX_REVEAL_BYTES = 256 * 1024 * 1024;
const TERMINAL_STATUSES = new Set(["paused", "complete", "complete-with-errors", "failed", "interrupted"]);
const SUPPORTED_INVENTORY_TOOLS = new Set(["aark", "agetnic-tools"]);

async function readStableRegularFile(filename: string, maximumBytes: number, expected?: { dev: bigint; ino: bigint }): Promise<Buffer> {
  const handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n || (expected !== undefined && (before.dev !== expected.dev || before.ino !== expected.ino))) {
      throw new Error("reveal input changed or is not a regular file");
    }
    if (!Number.isSafeInteger(Number(before.size)) || before.size < 0n || before.size > BigInt(maximumBytes)) {
      throw new Error(`reveal input exceeds its ${maximumBytes}-byte safety limit`);
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
    ) throw new Error("reveal input changed while it was being read");
    return data;
  } finally {
    await handle.close();
  }
}

export async function readValidatedRevealArtifact(input: string): Promise<Buffer> {
  const requested = path.resolve(input);
  const requestedMetadata = await lstat(requested, { bigint: true });
  if (requestedMetadata.isSymbolicLink() || !requestedMetadata.isFile()) {
    throw new Error("reveal requires a regular, non-symbolic-link artifact file");
  }
  const artifact = await realpath(requested);
  const findingDirectory = path.dirname(artifact);
  const artifactsDirectory = path.dirname(findingDirectory);
  const output = path.dirname(artifactsDirectory);
  if (path.basename(artifactsDirectory) !== "artifacts" || !/^finding-\d{6,16}$/.test(path.basename(findingDirectory))) {
    throw new Error("reveal accepts only a finding artifact produced by a finalized mining run");
  }
  await assertNoSymlinkComponents(output, artifact);
  const inventoryPath = safeJoin(output, "inventory-sensitive.json");
  await assertNoSymlinkComponents(output, inventoryPath);
  const inventoryMetadata = await lstat(inventoryPath, { bigint: true });
  if (inventoryMetadata.isSymbolicLink() || !inventoryMetadata.isFile()) throw new Error("the adjacent mining inventory is not a regular file");
  let inventory: SensitiveScanInventory;
  try {
    inventory = JSON.parse((await readStableRegularFile(inventoryPath, MAX_SENSITIVE_INVENTORY_BYTES, inventoryMetadata)).toString("utf8")) as SensitiveScanInventory;
  } catch (error) {
    throw new Error("the adjacent mining inventory is not valid JSON", { cause: error });
  }
  const completeStatus = inventory.status === "complete" || inventory.status === "complete-with-errors";
  if (
    inventory.version !== 1
    || !SUPPORTED_INVENTORY_TOOLS.has(inventory.tool)
    || inventory.layer !== "mining"
    || !TERMINAL_STATUSES.has(inventory.status)
    || inventory.complete !== completeStatus
    || typeof inventory.finishedAt !== "string"
    || typeof inventory.outputRoot !== "string"
    || path.resolve(inventory.outputRoot) !== output
    || !Array.isArray(inventory.findings)
  ) {
    throw new Error("the adjacent mining inventory is incomplete or does not match the artifact tree");
  }
  const relative = path.relative(output, artifact);
  const matchingFindings = (inventory.findings as unknown[]).filter((item) => {
    if (typeof item !== "object" || item === null || Array.isArray(item)) return false;
    const artifactFiles = (item as Record<string, unknown>).artifactFiles;
    return Array.isArray(artifactFiles) && artifactFiles.filter((entry) => entry === relative).length === 1;
  }) as Array<Record<string, unknown>>;
  if (matchingFindings.length !== 1) {
    throw new Error("the requested file is not referenced by the adjacent mining inventory");
  }
  const finding = matchingFindings[0];
  if (
    finding === undefined
    || !Number.isSafeInteger(finding.id)
    || Number(finding.id) < 1
    || `finding-${String(finding.id).padStart(6, "0")}` !== path.basename(findingDirectory)
    || path.dirname(relative) !== path.join("artifacts", path.basename(findingDirectory))
  ) throw new Error("the requested artifact does not match its finding directory metadata");
  const integrityMatches = Array.isArray(finding.artifactIntegrity)
    ? (finding.artifactIntegrity as unknown[]).filter((item) => (
      typeof item === "object"
      && item !== null
      && !Array.isArray(item)
      && (item as Record<string, unknown>).path === relative
    )) as Array<Record<string, unknown>>
    : [];
  const integrity = integrityMatches.length === 1 ? integrityMatches[0] : undefined;
  const integrityBytes = integrity?.bytes;
  const integritySha256 = integrity?.sha256;
  if (
    integrity === undefined
    || typeof integrityBytes !== "number"
    || !Number.isSafeInteger(integrityBytes)
    || integrityBytes < 0
    || integrityBytes > MAX_REVEAL_BYTES
    || typeof integritySha256 !== "string"
    || !/^[a-f0-9]{64}$/.test(integritySha256)
  ) throw new Error("the adjacent mining inventory lacks valid integrity metadata for this artifact");
  const value = await readStableRegularFile(artifact, integrityBytes, requestedMetadata);
  if (value.length !== integrityBytes || sha256Hex(value) !== integritySha256) {
    throw new Error("artifact bytes do not match the finalized mining inventory");
  }
  return value;
}
