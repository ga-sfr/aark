// Offline, bounded-memory staging for large regular files. Build AARK first.
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, mkdir, open, realpath, unlink } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { spawn } from "node:child_process";
import { acquireExclusiveLock, assertNoSymlinkComponents, atomicWriteJson, readJson } from "../dist/core/fs-safe.js";
import { assertStorageCapacity, storagePolicyFromGiB } from "../dist/core/storage.js";
import { mounts, mountForPathFrom, mountIsNetworkBacked } from "../dist/core/mounts.js";
import { loadCompletedInventory, loadScanState, readScanManifest, verifyResumeArtifacts } from "../dist/mining/resume.js";

const MIB = 1024 * 1024;
const MIN_OVERLAP = 17 * MIB;
const COPY_BUFFER_BYTES = 16 * MIB;
const MAX_RANGES = 100_000;
const PROVENANCE = new Set(["deleted-metadata", "unallocated-carve", "unallocated-stream", "shadow-copy", "residual-memory", "allocated-reference", "unknown"]);

export function planRanges(bytes, shardBytes, overlapBytes = MIN_OVERLAP) {
  if (![bytes, shardBytes, overlapBytes].every(Number.isSafeInteger)
    || bytes < 0 || shardBytes < 32 * MIB || overlapBytes < MIN_OVERLAP
    || overlapBytes > shardBytes || Math.ceil(bytes / shardBytes) > MAX_RANGES) {
    throw new Error("invalid or excessive sharded-scan ranges");
  }
  const shards = [];
  const boundaries = [];
  for (let start = 0; start < bytes; start += shardBytes) {
    shards.push({ index: shards.length, start, length: Math.min(shardBytes, bytes - start) });
    if (start > 0) {
      // Internal CLI chunk overlap cannot cover independent file boundaries.
      const begin = Math.max(0, start - overlapBytes);
      boundaries.push({ index: boundaries.length, start: begin, length: Math.min(bytes, start + overlapBytes) - begin });
    }
  }
  return { shards, boundaries };
}

function samePath(a, b) { return process.platform === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b; }
function inside(parent, child) {
  const relative = path.relative(parent, child);
  return relative !== "" && relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}
function identity(s) {
  return { device: s.dev.toString(), inode: s.ino.toString(), bytes: Number(s.size), modifiedNs: s.mtimeNs.toString(), changedNs: s.ctimeNs.toString() };
}
function matches(a, b) {
  return a.device === b.device && a.inode === b.inode && a.bytes === b.bytes && a.modifiedNs === b.modifiedNs && a.changedNs === b.changedNs;
}
function rangeName(phase, range, attempt) {
  const prefix = phase === "shards" ? "shard" : "boundary";
  return `${prefix}-${String(range.index).padStart(6, "0")}-offset-${String(range.start).padStart(16, "0")}-bytes-${String(range.length).padStart(16, "0")}-attempt-${attempt}`;
}
function rangeMatches(entry, range) { return entry.index === range.index && entry.start === range.start && entry.length === range.length; }
async function sourceCurrent(source, handle, expected) {
  await assertNoSymlinkComponents(path.parse(source).root, source);
  const [opened, current, canonical] = await Promise.all([handle.stat({ bigint: true }), lstat(source, { bigint: true }), realpath(source)]);
  if (!opened.isFile() || !current.isFile() || current.isSymbolicLink() || !samePath(canonical, source)
    || !matches(identity(opened), expected) || !matches(identity(current), expected)) {
    throw new Error("source identity changed during sharded scanning");
  }
}
async function hashFile(filename) {
  const handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n) throw new Error("staging input is not a single-link file");
    const digest = createHash("sha256");
    const buffer = Buffer.allocUnsafe(COPY_BUFFER_BYTES);
    let offset = 0;
    for (;;) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, offset);
      if (bytesRead === 0) break;
      digest.update(buffer.subarray(0, bytesRead));
      offset += bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    const current = await lstat(filename, { bigint: true });
    if (current.isSymbolicLink() || !matches(identity(before), identity(after)) || !matches(identity(after), identity(current))) {
      throw new Error("staging input changed while hashing");
    }
    return digest.digest("hex");
  } finally { await handle.close(); }
}
async function copyRange(source, destination, range, capacityCheck) {
  await capacityCheck(range.length);
  const handle = await open(destination, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  try {
    const buffer = Buffer.allocUnsafe(Math.min(COPY_BUFFER_BYTES, range.length));
    const digest = createHash("sha256");
    let copied = 0;
    while (copied < range.length) {
      const wanted = Math.min(buffer.length, range.length - copied);
      const { bytesRead } = await source.read(buffer, 0, wanted, range.start + copied);
      if (bytesRead === 0) throw new Error("source ended before its planned range");
      await capacityCheck(bytesRead);
      digest.update(buffer.subarray(0, bytesRead));
      let written = 0;
      while (written < bytesRead) {
        const result = await handle.write(buffer, written, bytesRead - written, copied + written);
        if (result.bytesWritten === 0) throw new Error("staging write made no progress");
        written += result.bytesWritten;
      }
      copied += bytesRead;
    }
    await handle.sync();
    return digest.digest("hex");
  } finally { await handle.close(); }
}
async function verifyOutput(output, range, staging, provenance) {
  const scan = await loadScanState(output);
  if (scan.status !== "complete" || scan.progress.bytesScanned !== range.length
    || scan.semantic.provenance !== provenance || scan.semantic.inputs.length !== 1
    || scan.semantic.inputs[0] !== staging || scan.manifest.entries !== 1) {
    throw new Error("range output does not prove the expected clean scan");
  }
  const inventory = await loadCompletedInventory(output, scan.inventory);
  for await (const file of readScanManifest(output, scan.manifest)) {
    if (file.path !== staging || file.bytes !== range.length) throw new Error("range input manifest mismatch");
  }
  await verifyResumeArtifacts(output, inventory);
  return { findings: inventory.findings.length, inventorySha256: scan.inventory.sha256 };
}
async function runAark(cli, input, output, options) {
  const args = [cli, "mine", "scan", input, "-o", output, "--provenance", options.provenance,
    "--workers", String(options.workers), "--chunk-mib", String(options.chunkMiB),
    "--overlap-mib", String(options.overlapMiB), "--min-free-gib", String(options.minimumFreeGiB), "--min-free-percent", "5", "--quiet"];
  // Do not relay child output containing evidence paths. Local reports retain diagnostics.
  return await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, args, { shell: false, windowsHide: true, stdio: "ignore" });
    child.once("error", reject);
    child.once("close", (code) => resolve(code));
  });
}
function parseOptions(argv) {
  const values = new Map();
  const allowed = new Set(["--source", "--output-root", "--staging-root", "--provenance", "--shard-mib", "--workers", "--chunk-mib", "--overlap-mib", "--min-free-gib", "--cli"]);
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    if (!allowed.has(key) || values.has(key) || !argv[index + 1]) throw new Error("expected unique --option value pairs; see docs/mining.md");
    values.set(key, argv[index + 1]);
  }
  const required = (key) => { const value = values.get(key); if (!value) throw new Error(`missing ${key}`); return value; };
  const integer = (key, fallback, min, max) => {
    const value = values.has(key) && /^[0-9]+$/.test(values.get(key)) ? Number(values.get(key)) : values.has(key) ? NaN : fallback;
    if (!Number.isSafeInteger(value) || value < min || value > max) throw new Error(`invalid ${key}`);
    return value;
  };
  const provenance = required("--provenance");
  if (!PROVENANCE.has(provenance)) throw new Error("invalid provenance");
  const chunkMiB = integer("--chunk-mib", 32, 17, 128);
  const minimumFreeGiB = Number(values.get("--min-free-gib") ?? 5);
  return {
    source: path.resolve(required("--source")), outputRoot: path.resolve(required("--output-root")), stagingRoot: path.resolve(required("--staging-root")),
    provenance, shardBytes: integer("--shard-mib", 4096, 32, 1024 * 1024) * MIB,
    workers: integer("--workers", 4, 1, 4), chunkMiB, overlapMiB: integer("--overlap-mib", 17, 17, chunkMiB), minimumFreeGiB,
    policy: storagePolicyFromGiB(minimumFreeGiB, 5), cli: path.resolve(values.get("--cli") ?? path.join(import.meta.dirname, "..", "dist", "cli.js")),
  };
}

export async function main(argv = process.argv.slice(2)) {
  const options = parseOptions(argv);
  const { source, outputRoot, stagingRoot, provenance, shardBytes } = options;
  if ([outputRoot, stagingRoot].some((root) => samePath(root, source) || inside(root, source) || inside(source, root))
    || samePath(outputRoot, stagingRoot) || inside(outputRoot, stagingRoot) || inside(stagingRoot, outputRoot)) {
    throw new Error("source, output and staging must be separate non-nested paths");
  }
  const records = await mounts();
  for (const filename of [source, outputRoot, stagingRoot]) {
    await assertNoSymlinkComponents(path.parse(filename).root, filename);
    if (await mountIsNetworkBacked(mountForPathFrom(records, filename))) throw new Error("controller paths must be on local filesystems");
  }
  const rootHandles = [];
  const locks = [];
  let sourceHandle;
  try {
    for (const root of [outputRoot, stagingRoot]) {
      await mkdir(root, { recursive: true, mode: 0o700 });
      const handle = await open(root, constants.O_RDONLY);
      rootHandles.push({ root, handle, original: identity(await handle.stat({ bigint: true })) });
      locks.push(await acquireExclusiveLock(root, ".aark-sharded.lock"));
    }
    const assertRoots = async () => {
      for (const { root, handle, original } of rootHandles) {
        await assertNoSymlinkComponents(path.parse(root).root, root);
        const current = await lstat(root, { bigint: true });
        const opened = await handle.stat({ bigint: true });
        if (!current.isDirectory() || current.isSymbolicLink() || !samePath(await realpath(root), root)
          || current.dev.toString() !== original.device || current.ino.toString() !== original.inode
          || opened.dev !== current.dev || opened.ino !== current.ino) throw new Error("controller root identity changed");
      }
      for (const lock of locks) await lock.assertHeld();
    };
    await assertRoots();
    sourceHandle = await open(source, constants.O_RDONLY | constants.O_NOFOLLOW);
    const sourceIdentity = identity(await sourceHandle.stat({ bigint: true }));
    await sourceCurrent(source, sourceHandle, sourceIdentity);
    const ranges = planRanges(sourceIdentity.bytes, shardBytes, options.overlapMiB * MIB);
    const statePath = path.join(outputRoot, "shard-controller-sensitive.json");
    let state;
    try { state = await readJson(statePath); }
    catch (error) { if (error.code !== "ENOENT") throw error; }
    if (state !== undefined) {
      if (![1, 2].includes(state.version) || state.tool !== "aark-sharded-scan" || state.source !== source
        || state.outputRoot !== outputRoot || state.stagingRoot !== stagingRoot || state.provenance !== provenance
        || state.shardBytes !== shardBytes || !matches(state.sourceIdentity ?? {}, sourceIdentity)
        || !Array.isArray(state.completed)) throw new Error("existing controller state does not match this source or invocation");
      if (state.version === 1) {
        // Version 1 'complete' meant byte coverage only. Reuse its scans but
        // do not claim completion until every cross-shard window is scanned.
        state.version = 2;
        state.overlapBytes = options.overlapMiB * MIB;
        state.boundaryCompleted = [];
        if (state.pending) state.pending.phase = "shards";
      }
      if (state.overlapBytes !== options.overlapMiB * MIB || !Array.isArray(state.boundaryCompleted)) throw new Error("boundary settings changed");
    } else {
      state = { version: 2, tool: "aark-sharded-scan", source, sourceIdentity, outputRoot, stagingRoot, provenance, shardBytes,
        overlapBytes: options.overlapMiB * MIB, completed: [], boundaryCompleted: [], pending: null };
    }
    state.status = "in-progress";
    await atomicWriteJson(statePath, state);
    await atomicWriteJson(path.join(outputRoot, "coverage-redacted.json"), { version: 2, tool: state.tool, status: "in-progress", complete: false, sourcePathsRedacted: true }, 0o644);
    const safeEntry = async (entry, range, phase, pending = false) => {
      if (!range || !rangeMatches(entry, range) || !Number.isSafeInteger(entry.attempt ?? 0) || (entry.attempt ?? 0) < 0) throw new Error("invalid range state");
      const match = typeof entry.output === "string" ? /-attempt-([0-9]+)$/.exec(entry.output) : null;
      const attempt = pending ? entry.attempt : Number(match?.[1]);
      if (!Number.isSafeInteger(attempt) || attempt < 0) throw new Error("invalid range output name");
      const output = path.join(outputRoot, rangeName(phase, range, attempt));
      const staging = path.join(stagingRoot, `${rangeName(phase, range, 0)}.bin`);
      if ((entry.output !== null && entry.output !== output) || (pending && entry.staging !== staging)) throw new Error("range paths escaped their fixed roots");
      await assertNoSymlinkComponents(outputRoot, output);
      await assertNoSymlinkComponents(stagingRoot, staging);
      return { output, staging };
    };
    for (const phase of ["shards", "boundaries"]) {
      const completed = phase === "shards" ? state.completed : state.boundaryCompleted;
      if (completed.length > ranges[phase].length) throw new Error("too many completed ranges");
      for (let index = 0; index < completed.length; index++) {
        const entry = completed[index];
        const paths = await safeEntry(entry, ranges[phase][index], phase);
        if (!/^[a-f0-9]{64}$/.test(entry.sha256)) throw new Error("invalid range hash");
        const verified = await verifyOutput(paths.output, entry, paths.staging, provenance);
        if (entry.inventorySha256 && entry.inventorySha256 !== verified.inventorySha256) throw new Error("completed inventory changed");
        entry.inventorySha256 = verified.inventorySha256;
      }
      while (completed.length < ranges[phase].length) {
        await assertRoots();
        await sourceCurrent(source, sourceHandle, sourceIdentity);
        const range = ranges[phase][completed.length];
        if (state.pending === null) {
          state.pending = { ...range, phase, staging: path.join(stagingRoot, `${rangeName(phase, range, 0)}.bin`), attempt: 0, output: null, sha256: null };
          await atomicWriteJson(statePath, state);
        }
        const pending = state.pending;
        if (pending.phase !== phase) throw new Error("pending range phase mismatch");
        await safeEntry(pending, range, phase, true);
        let staged;
        try { staged = await lstat(pending.staging); } catch (error) { if (error.code !== "ENOENT") throw error; }
        if (staged) {
          if (staged.isSymbolicLink() || !staged.isFile() || staged.size !== range.length || !/^[a-f0-9]{64}$/.test(pending.sha256 ?? "")
            || await hashFile(pending.staging) !== pending.sha256) throw new Error("incomplete or changed staging input requires local review");
        } else {
          pending.sha256 = await copyRange(sourceHandle, pending.staging, range, async (bytes) => {
            await assertRoots();
            await assertStorageCapacity(stagingRoot, options.policy, 0n, BigInt(bytes));
          });
          await sourceCurrent(source, sourceHandle, sourceIdentity);
          if (await hashFile(pending.staging) !== pending.sha256) throw new Error("staging copy failed hash verification");
          await atomicWriteJson(statePath, state);
        }
        let verified;
        if (pending.output !== null) {
          try { verified = await verifyOutput(pending.output, range, pending.staging, provenance); }
          catch { pending.attempt++; pending.output = null; }
        }
        if (!verified) {
          pending.output = path.join(outputRoot, rangeName(phase, range, pending.attempt));
          await safeEntry(pending, range, phase, true);
          await atomicWriteJson(statePath, state);
          const code = await runAark(options.cli, pending.staging, pending.output, options);
          if (code !== 0) throw new Error(`AARK ${phase} range ${range.index} stopped (exit ${code}); local outputs and staging retained`);
          verified = await verifyOutput(pending.output, range, pending.staging, provenance);
        }
        await sourceCurrent(source, sourceHandle, sourceIdentity);
        await assertRoots();
        if (await hashFile(pending.staging) !== pending.sha256) throw new Error("staging input changed during scanning");
        completed.push({ ...range, output: pending.output, sha256: pending.sha256, inventorySha256: verified.inventorySha256 });
        state.pending = null;
        await atomicWriteJson(statePath, state);
        // Only this exact, hashed temporary file is removed; the full source
        // remains the retained finding-containing file/decryption context.
        await assertNoSymlinkComponents(stagingRoot, pending.staging);
        await unlink(pending.staging);
        process.stdout.write(`${JSON.stringify({ phase, completed: completed.length, total: ranges[phase].length, findings: verified.findings })}\n`);
      }
    }
    if (state.pending !== null) throw new Error("unexpected pending range after completion");
    await sourceCurrent(source, sourceHandle, sourceIdentity);
    await assertRoots();
    state.status = "complete";
    await atomicWriteJson(statePath, state);
    const coverage = { version: 2, tool: state.tool, status: "complete", complete: true, sourcePathsRedacted: true, hashesRedacted: true,
      sourceBytes: sourceIdentity.bytes, shardBytes, shardsCompleted: state.completed.length, bytesCovered: sourceIdentity.bytes,
      boundaryRangesCompleted: state.boundaryCompleted.length, boundaryOverlapBytes: state.overlapBytes, streamingBoundariesCovered: true,
      originalSourceRetained: true, wholeSourceStructuredScan: false };
    await atomicWriteJson(path.join(outputRoot, "coverage-redacted.json"), coverage, 0o644);
    process.stdout.write(`${JSON.stringify(coverage)}\n`);
  } finally {
    const errors = [];
    try { await sourceHandle?.close(); } catch (error) { errors.push(error); }
    for (const lock of locks.reverse()) { try { await lock.release(); } catch (error) { errors.push(error); } }
    for (const { handle } of rootHandles) { try { await handle.close(); } catch (error) { errors.push(error); } }
    if (errors.length) throw new AggregateError(errors, "controller handles or locks could not all be released");
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
}
