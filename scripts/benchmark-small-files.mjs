import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readdir, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { scanSensitiveMaterial } from "../dist/mining/scanner.js";

function positiveInteger(name, fallback, maximum) {
  const text = process.env[name];
  if (text === undefined) return fallback;
  const value = Number(text);
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new Error(`${name} must be an integer from 1 through ${maximum}`);
  }
  return value;
}

function syntheticToken(label) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const offset = createHash("sha256").update(`aark synthetic benchmark ${label}`).digest()[0] ?? 0;
  const body = Array.from({ length: 36 }, (_, index) => alphabet[(offset + index) % alphabet.length]).join("");
  return ["gh", "p_", body].join("");
}

async function treeUsage(root) {
  let logicalBytes = 0;
  let allocatedBytes = 0;
  const pending = [root];
  while (pending.length > 0) {
    const current = pending.pop();
    if (current === undefined) break;
    const metadata = await stat(current, { bigint: true });
    allocatedBytes += Number(metadata.blocks * 512n);
    if (!metadata.isDirectory()) {
      if (metadata.isFile()) logicalBytes += Number(metadata.size);
      continue;
    }
    for (const entry of await readdir(current, { withFileTypes: true })) {
      if (entry.isDirectory() || entry.isFile()) pending.push(path.join(current, entry.name));
    }
  }
  return { logicalBytes, allocatedBytes };
}

const tinyFiles = positiveInteger("AARK_BENCH_FILES", 2_000, 100_000);
const workers = positiveInteger("AARK_BENCH_WORKERS", 4, 4);
const findingEvery = positiveInteger("AARK_BENCH_FINDING_EVERY", Math.min(100, tinyFiles), tinyFiles);
const chunkBytes = 17 * 1024 * 1024;
const root = await mkdtemp(path.join(os.tmpdir(), "aark-small-file-benchmark-"));
const input = path.join(root, "input");
const output = path.join(root, "output");
await mkdir(input);

try {
  const duplicateToken = syntheticToken("duplicate");
  const ordinary = Buffer.alloc(256, 0x41);
  let logicalInputBytes = 0;
  for (let index = 0; index < tinyFiles; index += 1) {
    const data = index % findingEvery === 0
      ? Buffer.from(`synthetic benchmark record\n${duplicateToken}\n`, "ascii")
      : ordinary;
    await writeFile(path.join(input, `${String(index).padStart(8, "0")}.dat`), data);
    logicalInputBytes += data.length;
  }

  const boundaryToken = syntheticToken("boundary");
  const boundaryPrefixBytes = chunkBytes - 10;
  const boundaryData = Buffer.concat([
    Buffer.alloc(boundaryPrefixBytes, 0x42),
    Buffer.from(`${boundaryToken}\n`, "ascii"),
    Buffer.alloc(128, 0x43),
  ]);
  await writeFile(path.join(input, "zz-boundary.dat"), boundaryData);
  logicalInputBytes += boundaryData.length;
  const structuredData = JSON.stringify({
    description: "synthetic benchmark container",
    api_key: syntheticToken("structured"),
  });
  await writeFile(path.join(input, "zz-structured.json"), structuredData);
  logicalInputBytes += Buffer.byteLength(structuredData);

  let peakRssBytes = process.memoryUsage().rss;
  const sampler = setInterval(() => {
    peakRssBytes = Math.max(peakRssBytes, process.memoryUsage().rss);
  }, 20);
  const started = performance.now();
  let result;
  try {
    result = await scanSensitiveMaterial({
      inputs: [input],
      output,
      provenance: "unknown",
      chunkBytes,
      overlapBytes: chunkBytes,
      wholeFileBytes: 1024 * 1024,
      workers,
      minimumFreeGiB: 0,
      minimumFreePercent: 0,
    });
  } finally {
    clearInterval(sampler);
  }
  const elapsedMs = performance.now() - started;
  const usage = await treeUsage(output);
  const files = tinyFiles + 2;
  process.stdout.write(`${JSON.stringify({
    benchmark: "aark-synthetic-small-files-v1",
    synthetic: true,
    workers,
    files,
    tinyFiles,
    logicalInputBytes,
    elapsedMs: Math.round(elapsedMs),
    filesPerSecond: Math.round((files / (elapsedMs / 1_000)) * 100) / 100,
    peakRssBytes,
    outputLogicalBytes: usage.logicalBytes,
    outputAllocatedBytes: usage.allocatedBytes,
    status: result.status,
    uniqueFindings: result.uniqueFindings,
    occurrences: result.occurrences,
    performance: result.performance,
  }, null, 2)}\n`);
} finally {
  await rm(root, { recursive: true, force: true });
}
