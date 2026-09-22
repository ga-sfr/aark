import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, open, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { main, planRanges } from "./scan-large-file-sharded.mjs";

const MIB = 1024 * 1024;
test("range plans cover both sides of every split, including short final shards", () => {
  const plan = planRanges(64 * MIB + 17, 32 * MIB);
  assert.equal(plan.shards.length, 3);
  assert.equal(plan.shards.reduce((n, range) => n + range.length, 0), 64 * MIB + 17);
  assert.deepEqual(plan.boundaries, [
    { index: 0, start: 15 * MIB, length: 34 * MIB },
    { index: 1, start: 47 * MIB, length: 17 * MIB + 17 },
  ]);
  assert.deepEqual(planRanges(0, 32 * MIB), { shards: [], boundaries: [] });
  assert.throws(() => planRanges(32 * MIB, 32 * MIB, 16 * MIB));
  assert.throws(() => planRanges(Number.MAX_SAFE_INTEGER, 32 * MIB));
});

test("controller finds a split key, verifies restart and refuses changed artifacts or paths", { timeout: 300_000 }, async () => {
  const root = await mkdtemp(path.join(tmpdir(), "aark-shards-test-"));
  const source = path.join(root, "source.raw");
  const output = path.join(root, "output");
  const staging = path.join(root, "staging");
  const { privateKey } = generateKeyPairSync("ed25519");
  const key = Buffer.from(privateKey.export({ format: "pem", type: "pkcs8" }));
  const offset = 32 * MIB - 64;
  const handle = await open(source, "wx");
  try {
    await handle.truncate(32 * MIB + 256);
    await handle.write(key, 0, key.length, offset);
  } finally { await handle.close(); }
  const args = ["--source", source, "--output-root", output, "--staging-root", staging,
    "--provenance", "unknown", "--shard-mib", "32", "--workers", "1"];
  try {
    await main(args);
    const statePath = path.join(output, "shard-controller-sensitive.json");
    const state = JSON.parse(await readFile(statePath, "utf8"));
    assert.equal(state.status, "complete");
    assert.equal(state.boundaryCompleted.length, 1);
    const range = state.boundaryCompleted[0];
    const inventory = JSON.parse(await readFile(path.join(range.output, "inventory-sensitive.json"), "utf8"));
    const finding = inventory.findings.find((item) => item.occurrences.some((entry) => entry.offset + range.start === offset));
    assert.ok(finding, "the key spanning two shards must be recovered at its original offset");
    assert.deepEqual(await readFile(path.join(range.output, finding.artifactFiles[0])), key);
    assert.deepEqual(await readdir(staging), []);
    await main(args);
    assert.equal(JSON.parse(await readFile(statePath, "utf8")).boundaryCompleted.length, 1);
    const substituted = structuredClone(state);
    substituted.completed[0].output = root;
    await writeFile(statePath, JSON.stringify(substituted));
    await assert.rejects(main(args), /range output name|range paths/);
    await writeFile(statePath, JSON.stringify(state));
    await writeFile(path.join(range.output, finding.artifactFiles[0]), Buffer.alloc(key.length));
    await assert.rejects(main(args), /integrity/);
    assert.equal((await readFile(source)).subarray(offset, offset + key.length).equals(key), true);
  } finally { await rm(root, { recursive: true, force: true }); }
});
