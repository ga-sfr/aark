import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { access, link, mkdir, mkdtemp, readFile, symlink, unlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { scanSensitiveMaterial } from "../mining/scanner.js";
import { planRetention, runRetention } from "../retention.js";
import { planSegmentedCleanup, runSegmentedCleanup } from "../segmented-cleanup.js";

async function missing(filename: string): Promise<boolean> {
  try { await access(filename); return false; } catch { return true; }
}

function syntheticSecret(): string {
  const prefix = ["gh", "p_"].join("");
  return `provider_token=${prefix}ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n`;
}

test("standalone retention deduplicates content while preserving whole source mappings", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-retention-"));
  const inputs = path.join(root, "inputs");
  const mining = path.join(root, "mining");
  const destination = path.join(root, "retained");
  await mkdir(inputs);
  const contents = syntheticSecret();
  await writeFile(path.join(inputs, "one.txt"), contents);
  await writeFile(path.join(inputs, "two.txt"), contents);
  const scan = await scanSensitiveMaterial({
    inputs: [inputs],
    output: mining,
    provenance: "allocated-reference",
    chunkBytes: 17 * 1024 * 1024,
    overlapBytes: 17 * 1024 * 1024,
    wholeFileBytes: 1024 * 1024,
    workers: 1,
    minimumFreeGiB: 0,
    minimumFreePercent: 0,
  });
  assert.equal(scan.status, "complete");
  const plan = await planRetention({
    miningOutputs: [mining],
    destination,
    requireReadOnlySources: false,
    minimumFreeGiB: 0,
    minimumFreePercent: 0,
  });
  assert.equal(plan.sourceFiles, "2");
  assert.equal(plan.contentObjects, "1");
  const result = await runRetention({
    miningOutputs: [mining],
    destination,
    requireReadOnlySources: false,
    minimumFreeGiB: 0,
    minimumFreePercent: 0,
    planToken: plan.planToken,
  });
  assert.equal(result.status, "complete");
  const digest = createHash("sha256").update(contents).digest("hex");
  assert.equal(await readFile(path.join(destination, "objects", digest.slice(0, 2), digest), "utf8"), contents);
  const mapping = JSON.parse(await readFile(path.join(destination, "retention-mapping-sensitive.json"), "utf8")) as { sources: unknown[] };
  assert.equal(mapping.sources.length, 2);
  const orphan = path.join(destination, "objects", digest.slice(0, 2), `${digest}.tmp-2147483647-123e4567-e89b-42d3-a456-426614174000`);
  await writeFile(orphan, "partial object");
  const resumedPlan = await planRetention({
    miningOutputs: [mining],
    destination,
    requireReadOnlySources: false,
    minimumFreeGiB: 0,
    minimumFreePercent: 0,
  });
  await runRetention({
    miningOutputs: [mining],
    destination,
    requireReadOnlySources: false,
    minimumFreeGiB: 0,
    minimumFreePercent: 0,
    planToken: resumedPlan.planToken,
  });
  assert.equal(await missing(orphan), true);
  const otherInputs = path.join(root, "other-inputs");
  const otherMining = path.join(root, "other-mining");
  await mkdir(otherInputs);
  await writeFile(path.join(otherInputs, "different.txt"), `${syntheticSecret()}different-content\n`);
  const otherScan = await scanSensitiveMaterial({
    inputs: [otherInputs],
    output: otherMining,
    provenance: "allocated-reference",
    chunkBytes: 17 * 1024 * 1024,
    overlapBytes: 17 * 1024 * 1024,
    wholeFileBytes: 1024 * 1024,
    workers: 1,
    minimumFreeGiB: 0,
    minimumFreePercent: 0,
  });
  assert.equal(otherScan.status, "complete");
  await assert.rejects(planRetention({
    miningOutputs: [otherMining],
    destination,
    requireReadOnlySources: false,
    minimumFreeGiB: 0,
    minimumFreePercent: 0,
  }), /already bound to a different completed plan/u);
  await writeFile(path.join(destination, "unexpected-user-file"), "do not overwrite\n");
  await assert.rejects(planRetention({
    miningOutputs: [mining],
    destination,
    requireReadOnlySources: false,
    minimumFreeGiB: 0,
    minimumFreePercent: 0,
  }), /unexpected top-level entry/);
});

test("standalone retention publishes and resumes a clean signal pause", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-retention-pause-"));
  const inputs = path.join(root, "inputs");
  const mining = path.join(root, "mining");
  const destination = path.join(root, "retained");
  await mkdir(inputs);
  await writeFile(path.join(inputs, "one.txt"), `${syntheticSecret()}one\n`);
  await writeFile(path.join(inputs, "two.txt"), `${syntheticSecret()}two\n`);
  const scan = await scanSensitiveMaterial({
    inputs: [inputs],
    output: mining,
    provenance: "allocated-reference",
    chunkBytes: 17 * 1024 * 1024,
    overlapBytes: 17 * 1024 * 1024,
    wholeFileBytes: 1024 * 1024,
    workers: 1,
    minimumFreeGiB: 0,
    minimumFreePercent: 0,
  });
  assert.equal(scan.status, "complete");
  const options = {
    miningOutputs: [mining],
    destination,
    requireReadOnlySources: false,
    minimumFreeGiB: 0,
    minimumFreePercent: 0,
  };
  const plan = await planRetention(options);
  const controller = new AbortController();
  const paused = await runRetention({
    ...options,
    planToken: plan.planToken,
    signal: controller.signal,
    progress: (progress) => {
      if (progress.filesCompleted === 1) controller.abort();
    },
  });
  assert.equal(paused.status, "paused");
  assert.equal(paused.resumable, true);
  const progress = JSON.parse(await readFile(path.join(destination, "retention-progress-redacted.json"), "utf8")) as { status: string; planToken: string };
  assert.equal(progress.status, "paused");
  assert.equal(progress.planToken, plan.planToken);
  const resumed = await runRetention({ ...options, planToken: plan.planToken });
  assert.equal(resumed.status, "complete");
});

test("standalone retention revalidates every source before publishing its mapping", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-retention-final-source-check-"));
  const inputs = path.join(root, "inputs");
  const mining = path.join(root, "mining");
  const destination = path.join(root, "retained");
  await mkdir(inputs);
  const first = path.join(inputs, "one.txt");
  await writeFile(first, `${syntheticSecret()}one\n`);
  await writeFile(path.join(inputs, "two.txt"), `${syntheticSecret()}two\n`);
  const scan = await scanSensitiveMaterial({
    inputs: [inputs],
    output: mining,
    provenance: "allocated-reference",
    chunkBytes: 17 * 1024 * 1024,
    overlapBytes: 17 * 1024 * 1024,
    wholeFileBytes: 1024 * 1024,
    workers: 1,
    minimumFreeGiB: 0,
    minimumFreePercent: 0,
  });
  assert.equal(scan.status, "complete");
  const options = {
    miningOutputs: [mining],
    destination,
    requireReadOnlySources: false,
    minimumFreeGiB: 0,
    minimumFreePercent: 0,
  };
  const plan = await planRetention(options);
  await assert.rejects(runRetention({
    ...options,
    planToken: plan.planToken,
    progress: (progress) => {
      if (progress.filesCompleted === progress.filesTotal) writeFileSync(first, "changed after its object was copied\n");
    },
  }), /source changed before retention completion/u);
  assert.equal(await missing(path.join(destination, "retention-mapping-sensitive.json")), true);
});

test("segmented cleanup rejects any retention or mining overlap with an active segment", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-segment-overlap-"));
  const selected = path.join(root, "closed");
  const active = path.join(root, "active");
  await assert.rejects(planSegmentedCleanup({
    segments: [selected],
    activeSegments: [active],
    miningOutputs: [path.join(root, "mining")],
    retentionDirectory: path.join(active, "retained"),
  }), /must not overlap an active segment/);
});

test("segmented cleanup rejects hard links that span independently deleted segments", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-segment-hardlinks-"));
  const one = path.join(root, "one");
  const two = path.join(root, "two");
  const mining = path.join(root, "mining");
  await mkdir(one);
  await mkdir(two);
  const first = path.join(one, "shared.bin");
  const second = path.join(two, "shared.bin");
  await writeFile(first, Buffer.alloc(8192, 7));
  await link(first, second);
  const scan = await scanSensitiveMaterial({
    inputs: [one, two],
    output: mining,
    provenance: "unallocated-carve",
    chunkBytes: 17 * 1024 * 1024,
    overlapBytes: 17 * 1024 * 1024,
    wholeFileBytes: 1024 * 1024,
    workers: 1,
    minimumFreeGiB: 0,
    minimumFreePercent: 0,
  });
  assert.equal(scan.status, "complete");
  await assert.rejects(planSegmentedCleanup({
    segments: [one, two],
    miningOutputs: [mining],
    retentionDirectory: path.join(root, "retained"),
  }), /hard links spanning selected segments/u);
});

test("segmented cleanup preserves active segments and moves finding source files before deletion", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-segment-cleanup-"));
  const closed = path.join(root, "recup_dir.1");
  const active = path.join(root, "recup_dir.2");
  const mining = path.join(root, "mining");
  const retained = path.join(root, "retained");
  await mkdir(closed);
  await mkdir(active);
  await mkdir(retained);
  const contents = syntheticSecret();
  const sensitive = path.join(closed, "sensitive.txt");
  await writeFile(sensitive, contents);
  await link(sensitive, path.join(closed, "sensitive-alias.txt"));
  await writeFile(path.join(closed, "ordinary.txt"), "ordinary\n");
  await writeFile(path.join(active, "still-growing.txt"), "active\n");
  const scan = await scanSensitiveMaterial({
    inputs: [closed],
    output: mining,
    provenance: "unallocated-carve",
    chunkBytes: 17 * 1024 * 1024,
    overlapBytes: 17 * 1024 * 1024,
    wholeFileBytes: 1024 * 1024,
    workers: 1,
    minimumFreeGiB: 0,
    minimumFreePercent: 0,
  });
  assert.equal(scan.status, "complete");
  const options = {
    segments: [closed],
    activeSegments: [active],
    miningOutputs: [mining],
    retentionDirectory: retained,
    errorSourceDisposition: "retain" as const,
  };
  const plan = await planSegmentedCleanup(options);
  assert.equal(plan.selectedClosedSegments, 1);
  assert.equal(plan.activeSegmentsPreserved, 1);
  assert.equal(plan.findingSourceFilesRetained, "2");
  assert.ok(BigInt(plan.deletion.allocatedBytes) >= 0n);
  const outside = path.join(root, "outside-retention");
  const retainedSourcesRoot = path.join(retained, "retained-segment-source-files");
  await mkdir(outside);
  await symlink(outside, retainedSourcesRoot, "dir");
  await assert.rejects(runSegmentedCleanup({
    ...options,
    approvalToken: plan.approvalToken,
    execute: true,
    confirmDeleteSegments: true,
  }), /symbolic-link/u);
  assert.equal(await missing(path.join(outside, plan.approvalToken)), true);
  await unlink(retainedSourcesRoot);
  const result = await runSegmentedCleanup({
    ...options,
    approvalToken: plan.approvalToken,
    execute: true,
    confirmDeleteSegments: true,
  });
  assert.equal(result.status, "complete");
  assert.equal(await missing(closed), true);
  assert.equal(await missing(active), false);
  assert.equal(await readFile(path.join(
    retained,
    "retained-segment-source-files",
    plan.approvalToken,
    "segment-000001",
    "sensitive.txt",
  ), "utf8"), contents);
  assert.equal(await readFile(path.join(
    retained,
    "retained-segment-source-files",
    plan.approvalToken,
    "segment-000001",
    "sensitive-alias.txt",
  ), "utf8"), contents);
  assert.equal(await missing(path.join(
    retained,
    "retained-segment-source-files",
    plan.approvalToken,
    "cleanup-report-sensitive.md",
  )), false);
  assert.equal(await missing(path.join(
    retained,
    "retained-segment-source-files",
    plan.approvalToken,
    "segment-000001",
    "ordinary.txt",
  )), true);
});
