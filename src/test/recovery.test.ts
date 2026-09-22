import assert from "node:assert/strict";
import { access, mkdtemp, readFile, readdir, unlink, writeFile } from "node:fs/promises";
import os from "node:os";
import test from "node:test";
import path from "node:path";
import { loadRecoveryConfig } from "../recovery/config.js";
import { buildRecoveryPlan } from "../recovery/plan.js";
import { renderRecoveryRedactedReport, renderRecoverySensitiveReport } from "../recovery/report.js";
import { recoveryStepStatus, redactedPlan, runRecoveryPlan } from "../recovery/runner.js";
import type { SourceSafety } from "../recovery/source-safety.js";
import type { RecoveryConfig } from "../recovery/types.js";

function config(): RecoveryConfig {
  return {
    version: 1,
    caseId: "synthetic-case",
    source: "/dev/source-test",
    destination: "/mnt/destination-test/case",
    requireReadOnlySource: true,
    execute: false,
    sectorOffset: 2048,
    photoRecCommand: "partition_none,fileopt,everything,enable,search",
    image: { enabled: false, path: "/mnt/destination-test/source.img", mapfile: "/mnt/destination-test/source.map", retryPasses: 3 },
    stages: {
      deletedMetadata: true,
      ntfsUndelete: false,
      unallocatedStream: true,
      signatureCarving: true,
      volumeShadows: false,
      residualMemory: false,
      deletedRegistryCells: false,
    },
  };
}

test("recovery plan selects deleted/unallocated modes and redacts local paths", { skip: process.platform === "win32" }, () => {
  const plan = buildRecoveryPlan(config());
  assert.equal(plan.requireReadOnlySource, true);
  assert.deepEqual(plan.storage, { minFreeGiB: 5, minFreePercent: 5 });
  const tsk = plan.steps.find((step) => step.executable === "tsk_recover");
  assert.ok(tsk);
  assert.equal(tsk.args.includes("-e"), false);
  const blkls = plan.steps.find((step) => step.executable === "blkls");
  assert.ok(blkls?.args.includes("-A"));
  const photoRec = plan.steps.find((step) => step.executable === "photorec");
  assert.ok(photoRec?.args.includes(path.join(config().destination, "recovery", "unallocated", "free-space.raw")));
  assert.equal(photoRec?.args.some((arg) => arg.includes("freespace")), false);

  const rendered = JSON.stringify(redactedPlan(plan));
  assert.equal(rendered.includes(config().source), false);
  assert.equal(rendered.includes(config().destination), false);
  assert.equal(rendered.includes(config().caseId), false);
  assert.ok(rendered.includes("<SOURCE>"));
  assert.ok(rendered.includes("<CASE_ROOT>"));
  assert.match(rendered, /"requireReadOnlySource":true/);

  const weakened = config();
  weakened.requireReadOnlySource = false;
  assert.notDeepEqual(buildRecoveryPlan(weakened), plan);
});

test("recovery plan uses supported ddrescue and ntfsundelete options", () => {
  const input = config();
  input.image.enabled = true;
  input.stages.ntfsUndelete = true;
  const plan = buildRecoveryPlan(input);

  const retry = plan.steps.find((step) => step.id === "image-retry-pass");
  assert.ok(retry);
  assert.ok(retry.args.includes("--idirect"));
  assert.equal(retry.args.includes("--direct"), false);

  const ntfsScan = plan.steps.find((step) => step.id === "ntfs-undelete-scan");
  assert.ok(ntfsScan);
  assert.ok(ntfsScan.args.includes("--parent"));
  assert.ok(ntfsScan.args.includes("--verbose"));

  const ntfsRecover = plan.steps.find((step) => step.id === "ntfs-undelete-recover");
  assert.ok(ntfsRecover);
  assert.ok(ntfsRecover.args.includes("--match"));
  assert.equal(ntfsRecover.args.includes("--percentage"), false);
  assert.deepEqual(ntfsRecover.partialSuccessExitCodes, [1]);
  assert.equal(recoveryStepStatus(ntfsRecover, 0, false), "completed");
  assert.equal(recoveryStepStatus(ntfsRecover, 1, true), "completed-with-warnings");
  assert.equal(recoveryStepStatus(ntfsRecover, 1, false), "failed");
  assert.equal(recoveryStepStatus(ntfsScan, 1, true), "failed");
});

test("redacted plans also hide mounted source-volume paths", () => {
  const input = config();
  input.mountedReadOnlyRoot = "/mnt/recovered-user-profile";
  input.stages.residualMemory = true;
  input.stages.deletedRegistryCells = true;
  const rendered = JSON.stringify(redactedPlan(buildRecoveryPlan(input)));
  assert.equal(rendered.includes(input.mountedReadOnlyRoot), false);
  assert.ok(rendered.includes("<LOCAL_PATH>"));
});

test("shipped recovery example parses into a reviewable dry-run plan", async () => {
  const loaded = await loadRecoveryConfig(path.join(process.cwd(), "examples", "recovery-case.example.json"));
  const plan = buildRecoveryPlan(loaded);
  assert.equal(loaded.execute, false);
  assert.ok(plan.steps.length >= 5);
});

test("recovery final reports locate restored outputs while the shareable version omits paths", { skip: process.platform === "win32" }, () => {
  const input = config();
  const plan = buildRecoveryPlan(input);
  const sensitiveStdoutLog = "/synthetic/private/step.stdout-sensitive.log";
  const results = plan.steps.map((step, index) => ({
    id: step.id,
    status: "completed",
    durationMs: 1,
    ...(index === 0 ? { stdoutLog: sensitiveStdoutLog } : {}),
  }));
  const safety: SourceSafety = {
    resolvedSource: input.source,
    kind: "block-device",
    bytes: 1024,
    regularFileIdentity: null,
    blockDeviceIdentity: { device: 1, inode: 2, rawDevice: 3 },
    kernelReadOnly: true,
    writableMounts: [],
    sourceTopDevices: ["/dev/source-physical-test"],
    sourceTopDevice: "/dev/source-physical-test",
    destinationDevices: ["/dev/destination-physical-test"],
    destinationDevice: "/dev/destination-physical-test",
    destinationFilesystemDevice: 200,
    destinationMountSource: "/dev/destination-partition-test",
    destinationBackingKind: "block-device",
    deviceComparisonCertain: true,
    destinationOnSourceDevice: false,
    safe: true,
    reasons: [],
  };
  const sensitive = renderRecoverySensitiveReport(plan, results, safety, true, "2026-01-01T00:00:00.000Z", "complete", "synthetic-run");
  const redacted = renderRecoveryRedactedReport(plan, results, true, "2026-01-01T00:00:00.000Z", "complete", "synthetic-run");
  assert.ok(sensitive.includes(path.join(input.destination, "recovery")));
  assert.ok(sensitive.includes(input.source));
  assert.ok(sensitive.includes("deleted-metadata-recover"));
  assert.ok(sensitive.includes(sensitiveStdoutLog));
  assert.equal(redacted.includes(input.source), false);
  assert.equal(redacted.includes(input.destination), false);
  assert.equal(redacted.includes(input.caseId), false);
  assert.equal(redacted.includes(sensitiveStdoutLog), false);
  assert.match(redacted, /Recovery stage results/);
});

test("recovery config rejects typos, coercion, and allocated-space carving", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agetnic-config-test-"));
  const filename = path.join(root, "case.json");
  const valid = {
    version: 1,
    caseId: "strict-case",
    source: "/dev/source-test",
    destination: "/mnt/destination-test/strict-case",
    execute: false,
    stages: { signatureCarving: true },
  };

  await writeFile(filename, JSON.stringify({ ...valid, storage: { minFreeGiB: 1.001, minFreePercent: 1.15, maxOutputGiB: 100.003 } }));
  assert.deepEqual((await loadRecoveryConfig(filename)).storage, { minFreeGiB: 1.001, minFreePercent: 1.15, maxOutputGiB: 100.003 });

  await writeFile(filename, JSON.stringify({ ...valid, stages: { signatureCarvin: false } }));
  await assert.rejects(loadRecoveryConfig(filename), /unknown field/);

  await writeFile(filename, JSON.stringify({ ...valid, execute: "false" }));
  await assert.rejects(loadRecoveryConfig(filename), /execute must be a boolean/);

  await writeFile(filename, JSON.stringify({ ...valid, sectorOffset: "2048" }));
  await assert.rejects(loadRecoveryConfig(filename), /sectorOffset must be an integer/);

  await writeFile(filename, JSON.stringify({ ...valid, storage: { minFreePercent: 101 } }));
  await assert.rejects(loadRecoveryConfig(filename), /storage.minFreePercent/);

  await writeFile(filename, JSON.stringify({ ...valid, storage: { minFreePercent: 5.001 } }));
  await assert.rejects(loadRecoveryConfig(filename), /two decimal places/);

  await writeFile(filename, JSON.stringify({ ...valid, storage: { maxOutputGiB: 0 } }));
  await assert.rejects(loadRecoveryConfig(filename), /storage.maxOutputGiB/);

  await writeFile(filename, JSON.stringify({ ...valid, destination: "/" }));
  await assert.rejects(loadRecoveryConfig(filename), /dedicated case directory/);

  await writeFile(filename, JSON.stringify({ ...valid, destination: "/mnt/destination-test/control\ncharacter" }));
  await assert.rejects(loadRecoveryConfig(filename), /control characters/);

  await writeFile(filename, JSON.stringify({ ...valid, source: "/mnt/destination-test/strict-case/evidence/source.img" }));
  await assert.rejects(loadRecoveryConfig(filename), /source must not be stored inside/);

  await writeFile(filename, JSON.stringify({ ...valid, source: "/mnt/destination-test/strict-case/..source.img" }));
  await assert.rejects(loadRecoveryConfig(filename), /source must not be stored inside/);

  await writeFile(filename, JSON.stringify({ ...valid, analysisSource: "/mnt/destination-test/strict-case/recovery/unallocated/free-space.raw" }));
  await assert.rejects(loadRecoveryConfig(filename), /reserved evidence directory/);

  await writeFile(filename, JSON.stringify({ ...valid, analysisSource: "/mnt/destination-test/strict-case/evidence/source.map" }));
  await assert.rejects(loadRecoveryConfig(filename), /overlap the ddrescue mapfile/);

  await writeFile(filename, JSON.stringify({ ...valid, mountedReadOnlyRoot: "/mnt/destination-test/strict-case/mounted" }));
  await assert.rejects(loadRecoveryConfig(filename), /must not contain one another/);

  await writeFile(filename, JSON.stringify({
    ...valid,
    image: { enabled: true, path: "/mnt/destination-test/strict-case/case-sensitive.json", mapfile: "/mnt/destination-test/strict-case/evidence/source.map" },
  }));
  await assert.rejects(loadRecoveryConfig(filename), /case evidence directory/);

  await writeFile(filename, JSON.stringify({
    ...valid,
    image: { enabled: true, path: "/mnt/destination-test/strict-case/evidence/image", mapfile: "/mnt/destination-test/strict-case/evidence/image/source.map" },
  }));
  await assert.rejects(loadRecoveryConfig(filename), /must not contain one another/);

  await writeFile(filename, JSON.stringify({ ...valid, photoRecCommand: "partition_none,search,extra" }));
  await assert.rejects(loadRecoveryConfig(filename), /begin with partition_none, end with search/);

  await writeFile(filename, JSON.stringify({ ...valid, photoRecCommand: "partition_none,search", stages: { signatureCarving: true, unallocatedStream: false } }));
  await assert.rejects(loadRecoveryConfig(filename), /signatureCarving requires unallocatedStream/);
});

test("recovery completion and interruption both produce sensitive and redacted final reports", { skip: process.platform === "win32" }, async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agetnic-recovery-run-test-"));
  const source = path.join(root, "source.img");
  await writeFile(source, Buffer.alloc(4096));
  const makeConfig = (destination: string): RecoveryConfig => ({
    ...config(),
    source,
    destination,
    execute: true,
    sectorOffset: 0,
    image: { enabled: false, path: path.join(destination, "evidence", "source.img"), mapfile: path.join(destination, "evidence", "source.map"), retryPasses: 0 },
    stages: {
      deletedMetadata: false,
      ntfsUndelete: false,
      unallocatedStream: false,
      signatureCarving: false,
      volumeShadows: false,
      residualMemory: false,
      deletedRegistryCells: false,
    },
  });

  const completeDestination = path.join(root, "complete-case");
  const completeConfig = makeConfig(completeDestination);
  const result = await runRecoveryPlan(completeConfig, buildRecoveryPlan(completeConfig), true);
  assert.equal(result.status, "complete");
  assert.match(await readFile(path.join(completeDestination, "final-report-sensitive.md"), "utf8"), /Status: complete/);
  const completeRedacted = await readFile(path.join(completeDestination, "final-report-redacted.md"), "utf8");
  assert.match(completeRedacted, /Status: complete/);
  assert.equal(completeRedacted.includes(completeConfig.caseId), false);
  assert.ok((await readdir(path.join(completeDestination, "runs"))).some((filename) => filename.endsWith("-final-report-sensitive.md")));
  await assert.rejects(access(path.join(completeDestination, ".aark-recovery.lock")));

  const redactedPlanPath = path.join(completeDestination, "plan-redacted.json");
  const storedRedactedPlan = await readFile(redactedPlanPath);
  await writeFile(redactedPlanPath, "{\"corrupted\":true}\n");
  await assert.rejects(runRecoveryPlan(completeConfig, buildRecoveryPlan(completeConfig), true), /corrupted redacted plan marker/);
  await writeFile(redactedPlanPath, storedRedactedPlan);

  const mismatchedConfig = { ...completeConfig, caseId: "different-case" };
  await assert.rejects(
    runRecoveryPlan(mismatchedConfig, buildRecoveryPlan(mismatchedConfig), true),
    /belongs to a different/,
  );
  await assert.rejects(
    runRecoveryPlan(completeConfig, buildRecoveryPlan(completeConfig), true),
    /only be reused for its explicitly resumable ddrescue quota pause/,
  );
  const lockPath = path.join(completeDestination, ".aark-recovery.lock");
  await writeFile(lockPath, "synthetic stale lock");
  await assert.rejects(runRecoveryPlan(completeConfig, buildRecoveryPlan(completeConfig), true), /exclusive lock/);
  await unlink(lockPath);
  const legacyLockPath = path.join(completeDestination, ".agetnic-recovery.lock");
  await writeFile(legacyLockPath, "synthetic stale legacy lock");
  await assert.rejects(runRecoveryPlan(completeConfig, buildRecoveryPlan(completeConfig), true), /exclusive lock/);
  await unlink(legacyLockPath);

  const interruptedDestination = path.join(root, "interrupted-case");
  const interruptedConfig = makeConfig(interruptedDestination);
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(runRecoveryPlan(interruptedConfig, buildRecoveryPlan(interruptedConfig), true, controller.signal), /interrupted/);
  assert.match(await readFile(path.join(interruptedDestination, "final-report-sensitive.md"), "utf8"), /Status: interrupted/);
  assert.match(await readFile(path.join(interruptedDestination, "final-report-redacted.md"), "utf8"), /Status: interrupted/);
  await assert.rejects(access(path.join(interruptedDestination, ".aark-recovery.lock")));
  await assert.rejects(access(path.join(interruptedDestination, ".agetnic-recovery.lock")));
});
