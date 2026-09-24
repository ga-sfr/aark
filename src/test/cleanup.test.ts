import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { access, mkdir, readdir, readFile, rename, rm, stat, unlink, writeFile } from "node:fs/promises";
import { mkdtemp } from "./helpers.js";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { planCleanup, runCleanup } from "../cleanup.js";
import { scanSensitiveMaterial } from "../mining/scanner.js";

async function missing(filename: string): Promise<boolean> {
  try {
    await access(filename);
    return false;
  } catch {
    return true;
  }
}

test("cleanup can truthfully plan an explicitly accepted inactive legacy interrupted case", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-cleanup-legacy-test-"));
  const caseRoot = path.join(root, "case");
  const recovery = path.join(caseRoot, "recovery");
  const runs = path.join(caseRoot, "runs");
  const mining = path.join(root, "mining");
  await mkdir(recovery, { recursive: true });
  await mkdir(runs);
  await writeFile(path.join(recovery, "ordinary.txt"), "ordinary recovered data\n");
  const runId = "synthetic-interrupted-run";
  const state = {
    version: 1,
    runId,
    status: "running",
    startedAt: new Date().toISOString(),
    finishedAt: null,
    currentStep: "signature-carving",
    failure: null,
    plan: {
      version: 1,
      destination: caseRoot,
      steps: [
        { id: "inventory", optional: false },
        { id: "signature-carving", optional: false },
      ],
    },
    results: [{ id: "inventory", status: "completed" }],
  };
  await writeFile(path.join(caseRoot, "case-sensitive.json"), `${JSON.stringify(state, null, 2)}\n`);
  await writeFile(path.join(caseRoot, "plan-redacted.json"), "{}\n");
  await writeFile(path.join(runs, `${runId}-sensitive.json`), await readFile(path.join(caseRoot, "case-sensitive.json")));
  await writeFile(path.join(runs, `${runId}-plan-redacted.json`), await readFile(path.join(caseRoot, "plan-redacted.json")));
  const scan = await scanSensitiveMaterial({
    inputs: [recovery],
    output: mining,
    provenance: "unknown",
    chunkBytes: 17 * 1024 * 1024,
    overlapBytes: 17 * 1024 * 1024,
    wholeFileBytes: 1024 * 1024,
    workers: 1,
    minimumFreeGiB: 0,
    minimumFreePercent: 0,
  });
  assert.equal(scan.status, "complete");
  const options = { caseDirectory: caseRoot, miningOutputs: [mining] };
  await assert.rejects(planCleanup(options), /terminal successful AARK recovery case/);
  const plan = await planCleanup({ ...options, acceptInterruptedCase: true });
  assert.equal(plan.recoveryStatus, "legacy-interrupted");
  assert.equal(plan.retained.recoveryFinalReports, false);
  assert.equal(plan.deletion.recoveredCopyIncluded, true);
  assert.equal(plan.sourceFilesRetained, "0");
  assert.match(plan.approvalToken, /^[a-f0-9]{64}$/);
});

test("cleanup requires fresh approval and retains reports, findings, and whole finding-containing source files", {
  skip: !["linux", "win32"].includes(process.platform),
}, async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-cleanup-test-"));
  const caseRoot = path.join(root, "case");
  const recovery = path.join(caseRoot, "recovery");
  const evidence = path.join(caseRoot, "evidence");
  const logs = path.join(caseRoot, "logs");
  const runs = path.join(caseRoot, "runs");
  const mining = path.join(root, "mining");
  await mkdir(recovery, { recursive: true });
  await mkdir(path.join(recovery, "nested", "empty"), { recursive: true });
  await mkdir(evidence);
  await mkdir(logs);
  await mkdir(runs);
  const tokenPrefix = ["gh", "p_"].join("");
  const token = `${tokenPrefix}ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij`;
  const sensitiveSourceContents = `provider_token=${token}\n`;
  const sensitiveEvidenceContents = `synthetic evidence context\nprovider_token=${token}\n`;
  const sensitiveSourcePath = path.join(recovery, "recovered.txt");
  await writeFile(sensitiveSourcePath, sensitiveSourceContents);
  await writeFile(path.join(recovery, "ordinary.txt"), "ordinary recovered data\n");
  const sensitiveEvidencePath = path.join(evidence, "source.img");
  await writeFile(sensitiveEvidencePath, sensitiveEvidenceContents);
  await writeFile(path.join(evidence, "ordinary.img"), randomBytes(1024));
  await writeFile(path.join(logs, "tool-sensitive.log"), "synthetic log\n");
  await writeFile(path.join(runs, "prior-sensitive.json"), "{}\n");

  const runId = "synthetic-complete-run";
  const startedAt = new Date(Date.now() - 1_000).toISOString();
  const finishedAt = new Date().toISOString();
  await writeFile(path.join(caseRoot, "case-sensitive.json"), `${JSON.stringify({
    version: 1,
    runId,
    status: "complete",
    startedAt,
    finishedAt,
    currentStep: null,
    failure: null,
    plan: { version: 1, destination: caseRoot, steps: [] },
    results: [],
  }, null, 2)}\n`);
  await writeFile(path.join(caseRoot, "plan-redacted.json"), "{}\n");
  await writeFile(path.join(caseRoot, "manifest-redacted.json"), `${JSON.stringify({
    tool: "aark",
    layer: "recovery",
    runId,
    status: "complete",
    complete: true,
    finishedAt,
  }, null, 2)}\n`);
  await writeFile(path.join(caseRoot, "final-report-sensitive.md"), "# recovery report\n");
  await writeFile(path.join(caseRoot, "final-report-redacted.md"), "# recovery report (redacted)\n");
  for (const [current, perRun] of [
    ["case-sensitive.json", `${runId}-sensitive.json`],
    ["plan-redacted.json", `${runId}-plan-redacted.json`],
    ["manifest-redacted.json", `${runId}-manifest-redacted.json`],
    ["final-report-sensitive.md", `${runId}-final-report-sensitive.md`],
    ["final-report-redacted.md", `${runId}-final-report-redacted.md`],
  ] as const) await writeFile(path.join(runs, perRun), await readFile(path.join(caseRoot, current)));

  const scan = await scanSensitiveMaterial({
    inputs: [recovery, evidence],
    output: mining,
    provenance: "unknown",
    chunkBytes: 17 * 1024 * 1024,
    overlapBytes: 17 * 1024 * 1024,
    wholeFileBytes: 1024 * 1024,
    workers: 1,
    minimumFreeGiB: 0,
    minimumFreePercent: 0,
  });
  assert.equal(scan.status, "complete");
  const sensitiveSourceIdentity = await stat(sensitiveSourcePath);
  const sensitiveEvidenceIdentity = await stat(sensitiveEvidencePath);

  const options = { caseDirectory: caseRoot, miningOutputs: [mining], includeEvidence: true };
  const retainedBase = path.join(caseRoot, "retained-sensitive-source-files");
  const overlappingMining = path.join(retainedBase, "synthetic-mining-output");
  await mkdir(overlappingMining, { recursive: true });
  await assert.rejects(planCleanup({
    ...options,
    miningOutputs: [overlappingMining],
  }), /reserved retained source-file directory/);
  await rm(retainedBase, { recursive: true });

  await mkdir(retainedBase);
  const firstPlan = await planCleanup(options);
  assert.equal(firstPlan.status, "ready");
  assert.equal(firstPlan.pathsRedacted, true);
  assert.equal(firstPlan.deletion.recoveredCopyIncluded, true);
  assert.equal(firstPlan.deletion.evidenceCopyIncluded, true);
  assert.ok(BigInt(firstPlan.deletion.filesystemEntries) > BigInt(firstPlan.deletion.regularFiles));
  assert.equal(firstPlan.retained.exactFindingArtifacts, true);
  assert.equal(firstPlan.retained.wholeFindingSourceFiles, true);
  assert.equal(firstPlan.sourceFilesRetained, "2");
  assert.equal(firstPlan.sourceFileLogicalBytesRetained, (
    Buffer.byteLength(sensitiveSourceContents) + Buffer.byteLength(sensitiveEvidenceContents)
  ).toString());
  assert.equal(firstPlan.markerOnlyFindingsWithoutArtifacts, "0");
  assert.match(firstPlan.approvalToken, /^[a-f0-9]{64}$/);
  assert.equal(JSON.stringify(firstPlan).includes(caseRoot), false);

  const approvedRetainedBase = path.join(caseRoot, "approved-retained-base");
  await rename(retainedBase, approvedRetainedBase);
  await mkdir(retainedBase);
  await assert.rejects(runCleanup({
    ...options,
    approvalToken: firstPlan.approvalToken,
    execute: true,
    confirmDeleteRecoveredCopy: true,
    confirmDeleteEvidence: true,
  }), /changed after planning/);
  assert.equal(await missing(recovery), false);
  await rm(retainedBase, { recursive: true });
  await rename(approvedRetainedBase, retainedBase);

  const unfinishedQuarantine = path.join(caseRoot, ".aark-cleanup-pending-recovery-synthetic");
  await mkdir(unfinishedQuarantine);
  await assert.rejects(planCleanup(options), /unfinished cleanup quarantine/);
  await rm(unfinishedQuarantine, { recursive: true });

  await assert.rejects(runCleanup({
    ...options,
    approvalToken: firstPlan.approvalToken,
    execute: true,
    confirmDeleteRecoveredCopy: true,
  }), /confirm-delete-evidence/);
  assert.equal(await missing(recovery), false);

  // An empty nested directory is not part of a mining file manifest, but it is
  // still a filesystem entry selected for recursive deletion and must stale
  // the cleanup authorization.
  const unapprovedEmptyDirectory = path.join(recovery, "nested", "added-after-approval");
  await mkdir(unapprovedEmptyDirectory);
  await assert.rejects(runCleanup({
    ...options,
    approvalToken: firstPlan.approvalToken,
    execute: true,
    confirmDeleteRecoveredCopy: true,
    confirmDeleteEvidence: true,
  }), /changed after planning/);
  assert.equal(await missing(unapprovedEmptyDirectory), false);
  await rm(unapprovedEmptyDirectory, { recursive: true });

  const rootRecoveryReport = path.join(caseRoot, "final-report-redacted.md");
  const runRecoveryReport = path.join(runs, `${runId}-final-report-redacted.md`);
  const originalRecoveryReport = await readFile(rootRecoveryReport);
  await writeFile(rootRecoveryReport, "# changed retained report\n");
  await writeFile(runRecoveryReport, "# changed retained report\n");
  await assert.rejects(runCleanup({
    ...options,
    approvalToken: firstPlan.approvalToken,
    execute: true,
    confirmDeleteRecoveredCopy: true,
    confirmDeleteEvidence: true,
  }), /changed after planning/);
  assert.equal(await missing(recovery), false);
  await writeFile(rootRecoveryReport, originalRecoveryReport);
  await writeFile(runRecoveryReport, originalRecoveryReport);

  const recoveryLog = path.join(logs, "tool-sensitive.log");
  await writeFile(recoveryLog, "modified  log\n");
  await assert.rejects(runCleanup({
    ...options,
    approvalToken: firstPlan.approvalToken,
    execute: true,
    confirmDeleteRecoveredCopy: true,
    confirmDeleteEvidence: true,
  }), /changed after planning/);
  assert.equal(await missing(logs), false);

  const changed = path.join(recovery, "not-scanned.bin");
  await writeFile(changed, "changed after approval");
  await assert.rejects(runCleanup({
    ...options,
    approvalToken: firstPlan.approvalToken,
    execute: true,
    confirmDeleteRecoveredCopy: true,
    confirmDeleteEvidence: true,
  }), /changed after scanning|not covered|changed after planning/);
  assert.equal(await missing(recovery), false);
  assert.equal(await missing(path.join(caseRoot, "cleanup-final-report-sensitive.md")), true);
  await unlink(changed);

  // Exercise first-time creation as well as the existing-base approval checks
  // above. The test base is still empty at this point.
  await rm(retainedBase, { recursive: true });
  const approved = await planCleanup(options);
  assert.notEqual(approved.approvalToken, firstPlan.approvalToken);
  const result = await runCleanup({
    ...options,
    approvalToken: approved.approvalToken,
    execute: true,
    confirmDeleteRecoveredCopy: true,
    confirmDeleteEvidence: true,
  });
  assert.equal(result.status, "complete");
  assert.equal(result.sourceFilesRetained, "2");
  assert.equal(await missing(recovery), true);
  assert.equal(await missing(evidence), true);
  assert.equal(await missing(logs), true);
  assert.equal(await missing(runs), true);
  assert.equal(await missing(path.join(caseRoot, "final-report-sensitive.md")), false);
  assert.equal(await missing(path.join(caseRoot, "cleanup-final-report-sensitive.md")), false);
  assert.equal(await missing(path.join(mining, "final-report-sensitive.md")), false);
  assert.equal(await missing(path.join(mining, "inventory-sensitive.json")), false);
  assert.equal(await missing(path.join(mining, "scan-state-sensitive.json")), false);
  const retainedSource = path.join(
    caseRoot,
    "retained-sensitive-source-files",
    approved.approvalToken,
    "recovery",
    "recovered.txt",
  );
  assert.equal(await readFile(retainedSource, "utf8"), sensitiveSourceContents);
  const retainedSourceIdentity = await stat(retainedSource);
  assert.equal(retainedSourceIdentity.dev, sensitiveSourceIdentity.dev);
  if (process.platform !== "win32") assert.equal(retainedSourceIdentity.ino, sensitiveSourceIdentity.ino);
  assert.equal(await missing(path.join(path.dirname(retainedSource), "ordinary.txt")), true);
  const retainedEvidence = path.join(
    caseRoot,
    "retained-sensitive-source-files",
    approved.approvalToken,
    "evidence",
    "source.img",
  );
  assert.equal(await readFile(retainedEvidence, "utf8"), sensitiveEvidenceContents);
  const retainedEvidenceIdentity = await stat(retainedEvidence);
  assert.equal(retainedEvidenceIdentity.dev, sensitiveEvidenceIdentity.dev);
  if (process.platform !== "win32") assert.equal(retainedEvidenceIdentity.ino, sensitiveEvidenceIdentity.ino);
  assert.equal(await missing(path.join(path.dirname(retainedEvidence), "ordinary.img")), true);
  assert.equal((await readdir(caseRoot)).some((entry) => entry.startsWith(".aark-cleanup-pending-")), false);
  const inventory = JSON.parse(await readFile(path.join(mining, "inventory-sensitive.json"), "utf8")) as { findings: unknown[] };
  assert.ok(inventory.findings.length > 0);
});
