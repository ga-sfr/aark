import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { atomicWriteJson, ensurePrivateDirectory, safeJoin } from "../core/fs-safe.js";
import { safetyBlockedContinuation } from "../workflow/continuation.js";
import { newWorkflowState, WORKFLOW_STATE_FILE } from "../workflow/state.js";
import type { WorkflowConfig } from "../workflow/types.js";
import { planWorkflowUpgrade, runWorkflowUpgrade } from "../workflow/upgrade.js";

const executeFile = promisify(execFile);

test("workflow upgrade validates compatibility, Linux checks, and optional platform tests in a separate checkout", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-upgrade-"));
  const workflowDirectory = path.join(root, "workflow");
  const candidateTool = path.join(root, "candidate");
  await ensurePrivateDirectory(workflowDirectory);
  await mkdir(candidateTool);
  const config: WorkflowConfig = {
    version: 1,
    workflowId: "synthetic-upgrade",
    directory: workflowDirectory,
    stages: [{
      id: "retain",
      kind: "retention",
      miningOutputs: [path.join(root, "mining")],
      destination: path.join(root, "retained"),
      requireReadOnlySources: false,
      storage: { minimumFreeGiB: 0, minimumFreePercent: 0 },
    }],
  };
  const state = newWorkflowState(config);
  const checkpoint = state.stages[0];
  if (checkpoint === undefined) throw new Error("synthetic workflow checkpoint is missing");
  checkpoint.status = "blocked";
  checkpoint.startedAt = state.startedAt;
  state.status = "blocked-safety";
  state.blocker = "synthetic clean boundary";
  state.continuation = safetyBlockedContinuation(state.blocker, "workflow-resume");
  state.process = null;
  await atomicWriteJson(safeJoin(workflowDirectory, WORKFLOW_STATE_FILE), state);

  const candidatePackage = {
    name: "aark",
    version: "9.9.9",
    private: true,
    scripts: {
      check: "node -e \"process.exit(0)\"",
      "test:linux": "node -e \"process.exit(0)\"",
      "test:python": "python3 -c \"import ast; ast.parse('value = 1')\"",
    },
    aarkCheckpointCompatibility: {
      workflow: [1],
      retention: [1],
      miningBatch: [1],
    },
  };
  await writeFile(path.join(candidateTool, "package.json"), `${JSON.stringify(candidatePackage, null, 2)}\n`);
  await writeFile(path.join(candidateTool, "package-lock.json"), `${JSON.stringify({
    name: "aark",
    version: "9.9.9",
    lockfileVersion: 3,
    requires: true,
    packages: { "": { name: "aark", version: "9.9.9" } },
  }, null, 2)}\n`);
  await writeFile(path.join(candidateTool, ".gitignore"), "node_modules/\n");
  await executeFile("git", ["init", "--quiet"], { cwd: candidateTool });
  await executeFile("git", ["add", ".gitignore", "package.json", "package-lock.json"], { cwd: candidateTool });
  await executeFile("git", ["-c", "user.name=AARK Test", "-c", "user.email=aark-test@example.invalid", "commit", "--quiet", "-m", "synthetic candidate"], { cwd: candidateTool });

  const plan = await planWorkflowUpgrade({ workflowDirectory, candidateTool });
  assert.equal(plan.checkpointCompatible, true);
  assert.deepEqual(plan.optionalTests, ["test:linux", "test:python"]);
  const resumeConfig = path.join(root, "workflow.json");
  await writeFile(resumeConfig, `${JSON.stringify(config, null, 2)}\n`);
  const resumePlan = await planWorkflowUpgrade({ workflowDirectory, candidateTool, resumeConfig, executeRecovery: true });
  assert.equal(resumePlan.resumeAfterTests, true);
  assert.equal(resumePlan.executeRecoveryAuthorized, true);
  assert.notEqual(resumePlan.approvalToken, plan.approvalToken);

  const miningWorkflowDirectory = path.join(root, "mining-workflow");
  await ensurePrivateDirectory(miningWorkflowDirectory);
  const miningConfig: WorkflowConfig = {
    version: 1,
    workflowId: "synthetic-mining-upgrade",
    directory: miningWorkflowDirectory,
    stages: [{
      id: "scan",
      kind: "mining-batch",
      inputs: [path.join(root, "closed-segment")],
      output: path.join(root, "mining-output"),
      provenance: "unallocated-carve",
      chunkMiB: 32,
      overlapMiB: 17,
      wholeFileMiB: 64,
      deepKeySchedules: false,
      storage: { minimumFreeGiB: 0, minimumFreePercent: 0 },
      maximumRootsPerBatch: 128,
      maximumFilesPerBatch: 50_000,
      maximumGiBPerBatch: 256,
    }],
  };
  const miningState = newWorkflowState(miningConfig);
  const miningCheckpoint = miningState.stages[0];
  if (miningCheckpoint === undefined) throw new Error("synthetic mining workflow checkpoint is missing");
  miningCheckpoint.status = "blocked";
  miningCheckpoint.startedAt = miningState.startedAt;
  miningState.status = "blocked-safety";
  miningState.blocker = "synthetic paused child scan";
  miningState.continuation = safetyBlockedContinuation(miningState.blocker, "workflow-resume");
  miningState.process = null;
  await atomicWriteJson(safeJoin(miningWorkflowDirectory, WORKFLOW_STATE_FILE), miningState);
  await assert.rejects(
    planWorkflowUpgrade({ workflowDirectory: miningWorkflowDirectory, candidateTool }),
    /checkpoint schema/,
  );

  const result = await runWorkflowUpgrade({
    workflowDirectory,
    candidateTool,
    approvalToken: plan.approvalToken,
    execute: true,
  });
  assert.equal(result.status, "complete");
  assert.equal(result.readyToResume, true);
  assert.equal(result.resumeWorkflowState, null);
  assert.equal(result.resumeBlocker, null);
  assert.deepEqual(result.testsPassed, ["npm ci", "npm run check", "test:linux", "test:python"]);
  await writeFile(path.join(candidateTool, "unexpected.txt"), "untracked\n");
  await assert.rejects(planWorkflowUpgrade({ workflowDirectory, candidateTool }), /tracked or untracked modifications/);
});
