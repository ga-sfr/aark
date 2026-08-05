import assert from "node:assert/strict";
import { existsSync, unlinkSync } from "node:fs";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { acquireExclusiveLock, atomicWriteJson, ensurePrivateDirectory, safeJoin } from "../core/fs-safe.js";
import { captureProcessIdentity, isProcessIdentity, probeProcess, processExistence, processIdentityMatch } from "../core/process-identity.js";
import { directoryUsage } from "../core/storage.js";
import { runMiningBatch } from "../mining/batch.js";
import { stableBlockDeviceKeys } from "../recovery/source-safety.js";
import { planRetention } from "../retention.js";
import { continuation, invariantFailureContinuation, runningContinuation } from "../workflow/continuation.js";
import { loadWorkflowConfig, workflowConfigHash } from "../workflow/config.js";
import { runWorkflowUntilBlocked } from "../workflow/controller.js";
import type { WorkflowDependencies } from "../workflow/controller.js";
import { newWorkflowState, WORKFLOW_STATE_FILE } from "../workflow/state.js";
import { workflowStatus } from "../workflow/status.js";
import type { WorkflowConfig } from "../workflow/types.js";

function workflow(root: string, minimumFreeGiB = 0): WorkflowConfig {
  return {
    version: 1,
    workflowId: "synthetic-continuity",
    directory: path.join(root, "workflow"),
    stages: [
      {
        id: "retain",
        kind: "retention",
        miningOutputs: [path.join(root, "mining")],
        destination: path.join(root, "retained"),
        requireReadOnlySources: false,
        storage: { minimumFreeGiB, minimumFreePercent: 0 },
      },
      {
        id: "approval-gate",
        kind: "cleanup-plan",
        caseDirectory: path.join(root, "case"),
        miningOutputs: [path.join(root, "mining")],
        includeEvidence: false,
      },
    ],
  };
}

function dependencies(calls: string[]): WorkflowDependencies {
  return {
    runRecovery: async () => { calls.push("recovery"); return { status: "complete", complete: true }; },
    runMiningBatch: async () => { calls.push("mining"); return { status: "complete", complete: true }; },
    planRetention: async () => {
      calls.push("retention-plan");
      return {
        version: 1,
        tool: "aark",
        layer: "retention",
        status: "ready",
        destructive: false,
        pathsRedacted: true,
        valuesPrinted: false,
        miningScansVerified: 1,
        sourceFiles: "1",
        sourceLogicalBytes: "10",
        sourceAllocatedBytes: "4096",
        contentObjects: "1",
        deduplicatedLogicalBytes: "10",
        allSourcesReadOnly: true,
        planToken: "a".repeat(64),
        approvalRequired: false,
        resumable: true,
      };
    },
    runRetention: async () => {
      calls.push("retention-run");
      return { status: "complete", complete: true, sourceFilesRetained: "1", contentObjects: "1" };
    },
    planCleanup: async () => {
      calls.push("cleanup-plan");
      return { status: "ready", approvalToken: "b".repeat(64), miningScansVerified: 1 };
    },
    planSegmentedCleanup: async () => {
      calls.push("segmented-plan");
      return { status: "ready", approvalToken: "c".repeat(64) };
    },
  };
}

test("workflow controller immediately chains safe stages and stops at approval", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-workflow-continuity-"));
  const calls: string[] = [];
  const result = await runWorkflowUntilBlocked(workflow(root), { executeRecovery: false }, dependencies(calls));
  assert.deepEqual(calls, ["retention-plan", "retention-run", "cleanup-plan"]);
  assert.equal(result.workflowState, "blocked-user");
  assert.equal(result.requiresUserInput, true);
  assert.equal(result.genuinelyRunning, false);
  assert.equal(result.currentStage, 1);
  assert.equal((result.stages as Array<{ status: string }>)[0]?.status, "complete");
  assert.equal((result.stages as Array<{ status: string }>)[1]?.status, "blocked");
});

test("workflow checkpoints bind the validated nested recovery configuration", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-workflow-recovery-config-"));
  const recoveryPath = path.join(root, "recovery.json");
  const workflowPath = path.join(root, "workflow.json");
  const recovery = JSON.parse(await readFile(path.join(process.cwd(), "examples", "recovery-case.example.json"), "utf8")) as Record<string, unknown>;
  await writeFile(recoveryPath, `${JSON.stringify(recovery, null, 2)}\n`);
  await writeFile(workflowPath, `${JSON.stringify({
    version: 1,
    workflowId: "bound-recovery-config",
    directory: path.join(root, "state"),
    stages: [{ id: "recover", kind: "recovery", config: recoveryPath }],
  }, null, 2)}\n`);
  const reviewed = await loadWorkflowConfig(workflowPath);
  const reviewedStage = reviewed.stages[0];
  assert.equal(reviewedStage?.kind, "recovery");
  assert.match(reviewedStage?.kind === "recovery" ? reviewedStage.configSha256 ?? "" : "", /^[a-f0-9]{64}$/u);
  await ensurePrivateDirectory(reviewed.directory);
  await atomicWriteJson(safeJoin(reviewed.directory, WORKFLOW_STATE_FILE), newWorkflowState(reviewed));

  recovery.caseId = "changed-after-review";
  await writeFile(recoveryPath, `${JSON.stringify(recovery, null, 2)}\n`);
  const changed = await loadWorkflowConfig(workflowPath);
  assert.notEqual(workflowConfigHash(changed), workflowConfigHash(reviewed));
  await assert.rejects(
    runWorkflowUntilBlocked(changed, { executeRecovery: true }, dependencies([])),
    /configuration changed|another configuration/u,
  );
});

test("controller restart advances from a durable pending-stage boundary", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-workflow-restart-"));
  const config = workflow(root);
  await ensurePrivateDirectory(config.directory);
  const state = newWorkflowState(config);
  state.currentStage = 1;
  const first = state.stages[0];
  if (first === undefined) throw new Error("synthetic stage missing");
  first.status = "complete";
  first.startedAt = state.startedAt;
  first.finishedAt = state.startedAt;
  first.summary = { status: "complete" };
  state.continuation = runningContinuation("workflow-next-stage");
  state.process = null;
  await atomicWriteJson(safeJoin(config.directory, WORKFLOW_STATE_FILE), state);
  const calls: string[] = [];
  const result = await runWorkflowUntilBlocked(config, { executeRecovery: false }, dependencies(calls));
  assert.deepEqual(calls, ["cleanup-plan"]);
  assert.equal(result.workflowState, "blocked-user");
});

test("controller restart re-enters an interrupted durable stage only after its prior process is proven dead", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-workflow-interrupted-"));
  const config = workflow(root);
  await ensurePrivateDirectory(config.directory);
  const state = newWorkflowState(config);
  const current = state.stages[0];
  if (current === undefined) throw new Error("synthetic stage missing");
  current.status = "running";
  current.startedAt = state.startedAt;
  current.activeSince = state.startedAt;
  state.process = {
    version: 1,
    pid: 2_147_483_647,
    processGroup: 1,
    kernelStartTicks: "1",
    executableDevice: "1",
    executableInode: "1",
    commandSha256: "a".repeat(64),
    bootIdSha256: "b".repeat(64),
  };
  state.continuation = runningContinuation("retention");
  await atomicWriteJson(safeJoin(config.directory, WORKFLOW_STATE_FILE), state);
  const calls: string[] = [];
  const result = await runWorkflowUntilBlocked(config, { executeRecovery: false }, dependencies(calls));
  assert.deepEqual(calls, ["retention-plan", "retention-run", "cleanup-plan"]);
  assert.equal(result.workflowState, "blocked-user");
  assert.ok(Number((result.stages as Array<{ activeMilliseconds: number }>)[0]?.activeMilliseconds) >= 0);
});

test("last-stage completion is committed atomically as terminal", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-workflow-terminal-"));
  const config = workflow(root);
  config.stages = [config.stages[0] as WorkflowConfig["stages"][number]];
  const calls: string[] = [];
  const result = await runWorkflowUntilBlocked(config, { executeRecovery: false }, dependencies(calls));
  assert.deepEqual(calls, ["retention-plan", "retention-run"]);
  assert.equal(result.status, "terminal");
  assert.equal(result.workflowState, "terminal");
  const persisted = JSON.parse(await readFile(path.join(config.directory, WORKFLOW_STATE_FILE), "utf8")) as {
    status: string;
    currentStage: number;
    continuation: { workflowState: string };
  };
  assert.equal(persisted.status, "terminal");
  assert.equal(persisted.currentStage, 1);
  assert.equal(persisted.continuation.workflowState, "terminal");
});

test("status publication failure cannot roll back a durably completed stage", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-workflow-status-boundary-"));
  const config = workflow(root);
  const calls: string[] = [];
  const injected = dependencies(calls);
  injected.runRetention = async () => {
    calls.push("retention-run");
    const { mkdir, rm } = await import("node:fs/promises");
    const statusFile = path.join(config.directory, "workflow-status-redacted.json");
    await rm(statusFile);
    await mkdir(statusFile);
    return { status: "complete", complete: true, sourceFilesRetained: "1", contentObjects: "1" };
  };
  await assert.rejects(runWorkflowUntilBlocked(config, { executeRecovery: false }, injected), /output destination|directory/u);
  const persisted = JSON.parse(await readFile(path.join(config.directory, WORKFLOW_STATE_FILE), "utf8")) as {
    status: string;
    currentStage: number;
    stages: Array<{ status: string }>;
    process: unknown;
  };
  assert.equal(persisted.status, "running");
  assert.equal(persisted.currentStage, 1);
  assert.deepEqual(persisted.stages.map((stage) => stage.status), ["complete", "pending"]);
  const { rm } = await import("node:fs/promises");
  await rm(path.join(config.directory, "workflow-status-redacted.json"), { recursive: true });
  // The production restart is a new CLI process. Model that boundary even
  // though node:test invokes both controller calls inside one process.
  persisted.process = {
    version: 1,
    pid: 2_147_483_647,
    processGroup: 1,
    kernelStartTicks: "1",
    executableDevice: "1",
    executableInode: "1",
    commandSha256: "a".repeat(64),
    bootIdSha256: "b".repeat(64),
  };
  await atomicWriteJson(path.join(config.directory, WORKFLOW_STATE_FILE), persisted);
  const resumedCalls: string[] = [];
  const resumed = await runWorkflowUntilBlocked(config, { executeRecovery: false }, dependencies(resumedCalls));
  assert.deepEqual(resumedCalls, ["cleanup-plan"]);
  assert.equal(resumed.workflowState, "blocked-user");
});

test("status reports an invariant failure for idle running state", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-workflow-idle-"));
  const config = workflow(root);
  await ensurePrivateDirectory(config.directory);
  const state = newWorkflowState(config);
  const current = state.stages[0];
  if (current === undefined) throw new Error("synthetic stage missing");
  current.status = "running";
  current.summary = { unexpectedPath: "/private/source/path" } as unknown as typeof current.summary;
  state.process = null;
  state.continuation = runningContinuation("retention");
  state.capacity = {
    availableBytes: "10",
    totalBytes: "20",
    reservedBytes: "5",
    reserveSatisfied: true,
    unexpectedPath: "/private/capacity/path",
  } as unknown as typeof state.capacity;
  await atomicWriteJson(safeJoin(config.directory, WORKFLOW_STATE_FILE), state);
  const result = await workflowStatus(config.directory);
  assert.equal(result.workflowState, "invariant-failure");
  assert.equal(result.genuinelyRunning, false);
  assert.match(String(result.blocker), /not currently verifiable/);
  assert.equal(Object.hasOwn(result.capacity as object, "unexpectedPath"), false);
  assert.equal(Object.hasOwn((result.stages as Array<{ summary: object }>)[0]?.summary ?? {}, "unexpectedPath"), false);
});

test("capacity safety stops before an authorized stage is invoked", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-workflow-capacity-"));
  const calls: string[] = [];
  const result = await runWorkflowUntilBlocked(workflow(root, 1_000_000), { executeRecovery: false }, dependencies(calls));
  assert.deepEqual(calls, []);
  assert.equal(result.workflowState, "blocked-safety");
  assert.equal(result.safeToAutoContinue, false);
});

test("a resumably paused retention stage cannot be marked complete or auto-advanced", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-workflow-retention-pause-"));
  const calls: string[] = [];
  const injected = dependencies(calls);
  injected.runRetention = async () => {
    calls.push("retention-run");
    return { status: "paused", complete: false, resumable: true, filesCompleted: 1, filesTotal: 2, bytesCopied: "10" };
  };
  const result = await runWorkflowUntilBlocked(workflow(root), { executeRecovery: false }, injected);
  assert.deepEqual(calls, ["retention-plan", "retention-run"]);
  assert.equal(result.workflowState, "blocked-safety");
  assert.equal(result.currentStage, 0);
  assert.equal((result.stages as Array<{ status: string }>)[0]?.status, "blocked");
});

test("process identity treats EPERM as existing and detects the current process", async () => {
  const denied = Object.assign(new Error("denied"), { code: "EPERM" });
  assert.equal(processExistence(123, () => { throw denied; }), "exists-unauthorized");
  const identity = await captureProcessIdentity();
  const probe = await probeProcess(identity);
  assert.equal(probe.existence, "exists");
  assert.equal(probe.identityMatches, true);
  assert.equal(isProcessIdentity({ version: 1, pid: 1 }), false);
  assert.equal(processIdentityMatch(identity, { ...identity, commandSha256: "c".repeat(64) }), null);
  assert.equal(processIdentityMatch(identity, { ...identity, kernelStartTicks: `${BigInt(identity.kernelStartTicks ?? "0") + 1n}` }), false);
  assert.deepEqual(stableBlockDeviceKeys([
    { path: "/dev/synthetic-partition", serial: null, wwn: null, filesystemUuid: "filesystem-uuid" },
  ]), ["uuid:filesystem-uuid"]);
});

test("continuation checkpoints reject unsupported states and missing runtime fields", () => {
  assert.throws(() => continuation({
    workflowState: "unsupported" as "running",
    requiresUserInput: false,
    safeToAutoContinue: false,
    nextAction: null,
    activeProcessExpected: false,
    blocker: null,
  }), /unsupported/);
  assert.throws(() => continuation({
    workflowState: "blocked-safety",
    requiresUserInput: false,
    safeToAutoContinue: false,
    nextAction: undefined as unknown as null,
    activeProcessExpected: false,
    blocker: "blocked",
  }), /action/);
});

test("dead-owner lock reclamation is identity-bound and never steals a live lock", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-dead-lock-"));
  const { writeFile } = await import("node:fs/promises");
  const filename = ".synthetic.lock";
  await writeFile(path.join(root, filename), `${JSON.stringify({
    version: 2,
    pid: 2_147_483_647,
    startedAt: new Date(0).toISOString(),
    processIdentity: {
      version: 1,
      pid: 2_147_483_647,
      processGroup: 1,
      kernelStartTicks: "1",
      executableDevice: "1",
      executableInode: "1",
      commandSha256: "a".repeat(64),
      bootIdSha256: "b".repeat(64),
    },
  })}\n`);
  const attempts = await Promise.allSettled([
    acquireExclusiveLock(root, filename, { reclaimDeadOwner: true }),
    acquireExclusiveLock(root, filename, { reclaimDeadOwner: true }),
  ]);
  const acquired = attempts.filter((result): result is PromiseFulfilledResult<Awaited<ReturnType<typeof acquireExclusiveLock>>> => result.status === "fulfilled");
  assert.equal(acquired.length, 1);
  const reclaimed = acquired[0]?.value;
  if (reclaimed === undefined) throw new Error("synthetic dead lock was not reclaimed");
  await assert.rejects(acquireExclusiveLock(root, filename, { reclaimDeadOwner: true }), /already exists/);
  await reclaimed.release();
});

test("directory usage reports allocated bytes and an allocation unit", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-usage-"));
  await import("node:fs/promises").then(async ({ writeFile }) => await writeFile(path.join(root, "tiny"), "x"));
  const usage = await directoryUsage(root);
  assert.equal(usage.logicalBytes, 1n);
  assert.ok(usage.allocatedBytes >= usage.logicalBytes);
  assert.ok(usage.allocationUnitBytes > 0n);
});

test("native mining batch automatically advances child scans and globally consolidates", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-mining-batch-"));
  const { mkdir, writeFile } = await import("node:fs/promises");
  const one = path.join(root, "one");
  const two = path.join(root, "two");
  await mkdir(one);
  await mkdir(two);
  const providerPrefix = ["gh", "p_"].join("");
  await writeFile(path.join(one, "sensitive.txt"), `provider_token=${providerPrefix}ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n`);
  await writeFile(path.join(two, "ordinary.txt"), "ordinary two\n");
  const batchOutput = path.join(root, "batch-output");
  const batchOptions = {
    inputs: [one, two],
    output: batchOutput,
    provenance: "unknown" as const,
    chunkBytes: 17 * 1024 * 1024,
    overlapBytes: 17 * 1024 * 1024,
    wholeFileBytes: 1024 * 1024,
    workers: 1,
    minimumFreeGiB: 0,
    minimumFreePercent: 0,
    maximumRootsPerBatch: 1,
    maximumFilesPerBatch: 1,
    maximumBytesPerBatch: 1024 * 1024,
  };
  const result = await runMiningBatch(batchOptions);
  assert.equal(result.status, "complete");
  assert.equal(result.batchesCompleted, 2);
  assert.equal(result.rootsCompleted, 2);
  assert.equal(result.globallyDeduplicatedFindings, 1);
  const retention = await planRetention({
    miningOutputs: [batchOutput],
    destination: path.join(root, "retained"),
    requireReadOnlySources: false,
    minimumFreeGiB: 0,
    minimumFreePercent: 0,
  });
  assert.equal(retention.miningScansVerified, 2);

  // A controller signal that lands after one completed child and before the
  // next child begins must publish a clean, ownerless pause rather than leave
  // the batch checkpoint marked as running.
  const stateFilename = path.join(batchOutput, "batch-state-sensitive.json");
  const aggregateFilename = path.join(batchOutput, "batch-aggregate-sensitive.json");
  const boundaryState = JSON.parse(await readFile(stateFilename, "utf8")) as {
    status: string;
    nextUnit: number;
    active: unknown;
    completed: Array<{
      index: number;
      firstUnit: number;
      nextUnit: number;
      filesScanned: number;
      bytesScanned: number;
      uniqueFindings: number;
      occurrences: number;
    }>;
    totals: {
      filesTotal: number;
      filesScanned: number;
      bytesScanned: number;
      uniqueFindings: number;
      occurrences: number;
    };
  };
  const firstCompleted = boundaryState.completed[0];
  if (firstCompleted === undefined) throw new Error("synthetic first batch is missing");
  boundaryState.completed = [firstCompleted];
  boundaryState.nextUnit = firstCompleted.nextUnit;
  boundaryState.active = null;
  boundaryState.status = "running";
  boundaryState.totals.filesScanned = firstCompleted.filesScanned;
  boundaryState.totals.bytesScanned = firstCompleted.bytesScanned;
  boundaryState.totals.uniqueFindings = firstCompleted.uniqueFindings;
  boundaryState.totals.occurrences = firstCompleted.occurrences;
  await writeFile(stateFilename, `${JSON.stringify(boundaryState, null, 2)}\n`);
  const boundaryAggregate = JSON.parse(await readFile(aggregateFilename, "utf8")) as { completedBatches: number[] };
  boundaryAggregate.completedBatches = [1];
  await writeFile(aggregateFilename, `${JSON.stringify(boundaryAggregate, null, 2)}\n`);
  const stopped = new AbortController();
  stopped.abort();
  const paused = await runMiningBatch({ ...batchOptions, signal: stopped.signal });
  assert.equal(paused.status, "paused");
  assert.equal(paused.activeBatch, null);
  const resumedAtBoundary = await runMiningBatch(batchOptions);
  assert.equal(resumedAtBoundary.status, "complete");

  // Simulate a controller crash after the aggregate commit but before the
  // completed-child checkpoint. The rerun must recognize the terminal child
  // and commit idempotently instead of trying to overwrite its output.
  const state = JSON.parse(await readFile(stateFilename, "utf8")) as {
    status: string;
    nextUnit: number;
    active: unknown;
    completed: Array<{
      index: number;
      firstUnit: number;
      nextUnit: number;
      filesScanned: number;
      bytesScanned: number;
      uniqueFindings: number;
      occurrences: number;
    }>;
    totals: {
      filesTotal: number;
      filesScanned: number;
      bytesScanned: number;
      uniqueFindings: number;
      occurrences: number;
    };
  };
  const completed = state.completed.pop();
  if (completed === undefined) throw new Error("synthetic completed batch is missing");
  state.totals.filesScanned -= completed.filesScanned;
  state.totals.bytesScanned -= completed.bytesScanned;
  state.totals.uniqueFindings -= completed.uniqueFindings;
  state.totals.occurrences -= completed.occurrences;
  state.status = "running";
  state.nextUnit = completed.firstUnit;
  state.active = {
    index: completed.index,
    firstUnit: completed.firstUnit,
    nextUnit: completed.nextUnit,
    status: "running",
    progress: {
      filesVisited: completed.filesScanned,
      filesScanned: completed.filesScanned,
      bytesScanned: completed.bytesScanned,
      uniqueFindings: completed.uniqueFindings,
      occurrences: completed.occurrences,
      scanErrors: 0,
    },
  };
  await writeFile(stateFilename, `${JSON.stringify(state, null, 2)}\n`);
  const recovered = await runMiningBatch(batchOptions);
  assert.equal(recovered.status, "complete");
  assert.equal(recovered.batchesCompleted, 2);
  assert.equal(recovered.globallyDeduplicatedFindings, 1);
});

test("native mining batch refuses to advance after losing its controller lock", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-mining-batch-lock-"));
  const { mkdir, writeFile } = await import("node:fs/promises");
  const input = path.join(root, "input");
  const output = path.join(root, "output");
  await mkdir(input);
  await writeFile(path.join(input, "ordinary.txt"), "ordinary\n");
  const lockPath = path.join(output, ".aark-batch.lock");
  let removed = false;
  await assert.rejects(runMiningBatch({
    inputs: [input],
    output,
    provenance: "unknown",
    chunkBytes: 17 * 1024 * 1024,
    overlapBytes: 17 * 1024 * 1024,
    wholeFileBytes: 1024 * 1024,
    workers: 1,
    minimumFreeGiB: 0,
    minimumFreePercent: 0,
    progress: () => {
      if (!removed && existsSync(lockPath)) {
        unlinkSync(lockPath);
        removed = true;
      }
    },
  }), /lock|failed/u);
  assert.equal(removed, true);
  const state = JSON.parse(await readFile(path.join(output, "batch-state-sensitive.json"), "utf8")) as { completed: unknown[] };
  assert.equal(state.completed.length, 0);
});

test("path containment checks cannot be bypassed by a lexically adjacent sibling", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-path-containment-"));
  await assert.rejects(runMiningBatch({
    inputs: [path.join(root, "parent"), path.join(root, "parent-sibling"), path.join(root, "parent", "child")],
    output: path.join(root, "output"),
    provenance: "unknown",
    chunkBytes: 17 * 1024 * 1024,
    overlapBytes: 17 * 1024 * 1024,
    wholeFileBytes: 1024 * 1024,
  }), /must not contain one another/u);
});

test("invariant-failure continuation is explicitly blocked", () => {
  const state = invariantFailureContinuation("synthetic invariant failure");
  assert.equal(state.safeToAutoContinue, false);
  assert.equal(state.blocker, "synthetic invariant failure");
});
