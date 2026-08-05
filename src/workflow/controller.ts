import { lstat } from "node:fs/promises";
import path from "node:path";
import { planCleanup } from "../cleanup.js";
import { acquireExclusiveLock, ensurePrivateDirectory, nearestExistingParent, readDirectoryNamesBounded } from "../core/fs-safe.js";
import { mountForPathFrom, mountIsReadOnly, mounts } from "../core/mounts.js";
import { captureProcessIdentity, probeProcess } from "../core/process-identity.js";
import { storageCapacity, storagePolicyFromGiB } from "../core/storage.js";
import { runMiningBatch } from "../mining/batch.js";
import type { MiningBatchOptions, MiningBatchProgress } from "../mining/batch.js";
import { buildRecoveryPlan } from "../recovery/plan.js";
import { loadRecoveryConfig } from "../recovery/config.js";
import { runRecoveryPlan } from "../recovery/runner.js";
import { inspectSourceSafety } from "../recovery/source-safety.js";
import { planRetention, runRetention } from "../retention.js";
import { planSegmentedCleanup } from "../segmented-cleanup.js";
import type { RetentionOptions, RetentionPlanResult, RetentionRunOptions } from "../retention.js";
import {
  assertBeforeYieldInvariant,
  invariantFailureContinuation,
  runningContinuation,
  safetyBlockedContinuation,
  terminalContinuation,
  userBlockedContinuation,
} from "./continuation.js";
import { loadWorkflowState, newWorkflowState, WORKFLOW_REDACTED_FILE, WORKFLOW_STATE_FILE, WorkflowStateWriter } from "./state.js";
import { workflowStatus } from "./status.js";
import type {
  CleanupPlanWorkflowStage,
  MiningBatchWorkflowStage,
  RecoveryWorkflowStage,
  RetentionWorkflowStage,
  SegmentedCleanupPlanWorkflowStage,
  WorkflowConfig,
  WorkflowSafetyState,
  WorkflowStage,
  WorkflowStageCheckpoint,
  WorkflowState,
  WorkflowStorageConfig,
} from "./types.js";
import { recoveryWorkflowConfigHash, workflowConfigHash } from "./config.js";

const WORKFLOW_LOCK = ".aark-workflow.lock";
const MIBIBYTE = 1024 ** 2;
const GIBIBYTE = 1024 ** 3;

export interface WorkflowRunOptions {
  executeRecovery: boolean;
  signal?: AbortSignal;
}

export interface WorkflowDependencies {
  runRecovery: (stage: RecoveryWorkflowStage, execute: boolean, signal?: AbortSignal) => Promise<Record<string, unknown>>;
  runMiningBatch: (stage: MiningBatchWorkflowStage, signal: AbortSignal | undefined, progress: (value: MiningBatchProgress) => void) => Promise<Record<string, unknown>>;
  planRetention: (stage: RetentionWorkflowStage, signal?: AbortSignal) => Promise<RetentionPlanResult>;
  runRetention: (stage: RetentionWorkflowStage, token: string, signal?: AbortSignal) => Promise<Record<string, unknown>>;
  planCleanup: (stage: CleanupPlanWorkflowStage, signal?: AbortSignal) => Promise<Record<string, unknown>>;
  planSegmentedCleanup: (stage: SegmentedCleanupPlanWorkflowStage, signal?: AbortSignal) => Promise<Record<string, unknown>>;
}

async function loadBoundRecoveryConfig(stage: RecoveryWorkflowStage): Promise<Awaited<ReturnType<typeof loadRecoveryConfig>>> {
  if (typeof stage.configSha256 !== "string" || !/^[a-f0-9]{64}$/u.test(stage.configSha256)) {
    throw new Error("recovery workflow stage is missing its loader-bound configuration digest");
  }
  const config = await loadRecoveryConfig(stage.config);
  if (recoveryWorkflowConfigHash(config) !== stage.configSha256) {
    throw new Error("recovery configuration changed after the workflow was reviewed");
  }
  return config;
}

function retentionOptions(stage: RetentionWorkflowStage, signal?: AbortSignal): RetentionOptions {
  return {
    miningOutputs: stage.miningOutputs,
    destination: stage.destination,
    requireReadOnlySources: stage.requireReadOnlySources,
    minimumFreeGiB: stage.storage.minimumFreeGiB,
    minimumFreePercent: stage.storage.minimumFreePercent,
    ...(stage.storage.maximumOutputGiB === undefined ? {} : { maximumOutputGiB: stage.storage.maximumOutputGiB }),
    ...(signal === undefined ? {} : { signal }),
  };
}

export const defaultWorkflowDependencies: WorkflowDependencies = {
  runRecovery: async (stage, execute, signal) => {
    const config = await loadBoundRecoveryConfig(stage);
    return await runRecoveryPlan(config, buildRecoveryPlan(config), execute, signal);
  },
  runMiningBatch: async (stage, signal, progress) => {
    const options: MiningBatchOptions = {
      inputs: stage.inputs,
      output: stage.output,
      provenance: stage.provenance,
      chunkBytes: stage.chunkMiB * MIBIBYTE,
      overlapBytes: stage.overlapMiB * MIBIBYTE,
      wholeFileBytes: stage.wholeFileMiB * MIBIBYTE,
      deepKeySchedules: stage.deepKeySchedules,
      ...(stage.workers === undefined ? {} : { workers: stage.workers }),
      minimumFreeGiB: stage.storage.minimumFreeGiB,
      minimumFreePercent: stage.storage.minimumFreePercent,
      ...(stage.storage.maximumOutputGiB === undefined ? {} : { maximumOutputGiB: stage.storage.maximumOutputGiB }),
      maximumRootsPerBatch: stage.maximumRootsPerBatch,
      maximumFilesPerBatch: stage.maximumFilesPerBatch,
      maximumBytesPerBatch: Math.floor(stage.maximumGiBPerBatch * GIBIBYTE),
      ...(signal === undefined ? {} : { signal }),
      progress,
    };
    return await runMiningBatch(options);
  },
  planRetention: async (stage, signal) => await planRetention(retentionOptions(stage, signal)),
  runRetention: async (stage, token, signal) => {
    const options: RetentionRunOptions = { ...retentionOptions(stage, signal), planToken: token };
    return await runRetention(options);
  },
  planCleanup: async (stage, signal) => ({ ...await planCleanup({
      caseDirectory: stage.caseDirectory,
      miningOutputs: stage.miningOutputs,
      includeEvidence: stage.includeEvidence,
      ...(signal === undefined ? {} : { signal }),
    }) }),
  planSegmentedCleanup: async (stage, signal) => ({ ...await planSegmentedCleanup({
    segments: stage.segments,
    activeSegments: stage.activeSegments,
    miningOutputs: stage.miningOutputs,
    retentionDirectory: stage.retentionDirectory,
    errorSourceDisposition: stage.errorSourceDisposition,
    ...(signal === undefined ? {} : { signal }),
  }) }),
};

function inside(root: string, candidate: string): boolean {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  return relative === "" || (relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

async function assertDirectorySeparated(config: WorkflowConfig): Promise<void> {
  const protectedPaths: string[] = [];
  for (const stage of config.stages) {
    if (stage.kind === "recovery") {
      const recovery = await loadBoundRecoveryConfig(stage);
      protectedPaths.push(recovery.source, recovery.destination);
      if (recovery.analysisSource !== undefined) protectedPaths.push(recovery.analysisSource);
      if (recovery.mountedReadOnlyRoot !== undefined) protectedPaths.push(recovery.mountedReadOnlyRoot);
    } else if (stage.kind === "mining-batch") {
      protectedPaths.push(...stage.inputs, stage.output);
    } else if (stage.kind === "retention") {
      protectedPaths.push(...stage.miningOutputs, stage.destination);
    } else if (stage.kind === "cleanup-plan") {
      protectedPaths.push(stage.caseDirectory, ...stage.miningOutputs);
    } else {
      protectedPaths.push(...stage.segments, ...stage.activeSegments, ...stage.miningOutputs, stage.retentionDirectory);
    }
  }
  if (protectedPaths.some((candidate) => inside(config.directory, candidate) || inside(candidate, config.directory))) {
    throw new Error("workflow state directory must not overlap any source, output, case, mining, or retention path");
  }
}

function summary(result: Record<string, unknown>, fields: readonly string[]): Record<string, string | number | boolean | null> {
  const selected: Record<string, string | number | boolean | null> = {};
  for (const field of fields) {
    const value = result[field];
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean" || value === null) selected[field] = value;
  }
  return selected;
}

function cleanupApprovalSummary(
  result: Record<string, unknown>,
  kind: "cleanup-plan" | "segmented-cleanup-plan",
): Record<string, string | number | boolean | null> {
  const deletion = result.deletion;
  if (result.status !== "ready" || result.destructive !== true || result.approvalRequired !== true
    || result.pathsRedacted !== true || result.valuesPrinted !== false
    || typeof result.approvalToken !== "string" || !/^[a-f0-9]{64}$/u.test(result.approvalToken)
    || !Number.isSafeInteger(result.miningScansVerified) || Number(result.miningScansVerified) < 1
    || typeof deletion !== "object" || deletion === null || Array.isArray(deletion)) {
    throw new Error("cleanup planning did not produce a complete redacted approval contract");
  }
  const values = deletion as Record<string, unknown>;
  const byteFields = [
    "filesystemEntries", "regularFiles", "logicalBytes", "allocatedBytes",
    "expectedFreeSpaceGainMinimumBytes", "expectedFreeSpaceGainMaximumBytes", "allocationUnitBytes",
  ];
  if (!byteFields.every((field) => typeof values[field] === "string"
    && Buffer.byteLength(values[field] as string) <= 128
    && /^\d+$/u.test(values[field] as string))
    || BigInt(values.allocationUnitBytes as string) < 1n
    || BigInt(values.expectedFreeSpaceGainMinimumBytes as string) > BigInt(values.expectedFreeSpaceGainMaximumBytes as string)
    || BigInt(values.expectedFreeSpaceGainMaximumBytes as string) > BigInt(values.allocatedBytes as string)
    || kind === "cleanup-plan" && (!Number.isSafeInteger(values.directories) || Number(values.directories) < 1)
    || kind === "segmented-cleanup-plan" && (!Number.isSafeInteger(result.selectedClosedSegments) || Number(result.selectedClosedSegments) < 1)
    || kind === "segmented-cleanup-plan" && !["retain", "delete"].includes(String(result.scanErrorSourceDisposition))) {
    throw new Error("cleanup planning produced inconsistent aggregate deletion accounting");
  }
  const selected = summary(result, [
    "status", "destructive", "approvalRequired", "approvalToken", "miningScansVerified", "scannedFilesVerified",
    "findingsRetained", "sourceFilesRetained", "selectedClosedSegments", "activeSegmentsPreserved",
    "findingSourceFilesRetained", "scanErrorSourceFiles", "scanErrorSourceDisposition",
  ]);
  const fields: Array<[string, string]> = [
    ["directories", "deletionDirectories"],
    ["filesystemEntries", "deletionFilesystemEntries"],
    ["regularFiles", "deletionRegularFiles"],
    ["logicalBytes", "deletionLogicalBytes"],
    ["allocatedBytes", "deletionPlannedMaximumReclaimableAllocatedBytes"],
    ["expectedFreeSpaceGainMinimumBytes", "expectedFreeSpaceGainMinimumBytes"],
    ["expectedFreeSpaceGainMaximumBytes", "expectedFreeSpaceGainMaximumBytes"],
    ["allocationUnitBytes", "allocationUnitBytes"],
    ["recoveredCopyIncluded", "recoveredCopyIncluded"],
    ["evidenceCopyIncluded", "evidenceCopyIncluded"],
    ["evidenceCopyPresent", "evidenceCopyPresent"],
    ["intermediateLogsAndRunsIncluded", "intermediateLogsAndRunsIncluded"],
  ];
  for (const [source, destination] of fields) {
    const value = values[source];
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean" || value === null) {
      selected[destination] = value;
    }
  }
  return selected;
}

function genericBlocker(error: unknown): string {
  let current: unknown = error;
  for (let depth = 0; depth < 8 && current !== undefined; depth += 1) {
    if (current instanceof Error) {
      if (/free-space reserve|free-space-reserve|output-size cap|output-cap/u.test(current.message)) {
        return "the configured destination capacity reserve or output cap is currently blocking progress";
      }
      if (/read-only|source safety|destination is on the source|mount/u.test(current.message)) {
        return "a source, destination, mount, or device-identity safety check failed";
      }
      if (/test|compatib|checkpoint|changed|integrity|lock/u.test(current.message)) {
        return "a durable checkpoint, process lock, compatibility, or integrity check requires local remediation";
      }
      current = "cause" in current ? current.cause : undefined;
    } else break;
  }
  return "the current stage failed; inspect its local redacted report and remediate before resuming";
}

async function capacityState(target: string, storage: WorkflowStorageConfig): Promise<WorkflowState["capacity"]> {
  const parent = await nearestExistingParent(target);
  const policy = storagePolicyFromGiB(storage.minimumFreeGiB, storage.minimumFreePercent, storage.maximumOutputGiB);
  const capacity = await storageCapacity(parent, policy);
  return {
    availableBytes: capacity.availableBytes.toString(),
    totalBytes: capacity.totalBytes.toString(),
    reservedBytes: capacity.reservedBytes.toString(),
    reserveSatisfied: capacity.availableBytes >= capacity.reservedBytes,
  };
}

async function preflightStage(stage: WorkflowStage): Promise<{ capacity: WorkflowState["capacity"]; safety: WorkflowSafetyState }> {
  if (stage.kind === "recovery") {
    const config = await loadBoundRecoveryConfig(stage);
    const safety = await inspectSourceSafety(config.source, config.destination);
    return {
      capacity: await capacityState(config.destination, {
        minimumFreeGiB: config.storage?.minFreeGiB ?? 5,
        minimumFreePercent: config.storage?.minFreePercent ?? 5,
        ...(config.storage?.maxOutputGiB === undefined ? {} : { maximumOutputGiB: config.storage.maxOutputGiB }),
      }),
      safety: {
        sourceReadOnly: safety.kind === "block-device" ? safety.kernelReadOnly === true && safety.writableMounts.length === 0 : null,
        destinationMounted: safety.destinationMountSource !== null,
        destinationIndependent: !safety.destinationOnSourceDevice && safety.deviceComparisonCertain,
        stableSourceDeviceIdentity: safety.sourceDeviceIdentities.length === 0
          ? null
          : safety.sourceDeviceIdentities.every((identity) => identity.serial !== null || identity.wwn !== null || identity.filesystemUuid !== null),
      },
    };
  }
  if (stage.kind === "mining-batch") {
    const records = await mounts();
    const sourceReadOnly = stage.inputs.every((input) => mountIsReadOnly(mountForPathFrom(records, input)));
    return {
      capacity: await capacityState(stage.output, stage.storage),
      safety: { sourceReadOnly, destinationMounted: mountForPathFrom(records, await nearestExistingParent(stage.output)) !== undefined, destinationIndependent: null, stableSourceDeviceIdentity: null },
    };
  }
  if (stage.kind === "retention") {
    const records = await mounts();
    return {
      capacity: await capacityState(stage.destination, stage.storage),
      safety: {
        // The finding sources are resolved from private inventories by the
        // retention stage itself; do not mislabel the mining-output mounts as
        // the source mounts here.
        sourceReadOnly: null,
        destinationMounted: mountForPathFrom(records, await nearestExistingParent(stage.destination)) !== undefined,
        destinationIndependent: null,
        stableSourceDeviceIdentity: null,
      },
    };
  }
  return {
    capacity: null,
    safety: { sourceReadOnly: null, destinationMounted: null, destinationIndependent: null, stableSourceDeviceIdentity: null },
  };
}

function beginCheckpoint(checkpoint: WorkflowStageCheckpoint): void {
  if (checkpoint.activeSince !== null) throw new Error("workflow stage already has an active timing interval");
  const now = new Date().toISOString();
  checkpoint.status = "running";
  checkpoint.startedAt ??= now;
  checkpoint.finishedAt = null;
  checkpoint.activeSince = now;
  checkpoint.summary = null;
}

function finishActiveInterval(checkpoint: WorkflowStageCheckpoint, finishedAt = new Date().toISOString()): void {
  if (checkpoint.activeSince === null) return;
  const elapsed = Math.max(0, Date.parse(finishedAt) - Date.parse(checkpoint.activeSince));
  const total = checkpoint.activeMilliseconds + elapsed;
  if (!Number.isSafeInteger(total)) throw new Error("workflow active-time accounting exceeded safe numeric bounds");
  checkpoint.activeMilliseconds = total;
  checkpoint.activeSince = null;
}

function completeCheckpoint(checkpoint: WorkflowStageCheckpoint, result: Record<string, string | number | boolean | null>): void {
  const now = new Date().toISOString();
  finishActiveInterval(checkpoint, now);
  checkpoint.status = "complete";
  checkpoint.finishedAt = now;
  checkpoint.summary = result;
}

async function stageResult(
  stage: WorkflowStage,
  options: WorkflowRunOptions,
  dependencies: WorkflowDependencies,
  onProgress: (progress: MiningBatchProgress) => void,
): Promise<{ outcome: "complete" | "blocked-safety" | "blocked-user"; summary: Record<string, string | number | boolean | null>; blocker?: string }> {
  if (stage.kind === "recovery") {
    const recovery = await loadBoundRecoveryConfig(stage);
    if (!recovery.execute || !options.executeRecovery) {
      return {
        outcome: "blocked-user",
        summary: {},
        blocker: "recovery execution needs execute=true in its reviewed recovery config and --execute-recovery on workflow run",
      };
    }
    const result = await dependencies.runRecovery(stage, true, options.signal);
    const selected = summary(result, ["status", "complete", "finishedAt"]);
    if (result.status === "paused") return { outcome: "blocked-safety", summary: selected, blocker: "recovery paused at its configured capacity reserve; restore the reserve and resume this workflow" };
    if (result.status !== "complete" && result.status !== "complete-with-warnings") throw new Error("recovery did not reach a terminal successful status");
    return { outcome: "complete", summary: selected };
  }
  if (stage.kind === "mining-batch") {
    const result = await dependencies.runMiningBatch(stage, options.signal, onProgress);
    const selected = summary(result, ["status", "complete", "batchesCompleted", "rootsPartitioned", "rootsCompleted", "rootsTotal", "filesScanned", "bytesScanned", "globallyDeduplicatedFindings", "occurrences"]);
    if (result.status === "paused") return { outcome: "blocked-safety", summary: selected, blocker: "mining paused at a clean checkpoint; restore its capacity reserve or clear the signal and resume this workflow" };
    if (result.status === "blocked-safety") return { outcome: "blocked-safety", summary: selected, blocker: "mining batch verification or integrity checks require local remediation" };
    if (result.status !== "complete") throw new Error("mining batch did not reach exact completion");
    return { outcome: "complete", summary: selected };
  }
  if (stage.kind === "retention") {
    const plan = await dependencies.planRetention(stage, options.signal);
    const result = await dependencies.runRetention(stage, plan.planToken, options.signal);
    if (result.status === "paused" && result.resumable === true) {
      return {
        outcome: "blocked-safety",
        summary: summary(result, ["status", "complete", "filesCompleted", "filesTotal", "bytesCopied", "objectsCreated", "objectsReused"]),
        blocker: "retention paused at a resumable signal or capacity boundary; resolve the blocker and resume this workflow",
      };
    }
    if (result.status !== "complete" || result.complete !== true) throw new Error("retention did not reach exact completion");
    return { outcome: "complete", summary: summary(result, ["status", "complete", "miningScansVerified", "sourceFilesRetained", "contentObjects", "copiedLogicalBytes", "allSourcesReadOnly"]) };
  }
  const result = stage.kind === "cleanup-plan"
    ? await dependencies.planCleanup(stage, options.signal)
    : await dependencies.planSegmentedCleanup(stage, options.signal);
  return {
    outcome: "blocked-user",
    summary: cleanupApprovalSummary(result, stage.kind),
    blocker: "cleanup plan is ready; deletion requires the end user to review its aggregate and explicitly approve the separate cleanup run command",
  };
}

export async function runWorkflowUntilBlocked(
  config: WorkflowConfig,
  options: WorkflowRunOptions,
  dependencies: WorkflowDependencies = defaultWorkflowDependencies,
): Promise<Record<string, unknown>> {
  await assertDirectorySeparated(config);
  let fresh = false;
  try { await lstat(config.directory); } catch (error) {
    const code = error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
    if (code !== "ENOENT") throw error;
    fresh = true;
  }
  if (fresh) await ensurePrivateDirectory(config.directory);
  const allowed = new Set([WORKFLOW_LOCK, ".aark-workflow-upgrade.lock", WORKFLOW_STATE_FILE, WORKFLOW_REDACTED_FILE, "upgrades", "workflow-upgrade-redacted.json"]);
  const entries = await readDirectoryNamesBounded(config.directory, allowed.size + 1);
  if (entries.some((entry) => !allowed.has(entry))) throw new Error("workflow directory contains an unexpected entry");
  const lock = await acquireExclusiveLock(config.directory, WORKFLOW_LOCK, { reclaimDeadOwner: true });
  const writer = new WorkflowStateWriter(config.directory);
  let operationError: unknown;
  try {
    let state = entries.includes(WORKFLOW_STATE_FILE) ? await loadWorkflowState(config) : newWorkflowState(config);
    if (state.configSha256 !== workflowConfigHash(config)) throw new Error("workflow configuration changed after its checkpoint was created");
    if (state.status === "terminal" || (state.status === "blocked-user" && (
      ["cleanup-plan", "segmented-cleanup-plan"].includes(config.stages[state.currentStage]?.kind ?? "") || !options.executeRecovery
    ))) {
      state.process = null;
      await writer.write(state);
      assertBeforeYieldInvariant(state.continuation, false);
      return await workflowStatus(config.directory, true);
    }
    if (state.status === "running" && entries.includes(WORKFLOW_STATE_FILE)) {
      const checkpoint = state.stages[state.currentStage];
      let priorControllerDead = false;
      if (state.process !== null) {
        const probe = await probeProcess(state.process);
        priorControllerDead = probe.existence === "missing" || probe.existence === "exists" && probe.identityMatches === false;
      }
      const cleanPendingBoundary = checkpoint?.status === "pending" && (state.process === null || priorControllerDead);
      const resumableInterruptedStage = checkpoint?.status === "running" && state.process !== null && priorControllerDead;
      if (!cleanPendingBoundary && !resumableInterruptedStage) {
        state.status = "invariant-failure";
        state.blocker = !priorControllerDead
          ? "a prior workflow controller process is still active or cannot be distinguished safely"
          : "a prior workflow controller stopped outside a resumable stage checkpoint";
        state.continuation = invariantFailureContinuation(state.blocker);
        state.process = null;
        await writer.write(state);
        return await workflowStatus(config.directory, true);
      }
      if (checkpoint.status === "running") {
        if (checkpoint.activeSince !== null) {
          const boundedHeartbeat = Math.max(
            Date.parse(checkpoint.activeSince),
            Math.min(Date.now(), Date.parse(state.heartbeatAt)),
          );
          finishActiveInterval(checkpoint, new Date(boundedHeartbeat).toISOString());
        }
        // Every runnable stage has its own durable checkpoint and operation
        // lock. Re-entering it is safe only after the prior controller is
        // proven dead; the child then decides whether it can resume or must
        // publish a safety blocker.
        checkpoint.status = "pending";
      }
    }
    if (state.status === "invariant-failure") {
      state.process = null;
      await writer.write(state);
      assertBeforeYieldInvariant(state.continuation, false);
      return await workflowStatus(config.directory, true);
    }

    state.status = "running";
    state.blocker = null;
    state.process = await captureProcessIdentity();
    state.heartbeatAt = new Date().toISOString();
    state.continuation = runningContinuation("workflow-until-blocked");
    await writer.write(state);
    await workflowStatus(config.directory, true);
    let heartbeatError: unknown;
    const heartbeatAbort = new AbortController();
    const stageSignal = options.signal === undefined
      ? heartbeatAbort.signal
      : AbortSignal.any([options.signal, heartbeatAbort.signal]);
    const stageOptions: WorkflowRunOptions = { ...options, signal: stageSignal };
    const timer = setInterval(() => {
      state.heartbeatAt = new Date().toISOString();
      void writer.write(state).catch((error: unknown) => {
        heartbeatError ??= error;
        heartbeatAbort.abort();
      });
    }, 5_000);
    timer.unref();
    try {
      while (state.currentStage < config.stages.length) {
        const stage = config.stages[state.currentStage];
        const checkpoint = state.stages[state.currentStage];
        if (stage === undefined || checkpoint === undefined) throw new Error("workflow stage checkpoint is missing");
        if (heartbeatError !== undefined || options.signal?.aborted === true) {
          finishActiveInterval(checkpoint);
          checkpoint.status = "blocked";
          checkpoint.summary = null;
          state.status = "blocked-safety";
          state.blocker = heartbeatError !== undefined
            ? "workflow heartbeat persistence failed; restore reliable control-state storage before resuming"
            : "workflow was interrupted at a clean stage boundary; clear the signal before resuming";
          state.continuation = safetyBlockedContinuation(state.blocker, "workflow-resume");
          break;
        }
        beginCheckpoint(checkpoint);
        state.progress = null;
        state.capacity = null;
        state.safety = null;
        state.continuation = runningContinuation(stage.kind);
        await writer.write(state);
        try {
          const preflight = await preflightStage(stage);
          state.capacity = preflight.capacity;
          state.safety = preflight.safety;
          if (preflight.capacity?.reserveSatisfied === false) throw new Error("free-space reserve is not currently satisfied");
          await writer.write(state);
          const outcome = await stageResult(stage, stageOptions, dependencies, (progress) => { state.progress = progress; });
          if (heartbeatError !== undefined) throw new Error("workflow heartbeat persistence failed", { cause: heartbeatError });
          checkpoint.summary = outcome.summary;
          if (outcome.outcome === "complete") {
            completeCheckpoint(checkpoint, outcome.summary);
            state.currentStage += 1;
            state.progress = null;
            state.capacity = null;
            state.safety = null;
            const terminal = state.currentStage >= config.stages.length;
            state.status = terminal ? "terminal" : "running";
            state.blocker = null;
            state.process = terminal ? null : state.process;
            state.continuation = terminal ? terminalContinuation() : runningContinuation("workflow-next-stage");
            await writer.write(state);
            await workflowStatus(config.directory, true);
            if (terminal) break;
            continue;
          }
          finishActiveInterval(checkpoint);
          checkpoint.status = "blocked";
          state.blocker = outcome.blocker ?? "workflow stage is blocked";
          state.status = outcome.outcome;
          state.continuation = outcome.outcome === "blocked-user"
            ? userBlockedContinuation(state.blocker, stage.kind === "segmented-cleanup-plan" ? "segmented-cleanup-run-approved-plan" : stage.kind === "cleanup-plan" ? "cleanup-run-approved-plan" : "workflow-resume")
            : safetyBlockedContinuation(state.blocker, "workflow-resume");
          break;
        } catch (error) {
          // Once a child completion has been durably advanced, a failure to
          // publish the convenience status copy must never roll that stage
          // back to `blocked` under the next-stage index. Leave the durable
          // completed/pending boundary intact for a safe controller restart.
          if (checkpoint.status === "complete") throw error;
          finishActiveInterval(checkpoint);
          checkpoint.status = "blocked";
          state.status = "blocked-safety";
          state.blocker = heartbeatError !== undefined
            ? "workflow heartbeat persistence failed; restore reliable control-state storage before resuming"
            : genericBlocker(error);
          state.continuation = safetyBlockedContinuation(state.blocker, "workflow-resume");
          break;
        }
      }
      if (state.currentStage >= config.stages.length) {
        state.status = "terminal";
        state.blocker = null;
        state.continuation = terminalContinuation();
      }
    } finally {
      clearInterval(timer);
      try {
        await writer.settled();
      } catch (error) {
        // Preserve the heartbeat failure as a safety blocker, then let the
        // final write below make one fresh attempt through the writer's
        // failure-isolated queue. A persistent storage failure still rejects.
        heartbeatError ??= error;
      }
    }
    state.process = null;
    state.heartbeatAt = new Date().toISOString();
    await writer.write(state);
    assertBeforeYieldInvariant(state.continuation, false);
    return await workflowStatus(config.directory, true);
  } catch (error) {
    operationError = error;
    throw error;
  } finally {
    try {
      await lock.release();
    } catch (releaseError) {
      if (operationError !== undefined) throw new AggregateError([operationError, releaseError], "workflow failed and its lock could not be released");
      throw releaseError;
    }
  }
}
