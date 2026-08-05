import { lstat } from "node:fs/promises";
import { atomicWriteJson, readJson, safeJoin } from "../core/fs-safe.js";
import { isProcessIdentity, probeProcess } from "../core/process-identity.js";
import type { ProcessProbe } from "../core/process-identity.js";
import { continuation, invariantFailureContinuation } from "./continuation.js";
import { WORKFLOW_REDACTED_FILE, WORKFLOW_STATE_FILE } from "./state.js";
import type { WorkflowState } from "./types.js";

const MAX_WORKFLOW_STATE_BYTES = 64 * 1024 * 1024;
const STALE_HEARTBEAT_MS = 20_000;
const SUMMARY_FIELDS = new Set([
  "status", "complete", "finishedAt", "batchesCompleted", "rootsCompleted", "rootsTotal", "filesScanned", "bytesScanned",
  "globallyDeduplicatedFindings", "occurrences", "miningScansVerified", "sourceFilesRetained", "contentObjects", "copiedLogicalBytes",
  "allSourcesReadOnly", "approvalToken", "scannedFilesVerified", "findingsRetained", "sourceFilesRetained", "selectedClosedSegments",
  "activeSegmentsPreserved", "findingSourceFilesRetained", "scanErrorSourceFiles", "filesCompleted", "filesTotal", "bytesCopied",
  "objectsCreated", "objectsReused",
]);

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("workflow state must be an object");
  return value as Record<string, unknown>;
}

function redactedText(value: string): string {
  return value
    .replace(/(["'])(?:\/|[A-Za-z]:\\)[^"'\r\n]*\1/gu, "$1<PATH>$1")
    .replace(/(^|[\s"'`(=:,])\/(?!\/)(?:[^/\s"'`()=:,]+\/)*[^/\s"'`()=:,]+/gmu, "$1<PATH>")
    .replace(/[A-Za-z]:\\(?:[^\s:]+\\)*[^\s:]*/gu, "<PATH>");
}

function safeStageSummary(value: unknown): Record<string, string | number | boolean | null> | null {
  if (value === null) return null;
  if (typeof value !== "object" || Array.isArray(value)) throw new Error("workflow stage summary is invalid");
  const result: Record<string, string | number | boolean | null> = {};
  for (const [key, candidate] of Object.entries(value as Record<string, unknown>)) {
    if (!SUMMARY_FIELDS.has(key)) continue;
    if (typeof candidate !== "string" && typeof candidate !== "number" && typeof candidate !== "boolean" && candidate !== null) {
      throw new Error("workflow stage summary contains a non-scalar value");
    }
    result[key] = typeof candidate === "string" ? redactedText(candidate).slice(0, 4096) : candidate;
  }
  return result;
}

function validIsoDate(value: unknown): value is string {
  if (typeof value !== "string" || Buffer.byteLength(value) > 128) return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function safeCapacity(value: unknown): WorkflowState["capacity"] {
  if (value === null) return null;
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("workflow capacity state is invalid");
  const item = value as Record<string, unknown>;
  if (![item.availableBytes, item.totalBytes, item.reservedBytes].every((entry) => typeof entry === "string" && /^\d+$/u.test(entry))
    || typeof item.reserveSatisfied !== "boolean") throw new Error("workflow capacity state is invalid");
  return {
    availableBytes: String(item.availableBytes),
    totalBytes: String(item.totalBytes),
    reservedBytes: String(item.reservedBytes),
    reserveSatisfied: item.reserveSatisfied,
  };
}

function safeSafety(value: unknown): WorkflowState["safety"] {
  if (value === null) return null;
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("workflow safety state is invalid");
  const item = value as Record<string, unknown>;
  const nullableBoolean = (entry: unknown): entry is boolean | null => entry === null || typeof entry === "boolean";
  if (!nullableBoolean(item.sourceReadOnly) || !nullableBoolean(item.destinationMounted)
    || !nullableBoolean(item.destinationIndependent) || !nullableBoolean(item.stableSourceDeviceIdentity)) {
    throw new Error("workflow safety state is invalid");
  }
  return {
    sourceReadOnly: item.sourceReadOnly,
    destinationMounted: item.destinationMounted,
    destinationIndependent: item.destinationIndependent,
    stableSourceDeviceIdentity: item.stableSourceDeviceIdentity,
  };
}

function safeProgress(value: unknown): WorkflowState["progress"] {
  if (value === null) return null;
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("workflow progress state is invalid");
  const item = value as Record<string, unknown>;
  if (!["partitioning", "scanning", "finalizing"].includes(String(item.phase))) throw new Error("workflow progress phase is invalid");
  const names = ["batch", "batchesCompleted", "rootsCompleted", "rootsTotal", "filesTotal", "filesScanned", "bytesScanned", "uniqueFindings", "occurrences", "scanErrors"] as const;
  if (!names.every((name) => Number.isSafeInteger(item[name]) && Number(item[name]) >= 0)) throw new Error("workflow progress counters are invalid");
  return {
    phase: item.phase as "partitioning" | "scanning" | "finalizing",
    batch: Number(item.batch),
    batchesCompleted: Number(item.batchesCompleted),
    rootsCompleted: Number(item.rootsCompleted),
    rootsTotal: Number(item.rootsTotal),
    filesTotal: Number(item.filesTotal),
    filesScanned: Number(item.filesScanned),
    bytesScanned: Number(item.bytesScanned),
    uniqueFindings: Number(item.uniqueFindings),
    occurrences: Number(item.occurrences),
    scanErrors: Number(item.scanErrors),
  };
}

function roughEta(state: WorkflowState): { stageEtaSeconds: number | null; totalActiveWorkEtaSeconds: number | null } {
  const progress = state.progress;
  const checkpoint = state.stages[state.currentStage];
  if (progress === null || checkpoint === undefined) {
    return { stageEtaSeconds: null, totalActiveWorkEtaSeconds: null };
  }
  const elapsed = checkpoint.activeMilliseconds + (checkpoint.activeSince === null
    ? 0
    : Math.max(0, Date.now() - Date.parse(checkpoint.activeSince)));
  const completed = progress.filesScanned > 0 && progress.filesTotal > 0 ? progress.filesScanned : progress.rootsCompleted;
  const total = progress.filesScanned > 0 && progress.filesTotal > 0 ? progress.filesTotal : progress.rootsTotal;
  if (total < 1 || completed < 1) return { stageEtaSeconds: null, totalActiveWorkEtaSeconds: null };
  const remainingRatio = Math.max(0, total - completed) / completed;
  const stageEtaSeconds = Math.ceil(elapsed * remainingRatio / 1000);
  return {
    stageEtaSeconds,
    totalActiveWorkEtaSeconds: state.currentStage === state.stages.length - 1 ? stageEtaSeconds : null,
  };
}

export async function workflowStatus(directory: string, persist = false): Promise<Record<string, unknown>> {
  const resolved = safeJoin(directory, WORKFLOW_STATE_FILE);
  const document = await readJson<unknown>(resolved, MAX_WORKFLOW_STATE_BYTES);
  const item = record(document);
  if (item.version !== 1 || item.tool !== "aark" || item.layer !== "workflow" || !Array.isArray(item.stages)
    || !["running", "blocked-user", "blocked-safety", "terminal", "invariant-failure"].includes(String(item.status))
    || typeof item.configSha256 !== "string" || !/^[a-f0-9]{64}$/u.test(item.configSha256)
    || !validIsoDate(item.startedAt) || !validIsoDate(item.updatedAt) || !validIsoDate(item.heartbeatAt)
    || !Number.isSafeInteger(item.currentStage) || Number(item.currentStage) < 0 || Number(item.currentStage) > item.stages.length
    || item.stages.length > 1_000 || !(item.process === null || isProcessIdentity(item.process))
    || typeof item.continuation !== "object" || item.continuation === null
    || !(item.blocker === null || typeof item.blocker === "string" && Buffer.byteLength(item.blocker) <= 1024)) {
    throw new Error("workflow state marker is invalid");
  }
  const state = document as WorkflowState;
  if (typeof state.workflowId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(state.workflowId)
    || state.stages.some((stage) => typeof stage.id !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(stage.id)
      || !["recovery", "mining-batch", "retention", "cleanup-plan", "segmented-cleanup-plan"].includes(stage.kind))) {
    throw new Error("workflow state identifiers are invalid");
  }
  for (let index = 0; index < state.stages.length; index += 1) {
    const stage = state.stages[index];
    if (stage === undefined || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(stage.id)
      || !["recovery", "mining-batch", "retention", "cleanup-plan", "segmented-cleanup-plan"].includes(stage.kind)
      || !["pending", "running", "complete", "blocked"].includes(stage.status)
      || !(stage.startedAt === null || validIsoDate(stage.startedAt)) || !(stage.finishedAt === null || validIsoDate(stage.finishedAt))) {
      throw new Error("workflow stage checkpoint is invalid");
    }
    if (!Number.isSafeInteger(stage.activeMilliseconds) || stage.activeMilliseconds < 0
      || !(stage.activeSince === null || validIsoDate(stage.activeSince))) throw new Error("workflow stage active-time checkpoint is invalid");
    safeStageSummary(stage.summary);
    if (index < state.currentStage && stage.status !== "complete") throw new Error("workflow prior-stage checkpoint is invalid");
    if (index > state.currentStage && stage.status !== "pending") throw new Error("workflow future-stage checkpoint is invalid");
  }
  if (state.status === "terminal" && (state.currentStage !== state.stages.length || state.stages.some((stage) => stage.status !== "complete"))) {
    throw new Error("terminal workflow state has incomplete stages");
  }
  const capacity = safeCapacity(state.capacity);
  const safety = safeSafety(state.safety);
  const progress = safeProgress(state.progress);
  let processProbe: ProcessProbe | null = null;
  if (state.process !== null) processProbe = await probeProcess(state.process);
  const heartbeatAgeMs = Math.max(0, Date.now() - Date.parse(state.heartbeatAt));
  const heartbeatFresh = Number.isFinite(heartbeatAgeMs) && heartbeatAgeMs <= STALE_HEARTBEAT_MS;
  const activeVerified = state.status === "running"
    && heartbeatFresh
    && processProbe !== null
    && processProbe.existence === "exists"
    && processProbe.identityMatches === true;
  const storedContinuation = continuation(state.continuation);
  const expectedContinuationStatus = state.status === "running" ? "running" : state.status;
  if (storedContinuation.workflowState !== expectedContinuationStatus || storedContinuation.blocker !== state.blocker) {
    throw new Error("workflow state and continuation marker disagree");
  }
  let currentContinuation = continuation({
    ...storedContinuation,
    blocker: storedContinuation.blocker === null ? null : redactedText(storedContinuation.blocker),
  });
  let effectiveStatus = state.status;
  let blocker = state.blocker;
  if (state.status === "running" && !activeVerified) {
    blocker = "workflow state says running, but its process identity or heartbeat is not currently verifiable";
    currentContinuation = invariantFailureContinuation(blocker);
    effectiveStatus = "invariant-failure";
  }
  const blocked = ["blocked-user", "blocked-safety", "invariant-failure"].includes(effectiveStatus);
  const eta = blocked ? { stageEtaSeconds: null, totalActiveWorkEtaSeconds: null } : roughEta(state);
  const current = state.stages[state.currentStage];
  const result = {
    version: 1,
    tool: "aark",
    layer: "workflow-status",
    workflowId: state.workflowId,
    status: effectiveStatus,
    currentStage: state.currentStage,
    stageCount: state.stages.length,
    currentStageId: current?.id ?? null,
    currentStageKind: current?.kind ?? null,
    stages: state.stages.map((stage) => ({
      id: stage.id,
      kind: stage.kind,
      status: stage.status,
      activeMilliseconds: stage.activeMilliseconds,
      summary: safeStageSummary(stage.summary),
    })),
    activeProcess: state.process === null ? null : {
      pid: state.process.pid,
      existence: processProbe?.existence ?? "unknown",
      identityMatches: processProbe?.identityMatches ?? null,
    },
    heartbeatAt: state.heartbeatAt,
    heartbeatAgeMs,
    heartbeatFresh,
    genuinelyRunning: activeVerified,
    capacity,
    safety,
    progress,
    stageEtaSeconds: eta.stageEtaSeconds,
    totalActiveWorkEtaSeconds: eta.totalActiveWorkEtaSeconds,
    wallClockEtaAvailable: !blocked && eta.totalActiveWorkEtaSeconds !== null,
    valuesPrinted: false,
    pathsRedacted: true,
    ...currentContinuation,
  };
  if (persist) {
    try {
      const root = await lstat(directory);
      if (!root.isDirectory() || root.isSymbolicLink()) throw new Error("workflow directory changed before status publication");
      await atomicWriteJson(safeJoin(directory, WORKFLOW_REDACTED_FILE), result, 0o644);
    } catch (error) {
      const code = error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
      if (code !== "EROFS") throw error;
    }
  }
  return result;
}
