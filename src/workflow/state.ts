import { atomicWriteJson, readJson, safeJoin } from "../core/fs-safe.js";
import { isProcessIdentity } from "../core/process-identity.js";
import type { WorkflowConfig, WorkflowState } from "./types.js";
import { continuation, runningContinuation } from "./continuation.js";
import { workflowConfigHash } from "./config.js";

export const WORKFLOW_STATE_FILE = "workflow-state-sensitive.json";
export const WORKFLOW_REDACTED_FILE = "workflow-status-redacted.json";
const MAX_WORKFLOW_STATE_BYTES = 64 * 1024 * 1024;

export function newWorkflowState(config: WorkflowConfig): WorkflowState {
  const now = new Date().toISOString();
  return {
    version: 1,
    tool: "aark",
    layer: "workflow",
    workflowId: config.workflowId,
    configSha256: workflowConfigHash(config),
    status: "running",
    startedAt: now,
    updatedAt: now,
    heartbeatAt: now,
    currentStage: 0,
    process: null,
    stages: config.stages.map((stage) => ({
      id: stage.id,
      kind: stage.kind,
      status: "pending",
      startedAt: null,
      finishedAt: null,
      activeMilliseconds: 0,
      activeSince: null,
      summary: null,
    })),
    continuation: runningContinuation("workflow-start"),
    blocker: null,
    capacity: null,
    safety: null,
    progress: null,
  };
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as Record<string, unknown>;
}

function validIsoDate(value: unknown): value is string {
  if (typeof value !== "string" || Buffer.byteLength(value) > 128) return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

export function validateWorkflowState(value: unknown, config: WorkflowConfig): WorkflowState {
  const item = record(value, "workflow state");
  if (
    item.version !== 1 || item.tool !== "aark" || item.layer !== "workflow"
    || item.workflowId !== config.workflowId || item.configSha256 !== workflowConfigHash(config)
    || !["running", "blocked-user", "blocked-safety", "terminal", "invariant-failure"].includes(String(item.status))
    || !validIsoDate(item.startedAt) || !validIsoDate(item.updatedAt) || !validIsoDate(item.heartbeatAt)
    || !Number.isSafeInteger(item.currentStage) || Number(item.currentStage) < 0 || Number(item.currentStage) > config.stages.length
    || !Array.isArray(item.stages) || item.stages.length !== config.stages.length
    || !(item.process === null || typeof item.process === "object")
    || typeof item.continuation !== "object" || item.continuation === null
    || !(item.blocker === null || typeof item.blocker === "string" && Buffer.byteLength(item.blocker) <= 1024)
  ) throw new Error("workflow state is invalid or belongs to another configuration");
  for (let index = 0; index < config.stages.length; index += 1) {
    const expected = config.stages[index];
    const checkpoint = record(item.stages[index], `workflow stage checkpoint ${index}`);
    if (expected === undefined || checkpoint.id !== expected.id || checkpoint.kind !== expected.kind
      || !["pending", "running", "complete", "blocked"].includes(String(checkpoint.status))
      || !(checkpoint.startedAt === null || validIsoDate(checkpoint.startedAt))
      || !(checkpoint.finishedAt === null || validIsoDate(checkpoint.finishedAt))
      || !Number.isSafeInteger(checkpoint.activeMilliseconds) || Number(checkpoint.activeMilliseconds) < 0
      || !(checkpoint.activeSince === null || validIsoDate(checkpoint.activeSince))
      || !(checkpoint.summary === null || typeof checkpoint.summary === "object" && !Array.isArray(checkpoint.summary))) {
      throw new Error("workflow stage checkpoint does not match its configuration");
    }
    if (index < Number(item.currentStage) && checkpoint.status !== "complete") throw new Error("a prior workflow stage is not complete");
    if (index > Number(item.currentStage) && checkpoint.status !== "pending") throw new Error("a future workflow stage is not pending");
  }
  const state = value as WorkflowState;
  const checkedContinuation = continuation(state.continuation);
  const expectedWorkflowState = state.status === "running" ? "running" : state.status;
  if (checkedContinuation.workflowState !== expectedWorkflowState || checkedContinuation.blocker !== state.blocker) {
    throw new Error("workflow status and continuation checkpoint disagree");
  }
  if (state.process !== null && !isProcessIdentity(state.process)) throw new Error("workflow process identity is invalid");
  if (state.status === "terminal" && state.currentStage !== config.stages.length) throw new Error("terminal workflow state has an unfinished stage");
  if ((state.status === "blocked-user" || state.status === "blocked-safety")
    && state.stages[state.currentStage]?.status !== "blocked") throw new Error("blocked workflow state lacks a blocked current stage");
  if (state.status !== "running" && state.process !== null) throw new Error("only a running workflow may retain a controller identity");
  return state;
}

export async function loadWorkflowState(config: WorkflowConfig): Promise<WorkflowState> {
  return validateWorkflowState(
    await readJson<unknown>(safeJoin(config.directory, WORKFLOW_STATE_FILE), MAX_WORKFLOW_STATE_BYTES),
    config,
  );
}

export class WorkflowStateWriter {
  private pending: Promise<void> = Promise.resolve();

  public constructor(private readonly directory: string) {}

  public async write(state: WorkflowState): Promise<void> {
    state.updatedAt = new Date().toISOString();
    const snapshot = structuredClone(state);
    const next = this.pending.catch(() => undefined).then(async () => {
      await atomicWriteJson(safeJoin(this.directory, WORKFLOW_STATE_FILE), snapshot);
    });
    this.pending = next;
    await next;
  }

  public async settled(): Promise<void> {
    await this.pending;
  }
}
