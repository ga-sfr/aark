import type { ProcessIdentity } from "../core/process-identity.js";
import type { Provenance } from "../core/types.js";
import type { MiningBatchProgress } from "../mining/batch.js";
import type { ContinuationState } from "./continuation.js";

export interface WorkflowStorageConfig {
  minimumFreeGiB: number;
  minimumFreePercent: number;
  maximumOutputGiB?: number;
}

export interface RecoveryWorkflowStage {
  id: string;
  kind: "recovery";
  config: string;
  /** Populated by the strict workflow loader; callers may not supply it in JSON. */
  configSha256?: string;
}

export interface MiningBatchWorkflowStage {
  id: string;
  kind: "mining-batch";
  inputs: string[];
  output: string;
  provenance: Provenance;
  chunkMiB: number;
  overlapMiB: number;
  wholeFileMiB: number;
  deepKeySchedules: boolean;
  workers?: number;
  storage: WorkflowStorageConfig;
  maximumRootsPerBatch: number;
  maximumFilesPerBatch: number;
  maximumGiBPerBatch: number;
}

export interface RetentionWorkflowStage {
  id: string;
  kind: "retention";
  miningOutputs: string[];
  destination: string;
  requireReadOnlySources: boolean;
  storage: WorkflowStorageConfig;
}

export interface CleanupPlanWorkflowStage {
  id: string;
  kind: "cleanup-plan";
  caseDirectory: string;
  miningOutputs: string[];
  includeEvidence: boolean;
}

export interface SegmentedCleanupPlanWorkflowStage {
  id: string;
  kind: "segmented-cleanup-plan";
  segments: string[];
  activeSegments: string[];
  miningOutputs: string[];
  retentionDirectory: string;
  errorSourceDisposition: "retain" | "delete";
}

export type WorkflowStage = RecoveryWorkflowStage | MiningBatchWorkflowStage | RetentionWorkflowStage | CleanupPlanWorkflowStage | SegmentedCleanupPlanWorkflowStage;

export interface WorkflowConfig {
  version: 1;
  workflowId: string;
  directory: string;
  stages: WorkflowStage[];
}

export interface WorkflowStageCheckpoint {
  id: string;
  kind: WorkflowStage["kind"];
  status: "pending" | "running" | "complete" | "blocked";
  startedAt: string | null;
  finishedAt: string | null;
  activeMilliseconds: number;
  activeSince: string | null;
  summary: Record<string, string | number | boolean | null> | null;
}

export interface WorkflowCapacityState {
  availableBytes: string;
  totalBytes: string;
  reservedBytes: string;
  reserveSatisfied: boolean;
}

export interface WorkflowSafetyState {
  sourceReadOnly: boolean | null;
  destinationMounted: boolean | null;
  destinationIndependent: boolean | null;
  stableSourceDeviceIdentity: boolean | null;
}

export interface WorkflowState {
  version: 1;
  tool: "aark";
  layer: "workflow";
  workflowId: string;
  configSha256: string;
  status: "running" | "blocked-user" | "blocked-safety" | "terminal" | "invariant-failure";
  startedAt: string;
  updatedAt: string;
  heartbeatAt: string;
  currentStage: number;
  process: ProcessIdentity | null;
  stages: WorkflowStageCheckpoint[];
  continuation: ContinuationState;
  blocker: string | null;
  capacity: WorkflowCapacityState | null;
  safety: WorkflowSafetyState | null;
  progress: MiningBatchProgress | null;
}
