import type { Confidence, JsonValue, Provenance, ValidationRecord } from "../core/types.js";

export interface MiningOptions {
  inputs: string[];
  output: string;
  provenance: Provenance;
  chunkBytes: number;
  overlapBytes: number;
  wholeFileBytes: number;
  deepKeySchedules?: boolean;
  workers?: number;
  minimumFreeGiB?: number;
  minimumFreePercent?: number;
  maximumOutputGiB?: number;
  signal?: AbortSignal;
  progress?: (progress: MiningProgress) => void;
}

export interface MiningProgress {
  phase?: "inventory" | "stream" | "whole-file" | "finalizing";
  filesTotal?: number;
  filesVisited: number;
  filesScanned: number;
  bytesScanned: number;
  uniqueFindings: number;
  occurrences: number;
  scanErrors: number;
}

/** Aggregate-only, invocation-local scanner measurements. No paths or values are recorded. */
export interface MiningPerformance {
  elapsedMs: number;
  inventoryTraversalMs: number;
  rootValidationCalls: number;
  rootValidationMs: number;
  fileValidationCalls: number;
  fileValidationMs: number;
  readCalls: number;
  bytesRead: number;
  readMs: number;
  workerJobs: number;
  workerPayloadCopies: number;
  workerPayloadBytes: number;
  maximumWorkerQueueDepth: number;
  maximumActiveWorkerJobs: number;
  maximumActiveWorkerBytes: number;
  deterministicCommitMs: number;
  artifactPublications: number;
  artifactLogicalBytes: number;
  artifactPublicationMs: number;
  checkpoints: number;
  checkpointBytes: number;
  checkpointMs: number;
  periodicSafetyChecks: number;
  periodicSafetyCheckMs: number;
  maximumOutstandingFiles: number;
  maximumOutstandingFileBytes: number;
  completeFileBuffersReused: number;
}

export type MiningRunStatus = "in-progress" | "paused" | "complete" | "complete-with-errors" | "failed" | "interrupted";

export interface SensitiveOccurrence {
  sourcePath: string;
  offset: number;
  length: number;
  provenance: Provenance;
}

export interface SensitiveFinding {
  id: number;
  category: string;
  confidence: Confidence;
  bytes: number;
  sha256: string;
  validation: ValidationRecord;
  artifactFiles: string[];
  artifactIntegrity: Array<{ path: string; bytes: number; sha256: string }>;
  sensitiveMetadata?: Record<string, JsonValue>;
  occurrences: SensitiveOccurrence[];
}

export interface SensitiveScanInventory {
  version: 1;
  tool: "aark" | "agetnic-tools";
  layer: "mining";
  status: MiningRunStatus;
  complete: boolean;
  startedAt: string;
  updatedAt: string;
  finishedAt?: string;
  failureMessage?: string;
  inputRoots: string[];
  outputRoot: string;
  resumeCheckpoint?: {
    runId: string;
    status: MiningRunStatus;
    inventoryComplete: boolean;
    semantic: {
      inputs: string[];
      output: string;
      provenance: Provenance;
      chunkBytes: number;
      overlapBytes: number;
      wholeFileBytes: number;
      deepKeySchedules: boolean;
    };
    inputRoots: Array<{ path: string; device: number; inode: number; kind: "file" | "directory"; mount: string }>;
    manifest: { filename: string; entries: number; bytes: number; sha256: string };
    cursor: { fileIndex: number; phase: "stream" | "whole-file"; nextOffset: number };
    progress: MiningProgress;
  };
  findings: SensitiveFinding[];
  errors: Array<{ sourcePath: string; operation: string; message: string }>;
  errorsOmitted: number;
}
