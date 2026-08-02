import type { Confidence, JsonValue, Provenance, ValidationRecord } from "../core/types.js";

export interface MiningOptions {
  inputs: string[];
  output: string;
  provenance: Provenance;
  chunkBytes: number;
  overlapBytes: number;
  wholeFileBytes: number;
  deepKeySchedules?: boolean;
  signal?: AbortSignal;
  progress?: (progress: MiningProgress) => void;
}

export interface MiningProgress {
  filesVisited: number;
  filesScanned: number;
  bytesScanned: number;
  uniqueFindings: number;
  occurrences: number;
  scanErrors: number;
}

export type MiningRunStatus = "in-progress" | "complete" | "complete-with-errors" | "failed" | "interrupted";

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
  findings: SensitiveFinding[];
  errors: Array<{ sourcePath: string; operation: string; message: string }>;
  errorsOmitted: number;
}
