import type { Provenance } from "../core/types.js";

export type RecoveryRunStatus = "complete" | "complete-with-warnings" | "failed" | "interrupted";

export interface RecoveryStages {
  deletedMetadata: boolean;
  ntfsUndelete: boolean;
  unallocatedStream: boolean;
  signatureCarving: boolean;
  volumeShadows: boolean;
  residualMemory: boolean;
  deletedRegistryCells: boolean;
}

export interface RecoveryImageConfig {
  enabled: boolean;
  path: string;
  mapfile: string;
  retryPasses: number;
}

export interface RecoveryConfig {
  version: 1;
  caseId: string;
  source: string;
  analysisSource?: string;
  mountedReadOnlyRoot?: string;
  destination: string;
  requireReadOnlySource: boolean;
  execute: boolean;
  sectorOffset: number;
  photoRecCommand: string;
  image: RecoveryImageConfig;
  stages: RecoveryStages;
}

export interface RecoveryStep {
  id: string;
  title: string;
  executable: string;
  args: string[];
  stdoutFile?: string;
  workingDirectory?: string;
  createsDirectories: string[];
  outputs: string[];
  provenance: Provenance;
  sourceMutationExpected: false;
  destinationWritesExpected: boolean;
  optional: boolean;
  notes: string[];
}

export interface RecoveryPlan {
  version: 1;
  caseId: string;
  source: string;
  analysisSource: string;
  destination: string;
  steps: RecoveryStep[];
  warnings: string[];
}
