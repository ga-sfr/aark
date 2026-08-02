import type { Candidate } from "../core/types.js";
import type { DetectionContext } from "./detectors/types.js";

export type DetectorJobKind =
  | "cryptographic-keys"
  | "configuration-secrets"
  | "wallet-secrets"
  | "provider-credentials"
  | "deep-key-schedules"
  | "structured";

export interface DetectorJobRequest {
  id: number;
  kind: DetectorJobKind;
  data: Uint8Array;
  context: DetectionContext;
}

export interface DetectorBatchResult {
  detector: string;
  candidates: Candidate[];
  error?: string;
}

export interface DetectorJobResponse {
  id: number;
  results: DetectorBatchResult[];
  fatalError?: string;
}
