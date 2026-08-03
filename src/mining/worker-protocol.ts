import type { Candidate } from "../core/types.js";
import type { DetectionContext } from "./detectors/types.js";

export type DetectorJobKind =
  | "cryptographic-keys"
  | "configuration-secrets"
  | "wallet-secrets"
  | "provider-credentials"
  | "streaming"
  | "small-file"
  | "deep-key-schedules"
  | "structured";

export const STREAMING_DETECTOR_NAMES = [
  "cryptographic-keys",
  "configuration-secrets",
  "wallet-secrets",
  "provider-credentials",
] as const;

export function expectedDetectorNames(kind: DetectorJobKind): readonly string[] {
  switch (kind) {
    case "streaming":
      return STREAMING_DETECTOR_NAMES;
    case "small-file":
      return [...STREAMING_DETECTOR_NAMES, "structured-artifacts"];
    case "structured":
      return ["structured-artifacts"];
    default:
      return [kind];
  }
}

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
