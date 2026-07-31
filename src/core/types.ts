export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

export type Confidence = "authenticated" | "high" | "medium" | "marker-only";

export type Provenance =
  | "deleted-metadata"
  | "unallocated-carve"
  | "unallocated-stream"
  | "shadow-copy"
  | "residual-memory"
  | "allocated-reference"
  | "unknown";

export interface ValidationRecord {
  method: string;
  checks: Record<string, JsonValue>;
}

export interface Candidate {
  category: string;
  offset: number;
  length: number;
  value: Buffer;
  confidence: Confidence;
  validation: ValidationRecord;
  extension: string;
  derivedArtifacts?: Array<{
    filename: string;
    data: Buffer;
    mode?: number;
  }>;
  sensitiveMetadata?: Record<string, JsonValue>;
}

export interface FindingResult {
  id: number;
  category: string;
  confidence: Confidence;
  disposition:
    | "recovered"
    | "duplicate-recovered-value"
    | "known-value-duplicate"
    | "marker-only-not-exported";
  bytes: number;
  validation: ValidationRecord;
  artifactFiles: string[];
  provenance: Provenance;
  deletedStatus: "metadata-confirmed" | "unallocated-confirmed" | "historical-only" | "not-provable";
}
