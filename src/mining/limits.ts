export const MAX_CANDIDATES_PER_DETECTOR_JOB = 10_000;
export const MAX_CANDIDATE_BYTES_PER_DETECTOR_JOB = 320 * 1024 * 1024;
export const MAX_STREAMING_CANDIDATE_BYTES_PER_DETECTOR_JOB = 64 * 1024 * 1024;
export const MAX_STRUCTURAL_VALIDATIONS_PER_DETECTOR_JOB = 100_000;
export const MAX_ARMORED_MARKERS_PER_VALIDATOR = 1_000;
export const MAX_ARMORED_SEARCH_BYTES_PER_VALIDATOR = 64 * 1024 * 1024;
export const MAX_EXPENSIVE_CRYPTO_VALIDATIONS_PER_DETECTOR_JOB = 64;
export const MAX_STRUCTURED_JSON_PARSE_BYTES = 32 * 1024 * 1024;
export const MAX_SENSITIVE_INVENTORY_BYTES = 128 * 1024 * 1024;
export const MAX_UNIQUE_FINDINGS = 10_000;
export const MAX_RECORDED_OCCURRENCES = 20_000;
export const MAX_RECORDED_SCAN_ERRORS = 1_000;
export const MAX_RECORDED_ERROR_FIELD_BYTES = 4 * 1024;
export const MAX_INPUT_ROOTS = 128;
export const MAX_DERIVED_ARTIFACT_BYTES_PER_CANDIDATE = 64 * 1024 * 1024;

export function isSafeDetectorIdentifier(value: unknown): value is string {
  return typeof value === "string" && /^[a-z0-9][a-z0-9.-]{0,127}$/.test(value);
}

export function isBoundedJsonValue(value: unknown, depth = 0): boolean {
  if (value === null || typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (typeof value === "string") return Buffer.byteLength(value) <= MAX_RECORDED_ERROR_FIELD_BYTES;
  if (depth >= 8 || typeof value !== "object") return false;
  if (Array.isArray(value)) return value.length <= 128 && value.every((item) => isBoundedJsonValue(item, depth + 1));
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  let entries = 0;
  for (const key in value as Record<string, unknown>) {
    if (!Object.hasOwn(value, key)) continue;
    entries += 1;
    if (
      entries > 128
      || Buffer.byteLength(key) > 256
      || !isBoundedJsonValue((value as Record<string, unknown>)[key], depth + 1)
    ) return false;
  }
  return true;
}
