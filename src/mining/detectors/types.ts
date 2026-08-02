import type { Candidate } from "../../core/types.js";
import { MAX_CANDIDATE_BYTES_PER_DETECTOR_JOB, MAX_CANDIDATES_PER_DETECTOR_JOB, MAX_STRUCTURAL_VALIDATIONS_PER_DETECTOR_JOB } from "../limits.js";

export interface DetectorRuntimeState {
  candidateLimitReached: boolean;
  validationLimitReached: boolean;
  structuralValidations: number;
  candidateBytes: number;
  candidateByteLimit?: number;
}

export interface DetectionContext {
  sourcePath: string;
  baseOffset: number;
  wholeFile: boolean;
  deepKeySchedules?: boolean;
  runtimeState?: DetectorRuntimeState;
}

export type Detector = (data: Buffer, context: DetectionContext) => Candidate[];

export function absoluteCandidate(candidate: Candidate, context: DetectionContext): Candidate {
  return { ...candidate, offset: context.baseOffset + candidate.offset };
}

export function appendCandidate(output: Candidate[], candidate: Candidate, context: DetectionContext): boolean {
  if (output.length >= MAX_CANDIDATES_PER_DETECTOR_JOB) {
    if (context.runtimeState !== undefined) context.runtimeState.candidateLimitReached = true;
    return false;
  }
  const byteLimit = context.runtimeState?.candidateByteLimit ?? MAX_CANDIDATE_BYTES_PER_DETECTOR_JOB;
  if (!Number.isSafeInteger(byteLimit) || byteLimit < 1 || byteLimit > MAX_CANDIDATE_BYTES_PER_DETECTOR_JOB) {
    throw new Error("detector candidate byte limit is invalid");
  }
  let candidateBytes = candidate.value.byteLength;
  for (const artifact of candidate.derivedArtifacts ?? []) {
    if (artifact.data.byteLength > byteLimit - candidateBytes) {
      if (context.runtimeState !== undefined) context.runtimeState.candidateLimitReached = true;
      return false;
    }
    candidateBytes += artifact.data.byteLength;
  }
  if (
    context.runtimeState !== undefined
    && candidateBytes > byteLimit - context.runtimeState.candidateBytes
  ) {
    context.runtimeState.candidateLimitReached = true;
    return false;
  }
  if (context.runtimeState !== undefined) context.runtimeState.candidateBytes += candidateBytes;
  output.push(candidate);
  return true;
}

export function markCandidateLimit(context: DetectionContext): void {
  if (context.runtimeState !== undefined) context.runtimeState.candidateLimitReached = true;
}

export function takeStructuralValidation(context: DetectionContext, maximum = MAX_STRUCTURAL_VALIDATIONS_PER_DETECTOR_JOB): boolean {
  const state = context.runtimeState;
  if (state === undefined) return true;
  const boundedMaximum = Math.min(maximum, MAX_STRUCTURAL_VALIDATIONS_PER_DETECTOR_JOB);
  if (!Number.isSafeInteger(boundedMaximum) || boundedMaximum < 1) throw new Error("detector validation limit must be a positive safe integer");
  if (state.structuralValidations >= boundedMaximum) {
    state.validationLimitReached = true;
    return false;
  }
  state.structuralValidations += 1;
  return true;
}

export function markValidationLimit(context: DetectionContext): void {
  if (context.runtimeState !== undefined) {
    context.runtimeState.validationLimitReached = true;
    context.runtimeState.structuralValidations = MAX_STRUCTURAL_VALIDATIONS_PER_DETECTOR_JOB;
  }
}
