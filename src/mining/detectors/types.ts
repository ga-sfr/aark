import type { Candidate } from "../../core/types.js";

export interface DetectionContext {
  sourcePath: string;
  baseOffset: number;
  wholeFile: boolean;
  deepKeySchedules?: boolean;
}

export type Detector = (data: Buffer, context: DetectionContext) => Candidate[];

export function absoluteCandidate(candidate: Candidate, context: DetectionContext): Candidate {
  return { ...candidate, offset: context.baseOffset + candidate.offset };
}
