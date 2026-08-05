import { createHash } from "node:crypto";
import path from "node:path";
import { readJson } from "../core/fs-safe.js";
import type { Provenance } from "../core/types.js";
import { loadRecoveryConfig } from "../recovery/config.js";
import type { RecoveryConfig } from "../recovery/types.js";
import type {
  CleanupPlanWorkflowStage,
  MiningBatchWorkflowStage,
  RecoveryWorkflowStage,
  RetentionWorkflowStage,
  SegmentedCleanupPlanWorkflowStage,
  WorkflowConfig,
  WorkflowStage,
  WorkflowStorageConfig,
} from "./types.js";

const PROVENANCE = new Set<Provenance>([
  "deleted-metadata", "unallocated-carve", "unallocated-stream", "shadow-copy",
  "residual-memory", "allocated-reference", "unknown",
]);

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as Record<string, unknown>;
}

function known(value: Record<string, unknown>, keys: readonly string[], label: string): void {
  const unexpected = Object.keys(value).filter((key) => !keys.includes(key));
  if (unexpected.length > 0) throw new Error(`${label} contains ${unexpected.length} unknown field(s)`);
}

function text(value: unknown, label: string, maximumBytes = 256): string {
  if (typeof value !== "string" || value.trim() === "" || Buffer.byteLength(value) > maximumBytes || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new Error(`${label} must be bounded non-empty text without control characters`);
  }
  return value;
}

function identifier(value: unknown, label: string): string {
  const result = text(value, label, 128);
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(result)) throw new Error(`${label} must be a safe identifier`);
  return result;
}

function absolute(value: unknown, label: string): string {
  const result = text(value, label, 4096);
  if (!path.isAbsolute(result)) throw new Error(`${label} must be an absolute path`);
  return path.normalize(result);
}

function boolean(value: unknown, fallback: boolean, label: string): boolean {
  if (value === undefined) return fallback;
  if (typeof value !== "boolean") throw new Error(`${label} must be a boolean`);
  return value;
}

function integer(value: unknown, fallback: number, minimum: number, maximum: number, label: string): number {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || Number(value) < minimum || Number(value) > maximum) {
    throw new Error(`${label} must be an integer from ${minimum} through ${maximum}`);
  }
  return Number(value);
}

function decimal(value: unknown, fallback: number, minimum: number, maximum: number, label: string, scale = 1000): number {
  if (value === undefined) return fallback;
  const rounded = typeof value === "number" ? Math.round(value * scale) : Number.NaN;
  const tolerance = typeof value === "number" ? Number.EPSILON * Math.max(1, Math.abs(value)) * 8 : 0;
  if (typeof value !== "number" || !Number.isFinite(value) || value < minimum || value > maximum
    || !Number.isSafeInteger(rounded) || Math.abs(value - rounded / scale) > tolerance) {
    throw new Error(`${label} must be a number from ${minimum} through ${maximum} with bounded decimal precision`);
  }
  return value;
}

function absoluteList(value: unknown, label: string, maximum: number): string[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > maximum) throw new Error(`${label} must contain from 1 through ${maximum} paths`);
  const result = value.map((item, index) => absolute(item, `${label}[${index}]`));
  if (new Set(result).size !== result.length) throw new Error(`${label} paths must be unique`);
  return result;
}

function storage(value: unknown, label: string): WorkflowStorageConfig {
  const item = value === undefined ? {} : record(value, label);
  known(item, ["minimumFreeGiB", "minimumFreePercent", "maximumOutputGiB"], label);
  return {
    minimumFreeGiB: decimal(item.minimumFreeGiB, 5, 0, 1_000_000, `${label}.minimumFreeGiB`),
    minimumFreePercent: decimal(item.minimumFreePercent, 5, 0, 100, `${label}.minimumFreePercent`, 100),
    ...(item.maximumOutputGiB === undefined ? {} : {
      maximumOutputGiB: decimal(item.maximumOutputGiB, 0, 0.001, 1_000_000, `${label}.maximumOutputGiB`),
    }),
  };
}

function stage(value: unknown, index: number): WorkflowStage {
  const item = record(value, `stages[${index}]`);
  const id = identifier(item.id, `stages[${index}].id`);
  const kind = text(item.kind, `stages[${index}].kind`);
  if (kind === "recovery") {
    known(item, ["id", "kind", "config"], `stages[${index}]`);
    return { id, kind, config: absolute(item.config, `stages[${index}].config`) } satisfies RecoveryWorkflowStage;
  }
  if (kind === "mining-batch") {
    known(item, [
      "id", "kind", "inputs", "output", "provenance", "chunkMiB", "overlapMiB", "wholeFileMiB",
      "deepKeySchedules", "workers", "storage", "maximumRootsPerBatch", "maximumFilesPerBatch", "maximumGiBPerBatch",
    ], `stages[${index}]`);
    const provenance = text(item.provenance ?? "unknown", `stages[${index}].provenance`) as Provenance;
    if (!PROVENANCE.has(provenance)) throw new Error(`stages[${index}].provenance is unsupported`);
    return {
      id,
      kind,
      inputs: absoluteList(item.inputs, `stages[${index}].inputs`, 100_000),
      output: absolute(item.output, `stages[${index}].output`),
      provenance,
      chunkMiB: integer(item.chunkMiB, 32, 1, 128, `stages[${index}].chunkMiB`),
      overlapMiB: integer(item.overlapMiB, 17, 1, 128, `stages[${index}].overlapMiB`),
      wholeFileMiB: integer(item.wholeFileMiB, 64, 1, 256, `stages[${index}].wholeFileMiB`),
      deepKeySchedules: boolean(item.deepKeySchedules, false, `stages[${index}].deepKeySchedules`),
      ...(item.workers === undefined ? {} : { workers: integer(item.workers, 1, 1, 4, `stages[${index}].workers`) }),
      storage: storage(item.storage, `stages[${index}].storage`),
      maximumRootsPerBatch: integer(item.maximumRootsPerBatch, 128, 1, 128, `stages[${index}].maximumRootsPerBatch`),
      maximumFilesPerBatch: integer(item.maximumFilesPerBatch, 50_000, 1, Number.MAX_SAFE_INTEGER, `stages[${index}].maximumFilesPerBatch`),
      maximumGiBPerBatch: decimal(item.maximumGiBPerBatch, 256, 0.001, 1_000_000, `stages[${index}].maximumGiBPerBatch`),
    } satisfies MiningBatchWorkflowStage;
  }
  if (kind === "retention") {
    known(item, ["id", "kind", "miningOutputs", "destination", "requireReadOnlySources", "storage"], `stages[${index}]`);
    return {
      id,
      kind,
      miningOutputs: absoluteList(item.miningOutputs, `stages[${index}].miningOutputs`, 128),
      destination: absolute(item.destination, `stages[${index}].destination`),
      requireReadOnlySources: boolean(item.requireReadOnlySources, true, `stages[${index}].requireReadOnlySources`),
      storage: storage(item.storage, `stages[${index}].storage`),
    } satisfies RetentionWorkflowStage;
  }
  if (kind === "cleanup-plan") {
    known(item, ["id", "kind", "caseDirectory", "miningOutputs", "includeEvidence"], `stages[${index}]`);
    return {
      id,
      kind,
      caseDirectory: absolute(item.caseDirectory, `stages[${index}].caseDirectory`),
      miningOutputs: absoluteList(item.miningOutputs, `stages[${index}].miningOutputs`, 128),
      includeEvidence: boolean(item.includeEvidence, false, `stages[${index}].includeEvidence`),
    } satisfies CleanupPlanWorkflowStage;
  }
  if (kind === "segmented-cleanup-plan") {
    known(item, ["id", "kind", "segments", "activeSegments", "miningOutputs", "retentionDirectory", "errorSourceDisposition"], `stages[${index}]`);
    const disposition = text(item.errorSourceDisposition ?? "retain", `stages[${index}].errorSourceDisposition`);
    if (disposition !== "retain" && disposition !== "delete") throw new Error(`stages[${index}].errorSourceDisposition must be retain or delete`);
    return {
      id,
      kind,
      segments: absoluteList(item.segments, `stages[${index}].segments`, 10_000),
      activeSegments: item.activeSegments === undefined ? [] : (() => {
        if (!Array.isArray(item.activeSegments) || item.activeSegments.length > 10_000) throw new Error(`stages[${index}].activeSegments must contain at most 10000 paths`);
        const values = item.activeSegments.map((entry, activeIndex) => absolute(entry, `stages[${index}].activeSegments[${activeIndex}]`));
        if (new Set(values).size !== values.length) throw new Error(`stages[${index}].activeSegments paths must be unique`);
        return values;
      })(),
      miningOutputs: absoluteList(item.miningOutputs, `stages[${index}].miningOutputs`, 128),
      retentionDirectory: absolute(item.retentionDirectory, `stages[${index}].retentionDirectory`),
      errorSourceDisposition: disposition,
    } satisfies SegmentedCleanupPlanWorkflowStage;
  }
  throw new Error(`stages[${index}].kind is unsupported; destructive cleanup execution is intentionally unavailable to workflow automation`);
}

export async function loadWorkflowConfig(filename: string): Promise<WorkflowConfig> {
  const document = record(await readJson<unknown>(filename), "workflow configuration");
  known(document, ["version", "workflowId", "directory", "stages"], "workflow configuration");
  if (document.version !== 1) throw new Error("workflow configuration version must be 1");
  if (!Array.isArray(document.stages) || document.stages.length < 1 || document.stages.length > 1_000) {
    throw new Error("workflow configuration requires from 1 through 1000 stages");
  }
  const parsedStages = document.stages.map(stage);
  const stages: WorkflowStage[] = [];
  for (const parsed of parsedStages) {
    if (parsed.kind === "recovery") {
      // Bind the normalized, validated nested configuration into the outer
      // workflow hash. The JSON schema intentionally does not accept a
      // caller-provided digest that could become detached from the file.
      const recovery = await loadRecoveryConfig(parsed.config);
      stages.push({ ...parsed, configSha256: recoveryWorkflowConfigHash(recovery) });
    } else {
      stages.push(parsed);
    }
  }
  if (new Set(stages.map((item) => item.id)).size !== stages.length) throw new Error("workflow stage identifiers must be unique");
  const approvalGate = stages.findIndex((item) => item.kind === "cleanup-plan" || item.kind === "segmented-cleanup-plan");
  if (approvalGate >= 0 && approvalGate !== stages.length - 1) {
    throw new Error("a cleanup planning approval gate must be the final workflow stage; cleanup execution is never auto-chained");
  }
  const directory = absolute(document.directory, "workflow directory");
  if (directory === path.parse(directory).root) throw new Error("workflow directory must be a dedicated directory");
  return { version: 1, workflowId: identifier(document.workflowId, "workflowId"), directory, stages };
}

export function recoveryWorkflowConfigHash(config: RecoveryConfig): string {
  return createHash("sha256").update(JSON.stringify(config)).digest("hex");
}

export function workflowConfigHash(config: WorkflowConfig): string {
  return createHash("sha256").update(JSON.stringify(config)).digest("hex");
}
