import path from "node:path";
import { readJson } from "../core/fs-safe.js";
import type { RecoveryConfig, RecoveryStages } from "./types.js";

const DEFAULT_STAGES: RecoveryStages = {
  deletedMetadata: true,
  ntfsUndelete: false,
  unallocatedStream: true,
  signatureCarving: true,
  volumeShadows: false,
  residualMemory: false,
  deletedRegistryCells: false,
};

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function knownKeys(value: Record<string, unknown>, allowed: readonly string[], label: string): void {
  const unexpected = Object.keys(value).filter((key) => !allowed.includes(key));
  if (unexpected.length > 0) throw new Error(`${label} contains ${unexpected.length} unknown field(s)`);
}

function text(value: unknown, label: string): string {
  if (typeof value !== "string" || value.trim() === "") throw new Error(`${label} must be a non-empty string`);
  if (/[\u0000-\u001f\u007f]/.test(value)) throw new Error(`${label} must not contain ASCII control characters`);
  return value;
}

function boolean(value: unknown, fallback: boolean, label: string): boolean {
  if (value === undefined) return fallback;
  if (typeof value !== "boolean") throw new Error(`${label} must be a boolean`);
  return value;
}

function integer(value: unknown, fallback: number, label: string, minimum: number, maximum = Number.MAX_SAFE_INTEGER): number {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new Error(`${label} must be an integer from ${minimum} through ${maximum}`);
  }
  return value as number;
}

function absolute(value: unknown, label: string): string {
  const result = text(value, label);
  if (!path.isAbsolute(result)) throw new Error(`${label} must be an absolute path`);
  return path.normalize(result);
}

function within(root: string, candidate: string): boolean {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

export async function loadRecoveryConfig(filename: string): Promise<RecoveryConfig> {
  const document = record(await readJson<unknown>(filename), "configuration");
  knownKeys(document, [
    "version", "caseId", "source", "analysisSource", "mountedReadOnlyRoot", "destination",
    "requireReadOnlySource", "execute", "sectorOffset", "photoRecCommand", "image", "stages",
  ], "configuration");
  if (document.version !== 1) throw new Error("configuration version must be 1");
  const stagesInput = document.stages === undefined ? {} : record(document.stages, "stages");
  const imageInput = document.image === undefined ? {} : record(document.image, "image");
  knownKeys(stagesInput, Object.keys(DEFAULT_STAGES), "stages");
  knownKeys(imageInput, ["enabled", "path", "mapfile", "retryPasses"], "image");
  const imageEnabled = boolean(imageInput.enabled, false, "image.enabled");
  const source = absolute(document.source, "source");
  const destination = absolute(document.destination, "destination");
  if (destination === path.parse(destination).root) throw new Error("destination must be a dedicated case directory, not the filesystem root");
  if (path.resolve(destination) === path.resolve(source)) throw new Error("destination must be distinct from source");
  if (within(destination, source)) throw new Error("source must not be stored inside the recovery case directory");
  const evidenceRoot = path.join(destination, "evidence");
  const imagePath = imageInput.path === undefined
    ? path.join(destination, "evidence", "source.img")
    : absolute(imageInput.path, "image.path");
  const mapfile = imageInput.mapfile === undefined
    ? path.join(destination, "evidence", "source.map")
    : absolute(imageInput.mapfile, "image.mapfile");
  if (imageEnabled) {
    if (path.resolve(imagePath) === path.resolve(source)) throw new Error("image.path must not overwrite source");
    if (!within(evidenceRoot, imagePath) || !within(evidenceRoot, mapfile)) {
      throw new Error("image.path and image.mapfile must stay below the case evidence directory");
    }
    if (path.resolve(imagePath) === path.resolve(evidenceRoot) || path.resolve(mapfile) === path.resolve(evidenceRoot)) {
      throw new Error("image.path and image.mapfile must name files below the case evidence directory");
    }
    if (path.resolve(mapfile) === path.resolve(source) || path.resolve(mapfile) === path.resolve(imagePath)) {
      throw new Error("image.mapfile must be distinct from source and image.path");
    }
    if (within(imagePath, mapfile) || within(mapfile, imagePath)) {
      throw new Error("image.path and image.mapfile must not contain one another");
    }
  }
  const sectorOffset = integer(document.sectorOffset, 0, "sectorOffset", 0);
  const retryPasses = integer(imageInput.retryPasses, 3, "image.retryPasses", 0, 20);

  const analysisSource = document.analysisSource === undefined
    ? undefined
    : absolute(document.analysisSource, "analysisSource");
  const mountedReadOnlyRoot = document.mountedReadOnlyRoot === undefined
    ? undefined
    : absolute(document.mountedReadOnlyRoot, "mountedReadOnlyRoot");
  if (analysisSource !== undefined) {
    if (within(mapfile, analysisSource) || within(analysisSource, mapfile)) throw new Error("analysisSource must not overlap the ddrescue mapfile path");
    if (
      path.resolve(analysisSource) !== path.resolve(imagePath)
      && (within(imagePath, analysisSource) || within(analysisSource, imagePath))
    ) throw new Error("analysisSource must not overlap the planned evidence image path");
    if (within(destination, analysisSource) && !within(evidenceRoot, analysisSource)) {
      throw new Error("an analysisSource inside the case must stay below its reserved evidence directory");
    }
  }
  if (mountedReadOnlyRoot !== undefined && (within(destination, mountedReadOnlyRoot) || within(mountedReadOnlyRoot, destination))) {
    throw new Error("mountedReadOnlyRoot and destination must not contain one another");
  }
  const caseId = text(document.caseId, "caseId");
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(caseId)) {
    throw new Error("caseId must start with an alphanumeric character and contain at most 128 alphanumeric, dot, underscore, or hyphen characters");
  }
  const stages = Object.fromEntries(
    Object.entries(DEFAULT_STAGES).map(([key, fallback]) => [key, boolean(stagesInput[key], fallback, `stages.${key}`)]),
  ) as unknown as RecoveryStages;
  if (stages.signatureCarving && !stages.unallocatedStream) {
    throw new Error("signatureCarving requires unallocatedStream so PhotoRec never scans allocated source data");
  }
  const photoRecCommand = document.photoRecCommand === undefined
    ? "partition_none,fileopt,everything,enable,search"
    : text(document.photoRecCommand, "photoRecCommand");
  if (photoRecCommand.length > 4096) throw new Error("photoRecCommand must not exceed 4096 characters");
  const photoRecTokens = photoRecCommand.split(",");
  if (stages.signatureCarving && (
    photoRecTokens[0] !== "partition_none"
    || photoRecTokens.at(-1) !== "search"
    || photoRecTokens.length > 256
    || photoRecTokens.some((token) => !/^[A-Za-z0-9_.+-]{1,64}$/.test(token))
  )) {
    throw new Error("photoRecCommand must begin with partition_none, end with search, and contain at most 256 simple comma-separated tokens");
  }
  return {
    version: 1,
    caseId,
    source,
    ...(analysisSource === undefined ? {} : { analysisSource }),
    ...(mountedReadOnlyRoot === undefined ? {} : { mountedReadOnlyRoot }),
    destination,
    requireReadOnlySource: boolean(document.requireReadOnlySource, true, "requireReadOnlySource"),
    execute: boolean(document.execute, false, "execute"),
    sectorOffset,
    photoRecCommand,
    image: {
      enabled: imageEnabled,
      path: imagePath,
      mapfile,
      retryPasses,
    },
    stages,
  };
}
