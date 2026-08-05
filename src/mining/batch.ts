import { createHash, randomUUID } from "node:crypto";
import { lstat, realpath } from "node:fs/promises";
import path from "node:path";
import {
  acquireExclusiveLock,
  atomicWriteJson,
  ensurePrivateDirectory,
  readDirectoryNamesBounded,
  readJson,
  safeJoin,
  walkRegularFiles,
} from "../core/fs-safe.js";
import { directoryLogicalBytes, gibibytesToBytes } from "../core/storage.js";
import type { MiningOptions, MiningProgress } from "./types.js";
import { MAX_INPUT_ROOTS, MAX_RECORDED_OCCURRENCES, MAX_UNIQUE_FINDINGS } from "./limits.js";
import { loadCompletedInventory, loadScanState } from "./resume.js";
import { resumeSensitiveMaterial, scanSensitiveMaterial } from "./scanner.js";

const BATCH_LOCK = ".aark-batch.lock";
const STATE_FILE = "batch-state-sensitive.json";
const AGGREGATE_FILE = "batch-aggregate-sensitive.json";
const REDACTED_FILE = "batch-manifest-redacted.json";
const MAX_BATCH_INPUTS = 100_000;
const MAX_BATCHES = 100_000;
const MAX_BATCH_STATE_BYTES = 128 * 1024 * 1024;
const DEFAULT_MAX_FILES = 50_000;
const DEFAULT_MAX_BYTES = 256 * 1024 ** 3;
const FINDING_HEADROOM = Math.floor(MAX_UNIQUE_FINDINGS * 0.8);
const OCCURRENCE_HEADROOM = Math.floor(MAX_RECORDED_OCCURRENCES * 0.8);
const BATCH_CONTROL_RESERVE_BYTES = 8n * 1024n * 1024n;

export interface MiningBatchOptions extends Omit<MiningOptions, "output" | "progress"> {
  output: string;
  maximumRootsPerBatch?: number;
  maximumFilesPerBatch?: number;
  maximumBytesPerBatch?: number;
  progress?: (progress: MiningBatchProgress) => void;
}

export interface MiningBatchProgress {
  phase: "partitioning" | "scanning" | "finalizing";
  batch: number;
  batchesCompleted: number;
  rootsCompleted: number;
  rootsTotal: number;
  filesTotal: number;
  filesScanned: number;
  bytesScanned: number;
  uniqueFindings: number;
  occurrences: number;
  scanErrors: number;
}

interface BatchUnit {
  input: string;
  kind: "file" | "directory";
  device: number;
  inode: number;
  modifiedMs: number;
  changedMs: number;
  files: number;
  bytes: number;
}

interface CompletedBatch {
  index: number;
  firstUnit: number;
  nextUnit: number;
  filesScanned: number;
  bytesScanned: number;
  uniqueFindings: number;
  occurrences: number;
}

interface ActiveBatch {
  index: number;
  firstUnit: number;
  nextUnit: number;
  status: "running" | "paused";
  progress: MiningProgress;
}

interface BatchState {
  version: 1;
  tool: "aark";
  layer: "mining-batch";
  runId: string;
  configSha256: string;
  status: "running" | "paused" | "blocked-safety" | "complete";
  startedAt: string;
  updatedAt: string;
  units: BatchUnit[];
  nextUnit: number;
  active: ActiveBatch | null;
  completed: CompletedBatch[];
  totals: {
    filesTotal: number;
    filesScanned: number;
    bytesScanned: number;
    uniqueFindings: number;
    occurrences: number;
  };
  blocker: string | null;
}

interface AggregateState {
  version: 1;
  completedBatches: number[];
  keys: string[];
  categories: Record<string, number>;
  occurrences: number;
}

interface NormalizedBatchOptions extends MiningBatchOptions {
  output: string;
  inputs: string[];
  maximumRootsPerBatch: number;
  maximumFilesPerBatch: number;
  maximumBytesPerBatch: number;
}

export interface ResolvedMiningOutputs {
  outputs: string[];
  batchRoots: string[];
}

function interrupted(signal: AbortSignal | undefined): void {
  if (signal?.aborted === true) throw new Error("mining batch was interrupted");
}

function safeAdd(left: number, right: number, label: string): number {
  const result = left + right;
  if (!Number.isSafeInteger(result) || result < 0) throw new Error(`${label} exceeds safe numeric bounds`);
  return result;
}

function positiveInteger(value: number | undefined, fallback: number, maximum: number, label: string): number {
  const actual = value ?? fallback;
  if (!Number.isSafeInteger(actual) || actual < 1 || actual > maximum) {
    throw new Error(`${label} must be an integer from 1 through ${maximum}`);
  }
  return actual;
}

function normalize(options: MiningBatchOptions): NormalizedBatchOptions {
  if (options.inputs.length < 1 || options.inputs.length > MAX_BATCH_INPUTS) {
    throw new Error(`mine batch requires from 1 through ${MAX_BATCH_INPUTS} input roots`);
  }
  const inputs = [...new Set(options.inputs.map((input) => path.resolve(input)))].sort();
  if (inputs.length !== options.inputs.length) throw new Error("mine batch inputs must be unique");
  const inputSet = new Set(inputs);
  for (const input of inputs) {
    let parent = path.dirname(input);
    while (parent !== input) {
      if (inputSet.has(parent)) throw new Error("mine batch input roots must not contain one another");
      const next = path.dirname(parent);
      if (next === parent) break;
      parent = next;
    }
  }
  const output = path.resolve(options.output);
  if (output === path.parse(output).root) throw new Error("mine batch output must be a dedicated directory");
  for (const input of inputs) {
    const relativeOutput = path.relative(input, output);
    const relativeInput = path.relative(output, input);
    if (
      relativeOutput === "" || (relativeOutput !== ".." && !relativeOutput.startsWith(`..${path.sep}`) && !path.isAbsolute(relativeOutput))
      || relativeInput === "" || (relativeInput !== ".." && !relativeInput.startsWith(`..${path.sep}`) && !path.isAbsolute(relativeInput))
    ) throw new Error("mine batch output and inputs must not contain one another");
  }
  return {
    ...options,
    inputs,
    output,
    maximumRootsPerBatch: positiveInteger(options.maximumRootsPerBatch, MAX_INPUT_ROOTS, MAX_INPUT_ROOTS, "maximum roots per batch"),
    maximumFilesPerBatch: positiveInteger(options.maximumFilesPerBatch, DEFAULT_MAX_FILES, Number.MAX_SAFE_INTEGER, "maximum files per batch"),
    maximumBytesPerBatch: positiveInteger(options.maximumBytesPerBatch, DEFAULT_MAX_BYTES, Number.MAX_SAFE_INTEGER, "maximum bytes per batch"),
  };
}

function configMaterial(options: NormalizedBatchOptions): Record<string, unknown> {
  return {
    inputs: options.inputs,
    output: options.output,
    provenance: options.provenance,
    chunkBytes: options.chunkBytes,
    overlapBytes: options.overlapBytes,
    wholeFileBytes: options.wholeFileBytes,
    deepKeySchedules: options.deepKeySchedules === true,
    workers: options.workers ?? null,
    minimumFreeGiB: options.minimumFreeGiB ?? null,
    minimumFreePercent: options.minimumFreePercent ?? null,
    maximumOutputGiB: options.maximumOutputGiB ?? null,
    maximumRootsPerBatch: options.maximumRootsPerBatch,
    maximumFilesPerBatch: options.maximumFilesPerBatch,
    maximumBytesPerBatch: options.maximumBytesPerBatch,
  };
}

function configHash(options: NormalizedBatchOptions): string {
  return createHash("sha256").update(JSON.stringify(configMaterial(options))).digest("hex");
}

async function inventoryUnits(options: NormalizedBatchOptions): Promise<BatchUnit[]> {
  const units: BatchUnit[] = [];
  for (let index = 0; index < options.inputs.length; index += 1) {
    interrupted(options.signal);
    const input = options.inputs[index];
    if (input === undefined) continue;
    const canonical = await realpath(input);
    if (canonical !== input) throw new Error("mine batch inputs must be canonical paths without symbolic-link aliases");
    const before = await lstat(input);
    if (!before.isFile() && !before.isDirectory()) throw new Error("mine batch inputs must be regular files or directories");
    let files = 0;
    let bytes = 0;
    for await (const file of walkRegularFiles([input], {
      ...(options.signal === undefined ? {} : { signal: options.signal }),
      onError: (_filename, error) => { throw error; },
    })) {
      files += 1;
      bytes += file.bytes;
      if (!Number.isSafeInteger(files) || !Number.isSafeInteger(bytes)) throw new Error("mine batch inventory exceeds safe numeric limits");
    }
    const after = await lstat(input);
    if (before.dev !== after.dev || before.ino !== after.ino || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) {
      throw new Error("mine batch input changed while it was partitioned");
    }
    if (files > 0) {
      units.push({
        input,
        kind: before.isFile() ? "file" : "directory",
        device: before.dev,
        inode: before.ino,
        modifiedMs: before.mtimeMs,
        changedMs: before.ctimeMs,
        files,
        bytes,
      });
    }
    options.progress?.({
      phase: "partitioning",
      batch: 0,
      batchesCompleted: 0,
      rootsCompleted: index + 1,
      rootsTotal: options.inputs.length,
      filesTotal: 0,
      filesScanned: 0,
      bytesScanned: 0,
      uniqueFindings: 0,
      occurrences: 0,
      scanErrors: 0,
    });
  }
  if (units.length < 1) throw new Error("mine batch inputs contain no regular files");
  return units;
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as Record<string, unknown>;
}

function validProgress(value: MiningProgress): boolean {
  return (value.phase === undefined || ["inventory", "stream", "whole-file", "finalizing"].includes(value.phase))
    && [value.filesVisited, value.filesScanned, value.bytesScanned, value.uniqueFindings, value.occurrences, value.scanErrors]
      .every((count) => Number.isSafeInteger(count) && count >= 0)
    && (value.filesTotal === undefined || Number.isSafeInteger(value.filesTotal) && value.filesTotal >= 0);
}

function validIsoDate(value: unknown): value is string {
  if (typeof value !== "string" || Buffer.byteLength(value) > 128) return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function parseState(value: unknown): BatchState {
  const item = record(value, "mining batch state");
  if (
    item.version !== 1 || item.tool !== "aark" || item.layer !== "mining-batch"
    || typeof item.runId !== "string" || !/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u.test(item.runId)
    || typeof item.configSha256 !== "string" || !/^[a-f0-9]{64}$/u.test(item.configSha256)
    || !["running", "paused", "blocked-safety", "complete"].includes(String(item.status))
    || !validIsoDate(item.startedAt) || !validIsoDate(item.updatedAt)
    || !Array.isArray(item.units) || !Array.isArray(item.completed)
    || !Number.isSafeInteger(item.nextUnit) || Number(item.nextUnit) < 0
    || !(item.active === null || typeof item.active === "object")
    || typeof item.totals !== "object" || item.totals === null
    || !(item.blocker === null || typeof item.blocker === "string" && Buffer.byteLength(item.blocker) <= 4096)
  ) throw new Error("mining batch state is invalid");
  const state = value as BatchState;
  const totalsValid = [state.totals.filesTotal, state.totals.filesScanned, state.totals.bytesScanned, state.totals.uniqueFindings, state.totals.occurrences]
    .every((count) => Number.isSafeInteger(count) && count >= 0);
  const unitsValid = state.units.length >= 1 && state.units.length <= MAX_BATCH_INPUTS && state.units.every((unit) => (
    typeof unit === "object" && unit !== null
    && typeof unit.input === "string" && path.isAbsolute(unit.input) && path.resolve(unit.input) === unit.input
    && (unit.kind === "file" || unit.kind === "directory")
    && Number.isSafeInteger(unit.device) && unit.device >= 0
    && Number.isSafeInteger(unit.inode) && unit.inode >= 0
    && Number.isFinite(unit.modifiedMs) && Number.isFinite(unit.changedMs)
    && Number.isSafeInteger(unit.files) && unit.files >= 1
    && Number.isSafeInteger(unit.bytes) && unit.bytes >= 0
  ));
  const completedValid = state.completed.every((batch, index) => (
    typeof batch === "object" && batch !== null
    && batch.index === index + 1
    && Number.isSafeInteger(batch.firstUnit) && Number.isSafeInteger(batch.nextUnit)
    && batch.firstUnit === (index === 0 ? 0 : state.completed[index - 1]?.nextUnit)
    && batch.nextUnit > batch.firstUnit && batch.nextUnit <= state.units.length
    && [batch.filesScanned, batch.bytesScanned, batch.uniqueFindings, batch.occurrences].every((count) => Number.isSafeInteger(count) && count >= 0)
  ));
  const expectedNext = state.completed.at(-1)?.nextUnit ?? 0;
  const activeValid = state.active === null || (
    Number.isSafeInteger(state.active.index) && state.active.index === state.completed.length + 1
    && state.active.firstUnit === expectedNext
    && Number.isSafeInteger(state.active.nextUnit) && state.active.nextUnit > state.active.firstUnit && state.active.nextUnit <= state.units.length
    && (state.active.status === "running" || state.active.status === "paused")
    && typeof state.active.progress === "object" && state.active.progress !== null && validProgress(state.active.progress)
  );
  let expectedTotals: BatchState["totals"];
  try {
    expectedTotals = {
      filesTotal: state.units.reduce((sum, unit) => safeAdd(sum, unit.files, "mining batch file inventory total"), 0),
      filesScanned: state.completed.reduce((sum, batch) => safeAdd(sum, batch.filesScanned, "mining batch scanned-file total"), 0),
      bytesScanned: state.completed.reduce((sum, batch) => safeAdd(sum, batch.bytesScanned, "mining batch scanned-byte total"), 0),
      uniqueFindings: state.completed.reduce((sum, batch) => safeAdd(sum, batch.uniqueFindings, "mining batch child-finding total"), 0),
      occurrences: state.completed.reduce((sum, batch) => safeAdd(sum, batch.occurrences, "mining batch child-occurrence total"), 0),
    };
  } catch {
    throw new Error("mining batch state totals exceed safe numeric bounds");
  }
  if (!unitsValid || !totalsValid || new Set(state.units.map((unit) => unit.input)).size !== state.units.length || !completedValid
    || state.nextUnit !== expectedNext || !activeValid
    || state.totals.filesTotal !== expectedTotals.filesTotal
    || state.totals.filesScanned !== expectedTotals.filesScanned
    || state.totals.bytesScanned !== expectedTotals.bytesScanned
    || state.totals.uniqueFindings !== expectedTotals.uniqueFindings
    || state.totals.occurrences !== expectedTotals.occurrences
    || (state.status === "complete" && (state.nextUnit !== state.units.length || state.active !== null))
    || (state.status === "paused" && !(
      state.active?.status === "paused"
      || state.active === null && state.nextUnit < state.units.length
    ))
    || (state.status === "blocked-safety") !== (state.blocker !== null)
    || (state.status !== "blocked-safety" && state.blocker !== null)) {
    throw new Error("mining batch state has inconsistent units or checkpoint ranges");
  }
  return state;
}

function parseAggregate(value: unknown): AggregateState {
  const item = record(value, "mining batch aggregate");
  if (item.version !== 1 || !Array.isArray(item.completedBatches) || item.completedBatches.length > MAX_BATCHES
    || !Array.isArray(item.keys) || typeof item.categories !== "object" || item.categories === null
    || !Number.isSafeInteger(item.occurrences) || Number(item.occurrences) < 0) {
    throw new Error("mining batch aggregate is invalid");
  }
  if (item.completedBatches.some((batch, index) => batch !== index + 1)
    || item.keys.some((key) => typeof key !== "string" || !/^[a-z0-9][a-z0-9.-]{0,127}\0[a-f0-9]{64}$/u.test(key) || Buffer.byteLength(key) > 256)
    || new Set(item.keys).size !== item.keys.length) throw new Error("mining batch aggregate key or completion list is invalid");
  for (const [category, count] of Object.entries(item.categories as Record<string, unknown>)) {
    if (!/^[a-z0-9][a-z0-9.-]{0,127}$/u.test(category) || !Number.isSafeInteger(count) || Number(count) < 0) {
      throw new Error("mining batch aggregate category is invalid");
    }
  }
  return value as AggregateState;
}

async function writeState(output: string, state: BatchState): Promise<void> {
  state.updatedAt = new Date().toISOString();
  if (Buffer.byteLength(JSON.stringify(state)) > MAX_BATCH_STATE_BYTES) {
    throw new Error("mining batch checkpoint exceeds its bounded control-state limit; split the workflow input set");
  }
  await atomicWriteJson(safeJoin(output, STATE_FILE), state);
}

async function assertUnitsCurrent(units: BatchUnit[], first = 0): Promise<void> {
  for (let index = first; index < units.length; index += 1) {
    const unit = units[index];
    if (unit === undefined) continue;
    const current = await lstat(unit.input);
    if (
      current.isSymbolicLink()
      || (unit.kind === "file" ? !current.isFile() : !current.isDirectory())
      || current.dev !== unit.device || current.ino !== unit.inode
      || current.mtimeMs !== unit.modifiedMs || current.ctimeMs !== unit.changedMs
      || await realpath(unit.input) !== unit.input
    ) throw new Error("mine batch input roots changed after partitioning");
  }
}

function dynamicFileLimit(state: BatchState, options: NormalizedBatchOptions): number {
  if (state.totals.filesScanned < 1) return options.maximumFilesPerBatch;
  const densityLimit = (headroom: number, count: number): number => {
    if (count < 1) return options.maximumFilesPerBatch;
    const projected = BigInt(headroom) * BigInt(state.totals.filesScanned) / BigInt(count);
    return Math.max(1, Number(projected > BigInt(options.maximumFilesPerBatch) ? BigInt(options.maximumFilesPerBatch) : projected));
  };
  const byFindings = densityLimit(FINDING_HEADROOM, state.totals.uniqueFindings);
  const byOccurrences = densityLimit(OCCURRENCE_HEADROOM, state.totals.occurrences);
  return Math.min(options.maximumFilesPerBatch, byFindings, byOccurrences);
}

function selectBatch(state: BatchState, options: NormalizedBatchOptions): { first: number; next: number } {
  const fileLimit = dynamicFileLimit(state, options);
  let next = state.nextUnit;
  let files = 0;
  let bytes = 0;
  while (next < state.units.length && next - state.nextUnit < options.maximumRootsPerBatch) {
    const unit = state.units[next];
    if (unit === undefined) break;
    if (next > state.nextUnit && (files + unit.files > fileLimit || bytes + unit.bytes > options.maximumBytesPerBatch)) break;
    files += unit.files;
    bytes += unit.bytes;
    next += 1;
  }
  if (next === state.nextUnit) next += 1;
  return { first: state.nextUnit, next };
}

function batchDirectory(output: string, index: number): string {
  return safeJoin(output, "batches", `batch-${String(index).padStart(6, "0")}`);
}

export async function resolveMiningOutputs(references: string[], maximumOutputs = 10_000): Promise<ResolvedMiningOutputs> {
  if (references.length < 1 || references.length > maximumOutputs) throw new Error("mining output reference count is outside its supported range");
  const outputs: string[] = [];
  const batchRoots: string[] = [];
  for (const referenceInput of references) {
    const reference = path.resolve(referenceInput);
    let state: BatchState | undefined;
    try {
      state = parseState(await readJson<unknown>(safeJoin(reference, STATE_FILE), MAX_BATCH_STATE_BYTES));
    } catch (error) {
      const code = error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
      const causeCode = error instanceof Error && "cause" in error && error.cause instanceof Error && "code" in error.cause
        ? (error.cause as NodeJS.ErrnoException).code : undefined;
      if (code !== "ENOENT" && causeCode !== "ENOENT") throw error;
    }
    if (state === undefined) {
      outputs.push(reference);
      continue;
    }
    if (state.status !== "complete" || state.active !== null || state.nextUnit !== state.units.length) {
      throw new Error("referenced mining batch workflow is not exactly complete");
    }
    const aggregate = await loadAggregate(reference);
    if (aggregate.completedBatches.length !== state.completed.length) throw new Error("mining batch aggregate is not synchronized with its completed scans");
    batchRoots.push(reference);
    outputs.push(...state.completed.map((batch) => batchDirectory(reference, batch.index)));
    if (outputs.length > maximumOutputs) throw new Error("expanded mining output set exceeds its supported range; retain or clean smaller workflow groups");
  }
  const uniqueOutputs = [...new Set(outputs)].sort();
  const uniqueBatchRoots = [...new Set(batchRoots)].sort();
  if (uniqueOutputs.length !== outputs.length || uniqueBatchRoots.length !== batchRoots.length) throw new Error("mining output references overlap or expand more than once");
  return { outputs: uniqueOutputs, batchRoots: uniqueBatchRoots };
}

async function loadAggregate(output: string): Promise<AggregateState> {
  try {
    return parseAggregate(await readJson<unknown>(safeJoin(output, AGGREGATE_FILE), MAX_BATCH_STATE_BYTES));
  } catch (error) {
    const code = error instanceof Error && "cause" in error && error.cause instanceof Error && "code" in error.cause
      ? (error.cause as NodeJS.ErrnoException).code
      : error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
    if (code === "ENOENT") return { version: 1, completedBatches: [], keys: [], categories: {}, occurrences: 0 };
    throw error;
  }
}

async function updateAggregate(output: string, active: ActiveBatch): Promise<AggregateState> {
  const aggregate = await loadAggregate(output);
  if (aggregate.completedBatches.includes(active.index)) return aggregate;
  if (aggregate.completedBatches.length + 1 !== active.index) throw new Error("mining batch aggregate completion order is inconsistent");
  const keys = new Set(aggregate.keys);
  const scanOutput = batchDirectory(output, active.index);
  const scanState = await loadScanState(scanOutput);
  const inventory = await loadCompletedInventory(scanOutput, scanState.inventory);
  for (const finding of inventory.findings) {
    const key = `${finding.category}\0${finding.sha256}`;
    if (keys.has(key)) continue;
    keys.add(key);
    aggregate.categories[finding.category] = (aggregate.categories[finding.category] ?? 0) + 1;
  }
  aggregate.keys = [...keys].sort();
  const childOccurrences = inventory.findings.reduce(
    (sum, finding) => safeAdd(sum, finding.occurrences.length, "mining batch child occurrence total"),
    0,
  );
  aggregate.occurrences = safeAdd(aggregate.occurrences, childOccurrences, "mining batch aggregate occurrence total");
  aggregate.completedBatches.push(active.index);
  if (Buffer.byteLength(JSON.stringify(aggregate)) > MAX_BATCH_STATE_BYTES) {
    throw new Error("mining batch aggregate exceeds its bounded control-state limit; finish this workflow group and start another");
  }
  await atomicWriteJson(safeJoin(output, AGGREGATE_FILE), aggregate);
  return aggregate;
}

function totalProgress(state: BatchState): Omit<MiningBatchProgress, "phase" | "batch"> {
  return {
    batchesCompleted: state.completed.length,
    rootsCompleted: state.nextUnit,
    rootsTotal: state.units.length,
    filesTotal: state.totals.filesTotal,
    filesScanned: state.totals.filesScanned,
    bytesScanned: state.totals.bytesScanned,
    uniqueFindings: state.totals.uniqueFindings,
    occurrences: state.totals.occurrences,
    scanErrors: 0,
  };
}

async function writeRedacted(output: string, state: BatchState, aggregate: AggregateState): Promise<Record<string, unknown>> {
  const totals = totalProgress(state);
  const complete = state.status === "complete";
  const result = {
    version: 1,
    tool: "aark",
    layer: "mining-batch",
    status: state.status,
    complete,
    resumable: state.status === "running" || state.status === "paused",
    batchesCompleted: totals.batchesCompleted,
    rootsCompleted: totals.rootsCompleted,
    rootsTotal: totals.rootsTotal,
    filesScanned: totals.filesScanned,
    bytesScanned: totals.bytesScanned,
    globallyDeduplicatedFindings: aggregate.keys.length,
    occurrences: aggregate.occurrences,
    categories: aggregate.categories,
    activeBatch: state.active?.index ?? null,
    updatedAt: state.updatedAt,
    valuesPrinted: false,
    pathsRedacted: true,
    ...(state.blocker === null ? {} : { blocker: state.blocker }),
  };
  await atomicWriteJson(safeJoin(output, REDACTED_FILE), result, 0o644);
  return result;
}

export async function runMiningBatch(input: MiningBatchOptions): Promise<Record<string, unknown>> {
  const options = normalize(input);
  let fresh = false;
  try {
    await lstat(options.output);
  } catch (error) {
    const code = error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
    if (code !== "ENOENT") throw error;
    fresh = true;
  }
  if (fresh) await ensurePrivateDirectory(options.output);
  else if (await realpath(options.output) !== options.output) throw new Error("mine batch output must be a canonical real directory");
  const allowed = new Set([BATCH_LOCK, STATE_FILE, AGGREGATE_FILE, REDACTED_FILE, "batches"]);
  const entries = await readDirectoryNamesBounded(options.output, allowed.size + 1);
  if (entries.some((entry) => !allowed.has(entry))) throw new Error("mine batch output contains an unexpected entry");
  const lock = await acquireExclusiveLock(options.output, BATCH_LOCK, { reclaimDeadOwner: true });
  let operationError: unknown;
  try {
    const hash = configHash(options);
    let state: BatchState;
    if (entries.includes(STATE_FILE)) {
      state = parseState(await readJson<unknown>(safeJoin(options.output, STATE_FILE), MAX_BATCH_STATE_BYTES));
      if (state.configSha256 !== hash) throw new Error("mine batch options differ from its durable checkpoint");
      if (state.units.some((unit) => !options.inputs.includes(unit.input))) {
        throw new Error("mine batch checkpoint contains an input outside its current configuration");
      }
      await assertUnitsCurrent(state.units, state.nextUnit);
    } else {
      const units = await inventoryUnits(options);
      const now = new Date().toISOString();
      state = {
        version: 1,
        tool: "aark",
        layer: "mining-batch",
        runId: randomUUID(),
        configSha256: hash,
        status: "running",
        startedAt: now,
        updatedAt: now,
        units,
        nextUnit: 0,
        active: null,
        completed: [],
        totals: {
          filesTotal: units.reduce((sum, unit) => safeAdd(sum, unit.files, "mining batch file inventory total"), 0),
          filesScanned: 0,
          bytesScanned: 0,
          uniqueFindings: 0,
          occurrences: 0,
        },
        blocker: null,
      };
      await ensurePrivateDirectory(safeJoin(options.output, "batches"));
      await atomicWriteJson(safeJoin(options.output, AGGREGATE_FILE), { version: 1, completedBatches: [], keys: [], categories: {}, occurrences: 0 });
      await writeState(options.output, state);
    }
    if (state.status === "complete") return await writeRedacted(options.output, state, await loadAggregate(options.output));
    if (state.status === "blocked-safety") return await writeRedacted(options.output, state, await loadAggregate(options.output));

    while (state.nextUnit < state.units.length || state.active !== null) {
      if (options.signal?.aborted === true && state.active === null) {
        // A signal between children is already a durable boundary. Publish it
        // as a clean pause instead of leaving an ownerless `running` marker.
        state.status = "paused";
        await lock.assertHeld();
        await writeState(options.output, state);
        return await writeRedacted(options.output, state, await loadAggregate(options.output));
      }
      interrupted(options.signal);
      await lock.assertHeld();
      if (state.completed.length >= MAX_BATCHES) throw new Error("mine batch exceeded its bounded batch-count limit");
      if (state.active === null) {
        const selected = selectBatch(state, options);
        state.active = {
          index: state.completed.length + 1,
          firstUnit: selected.first,
          nextUnit: selected.next,
          status: "running",
          progress: { filesVisited: 0, filesScanned: 0, bytesScanned: 0, uniqueFindings: 0, occurrences: 0, scanErrors: 0 },
        };
        state.status = "running";
        await writeState(options.output, state);
      }
      const active = state.active;
      if (active === null) throw new Error("mine batch lost its active batch checkpoint");
      const output = batchDirectory(options.output, active.index);
      let recoveredResult: Record<string, unknown> | undefined;
      try {
        const outputMetadata = await lstat(output);
        if (!outputMetadata.isDirectory() || outputMetadata.isSymbolicLink()) throw new Error("existing child batch output is not a real directory");
        const childState = await loadScanState(output, options.signal);
        active.progress = { ...childState.progress };
        if (childState.status === "paused" && childState.resumable) {
          active.status = "paused";
        } else if (childState.status === "complete" || childState.status === "complete-with-errors") {
          recoveredResult = {
            status: childState.status,
            complete: true,
            resumable: false,
            filesScanned: childState.progress.filesScanned,
            bytesScanned: childState.progress.bytesScanned,
            uniqueFindings: childState.progress.uniqueFindings,
            occurrences: childState.progress.occurrences,
            scanErrors: childState.progress.scanErrors,
          };
        } else {
          throw new Error("an existing child batch output is not at a clean resumable or completed checkpoint");
        }
      } catch (error) {
        const code = error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
        const causeCode = error instanceof Error && "cause" in error && error.cause instanceof Error && "code" in error.cause
          ? (error.cause as NodeJS.ErrnoException).code : undefined;
        if (code !== "ENOENT" && causeCode !== "ENOENT") throw error;
        if (active.status === "paused") throw new Error("paused child batch output disappeared");
      }
      let childMaximumOutputGiB: number | undefined;
      if (recoveredResult === undefined && options.maximumOutputGiB !== undefined) {
        const maximumBytes = gibibytesToBytes(options.maximumOutputGiB, "maximum output GiB");
        const currentBytes = await directoryLogicalBytes(options.output, options.signal);
        const remaining = maximumBytes - currentBytes - BATCH_CONTROL_RESERVE_BYTES;
        const existingChildBytes = active.status === "paused" ? await directoryLogicalBytes(output, options.signal) : 0n;
        const childLimit = remaining > 0n ? existingChildBytes + remaining : 0n;
        const milliGiB = childLimit * 1000n / (1024n ** 3n);
        if (milliGiB < 1n || milliGiB > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("aggregate mining batch output cap has no safe capacity for another child scan");
        childMaximumOutputGiB = Number(milliGiB) / 1000;
      }
      let heartbeatError: unknown;
      let heartbeat = Promise.resolve();
      const timer = setInterval(() => {
        heartbeat = heartbeat.then(async () => {
          await lock.assertHeld();
          await writeState(options.output, state);
        }).catch((error: unknown) => { heartbeatError ??= error; });
      }, 5_000);
      timer.unref();
      const completedProgress = totalProgress(state);
      const reportProgress = (progress: MiningProgress): void => {
        active.progress = { ...progress };
        options.progress?.({
          phase: "scanning",
          batch: active.index,
          ...completedProgress,
          filesScanned: safeAdd(completedProgress.filesScanned, progress.filesScanned, "mining batch live scanned-file total"),
          bytesScanned: safeAdd(completedProgress.bytesScanned, progress.bytesScanned, "mining batch live scanned-byte total"),
          uniqueFindings: safeAdd(completedProgress.uniqueFindings, progress.uniqueFindings, "mining batch live finding total"),
          occurrences: safeAdd(completedProgress.occurrences, progress.occurrences, "mining batch live occurrence total"),
          scanErrors: progress.scanErrors,
        });
      };
      let result: Record<string, unknown>;
      try {
        result = recoveredResult ?? (active.status === "paused"
          ? await resumeSensitiveMaterial({
            output,
            ...(options.workers === undefined ? {} : { workers: options.workers }),
            ...(options.minimumFreeGiB === undefined ? {} : { minimumFreeGiB: options.minimumFreeGiB }),
            ...(options.minimumFreePercent === undefined ? {} : { minimumFreePercent: options.minimumFreePercent }),
            ...(childMaximumOutputGiB === undefined ? {} : { maximumOutputGiB: childMaximumOutputGiB }),
            ...(options.signal === undefined ? {} : { signal: options.signal }),
            progress: reportProgress,
          })
          : await scanSensitiveMaterial({
            inputs: state.units.slice(active.firstUnit, active.nextUnit).map((unit) => unit.input),
            output,
            provenance: options.provenance,
            chunkBytes: options.chunkBytes,
            overlapBytes: options.overlapBytes,
            wholeFileBytes: options.wholeFileBytes,
            ...(options.deepKeySchedules === undefined ? {} : { deepKeySchedules: options.deepKeySchedules }),
            ...(options.workers === undefined ? {} : { workers: options.workers }),
            ...(options.minimumFreeGiB === undefined ? {} : { minimumFreeGiB: options.minimumFreeGiB }),
            ...(options.minimumFreePercent === undefined ? {} : { minimumFreePercent: options.minimumFreePercent }),
            ...(childMaximumOutputGiB === undefined ? {} : { maximumOutputGiB: childMaximumOutputGiB }),
            ...(options.signal === undefined ? {} : { signal: options.signal }),
            progress: reportProgress,
          }));
      } catch (error) {
        state.status = "blocked-safety";
        state.blocker = error instanceof Error && /inventory (?:finding|occurrence) limit reached/u.test(error.message)
          ? "a single adaptive batch reached a sensitive-inventory limit; subdivide its input roots and start a new batch workflow"
          : "a mining batch failed a safety or integrity check; inspect its local redacted report before retrying";
        await lock.assertHeld();
        await writeState(options.output, state);
        return await writeRedacted(options.output, state, await loadAggregate(options.output));
      } finally {
        clearInterval(timer);
        await heartbeat;
      }
      // A heartbeat may have discovered a substituted or removed lock while
      // the child was still finishing. Never commit child advancement unless
      // ownership is freshly re-established at the stage boundary.
      await lock.assertHeld();
      // A successful final checkpoint supersedes a transient heartbeat write
      // failure. If persistence is still unavailable, the state write below
      // will fail and prevent unsafe advancement.
      if (result.status === "paused" && result.resumable === true) {
        active.status = "paused";
        state.status = "paused";
        await writeState(options.output, state);
        return await writeRedacted(options.output, state, await loadAggregate(options.output));
      }
      if (result.status !== "complete" || result.scanErrors !== 0) {
        state.status = "blocked-safety";
        state.blocker = "a mining batch did not finish exactly and error-free; it will not be auto-advanced";
        await writeState(options.output, state);
        return await writeRedacted(options.output, state, await loadAggregate(options.output));
      }
      if (options.maximumOutputGiB !== undefined) {
        const aggregateBytes = await directoryLogicalBytes(options.output, options.signal);
        if (aggregateBytes > gibibytesToBytes(options.maximumOutputGiB, "maximum output GiB")) {
          state.status = "blocked-safety";
          state.blocker = "the aggregate mining batch output cap was reached before safe advancement";
          await writeState(options.output, state);
          return await writeRedacted(options.output, state, await loadAggregate(options.output));
        }
      }
      let aggregate: AggregateState;
      try {
        aggregate = await updateAggregate(options.output, active);
      } catch (error) {
        state.status = "blocked-safety";
        state.blocker = "the global mining aggregate could not be committed within its bounded integrity limits; split the workflow group";
        await lock.assertHeld();
        await writeState(options.output, state);
        return await writeRedacted(options.output, state, await loadAggregate(options.output));
      }
      state.completed.push({
        index: active.index,
        firstUnit: active.firstUnit,
        nextUnit: active.nextUnit,
        filesScanned: Number(result.filesScanned),
        bytesScanned: Number(result.bytesScanned),
        uniqueFindings: Number(result.uniqueFindings),
        occurrences: Number(result.occurrences),
      });
      const completedBatch = state.completed.at(-1);
      if (completedBatch === undefined) throw new Error("mining batch lost its completed-child accounting");
      state.totals.filesScanned = safeAdd(state.totals.filesScanned, completedBatch.filesScanned, "mining batch scanned-file total");
      state.totals.bytesScanned = safeAdd(state.totals.bytesScanned, completedBatch.bytesScanned, "mining batch scanned-byte total");
      state.totals.uniqueFindings = safeAdd(state.totals.uniqueFindings, completedBatch.uniqueFindings, "mining batch child-finding total");
      state.totals.occurrences = safeAdd(state.totals.occurrences, completedBatch.occurrences, "mining batch child-occurrence total");
      state.nextUnit = active.nextUnit;
      state.active = null;
      state.status = "running";
      await writeState(options.output, state);
      await writeRedacted(options.output, state, aggregate);
    }
    state.status = "complete";
    state.active = null;
    state.blocker = null;
    await writeState(options.output, state);
    options.progress?.({ phase: "finalizing", batch: state.completed.length, ...totalProgress(state) });
    return await writeRedacted(options.output, state, await loadAggregate(options.output));
  } catch (error) {
    operationError = error;
    throw error;
  } finally {
    try {
      await lock.release();
    } catch (releaseError) {
      if (operationError !== undefined) throw new AggregateError([operationError, releaseError], "mine batch failed and its lock could not be released");
      throw releaseError;
    }
  }
}
