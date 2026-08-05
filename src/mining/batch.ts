import { createHash, randomUUID } from "node:crypto";
import { lstat, realpath } from "node:fs/promises";
import path from "node:path";
import { isDeepStrictEqual } from "node:util";
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
import { loadScanState, loadVerifiedCompletedInventory } from "./resume.js";
import type { SensitiveScanInventory } from "./types.js";
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
const BATCH_CONTROL_RESERVE_BYTES = 2n * BigInt(MAX_BATCH_STATE_BYTES) + 1024n * 1024n;
const PARTITION_CHECKPOINT_ROOTS = 1_024;
const PARTITION_CHECKPOINT_INTERVAL_MS = 5_000;

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
  status: "partitioning" | "running" | "paused" | "blocked-safety" | "complete";
  startedAt: string;
  updatedAt: string;
  inputsTotal: number;
  partitionNextInput: number;
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

function signalAborted(signal: AbortSignal | undefined): boolean {
  return signal?.aborted === true;
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

async function inventoryUnit(input: string, options: NormalizedBatchOptions): Promise<BatchUnit> {
  interrupted(options.signal);
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
  if (files === 0) throw new Error("mine batch input roots must each contain at least one regular file");
  return {
    input,
    kind: before.isFile() ? "file" : "directory",
    device: before.dev,
    inode: before.ino,
    modifiedMs: before.mtimeMs,
    changedMs: before.ctimeMs,
    files,
    bytes,
  };
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
    || !["partitioning", "running", "paused", "blocked-safety", "complete"].includes(String(item.status))
    || !validIsoDate(item.startedAt) || !validIsoDate(item.updatedAt)
    || !Array.isArray(item.units) || !Array.isArray(item.completed)
    || !Number.isSafeInteger(item.nextUnit) || Number(item.nextUnit) < 0
    || !(item.active === null || typeof item.active === "object")
    || typeof item.totals !== "object" || item.totals === null
    || !(item.blocker === null || typeof item.blocker === "string" && Buffer.byteLength(item.blocker) <= 4096)
  ) throw new Error("mining batch state is invalid");
  // Pre-partition-checkpoint v1 states were written only after every root was
  // inventoried. Default the new counters accordingly so those checkpoints
  // remain forward compatible.
  const legacyUnits = item.units as BatchUnit[];
  const inputsTotal = item.inputsTotal ?? legacyUnits.length;
  const partitionNextInput = item.partitionNextInput ?? legacyUnits.length;
  if (!Number.isSafeInteger(inputsTotal) || Number(inputsTotal) < 1 || Number(inputsTotal) > MAX_BATCH_INPUTS
    || !Number.isSafeInteger(partitionNextInput) || Number(partitionNextInput) < 0 || Number(partitionNextInput) > Number(inputsTotal)) {
    throw new Error("mining batch partition checkpoint is invalid");
  }
  const state = { ...(value as BatchState), inputsTotal: Number(inputsTotal), partitionNextInput: Number(partitionNextInput) };
  const totalsValid = [state.totals.filesTotal, state.totals.filesScanned, state.totals.bytesScanned, state.totals.uniqueFindings, state.totals.occurrences]
    .every((count) => Number.isSafeInteger(count) && count >= 0);
  const unitsValid = state.units.length <= MAX_BATCH_INPUTS && state.units.every((unit) => (
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
  const partitionIncomplete = state.partitionNextInput < state.inputsTotal;
  const pausedPartition = state.status === "paused" && partitionIncomplete
    && state.active === null && state.completed.length === 0 && state.nextUnit === 0;
  if (!unitsValid || !totalsValid || state.units.length !== state.partitionNextInput
    || new Set(state.units.map((unit) => unit.input)).size !== state.units.length || !completedValid
    || state.nextUnit !== expectedNext || !activeValid
    || state.totals.filesTotal !== expectedTotals.filesTotal
    || state.totals.filesScanned !== expectedTotals.filesScanned
    || state.totals.bytesScanned !== expectedTotals.bytesScanned
    || state.totals.uniqueFindings !== expectedTotals.uniqueFindings
    || state.totals.occurrences !== expectedTotals.occurrences
    || (state.status === "partitioning" && !partitionIncomplete)
    || (!partitionIncomplete && state.units.length < 1)
    || (partitionIncomplete && state.status !== "partitioning" && !pausedPartition)
    || (partitionIncomplete && (state.active !== null || state.completed.length !== 0 || state.nextUnit !== 0))
    || (state.status === "complete" && (state.nextUnit !== state.units.length || state.active !== null))
    || (state.status === "paused" && !(
      pausedPartition
      || !partitionIncomplete && (
        state.active?.status === "paused"
        || state.active === null && state.nextUnit <= state.units.length
      )
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
    || !Array.isArray(item.keys) || typeof item.categories !== "object" || item.categories === null || Array.isArray(item.categories)
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
    await verifyCompletedAggregate(reference, state);
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

function assertChildBinding(
  parentOutput: string,
  parent: BatchState,
  range: Pick<CompletedBatch, "firstUnit" | "nextUnit" | "index">,
  child: Awaited<ReturnType<typeof loadScanState>>,
  options?: NormalizedBatchOptions,
): void {
  const childOutput = batchDirectory(parentOutput, range.index);
  const expectedInputs = parent.units.slice(range.firstUnit, range.nextUnit).map((unit) => unit.input);
  if (child.semantic.output !== childOutput || !isDeepStrictEqual(child.semantic.inputs, expectedInputs)) {
    throw new Error("completed child scan is not bound to its parent batch range");
  }
  if (options !== undefined && (
    child.semantic.provenance !== options.provenance
    || child.semantic.chunkBytes !== options.chunkBytes
    || child.semantic.overlapBytes !== options.overlapBytes
    || child.semantic.wholeFileBytes !== options.wholeFileBytes
    || child.semantic.deepKeySchedules !== (options.deepKeySchedules === true)
  )) throw new Error("completed child scan options disagree with its parent batch configuration");
}

async function loadVerifiedChild(
  output: string,
  parent: BatchState,
  range: Pick<CompletedBatch, "firstUnit" | "nextUnit" | "index">,
  options?: NormalizedBatchOptions,
  signal?: AbortSignal,
): Promise<{ state: Awaited<ReturnType<typeof loadScanState>>; inventory: SensitiveScanInventory }> {
  const childOutput = batchDirectory(output, range.index);
  const state = await loadScanState(childOutput, signal);
  assertChildBinding(output, parent, range, state, options);
  const inventory = await loadVerifiedCompletedInventory(childOutput, state, signal);
  return { state, inventory };
}

async function verifyCompletedAggregate(
  output: string,
  state: BatchState,
  options?: NormalizedBatchOptions,
  signal?: AbortSignal,
): Promise<AggregateState> {
  const rebuilt: AggregateState = { version: 1, completedBatches: [], keys: [], categories: {}, occurrences: 0 };
  const keys = new Set<string>();
  for (const batch of state.completed) {
    interrupted(signal);
    const child = await loadVerifiedChild(output, state, batch, options, signal);
    const childOccurrences = child.inventory.findings.reduce(
      (sum, finding) => safeAdd(sum, finding.occurrences.length, "mining batch child occurrence total"),
      0,
    );
    if (
      batch.filesScanned !== child.state.progress.filesScanned
      || batch.bytesScanned !== child.state.progress.bytesScanned
      || batch.uniqueFindings !== child.state.progress.uniqueFindings
      || batch.occurrences !== child.state.progress.occurrences
      || childOccurrences !== batch.occurrences
    ) throw new Error("completed child scan counters disagree with the parent batch checkpoint");
    for (const finding of child.inventory.findings) {
      const key = `${finding.category}\0${finding.sha256}`;
      if (keys.has(key)) continue;
      keys.add(key);
      rebuilt.categories[finding.category] = safeAdd(
        Object.hasOwn(rebuilt.categories, finding.category) ? rebuilt.categories[finding.category] ?? 0 : 0,
        1,
        "mining batch aggregate category total",
      );
    }
    rebuilt.occurrences = safeAdd(rebuilt.occurrences, childOccurrences, "mining batch aggregate occurrence total");
    rebuilt.completedBatches.push(batch.index);
  }
  rebuilt.keys = [...keys].sort();
  const stored = await loadAggregate(output);
  if (!isDeepStrictEqual(stored, rebuilt)) throw new Error("mining batch aggregate disagrees with its verified completed scans");
  return stored;
}

async function updateAggregate(output: string, active: ActiveBatch, inventory: SensitiveScanInventory): Promise<AggregateState> {
  const aggregate = await loadAggregate(output);
  if (aggregate.completedBatches.includes(active.index)) return aggregate;
  if (aggregate.completedBatches.length + 1 !== active.index) throw new Error("mining batch aggregate completion order is inconsistent");
  const keys = new Set(aggregate.keys);
  for (const finding of inventory.findings) {
    const key = `${finding.category}\0${finding.sha256}`;
    if (keys.has(key)) continue;
    keys.add(key);
    aggregate.categories[finding.category] = safeAdd(
      Object.hasOwn(aggregate.categories, finding.category) ? aggregate.categories[finding.category] ?? 0 : 0,
      1,
      "mining batch aggregate category total",
    );
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

async function verifiedCompletedChild(
  output: string,
  parent: BatchState,
  active: ActiveBatch,
  options: NormalizedBatchOptions,
  result: Record<string, unknown>,
  signal?: AbortSignal,
): Promise<{
  inventory: SensitiveScanInventory;
  filesScanned: number;
  bytesScanned: number;
  uniqueFindings: number;
  occurrences: number;
}> {
  const { state, inventory } = await loadVerifiedChild(output, parent, active, options, signal);
  const expected = {
    filesScanned: state.progress.filesScanned,
    bytesScanned: state.progress.bytesScanned,
    uniqueFindings: state.progress.uniqueFindings,
    occurrences: state.progress.occurrences,
  };
  if (result.status !== "complete" || result.complete !== true || result.resumable !== false
    || result.scanErrors !== 0
    || result.filesScanned !== expected.filesScanned
    || result.bytesScanned !== expected.bytesScanned
    || result.uniqueFindings !== expected.uniqueFindings
    || result.occurrences !== expected.occurrences) {
    throw new Error("completed child scan result disagrees with its exact durable checkpoint");
  }
  return { inventory, ...expected };
}

function totalProgress(state: BatchState): Omit<MiningBatchProgress, "phase" | "batch"> {
  return {
    batchesCompleted: state.completed.length,
    rootsCompleted: state.nextUnit,
    rootsTotal: state.inputsTotal,
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
    resumable: state.status === "partitioning" || state.status === "running" || state.status === "paused",
    batchesCompleted: totals.batchesCompleted,
    rootsPartitioned: state.partitionNextInput,
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
  let entries = await readDirectoryNamesBounded(options.output, allowed.size + 1);
  if (entries.some((entry) => !allowed.has(entry))) throw new Error("mine batch output contains an unexpected entry");
  const lock = await acquireExclusiveLock(options.output, BATCH_LOCK, { reclaimDeadOwner: true });
  let operationError: unknown;
  try {
    entries = await readDirectoryNamesBounded(options.output, allowed.size + 1);
    if (entries.some((entry) => !allowed.has(entry))) throw new Error("mine batch output changed to contain an unexpected entry while its lock was acquired");
    const hash = configHash(options);
    let state: BatchState;
    if (entries.includes(STATE_FILE)) {
      state = parseState(await readJson<unknown>(safeJoin(options.output, STATE_FILE), MAX_BATCH_STATE_BYTES));
      if (state.configSha256 !== hash) throw new Error("mine batch options differ from its durable checkpoint");
      if (state.inputsTotal !== options.inputs.length
        || !isDeepStrictEqual(state.units.map((unit) => unit.input), options.inputs.slice(0, state.partitionNextInput))) {
        throw new Error("mine batch checkpoint inputs do not exactly match its current configuration");
      }
      await assertUnitsCurrent(state.units, state.nextUnit);
    } else {
      const now = new Date().toISOString();
      state = {
        version: 1,
        tool: "aark",
        layer: "mining-batch",
        runId: randomUUID(),
        configSha256: hash,
        status: "partitioning",
        startedAt: now,
        updatedAt: now,
        inputsTotal: options.inputs.length,
        partitionNextInput: 0,
        units: [],
        nextUnit: 0,
        active: null,
        completed: [],
        totals: {
          filesTotal: 0,
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
    if (state.partitionNextInput < state.inputsTotal) {
      state.status = "partitioning";
      state.blocker = null;
      await writeState(options.output, state);
      let checkpointedInput = state.partitionNextInput;
      let checkpointedAt = Date.now();
      while (state.partitionNextInput < state.inputsTotal) {
        if (options.signal?.aborted === true) {
          state.status = "paused";
          await writeState(options.output, state);
          return await writeRedacted(options.output, state, await loadAggregate(options.output));
        }
        const input = options.inputs[state.partitionNextInput];
        if (input === undefined) throw new Error("mine batch lost its next configured input root");
        let unit: BatchUnit;
        try {
          unit = await inventoryUnit(input, options);
        } catch (error) {
          if (!signalAborted(options.signal)) throw error;
          state.status = "paused";
          await writeState(options.output, state);
          return await writeRedacted(options.output, state, await loadAggregate(options.output));
        }
        state.units.push(unit);
        state.partitionNextInput += 1;
        state.totals.filesTotal = safeAdd(state.totals.filesTotal, unit.files, "mining batch file inventory total");
        if (state.partitionNextInput === state.inputsTotal) state.status = "running";
        const now = Date.now();
        if (state.partitionNextInput === state.inputsTotal
          || state.partitionNextInput - checkpointedInput >= PARTITION_CHECKPOINT_ROOTS
          || now - checkpointedAt >= PARTITION_CHECKPOINT_INTERVAL_MS) {
          await writeState(options.output, state);
          checkpointedInput = state.partitionNextInput;
          checkpointedAt = now;
        }
        options.progress?.({
          phase: "partitioning",
          batch: 0,
          batchesCompleted: 0,
          rootsCompleted: state.partitionNextInput,
          rootsTotal: state.inputsTotal,
          filesTotal: state.totals.filesTotal,
          filesScanned: 0,
          bytesScanned: 0,
          uniqueFindings: 0,
          occurrences: 0,
          scanErrors: 0,
        });
      }
      state.status = "running";
    }
    if (state.status === "complete") {
      return await writeRedacted(options.output, state, await verifyCompletedAggregate(options.output, state, options, options.signal));
    }
    if (state.status === "blocked-safety") {
      // A fresh invocation is an explicit retry after remediation. Re-enter
      // the exact child/aggregate checks below; they will publish the same
      // blocker again unless the underlying safety condition is truly fixed.
      state.status = "running";
      state.blocker = null;
    }

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
      let childOutputExists = false;
      let childCheckpointLoaded = false;
      try {
        const outputMetadata = await lstat(output);
        childOutputExists = true;
        if (!outputMetadata.isDirectory() || outputMetadata.isSymbolicLink()) throw new Error("existing child batch output is not a real directory");
        const childState = await loadScanState(output);
        childCheckpointLoaded = true;
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
        if (code !== "ENOENT" && causeCode !== "ENOENT") {
          state.status = "blocked-safety";
          state.blocker = "an existing child batch output failed durable checkpoint or filesystem verification";
          await lock.assertHeld();
          await writeState(options.output, state);
          return await writeRedacted(options.output, state, await loadAggregate(options.output));
        }
        if (active.status === "paused") {
          state.status = "blocked-safety";
          state.blocker = "a paused child batch output disappeared and cannot be resumed safely";
          await lock.assertHeld();
          await writeState(options.output, state);
          return await writeRedacted(options.output, state, await loadAggregate(options.output));
        }
      }
      if (options.signal?.aborted === true) {
        if (!childOutputExists) state.active = null;
        else if (childCheckpointLoaded) active.status = "paused";
        else {
          state.status = "blocked-safety";
          state.blocker = "an existing child output has no durable scan checkpoint; inspect it before retrying";
        }
        if (state.status !== "blocked-safety") state.status = "paused";
        await lock.assertHeld();
        await writeState(options.output, state);
        return await writeRedacted(options.output, state, await loadAggregate(options.output));
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
      const heartbeatAbort = new AbortController();
      const childSignal = options.signal === undefined
        ? heartbeatAbort.signal
        : AbortSignal.any([options.signal, heartbeatAbort.signal]);
      const timer = setInterval(() => {
        heartbeat = heartbeat.then(async () => {
          await lock.assertHeld();
          await writeState(options.output, state);
        }).catch((error: unknown) => {
          heartbeatError ??= error;
          heartbeatAbort.abort();
        });
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
            signal: childSignal,
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
            signal: childSignal,
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
      if (heartbeatError !== undefined) {
        // The child was asked to stop at its own durable boundary. Do not
        // advance the outer batch even if the child happened to finish while
        // the heartbeat write was failing; a later invocation will verify and
        // commit that completed checkpoint idempotently.
        await lock.assertHeld();
        active.status = "paused";
        state.status = "paused";
        state.blocker = null;
        await writeState(options.output, state);
        return await writeRedacted(options.output, state, await loadAggregate(options.output));
      }
      // A heartbeat may have discovered a substituted or removed lock while
      // the child was still finishing. Never commit child advancement unless
      // ownership is freshly re-established at the stage boundary.
      await lock.assertHeld();
      // A successful final checkpoint supersedes a transient heartbeat write
      // failure. If persistence is still unavailable, the state write below
      // will fail and prevent unsafe advancement.
      if (signalAborted(options.signal) && result.status === "complete") {
        active.status = "paused";
        state.status = "paused";
        await writeState(options.output, state);
        return await writeRedacted(options.output, state, await loadAggregate(options.output));
      }
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
      let completedChild: Awaited<ReturnType<typeof verifiedCompletedChild>>;
      try {
        completedChild = await verifiedCompletedChild(options.output, state, active, options, result, options.signal);
      } catch {
        state.status = "blocked-safety";
        state.blocker = "a completed child scan failed exact checkpoint, counter, or artifact verification; inspect it before advancement";
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
        aggregate = await updateAggregate(options.output, active, completedChild.inventory);
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
        filesScanned: completedChild.filesScanned,
        bytesScanned: completedChild.bytesScanned,
        uniqueFindings: completedChild.uniqueFindings,
        occurrences: completedChild.occurrences,
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
    if (options.signal?.aborted === true) {
      state.status = "paused";
      await writeState(options.output, state);
      return await writeRedacted(options.output, state, await loadAggregate(options.output));
    }
    state.active = null;
    state.blocker = null;
    let aggregate: AggregateState;
    try {
      aggregate = await verifyCompletedAggregate(options.output, state, options, options.signal);
    } catch (error) {
      if (!signalAborted(options.signal)) throw error;
      state.status = "paused";
      await writeState(options.output, state);
      return await writeRedacted(options.output, state, await loadAggregate(options.output));
    }
    state.status = "complete";
    await writeState(options.output, state);
    options.progress?.({ phase: "finalizing", batch: state.completed.length, ...totalProgress(state) });
    return await writeRedacted(options.output, state, aggregate);
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
