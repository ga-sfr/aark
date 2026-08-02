import { randomUUID } from "node:crypto";
import { lstat, realpath, rename, rm } from "node:fs/promises";
import path from "node:path";
import type { Candidate, JsonValue, Provenance } from "../core/types.js";
import { sha256Hex } from "../core/crypto.js";
import type { StorageBudget } from "../core/storage.js";
import { assertNoSymlinkComponents, atomicWriteFile, ensurePrivateDirectory, safeJoin, syncDirectory } from "../core/fs-safe.js";
import {
  MAX_RECORDED_ERROR_FIELD_BYTES,
  MAX_DERIVED_ARTIFACT_BYTES_PER_CANDIDATE,
  MAX_RECORDED_OCCURRENCES,
  MAX_RECORDED_SCAN_ERRORS,
  MAX_SENSITIVE_INVENTORY_BYTES,
  MAX_UNIQUE_FINDINGS,
  isSafeDetectorIdentifier,
} from "./limits.js";
import { renderMiningRedactedReport, renderMiningSensitiveReport } from "./report.js";
import type { MiningProgress, MiningRunStatus, SensitiveFinding, SensitiveScanInventory } from "./types.js";

function genericId(id: number): string {
  return `finding-${String(id).padStart(6, "0")}`;
}

function safeExtension(extension: string): string {
  return /^\.[a-z0-9][a-z0-9.-]{0,40}$/i.test(extension) ? extension : ".bin";
}

function safeDerivedName(filename: string): string {
  if (filename !== path.basename(filename) || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(filename)) {
    throw new Error("validator supplied an unsafe derived artifact filename");
  }
  return filename;
}

export class ArtifactStore {
  private readonly findings: SensitiveFinding[] = [];
  private readonly byValue = new Map<string, SensitiveFinding>();
  private readonly occurrenceKeys = new Set<string>();
  private occurrenceCount = 0;
  private readonly errors: SensitiveScanInventory["errors"] = [];
  private errorsOmitted = 0;
  private startedAt = new Date().toISOString();

  public constructor(
    private readonly output: string,
    private readonly inputRoots: string[],
    private readonly deepKeySchedules: boolean,
    private readonly assertOutputSafe?: () => Promise<void>,
    private readonly storageBudget?: StorageBudget,
  ) {}

  public restore(inventory: SensitiveScanInventory): void {
    if (this.findings.length !== 0 || this.errors.length !== 0 || this.occurrenceCount !== 0) {
      throw new Error("artifact store can only be restored before accepting scan results");
    }
    const restoredOccurrences = inventory.findings.reduce((sum, finding) => sum + finding.occurrences.length, 0);
    if (
      inventory.findings.length > MAX_UNIQUE_FINDINGS
      || restoredOccurrences > MAX_RECORDED_OCCURRENCES
      || inventory.errors.length > MAX_RECORDED_SCAN_ERRORS
    ) throw new Error("restored mining inventory exceeds its bounded metadata limits");
    this.startedAt = inventory.startedAt;
    for (const source of inventory.findings) {
      const finding: SensitiveFinding = {
        ...source,
        artifactFiles: [...source.artifactFiles],
        artifactIntegrity: source.artifactIntegrity.map((entry) => ({ ...entry })),
        occurrences: source.occurrences.map((entry) => ({ ...entry })),
      };
      if (finding.id !== this.findings.length + 1 || !/^[a-f0-9]{64}$/.test(finding.sha256)) {
        throw new Error("restored mining inventory has invalid finding identifiers or hashes");
      }
      const valueKey = `${finding.category}\0${finding.sha256}`;
      if (this.byValue.has(valueKey)) throw new Error("restored mining inventory contains duplicate findings");
      this.findings.push(finding);
      this.byValue.set(valueKey, finding);
      for (const occurrence of finding.occurrences) {
        const occurrenceKey = `${valueKey}\0${occurrence.sourcePath}\0${occurrence.offset}`;
        if (this.occurrenceKeys.has(occurrenceKey)) throw new Error("restored mining inventory contains duplicate occurrences");
        this.occurrenceKeys.add(occurrenceKey);
        this.occurrenceCount += 1;
      }
    }
    this.errors.push(...inventory.errors.map((entry) => ({ ...entry })));
    this.errorsOmitted = inventory.errorsOmitted;
  }

  public async initialize(): Promise<void> {
    await this.assertOutputSafe?.();
    await ensurePrivateDirectory(this.output);
    const artifacts = safeJoin(this.output, "artifacts");
    await assertNoSymlinkComponents(this.output, artifacts);
    await ensurePrivateDirectory(artifacts);
    await this.assertOutputSafe?.();
  }

  public counts(): { uniqueFindings: number; occurrences: number; scanErrors: number } {
    return {
      uniqueFindings: this.findings.length,
      occurrences: this.occurrenceCount,
      scanErrors: this.errors.length + this.errorsOmitted,
    };
  }

  public recordError(sourcePath: string, operation: string, error: unknown): void {
    if (this.errors.length < MAX_RECORDED_SCAN_ERRORS) this.errors.push({
      sourcePath: boundedText(sourcePath),
      operation: boundedText(operation, 256),
      message: boundedText(error instanceof Error ? error.message : String(error)),
    });
    else this.errorsOmitted += 1;
  }

  public async add(sourcePath: string, provenance: Provenance, candidate: Candidate): Promise<void> {
    await this.assertOutputSafe?.();
    if (!isSafeDetectorIdentifier(candidate.category) || !isSafeDetectorIdentifier(candidate.validation.method)) {
      throw new Error("validator returned an unsafe category or validation identifier");
    }
    if (!Number.isSafeInteger(candidate.offset) || candidate.offset < 0 || candidate.length !== candidate.value.length) {
      throw new Error("validator returned inconsistent candidate bounds");
    }
    if ((candidate.derivedArtifacts?.length ?? 0) > 16) throw new Error("validator returned too many derived artifacts");
    let derivedArtifactBytes = 0;
    for (const artifact of candidate.derivedArtifacts ?? []) {
      if (artifact.data.length > MAX_DERIVED_ARTIFACT_BYTES_PER_CANDIDATE - derivedArtifactBytes) {
        throw new Error("validator returned derived artifacts above the per-candidate byte limit");
      }
      derivedArtifactBytes += artifact.data.length;
    }
    const digest = sha256Hex(candidate.value);
    const valueKey = `${candidate.category}\0${digest}`;
    const occurrenceKey = `${valueKey}\0${sourcePath}\0${candidate.offset}`;
    if (this.occurrenceKeys.has(occurrenceKey)) return;

    let finding = this.byValue.get(valueKey);
    if (this.occurrenceCount >= MAX_RECORDED_OCCURRENCES) {
      throw new Error("sensitive inventory occurrence limit reached; split the scan into smaller input sets");
    }
    if (finding === undefined && this.findings.length >= MAX_UNIQUE_FINDINGS) {
      throw new Error("sensitive inventory finding limit reached; split the scan into smaller input sets");
    }
    if (finding === undefined) {
      const id = this.findings.length + 1;
      const directoryName = genericId(id);
      const artifactFiles: string[] = [];
      const artifactIntegrity: SensitiveFinding["artifactIntegrity"] = [];
      if (candidate.confidence !== "marker-only") {
        const directory = safeJoin(this.output, "artifacts", directoryName);
        const staging = safeJoin(this.output, "artifacts", `.staging-${directoryName}-${randomUUID()}`);
        await assertNoSymlinkComponents(this.output, directory);
        await assertNoSymlinkComponents(this.output, staging);
        let published = false;
        let stagingIdentity: { device: number; inode: number } | undefined;
        try {
          const artifactBytes = BigInt(candidate.value.length + derivedArtifactBytes);
          await this.storageBudget?.beforeWrite(artifactBytes);
          await ensurePrivateDirectory(staging);
          const stagingMetadata = await lstat(staging);
          if (stagingMetadata.isSymbolicLink() || !stagingMetadata.isDirectory() || await realpath(staging) !== staging) {
            throw new Error("artifact staging path must be a canonical real directory");
          }
          stagingIdentity = { device: stagingMetadata.dev, inode: stagingMetadata.ino };
          const primaryName = `value${safeExtension(candidate.extension)}`;
          const names = new Set([primaryName.toLowerCase()]);
          const primary = safeJoin(staging, primaryName);
          await this.assertOutputSafe?.();
          await atomicWriteFile(primary, candidate.value);
          const primaryRelative = path.join("artifacts", directoryName, primaryName);
          artifactFiles.push(primaryRelative);
          artifactIntegrity.push({ path: primaryRelative, bytes: candidate.value.length, sha256: digest });
          for (const derived of candidate.derivedArtifacts ?? []) {
            const filename = safeDerivedName(derived.filename);
            const collisionKey = filename.toLowerCase();
            if (names.has(collisionKey)) throw new Error("validator supplied duplicate or reserved derived artifact filenames");
            names.add(collisionKey);
            const mode = derived.mode ?? 0o600;
            if (!Number.isSafeInteger(mode) || mode < 0 || mode > 0o777 || (mode & 0o077) !== 0) {
              throw new Error("derived sensitive artifacts must use a private Unix mode");
            }
            const destination = safeJoin(staging, filename);
            await this.assertOutputSafe?.();
            await atomicWriteFile(destination, derived.data, mode);
            const relative = path.join("artifacts", directoryName, filename);
            artifactFiles.push(relative);
            artifactIntegrity.push({ path: relative, bytes: derived.data.length, sha256: sha256Hex(derived.data) });
          }
          await this.assertOutputSafe?.();
          await rename(staging, directory);
          published = true;
          const assertPublishedDirectory = async (): Promise<void> => {
            const current = await lstat(directory);
            if (
              current.isSymbolicLink()
              || !current.isDirectory()
              || current.dev !== stagingIdentity?.device
              || current.ino !== stagingIdentity.inode
              || await realpath(directory) !== directory
            ) throw new Error("artifact directory changed during publication");
          };
          await assertPublishedDirectory();
          await syncDirectory(path.dirname(directory));
          await assertPublishedDirectory();
          this.storageBudget?.committedWrite(artifactBytes);
          await this.assertOutputSafe?.();
        } catch (error) {
          let cleanupError: unknown;
          if (!published && stagingIdentity !== undefined) {
            try {
              await this.assertOutputSafe?.();
              const current = await lstat(staging);
              if (
                current.isSymbolicLink()
                || !current.isDirectory()
                || current.dev !== stagingIdentity.device
                || current.ino !== stagingIdentity.inode
                || await realpath(staging) !== staging
              ) throw new Error("artifact staging directory changed before cleanup");
              await rm(staging, { recursive: true, force: false });
              await syncDirectory(path.dirname(staging));
            } catch (candidateCleanupError) {
              const code = candidateCleanupError instanceof Error && "code" in candidateCleanupError
                ? (candidateCleanupError as NodeJS.ErrnoException).code
                : undefined;
              if (code !== "ENOENT") cleanupError = candidateCleanupError;
            }
          }
          if (cleanupError !== undefined) throw new AggregateError([error, cleanupError], "artifact publication failed and its verified staging directory could not be removed");
          throw error;
        }
      }
      finding = {
        id,
        category: candidate.category,
        confidence: candidate.confidence,
        bytes: candidate.value.length,
        sha256: digest,
        validation: candidate.validation,
        artifactFiles,
        artifactIntegrity,
        ...(candidate.sensitiveMetadata === undefined ? {} : { sensitiveMetadata: candidate.sensitiveMetadata }),
        occurrences: [],
      };
      this.findings.push(finding);
      this.byValue.set(valueKey, finding);
    }
    this.occurrenceKeys.add(occurrenceKey);
    finding.occurrences.push({ sourcePath, offset: candidate.offset, length: candidate.length, provenance });
    this.occurrenceCount += 1;
  }

  private sensitiveInventory(
    status: MiningRunStatus,
    failureMessage?: string,
    resumeCheckpoint?: SensitiveScanInventory["resumeCheckpoint"],
  ): SensitiveScanInventory {
    const finished = status !== "in-progress";
    return {
      version: 1,
      tool: "aark",
      layer: "mining",
      status,
      complete: status === "complete" || status === "complete-with-errors",
      startedAt: this.startedAt,
      updatedAt: new Date().toISOString(),
      ...(finished ? { finishedAt: new Date().toISOString() } : {}),
      ...(failureMessage === undefined ? {} : { failureMessage: boundedText(failureMessage) }),
      inputRoots: [...this.inputRoots],
      outputRoot: this.output,
      ...(resumeCheckpoint === undefined ? {} : { resumeCheckpoint }),
      findings: this.findings,
      errors: this.errors,
      errorsOmitted: this.errorsOmitted,
    };
  }

  private redactedManifest(status: MiningRunStatus, progress: MiningProgress): Record<string, JsonValue> {
    const categories: Record<string, number> = Object.create(null) as Record<string, number>;
    const confidence: Record<string, number> = Object.create(null) as Record<string, number>;
    for (const finding of this.findings) {
      categories[finding.category] = (categories[finding.category] ?? 0) + 1;
      confidence[finding.confidence] = (confidence[finding.confidence] ?? 0) + 1;
    }
    return {
      version: 1,
      tool: "aark",
      layer: "mining",
      status,
      complete: status === "complete" || status === "complete-with-errors",
      updatedAt: new Date().toISOString(),
      valuesRedacted: true,
      sourcePathsRedacted: true,
      offsetsRedacted: true,
      hashesRedacted: true,
      deepKeySchedules: this.deepKeySchedules,
      filesVisited: progress.filesVisited,
      filesScanned: progress.filesScanned,
      bytesScanned: progress.bytesScanned,
      uniqueFindings: progress.uniqueFindings,
      occurrences: progress.occurrences,
      scanErrors: this.errors.length + this.errorsOmitted,
      categories,
      confidence,
      reports: {
        sensitive: "final-report-sensitive.md",
        redacted: "final-report-redacted.md",
      },
      findings: this.findings.map((finding) => ({
        id: finding.id,
        category: finding.category,
        confidence: finding.confidence,
        disposition: finding.confidence === "marker-only" ? "marker-only-not-exported" : "recovered",
        bytes: finding.bytes,
        validation: { method: finding.validation.method, checks: finding.validation.checks },
        artifactCount: finding.artifactFiles.length,
        occurrenceCount: finding.occurrences.length,
      })),
    };
  }

  private async writeChecked(filename: string, data: Uint8Array | string, mode = 0o600, enforceCapacity = true): Promise<void> {
    await this.assertOutputSafe?.();
    const destination = safeJoin(this.output, filename);
    await assertNoSymlinkComponents(this.output, destination);
    let replacingBytes = 0n;
    try {
      const existing = await lstat(destination);
      if (existing.isSymbolicLink() || !existing.isFile()) throw new Error("mining control output must remain a regular file");
      replacingBytes = BigInt(existing.size);
    } catch (error) {
      const code = error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
      if (code !== "ENOENT") throw error;
    }
    const newBytes = BigInt(typeof data === "string" ? Buffer.byteLength(data) : data.byteLength);
    if (enforceCapacity) await this.storageBudget?.beforeWrite(newBytes, replacingBytes);
    await atomicWriteFile(destination, data, mode);
    this.storageBudget?.committedWrite(newBytes, replacingBytes);
    await this.assertOutputSafe?.();
  }

  private serializedInventory(inventory: SensitiveScanInventory): string {
    const serialized = `${JSON.stringify(inventory, null, 2)}\n`;
    if (Buffer.byteLength(serialized) > MAX_SENSITIVE_INVENTORY_BYTES) {
      throw new Error("sensitive inventory exceeded its bounded size limit; split the scan into smaller input sets");
    }
    return serialized;
  }

  public async checkpoint(
    progress: MiningProgress,
    resumeCheckpoint?: SensitiveScanInventory["resumeCheckpoint"],
  ): Promise<{ bytes: number; sha256: string }> {
    const inventory = this.sensitiveInventory("in-progress", undefined, resumeCheckpoint);
    const serialized = this.serializedInventory(inventory);
    await this.writeChecked("inventory-sensitive.json", serialized);
    await this.writeChecked("manifest-redacted.json", `${JSON.stringify(this.redactedManifest("in-progress", progress), null, 2)}\n`, 0o644);
    return { bytes: Buffer.byteLength(serialized), sha256: sha256Hex(Buffer.from(serialized)) };
  }

  public async finalize(
    status: Exclude<MiningRunStatus, "in-progress">,
    progress: MiningProgress,
    failureMessage?: string,
    emergency = false,
    resumeCheckpoint?: SensitiveScanInventory["resumeCheckpoint"],
  ): Promise<{ bytes: number; sha256: string }> {
    const inventory = this.sensitiveInventory(status, failureMessage, resumeCheckpoint);
    const serialized = this.serializedInventory(inventory);
    await this.writeChecked("final-report-sensitive.md", renderMiningSensitiveReport(inventory, progress), 0o600, !emergency);
    await this.writeChecked("final-report-redacted.md", renderMiningRedactedReport(inventory, progress), 0o644, !emergency);
    await this.writeChecked("manifest-redacted.json", `${JSON.stringify(this.redactedManifest(status, progress), null, 2)}\n`, 0o644, !emergency);
    await this.writeChecked("inventory-sensitive.json", serialized, 0o600, !emergency);
    return { bytes: Buffer.byteLength(serialized), sha256: sha256Hex(Buffer.from(serialized)) };
  }
}

function boundedText(value: string, maximumBytes = MAX_RECORDED_ERROR_FIELD_BYTES): string {
  const data = Buffer.from(value, "utf8");
  if (data.length <= maximumBytes) return value;
  const suffix = "...[truncated]";
  const prefix = data.subarray(0, Math.max(0, maximumBytes - Buffer.byteLength(suffix)));
  return `${prefix.toString("utf8").replace(/\uFFFD+$/u, "")}${suffix}`;
}
