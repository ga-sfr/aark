import { randomUUID } from "node:crypto";
import { rename, rm } from "node:fs/promises";
import path from "node:path";
import type { Candidate, JsonValue, Provenance } from "../core/types.js";
import { sha256Hex } from "../core/crypto.js";
import { assertNoSymlinkComponents, atomicWriteFile, ensurePrivateDirectory, safeJoin, syncDirectory } from "../core/fs-safe.js";
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
  private readonly startedAt = new Date().toISOString();

  public constructor(
    private readonly output: string,
    private readonly inputRoots: string[],
    private readonly deepKeySchedules: boolean,
    private readonly assertOutputSafe?: () => Promise<void>,
  ) {}

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
    if (this.errors.length < 10_000) this.errors.push({ sourcePath, operation, message: error instanceof Error ? error.message : String(error) });
    else this.errorsOmitted += 1;
  }

  public async add(sourcePath: string, provenance: Provenance, candidate: Candidate): Promise<void> {
    await this.assertOutputSafe?.();
    if (!Number.isSafeInteger(candidate.offset) || candidate.offset < 0 || candidate.length !== candidate.value.length) {
      throw new Error("validator returned inconsistent candidate bounds");
    }
    const digest = sha256Hex(candidate.value);
    const valueKey = `${candidate.category}\0${digest}`;
    const occurrenceKey = `${valueKey}\0${sourcePath}\0${candidate.offset}`;
    if (this.occurrenceKeys.has(occurrenceKey)) return;
    this.occurrenceKeys.add(occurrenceKey);

    let finding = this.byValue.get(valueKey);
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
        try {
          await ensurePrivateDirectory(staging);
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
          await syncDirectory(path.dirname(directory));
          await this.assertOutputSafe?.();
        } finally {
          if (!published) await rm(staging, { recursive: true, force: true }).catch(() => undefined);
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
    finding.occurrences.push({ sourcePath, offset: candidate.offset, length: candidate.length, provenance });
    this.occurrenceCount += 1;
  }

  private sensitiveInventory(status: MiningRunStatus, failureMessage?: string): SensitiveScanInventory {
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
      ...(failureMessage === undefined ? {} : { failureMessage }),
      inputRoots: [...this.inputRoots],
      outputRoot: this.output,
      findings: this.findings,
      errors: this.errors,
      errorsOmitted: this.errorsOmitted,
    };
  }

  private redactedManifest(status: MiningRunStatus, progress: MiningProgress): Record<string, JsonValue> {
    const categories: Record<string, number> = {};
    const confidence: Record<string, number> = {};
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
        artifactFiles: finding.artifactFiles,
        occurrenceCount: finding.occurrences.length,
      })),
    };
  }

  private async writeChecked(filename: string, data: Uint8Array | string, mode = 0o600): Promise<void> {
    await this.assertOutputSafe?.();
    const destination = safeJoin(this.output, filename);
    await assertNoSymlinkComponents(this.output, destination);
    await atomicWriteFile(destination, data, mode);
    await this.assertOutputSafe?.();
  }

  public async checkpoint(progress: MiningProgress): Promise<void> {
    const inventory = this.sensitiveInventory("in-progress");
    await this.writeChecked("inventory-sensitive.json", `${JSON.stringify(inventory, null, 2)}\n`);
    await this.writeChecked("manifest-redacted.json", `${JSON.stringify(this.redactedManifest("in-progress", progress), null, 2)}\n`, 0o644);
  }

  public async finalize(status: Exclude<MiningRunStatus, "in-progress">, progress: MiningProgress, failureMessage?: string): Promise<void> {
    const inventory = this.sensitiveInventory(status, failureMessage);
    await this.writeChecked("final-report-sensitive.md", renderMiningSensitiveReport(inventory, progress));
    await this.writeChecked("final-report-redacted.md", renderMiningRedactedReport(inventory, progress), 0o644);
    await this.writeChecked("manifest-redacted.json", `${JSON.stringify(this.redactedManifest(status, progress), null, 2)}\n`, 0o644);
    await this.writeChecked("inventory-sensitive.json", `${JSON.stringify(inventory, null, 2)}\n`);
  }
}
