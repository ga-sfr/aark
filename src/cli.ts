#!/usr/bin/env node
import process from "node:process";
import { Command, Option } from "commander";
import { dependencyReport } from "./recovery/dependencies.js";
import { machineInventory } from "./recovery/inventory.js";
import { loadRecoveryConfig } from "./recovery/config.js";
import { buildRecoveryPlan } from "./recovery/plan.js";
import { redactedPlan, runRecoveryPlan } from "./recovery/runner.js";
import { resumeSensitiveMaterial, scanSensitiveMaterial } from "./mining/scanner.js";
import { readValidatedRevealArtifact } from "./mining/reveal.js";
import { planCleanup, runCleanup } from "./cleanup.js";
import { runMiningBatch } from "./mining/batch.js";
import { planRetention, runRetention } from "./retention.js";
import { planSegmentedCleanup, runSegmentedCleanup } from "./segmented-cleanup.js";
import { loadWorkflowConfig } from "./workflow/config.js";
import { runWorkflowUntilBlocked } from "./workflow/controller.js";
import { workflowStatus } from "./workflow/status.js";
import { planWorkflowUpgrade, runWorkflowUpgrade } from "./workflow/upgrade.js";
import {
  readyContinuation,
  invariantFailureContinuation,
  safetyBlockedContinuation,
  terminalContinuation,
  userBlockedContinuation,
  withContinuation,
} from "./workflow/continuation.js";
import type { ContinuationState } from "./workflow/continuation.js";
import type { Provenance } from "./core/types.js";

const VERSION = "0.2.0";
const PROVENANCE: Provenance[] = [
  "deleted-metadata",
  "unallocated-carve",
  "unallocated-stream",
  "shadow-copy",
  "residual-memory",
  "allocated-reference",
  "unknown",
];

function json(value: unknown): void {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

function resultJson(value: unknown, state: ContinuationState): void {
  json(withContinuation(value, state));
}

function resultStatus(value: Record<string, unknown>, completeNextAction: string): ContinuationState {
  if (value.status === "paused") return safetyBlockedContinuation(
    "operation paused at a clean checkpoint; resolve the reported capacity or signal blocker before resuming",
    "resume-operation",
  );
  if (value.status === "blocked-safety") return safetyBlockedContinuation(
    "operation stopped on a safety or integrity gate that requires local remediation",
    "resume-operation",
  );
  if (value.status === "complete-with-errors") return safetyBlockedContinuation(
    "scan completed with one or more errors; remediate or rescan before retention or cleanup",
    "review-scan-errors",
  );
  if (value.complete === true || value.status === "complete" || value.status === "complete-with-warnings") {
    return readyContinuation(completeNextAction);
  }
  return safetyBlockedContinuation(
    "operation returned without a recognized successful terminal checkpoint; inspect its local report before continuing",
    "inspect-operation-state",
  );
}

function upgradeResultStatus(value: Record<string, unknown>): ContinuationState {
  if (value.readyToResume === true) return readyContinuation("workflow-resume-with-candidate");
  const blocker = typeof value.resumeBlocker === "string" ? value.resumeBlocker : "the resumed workflow reached a durable boundary";
  const nextAction = typeof value.resumeNextAction === "string" ? value.resumeNextAction : null;
  if (value.resumeWorkflowState === "blocked-user") return userBlockedContinuation(blocker, nextAction);
  if (value.resumeWorkflowState === "blocked-safety") {
    return safetyBlockedContinuation(blocker, nextAction);
  }
  if (value.resumeWorkflowState === "invariant-failure") return invariantFailureContinuation(blocker);
  if (value.resumeWorkflowState === "terminal") return terminalContinuation();
  throw new Error("workflow upgrade result does not identify its post-test continuation boundary");
}

function mib(value: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1) throw new Error("size options must be positive whole MiB values");
  return parsed * 1024 * 1024;
}

function quantity(value: string, label: string): number {
  if (value.trim() === "") throw new Error(`${label} must be a non-negative number`);
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) throw new Error(`${label} must be a non-negative number`);
  return parsed;
}

function workers(value: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > 4) throw new Error("workers must be an integer from 1 through 4");
  return parsed;
}

function redactedError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  if (process.env.AARK_SENSITIVE_DEBUG === "1" || process.env.AGETNIC_SENSITIVE_DEBUG === "1") return message;
  return message
    .replace(/(["'])(?:\/|[A-Za-z]:\\)[^"'\r\n]*\1/g, "$1<PATH>$1")
    .replace(/(^|[\s"'`(=:,])\/(?!\/)(?:[^/\s"'`()=:,]+\/)*[^/\s"'`()=:,]+/gm, "$1<PATH>")
    .replace(/[A-Za-z]:\\(?:[^\s:]+\\)*[^\s:]*/g, "<PATH>");
}

function supportedNodeVersion(version: string): boolean {
  const [major = 0, minor = 0] = version.split(".").map(Number);
  return major > 22 || (major === 22 && minor >= 12);
}

const program = new Command()
  .name("aark")
  .description("Agentic Artifact Recovery Kit: read-only recovery and offline sensitive-material analysis")
  .version(VERSION)
  .configureOutput({ outputError: (message, write) => write(redactedError(message)) })
  .showHelpAfterError();

program.command("doctor")
  .description("Report local forensic-tool availability without changing the machine")
  .option("--json", "emit JSON")
  .action(async (options: { json?: boolean }) => {
    const dependencies = await dependencyReport();
    const report = {
      node: process.version,
      platform: process.platform,
      architecture: process.arch,
      supportedNode: supportedNodeVersion(process.versions.node),
      dependencies,
    };
    if (options.json === true) resultJson(report, terminalContinuation());
    else {
      process.stdout.write(`Node ${report.node} (${report.supportedNode ? "supported" : "requires 22.12+"})\n`);
      for (const dependency of dependencies) {
        process.stdout.write(`${dependency.available ? "ok     " : "missing"}  ${dependency.executable}  ${dependency.purpose}\n`);
      }
    }
  });

const recover = program.command("recover").description("Plan and run read-only disk-recovery workflows");

recover.command("inventory")
  .description("Inventory block devices and mounts without changing them")
  .option("--json", "emit the full local JSON inventory")
  .action(async (options: { json?: boolean }) => {
    const inventory = await machineInventory();
    if (options.json === true) resultJson(inventory, terminalContinuation());
    else process.stdout.write("Inventory collected. Use --json to display the local device and mount details.\n");
  });

recover.command("plan")
  .description("Build and display a redacted recovery plan")
  .requiredOption("-c, --config <path>", "case configuration JSON")
  .action(async (options: { config: string }) => {
    const config = await loadRecoveryConfig(options.config);
    resultJson(
      redactedPlan(buildRecoveryPlan(config)),
      userBlockedContinuation("reviewed recovery execution still requires both configuration and CLI confirmations", "recover-run"),
    );
  });

recover.command("run")
  .description("Execute a reviewed recovery plan; requires two independent confirmations")
  .requiredOption("-c, --config <path>", "case configuration JSON")
  .option("--execute", "second execution confirmation", false)
  .action(async (options: { config: string; execute: boolean }) => {
    const config = await loadRecoveryConfig(options.config);
    const controller = new AbortController();
    const interrupt = (): void => controller.abort();
    process.on("SIGINT", interrupt);
    process.on("SIGTERM", interrupt);
    try {
      const result = await runRecoveryPlan(config, buildRecoveryPlan(config), options.execute, controller.signal);
      resultJson(result, resultStatus(result, "mine-recovered-data"));
      if (result.status === "paused") process.exitCode = 75;
    } finally {
      process.removeListener("SIGINT", interrupt);
      process.removeListener("SIGTERM", interrupt);
    }
  });

const mine = program.command("mine").description("Scan local recovered data for validated sensitive material");

mine.command("scan")
  .description("Stream-scan files and directories; exact values are written only to local artifacts")
  .argument("<inputs...>", "recovered files or directories")
  .requiredOption("-o, --output <directory>", "new or empty output directory")
  .addOption(new Option("--provenance <label>", "recovery provenance").choices(PROVENANCE).default("unknown"))
  .option("--chunk-mib <number>", "streaming chunk size in MiB", "32")
  .option("--overlap-mib <number>", "window overlap in MiB", "17")
  .option("--whole-file-mib <number>", "maximum file size for whole-file container validation", "64")
  .option("--deep-key-schedules", "scan every byte for AES schedules and initialized ChaCha states", false)
  .option("--workers <number>", "detector worker threads (1-4; defaults to available CPUs minus one, capped at 4)")
  .option("--min-free-gib <number>", "minimum free-space reserve in GiB", "5")
  .option("--min-free-percent <number>", "minimum free-space reserve as a filesystem percentage", "5")
  .option("--max-output-gib <number>", "optional logical output-size cap in GiB")
  .option("--quiet", "suppress aggregate progress messages", false)
  .action(async (inputs: string[], options: {
    output: string;
    provenance: Provenance;
    chunkMib: string;
    overlapMib: string;
    wholeFileMib: string;
    deepKeySchedules: boolean;
    workers?: string;
    minFreeGib: string;
    minFreePercent: string;
    maxOutputGib?: string;
    quiet: boolean;
  }) => {
    let lastFiles = 0;
    let lastBytes = 0;
    let lastDiscovered = 0;
    const controller = new AbortController();
    const interrupt = (): void => controller.abort();
    process.on("SIGINT", interrupt);
    process.on("SIGTERM", interrupt);
    try {
      const result = await scanSensitiveMaterial({
        inputs,
        output: options.output,
        provenance: options.provenance,
        chunkBytes: mib(options.chunkMib),
        overlapBytes: mib(options.overlapMib),
        wholeFileBytes: mib(options.wholeFileMib),
        deepKeySchedules: options.deepKeySchedules,
        ...(options.workers === undefined ? {} : { workers: workers(options.workers) }),
        minimumFreeGiB: quantity(options.minFreeGib, "minimum free GiB"),
        minimumFreePercent: quantity(options.minFreePercent, "minimum free percent"),
        ...(options.maxOutputGib === undefined ? {} : { maximumOutputGiB: quantity(options.maxOutputGib, "maximum output GiB") }),
        signal: controller.signal,
        ...(options.quiet ? {} : {
          progress: (progress) => {
            if (progress.phase === "inventory" && (progress.filesTotal ?? 0) - lastDiscovered >= 1_000) {
              process.stderr.write(`inventoryFiles=${progress.filesTotal ?? 0} errors=${progress.scanErrors}\n`);
              lastDiscovered = progress.filesTotal ?? lastDiscovered;
            }
            if (progress.filesScanned - lastFiles >= 100 || progress.bytesScanned - lastBytes >= 1024 ** 3) {
              process.stderr.write(`scanned=${progress.filesScanned} bytes=${progress.bytesScanned} findings=${progress.uniqueFindings}\n`);
              lastFiles = progress.filesScanned;
              lastBytes = progress.bytesScanned;
            }
          },
        }),
      });
      resultJson(result, resultStatus(result, "retention-or-cleanup-plan"));
      if (result.status === "paused") process.exitCode = 75;
    } finally {
      process.removeListener("SIGINT", interrupt);
      process.removeListener("SIGTERM", interrupt);
    }
  });

mine.command("resume")
  .description("Resume a cleanly paused mining scan from its verified checkpoint")
  .requiredOption("-o, --output <directory>", "paused mining output directory")
  .option("--workers <number>", "detector worker threads (1-4)")
  .option("--min-free-gib <number>", "override the saved minimum free-space reserve in GiB")
  .option("--min-free-percent <number>", "override the saved minimum free-space percentage")
  .option("--max-output-gib <number>", "override the saved logical output-size cap in GiB")
  .option("--quiet", "suppress aggregate progress messages", false)
  .action(async (options: {
    output: string;
    workers?: string;
    minFreeGib?: string;
    minFreePercent?: string;
    maxOutputGib?: string;
    quiet: boolean;
  }) => {
    let lastFiles = 0;
    let lastBytes = 0;
    let lastDiscovered = 0;
    const controller = new AbortController();
    const interrupt = (): void => controller.abort();
    process.on("SIGINT", interrupt);
    process.on("SIGTERM", interrupt);
    try {
      const result = await resumeSensitiveMaterial({
        output: options.output,
        ...(options.workers === undefined ? {} : { workers: workers(options.workers) }),
        ...(options.minFreeGib === undefined ? {} : { minimumFreeGiB: quantity(options.minFreeGib, "minimum free GiB") }),
        ...(options.minFreePercent === undefined ? {} : { minimumFreePercent: quantity(options.minFreePercent, "minimum free percent") }),
        ...(options.maxOutputGib === undefined ? {} : { maximumOutputGiB: quantity(options.maxOutputGib, "maximum output GiB") }),
        signal: controller.signal,
        ...(options.quiet ? {} : {
          progress: (progress) => {
            if (progress.phase === "inventory" && (progress.filesTotal ?? 0) - lastDiscovered >= 1_000) {
              process.stderr.write(`inventoryFiles=${progress.filesTotal ?? 0} errors=${progress.scanErrors}\n`);
              lastDiscovered = progress.filesTotal ?? lastDiscovered;
            }
            if (progress.filesScanned - lastFiles >= 100 || progress.bytesScanned - lastBytes >= 1024 ** 3) {
              process.stderr.write(`scanned=${progress.filesScanned} bytes=${progress.bytesScanned} findings=${progress.uniqueFindings}\n`);
              lastFiles = progress.filesScanned;
              lastBytes = progress.bytesScanned;
            }
          },
        }),
      });
      resultJson(result, resultStatus(result, "retention-or-cleanup-plan"));
      if (result.status === "paused") process.exitCode = 75;
    } finally {
      process.removeListener("SIGINT", interrupt);
      process.removeListener("SIGTERM", interrupt);
    }
  });

mine.command("batch")
  .description("Adaptively partition and auto-advance a large, resumable mining workflow")
  .argument("<inputs...>", "closed recovery roots to partition into bounded scans")
  .requiredOption("-o, --output <directory>", "dedicated batch-workflow output directory")
  .addOption(new Option("--provenance <label>", "recovery provenance").choices(PROVENANCE).default("unknown"))
  .option("--chunk-mib <number>", "streaming chunk size in MiB", "32")
  .option("--overlap-mib <number>", "window overlap in MiB", "17")
  .option("--whole-file-mib <number>", "maximum file size for whole-file validation", "64")
  .option("--deep-key-schedules", "scan every byte for expanded key schedules", false)
  .option("--workers <number>", "detector worker threads (1-4)")
  .option("--min-free-gib <number>", "minimum free-space reserve in GiB", "5")
  .option("--min-free-percent <number>", "minimum free-space reserve percentage", "5")
  .option("--max-output-gib <number>", "optional aggregate logical output cap in GiB")
  .option("--max-roots-per-batch <number>", "maximum input roots per child scan", "128")
  .option("--max-files-per-batch <number>", "initial file-count ceiling per child scan", "50000")
  .option("--max-gib-per-batch <number>", "initial logical input GiB ceiling per child scan", "256")
  .option("--quiet", "suppress aggregate progress messages", false)
  .action(async (inputs: string[], options: {
    output: string;
    provenance: Provenance;
    chunkMib: string;
    overlapMib: string;
    wholeFileMib: string;
    deepKeySchedules: boolean;
    workers?: string;
    minFreeGib: string;
    minFreePercent: string;
    maxOutputGib?: string;
    maxRootsPerBatch: string;
    maxFilesPerBatch: string;
    maxGibPerBatch: string;
    quiet: boolean;
  }) => {
    const integer = (value: string, label: string, maximum = Number.MAX_SAFE_INTEGER): number => {
      const parsed = Number(value);
      if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > maximum) throw new Error(`${label} must be a positive integer`);
      return parsed;
    };
    const batchGiB = quantity(options.maxGibPerBatch, "maximum GiB per batch");
    const maximumBytesPerBatch = Math.floor(batchGiB * 1024 ** 3);
    if (!Number.isSafeInteger(maximumBytesPerBatch) || maximumBytesPerBatch < 1) throw new Error("maximum GiB per batch is outside safe numeric bounds");
    let lastFiles = 0;
    let lastRoots = 0;
    const controller = new AbortController();
    const interrupt = (): void => controller.abort();
    process.on("SIGINT", interrupt);
    process.on("SIGTERM", interrupt);
    try {
      const result = await runMiningBatch({
        inputs,
        output: options.output,
        provenance: options.provenance,
        chunkBytes: mib(options.chunkMib),
        overlapBytes: mib(options.overlapMib),
        wholeFileBytes: mib(options.wholeFileMib),
        deepKeySchedules: options.deepKeySchedules,
        ...(options.workers === undefined ? {} : { workers: workers(options.workers) }),
        minimumFreeGiB: quantity(options.minFreeGib, "minimum free GiB"),
        minimumFreePercent: quantity(options.minFreePercent, "minimum free percent"),
        ...(options.maxOutputGib === undefined ? {} : { maximumOutputGiB: quantity(options.maxOutputGib, "maximum output GiB") }),
        maximumRootsPerBatch: integer(options.maxRootsPerBatch, "maximum roots per batch", 128),
        maximumFilesPerBatch: integer(options.maxFilesPerBatch, "maximum files per batch"),
        maximumBytesPerBatch,
        signal: controller.signal,
        ...(options.quiet ? {} : { progress: (progress) => {
          if (progress.filesScanned - lastFiles >= 100 || progress.rootsCompleted - lastRoots >= 10 || progress.phase === "finalizing") {
            process.stderr.write(`phase=${progress.phase} batch=${progress.batch} roots=${progress.rootsCompleted}/${progress.rootsTotal} scanned=${progress.filesScanned} findings=${progress.uniqueFindings}\n`);
            lastFiles = progress.filesScanned;
            lastRoots = progress.rootsCompleted;
          }
        } }),
      });
      resultJson(result, resultStatus(result, "retention-or-cleanup-plan"));
      if (result.status === "paused" || result.status === "blocked-safety") process.exitCode = 75;
    } finally {
      process.removeListener("SIGINT", interrupt);
      process.removeListener("SIGTERM", interrupt);
    }
  });

mine.command("reveal")
  .description("Intentionally write one exact local artifact to stdout")
  .argument("<artifact>", "path to a recovered artifact")
  .action(async (artifact: string) => {
    const value = await readValidatedRevealArtifact(artifact);
    await new Promise<void>((resolve, reject) => {
      process.stdout.write(value, (error) => error === null || error === undefined ? resolve() : reject(error));
    });
  });

const cleanup = program.command("cleanup").description("Verify and remove scanned recovery copies while retaining reports, exact findings, and their complete source files");

cleanup.command("plan")
  .description("Build a path-redacted, read-only cleanup plan and approval token")
  .argument("<mining-outputs...>", "completed error-free mining output directories covering the selected recovered data")
  .requiredOption("-c, --case <directory>", "completed AARK recovery case directory")
  .option("--include-evidence", "also plan deletion of the case evidence copy", false)
  .action(async (miningOutputs: string[], options: { case: string; includeEvidence: boolean }) => {
    const controller = new AbortController();
    const interrupt = (): void => controller.abort();
    process.on("SIGINT", interrupt);
    process.on("SIGTERM", interrupt);
    try {
      resultJson(await planCleanup({
        caseDirectory: options.case,
        miningOutputs,
        includeEvidence: options.includeEvidence,
        signal: controller.signal,
      }), userBlockedContinuation("cleanup deletion requires review of this exact aggregate plan and fresh end-user approval", "cleanup-run-approved-plan"));
    } finally {
      process.removeListener("SIGINT", interrupt);
      process.removeListener("SIGTERM", interrupt);
    }
  });

cleanup.command("run")
  .description("Execute an unchanged approved cleanup plan; deletion requires explicit confirmations")
  .argument("<mining-outputs...>", "the same mining output directories supplied to cleanup plan")
  .requiredOption("-c, --case <directory>", "the same completed AARK recovery case directory")
  .requiredOption("--approval-token <sha256>", "exact token returned by cleanup plan")
  .option("--execute", "execution confirmation", false)
  .option("--confirm-delete-recovered-copy", "confirm irreversible deletion of selected recovered data", false)
  .option("--include-evidence", "also delete the case evidence copy", false)
  .option("--confirm-delete-evidence", "separately confirm irreversible evidence-copy deletion", false)
  .action(async (miningOutputs: string[], options: {
    case: string;
    approvalToken: string;
    execute: boolean;
    confirmDeleteRecoveredCopy: boolean;
    includeEvidence: boolean;
    confirmDeleteEvidence: boolean;
  }) => {
    const controller = new AbortController();
    const interrupt = (): void => controller.abort();
    process.on("SIGINT", interrupt);
    process.on("SIGTERM", interrupt);
    try {
      resultJson(await runCleanup({
        caseDirectory: options.case,
        miningOutputs,
        approvalToken: options.approvalToken,
        execute: options.execute,
        confirmDeleteRecoveredCopy: options.confirmDeleteRecoveredCopy,
        includeEvidence: options.includeEvidence,
        confirmDeleteEvidence: options.confirmDeleteEvidence,
        signal: controller.signal,
      }), terminalContinuation());
    } finally {
      process.removeListener("SIGINT", interrupt);
      process.removeListener("SIGTERM", interrupt);
    }
  });

const retain = program.command("retain").description("Preserve complete finding-containing files in verified content-addressed storage");

retain.command("plan")
  .description("Verify completed scans and build a path-redacted non-destructive retention plan")
  .argument("<mining-outputs...>", "completed error-free mining output directories")
  .requiredOption("-d, --destination <directory>", "dedicated retention directory")
  .option("--min-free-gib <number>", "minimum free-space reserve in GiB", "5")
  .option("--min-free-percent <number>", "minimum free-space reserve percentage", "5")
  .option("--max-output-gib <number>", "optional logical output cap in GiB")
  .action(async (miningOutputs: string[], options: { destination: string; minFreeGib: string; minFreePercent: string; maxOutputGib?: string }) => {
    const controller = new AbortController();
    const interrupt = (): void => controller.abort();
    process.on("SIGINT", interrupt);
    process.on("SIGTERM", interrupt);
    try {
      resultJson(await planRetention({
        miningOutputs,
        destination: options.destination,
        requireReadOnlySources: true,
        minimumFreeGiB: quantity(options.minFreeGib, "minimum free GiB"),
        minimumFreePercent: quantity(options.minFreePercent, "minimum free percent"),
        ...(options.maxOutputGib === undefined ? {} : { maximumOutputGiB: quantity(options.maxOutputGib, "maximum output GiB") }),
        signal: controller.signal,
      }), readyContinuation("retention-run"));
    } finally {
      process.removeListener("SIGINT", interrupt);
      process.removeListener("SIGTERM", interrupt);
    }
  });

retain.command("run")
  .description("Execute an unchanged retention plan; source files are copied, never deleted")
  .argument("<mining-outputs...>", "the same completed mining outputs supplied to retain plan")
  .requiredOption("-d, --destination <directory>", "the same dedicated retention directory")
  .requiredOption("--plan-token <sha256>", "exact token returned by retain plan")
  .option("--min-free-gib <number>", "minimum free-space reserve in GiB", "5")
  .option("--min-free-percent <number>", "minimum free-space reserve percentage", "5")
  .option("--max-output-gib <number>", "optional logical output cap in GiB")
  .action(async (miningOutputs: string[], options: { destination: string; planToken: string; minFreeGib: string; minFreePercent: string; maxOutputGib?: string }) => {
    const controller = new AbortController();
    const interrupt = (): void => controller.abort();
    process.on("SIGINT", interrupt);
    process.on("SIGTERM", interrupt);
    try {
      const result = await runRetention({
        miningOutputs,
        destination: options.destination,
        planToken: options.planToken,
        requireReadOnlySources: true,
        minimumFreeGiB: quantity(options.minFreeGib, "minimum free GiB"),
        minimumFreePercent: quantity(options.minFreePercent, "minimum free percent"),
        ...(options.maxOutputGib === undefined ? {} : { maximumOutputGiB: quantity(options.maxOutputGib, "maximum output GiB") }),
        signal: controller.signal,
      });
      resultJson(result, resultStatus(result, "cleanup-plan"));
      if (result.status === "paused") process.exitCode = 75;
    } finally {
      process.removeListener("SIGINT", interrupt);
      process.removeListener("SIGTERM", interrupt);
    }
  });

const collect = (value: string, previous: string[]): string[] => [...previous, value];
const cleanupSegments = cleanup.command("segments").description("Plan and execute cleanup of immutable closed recovery segments while preserving active segments");

cleanupSegments.command("plan")
  .description("Build a token-bound segmented cleanup plan; scan-error sources default to retention")
  .argument("<segments...>", "closed recovery segment directories selected for cleanup")
  .requiredOption("--mining-output <directory>", "terminal mining output covering selected segments; repeat as needed", collect, [])
  .option("--active-segment <directory>", "active recovery segment to preserve; repeat as needed", collect, [])
  .requiredOption("-r, --retention-directory <directory>", "dedicated same-filesystem retained-source directory")
  .addOption(new Option("--error-source-disposition <choice>", "retain or delete scan-error source files").choices(["retain", "delete"]).default("retain"))
  .action(async (segments: string[], options: { miningOutput: string[]; activeSegment: string[]; retentionDirectory: string; errorSourceDisposition: "retain" | "delete" }) => {
    const controller = new AbortController();
    const interrupt = (): void => controller.abort();
    process.on("SIGINT", interrupt);
    process.on("SIGTERM", interrupt);
    try {
      resultJson(await planSegmentedCleanup({
        segments,
        activeSegments: options.activeSegment,
        miningOutputs: options.miningOutput,
        retentionDirectory: options.retentionDirectory,
        errorSourceDisposition: options.errorSourceDisposition,
        signal: controller.signal,
      }), userBlockedContinuation("segmented deletion requires review of this exact plan and fresh end-user approval", "segmented-cleanup-run-approved-plan"));
    } finally {
      process.removeListener("SIGINT", interrupt);
      process.removeListener("SIGTERM", interrupt);
    }
  });

cleanupSegments.command("run")
  .description("Execute an unchanged approved segmented cleanup plan")
  .argument("<segments...>", "the same closed segments supplied to cleanup segments plan")
  .requiredOption("--mining-output <directory>", "the same terminal mining output; repeat as needed", collect, [])
  .option("--active-segment <directory>", "the same active segment exclusions; repeat as needed", collect, [])
  .requiredOption("-r, --retention-directory <directory>", "the same retained-source directory")
  .addOption(new Option("--error-source-disposition <choice>", "the same error-source choice").choices(["retain", "delete"]).default("retain"))
  .requiredOption("--approval-token <sha256>", "exact token returned by cleanup segments plan")
  .option("--execute", "execution confirmation", false)
  .option("--confirm-delete-segments", "confirm irreversible deletion of selected closed segments", false)
  .option("--confirm-delete-error-sources", "separately confirm deletion of scan-error source files", false)
  .action(async (segments: string[], options: {
    miningOutput: string[];
    activeSegment: string[];
    retentionDirectory: string;
    errorSourceDisposition: "retain" | "delete";
    approvalToken: string;
    execute: boolean;
    confirmDeleteSegments: boolean;
    confirmDeleteErrorSources: boolean;
  }) => {
    const controller = new AbortController();
    const interrupt = (): void => controller.abort();
    process.on("SIGINT", interrupt);
    process.on("SIGTERM", interrupt);
    try {
      resultJson(await runSegmentedCleanup({
        segments,
        activeSegments: options.activeSegment,
        miningOutputs: options.miningOutput,
        retentionDirectory: options.retentionDirectory,
        errorSourceDisposition: options.errorSourceDisposition,
        approvalToken: options.approvalToken,
        execute: options.execute,
        confirmDeleteSegments: options.confirmDeleteSegments,
        confirmDeleteErrorSources: options.confirmDeleteErrorSources,
        signal: controller.signal,
      }), readyContinuation("workflow-next-stage"));
    } finally {
      process.removeListener("SIGINT", interrupt);
      process.removeListener("SIGTERM", interrupt);
    }
  });

const workflow = program.command("workflow").description("Run durable authorized stages continuously until a real blocker or terminal completion");

workflow.command("plan")
  .description("Validate a strict workflow configuration without starting its stages")
  .requiredOption("-c, --config <path>", "workflow configuration JSON")
  .action(async (options: { config: string }) => {
    const config = await loadWorkflowConfig(options.config);
    resultJson({
      version: 1,
      tool: "aark",
      layer: "workflow-plan",
      workflowId: config.workflowId,
      stages: config.stages.map((stage, index) => ({ index, id: stage.id, kind: stage.kind })),
      stageCount: config.stages.length,
      cleanupExecutionAutomated: false,
      pathsRedacted: true,
      valuesPrinted: false,
    }, userBlockedContinuation("review the stage order and recovery confirmations before starting run --until-blocked", "workflow-run-until-blocked"));
  });

workflow.command("run")
  .description("Advance safe authorized stages without idling; stop only at a blocker or completion")
  .requiredOption("-c, --config <path>", "workflow configuration JSON")
  .option("--until-blocked", "required durable-controller mode", false)
  .option("--execute-recovery", "independent recovery execution confirmation", false)
  .action(async (options: { config: string; untilBlocked: boolean; executeRecovery: boolean }) => {
    if (!options.untilBlocked) throw new Error("workflow run requires --until-blocked");
    const config = await loadWorkflowConfig(options.config);
    const controller = new AbortController();
    const interrupt = (): void => controller.abort();
    process.on("SIGINT", interrupt);
    process.on("SIGTERM", interrupt);
    try {
      const result = await runWorkflowUntilBlocked(config, { executeRecovery: options.executeRecovery, signal: controller.signal });
      json(result);
      if (result.workflowState === "blocked-safety" || result.workflowState === "invariant-failure") process.exitCode = 75;
    } finally {
      process.removeListener("SIGINT", interrupt);
      process.removeListener("SIGTERM", interrupt);
    }
  });

workflow.command("status")
  .description("Report heartbeat, continuation, capacity, safety, blocker, and truthful ETA state")
  .requiredOption("-d, --directory <path>", "workflow state directory")
  .action(async (options: { directory: string }) => {
    const result = await workflowStatus(options.directory, false);
    json(result);
    if (result.workflowState === "blocked-safety" || result.workflowState === "invariant-failure") process.exitCode = 75;
  });

const workflowUpgrade = workflow.command("upgrade").description("Validate and optionally resume from a clean boundary with a candidate tool checkout");

workflowUpgrade.command("plan")
  .requiredOption("-d, --directory <path>", "blocked or terminal workflow state directory")
  .requiredOption("--candidate-tool <path>", "separate candidate checkout or worktree")
  .option("--resume-config <path>", "bind automatic post-test resume of this workflow config")
  .option("--execute-recovery", "bind independent recovery confirmation to the planned resume", false)
  .action(async (options: { directory: string; candidateTool: string; resumeConfig?: string; executeRecovery: boolean }) => {
    resultJson(await planWorkflowUpgrade({
      workflowDirectory: options.directory,
      candidateTool: options.candidateTool,
      ...(options.resumeConfig === undefined ? {} : { resumeConfig: options.resumeConfig }),
      executeRecovery: options.executeRecovery,
    }),
      userBlockedContinuation("review the candidate commit, checkpoint compatibility, and test list before upgrade run", "workflow-upgrade-run"));
  });

workflowUpgrade.command("run")
  .requiredOption("-d, --directory <path>", "the same workflow state directory")
  .requiredOption("--candidate-tool <path>", "the same candidate checkout")
  .requiredOption("--approval-token <sha256>", "exact token returned by workflow upgrade plan")
  .option("--execute", "authorize candidate dependency installation and tests", false)
  .option("--resume-config <path>", "the same post-test resume config bound by workflow upgrade plan")
  .option("--execute-recovery", "the same independent recovery confirmation bound by workflow upgrade plan", false)
  .action(async (options: { directory: string; candidateTool: string; approvalToken: string; execute: boolean; resumeConfig?: string; executeRecovery: boolean }) => {
    const controller = new AbortController();
    const interrupt = (): void => controller.abort();
    process.on("SIGINT", interrupt);
    process.on("SIGTERM", interrupt);
    try {
      const result = await runWorkflowUpgrade({
        workflowDirectory: options.directory,
        candidateTool: options.candidateTool,
        approvalToken: options.approvalToken,
        execute: options.execute,
        ...(options.resumeConfig === undefined ? {} : { resumeConfig: options.resumeConfig }),
        executeRecovery: options.executeRecovery,
        signal: controller.signal,
      });
      resultJson(result, upgradeResultStatus(result));
    } finally {
      process.removeListener("SIGINT", interrupt);
      process.removeListener("SIGTERM", interrupt);
    }
  });

program.parseAsync(process.argv).catch((error: unknown) => {
  process.stderr.write(`error: ${redactedError(error)}\n`);
  process.exitCode = 1;
});
