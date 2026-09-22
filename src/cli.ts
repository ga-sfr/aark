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
import type { Provenance } from "./core/types.js";

const VERSION = "0.1.0";
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
    if (options.json === true) json(report);
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
    if (options.json === true) json(inventory);
    else process.stdout.write("Inventory collected. Use --json to display the local device and mount details.\n");
  });

recover.command("plan")
  .description("Build and display a redacted recovery plan")
  .requiredOption("-c, --config <path>", "case configuration JSON")
  .action(async (options: { config: string }) => {
    const config = await loadRecoveryConfig(options.config);
    json(redactedPlan(buildRecoveryPlan(config)));
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
      json(result);
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
      json(result);
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
      json(result);
      if (result.status === "paused") process.exitCode = 75;
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
  .option("--accept-interrupted-case", "accept an inactive legacy interrupted recovery state while still requiring exact completed scan coverage", false)
  .action(async (miningOutputs: string[], options: { case: string; includeEvidence: boolean; acceptInterruptedCase: boolean }) => {
    const controller = new AbortController();
    const interrupt = (): void => controller.abort();
    process.on("SIGINT", interrupt);
    process.on("SIGTERM", interrupt);
    try {
      json(await planCleanup({
        caseDirectory: options.case,
        miningOutputs,
        includeEvidence: options.includeEvidence,
        acceptInterruptedCase: options.acceptInterruptedCase,
        signal: controller.signal,
      }));
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
  .option("--accept-interrupted-case", "accept the same inactive legacy interrupted recovery state used for planning", false)
  .action(async (miningOutputs: string[], options: {
    case: string;
    approvalToken: string;
    execute: boolean;
    confirmDeleteRecoveredCopy: boolean;
    includeEvidence: boolean;
    confirmDeleteEvidence: boolean;
    acceptInterruptedCase: boolean;
  }) => {
    const controller = new AbortController();
    const interrupt = (): void => controller.abort();
    process.on("SIGINT", interrupt);
    process.on("SIGTERM", interrupt);
    try {
      json(await runCleanup({
        caseDirectory: options.case,
        miningOutputs,
        approvalToken: options.approvalToken,
        execute: options.execute,
        confirmDeleteRecoveredCopy: options.confirmDeleteRecoveredCopy,
        includeEvidence: options.includeEvidence,
        confirmDeleteEvidence: options.confirmDeleteEvidence,
        acceptInterruptedCase: options.acceptInterruptedCase,
        signal: controller.signal,
      }));
    } finally {
      process.removeListener("SIGINT", interrupt);
      process.removeListener("SIGTERM", interrupt);
    }
  });

program.parseAsync(process.argv).catch((error: unknown) => {
  process.stderr.write(`error: ${redactedError(error)}\n`);
  process.exitCode = 1;
});
