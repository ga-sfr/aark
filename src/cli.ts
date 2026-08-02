#!/usr/bin/env node
import process from "node:process";
import { Command, Option } from "commander";
import { dependencyReport } from "./recovery/dependencies.js";
import { machineInventory } from "./recovery/inventory.js";
import { loadRecoveryConfig } from "./recovery/config.js";
import { buildRecoveryPlan } from "./recovery/plan.js";
import { redactedPlan, runRecoveryPlan } from "./recovery/runner.js";
import { scanSensitiveMaterial } from "./mining/scanner.js";
import { readValidatedRevealArtifact } from "./mining/reveal.js";
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
  .option("--quiet", "suppress aggregate progress messages", false)
  .action(async (inputs: string[], options: {
    output: string;
    provenance: Provenance;
    chunkMib: string;
    overlapMib: string;
    wholeFileMib: string;
    deepKeySchedules: boolean;
    quiet: boolean;
  }) => {
    let lastFiles = 0;
    let lastBytes = 0;
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
        signal: controller.signal,
        ...(options.quiet ? {} : {
          progress: (progress) => {
            if (progress.filesScanned - lastFiles >= 100 || progress.bytesScanned - lastBytes >= 1024 ** 3) {
              process.stderr.write(`scanned=${progress.filesScanned} bytes=${progress.bytesScanned} findings=${progress.uniqueFindings}\n`);
              lastFiles = progress.filesScanned;
              lastBytes = progress.bytesScanned;
            }
          },
        }),
      });
      json(result);
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

program.parseAsync(process.argv).catch((error: unknown) => {
  process.stderr.write(`error: ${redactedError(error)}\n`);
  process.exitCode = 1;
});
