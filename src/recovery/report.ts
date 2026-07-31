import path from "node:path";
import type { JsonValue } from "../core/types.js";
import type { RecoveryPlan, RecoveryRunStatus, RecoveryStep } from "./types.js";
import type { SourceSafety } from "./source-safety.js";

function literal(value: string): string {
  return `\`${JSON.stringify(value).replace(/`/g, "\\u0060")}\``;
}

function inside(root: string, candidate: string): boolean {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function outputPaths(step: RecoveryStep, root: string): string[] {
  return [...new Set(step.outputs.filter((output) => inside(root, output)).map((value) => path.resolve(value)))].sort();
}

function statusFor(step: RecoveryStep, results: Array<Record<string, JsonValue>>): string {
  const result = results.find((item) => item.id === step.id);
  return typeof result?.status === "string" ? result.status : "not-recorded";
}

function resultFor(step: RecoveryStep, results: Array<Record<string, JsonValue>>): Record<string, JsonValue> | undefined {
  return results.find((item) => item.id === step.id);
}

export function renderRecoverySensitiveReport(
  plan: RecoveryPlan,
  results: Array<Record<string, JsonValue>>,
  safety: SourceSafety,
  permissionsEnforced: boolean,
  finishedAt: string,
  status: RecoveryRunStatus,
  runId: string,
  failureMessage?: string,
): string {
  const recoveryRoot = path.join(plan.destination, "recovery");
  const lines = [
    "# Disk-recovery final report",
    "",
    "> Sensitive local report: it contains device names, source paths, and restored-output locations. Do not publish it.",
    "",
    `- Status: ${status}`,
    `- Run ID: ${runId}`,
    `- Case ID: ${plan.caseId}`,
    `- Finished: ${finishedAt}`,
    `- Recovery stages recorded: ${plan.steps.length}`,
    `- Destination enforces Unix permissions: ${permissionsEnforced}`,
    "",
    "## Local paths",
    "",
    `- Original source: ${literal(plan.source)}`,
    `- Analysis source: ${literal(plan.analysisSource)}`,
    `- Case folder: ${literal(plan.destination)}`,
    `- Restored-data folder: ${literal(recoveryRoot)}`,
    `- Sensitive case state: ${literal(path.join(plan.destination, "case-sensitive.json"))}`,
    `- This run's sensitive state: ${literal(path.join(plan.destination, "runs", `${runId}-sensitive.json`))}`,
    `- This run's sensitive tool logs: ${literal(path.join(plan.destination, "logs", runId))}`,
    `- Redacted manifest: ${literal(path.join(plan.destination, "manifest-redacted.json"))}`,
    "",
    "## Source-safety result",
    "",
    `- Source kind: ${safety.kind}`,
    `- Kernel read-only state: ${safety.kernelReadOnly === null ? "not applicable" : safety.kernelReadOnly}`,
    `- Source top-level device(s): ${safety.sourceTopDevices.length === 0 ? "not resolved" : safety.sourceTopDevices.map(literal).join(", ")}`,
    `- Destination device(s): ${safety.destinationDevices.length === 0 ? "not resolved" : safety.destinationDevices.map(literal).join(", ")}`,
    `- Destination backing kind: ${safety.destinationBackingKind}`,
    `- Device comparison certain: ${safety.deviceComparisonCertain}`,
    `- Writable source mounts detected: ${safety.writableMounts.length === 0 ? "none" : safety.writableMounts.map(literal).join(", ")}`,
    "",
    "## Recovery stages and output locations",
    "",
  ];

  for (const step of plan.steps) {
    const outputs = outputPaths(step, plan.destination);
    const result = resultFor(step, results);
    const stdoutLog = typeof result?.stdoutLog === "string" ? literal(result.stdoutLog) : "none (stdout may be a listed recovery output)";
    const stderrLog = typeof result?.stderrLog === "string" ? literal(result.stderrLog) : "none recorded";
    lines.push(
      `### ${step.id}`,
      "",
      `- Purpose: ${step.title}`,
      `- Status: ${statusFor(step, results)}`,
      `- Provenance: ${step.provenance}`,
      `- Output locations: ${outputs.length === 0 ? "none recorded" : outputs.map(literal).join(", ")}`,
      `- Sensitive stdout log: ${stdoutLog}`,
      `- Sensitive stderr log: ${stderrLog}`,
      "",
    );
  }

  if (failureMessage !== undefined) {
    lines.push("## Failure detail", "", literal(failureMessage), "");
  }

  lines.push(
    "## What this report establishes",
    "",
    "The paths above identify where each recovery engine wrote its results. Only stages marked completed should be treated as successfully run. Deleted-metadata and filesystem-unallocated provenance are retained separately from carved, shadow-copy, residual-memory, and allocated-reference material. A successful stage does not guarantee that every deleted byte was recoverable, and a carved file does not by itself prove an original pathname.",
    "",
    "Run the mining layer against the relevant restored-data subfolders, using separate scans when their provenance labels differ. The mining layer writes its own final reports with credential categories, possible access, and exact local finding locations.",
    "",
  );
  return lines.join("\n");
}

export function renderRecoveryRedactedReport(
  plan: RecoveryPlan,
  results: Array<Record<string, JsonValue>>,
  permissionsEnforced: boolean,
  finishedAt: string,
  status: RecoveryRunStatus,
  runId: string,
): string {
  return [
    "# Disk-recovery final report (redacted)",
    "",
    "> This report omits source, device, case, restored-output, and log paths.",
    "",
    `- Status: ${status}`,
    `- Run ID: ${runId}`,
    "- Case ID: redacted",
    `- Finished: ${finishedAt}`,
    `- Recovery stages recorded: ${plan.steps.length}`,
    `- Destination enforces Unix permissions: ${permissionsEnforced}`,
    "",
    "## Recovery stage results",
    "",
    "| Stage | Status | Provenance | Purpose |",
    "| --- | --- | --- | --- |",
    ...plan.steps.map((step) => `| ${step.id} | ${statusFor(step, results)} | ${step.provenance} | ${step.title.replace(/\|/g, "\\|")} |`),
    "",
    "See the local sensitive final report for restored folder paths, device details, and per-stage output locations. No evidence was uploaded or sent to an LLM while producing either report.",
    "",
  ].join("\n");
}
