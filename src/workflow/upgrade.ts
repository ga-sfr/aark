import { createHash } from "node:crypto";
import { lstat, mkdir, realpath } from "node:fs/promises";
import path from "node:path";
import { captureCommand } from "../core/command.js";
import { acquireExclusiveLock, atomicWriteJson, ensurePrivateDirectory, readJson, safeJoin } from "../core/fs-safe.js";
import { probeProcess } from "../core/process-identity.js";
import { loadWorkflowConfig, workflowConfigHash } from "./config.js";
import { validateWorkflowState, WORKFLOW_STATE_FILE } from "./state.js";
import { workflowStatus } from "./status.js";
import type { WorkflowState } from "./types.js";

const UPGRADE_LOCK = ".aark-workflow-upgrade.lock";
const WORKFLOW_LOCK = ".aark-workflow.lock";
const TOKEN = /^[a-f0-9]{64}$/u;
const COMMIT = /^[a-f0-9]{40}$/u;
const SAFE_SCRIPT = /^[A-Za-z0-9][A-Za-z0-9:._-]{0,127}$/u;
const OPTIONAL_LINUX_TEST_SCRIPTS = ["test:linux", "test:integration:linux", "test:python"] as const;

export interface WorkflowUpgradeOptions {
  workflowDirectory: string;
  candidateTool: string;
  resumeConfig?: string;
  executeRecovery?: boolean;
}

export interface WorkflowUpgradeRunOptions extends WorkflowUpgradeOptions {
  approvalToken: string;
  execute: boolean;
  resumeConfig?: string;
  executeRecovery?: boolean;
  signal?: AbortSignal;
}

export interface WorkflowUpgradePlanResult {
  version: 1;
  tool: "aark";
  layer: "workflow-upgrade";
  status: "ready";
  destructive: false;
  pathsRedacted: true;
  valuesPrinted: false;
  workflowStatus: "blocked-user" | "blocked-safety" | "terminal";
  currentStageKind: string | null;
  candidateCommit: string;
  candidateVersion: string;
  checkpointCompatible: true;
  requiredTests: string[];
  optionalTests: string[];
  resumeAfterTests: boolean;
  executeRecoveryAuthorized: boolean;
  approvalToken: string;
  approvalRequired: true;
}

interface CandidatePackage {
  name?: unknown;
  version?: unknown;
  scripts?: unknown;
  aarkCheckpointCompatibility?: unknown;
}

interface InternalUpgradePlan {
  public: WorkflowUpgradePlanResult;
  workflowDirectory: string;
  candidateTool: string;
  packageScripts: Record<string, string>;
  candidateDevice: number;
  candidateInode: number;
  state: WorkflowState;
  resumeConfig?: string;
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as Record<string, unknown>;
}

function checkpointKeys(kind: string | undefined): string[] {
  // A mining-batch checkpoint can own a paused ordinary scan checkpoint.
  // Both schemas therefore have to be compatible before the candidate is
  // allowed to resume the outer controller.
  if (kind === "mining-batch") return ["miningBatch", "miningScan"];
  if (kind === "recovery") return ["recovery"];
  if (kind === "retention") return ["retention"];
  if (kind === "cleanup-plan" || kind === "segmented-cleanup-plan") return ["cleanup"];
  return [];
}

async function git(candidate: string, args: string[]): Promise<string> {
  const result = await captureCommand("git", ["-C", candidate, ...args], { maxCaptureBytes: 1024 * 1024, timeoutMs: 30_000 });
  if (result.exitCode !== 0 || result.stdoutTruncated || result.stderrTruncated) throw new Error("candidate tool git identity could not be verified");
  return result.stdout.toString("utf8").trim();
}

async function assertCandidateClean(candidate: string): Promise<void> {
  if ((await git(candidate, ["status", "--porcelain", "--untracked-files=all"])) !== "") {
    throw new Error("candidate tool has tracked or untracked modifications; commit or remove them before workflow upgrade validation");
  }
  const ignored = (await git(candidate, ["status", "--porcelain", "--ignored", "--untracked-files=normal"]))
    .split("\n")
    .filter(Boolean);
  const allowedGenerated = new Set(["!! dist/", "!! node_modules/"]);
  if (ignored.some((entry) => !allowedGenerated.has(entry))) {
    throw new Error("candidate tool contains ignored local inputs outside the replaceable dependency/build directories");
  }
}

async function buildPlan(options: WorkflowUpgradeOptions): Promise<InternalUpgradePlan> {
  const workflowDirectory = path.resolve(options.workflowDirectory);
  const candidateTool = path.resolve(options.candidateTool);
  const workflowMetadata = await lstat(workflowDirectory);
  const candidateMetadata = await lstat(candidateTool);
  if (workflowMetadata.isSymbolicLink() || !workflowMetadata.isDirectory() || await realpath(workflowDirectory) !== workflowDirectory) {
    throw new Error("workflow upgrade requires a canonical workflow directory");
  }
  if (candidateMetadata.isSymbolicLink() || !candidateMetadata.isDirectory() || await realpath(candidateTool) !== candidateTool) {
    throw new Error("workflow upgrade candidate must be a canonical real directory");
  }
  if (workflowDirectory === candidateTool || candidateTool.startsWith(`${workflowDirectory}${path.sep}`) || workflowDirectory.startsWith(`${candidateTool}${path.sep}`)) {
    throw new Error("workflow directory and candidate tool checkout must not contain one another");
  }
  const state = await readJson<WorkflowState>(safeJoin(workflowDirectory, WORKFLOW_STATE_FILE), 64 * 1024 * 1024);
  await workflowStatus(workflowDirectory, false);
  if (!["blocked-user", "blocked-safety", "terminal"].includes(state.status)) {
    throw new Error("workflow upgrade is allowed only at a durable blocked or terminal boundary");
  }
  if (state.process !== null) {
    const probe = await probeProcess(state.process);
    if (probe.existence !== "missing" && probe.identityMatches !== false) throw new Error("workflow upgrade refuses an active or unverifiable controller process");
  }
  let resumeConfig: string | undefined;
  if (options.resumeConfig !== undefined) {
    resumeConfig = path.resolve(options.resumeConfig);
    const config = await loadWorkflowConfig(resumeConfig);
    if (config.directory !== workflowDirectory || workflowConfigHash(config) !== state.configSha256) {
      throw new Error("upgrade resume configuration does not match this workflow checkpoint");
    }
    validateWorkflowState(state, config);
  } else if (options.executeRecovery === true) {
    throw new Error("upgrade recovery confirmation is valid only with a bound resume configuration");
  }
  const commit = await git(candidateTool, ["rev-parse", "HEAD"]);
  if (!COMMIT.test(commit)) throw new Error("candidate tool commit identity is invalid");
  await assertCandidateClean(candidateTool);
  const candidatePackage = await readJson<CandidatePackage>(safeJoin(candidateTool, "package.json"), 1024 * 1024);
  if (candidatePackage.name !== "aark" || typeof candidatePackage.version !== "string" || Buffer.byteLength(candidatePackage.version) > 128) {
    throw new Error("candidate tool package identity is invalid");
  }
  const scriptsInput = record(candidatePackage.scripts, "candidate package scripts");
  const scripts: Record<string, string> = {};
  for (const [name, command] of Object.entries(scriptsInput)) {
    if (!SAFE_SCRIPT.test(name) || typeof command !== "string" || Buffer.byteLength(command) > 4096) throw new Error("candidate package contains an invalid script declaration");
    scripts[name] = command;
  }
  if (scripts.check === undefined) throw new Error("candidate tool must provide its complete npm check script");
  const compatibility = record(candidatePackage.aarkCheckpointCompatibility, "candidate checkpoint compatibility");
  const requiredCompatibility = new Set(["workflow", ...checkpointKeys(state.stages[state.currentStage]?.kind)]);
  for (const key of requiredCompatibility) {
    const versions = compatibility[key];
    if (!Array.isArray(versions) || !versions.includes(1) || versions.some((version) => !Number.isSafeInteger(version) || Number(version) < 1)) {
      throw new Error("candidate tool does not declare compatibility with the active checkpoint schema");
    }
  }
  const optionalTests = OPTIONAL_LINUX_TEST_SCRIPTS.filter((name) => scripts[name] !== undefined);
  const tokenMaterial = {
    version: 1,
    workflow: {
      workflowId: state.workflowId,
      configSha256: state.configSha256,
      status: state.status,
      currentStage: state.currentStage,
      checkpoint: state.stages[state.currentStage] ?? null,
    },
    candidate: {
      commit,
      version: candidatePackage.version,
      device: candidateMetadata.dev,
      inode: candidateMetadata.ino,
      compatibility,
      scripts: { check: scripts.check, optionalTests: optionalTests.map((name) => scripts[name]) },
    },
    resume: resumeConfig === undefined ? null : {
      config: resumeConfig,
      configSha256: state.configSha256,
      executeRecovery: options.executeRecovery === true,
    },
  };
  const approvalToken = createHash("sha256").update(JSON.stringify(tokenMaterial)).digest("hex");
  return {
    public: {
      version: 1,
      tool: "aark",
      layer: "workflow-upgrade",
      status: "ready",
      destructive: false,
      pathsRedacted: true,
      valuesPrinted: false,
      workflowStatus: state.status as "blocked-user" | "blocked-safety" | "terminal",
      currentStageKind: state.stages[state.currentStage]?.kind ?? null,
      candidateCommit: commit,
      candidateVersion: candidatePackage.version,
      checkpointCompatible: true,
      requiredTests: ["npm ci", "npm run check"],
      optionalTests: [...optionalTests],
      resumeAfterTests: resumeConfig !== undefined,
      executeRecoveryAuthorized: resumeConfig !== undefined && options.executeRecovery === true,
      approvalToken,
      approvalRequired: true,
    },
    workflowDirectory,
    candidateTool,
    packageScripts: scripts,
    candidateDevice: candidateMetadata.dev,
    candidateInode: candidateMetadata.ino,
    state,
    ...(resumeConfig === undefined ? {} : { resumeConfig }),
  };
}

export async function planWorkflowUpgrade(options: WorkflowUpgradeOptions): Promise<WorkflowUpgradePlanResult> {
  return (await buildPlan(options)).public;
}

async function runNpm(
  plan: InternalUpgradePlan,
  runRoot: string,
  name: string,
  args: string[],
  signal?: AbortSignal,
): Promise<void> {
  const result = await captureCommand("npm", ["--cache", safeJoin(runRoot, "npm-cache"), ...args], {
    cwd: plan.candidateTool,
    temporaryDirectory: safeJoin(runRoot, "tmp"),
    stdoutFile: safeJoin(runRoot, `${name}.stdout.log`),
    stderrFile: safeJoin(runRoot, `${name}.stderr.log`),
    maxCaptureBytes: 0,
    ...(signal === undefined ? {} : { signal }),
  });
  if (result.exitCode !== 0 || result.signal !== null || result.terminationReason !== null) throw new Error(`candidate ${name} validation failed`);
}

export async function runWorkflowUpgrade(options: WorkflowUpgradeRunOptions): Promise<Record<string, unknown>> {
  if (!options.execute || !TOKEN.test(options.approvalToken)) throw new Error("workflow upgrade requires --execute and the exact approval token");
  const initial = await buildPlan(options);
  if (initial.public.approvalToken !== options.approvalToken) throw new Error("workflow or candidate changed after upgrade planning");
  const lock = await acquireExclusiveLock(initial.workflowDirectory, UPGRADE_LOCK, { reclaimDeadOwner: true });
  let workflowLock: Awaited<ReturnType<typeof acquireExclusiveLock>> | undefined;
  let operationError: unknown;
  try {
    workflowLock = await acquireExclusiveLock(initial.workflowDirectory, WORKFLOW_LOCK, { reclaimDeadOwner: true });
    const plan = await buildPlan(options);
    if (plan.public.approvalToken !== options.approvalToken) throw new Error("workflow or candidate changed while the upgrade lock was acquired");
    const currentCandidate = await lstat(plan.candidateTool);
    if (currentCandidate.dev !== plan.candidateDevice || currentCandidate.ino !== plan.candidateInode) throw new Error("candidate tool directory identity changed");
    const upgradesRoot = safeJoin(plan.workflowDirectory, "upgrades");
    await ensurePrivateDirectory(upgradesRoot);
    const runRoot = safeJoin(upgradesRoot, options.approvalToken);
    await mkdir(runRoot, { mode: 0o700 });
    await ensurePrivateDirectory(runRoot);
    await runNpm(plan, runRoot, "npm-ci", ["ci"], options.signal);
    await runNpm(plan, runRoot, "npm-check", ["run", "check"], options.signal);
    for (const script of plan.public.optionalTests) {
      await runNpm(plan, runRoot, script.replace(/[^A-Za-z0-9._-]/gu, "-"), ["run", script], options.signal);
    }
    const afterCommit = await git(plan.candidateTool, ["rev-parse", "HEAD"]);
    if (afterCommit !== plan.public.candidateCommit) throw new Error("candidate commit changed while upgrade tests were running");
    await assertCandidateClean(plan.candidateTool);
    const testedCandidate = await lstat(plan.candidateTool);
    if (testedCandidate.isSymbolicLink() || !testedCandidate.isDirectory()
      || testedCandidate.dev !== plan.candidateDevice || testedCandidate.ino !== plan.candidateInode
      || await realpath(plan.candidateTool) !== plan.candidateTool) {
      throw new Error("candidate tool directory identity changed while upgrade tests were running");
    }
    let resumed = false;
    let resumeStatus: number | null = null;
    let resumeBoundary: {
      workflowState: string;
      requiresUserInput: boolean;
      safeToAutoContinue: boolean;
      nextAction: string | null;
      blocker: string | null;
    } | null = null;
    if (plan.resumeConfig !== undefined) {
      const config = plan.resumeConfig;
      const executable = safeJoin(plan.candidateTool, "dist", "cli.js");
      await workflowLock.release();
      workflowLock = undefined;
      const result = await captureCommand(process.execPath, [
        executable,
        "workflow", "run", "--config", config, "--until-blocked",
        ...(plan.public.executeRecoveryAuthorized ? ["--execute-recovery"] : []),
      ], {
        cwd: plan.candidateTool,
        stdoutFile: safeJoin(runRoot, "resume.stdout.log"),
        stderrFile: safeJoin(runRoot, "resume.stderr.log"),
        maxCaptureBytes: 0,
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      });
      resumeStatus = result.exitCode;
      if (![0, 75].includes(result.exitCode) || result.signal !== null || result.terminationReason !== null) throw new Error("candidate tool could not resume the workflow to its next boundary");
      const boundary = await workflowStatus(plan.workflowDirectory, false);
      if (!["blocked-user", "blocked-safety", "invariant-failure", "terminal"].includes(String(boundary.workflowState))
        || typeof boundary.requiresUserInput !== "boolean" || typeof boundary.safeToAutoContinue !== "boolean"
        || !(boundary.nextAction === null || typeof boundary.nextAction === "string")
        || !(boundary.blocker === null || typeof boundary.blocker === "string")) {
        throw new Error("candidate workflow resume did not publish a valid durable boundary");
      }
      const safetyExitExpected = boundary.workflowState === "blocked-safety" || boundary.workflowState === "invariant-failure";
      if ((result.exitCode === 75) !== safetyExitExpected) throw new Error("candidate workflow resume exit status disagrees with its durable boundary");
      resumeBoundary = {
        workflowState: String(boundary.workflowState),
        requiresUserInput: boundary.requiresUserInput,
        safeToAutoContinue: boundary.safeToAutoContinue,
        nextAction: boundary.nextAction as string | null,
        blocker: boundary.blocker as string | null,
      };
      resumed = true;
    }
    const manifest = {
      version: 1,
      tool: "aark",
      layer: "workflow-upgrade",
      status: "complete",
      candidateCommit: plan.public.candidateCommit,
      candidateVersion: plan.public.candidateVersion,
      checkpointCompatible: true,
      testsPassed: [...plan.public.requiredTests, ...plan.public.optionalTests],
      readyToResume: !resumed,
      resumed,
      resumeExitCode: resumeStatus,
      resumeWorkflowState: resumeBoundary?.workflowState ?? null,
      resumeRequiresUserInput: resumeBoundary?.requiresUserInput ?? null,
      resumeSafeToAutoContinue: resumeBoundary?.safeToAutoContinue ?? null,
      resumeNextAction: resumeBoundary?.nextAction ?? null,
      resumeBlocker: resumeBoundary?.blocker ?? null,
      pathsRedacted: true,
      valuesPrinted: false,
    };
    await atomicWriteJson(safeJoin(runRoot, "upgrade-manifest-redacted.json"), manifest, 0o644);
    await atomicWriteJson(safeJoin(plan.workflowDirectory, "workflow-upgrade-redacted.json"), manifest, 0o644);
    await atomicWriteJson(safeJoin(runRoot, "upgrade-record-sensitive.json"), {
      ...manifest,
      candidateTool: plan.candidateTool,
      workflowDirectory: plan.workflowDirectory,
      resumeConfig: plan.resumeConfig ?? null,
    });
    return manifest;
  } catch (error) {
    operationError = error;
    throw error;
  } finally {
    const releaseErrors: unknown[] = [];
    if (workflowLock !== undefined) {
      try { await workflowLock.release(); } catch (error) { releaseErrors.push(error); }
    }
    try { await lock.release(); } catch (error) { releaseErrors.push(error); }
    if (releaseErrors.length > 0) {
      if (operationError !== undefined) throw new AggregateError([operationError, ...releaseErrors], "workflow upgrade failed and its locks could not be released");
      throw new AggregateError(releaseErrors, "workflow upgrade locks could not be released");
    }
  }
}
