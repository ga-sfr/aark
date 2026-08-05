import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";

export type ProcessExistence = "missing" | "exists" | "exists-unauthorized";

export interface ProcessIdentity {
  version: 1;
  pid: number;
  processGroup: number | null;
  kernelStartTicks: string | null;
  executableDevice: string | null;
  executableInode: string | null;
  commandSha256: string | null;
  bootIdSha256: string | null;
}

export interface ProcessProbe {
  existence: ProcessExistence;
  identityMatches: boolean | null;
  expected: ProcessIdentity;
  observed?: ProcessIdentity;
}

export function isProcessIdentity(value: unknown): value is ProcessIdentity {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const item = value as Record<string, unknown>;
  const nullableDigits = (candidate: unknown): boolean => candidate === null || typeof candidate === "string" && /^\d+$/u.test(candidate);
  const nullableHash = (candidate: unknown): boolean => candidate === null || typeof candidate === "string" && /^[a-f0-9]{64}$/u.test(candidate);
  return item.version === 1
    && Number.isSafeInteger(item.pid) && Number(item.pid) > 0
    && (item.processGroup === null || Number.isSafeInteger(item.processGroup) && Number(item.processGroup) > 0)
    && nullableDigits(item.kernelStartTicks)
    && nullableDigits(item.executableDevice)
    && nullableDigits(item.executableInode)
    && nullableHash(item.commandSha256)
    && nullableHash(item.bootIdSha256);
}

type SignalProcess = (pid: number, signal: 0) => void;

function processErrorCode(error: unknown): string | undefined {
  return error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
}

export function processExistence(pid: number, signalProcess: SignalProcess = process.kill): ProcessExistence {
  if (!Number.isSafeInteger(pid) || pid < 1) throw new Error("process id must be a positive safe integer");
  try {
    signalProcess(pid, 0);
    return "exists";
  } catch (error) {
    const code = processErrorCode(error);
    if (code === "ESRCH") return "missing";
    if (code === "EPERM" || code === "EACCES") return "exists-unauthorized";
    throw error;
  }
}

function linuxStatFields(value: string): { processGroup: number; startTicks: string } {
  const closing = value.lastIndexOf(")");
  if (closing < 2 || closing + 2 >= value.length) throw new Error("process stat record is malformed");
  const fields = value.slice(closing + 2).trim().split(/\s+/u);
  const processGroup = Number(fields[2]);
  const startTicks = fields[19];
  if (!Number.isSafeInteger(processGroup) || processGroup < 1 || startTicks === undefined || !/^\d+$/u.test(startTicks)) {
    throw new Error("process stat identity fields are malformed");
  }
  return { processGroup, startTicks };
}

async function optionalRead(filename: string): Promise<Buffer | undefined> {
  try {
    return await readFile(filename);
  } catch (error) {
    const code = processErrorCode(error);
    if (code === "ENOENT" || code === "ESRCH" || code === "EACCES" || code === "EPERM") return undefined;
    throw error;
  }
}

export async function captureProcessIdentity(pid = process.pid): Promise<ProcessIdentity> {
  if (!Number.isSafeInteger(pid) || pid < 1) throw new Error("process id must be a positive safe integer");
  if (process.platform !== "linux") {
    return {
      version: 1,
      pid,
      processGroup: null,
      kernelStartTicks: null,
      executableDevice: null,
      executableInode: null,
      commandSha256: null,
      bootIdSha256: null,
    };
  }

  const statBytes = await optionalRead(`/proc/${pid}/stat`);
  const command = await optionalRead(`/proc/${pid}/cmdline`);
  const bootId = await optionalRead("/proc/sys/kernel/random/boot_id");
  let executableDevice: string | null = null;
  let executableInode: string | null = null;
  try {
    // Stat the procfs link itself (following it in-kernel) so an executable
    // path replacement cannot race a separate readlink/stat pair.
    const metadata = await stat(`/proc/${pid}/exe`, { bigint: true });
    executableDevice = metadata.dev.toString();
    executableInode = metadata.ino.toString();
  } catch (error) {
    const code = processErrorCode(error);
    if (code !== "ENOENT" && code !== "ESRCH" && code !== "EACCES" && code !== "EPERM") throw error;
  }
  const parsed = statBytes === undefined ? undefined : linuxStatFields(statBytes.toString("utf8"));
  return {
    version: 1,
    pid,
    processGroup: parsed?.processGroup ?? null,
    kernelStartTicks: parsed?.startTicks ?? null,
    executableDevice,
    executableInode,
    commandSha256: command === undefined ? null : createHash("sha256").update(command).digest("hex"),
    bootIdSha256: bootId === undefined ? null : createHash("sha256").update(bootId).digest("hex"),
  };
}

export function sameProcessIdentity(expected: ProcessIdentity, observed: ProcessIdentity): boolean {
  if (expected.pid !== observed.pid) return false;
  const comparable: Array<keyof Omit<ProcessIdentity, "version" | "pid">> = [
    "processGroup",
    "kernelStartTicks",
    "executableDevice",
    "executableInode",
    "commandSha256",
    "bootIdSha256",
  ];
  let compared = 0;
  for (const key of comparable) {
    const left = expected[key];
    const right = observed[key];
    if (left === null || right === null) continue;
    compared += 1;
    if (left !== right) return false;
  }
  return compared > 0;
}

function comparableIdentityFields(expected: ProcessIdentity, observed: ProcessIdentity): number {
  return [
    [expected.processGroup, observed.processGroup],
    [expected.kernelStartTicks, observed.kernelStartTicks],
    [expected.executableDevice, observed.executableDevice],
    [expected.executableInode, observed.executableInode],
    [expected.commandSha256, observed.commandSha256],
  ].filter(([left, right]) => left !== null && right !== null).length;
}

export function processIdentityMatch(expected: ProcessIdentity, observed: ProcessIdentity): boolean | null {
  if (expected.pid !== observed.pid) return false;
  if (expected.bootIdSha256 !== null && observed.bootIdSha256 !== null
    && expected.bootIdSha256 !== observed.bootIdSha256) return false;
  if (expected.kernelStartTicks !== null && observed.kernelStartTicks !== null) {
    if (expected.kernelStartTicks !== observed.kernelStartTicks) return false;
    // A matching boot and kernel start tick prove the PID is the same process.
    // Command, executable, or process-group drift is suspicious but may result
    // from exec/argv/setpgid; it must make the identity unverifiable, not prove
    // the live owner dead and authorize lock theft.
    return sameProcessIdentity(expected, observed) ? true : null;
  }
  if (comparableIdentityFields(expected, observed) === 0) return null;
  return sameProcessIdentity(expected, observed) ? true : null;
}

export async function probeProcess(expected: ProcessIdentity): Promise<ProcessProbe> {
  const existence = processExistence(expected.pid);
  if (existence === "missing") return { existence, identityMatches: false, expected };
  if (existence === "exists-unauthorized") return { existence, identityMatches: null, expected };
  try {
    const observed = await captureProcessIdentity(expected.pid);
    return {
      existence,
      identityMatches: processIdentityMatch(expected, observed),
      expected,
      observed,
    };
  } catch (error) {
    if (processErrorCode(error) === "ENOENT" || processErrorCode(error) === "ESRCH") {
      return { existence: "missing", identityMatches: false, expected };
    }
    throw error;
  }
}
