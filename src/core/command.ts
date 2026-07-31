import { spawn } from "node:child_process";
import { constants } from "node:fs";
import { access, lstat, open, stat, unlink } from "node:fs/promises";
import { basename, delimiter, dirname, isAbsolute, join, resolve } from "node:path";
import { ensurePrivateDirectory, syncDirectory } from "./fs-safe.js";

export interface CommandResult {
  executable: string;
  args: string[];
  exitCode: number;
  signal: NodeJS.Signals | null;
  stdout: Buffer;
  stderr: Buffer;
  durationMs: number;
  terminationReason: "abort" | "timeout" | "safety-check" | null;
}

export interface CommandOptions {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  temporaryDirectory?: string;
  stdin?: Uint8Array;
  stdoutFile?: string;
  stderrFile?: string;
  timeoutMs?: number;
  killGraceMs?: number;
  maxCaptureBytes?: number;
  signal?: AbortSignal;
  safetyCheck?: () => Promise<void>;
  safetyCheckIntervalMs?: number;
}

const SAFE_EXECUTABLE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const SAFE_TEMPORARY_DIRECTORY = "/tmp";

interface CommandOutputIdentity {
  device: number;
  inode: number;
}

async function assertCommandOutputLink(filename: string, identity: CommandOutputIdentity): Promise<void> {
  const current = await lstat(filename);
  if (current.isSymbolicLink() || !current.isFile() || current.nlink !== 1 || current.dev !== identity.device || current.ino !== identity.inode) {
    throw new Error("command output path changed after protected creation");
  }
}

async function unlinkCommandOutputIfOwned(filename: string, identity: CommandOutputIdentity | undefined): Promise<boolean> {
  if (identity === undefined) return false;
  try {
    await assertCommandOutputLink(filename, identity);
    await unlink(filename);
    return true;
  } catch {
    return false;
  }
}

export function sanitizedEnvironment(_source: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  return {
    PATH: SAFE_EXECUTABLE_PATH,
    HOME: "/nonexistent",
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    TERM: "dumb",
    TMPDIR: SAFE_TEMPORARY_DIRECTORY,
    TMP: SAFE_TEMPORARY_DIRECTORY,
    TEMP: SAFE_TEMPORARY_DIRECTORY,
    PYTHONNOUSERSITE: "1",
  };
}

export async function commandExists(executable: string): Promise<boolean> {
  if (executable === "" || executable.includes("\0")) return false;
  const candidates = isAbsolute(executable)
    ? [executable]
    : executable === basename(executable)
      ? SAFE_EXECUTABLE_PATH.split(delimiter).map((directory) => join(directory, executable))
      : [];
  for (const candidate of candidates) {
    try {
      await access(candidate, constants.X_OK);
      if ((await stat(candidate)).isFile()) return true;
    } catch (error) {
      const code = error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
      if (code !== "ENOENT" && code !== "ENOTDIR" && code !== "EACCES") throw error;
    }
  }
  return false;
}

export async function captureCommand(
  executable: string,
  args: string[],
  options: CommandOptions = {},
): Promise<CommandResult> {
  if (executable.includes("\0") || args.some((arg) => arg.includes("\0"))) {
    throw new Error("NUL byte in command argument");
  }
  const started = Date.now();
  const maxCapture = options.maxCaptureBytes ?? 8 * 1024 * 1024;
  const killGraceMs = options.killGraceMs ?? 5_000;
  if (!Number.isSafeInteger(maxCapture) || maxCapture < 0) throw new Error("maxCaptureBytes must be a non-negative integer");
  if (!Number.isSafeInteger(killGraceMs) || killGraceMs < 1 || killGraceMs > 60_000) throw new Error("killGraceMs must be an integer from 1 through 60000");
  if (options.timeoutMs !== undefined && (!Number.isSafeInteger(options.timeoutMs) || options.timeoutMs < 1)) throw new Error("timeoutMs must be a positive integer");
  const safetyCheckIntervalMs = options.safetyCheckIntervalMs ?? 5_000;
  if (!Number.isSafeInteger(safetyCheckIntervalMs) || safetyCheckIntervalMs < 10 || safetyCheckIntervalMs > 60_000) {
    throw new Error("safetyCheckIntervalMs must be an integer from 10 through 60000");
  }
  let outputHandle: Awaited<ReturnType<typeof open>> | undefined;
  let errorHandle: Awaited<ReturnType<typeof open>> | undefined;
  let temporaryDirectory: string | undefined;
  let outputCreated = false;
  let errorCreated = false;
  let outputIdentity: CommandOutputIdentity | undefined;
  let errorIdentity: CommandOutputIdentity | undefined;
  const cleanupUnstartedOutputs = async (): Promise<void> => {
    await outputHandle?.close().catch(() => undefined);
    await errorHandle?.close().catch(() => undefined);
    if (outputCreated && options.stdoutFile !== undefined) await unlinkCommandOutputIfOwned(options.stdoutFile, outputIdentity);
    if (errorCreated && options.stderrFile !== undefined) await unlinkCommandOutputIfOwned(options.stderrFile, errorIdentity);
    const directories = new Set([
      ...(outputCreated && options.stdoutFile !== undefined ? [dirname(options.stdoutFile)] : []),
      ...(errorCreated && options.stderrFile !== undefined ? [dirname(options.stderrFile)] : []),
    ]);
    for (const directory of directories) await syncDirectory(directory).catch(() => undefined);
  };
  try {
    if (options.temporaryDirectory !== undefined) {
      if (!isAbsolute(options.temporaryDirectory) || options.temporaryDirectory.includes("\0")) {
        throw new Error("temporaryDirectory must be an absolute path without NUL bytes");
      }
      temporaryDirectory = resolve(options.temporaryDirectory);
      await ensurePrivateDirectory(temporaryDirectory);
    }
    if (options.stdoutFile !== undefined) {
      await ensurePrivateDirectory(dirname(options.stdoutFile));
      outputHandle = await open(options.stdoutFile, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
      outputCreated = true;
      const metadata = await outputHandle.stat();
      outputIdentity = { device: metadata.dev, inode: metadata.ino };
      await assertCommandOutputLink(options.stdoutFile, outputIdentity);
    }
    if (options.stderrFile !== undefined) {
      await ensurePrivateDirectory(dirname(options.stderrFile));
      errorHandle = await open(options.stderrFile, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
      errorCreated = true;
      const metadata = await errorHandle.stat();
      errorIdentity = { device: metadata.dev, inode: metadata.ino };
      await assertCommandOutputLink(options.stderrFile, errorIdentity);
    }
  } catch (error) {
    await cleanupUnstartedOutputs();
    throw error;
  }
  if (options.signal?.aborted === true) {
    await cleanupUnstartedOutputs();
    throw new Error("command aborted before execution");
  }

  return await new Promise<CommandResult>((resolve, reject) => {
    let child: ReturnType<typeof spawn>;
    const detached = process.platform !== "win32";
    try {
      const environment = sanitizedEnvironment(options.env ?? process.env);
      if (temporaryDirectory !== undefined) {
        environment.TMPDIR = temporaryDirectory;
        environment.TMP = temporaryDirectory;
        environment.TEMP = temporaryDirectory;
      }
      child = spawn(executable, args, {
        cwd: options.cwd,
        env: environment,
        detached,
        shell: false,
        stdio: [
          options.stdin === undefined ? "ignore" : "pipe",
          outputHandle === undefined ? "pipe" : outputHandle.fd,
          errorHandle === undefined ? "pipe" : errorHandle.fd,
        ],
      });
    } catch (error) {
      void cleanupUnstartedOutputs().then(() => reject(error), reject);
      return;
    }
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let timer: NodeJS.Timeout | undefined;
    let killTimer: NodeJS.Timeout | undefined;
    let safetyTimer: NodeJS.Timeout | undefined;
    let safetyCheckPromise: Promise<void> | undefined;
    let settled = false;
    let runtimeError: unknown;
    let terminationReason: CommandResult["terminationReason"] = null;
    const signalProcessTree = (signal: NodeJS.Signals): void => {
      if (detached && child.pid !== undefined) {
        try {
          process.kill(-child.pid, signal);
          return;
        } catch {
          // Fall back to the direct child if its process group has already gone away.
        }
      }
      try {
        child.kill(signal);
      } catch {
        // A concurrent process exit is equivalent to a successful termination request.
      }
    };
    const terminate = (reason: Exclude<CommandResult["terminationReason"], null>): void => {
      if (terminationReason !== null || (!detached && (child.exitCode !== null || child.signalCode !== null))) return;
      terminationReason = reason;
      signalProcessTree("SIGTERM");
      killTimer = setTimeout(() => {
        if (detached || (child.exitCode === null && child.signalCode === null)) signalProcessTree("SIGKILL");
      }, killGraceMs);
      killTimer.unref();
    };
    const abort = (): void => terminate("abort");
    options.signal?.addEventListener("abort", abort, { once: true });
    if (options.signal?.aborted === true) abort();
    if (options.timeoutMs !== undefined) {
      timer = setTimeout(() => terminate("timeout"), options.timeoutMs);
      timer.unref();
    }
    const scheduleSafetyCheck = (): void => {
      if (options.safetyCheck === undefined || settled || terminationReason !== null) return;
      safetyTimer = setTimeout(() => {
        safetyCheckPromise = Promise.resolve()
          .then(async () => options.safetyCheck?.())
          .catch((error: unknown) => {
            if (settled || terminationReason !== null || runtimeError !== undefined) return;
            runtimeError = new Error("command safety check failed", { cause: error });
            terminate("safety-check");
          })
          .finally(() => {
            safetyCheckPromise = undefined;
            scheduleSafetyCheck();
          });
      }, safetyCheckIntervalMs);
      safetyTimer.unref();
    };
    scheduleSafetyCheck();
    if (options.stdin !== undefined) {
      child.stdin?.on("error", () => undefined);
      child.stdin?.end(options.stdin);
    }
    child.stdout?.on("data", (chunk: Buffer) => {
      if (stdoutBytes < maxCapture) {
        stdout.push(chunk.subarray(0, maxCapture - stdoutBytes));
        stdoutBytes += chunk.length;
      }
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      if (stderrBytes < maxCapture) {
        stderr.push(chunk.subarray(0, maxCapture - stderrBytes));
        stderrBytes += chunk.length;
      }
    });
    child.on("error", async (error) => {
      if (settled) return;
      if (child.pid !== undefined) {
        if (runtimeError === undefined) {
          runtimeError = error;
          signalProcessTree("SIGKILL");
        }
        return;
      }
      settled = true;
      if (timer !== undefined) clearTimeout(timer);
      if (killTimer !== undefined) clearTimeout(killTimer);
      if (safetyTimer !== undefined) clearTimeout(safetyTimer);
      options.signal?.removeEventListener("abort", abort);
      await cleanupUnstartedOutputs();
      reject(error);
    });
    child.on("close", async (exitCode, signal) => {
      if (settled) return;
      settled = true;
      if (timer !== undefined) clearTimeout(timer);
      if (killTimer !== undefined) clearTimeout(killTimer);
      if (safetyTimer !== undefined) clearTimeout(safetyTimer);
      if (terminationReason !== null && detached) signalProcessTree("SIGKILL");
      options.signal?.removeEventListener("abort", abort);
      await safetyCheckPromise?.catch(() => undefined);
      let persistenceError: unknown;
      const protectedOutputs = [
        ...(outputHandle !== undefined && options.stdoutFile !== undefined && outputIdentity !== undefined
          ? [{ handle: outputHandle, filename: options.stdoutFile, identity: outputIdentity }]
          : []),
        ...(errorHandle !== undefined && options.stderrFile !== undefined && errorIdentity !== undefined
          ? [{ handle: errorHandle, filename: options.stderrFile, identity: errorIdentity }]
          : []),
      ];
      for (const { handle, filename, identity } of protectedOutputs) {
        try {
          await assertCommandOutputLink(filename, identity);
        } catch (error) {
          persistenceError ??= error;
        }
        try {
          await handle.sync();
        } catch (error) {
          persistenceError ??= error;
        }
        try {
          await handle.close();
        } catch (error) {
          persistenceError ??= error;
        }
      }
      for (const directory of new Set([
        ...(outputCreated && options.stdoutFile !== undefined ? [dirname(options.stdoutFile)] : []),
        ...(errorCreated && options.stderrFile !== undefined ? [dirname(options.stderrFile)] : []),
      ])) {
        try {
          await syncDirectory(directory);
        } catch (error) {
          persistenceError ??= error;
        }
      }
      for (const { filename, identity } of protectedOutputs) {
        try {
          await assertCommandOutputLink(filename, identity);
        } catch (error) {
          persistenceError ??= error;
        }
      }
      if (persistenceError !== undefined) {
        reject(new Error("could not durably persist command output", { cause: persistenceError }));
        return;
      }
      if (runtimeError !== undefined) {
        reject(new Error(
          terminationReason === "safety-check"
            ? "command safety invariant failed during execution"
            : "command process failed after it started",
          { cause: runtimeError },
        ));
        return;
      }
      resolve({
        executable,
        args: [...args],
        exitCode: exitCode ?? -1,
        signal,
        stdout: Buffer.concat(stdout),
        stderr: Buffer.concat(stderr),
        durationMs: Date.now() - started,
        terminationReason,
      });
    });
  });
}
