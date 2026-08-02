import assert from "node:assert/strict";
import { access, mkdtemp, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { captureCommand, commandExists } from "../core/command.js";

test("command discovery uses the fixed system path without an external which dependency", async () => {
  assert.equal(await commandExists("node"), true);
  assert.equal(await commandExists(process.execPath), true);
  assert.equal(await commandExists("../node"), false);
  assert.equal(await commandExists("agetnic-executable-that-does-not-exist"), false);
});

test("command runner streams large stdout and stderr to exclusive private files", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agetnic-command-"));
  const stdoutFile = path.join(root, "stdout.bin");
  const stderrFile = path.join(root, "stderr.bin");
  const script = [
    "const out = Buffer.alloc(2 * 1024 * 1024, 0x41);",
    "const err = Buffer.alloc(1024 * 1024, 0x42);",
    "process.stdout.write(out); process.stderr.write(err);",
  ].join("");
  const result = await captureCommand(process.execPath, ["-e", script], { stdoutFile, stderrFile });
  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout.length, 0);
  assert.equal(result.stderr.length, 0);
  assert.equal((await readFile(stdoutFile)).length, 2 * 1024 * 1024);
  assert.equal((await readFile(stderrFile)).length, 1024 * 1024);
  await assert.rejects(captureCommand(process.execPath, ["-e", ""], { stdoutFile }));
});

test("command setup and spawn failures remove unpublished output files", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agetnic-command-cleanup-"));
  const stdoutFile = path.join(root, "stdout.bin");
  const stderrFile = path.join(root, "stderr.bin");
  await writeFile(stderrFile, "existing");
  await assert.rejects(captureCommand(process.execPath, ["-e", ""], { stdoutFile, stderrFile }));
  await assert.rejects(access(stdoutFile));

  const spawnOutput = path.join(root, "spawn-output.bin");
  await assert.rejects(captureCommand("agetnic-executable-that-does-not-exist", [], { stdoutFile: spawnOutput }));
  await assert.rejects(access(spawnOutput));

  const synchronousOutput = path.join(root, "synchronous-spawn-output.bin");
  await assert.rejects(captureCommand(process.execPath, [], { cwd: "invalid\0cwd", stdoutFile: synchronousOutput }));
  await assert.rejects(access(synchronousOutput));
});

test("command runner forwards local cancellation to the child process", async () => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 50);
  const result = await captureCommand(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { signal: controller.signal });
  clearTimeout(timer);
  assert.notEqual(result.exitCode, 0);
  assert.equal(result.signal, "SIGTERM");
  assert.equal(result.terminationReason, "abort");
});

test("command runner strips unrelated credential environment variables", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agetnic-command-environment-"));
  const temporaryDirectory = path.join(root, "private-temporary");
  const result = await captureCommand(process.execPath, ["-e", "process.stdout.write(JSON.stringify(process.env))"], {
    temporaryDirectory,
    env: {
      PATH: process.env.PATH,
      HOME: "/synthetic/untrusted-home",
      TMPDIR: "/synthetic/untrusted-temp",
      LANG: "C.UTF-8",
      LC_TEST: "preserved",
      SHELL: "/synthetic/untrusted-shell",
      TZ: ":/synthetic/untrusted-timezone",
      GH_PAT: "synthetic-must-not-reach-child",
      AWS_SECRET_ACCESS_KEY: "synthetic-must-not-reach-child",
      NODE_OPTIONS: "--definitely-not-a-real-node-option",
    },
  });
  assert.equal(result.exitCode, 0);
  const environment = JSON.parse(result.stdout.toString("utf8")) as Record<string, string>;
  assert.equal(environment.LANG, "C.UTF-8");
  assert.equal(environment.LC_ALL, "C.UTF-8");
  assert.equal(environment.TERM, "dumb");
  assert.equal(environment.LC_TEST, undefined);
  assert.equal(environment.SHELL, undefined);
  assert.equal(environment.TZ, undefined);
  assert.equal(environment.PATH, "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
  assert.equal(environment.HOME, "/nonexistent");
  assert.equal(environment.TMPDIR, temporaryDirectory);
  assert.equal(environment.TMP, temporaryDirectory);
  assert.equal(environment.TEMP, temporaryDirectory);
  assert.equal(environment.PYTHONNOUSERSITE, "1");
  assert.equal(environment.GH_PAT, undefined);
  assert.equal(environment.AWS_SECRET_ACCESS_KEY, undefined);
  assert.equal(environment.NODE_OPTIONS, undefined);
});

test("command runner escalates cancellation when a child ignores SIGTERM", async () => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 200);
  const result = await captureCommand(process.execPath, ["-e", "process.on('SIGTERM',()=>{});setInterval(()=>{},1000)"], {
    signal: controller.signal,
    killGraceMs: 40,
  });
  clearTimeout(timer);
  assert.equal(result.signal, "SIGKILL");
  assert.equal(result.terminationReason, "abort");
  assert.ok(result.durationMs < 2_000);
});

test("command runner terminates a process when its safety invariant fails", async () => {
  let checks = 0;
  const started = Date.now();
  await assert.rejects(captureCommand(process.execPath, ["-e", "process.on('SIGTERM',()=>{});setInterval(()=>{},1000)"], {
    killGraceMs: 40,
    safetyCheckIntervalMs: 20,
    safetyCheck: async () => {
      checks += 1;
      throw new Error("synthetic safety failure");
    },
  }), /command safety invariant failed during execution/);
  assert.equal(checks, 1);
  assert.ok(Date.now() - started < 2_000);
});

test("command runner reports bounded capture truncation", async () => {
  const result = await captureCommand(process.execPath, ["-e", "process.stdout.write('abcdef'); process.stderr.write('uvwxyz')"], {
    maxCaptureBytes: 3,
  });
  assert.equal(result.stdout.toString("utf8"), "abc");
  assert.equal(result.stderr.toString("utf8"), "uvw");
  assert.equal(result.stdoutTruncated, true);
  assert.equal(result.stderrTruncated, true);
});

test("a safety check that finishes after process exit still invalidates the command", async () => {
  let markStarted: (() => void) | undefined;
  const started = new Promise<void>((resolve) => { markStarted = resolve; });
  let rejectSafety: ((error: Error) => void) | undefined;
  const pendingSafety = new Promise<void>((_resolve, reject) => { rejectSafety = reject; });
  const command = captureCommand(process.execPath, ["-e", "setTimeout(() => {}, 40)"], {
    safetyCheckIntervalMs: 10,
    safetyCheck: async () => {
      markStarted?.();
      await pendingSafety;
    },
  });
  await started;
  await new Promise((resolve) => setTimeout(resolve, 80));
  rejectSafety?.(new Error("late synthetic safety failure"));
  await assert.rejects(command, /command safety invariant failed during execution/);
});

test("command cancellation terminates descendants in the isolated process group", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agetnic-command-tree-"));
  const survived = path.join(root, "descendant-survived");
  const descendant = [
    "const fs=require('node:fs');",
    "process.on('SIGTERM',()=>{});",
    `setTimeout(()=>fs.writeFileSync(${JSON.stringify(survived)},'unexpected'),300);`,
    "setInterval(()=>{},1000);",
  ].join("");
  const parent = [
    "const {spawn}=require('node:child_process');",
    `spawn(process.execPath,['-e',${JSON.stringify(descendant)}],{stdio:'ignore'});`,
    "setInterval(()=>{},1000);",
  ].join("");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 100);
  const result = await captureCommand(process.execPath, ["-e", parent], { signal: controller.signal, killGraceMs: 40 });
  clearTimeout(timer);
  assert.equal(result.terminationReason, "abort");
  await new Promise((resolve) => setTimeout(resolve, 400));
  await assert.rejects(access(survived));
});

test("normal command completion also terminates leftover descendants", { skip: process.platform === "win32" }, async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-command-normal-tree-"));
  const survived = path.join(root, "descendant-survived");
  const descendant = [
    "const fs=require('node:fs');",
    `setTimeout(()=>fs.writeFileSync(${JSON.stringify(survived)},'unexpected'),300);`,
    "setInterval(()=>{},1000);",
  ].join("");
  const parent = [
    "const {spawn}=require('node:child_process');",
    `spawn(process.execPath,['-e',${JSON.stringify(descendant)}],{stdio:'ignore'});`,
  ].join("");
  const result = await captureCommand(process.execPath, ["-e", parent], { killGraceMs: 40 });
  assert.equal(result.exitCode, 0);
  assert.equal(result.terminationReason, null);
  await new Promise((resolve) => setTimeout(resolve, 400));
  await assert.rejects(access(survived));
});
