import assert from "node:assert/strict";
import { access, link, mkdir, mkdtemp, readFile, readdir, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { acquireExclusiveLock, assertNoSymlinkComponents, atomicWriteFile, ensurePrivateDirectory, readDirectoryNamesBounded, readJson, walkRegularFiles } from "../core/fs-safe.js";

test("regular-file walks are deterministic and honor cancellation", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-walk-test-"));
  await mkdir(path.join(root, "b-directory"));
  await writeFile(path.join(root, "z.txt"), "z");
  await writeFile(path.join(root, "a.txt"), "a");
  await writeFile(path.join(root, "b-directory", "c.txt"), "c");
  const collect = async (): Promise<string[]> => {
    const files: string[] = [];
    for await (const file of walkRegularFiles([root])) files.push(path.relative(root, file.path));
    return files;
  };
  assert.deepEqual(await collect(), ["a.txt", path.join("b-directory", "c.txt"), "z.txt"]);
  assert.deepEqual(await collect(), await collect());

  const controller = new AbortController();
  controller.abort();
  await assert.rejects(async () => {
    for await (const _file of walkRegularFiles([root], { signal: controller.signal })) {
      // The pre-aborted walk must never yield a file.
    }
  }, /paused/);
});

test("regular-file walks bound flat directories and the pending frontier", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-walk-bound-test-"));
  const oversized = path.join(root, "oversized");
  await mkdir(oversized);
  await writeFile(path.join(root, "safe.txt"), "safe");
  await writeFile(path.join(oversized, "a.txt"), "a");
  await writeFile(path.join(oversized, "b.txt"), "b");
  await writeFile(path.join(oversized, "c.txt"), "c");
  const errors: string[] = [];
  const files: string[] = [];
  for await (const file of walkRegularFiles([root], {
    maximumDirectoryEntries: 2,
    onError: (input) => errors.push(path.relative(root, input)),
  })) files.push(path.relative(root, file.path));
  assert.deepEqual(files, ["safe.txt"]);
  assert.deepEqual(errors, ["oversized"]);
  await assert.rejects(async () => {
    for await (const _file of walkRegularFiles([root], { maximumPendingEntries: 1 })) {
      // A root whose deterministic frontier is too wide fails rather than allocating without bound.
    }
  }, /frontier limit/);

  const directoryHeavy = path.join(root, "directory-heavy");
  await mkdir(directoryHeavy);
  await mkdir(path.join(directoryHeavy, "one"));
  await mkdir(path.join(directoryHeavy, "two"));
  const directoryErrors: string[] = [];
  for await (const _file of walkRegularFiles([directoryHeavy], {
    maximumDirectories: 2,
    onError: (input) => directoryErrors.push(path.relative(directoryHeavy, input)),
  })) {
    // No regular files are needed to exercise the visited-directory bound.
  }
  assert.deepEqual(directoryErrors, ["two"]);
});

test("failed atomic writes remove unpublished temporary sensitive files", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agetnic-atomic-test-"));
  const destination = path.join(root, "existing-directory");
  await mkdir(destination);
  await assert.rejects(atomicWriteFile(destination, "synthetic-sensitive-payload"));
  assert.deepEqual((await readdir(root)).sort(), ["existing-directory"]);
});

test("atomic rewrites reject hard-linked control destinations", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-atomic-hardlink-test-"));
  const destination = path.join(root, "control.json");
  const alias = path.join(root, "control-alias.json");
  await writeFile(destination, "old");
  await link(destination, alias);
  await assert.rejects(atomicWriteFile(destination, "new"), /single-link/);
  assert.equal(await readFile(destination, "utf8"), "old");
  assert.equal(await readFile(alias, "utf8"), "old");
});

test("output guards reject final and intermediate symbolic links", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agetnic-symlink-test-"));
  const outside = await mkdtemp(path.join(os.tmpdir(), "agetnic-symlink-outside-"));
  const link = path.join(root, "redirected");
  await symlink(outside, link);
  await assert.rejects(assertNoSymlinkComponents(root, path.join(link, "artifact.bin")), /symbolic-link output component/);
  await assert.rejects(ensurePrivateDirectory(link), /symbolic-link/);
});

test("exclusive output locks reject concurrent writers and are removed on release", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agetnic-lock-test-"));
  const first = await acquireExclusiveLock(root, ".agetnic-test.lock");
  await first.assertHeld();
  await assert.rejects(acquireExclusiveLock(root, ".agetnic-test.lock"), /exclusive operation lock/);
  await first.release();
  await assert.rejects(first.assertHeld(), /already released/);
  await assert.rejects(access(path.join(root, ".agetnic-test.lock")));
  const second = await acquireExclusiveLock(root, ".agetnic-test.lock");
  await second.release();
});

test("JSON control files are bounded regular files and final symlinks are not followed", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agetnic-json-test-"));
  const filename = path.join(root, "control.json");
  const alias = path.join(root, "control-alias.json");
  await writeFile(filename, "{\"version\":1}");
  assert.deepEqual(await readJson(filename), { version: 1 });
  await assert.rejects(readJson(filename, 4), /bounded size limit/);
  const malformed = path.join(root, "malformed.json");
  const diagnosticSecret = "synthetic-value-that-must-not-appear-in-an-error";
  await writeFile(malformed, `{\"value\":\"${diagnosticSecret}\",broken}`);
  await assert.rejects(readJson(malformed), (error: unknown) => {
    assert.match(String(error), /not valid JSON/);
    assert.equal(String(error).includes(diagnosticSecret), false);
    return true;
  });
  await symlink(filename, alias);
  await assert.rejects(readJson(alias));
  const hardlink = path.join(root, "control-hardlink.json");
  await link(filename, hardlink);
  await assert.rejects(readJson(filename), /single-link/);
});

test("bounded directory reads stop oversized control layouts", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-directory-bound-test-"));
  await writeFile(path.join(root, "first"), "1");
  await writeFile(path.join(root, "second"), "2");
  assert.deepEqual((await readDirectoryNamesBounded(root, 2)).sort(), ["first", "second"]);
  await assert.rejects(readDirectoryNamesBounded(root, 1), /more entries/);
  await assert.rejects(readDirectoryNamesBounded(root, -1), /non-negative safe integer/);
});
