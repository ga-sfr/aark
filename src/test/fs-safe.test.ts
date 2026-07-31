import assert from "node:assert/strict";
import { access, mkdir, mkdtemp, readdir, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { acquireExclusiveLock, assertNoSymlinkComponents, atomicWriteFile, ensurePrivateDirectory, readJson } from "../core/fs-safe.js";

test("failed atomic writes remove unpublished temporary sensitive files", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agetnic-atomic-test-"));
  const destination = path.join(root, "existing-directory");
  await mkdir(destination);
  await assert.rejects(atomicWriteFile(destination, "synthetic-sensitive-payload"));
  assert.deepEqual((await readdir(root)).sort(), ["existing-directory"]);
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
});
