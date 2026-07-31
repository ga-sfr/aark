import assert from "node:assert/strict";
import { mkdir, mkdtemp, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { sha256Hex } from "../core/crypto.js";
import { readValidatedRevealArtifact } from "../mining/reveal.js";
import type { SensitiveScanInventory } from "../mining/types.js";

test("reveal validation accepts only artifacts referenced by a finalized adjacent inventory", async () => {
  const output = await mkdtemp(path.join(os.tmpdir(), "agetnic-reveal-test-"));
  const findingDirectory = path.join(output, "artifacts", "finding-000001");
  await mkdir(findingDirectory, { recursive: true });
  const artifact = path.join(findingDirectory, "value.txt");
  const unlisted = path.join(findingDirectory, "unlisted.txt");
  const exact = Buffer.from("synthetic local value");
  await writeFile(artifact, exact);
  await writeFile(unlisted, "not listed");
  const inventory: SensitiveScanInventory = {
    version: 1,
    tool: "agetnic-tools",
    layer: "mining",
    status: "complete",
    complete: true,
    startedAt: "2026-01-01T00:00:00.000Z",
    updatedAt: "2026-01-01T00:00:01.000Z",
    finishedAt: "2026-01-01T00:00:01.000Z",
    inputRoots: [path.join(output, "input")],
    outputRoot: output,
    findings: [{
      id: 1,
      category: "synthetic",
      confidence: "high",
      bytes: exact.length,
      sha256: sha256Hex(exact),
      validation: { method: "synthetic", checks: {} },
      artifactFiles: [path.join("artifacts", "finding-000001", "value.txt")],
      artifactIntegrity: [{
        path: path.join("artifacts", "finding-000001", "value.txt"),
        bytes: exact.length,
        sha256: sha256Hex(exact),
      }],
      occurrences: [],
    }],
    errors: [],
    errorsOmitted: 0,
  };
  await writeFile(path.join(output, "inventory-sensitive.json"), JSON.stringify(inventory));
  assert.deepEqual(await readValidatedRevealArtifact(artifact), exact);
  await assert.rejects(readValidatedRevealArtifact(unlisted), /not referenced/);

  const alias = path.join(findingDirectory, "alias.txt");
  await symlink(artifact, alias);
  await assert.rejects(readValidatedRevealArtifact(alias), /non-symbolic-link/);

  await writeFile(artifact, "modified artifact bytes");
  await assert.rejects(readValidatedRevealArtifact(artifact), /do not match|integrity metadata|safety limit/);
  await writeFile(artifact, exact);

  delete (inventory as unknown as { status?: string }).status;
  await writeFile(path.join(output, "inventory-sensitive.json"), JSON.stringify(inventory));
  await assert.rejects(readValidatedRevealArtifact(artifact), /incomplete/);

  inventory.status = "in-progress";
  inventory.complete = false;
  await writeFile(path.join(output, "inventory-sensitive.json"), JSON.stringify(inventory));
  await assert.rejects(readValidatedRevealArtifact(artifact), /incomplete/);
});
