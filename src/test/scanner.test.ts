import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { unlinkSync } from "node:fs";
import { access, mkdir, mkdtemp, readFile, readdir, realpath, stat, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { entropyToMnemonic } from "@scure/bip39";
import { wordlist as english } from "@scure/bip39/wordlists/english.js";
import { sha256Hex } from "../core/crypto.js";
import { ArtifactStore } from "../mining/artifacts.js";
import { resumeSensitiveMaterial, scanSensitiveMaterial } from "../mining/scanner.js";
import type { SensitiveScanInventory } from "../mining/types.js";
import { expandAesKey } from "../mining/validators/aes.js";
import { BITCOIN_ALPHABET, encodeBase58Check } from "./helpers.js";

function randomAlphanumeric(length: number): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const bytes = randomBytes(length);
  return [...bytes].map((byte) => alphabet[byte % alphabet.length] ?? "A").join("");
}

async function artifactContents(output: string): Promise<Buffer[]> {
  const values: Buffer[] = [];
  const root = path.join(output, "artifacts");
  for (const directory of await readdir(root)) {
    for (const filename of await readdir(path.join(root, directory))) values.push(await readFile(path.join(root, directory, filename)));
  }
  return values;
}

test("artifact publication revalidates output safety before exact writes", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agetnic-output-guard-test-"));
  const output = path.join(root, "mined");
  let safe = true;
  const store = new ArtifactStore(output, [root], false, async () => {
    if (!safe) throw new Error("synthetic output safety change");
  });
  await store.initialize();
  safe = false;
  const value = randomBytes(32);
  await assert.rejects(store.add(path.join(root, "source.bin"), "unknown", {
    category: "synthetic-test-secret",
    offset: 0,
    length: value.length,
    value,
    confidence: "high",
    validation: { method: "synthetic", checks: { exact: true } },
    extension: ".key",
  }), /synthetic output safety change/);
  assert.deepEqual(await readdir(path.join(output, "artifacts")), []);
});

test("an output child whose name begins with two dots is still rejected inside an input", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-containment-test-"));
  const input = path.join(root, "input");
  await mkdir(input);
  await assert.rejects(scanSensitiveMaterial({
    inputs: [input],
    output: path.join(input, "..results"),
    provenance: "unknown",
    chunkBytes: 17 * 1024 * 1024,
    overlapBytes: 17 * 1024 * 1024,
    wholeFileBytes: 1024 * 1024,
    workers: 1,
    minimumFreeGiB: 0,
    minimumFreePercent: 0,
  }), /cannot be inside a scanned input directory/);
});

test("scanner keeps exact values local while default manifests stay redacted", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agetnic-test-"));
  const input = path.join(root, "recovered");
  const output = path.join(root, "mined");
  await mkdir(input);

  const mnemonic = entropyToMnemonic(randomBytes(16), english);
  const scalar = Buffer.concat([Buffer.alloc(31), Buffer.from([9])]);
  const wif = encodeBase58Check(Buffer.concat([Buffer.from([0x80]), scalar, Buffer.from([1])]), BITCOIN_ALPHABET);
  const providerToken = `ghp_${randomAlphanumeric(36)}`;
  const genericSecret = randomBytes(32).toString("base64url");
  const awsSecret = randomBytes(30).toString("base64");
  const awsSession = randomBytes(48).toString("base64");
  const { privateKey } = generateKeyPairSync("ed25519");
  const pem = Buffer.from(privateKey.export({ format: "pem", type: "pkcs8" }));

  await writeFile(path.join(input, "wallet-a.txt"), `${mnemonic}\n${wif}\napi_key=${genericSecret}\nAWS_SECRET_ACCESS_KEY=${awsSecret}\nAWS_SESSION_TOKEN=${awsSession}\n`);
  await writeFile(path.join(input, "wallet-b.txt"), mnemonic);
  await writeFile(path.join(input, "identity.pem"), pem);
  await writeFile(path.join(input, "stream.raw"), Buffer.concat([
    Buffer.alloc(1024 * 1024 - 10, 0x41),
    Buffer.from(`\n${providerToken}\n`, "ascii"),
    Buffer.alloc(1024 * 1024, 0x42),
  ]));
  const ignored = path.join(root, "ignored.txt");
  await writeFile(ignored, `api_key=${randomBytes(32).toString("hex")}`);
  await symlink(ignored, path.join(input, "not-followed"));

  const result = await scanSensitiveMaterial({
    inputs: [input],
    output,
    provenance: "unallocated-carve",
    chunkBytes: 17 * 1024 * 1024,
    overlapBytes: 17 * 1024 * 1024,
    wholeFileBytes: 1024 * 1024,
    minimumFreeGiB: 0,
    minimumFreePercent: 0,
  });
  assert.equal(result.complete, true);
  assert.equal(result.filesVisited, 4);
  await assert.rejects(access(path.join(output, ".aark-mining.lock")));
  await assert.rejects(access(path.join(output, ".agetnic-mining.lock")));

  const inventoryText = await readFile(path.join(output, "inventory-sensitive.json"), "utf8");
  const manifestText = await readFile(path.join(output, "manifest-redacted.json"), "utf8");
  const sensitiveReport = await readFile(path.join(output, "final-report-sensitive.md"), "utf8");
  const redactedReport = await readFile(path.join(output, "final-report-redacted.md"), "utf8");
  const inventory = JSON.parse(inventoryText) as SensitiveScanInventory;
  assert.equal(inventory.complete, true);
  assert.ok(inventory.findings.some((finding) => finding.category === "bip39-mnemonic" && finding.occurrences.length === 2));
  assert.ok(inventory.findings.some((finding) => finding.category === "bitcoin-wif-private-key"));
  assert.ok(inventory.findings.some((finding) => finding.category === "pem-private-key"));
  assert.ok(inventory.findings.some((finding) => finding.category === "github-access-token"));
  assert.ok(inventory.findings.some((finding) => finding.category === "aws-secret-access-key"));
  assert.ok(inventory.findings.some((finding) => finding.category === "aws-session-token"));
  for (const finding of inventory.findings) {
    assert.deepEqual(finding.artifactIntegrity.map((entry) => entry.path), finding.artifactFiles);
    for (const entry of finding.artifactIntegrity) {
      const artifact = await readFile(path.join(output, entry.path));
      assert.equal(artifact.length, entry.bytes);
      assert.equal(sha256Hex(artifact), entry.sha256);
    }
  }

  const artifacts = await artifactContents(output);
  for (const exact of [Buffer.from(mnemonic), Buffer.from(wif), pem, Buffer.from(providerToken), Buffer.from(genericSecret), Buffer.from(awsSecret), Buffer.from(awsSession)]) {
    assert.ok(artifacts.some((artifact) => artifact.equals(exact)), "an exact local secret artifact was missing");
  }

  for (const secret of [mnemonic, wif, providerToken, genericSecret, awsSecret, awsSession, pem.toString("utf8"), input, sha256Hex(Buffer.from(mnemonic))]) {
    assert.equal(manifestText.includes(secret), false, "redacted manifest leaked sensitive scan data");
    assert.equal(redactedReport.includes(secret), false, "redacted final report leaked sensitive scan data");
  }
  assert.match(sensitiveReport, /Cryptocurrency and wallet findings/);
  assert.match(sensitiveReport, /Total cryptocurrency-related unique findings: [1-9]/);
  assert.ok(sensitiveReport.includes(input));
  assert.ok(sensitiveReport.includes(path.join(output, "artifacts")));
  assert.ok(sensitiveReport.includes("bitcoin-wif-private-key"));
  assert.equal(sensitiveReport.includes(mnemonic), false, "sensitive report should reference exact artifacts without duplicating values");
  assert.equal(inventoryText.includes(mnemonic), false, "sensitive inventory should map artifacts, not duplicate values inline");
  assert.equal(inventory.findings.some((finding) => finding.occurrences.some((occurrence) => occurrence.sourcePath === ignored)), false);
  assert.equal((await stat(path.join(output, "inventory-sensitive.json"))).mode & 0o777, 0o600);
  assert.equal((await stat(path.join(output, "manifest-redacted.json"))).mode & 0o777, 0o644);
  assert.equal((await stat(path.join(output, "final-report-sensitive.md"))).mode & 0o777, 0o600);
  assert.equal((await stat(path.join(output, "final-report-redacted.md"))).mode & 0o777, 0o644);
});

test("scanner rejects an output that aliases a scanned input through a parent symlink", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agetnic-alias-test-"));
  const input = path.join(root, "recovered");
  const alias = path.join(root, "recovered-alias");
  await mkdir(input);
  await symlink(input, alias);
  await assert.rejects(scanSensitiveMaterial({
    inputs: [input],
    output: path.join(alias, "mined"),
    provenance: "unknown",
    chunkBytes: 17 * 1024 * 1024,
    overlapBytes: 17 * 1024 * 1024,
    wholeFileBytes: 1024 * 1024,
  }), /output cannot be inside a scanned input/);
});

test("scanner rejects overlap settings that could lose a maximum-size streaming candidate", async () => {
  await assert.rejects(scanSensitiveMaterial({
    inputs: ["/synthetic-input-not-opened"],
    output: "/synthetic-output-not-created",
    provenance: "unknown",
    chunkBytes: 16 * 1024 * 1024,
    overlapBytes: 16 * 1024 * 1024,
    wholeFileBytes: 1024 * 1024,
  }), /17 MiB/);
});

test("scanner canonicalizes overlapping roots so each file is scanned once", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agetnic-overlap-test-"));
  const input = path.join(root, "recovered");
  const file = path.join(input, "single.txt");
  const output = path.join(root, "mined");
  await mkdir(input);
  await writeFile(file, "ordinary recovered data");
  const result = await scanSensitiveMaterial({
    inputs: [input, file, input],
    output,
    provenance: "unknown",
    chunkBytes: 17 * 1024 * 1024,
    overlapBytes: 17 * 1024 * 1024,
    wholeFileBytes: 1024 * 1024,
    minimumFreeGiB: 0,
    minimumFreePercent: 0,
  });
  assert.equal(result.filesScanned, 1);
  const inventory = JSON.parse(await readFile(path.join(output, "inventory-sensitive.json"), "utf8")) as SensitiveScanInventory;
  assert.deepEqual(inventory.inputRoots, [await realpath(input)]);
});

test("deep scan recovers an AES key whose expanded schedule crosses an internal slice boundary", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agetnic-deep-boundary-test-"));
  const input = path.join(root, "memory.raw");
  const output = path.join(root, "mined");
  const key = Buffer.from("000102030405060708090a0b0c0d0e0f", "hex");
  const schedule = expandAesKey(key);
  const expectedOffset = 1024 * 1024 - 100;
  await writeFile(input, Buffer.concat([Buffer.alloc(expectedOffset), schedule, Buffer.alloc(100)]));

  const result = await scanSensitiveMaterial({
    inputs: [input],
    output,
    provenance: "residual-memory",
    chunkBytes: 17 * 1024 * 1024,
    overlapBytes: 17 * 1024 * 1024,
    wholeFileBytes: 1,
    deepKeySchedules: true,
    minimumFreeGiB: 0,
    minimumFreePercent: 0,
  });
  assert.equal(result.status, "complete");
  const inventory = JSON.parse(await readFile(path.join(output, "inventory-sensitive.json"), "utf8")) as SensitiveScanInventory;
  const finding = inventory.findings.find((item) => item.category === "aes-encryption-key-from-expanded-schedule");
  assert.ok(finding);
  assert.deepEqual(finding.occurrences.map((occurrence) => occurrence.offset), [expectedOffset]);
  assert.ok((await artifactContents(output)).some((artifact) => artifact.equals(key)));
});

test("gracefully paused scans emit reports and resumable state", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agetnic-interrupt-test-"));
  const input = path.join(root, "recovered");
  const output = path.join(root, "mined");
  await mkdir(input);
  await writeFile(path.join(input, "file.bin"), randomBytes(64));
  const controller = new AbortController();
  controller.abort();
  const result = await scanSensitiveMaterial({
    inputs: [input],
    output,
    provenance: "unknown",
    chunkBytes: 17 * 1024 * 1024,
    overlapBytes: 17 * 1024 * 1024,
    wholeFileBytes: 1024 * 1024,
    minimumFreeGiB: 0,
    minimumFreePercent: 0,
    signal: controller.signal,
  });
  assert.equal(result.status, "paused");
  assert.equal(result.resumable, true);
  const inventory = JSON.parse(await readFile(path.join(output, "inventory-sensitive.json"), "utf8")) as SensitiveScanInventory;
  assert.equal(inventory.status, "paused");
  assert.equal(inventory.complete, false);
  assert.match(await readFile(path.join(output, "final-report-sensitive.md"), "utf8"), /Status: paused/);
  assert.match(await readFile(path.join(output, "final-report-redacted.md"), "utf8"), /Status: paused/);
  const pausedState = await readFile(path.join(output, "scan-state-sensitive.json"), "utf8");
  assert.match(pausedState, /"resumable": true/);
  assert.match(pausedState, /"inventoryComplete": false/);
  assert.match(await readFile(path.join(output, "final-report-sensitive.md"), "utf8"), /absence cannot be concluded/);
  await assert.rejects(access(path.join(output, ".aark-mining.lock")));
  await assert.rejects(access(path.join(output, ".agetnic-mining.lock")));
  await writeFile(path.join(output, ".agetnic-mining.lock"), "synthetic stale compatibility lock\n");
  await assert.rejects(resumeSensitiveMaterial({ output }), /exclusive operation lock/);
  unlinkSync(path.join(output, ".agetnic-mining.lock"));
  const resumed = await resumeSensitiveMaterial({ output });
  assert.equal(resumed.status, "complete");
  assert.equal(resumed.filesScanned, 1);
});

test("a pause during a file resumes from its committed chunk", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agetnic-mid-interrupt-test-"));
  const input = path.join(root, "recovered");
  const output = path.join(root, "mined");
  await mkdir(input);
  await writeFile(path.join(input, "large.bin"), Buffer.alloc(20 * 1024 * 1024));
  const controller = new AbortController();
  const result = await scanSensitiveMaterial({
    inputs: [input],
    output,
    provenance: "unknown",
    chunkBytes: 17 * 1024 * 1024,
    overlapBytes: 17 * 1024 * 1024,
    wholeFileBytes: 1024 * 1024,
    workers: 2,
    minimumFreeGiB: 0,
    minimumFreePercent: 0,
    signal: controller.signal,
    progress: (progress) => {
      if (progress.bytesScanned >= 1024 * 1024) controller.abort();
    },
  });
  assert.equal(result.status, "paused");
  const inventory = JSON.parse(await readFile(path.join(output, "inventory-sensitive.json"), "utf8")) as SensitiveScanInventory;
  assert.equal(inventory.status, "paused");
  assert.equal(inventory.complete, false);
  const manifestPath = path.join(output, "scan-files-sensitive.ndjson");
  const manifest = await readFile(manifestPath);
  await writeFile(manifestPath, Buffer.concat([manifest, Buffer.from("tampered\n")]));
  await assert.rejects(resumeSensitiveMaterial({ output }), /manifest/);
  await writeFile(manifestPath, manifest);
  const statePath = path.join(output, "scan-state-sensitive.json");
  const storedState = await readFile(statePath);
  const state = JSON.parse(storedState.toString("utf8")) as {
    cursor: { fileIndex: number; phase: string; nextOffset: number };
    progress: { phase?: string; bytesScanned: number; filesVisited: number };
  };
  state.cursor = { fileIndex: 0, phase: "stream", nextOffset: 0 };
  state.progress.phase = "stream";
  state.progress.bytesScanned = 0;
  state.progress.filesVisited = 1;
  await writeFile(statePath, `${JSON.stringify(state, null, 2)}\n`);
  await assert.rejects(resumeSensitiveMaterial({ output }), /checkpoint/);
  await writeFile(statePath, storedState);
  const resumed = await resumeSensitiveMaterial({ output });
  assert.equal(resumed.status, "complete");
  assert.equal(resumed.filesVisited, 1);
  assert.equal(resumed.filesScanned, 1);
  assert.equal(resumed.bytesScanned, 20 * 1024 * 1024);
});

test("a changing input produces complete-with-errors reports instead of a false clean result", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agetnic-changing-input-test-"));
  const input = path.join(root, "changing.bin");
  const output = path.join(root, "mined");
  await writeFile(input, Buffer.alloc(1024 * 1024, 0x41));
  let removed = false;
  const result = await scanSensitiveMaterial({
    inputs: [input],
    output,
    provenance: "unknown",
    chunkBytes: 17 * 1024 * 1024,
    overlapBytes: 17 * 1024 * 1024,
    wholeFileBytes: 2 * 1024 * 1024,
    minimumFreeGiB: 0,
    minimumFreePercent: 0,
    progress: () => {
      if (!removed) {
        removed = true;
        unlinkSync(input);
      }
    },
  });
  assert.equal(result.status, "complete-with-errors");
  assert.equal(result.filesVisited, 1);
  assert.equal(result.filesScanned, 0);
  assert.match(await readFile(path.join(output, "final-report-sensitive.md"), "utf8"), /Status: complete-with-errors/);
  assert.match(await readFile(path.join(output, "final-report-redacted.md"), "utf8"), /absence cannot be concluded/);
});

test("fatal scan-control errors still produce failed reports and release the output lock", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agetnic-control-error-test-"));
  const input = path.join(root, "input.bin");
  const output = path.join(root, "mined");
  await writeFile(input, Buffer.alloc(64, 0x41));
  await assert.rejects(scanSensitiveMaterial({
    inputs: [input],
    output,
    provenance: "unknown",
    chunkBytes: 17 * 1024 * 1024,
    overlapBytes: 17 * 1024 * 1024,
    wholeFileBytes: 1024 * 1024,
    minimumFreeGiB: 0,
    minimumFreePercent: 0,
    progress: () => {
      throw new Error("synthetic progress failure");
    },
  }), /progress callback failed/);
  assert.match(await readFile(path.join(output, "final-report-sensitive.md"), "utf8"), /Status: failed/);
  assert.match(await readFile(path.join(output, "final-report-redacted.md"), "utf8"), /Status: failed/);
  await assert.rejects(access(path.join(output, ".aark-mining.lock")));
  await assert.rejects(access(path.join(output, ".agetnic-mining.lock")));
});
