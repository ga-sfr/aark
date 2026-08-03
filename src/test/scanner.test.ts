import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { renameSync, unlinkSync } from "node:fs";
import { access, mkdir, mkdtemp, readFile, readdir, realpath, stat, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { entropyToMnemonic } from "@scure/bip39";
import { wordlist as english } from "@scure/bip39/wordlists/english.js";
import { sha256Hex } from "../core/crypto.js";
import { ArtifactStore } from "../mining/artifacts.js";
import { resumeSensitiveMaterial, scanSensitiveMaterial } from "../mining/scanner.js";
import type { MiningPerformance, SensitiveScanInventory } from "../mining/types.js";
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

async function artifactHashes(output: string): Promise<Record<string, string>> {
  const hashes: Record<string, string> = {};
  const root = path.join(output, "artifacts");
  for (const directory of (await readdir(root)).sort()) {
    for (const filename of (await readdir(path.join(root, directory))).sort()) {
      const relative = path.join(directory, filename);
      hashes[relative] = sha256Hex(await readFile(path.join(root, relative)));
    }
  }
  return hashes;
}

function normalizedReport(report: string, output: string): string {
  return report
    .replaceAll(output, "<OUTPUT>")
    .replace(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z/g, "<TIMESTAMP>");
}

function syntheticEncryptedPem(decodedBytes: number): Buffer {
  const decoded = Buffer.alloc(decodedBytes, 0x5a);
  return Buffer.from([
    ["-----BEGIN RSA ", "PRIVATE", " KEY-----"].join(""),
    "Proc-Type: 4,ENCRYPTED",
    `DEK-Info: AES-256-CBC,${"00".repeat(16)}`,
    "",
    decoded.toString("base64"),
    ["-----END RSA ", "PRIVATE", " KEY-----"].join(""),
    "",
  ].join("\n"), "ascii");
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

test("artifact metrics cannot change an already durable publication outcome", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-artifact-metrics-test-"));
  const output = path.join(root, "mined");
  const store = new ArtifactStore(output, [root], false, undefined, undefined, {
    artifactPublished: () => { throw new Error("synthetic observer failure"); },
  });
  await store.initialize();
  const value = randomBytes(32);
  await store.add(path.join(root, "source.bin"), "unknown", {
    category: "synthetic-test-secret",
    offset: 0,
    length: value.length,
    value,
    confidence: "high",
    validation: { method: "synthetic", checks: { exact: true } },
    extension: ".key",
  });
  assert.ok((await artifactContents(output)).some((artifact) => artifact.equals(value)));
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

test("small-file scheduling is deterministic across workers and keeps aggregate work bounded", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-small-pipeline-test-"));
  const input = path.join(root, "recovered");
  await mkdir(input);
  const providerToken = `ghp_${randomAlphanumeric(36)}`;
  const fileCount = 32;
  for (let index = 0; index < fileCount; index += 1) {
    const contents = index % 8 === 0
      ? `ordinary synthetic data\n${providerToken}\n`
      : `ordinary synthetic data ${index}\n`;
    await writeFile(path.join(input, `${String(index).padStart(3, "0")}.txt`), contents);
  }

  let baseline: {
    findings: SensitiveScanInventory["findings"];
    sensitiveReport: string;
    redactedReport: string;
    artifacts: Record<string, string>;
  } | undefined;
  for (const workers of [1, 2, 3, 4]) {
    const output = path.join(root, `mined-${workers}`);
    const result = await scanSensitiveMaterial({
      inputs: [input],
      output,
      provenance: "unallocated-carve",
      chunkBytes: 17 * 1024 * 1024,
      overlapBytes: 17 * 1024 * 1024,
      wholeFileBytes: 1024 * 1024,
      workers,
      minimumFreeGiB: 0,
      minimumFreePercent: 0,
    });
    assert.equal(result.status, "complete");
    const performanceResult = result.performance as MiningPerformance;
    assert.equal(performanceResult.workerJobs, fileCount);
    assert.equal(performanceResult.workerPayloadCopies, fileCount);
    assert.equal(performanceResult.readCalls, fileCount);
    assert.equal(performanceResult.completeFileBuffersReused, fileCount);
    assert.equal(performanceResult.checkpoints, 1);
    assert.ok(performanceResult.rootValidationCalls < fileCount);
    assert.equal(performanceResult.maximumOutstandingFiles, workers);
    assert.ok(performanceResult.maximumOutstandingFileBytes <= 64 * 1024 * 1024);

    const inventory = JSON.parse(await readFile(path.join(output, "inventory-sensitive.json"), "utf8")) as SensitiveScanInventory;
    const comparison = {
      findings: inventory.findings,
      sensitiveReport: normalizedReport(await readFile(path.join(output, "final-report-sensitive.md"), "utf8"), output),
      redactedReport: normalizedReport(await readFile(path.join(output, "final-report-redacted.md"), "utf8"), output),
      artifacts: await artifactHashes(output),
    };
    if (baseline === undefined) baseline = comparison;
    else assert.deepEqual(comparison, baseline);
  }
});

test("a signal during an ordered small-file batch pauses before uncommitted files and resumes exactly", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-small-pause-test-"));
  const input = path.join(root, "recovered");
  const output = path.join(root, "mined");
  await mkdir(input);
  await writeFile(path.join(input, "000-small.txt"), "ordinary synthetic data\n");
  for (let index = 1; index < 4; index += 1) {
    await writeFile(path.join(input, `${String(index).padStart(3, "0")}-buffered.bin`), Buffer.alloc(2 * 1024 * 1024, 0x41 + index));
  }
  const controller = new AbortController();
  const paused = await scanSensitiveMaterial({
    inputs: [input],
    output,
    provenance: "unknown",
    chunkBytes: 17 * 1024 * 1024,
    overlapBytes: 17 * 1024 * 1024,
    wholeFileBytes: 17 * 1024 * 1024,
    workers: 4,
    minimumFreeGiB: 0,
    minimumFreePercent: 0,
    signal: controller.signal,
    progress: (progress) => {
      if (progress.phase === "stream" && progress.filesVisited === 1) controller.abort();
    },
  });
  assert.equal(paused.status, "paused");
  assert.equal(paused.filesVisited, 1);
  assert.equal(paused.filesScanned, 0);
  assert.equal((paused.performance as MiningPerformance).maximumOutstandingFiles, 4);

  const resumed = await resumeSensitiveMaterial({ output, workers: 4 });
  assert.equal(resumed.status, "complete");
  assert.equal(resumed.filesVisited, 4);
  assert.equal(resumed.filesScanned, 4);
  assert.equal(resumed.bytesScanned, 6 * 1024 * 1024 + Buffer.byteLength("ordinary synthetic data\n"));
});

test("an output cap cancels an in-flight small-file batch and resumes after an operational override", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-small-quota-test-"));
  const input = path.join(root, "recovered");
  const output = path.join(root, "mined");
  await mkdir(input);
  await writeFile(path.join(input, "000-encrypted.pem"), syntheticEncryptedPem(900 * 1024));
  for (let index = 1; index < 4; index += 1) {
    await writeFile(path.join(input, `${String(index).padStart(3, "0")}-buffered.bin`), Buffer.alloc(2 * 1024 * 1024, 0x41 + index));
  }
  const paused = await scanSensitiveMaterial({
    inputs: [input],
    output,
    provenance: "unknown",
    chunkBytes: 17 * 1024 * 1024,
    overlapBytes: 17 * 1024 * 1024,
    wholeFileBytes: 17 * 1024 * 1024,
    workers: 4,
    minimumFreeGiB: 0,
    minimumFreePercent: 0,
    maximumOutputGiB: 0.001,
  });
  assert.equal(paused.status, "paused");
  assert.equal(paused.pauseReason, "output-cap");
  assert.equal(paused.filesVisited, 1);
  assert.equal(paused.filesScanned, 0);
  assert.equal((paused.performance as MiningPerformance).maximumOutstandingFiles, 4);

  const resumed = await resumeSensitiveMaterial({ output, workers: 4, maximumOutputGiB: 0.01 });
  assert.equal(resumed.status, "complete");
  assert.equal(resumed.filesVisited, 4);
  assert.equal(resumed.filesScanned, 4);
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

test("a signal concurrent with an explicit input-root change is not mislabeled resumable", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-changing-root-signal-test-"));
  const input = path.join(root, "changing.bin");
  const output = path.join(root, "mined");
  await writeFile(input, Buffer.alloc(1024, 0x41));
  const controller = new AbortController();
  let changed = false;
  await assert.rejects(scanSensitiveMaterial({
    inputs: [input],
    output,
    provenance: "unknown",
    chunkBytes: 17 * 1024 * 1024,
    overlapBytes: 17 * 1024 * 1024,
    wholeFileBytes: 1024 * 1024,
    minimumFreeGiB: 0,
    minimumFreePercent: 0,
    signal: controller.signal,
    progress: (progress) => {
      if (!changed && progress.phase === "stream" && progress.bytesScanned === 1024) {
        changed = true;
        unlinkSync(input);
        controller.abort();
      }
    },
  }), /scan input changed|explicit file input root changed/);
  assert.equal(changed, true);
  const state = JSON.parse(await readFile(path.join(output, "scan-state-sensitive.json"), "utf8")) as {
    status: string;
    resumable: boolean;
  };
  assert.equal(state.status, "failed");
  assert.equal(state.resumable, false);
});

test("a signal concurrent with a completed child-file change is not mislabeled resumable", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-changing-child-signal-test-"));
  const input = path.join(root, "recovered");
  const file = path.join(input, "changing.bin");
  const output = path.join(root, "mined");
  await mkdir(input);
  await writeFile(file, Buffer.alloc(1024, 0x41));
  const controller = new AbortController();
  let changed = false;
  await assert.rejects(scanSensitiveMaterial({
    inputs: [input],
    output,
    provenance: "unknown",
    chunkBytes: 17 * 1024 * 1024,
    overlapBytes: 17 * 1024 * 1024,
    wholeFileBytes: 1024 * 1024,
    minimumFreeGiB: 0,
    minimumFreePercent: 0,
    signal: controller.signal,
    progress: (progress) => {
      if (!changed && progress.phase === "stream" && progress.bytesScanned === 1024) {
        changed = true;
        unlinkSync(file);
        controller.abort();
      }
    },
  }), /scan input changed|completed or partial resume input is no longer stably addressable/);
  assert.equal(changed, true);
  const state = JSON.parse(await readFile(path.join(output, "scan-state-sensitive.json"), "utf8")) as {
    status: string;
    resumable: boolean;
  };
  assert.equal(state.status, "failed");
  assert.equal(state.resumable, false);
});

test("a signal concurrent with an inventory root change is not mislabeled resumable", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aark-changing-inventory-root-test-"));
  const input = path.join(root, "recovered");
  const moved = path.join(root, "recovered-moved");
  const output = path.join(root, "mined");
  await mkdir(input);
  for (let index = 0; index < 1_000; index += 1) {
    await writeFile(path.join(input, `${String(index).padStart(4, "0")}.bin`), "synthetic\n");
  }
  const controller = new AbortController();
  let changed = false;
  await assert.rejects(scanSensitiveMaterial({
    inputs: [input],
    output,
    provenance: "unknown",
    chunkBytes: 17 * 1024 * 1024,
    overlapBytes: 17 * 1024 * 1024,
    wholeFileBytes: 1024 * 1024,
    minimumFreeGiB: 0,
    minimumFreePercent: 0,
    signal: controller.signal,
    progress: (progress) => {
      if (!changed && progress.phase === "inventory" && progress.filesTotal === 1_000) {
        changed = true;
        renameSync(input, moved);
        controller.abort();
      }
    },
  }), /directory input root or its mount changed/);
  assert.equal(changed, true);
  const state = JSON.parse(await readFile(path.join(output, "scan-state-sensitive.json"), "utf8")) as {
    status: string;
    resumable: boolean;
  };
  assert.equal(state.status, "failed");
  assert.equal(state.resumable, false);
});

test("a changed directory input remains a fatal scan-control error", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agetnic-changing-directory-test-"));
  const input = path.join(root, "recovered");
  const moved = path.join(root, "recovered-moved");
  const output = path.join(root, "mined");
  await mkdir(input);
  await writeFile(path.join(input, "file.bin"), Buffer.alloc(64, 0x41));
  let renamed = false;
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
      if (!renamed) {
        renamed = true;
        renameSync(input, moved);
      }
    },
  }), /directory input root or its mount changed/);
  assert.equal(renamed, true);
  assert.match(await readFile(path.join(output, "final-report-sensitive.md"), "utf8"), /Status: failed/);
  assert.match(await readFile(path.join(output, "final-report-redacted.md"), "utf8"), /Status: failed/);
  await assert.rejects(access(path.join(output, ".aark-mining.lock")));
  await assert.rejects(access(path.join(output, ".agetnic-mining.lock")));
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
