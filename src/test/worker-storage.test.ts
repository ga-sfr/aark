import assert from "node:assert/strict";
import { createECDH, generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { StorageBudget, StorageQuotaError, storageCapacity, storagePolicyFromGiB } from "../core/storage.js";
import { isBoundedJsonValue, isSafeDetectorIdentifier, MAX_CANDIDATE_BYTES_PER_DETECTOR_JOB, MAX_CANDIDATES_PER_DETECTOR_JOB, MAX_EXPENSIVE_CRYPTO_VALIDATIONS_PER_DETECTOR_JOB, MAX_STRUCTURAL_VALIDATIONS_PER_DETECTOR_JOB } from "../mining/limits.js";
import { appendCandidate } from "../mining/detectors/types.js";
import { DetectorWorkerPool } from "../mining/worker-pool.js";
import { expandAesKey } from "../mining/validators/aes.js";
import { dpapiMagic } from "../mining/validators/dpapi.js";

test("detector workers preserve candidate bytes and offsets across pool sizes", async () => {
  const { privateKey } = generateKeyPairSync("ed25519");
  const data = Buffer.from(privateKey.export({ type: "pkcs8", format: "pem" }));
  const run = async (workers: number): Promise<Array<{ detector: string; offsets: number[]; values: string[] }>> => {
    const pool = new DetectorWorkerPool(workers);
    try {
      const batches = await Promise.all([
        pool.run("cryptographic-keys", data, { sourcePath: "/synthetic", baseOffset: 123, wholeFile: false }),
        pool.run("configuration-secrets", data, { sourcePath: "/synthetic", baseOffset: 123, wholeFile: false }),
        pool.run("wallet-secrets", data, { sourcePath: "/synthetic", baseOffset: 123, wholeFile: false }),
        pool.run("provider-credentials", data, { sourcePath: "/synthetic", baseOffset: 123, wholeFile: false }),
      ]);
      return batches.flat().map((batch) => ({
        detector: batch.detector,
        offsets: batch.candidates.map((candidate) => candidate.offset),
        values: batch.candidates.map((candidate) => Buffer.from(candidate.value).toString("hex")),
      }));
    } finally {
      await pool.close();
    }
  };
  assert.deepEqual(await run(4), await run(1));
});

test("fused worker requests preserve detector order while copying each buffer once", async () => {
  const { privateKey } = generateKeyPairSync("ed25519");
  const data = Buffer.from(privateKey.export({ type: "pkcs8", format: "pem" }));
  const context = { sourcePath: "/synthetic", baseOffset: 123, wholeFile: false } as const;
  const pool = new DetectorWorkerPool(2);
  try {
    const fused = await pool.run("streaming", data, context);
    assert.deepEqual(fused.map((batch) => batch.detector), [
      "cryptographic-keys",
      "configuration-secrets",
      "wallet-secrets",
      "provider-credentials",
    ]);
    const metrics = pool.metrics();
    assert.equal(metrics.jobsSubmitted, 1);
    assert.equal(metrics.payloadCopies, 1);
    assert.equal(metrics.payloadBytesCopied, data.length);
  } finally {
    await pool.close();
  }
});

test("deep detector jobs recover schedules through worker serialization", async () => {
  const key = Buffer.from("000102030405060708090a0b0c0d0e0f", "hex");
  const data = Buffer.concat([Buffer.alloc(37), expandAesKey(key), Buffer.alloc(11)]);
  const pool = new DetectorWorkerPool(2);
  try {
    const [batch] = await pool.run("deep-key-schedules", data, { sourcePath: "/memory.raw", baseOffset: 1000, wholeFile: false, deepKeySchedules: true });
    const candidate = batch?.candidates.find((item) => item.category === "aes-encryption-key-from-expanded-schedule");
    assert.ok(candidate);
    assert.equal(candidate.offset, 1037);
    assert.deepEqual(Buffer.from(candidate.value), key);
  } finally {
    await pool.close();
  }
});

test("detector workers bound repetitive matches and retain the capped results", async () => {
  const key = Buffer.alloc(32, 0x5a).toString("base64");
  const data = Buffer.from(`${`PrivateKey = ${key}\n`.repeat(MAX_CANDIDATES_PER_DETECTOR_JOB + 1)}`, "ascii");
  const pool = new DetectorWorkerPool(2);
  try {
    const [batch] = await pool.run("configuration-secrets", data, { sourcePath: "/repetitive.conf", baseOffset: 0, wholeFile: false });
    assert.equal(batch?.candidates.length, MAX_CANDIDATES_PER_DETECTOR_JOB);
    assert.match(batch?.error ?? "", /candidate limit reached/);
    assert.equal(Buffer.from(batch?.candidates[0]?.value ?? []).toString("ascii"), key);
  } finally {
    await pool.close();
  }
});

test("detector workers bound repetitive malformed structural markers", async () => {
  const marker = ["-----BEGIN ", "PRIVATE", " KEY-----\n"].join("");
  const data = Buffer.from(marker.repeat(1_001), "ascii");
  const pool = new DetectorWorkerPool(1);
  try {
    const [batch] = await pool.run("cryptographic-keys", data, { sourcePath: "/malformed.raw", baseOffset: 0, wholeFile: false });
    assert.equal(batch?.candidates.length, 0);
    assert.match(batch?.error ?? "", /structural-validation limit reached/);
  } finally {
    await pool.close();
  }
});

test("exact DPAPI signatures do not exhaust the shared structural-validation budget", async () => {
  const data = Buffer.concat(Array.from(
    { length: MAX_STRUCTURAL_VALIDATIONS_PER_DETECTOR_JOB + 1 },
    () => dpapiMagic(),
  ));
  const pool = new DetectorWorkerPool(1);
  try {
    const [batch] = await pool.run("cryptographic-keys", data, { sourcePath: "/dpapi-signatures.raw", baseOffset: 0, wholeFile: false });
    assert.equal(batch?.candidates.length, 0);
    assert.equal(batch?.error, undefined);
  } finally {
    await pool.close();
  }
});

test("raw CNG magic strings do not consume the expensive crypto budget", async () => {
  const data = Buffer.concat(Array.from({ length: MAX_STRUCTURAL_VALIDATIONS_PER_DETECTOR_JOB + 1 }, () => (
    Buffer.concat([Buffer.from("RSA2", "ascii"), Buffer.alloc(24)])
  )));
  const pool = new DetectorWorkerPool(1);
  try {
    const [batch] = await pool.run("cryptographic-keys", data, { sourcePath: "/cng-signatures.raw", baseOffset: 0, wholeFile: false });
    assert.equal(batch?.candidates.length, 0);
    assert.equal(batch?.error, undefined);
  } finally {
    await pool.close();
  }
});

test("plausible CNG keys still enforce the original expensive crypto limit", async () => {
  const ecdh = createECDH("prime256v1");
  ecdh.generateKeys();
  const header = Buffer.alloc(8);
  header.write("ECS2", "ascii");
  header.writeUInt32LE(32, 4);
  const blob = Buffer.concat([header, ecdh.getPublicKey().subarray(1), ecdh.getPrivateKey()]);
  const data = Buffer.concat(Array.from({ length: MAX_EXPENSIVE_CRYPTO_VALIDATIONS_PER_DETECTOR_JOB + 1 }, () => blob));
  const pool = new DetectorWorkerPool(1);
  try {
    const [batch] = await pool.run("cryptographic-keys", data, { sourcePath: "/cng-budget.raw", baseOffset: 0, wholeFile: false });
    assert.equal(batch?.candidates.length, MAX_EXPENSIVE_CRYPTO_VALIDATIONS_PER_DETECTOR_JOB);
    assert.match(batch?.error ?? "", /structural-validation limit reached/);
  } finally { await pool.close(); }
});

test("JWT prefilter preserves objects with long leading JSON whitespace", async () => {
  const header = Buffer.from(" ".repeat(300) + JSON.stringify({ alg: "HS256" })).toString("base64url");
  const payload = Buffer.from("\t\r\n ".repeat(100) + JSON.stringify({ sub: "synthetic" })).toString("base64url");
  const data = Buffer.from(`${header}.${payload}.${Buffer.alloc(32, 0x73).toString("base64url")}`);
  const pool = new DetectorWorkerPool(1);
  try {
    const [batch] = await pool.run("provider-credentials", data, { sourcePath: "/jwt.raw", baseOffset: 0, wholeFile: false });
    assert.equal(batch?.error, undefined);
    assert.equal(batch?.candidates.filter((candidate) => candidate.category === "json-web-token").length, 1);
  } finally { await pool.close(); }
});

test("irrelevant assignment and JWT shapes do not exhaust provider validation", async () => {
  const repeated = MAX_STRUCTURAL_VALIDATIONS_PER_DETECTOR_JOB + 1;
  const data = Buffer.from([
    "ordinary_name=ordinary-value-12345\n".repeat(repeated),
    "AAAAAAAA.AAAAAAAA.AAAAAAAA\n".repeat(repeated),
  ].join(""), "ascii");
  const pool = new DetectorWorkerPool(1);
  try {
    const [batch] = await pool.run("provider-credentials", data, { sourcePath: "/provider-shapes.raw", baseOffset: 0, wholeFile: false });
    assert.equal(batch?.candidates.length, 0);
    assert.equal(batch?.error, undefined);
  } finally {
    await pool.close();
  }
});

test("detector result byte accounting rejects a candidate that would exceed the transfer bound", () => {
  const output: Parameters<typeof appendCandidate>[0] = [];
  const runtimeState = {
    candidateLimitReached: false,
    validationLimitReached: false,
    structuralValidations: 0,
    candidateBytes: MAX_CANDIDATE_BYTES_PER_DETECTOR_JOB - 1,
  };
  const accepted = appendCandidate(output, {
    category: "synthetic",
    offset: 0,
    length: 2,
    value: Buffer.alloc(2),
    confidence: "high",
    validation: { method: "synthetic", checks: {} },
    extension: ".bin",
  }, { sourcePath: "/synthetic", baseOffset: 0, wholeFile: false, runtimeState });
  assert.equal(accepted, false);
  assert.equal(runtimeState.candidateLimitReached, true);
  assert.equal(output.length, 0);
});

test("bounded detector metadata rejects typed arrays and oversized plain objects", () => {
  assert.equal(isBoundedJsonValue({ nested: [true, 1, "safe"] }), true);
  assert.equal(isBoundedJsonValue(Buffer.alloc(1024)), false);
  assert.equal(isBoundedJsonValue(Object.fromEntries(Array.from({ length: 129 }, (_, index) => [`k${index}`, index]))), false);
});

test("detector identifiers cannot corrupt report structure or deduplication keys", () => {
  assert.equal(isSafeDetectorIdentifier("windows-dpapi-blob"), true);
  assert.equal(isSafeDetectorIdentifier("validation.method-v2"), true);
  assert.equal(isSafeDetectorIdentifier("bad\0category"), false);
  assert.equal(isSafeDetectorIdentifier("bad\ncategory"), false);
  assert.equal(isSafeDetectorIdentifier("UPPERCASE"), false);
});

test("storage policy reserves the larger of five percent and five GiB and enforces replacement-aware caps", async () => {
  const policy = storagePolicyFromGiB(5, 5);
  const capacity = await storageCapacity(process.cwd(), policy);
  const fiveGiB = 5n * 1024n ** 3n;
  const fivePercent = (capacity.totalBytes * 500n + 9_999n) / 10_000n;
  assert.equal(capacity.reservedBytes, fiveGiB > fivePercent ? fiveGiB : fivePercent);

  const capped = new StorageBudget(process.cwd(), storagePolicyFromGiB(0, 0, 0.001), 500_000n);
  await assert.rejects(capped.beforeWrite(700_000n), (error: unknown) => error instanceof StorageQuotaError && error.reason === "output-cap");
  await capped.beforeWrite(400_000n, 300_000n);
  capped.committedWrite(400_000n, 300_000n);
  assert.equal(capped.outputBytes(), 600_000n);
});

test("storage policy accepts valid fixed-point decimals despite binary floating-point representation", () => {
  assert.doesNotThrow(() => storagePolicyFromGiB(1.001, 1.15, 2.003));
  assert.throws(() => storagePolicyFromGiB(1.0001, 1, 2), /three decimal places/);
  assert.throws(() => storagePolicyFromGiB(1, 1.001, 2), /two decimal places/);
});

test("closing a worker pool rejects active and queued work instead of leaving promises pending", async () => {
  const pool = new DetectorWorkerPool(1);
  const jobs = [
    pool.run("cryptographic-keys", Buffer.alloc(1024), { sourcePath: "/synthetic", baseOffset: 0, wholeFile: false }),
    pool.run("configuration-secrets", Buffer.alloc(1024), { sourcePath: "/synthetic", baseOffset: 0, wholeFile: false }),
  ];
  const outcomesPromise = Promise.allSettled(jobs);
  const close = pool.close(true);
  const repeatedClose = pool.close(true);
  assert.equal(repeatedClose, close);
  await close;
  const outcomes = await outcomesPromise;
  assert.deepEqual(outcomes.map((outcome) => outcome.status), ["rejected", "rejected"]);
});
