import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { StorageBudget, StorageQuotaError, storageCapacity, storagePolicyFromGiB } from "../core/storage.js";
import { isBoundedJsonValue, isSafeDetectorIdentifier, MAX_CANDIDATE_BYTES_PER_DETECTOR_JOB, MAX_CANDIDATES_PER_DETECTOR_JOB } from "../mining/limits.js";
import { appendCandidate } from "../mining/detectors/types.js";
import { DetectorWorkerPool } from "../mining/worker-pool.js";
import { expandAesKey } from "../mining/validators/aes.js";

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
