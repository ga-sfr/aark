import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import test from "node:test";
import { detectStructuredArtifacts } from "../mining/detectors/structured.js";
import { validateKdbx, validateOpenPgpSecretKeyring, validatePasswordSafeV3, validatePkcs12, validateSensitiveSqlite } from "../mining/validators/containers.js";

function u32(value: number): Buffer {
  const output = Buffer.alloc(4);
  output.writeUInt32LE(value);
  return output;
}

function kdbx4(): Buffer {
  const field = (id: number, value: Buffer): Buffer => Buffer.concat([Buffer.from([id]), u32(value.length), value]);
  const header = Buffer.concat([
    Buffer.from("03d9a29a67fb4bb5", "hex"),
    u32(0x00040000),
    field(2, randomBytes(16)),
    field(3, u32(1)),
    field(4, randomBytes(32)),
    field(7, randomBytes(16)),
    field(11, randomBytes(48)),
    field(0, Buffer.from("0d0a0d0a", "hex")),
  ]);
  return Buffer.concat([header, createHash("sha256").update(header).digest(), randomBytes(32), randomBytes(64)]);
}

test("KDBX4 header hash is verified and corruption is rejected", () => {
  const valid = kdbx4();
  const result = validateKdbx(valid);
  assert.equal(result?.category, "keepass-kdbx-database");
  assert.equal(result?.confidence, "authenticated");
  const corrupt = Buffer.from(valid);
  corrupt[20] = (corrupt[20] ?? 0) ^ 1;
  assert.equal(validateKdbx(corrupt), null);
});

test("Password Safe and sensitive SQLite validators require complete format markers", () => {
  const preamble = randomBytes(152);
  preamble.write("PWS3", 0, "ascii");
  preamble.writeUInt32LE(50_000, 36);
  const passwordSafe = Buffer.concat([preamble, randomBytes(32), Buffer.from("PWS3-EOFPWS3-EOF"), randomBytes(32)]);
  assert.equal(validatePasswordSafeV3(passwordSafe)?.category, "password-safe-v3-database");
  assert.equal(validatePasswordSafeV3(passwordSafe.subarray(0, -1)), null);

  const sqlite = Buffer.alloc(4096);
  sqlite.write("SQLite format 3\0", 0, "binary");
  sqlite.writeUInt16BE(4096, 16);
  sqlite[18] = 1;
  sqlite[19] = 1;
  sqlite[20] = 0;
  sqlite[21] = 64;
  sqlite[22] = 32;
  sqlite[23] = 32;
  sqlite.writeUInt32BE(4, 44);
  sqlite.writeUInt32BE(1, 56);
  sqlite[100] = 13;
  sqlite.write("origin_url username_value password_value signon_realm", 256, "ascii");
  assert.equal(validateSensitiveSqlite(sqlite)?.category, "chromium-login-database");
  const corruptSqlite = Buffer.from(sqlite);
  corruptSqlite[21] = 63;
  assert.equal(validateSensitiveSqlite(corruptSqlite), null);
});

test("whole-file DER private keys are parsed and exported without exposing them to logs", () => {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const der = Buffer.from(privateKey.export({ format: "der", type: "pkcs8" }));
  const results = detectStructuredArtifacts(der, { sourcePath: "local", baseOffset: 0, wholeFile: true });
  const candidate = results.find((item) => item.category === "der-private-key");
  assert.ok(candidate);
  assert.ok(candidate.value.equals(der));
  assert.equal(candidate.derivedArtifacts?.length, 2);
  assert.equal(detectStructuredArtifacts(Buffer.concat([der, Buffer.from([0])]), { sourcePath: "local", baseOffset: 0, wholeFile: true }).some((item) => item.category === "der-private-key"), false);
});

test("Docker and Bitwarden JSON validators require canonical, format-specific structures", () => {
  const context = { sourcePath: "local", baseOffset: 0, wholeFile: true };
  const dockerCredential = "user:password:with-colon";
  const docker = Buffer.from(JSON.stringify({ auths: { "registry.example": { auth: Buffer.from(dockerCredential).toString("base64") } } }));
  const dockerCandidate = detectStructuredArtifacts(docker, context).find((item) => item.category === "docker-registry-credentials");
  assert.ok(dockerCandidate);
  const decoded = dockerCandidate.derivedArtifacts?.find((item) => item.filename === "decoded-registry-credentials.json");
  assert.deepEqual(JSON.parse(decoded?.data.toString("utf8") ?? "null"), [{ registry: "registry.example", credential: dockerCredential }]);
  const canonicalAuth = Buffer.from("user:pa").toString("base64");
  const noncanonicalAuth = canonicalAuth.replace(/Q==$/, "R==");
  assert.ok(noncanonicalAuth !== canonicalAuth && Buffer.from(noncanonicalAuth, "base64").equals(Buffer.from("user:pa")));
  const noncanonical = Buffer.from(JSON.stringify({ auths: { "registry.example": { auth: noncanonicalAuth } } }));
  assert.equal(detectStructuredArtifacts(noncanonical, context).some((item) => item.category === "docker-registry-credentials"), false);

  const genericEncrypted = Buffer.from(JSON.stringify({ encrypted: true, data: "x".repeat(64) }));
  assert.equal(detectStructuredArtifacts(genericEncrypted, context).some((item) => item.category === "bitwarden-encrypted-export"), false);
  const bitwarden = Buffer.from(JSON.stringify({
    encrypted: true,
    passwordProtected: true,
    salt: "synthetic-salt",
    kdfType: 0,
    kdfIterations: 600_000,
    encKeyValidation_DO_NOT_EDIT: "synthetic-validation-value",
    data: "x".repeat(64),
  }));
  assert.equal(detectStructuredArtifacts(bitwarden, context).some((item) => item.category === "bitwarden-encrypted-export"), true);
});

function der(tag: number, value: Buffer): Buffer {
  assert.ok(value.length < 128);
  return Buffer.concat([Buffer.from([tag, value.length]), value]);
}

test("PKCS#12 and binary OpenPGP secret containers require complete outer structures", () => {
  const contentInfo = der(0x30, Buffer.concat([
    der(0x06, Buffer.from("2a864886f70d010701", "hex")),
    der(0xa0, der(0x04, randomBytes(24))),
  ]));
  const pfx = der(0x30, Buffer.concat([der(0x02, Buffer.from([3])), contentInfo]));
  assert.equal(validatePkcs12(pfx)?.category, "pkcs12-key-store");
  assert.equal(validatePkcs12(pfx.subarray(0, -1)), null);

  const secretPacketBody = Buffer.concat([Buffer.from([4]), randomBytes(19)]);
  const secretPacket = Buffer.concat([Buffer.from([0xc5, secretPacketBody.length]), secretPacketBody]);
  assert.equal(validateOpenPgpSecretKeyring(secretPacket)?.category, "openpgp-binary-secret-keyring");
  assert.equal(validateOpenPgpSecretKeyring(secretPacket.subarray(0, -1)), null);
});
