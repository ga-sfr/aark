import assert from "node:assert/strict";
import { createECDH, generateKeyPairSync, randomBytes } from "node:crypto";
import test from "node:test";
import { entropyToMnemonic } from "@scure/bip39";
import { wordlist as english } from "@scure/bip39/wordlists/english.js";
import { validExtendedPrivateKey, validWif } from "../mining/validators/base58.js";
import { expandAesKey, findAesEncryptionSchedules, findChaChaStates } from "../mining/validators/aes.js";
import { validateAgeSecretKey } from "../mining/validators/bech32.js";
import { findBip39Mnemonics } from "../mining/validators/bip39.js";
import { parseCngPrivateBlob } from "../mining/validators/cng.js";
import { decodeChromiumDpapiWrapper, parseDpapiBlob, parseDpapiMasterKeyFile } from "../mining/validators/dpapi.js";
import { findPgpPrivateBlocks, findPrivateKeyBlocks, findPuttyPrivateKeys, findSsh2PrivateBlocks } from "../mining/validators/pem.js";
import { validStellarSecretSeed, validTezosSecretKey, validXrpFamilySeed } from "../mining/validators/wallet-formats.js";
import { ageSecretKey, base32Encode, BITCOIN_ALPHABET, crc16Xmodem, encodeBase58Check, RIPPLE_ALPHABET } from "./helpers.js";

function u32(value: number): Buffer {
  const output = Buffer.alloc(4);
  output.writeUInt32LE(value);
  return output;
}

function dpapiFixture(): Buffer {
  const variable = (value: Buffer): Buffer => Buffer.concat([u32(value.length), value]);
  return Buffer.concat([
    Buffer.from("01000000d08c9ddf0115d1118c7a00c04fc297eb", "hex"),
    u32(1), randomBytes(16), u32(0),
    variable(Buffer.from("test", "utf16le")),
    u32(0x6610), u32(256),
    variable(randomBytes(16)), variable(randomBytes(20)),
    u32(0x800e), u32(512),
    variable(randomBytes(20)), variable(randomBytes(32)), variable(randomBytes(64)),
  ]);
}

function dpapiMasterKeyFixture(): Buffer {
  const section = Buffer.concat([u32(2), randomBytes(16), u32(10_000), u32(0x800e), u32(0x6610), randomBytes(96)]);
  const header = Buffer.alloc(128);
  header.writeUInt32LE(2, 0);
  header.write("12345678-1234-1234-1234-123456789abc", 12, "utf16le");
  header.writeBigUInt64LE(BigInt(section.length), 96);
  return Buffer.concat([header, section]);
}

test("Base58Check wallet validators reject corruption and accept generated payloads", () => {
  const scalar = Buffer.concat([Buffer.alloc(31), Buffer.from([7])]);
  const wif = encodeBase58Check(Buffer.concat([Buffer.from([0x80]), scalar, Buffer.from([1])]), BITCOIN_ALPHABET);
  assert.deepEqual(validWif(wif), { network: "mainnet", compressed: true });
  assert.equal(validWif(`${wif.slice(0, -1)}${wif.endsWith("1") ? "2" : "1"}`), null);

  const extended = Buffer.concat([
    Buffer.from("0488ade4", "hex"), Buffer.from([3]), randomBytes(4), u32(9).reverse(), randomBytes(32), Buffer.from([0]), scalar,
  ]);
  const xprv = encodeBase58Check(extended);
  assert.equal(xprv.length, 111);
  assert.deepEqual(validExtendedPrivateKey(xprv), { network: "mainnet", format: "xprv", depth: 3 });
});

test("BIP39 scanner validates checksums and preserves exact local whitespace", () => {
  const mnemonic = entropyToMnemonic(randomBytes(16), english);
  const embedded = mnemonic.replace(/ /g, "\n");
  const data = Buffer.from(`prefix:${embedded}:suffix`, "utf8");
  const hits = findBip39Mnemonics(data);
  assert.equal(hits.length, 1);
  assert.equal(hits[0]?.value.toString("utf8"), embedded);
  assert.equal(hits[0]?.language, "english");
  assert.equal(hits[0]?.words, 12);
});

test("PEM, DPAPI, CNG, and age validators require complete structures", () => {
  const { privateKey } = generateKeyPairSync("ed25519");
  const pem = Buffer.from(privateKey.export({ format: "pem", type: "pkcs8" }));
  assert.equal(findPrivateKeyBlocks(pem).length, 1);
  assert.equal(findPrivateKeyBlocks(pem.subarray(0, -20)).length, 0);

  const dpapi = dpapiFixture();
  assert.ok(parseDpapiBlob(dpapi)?.equals(dpapi));
  assert.equal(parseDpapiBlob(dpapi.subarray(0, -1)), null);
  const wrapper = Buffer.concat([Buffer.from("DPAPI"), dpapi]).toString("base64");
  assert.ok(decodeChromiumDpapiWrapper(wrapper)?.equals(dpapi));
  const masterKey = dpapiMasterKeyFixture();
  assert.equal(parseDpapiMasterKeyFile(masterKey)?.guid, "12345678-1234-1234-1234-123456789abc");
  assert.equal(parseDpapiMasterKeyFile(masterKey.subarray(0, -1)), null);

  const ecdh = createECDH("prime256v1");
  ecdh.generateKeys();
  const point = ecdh.getPublicKey(undefined, "uncompressed");
  const ecc = Buffer.concat([Buffer.from("ECS2"), u32(32), point.subarray(1, 33), point.subarray(33), ecdh.getPrivateKey()]);
  const parsed = parseCngPrivateBlob(ecc);
  assert.equal(parsed?.category, "cng-ecc-private-key");
  assert.equal(parsed?.confidence, "authenticated");
  assert.ok(parsed?.primary.equals(ecc));
  const symmetric = Buffer.concat([Buffer.from("KDBM"), u32(1), u32(32), randomBytes(32)]);
  assert.equal(parseCngPrivateBlob(symmetric)?.confidence, "high");

  const age = ageSecretKey(randomBytes(32));
  assert.equal(age.length, 74);
  assert.equal(validateAgeSecretKey(age), true);
  assert.equal(validateAgeSecretKey(`${age.slice(0, -1)}${age.endsWith("Q") ? "P" : "Q"}`), false);
});

test("malformed CNG RSA arithmetic is rejected without escaping the validator", () => {
  const malformed = Buffer.alloc(24 + 1 + 64 + 31 + 31);
  malformed.write("RSA2", 0, "ascii");
  malformed.writeUInt32LE(512, 4);
  malformed.writeUInt32LE(1, 8);
  malformed.writeUInt32LE(64, 12);
  malformed.writeUInt32LE(31, 16);
  malformed.writeUInt32LE(31, 20);
  malformed[24] = 3;
  malformed[24 + 1 + 64 - 1] = 91;
  malformed[24 + 1 + 64 + 31 - 1] = 7;
  malformed[malformed.length - 1] = 13;
  assert.equal(parseCngPrivateBlob(malformed), null);

  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 1024, publicExponent: 65_537 });
  const jwk = privateKey.export({ format: "jwk" });
  assert.equal(typeof jwk.e, "string");
  assert.equal(typeof jwk.n, "string");
  assert.equal(typeof jwk.p, "string");
  assert.equal(typeof jwk.q, "string");
  const exponent = Buffer.from(jwk.e ?? "", "base64url");
  const modulus = Buffer.from(jwk.n ?? "", "base64url");
  const prime1 = Buffer.from(jwk.p ?? "", "base64url");
  const prime2 = Buffer.from(jwk.q ?? "", "base64url");
  const header = Buffer.alloc(24);
  header.write("RSA2", 0, "ascii");
  header.writeUInt32LE(modulus.length * 8, 4);
  header.writeUInt32LE(exponent.length, 8);
  header.writeUInt32LE(modulus.length, 12);
  header.writeUInt32LE(prime1.length, 16);
  header.writeUInt32LE(prime2.length, 20);
  const valid = parseCngPrivateBlob(Buffer.concat([header, exponent, modulus, prime1, prime2]));
  assert.equal(valid?.category, "cng-rsa-private-key");
  assert.equal(valid?.confidence, "authenticated");
  assert.equal(valid?.checks.probablePrimeFactors, true);
});

test("armored OpenPGP and PuTTY validators require complete internal structures", () => {
  const secretPacketBody = Buffer.concat([Buffer.from([4]), randomBytes(19)]);
  const secretPacket = Buffer.concat([Buffer.from([0xc5, secretPacketBody.length]), secretPacketBody]);
  const pgp = Buffer.from([
    ["-----BEGIN PGP ", "PRIVATE KEY BLOCK-----"].join(""),
    "",
    secretPacket.toString("base64"),
    "-----END PGP PRIVATE KEY BLOCK-----",
  ].join("\n"), "ascii");
  assert.equal(findPgpPrivateBlocks(pgp).length, 1);
  const fakePgp = Buffer.from(pgp.toString("ascii").replace(secretPacket.toString("base64"), randomBytes(secretPacket.length).toString("base64")), "ascii");
  assert.equal(findPgpPrivateBlocks(fakePgp).length, 0);

  const algorithm = Buffer.from("ssh-ed25519", "ascii");
  const length = Buffer.alloc(4);
  length.writeUInt32BE(algorithm.length);
  const publicBlob = Buffer.concat([length, algorithm, randomBytes(36)]);
  const putty = Buffer.from([
    "PuTTY-User-Key-File-2: ssh-ed25519",
    "Encryption: none",
    "Comment: recovered",
    "Public-Lines: 1",
    publicBlob.toString("base64"),
    "Private-Lines: 1",
    randomBytes(32).toString("base64"),
    `Private-MAC: ${randomBytes(20).toString("hex")}`,
  ].join("\n"), "ascii");
  assert.equal(findPuttyPrivateKeys(putty).length, 1);
  assert.equal(findPuttyPrivateKeys(Buffer.from(putty.toString("ascii").replace("Public-Lines: 1", "Public-Lines: 2"), "ascii")).length, 0);
});

test("encrypted PEM, OpenSSH, and SSH2 armor requires valid internal framing", () => {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const encryptedPem = Buffer.from(privateKey.export({
    format: "pem",
    type: "pkcs8",
    cipher: "aes-256-cbc",
    passphrase: "synthetic-test-passphrase",
  }));
  assert.equal(findPrivateKeyBlocks(encryptedPem).length, 1);
  const fakeEncryptedPem = Buffer.from([
    ["-----BEGIN ENCRYPTED ", "PRIVATE KEY-----"].join(""),
    randomBytes(96).toString("base64"),
    "-----END ENCRYPTED PRIVATE KEY-----",
  ].join("\n"), "ascii");
  assert.equal(findPrivateKeyBlocks(fakeEncryptedPem).length, 0);

  const sshString = (value: Buffer): Buffer => {
    const length = Buffer.alloc(4);
    length.writeUInt32BE(value.length);
    return Buffer.concat([length, value]);
  };
  const check = Buffer.alloc(8);
  check.writeUInt32BE(0x12345678, 0);
  check.writeUInt32BE(0x12345678, 4);
  const openSsh = Buffer.concat([
    Buffer.from("openssh-key-v1\0", "binary"),
    sshString(Buffer.from("none")),
    sshString(Buffer.from("none")),
    sshString(Buffer.alloc(0)),
    Buffer.from([0, 0, 0, 1]),
    sshString(Buffer.concat([Buffer.from([0, 0, 0, 3]), Buffer.from("key"), Buffer.from([0])])),
    sshString(Buffer.concat([check, randomBytes(8)])),
  ]);
  const openSshArmor = Buffer.from([
    ["-----BEGIN OPENSSH ", "PRIVATE KEY-----"].join(""),
    openSsh.toString("base64"),
    "-----END OPENSSH PRIVATE KEY-----",
  ].join("\n"), "ascii");
  assert.equal(findPrivateKeyBlocks(openSshArmor).length, 1);

  const ssh2Payload = Buffer.concat([Buffer.from("3f6ff9eb", "hex"), randomBytes(28)]);
  const ssh2Armor = Buffer.from([
    "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----",
    ssh2Payload.toString("base64"),
    "---- END SSH2 ENCRYPTED PRIVATE KEY ----",
  ].join("\n"), "ascii");
  assert.equal(findSsh2PrivateBlocks(ssh2Armor).length, 1);
  const fakeSsh2 = Buffer.from(ssh2Armor.toString("ascii").replace(ssh2Payload.toString("base64"), randomBytes(32).toString("base64")), "ascii");
  assert.equal(findSsh2PrivateBlocks(fakeSsh2).length, 0);
});

test("Stellar, XRP, and Tezos private formats validate checksums without network access", () => {
  const stellarBody = Buffer.concat([Buffer.from([18 << 3]), randomBytes(32)]);
  const checksum = Buffer.alloc(2);
  checksum.writeUInt16LE(crc16Xmodem(stellarBody));
  const stellar = base32Encode(Buffer.concat([stellarBody, checksum]));
  assert.equal(validStellarSecretSeed(stellar), true);

  const xrp = encodeBase58Check(Buffer.concat([Buffer.from([0x21]), randomBytes(16)]), RIPPLE_ALPHABET);
  assert.equal(validXrpFamilySeed(xrp), true);

  const tezos = encodeBase58Check(Buffer.concat([Buffer.from("0d0f3a07", "hex"), randomBytes(32)]));
  assert.deepEqual(validTezosSecretKey(tezos), { format: "ed25519-seed" });
});

test("deep AES schedule scan recovers only keys with a complete expansion recurrence", () => {
  for (const bytes of [16, 24, 32]) {
    const key = randomBytes(bytes);
    const schedule = expandAesKey(key);
    const embedded = Buffer.concat([randomBytes(37), schedule, randomBytes(29)]);
    const hits = findAesEncryptionSchedules(embedded).filter((hit) => hit.offset === 37);
    assert.equal(hits.length, 1);
    assert.ok(hits[0]?.key.equals(key));
    const corrupt = Buffer.from(embedded);
    corrupt[37 + schedule.length - 1] = (corrupt[37 + schedule.length - 1] ?? 0) ^ 1;
    assert.equal(findAesEncryptionSchedules(corrupt).some((hit) => hit.offset === 37 && hit.key.length === bytes), false);
  }
});

test("deep memory scan recognizes initialized ChaCha states and extracts their exact key bytes", () => {
  const key = randomBytes(32);
  const state = Buffer.concat([Buffer.from("expand 32-byte k"), key, randomBytes(16)]);
  const embedded = Buffer.concat([randomBytes(13), state, randomBytes(11)]);
  const hit = findChaChaStates(embedded)[0];
  assert.equal(hit?.offset, 29);
  assert.ok(hit?.key.equals(key));
  assert.ok(hit?.state.equals(state));
});
