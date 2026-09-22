import { checkPrimeSync, createECDH, createPrivateKey, createPublicKey } from "node:crypto";
import { base64Url } from "../../core/crypto.js";

export interface CngValidation {
  category: "cng-rsa-private-key" | "cng-ecc-private-key" | "cng-symmetric-key";
  bytes: number;
  primary: Buffer;
  extension: string;
  derived: Array<{ filename: string; data: Buffer }>;
  confidence: "high" | "authenticated";
  checks: Record<string, string | number | boolean>;
}

const ECC = new Map<string, { bytes: number; curve: string; jwkCurve: "P-256" | "P-384" | "P-521"; purpose: string }>([
  ["ECS2", { bytes: 32, curve: "prime256v1", jwkCurve: "P-256", purpose: "ECDSA" }],
  ["ECS4", { bytes: 48, curve: "secp384r1", jwkCurve: "P-384", purpose: "ECDSA" }],
  ["ECS6", { bytes: 66, curve: "secp521r1", jwkCurve: "P-521", purpose: "ECDSA" }],
  ["ECK2", { bytes: 32, curve: "prime256v1", jwkCurve: "P-256", purpose: "ECDH" }],
  ["ECK4", { bytes: 48, curve: "secp384r1", jwkCurve: "P-384", purpose: "ECDH" }],
  ["ECK6", { bytes: 66, curve: "secp521r1", jwkCurve: "P-521", purpose: "ECDH" }],
]);

function integer(value: Buffer): bigint {
  return value.length === 0 ? 0n : BigInt(`0x${value.toString("hex")}`);
}

function bigIntBuffer(value: bigint, bytes: number): Buffer {
  let hex = value.toString(16);
  if (hex.length % 2 !== 0) hex = `0${hex}`;
  const raw = Buffer.from(hex, "hex");
  if (raw.length > bytes) throw new Error("integer does not fit expected width");
  return Buffer.concat([Buffer.alloc(bytes - raw.length), raw]);
}

function gcd(left: bigint, right: bigint): bigint {
  let a = left;
  let b = right;
  while (b !== 0n) [a, b] = [b, a % b];
  return a;
}

function lcm(left: bigint, right: bigint): bigint {
  return (left / gcd(left, right)) * right;
}

function modInverse(value: bigint, modulus: bigint): bigint {
  let [oldR, r] = [value, modulus];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const quotient = oldR / r;
    [oldR, r] = [r, oldR - quotient * r];
    [oldS, s] = [s, oldS - quotient * s];
  }
  if (oldR !== 1n) throw new Error("RSA exponent has no modular inverse");
  return (oldS % modulus + modulus) % modulus;
}

function rsa(data: Buffer, offset: number, beforeCrypto: () => boolean): CngValidation | null {
  if (offset + 24 > data.length) return null;
  const magic = data.toString("ascii", offset, offset + 4);
  if (magic !== "RSA2" && magic !== "RSA3") return null;
  const bitLength = data.readUInt32LE(offset + 4);
  const exponentBytes = data.readUInt32LE(offset + 8);
  const modulusBytes = data.readUInt32LE(offset + 12);
  const pBytes = data.readUInt32LE(offset + 16);
  const qBytes = data.readUInt32LE(offset + 20);
  const shortBytes = 24 + exponentBytes + modulusBytes + pBytes + qBytes;
  const total = magic === "RSA3" ? shortBytes + pBytes + qBytes + pBytes + modulusBytes : shortBytes;
  if (
    bitLength < 512
    || bitLength > 16_384
    || exponentBytes < 1
    || exponentBytes > 8
    || modulusBytes !== Math.ceil(bitLength / 8)
    || pBytes < Math.floor(modulusBytes / 2) - 1
    || qBytes < Math.floor(modulusBytes / 2) - 1
    || pBytes > modulusBytes
    || qBytes > modulusBytes
    || total > data.length - offset
  ) return null;
  let cursor = offset + 24;
  const eBytes = data.subarray(cursor, cursor += exponentBytes);
  const nBytes = data.subarray(cursor, cursor += modulusBytes);
  const prime1Bytes = data.subarray(cursor, cursor += pBytes);
  const prime2Bytes = data.subarray(cursor, cursor += qBytes);
  const e = integer(eBytes);
  const n = integer(nBytes);
  const p = integer(prime1Bytes);
  const q = integer(prime2Bytes);
  if (
    p <= 1n
    || q <= 1n
    || p * q !== n
    || n.toString(2).length !== bitLength
    || e < 3n
    || e % 2n === 0n
  ) return null;
  try {
    if (!beforeCrypto()) return null;
    if (!checkPrimeSync(prime1Bytes, { checks: 32 }) || !checkPrimeSync(prime2Bytes, { checks: 32 })) return null;
    const lambda = lcm(p - 1n, q - 1n);
    const d = modInverse(e, lambda);
    const dp = d % (p - 1n);
    const dq = d % (q - 1n);
    const qi = modInverse(q, p);
    let fullPrivateComponentsMatch = false;
    if (magic === "RSA3") {
      const storedDp = integer(data.subarray(cursor, cursor += pBytes));
      const storedDq = integer(data.subarray(cursor, cursor += qBytes));
      const storedQi = integer(data.subarray(cursor, cursor += pBytes));
      const storedD = integer(data.subarray(cursor, cursor += modulusBytes));
      fullPrivateComponentsMatch = storedDp === dp && storedDq === dq && storedQi === qi && storedD % lambda === d;
      if (!fullPrivateComponentsMatch) return null;
    }
    const key = createPrivateKey({
      format: "jwk",
      key: {
        kty: "RSA",
        n: base64Url(nBytes),
        e: base64Url(eBytes),
        d: base64Url(bigIntBuffer(d, modulusBytes)),
        p: base64Url(prime1Bytes),
        q: base64Url(prime2Bytes),
        dp: base64Url(bigIntBuffer(dp, pBytes)),
        dq: base64Url(bigIntBuffer(dq, qBytes)),
        qi: base64Url(bigIntBuffer(qi, pBytes)),
      },
    });
    const privatePem = Buffer.from(key.export({ format: "pem", type: "pkcs8" }));
    const publicPem = Buffer.from(createPublicKey(key).export({ format: "pem", type: "spki" }));
    return {
      category: "cng-rsa-private-key",
      bytes: total,
      primary: data.subarray(offset, offset + total),
      extension: ".cng-rsa-private.bin",
      derived: [
        { filename: "private-key-pkcs8.pem", data: privatePem },
        { filename: "public-key-spki.pem", data: publicPem },
      ],
      confidence: "authenticated",
      checks: { bitLength, modulusBitLengthMatches: true, modulusEqualsPrimeProduct: true, probablePrimeFactors: true, fullPrivateComponentsMatch, pkcs8RoundTrip: true },
    };
  } catch {
    return null;
  }
}

function ecc(data: Buffer, offset: number, beforeCrypto: () => boolean): CngValidation | null {
  if (offset + 8 > data.length) return null;
  const magic = data.toString("ascii", offset, offset + 4);
  const parameters = ECC.get(magic);
  if (parameters === undefined) return null;
  const keyBytes = data.readUInt32LE(offset + 4);
  const total = 8 + 3 * keyBytes;
  if (keyBytes !== parameters.bytes || total > data.length - offset) return null;
  const x = data.subarray(offset + 8, offset + 8 + keyBytes);
  const y = data.subarray(offset + 8 + keyBytes, offset + 8 + 2 * keyBytes);
  const d = data.subarray(offset + 8 + 2 * keyBytes, offset + total);
  try {
    if (!beforeCrypto()) return null;
    const ecdh = createECDH(parameters.curve);
    ecdh.setPrivateKey(d);
    const publicPoint = ecdh.getPublicKey(undefined, "uncompressed");
    if (!publicPoint.subarray(1, 1 + keyBytes).equals(x) || !publicPoint.subarray(1 + keyBytes).equals(y)) return null;
    const key = createPrivateKey({
      format: "jwk",
      key: { kty: "EC", crv: parameters.jwkCurve, x: base64Url(x), y: base64Url(y), d: base64Url(d) },
    });
    const pem = Buffer.from(key.export({ format: "pem", type: "pkcs8" }));
    return {
      category: "cng-ecc-private-key",
      bytes: total,
      primary: data.subarray(offset, offset + total),
      extension: ".cng-ecc-private.bin",
      derived: [{ filename: "private-key-pkcs8.pem", data: pem }],
      confidence: "authenticated",
      checks: { curve: parameters.jwkCurve, purpose: parameters.purpose, publicPrivateConsistency: true, pkcs8RoundTrip: true },
    };
  } catch {
    return null;
  }
}

function symmetric(data: Buffer, offset: number): CngValidation | null {
  if (offset + 12 > data.length || data.toString("ascii", offset, offset + 4) !== "KDBM") return null;
  const version = data.readUInt32LE(offset + 4);
  const keyBytes = data.readUInt32LE(offset + 8);
  if (version !== 1 || ![16, 24, 32, 48, 64].includes(keyBytes) || offset + 12 + keyBytes > data.length) return null;
  const original = data.subarray(offset, offset + 12 + keyBytes);
  return {
    category: "cng-symmetric-key",
    bytes: original.length,
    primary: original.subarray(12),
    extension: ".key",
    derived: [{ filename: "original-kdbm-key-blob.bin", data: original }],
    confidence: "high",
    checks: { bcryptKeyDataVersion: 1, keyBytes },
  };
}

export function parseCngPrivateBlob(data: Buffer, offset = 0, beforeCrypto: () => boolean = () => true): CngValidation | null {
  return rsa(data, offset, beforeCrypto) ?? ecc(data, offset, beforeCrypto) ?? symmetric(data, offset);
}

export const CNG_MAGICS = ["RSA2", "RSA3", ...ECC.keys(), "KDBM"].map((value) => Buffer.from(value, "ascii"));
