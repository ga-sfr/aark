import { createPrivateKey } from "node:crypto";
import { validateOpenPgpSecretKeyring } from "./containers.js";
import { decodedText } from "../text.js";

export interface ArmoredValidation {
  category: string;
  value: Buffer;
  extension: string;
  checks: Record<string, string | number | boolean>;
  confidence: "high" | "authenticated";
}

const BEGIN = /-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----/g;

function decodeCanonicalBase64(value: string): Buffer | null {
  if (value.length === 0 || value.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return null;
  const decoded = Buffer.from(value, "base64");
  return decoded.toString("base64") === value ? decoded : null;
}

interface DerElement {
  tag: number;
  valueStart: number;
  end: number;
}

function derElement(data: Buffer, offset: number): DerElement | null {
  if (offset < 0 || offset + 2 > data.length) return null;
  const tag = data[offset] ?? -1;
  const first = data[offset + 1] ?? -1;
  let valueStart = offset + 2;
  let length = first;
  if ((first & 0x80) !== 0) {
    const bytes = first & 0x7f;
    if (bytes < 1 || bytes > 4 || valueStart + bytes > data.length || data[valueStart] === 0) return null;
    length = 0;
    for (const byte of data.subarray(valueStart, valueStart + bytes)) length = length * 256 + byte;
    if (length < 0x80) return null;
    valueStart += bytes;
  }
  return valueStart + length <= data.length ? { tag, valueStart, end: valueStart + length } : null;
}

function encryptedPkcs8Structure(data: Buffer): boolean {
  const root = derElement(data, 0);
  if (root?.tag !== 0x30 || root.end !== data.length) return false;
  const algorithm = derElement(data, root.valueStart);
  if (algorithm?.tag !== 0x30 || algorithm.end >= root.end) return false;
  const algorithmOid = derElement(data, algorithm.valueStart);
  if (algorithmOid?.tag !== 0x06 || algorithmOid.end > algorithm.end || algorithmOid.end - algorithmOid.valueStart < 3) return false;
  const encrypted = derElement(data, algorithm.end);
  return encrypted?.tag === 0x04 && encrypted.end === root.end && encrypted.end - encrypted.valueStart >= 16;
}

function sshString(data: Buffer, cursor: number): { value: Buffer; next: number } | null {
  if (cursor + 4 > data.length) return null;
  const bytes = data.readUInt32BE(cursor);
  if (bytes > 4 * 1024 * 1024 || cursor + 4 + bytes > data.length) return null;
  return { value: data.subarray(cursor + 4, cursor + 4 + bytes), next: cursor + 4 + bytes };
}

function openSshStructure(data: Buffer): boolean {
  const magic = Buffer.from("openssh-key-v1\0", "binary");
  if (!data.subarray(0, magic.length).equals(magic)) return false;
  let cursor = magic.length;
  const cipher = sshString(data, cursor);
  if (cipher === null || !/^[a-z0-9@._+-]{1,64}$/.test(cipher.value.toString("ascii"))) return false;
  cursor = cipher.next;
  const kdf = sshString(data, cursor);
  if (kdf === null || !/^[a-z0-9@._+-]{1,64}$/.test(kdf.value.toString("ascii"))) return false;
  cursor = kdf.next;
  const kdfOptions = sshString(data, cursor);
  if (kdfOptions === null) return false;
  cursor = kdfOptions.next;
  if (cursor + 4 > data.length) return false;
  const keyCount = data.readUInt32BE(cursor);
  cursor += 4;
  if (keyCount < 1 || keyCount > 16) return false;
  for (let index = 0; index < keyCount; index += 1) {
    const publicKey = sshString(data, cursor);
    if (publicKey === null || publicKey.value.length < 8) return false;
    cursor = publicKey.next;
  }
  const privateSection = sshString(data, cursor);
  if (privateSection === null || privateSection.value.length < 16 || privateSection.next !== data.length) return false;
  const cipherName = cipher.value.toString("ascii");
  const kdfName = kdf.value.toString("ascii");
  if (cipherName === "none") {
    if (kdfName !== "none" || kdfOptions.value.length !== 0 || privateSection.value.readUInt32BE(0) !== privateSection.value.readUInt32BE(4)) return false;
  } else if (kdfName === "none" || kdfOptions.value.length === 0) return false;
  return true;
}

function legacyPemEncryption(lines: string[], decoded: Buffer): boolean {
  if (!lines.some((line) => /^Proc-Type:\s*4,ENCRYPTED$/i.test(line))) return false;
  const declaration = lines.map((line) => /^DEK-Info:\s*([A-Z0-9-]+),([A-Fa-f0-9]+)$/i.exec(line)).find((value) => value !== null);
  if (declaration === undefined) return false;
  const cipher = declaration[1]?.toUpperCase();
  const iv = declaration[2];
  const parameters = new Map([
    ["DES-CBC", { ivHex: 16, block: 8 }],
    ["DES-EDE3-CBC", { ivHex: 16, block: 8 }],
    ["AES-128-CBC", { ivHex: 32, block: 16 }],
    ["AES-192-CBC", { ivHex: 32, block: 16 }],
    ["AES-256-CBC", { ivHex: 32, block: 16 }],
  ]).get(cipher ?? "");
  return parameters !== undefined && iv?.length === parameters.ivHex && decoded.length >= parameters.block && decoded.length % parameters.block === 0;
}

export function findPrivateKeyBlocks(data: Buffer): Array<{ offset: number; validation: ArmoredValidation }> {
  const text = decodedText(data, "latin1");
  const results: Array<{ offset: number; validation: ArmoredValidation }> = [];
  BEGIN.lastIndex = 0;
  for (const match of text.matchAll(BEGIN)) {
    const label = match[1];
    const offset = match.index;
    if (label === undefined || offset === undefined) continue;
    const footer = `-----END ${label}-----`;
    const endIndex = text.indexOf(footer, offset + match[0].length);
    if (endIndex < 0 || endIndex - offset > 4 * 1024 * 1024) continue;
    let end = endIndex + footer.length;
    while (end < text.length && (text[end] === "\r" || text[end] === "\n")) end += 1;
    const value = data.subarray(offset, end);
    const interior = text.slice(offset + match[0].length, endIndex);
    const lines = interior.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    const body = lines.filter((line) => !line.includes(":")).join("");
    const decoded = decodeCanonicalBase64(body);
    if (decoded === null || decoded.length < 16) continue;
    const legacyEncrypted = legacyPemEncryption(lines, decoded);
    const encryptedPkcs8 = label === "ENCRYPTED PRIVATE KEY" && encryptedPkcs8Structure(decoded);
    const openSsh = label === "OPENSSH PRIVATE KEY" && openSshStructure(decoded);
    let parsed = false;
    try {
      createPrivateKey(value);
      parsed = true;
    } catch {
      if (!encryptedPkcs8 && !openSsh && !legacyEncrypted) continue;
    }
    results.push({
      offset,
      validation: {
        category: label === "OPENSSH PRIVATE KEY" ? "openssh-private-key" : "pem-private-key",
        value,
        extension: ".pem",
        confidence: parsed ? "authenticated" : "high",
        checks: {
          completeMatchingArmor: true,
          base64BodyValid: true,
          nodePrivateKeyParseValid: parsed,
          encryptedPkcs8Structure: encryptedPkcs8,
          openSshStructure: openSsh,
          legacyPemEncryptionHeaders: legacyEncrypted,
        },
      },
    });
  }
  return results;
}

export function findPgpPrivateBlocks(data: Buffer): Array<{ offset: number; validation: ArmoredValidation }> {
  const begin = Buffer.from("-----BEGIN PGP PRIVATE KEY BLOCK-----", "ascii");
  const end = Buffer.from("-----END PGP PRIVATE KEY BLOCK-----", "ascii");
  const output = [];
  let cursor = 0;
  while (cursor < data.length) {
    const offset = data.indexOf(begin, cursor);
    if (offset < 0) break;
    const ending = data.indexOf(end, offset + begin.length);
    if (ending >= 0 && ending - offset <= 8 * 1024 * 1024) {
      const value = data.subarray(offset, ending + end.length);
      const body = value.toString("ascii").split(/\r?\n/).filter((line) => line !== "" && !line.startsWith("-----") && !line.includes(":") && !line.startsWith("="));
      try {
        const decoded = decodeCanonicalBase64(body.join(""));
        const packetValidation = decoded === null ? null : validateOpenPgpSecretKeyring(decoded);
        if (packetValidation !== null) {
          output.push({
            offset,
            validation: {
              category: "pgp-private-key-block",
              value,
              extension: ".asc",
              confidence: "high" as const,
              checks: {
                completeMatchingArmor: true,
                canonicalBase64: true,
                completePacketStream: true,
                secretKeyPacketPresent: true,
                openPgpPacketCryptographyVerified: false,
              },
            },
          });
        }
      } catch {
        // Reject malformed armor.
      }
    }
    cursor = offset + begin.length;
  }
  return output;
}

export function findPuttyPrivateKeys(data: Buffer): Array<{ offset: number; validation: ArmoredValidation }> {
  const text = decodedText(data, "latin1");
  const header = /^PuTTY-User-Key-File-(\d+):\s*([^\r\n]+)$/gm;
  const output = [];
  for (const match of text.matchAll(header)) {
    const offset = match.index;
    const version = Number(match[1]);
    const algorithm = match[2]?.trim();
    if (offset === undefined || ![2, 3].includes(version) || algorithm === undefined || !/^ssh-[A-Za-z0-9@._+-]+$/.test(algorithm)) continue;
    const tail = text.slice(offset, Math.min(text.length, offset + 4 * 1024 * 1024));
    const lines = tail.split(/\r?\n/);
    const encryption = /^Encryption:\s*(none|aes256-cbc)$/.exec(lines[1] ?? "");
    if (encryption === null || !/^Comment:\s*[^\0]*$/.test(lines[2] ?? "")) continue;
    const publicDeclaration = /^Public-Lines:\s*(\d+)$/.exec(lines[3] ?? "");
    const publicCount = Number(publicDeclaration?.[1]);
    if (!Number.isSafeInteger(publicCount) || publicCount < 1 || publicCount > 65_536) continue;
    const publicStart = 4;
    const publicEnd = publicStart + publicCount;
    const publicEncoded = lines.slice(publicStart, publicEnd).join("");
    const publicBlob = decodeCanonicalBase64(publicEncoded);
    const privateDeclaration = /^Private-Lines:\s*(\d+)$/.exec(lines[publicEnd] ?? "");
    const privateCount = Number(privateDeclaration?.[1]);
    if (publicBlob === null || publicBlob.length < 8 || !Number.isSafeInteger(privateCount) || privateCount < 1 || privateCount > 65_536) continue;
    const algorithmBytes = publicBlob.readUInt32BE(0);
    if (algorithmBytes < 1 || algorithmBytes > publicBlob.length - 4 || publicBlob.toString("ascii", 4, 4 + algorithmBytes) !== algorithm) continue;
    const privateStart = publicEnd + 1;
    const privateEnd = privateStart + privateCount;
    const privateBlob = decodeCanonicalBase64(lines.slice(privateStart, privateEnd).join(""));
    if (privateBlob === null || privateBlob.length === 0) continue;

    let macLine = privateEnd;
    const kdfFields = new Set<string>();
    while (version === 3 && macLine < lines.length && !/^Private-MAC:/.test(lines[macLine] ?? "")) {
      const kdf = /^(Key-Derivation|Argon2-Memory|Argon2-Passes|Argon2-Parallelism|Argon2-Salt):\s*(\S+)$/.exec(lines[macLine] ?? "");
      if (kdf === null || kdfFields.has(kdf[1] ?? "") || kdfFields.size >= 5) break;
      kdfFields.add(kdf[1] ?? "");
      macLine += 1;
    }
    if (encryption[1] === "aes256-cbc" && privateBlob.length % 16 !== 0) continue;
    if (version === 3 && encryption[1] === "aes256-cbc") {
      const requiredKdf = ["Key-Derivation", "Argon2-Memory", "Argon2-Passes", "Argon2-Parallelism", "Argon2-Salt"];
      if (requiredKdf.some((field) => !kdfFields.has(field))) continue;
    }
    const expectedMacBytes = version === 2 ? 40 : 64;
    const mac = new RegExp(`^Private-MAC:\\s*([0-9a-fA-F]{${expectedMacBytes}})$`).exec(lines[macLine] ?? "");
    if (mac === null) continue;
    const end = lines.slice(0, macLine + 1).join("\n").length;
    const originalEnd = (() => {
      let position = 0;
      for (let index = 0; index <= macLine; index += 1) {
        position += (lines[index] ?? "").length;
        if (index < macLine) position += tail[position] === "\r" ? 2 : 1;
      }
      return position;
    })();
    const value = Buffer.from(tail.slice(0, Math.max(end, originalEnd)), "latin1");
    output.push({
      offset,
      validation: {
        category: "putty-private-key",
        value,
        extension: ".ppk",
        confidence: "high" as const,
        checks: {
          formatVersion: version,
          publicLineCountDeclared: publicCount,
          privateLineCountDeclared: privateCount,
          publicBlobAlgorithmMatchesHeader: true,
          publicAndPrivateBase64Canonical: true,
          encryption: encryption[1] ?? "unknown",
          keyDerivationFields: kdfFields.size,
          privateMacPresent: true,
          privateMacPasswordVerified: false,
        },
      },
    });
  }
  return output;
}

export function findSsh2PrivateBlocks(data: Buffer): Array<{ offset: number; validation: ArmoredValidation }> {
  const begin = Buffer.from("---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----", "ascii");
  const end = Buffer.from("---- END SSH2 ENCRYPTED PRIVATE KEY ----", "ascii");
  const output: Array<{ offset: number; validation: ArmoredValidation }> = [];
  let cursor = 0;
  while (cursor < data.length) {
    const offset = data.indexOf(begin, cursor);
    if (offset < 0) break;
    const ending = data.indexOf(end, offset + begin.length);
    if (ending >= 0 && ending - offset <= 4 * 1024 * 1024) {
      const value = data.subarray(offset, ending + end.length);
      const lines = value.toString("ascii").split(/\r?\n/);
      const encoded = lines.filter((line) => line !== "" && !line.startsWith("----") && !line.includes(":")).join("");
      const decoded = decodeCanonicalBase64(encoded);
      if (decoded !== null && decoded.length >= 32 && decoded.readUInt32BE(0) === 0x3f6ff9eb) {
        output.push({
          offset,
          validation: {
            category: "ssh2-encrypted-private-key",
            value,
            extension: ".ssh2",
            confidence: "high",
            checks: { completeMatchingArmor: true, canonicalBase64: true, ssh2PrivateKeyMagic: true, passwordCryptographyVerified: false },
          },
        });
      }
    }
    cursor = offset + begin.length;
  }
  return output;
}
