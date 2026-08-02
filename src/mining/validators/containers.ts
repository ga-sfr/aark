import { createHash, X509Certificate } from "node:crypto";
import { shannonEntropy } from "../../core/crypto.js";

export interface ContainerValidation {
  category: string;
  value: Buffer;
  extension: string;
  confidence: "high" | "authenticated";
  checks: Record<string, string | number | boolean>;
}

class Reader {
  public cursor = 0;
  public constructor(private readonly data: Buffer) {}

  public read(bytes: number): Buffer {
    if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > 512 * 1024 * 1024 || this.cursor + bytes > this.data.length) {
      throw new Error("truncated or oversized structure");
    }
    const value = this.data.subarray(this.cursor, this.cursor + bytes);
    this.cursor += bytes;
    return value;
  }

  public u16be(): number {
    return this.read(2).readUInt16BE(0);
  }

  public u32be(): number {
    return this.read(4).readUInt32BE(0);
  }

  public u64be(): bigint {
    return this.read(8).readBigUInt64BE(0);
  }

  public modifiedUtf(): Buffer {
    const value = this.read(this.u16be());
    if (value.length === 0 || value.includes(0)) throw new Error("invalid JKS modified-UTF field");
    return value;
  }
}

function completeDer(value: Buffer): boolean {
  if (value.length < 4 || value[0] !== 0x30) return false;
  const first = value[1];
  if (first === undefined) return false;
  let header: number;
  let payload: number;
  if (first < 0x80) {
    header = 2;
    payload = first;
  } else {
    const count = first & 0x7f;
    if (count < 1 || count > 4 || 2 + count > value.length || value[2] === 0) return false;
    header = 2 + count;
    payload = 0;
    for (const byte of value.subarray(2, header)) payload = payload * 256 + byte;
    if (payload < 0x80) return false;
  }
  return header + payload === value.length;
}

export function validateJks(data: Buffer, takeValidation: () => boolean = () => true): ContainerValidation | null {
  try {
    const reader = new Reader(data);
    if (reader.u32be() !== 0xfeedfeed) return null;
    const version = reader.u32be();
    const entries = reader.u32be();
    if (![1, 2].includes(version) || entries < 1 || entries > 10_000) return null;
    let privateKeyEntries = 0;
    let trustedCertificateEntries = 0;
    let certificates = 0;
    for (let index = 0; index < entries; index += 1) {
      if (!takeValidation()) throw new Error("JKS validation limit reached");
      const tag = reader.u32be();
      reader.modifiedUtf();
      const timestamp = reader.u64be();
      if (timestamp < 315_532_800_000n || timestamp > 4_102_444_800_000n) throw new Error("implausible JKS timestamp");
      if (tag === 1) {
        privateKeyEntries += 1;
        const protectedKey = reader.read(reader.u32be());
        if (!completeDer(protectedKey)) throw new Error("invalid protected private-key DER");
        const chain = reader.u32be();
        if (chain > 10_000) throw new Error("invalid certificate chain count");
        for (let item = 0; item < chain; item += 1) {
          if (certificates >= 100_000) throw new Error("JKS certificate count exceeds its validation limit");
          if (!takeValidation()) throw new Error("JKS validation limit reached");
          if (version === 2) reader.modifiedUtf();
          const certificate = reader.read(reader.u32be());
          new X509Certificate(certificate);
          certificates += 1;
        }
      } else if (tag === 2) {
        trustedCertificateEntries += 1;
        if (version === 2) reader.modifiedUtf();
        const certificate = reader.read(reader.u32be());
        new X509Certificate(certificate);
        certificates += 1;
      } else {
        throw new Error("invalid JKS entry tag");
      }
    }
    reader.read(20);
    if (reader.cursor !== data.length) return null;
    return {
      category: "java-jks-key-store",
      value: data,
      extension: ".jks",
      confidence: "high",
      checks: {
        version,
        entries,
        privateKeyEntries,
        trustedCertificateEntries,
        certificatesParsed: certificates,
        trailingIntegrityDigestPresent: true,
        passwordIntegrityVerified: false,
      },
    };
  } catch {
    return null;
  }
}

export function validatePasswordSafeV3(data: Buffer): ContainerValidation | null {
  const terminal = Buffer.from("PWS3-EOFPWS3-EOF", "ascii");
  if (data.length < 232 || data.toString("ascii", 0, 4) !== "PWS3") return null;
  const iterations = data.readUInt32LE(36);
  if (iterations < 2_048 || iterations > 100_000_000) return null;
  const terminalOffset = data.length - terminal.length - 32;
  if (terminalOffset < 152 || !data.subarray(terminalOffset, terminalOffset + terminal.length).equals(terminal)) return null;
  if ((terminalOffset - 152) % 16 !== 0 || shannonEntropy(data.subarray(4, 152)) < 5.5) return null;
  return {
    category: "password-safe-v3-database",
    value: data,
    extension: ".psafe3",
    confidence: "high",
    checks: {
      completeFixedPreamble: true,
      iterationCountPlausible: true,
      encryptedRegionBlockAligned: true,
      terminalMarkerPresent: true,
      trailingHmacPresent: true,
      passwordHmacVerified: false,
    },
  };
}

interface KdbxField {
  id: number;
  value: Buffer;
}

export function validateKdbx(data: Buffer): ContainerValidation | null {
  if (data.length < 64 || !data.subarray(0, 8).equals(Buffer.from("03d9a29a67fb4bb5", "hex"))) return null;
  const version = data.readUInt32LE(8);
  const major = version >>> 16;
  if (major !== 3 && major !== 4) return null;
  let cursor = 12;
  const fields: KdbxField[] = [];
  try {
    for (let count = 0; count < 64; count += 1) {
      if (cursor + (major === 4 ? 5 : 3) > data.length) return null;
      const id = data[cursor] ?? -1;
      cursor += 1;
      const length = major === 4 ? data.readUInt32LE(cursor) : data.readUInt16LE(cursor);
      cursor += major === 4 ? 4 : 2;
      if (length > 16 * 1024 * 1024 || cursor + length > data.length) return null;
      const value = data.subarray(cursor, cursor + length);
      cursor += length;
      fields.push({ id, value });
      if (id === 0) break;
    }
  } catch {
    return null;
  }
  const end = fields.at(-1);
  if (end?.id !== 0 || !end.value.equals(Buffer.from("0d0a0d0a", "hex"))) return null;
  const byId = new Map(fields.map((field) => [field.id, field.value]));
  const required = major === 4 ? [2, 3, 4, 7, 11] : [2, 3, 4, 5, 6, 7, 8, 9, 10];
  if (required.some((id) => !byId.has(id))) return null;
  if (byId.get(2)?.length !== 16 || byId.get(3)?.length !== 4 || byId.get(4)?.length !== 32) return null;
  let headerHashVerified = false;
  if (major === 4) {
    if (cursor + 64 > data.length) return null;
    const stored = data.subarray(cursor, cursor + 32);
    const expected = createHash("sha256").update(data.subarray(0, cursor)).digest();
    if (!stored.equals(expected)) return null;
    headerHashVerified = true;
  }
  return {
    category: "keepass-kdbx-database",
    value: data,
    extension: ".kdbx",
    confidence: headerHashVerified ? "authenticated" : "high",
    checks: {
      majorVersion: major,
      mandatoryHeaderFieldsPresent: true,
      headerEndMarkerValid: true,
      headerSha256Verified: headerHashVerified,
      passwordHmacVerified: false,
    },
  };
}

export function validateSensitiveSqlite(data: Buffer): ContainerValidation | null {
  if (data.length < 100 || !data.subarray(0, 16).equals(Buffer.from("SQLite format 3\0", "binary"))) return null;
  let pageSize = data.readUInt16BE(16);
  if (pageSize === 1) pageSize = 65_536;
  if (pageSize < 512 || pageSize > 65_536 || (pageSize & (pageSize - 1)) !== 0) return null;
  const readVersion = data[18] ?? -1;
  const writeVersion = data[19] ?? -1;
  const reservedBytes = data[20] ?? pageSize;
  const schemaFormat = data.readUInt32BE(44);
  const textEncoding = data.readUInt32BE(56);
  const firstPageType = data[100] ?? -1;
  if (
    ![1, 2].includes(readVersion)
    || ![1, 2].includes(writeVersion)
    || reservedBytes > pageSize - 480
    || data[21] !== 64
    || data[22] !== 32
    || data[23] !== 32
    || ![1, 2, 3, 4].includes(schemaFormat)
    || ![1, 2, 3].includes(textEncoding)
    || ![2, 5, 10, 13].includes(firstPageType)
    || data.length % pageSize !== 0
  ) return null;
  const lowered = data.subarray(0, Math.min(data.length, 64 * 1024 * 1024)).toString("latin1").toLowerCase();
  const markerGroups = [
    ["origin_url", "username_value", "password_value", "signon_realm"],
    ["host_key", "encrypted_value", "cookies"],
    ["card_number_encrypted", "name_on_card"],
    ["encryptedusername", "encryptedpassword", "hostname"],
    ["metadata", "nssprivate", "item1", "item2"],
    ["genp", "inet", "agrp", "svce", "acct"],
    ["mkey", "ckey", "keymeta"],
    ["walletdescriptor", "activeexternalspk", "descriptorcache"],
  ];
  const matched = markerGroups.findIndex((group) => group.every((marker) => lowered.includes(marker)));
  if (matched < 0) return null;
  return {
    category: [
      "chromium-login-database",
      "chromium-cookie-database",
      "chromium-payment-database",
      "firefox-login-database",
      "firefox-nss-key-database",
      "macos-keychain-database",
      "bitcoin-core-sqlite-wallet",
      "bitcoin-core-sqlite-wallet",
    ][matched] ?? "authentication-database",
    value: data,
    extension: ".sqlite",
    confidence: "high",
    checks: {
      sqliteHeaderValid: true,
      pageSize,
      readVersion,
      writeVersion,
      schemaFormat,
      textEncoding,
      completePageCount: true,
      firstBtreePageTypeValid: true,
      authenticationSchemaMarkersPresent: true,
      sqliteIntegrityChecked: false,
    },
  };
}

export function validateBitcoinCoreBerkeleyWallet(data: Buffer): ContainerValidation | null {
  if (data.length < 512 || data.length > 4 * 1024 * 1024 * 1024 || data.length < 24) return null;
  const magicLe = data.readUInt32LE(12);
  const magicBe = data.readUInt32BE(12);
  if (![0x00053162, 0x00061561].includes(magicLe) && ![0x00053162, 0x00061561].includes(magicBe)) return null;
  const littleEndian = [0x00053162, 0x00061561].includes(magicLe);
  const pageSize = littleEndian ? data.readUInt32LE(20) : data.readUInt32BE(20);
  if (pageSize < 512 || pageSize > 65_536 || (pageSize & (pageSize - 1)) !== 0 || data.length % pageSize !== 0) return null;
  const sample = data.subarray(0, Math.min(data.length, 128 * 1024 * 1024));
  const recordMarkers = [
    Buffer.from("046d6b6579", "hex"),
    Buffer.from("04636b6579", "hex"),
    Buffer.from("036b6579", "hex"),
    Buffer.from("04776b6579", "hex"),
  ];
  const metadataMarkers = [
    Buffer.from("076b65796d657461", "hex"),
    Buffer.from("076b6579706f6f6c", "hex"),
    Buffer.from("0962657374626c6f636b", "hex"),
    Buffer.from("0a6d696e76657273696f6e", "hex"),
  ];
  const privateRecordTypes = recordMarkers.filter((marker) => sample.includes(marker)).length;
  const walletMetadataTypes = metadataMarkers.filter((marker) => sample.includes(marker)).length;
  if (privateRecordTypes === 0 || walletMetadataTypes === 0) return null;
  return {
    category: "bitcoin-family-berkeley-wallet",
    value: data,
    extension: ".wallet.dat",
    confidence: "high",
    checks: {
      berkeleyDatabaseMagic: true,
      pageSize,
      completePageCount: true,
      privateRecordTypes,
      walletMetadataTypes,
      walletCryptographyVerified: false,
    },
  };
}

interface DerElement {
  tag: number;
  valueStart: number;
  end: number;
}

function derElement(data: Buffer, offset: number): DerElement | null {
  if (offset < 0 || offset + 2 > data.length) return null;
  const tag = data[offset] ?? -1;
  const firstLength = data[offset + 1] ?? -1;
  let valueStart = offset + 2;
  let length = firstLength;
  if ((firstLength & 0x80) !== 0) {
    const bytes = firstLength & 0x7f;
    if (bytes < 1 || bytes > 4 || valueStart + bytes > data.length || data[valueStart] === 0) return null;
    length = 0;
    for (const byte of data.subarray(valueStart, valueStart + bytes)) length = length * 256 + byte;
    if (length < 0x80) return null;
    valueStart += bytes;
  }
  if (length < 0 || valueStart + length > data.length) return null;
  return { tag, valueStart, end: valueStart + length };
}

export function validatePkcs12(data: Buffer): ContainerValidation | null {
  const root = derElement(data, 0);
  if (root?.tag !== 0x30 || root.end !== data.length) return null;
  const version = derElement(data, root.valueStart);
  if (version?.tag !== 0x02 || version.end - version.valueStart !== 1 || data[version.valueStart] !== 3) return null;
  const contentInfo = derElement(data, version.end);
  if (contentInfo?.tag !== 0x30) return null;
  const oid = derElement(data, contentInfo.valueStart);
  if (oid?.tag !== 0x06 || !data.subarray(oid.valueStart, oid.end).equals(Buffer.from("2a864886f70d010701", "hex"))) return null;
  const explicitContent = derElement(data, oid.end);
  if (explicitContent?.tag !== 0xa0 || explicitContent.end !== contentInfo.end || explicitContent.end - explicitContent.valueStart < 8) return null;
  const authenticatedSafe = derElement(data, explicitContent.valueStart);
  if (authenticatedSafe?.tag !== 0x04 || authenticatedSafe.end !== explicitContent.end) return null;
  const macData = contentInfo.end === root.end ? null : derElement(data, contentInfo.end);
  if (macData !== null && (macData.tag !== 0x30 || macData.end !== root.end)) return null;
  return {
    category: "pkcs12-key-store",
    value: data,
    extension: ".p12",
    confidence: "high",
    checks: {
      completeDer: true,
      pfxVersion3: true,
      authenticatedSafeContentInfo: true,
      macDataPresent: macData !== null,
      passwordMacVerified: false,
    },
  };
}

function openPgpPacket(data: Buffer, offset: number): { tag: number; bodyStart: number; end: number } | null {
  const header = data[offset];
  if (header === undefined || (header & 0x80) === 0) return null;
  let cursor = offset + 1;
  let tag: number;
  let length: number;
  if ((header & 0x40) !== 0) {
    tag = header & 0x3f;
    const first = data[cursor];
    if (first === undefined) return null;
    cursor += 1;
    if (first < 192) length = first;
    else if (first <= 223) {
      const second = data[cursor];
      if (second === undefined) return null;
      cursor += 1;
      length = ((first - 192) << 8) + second + 192;
    } else if (first === 255) {
      if (cursor + 4 > data.length) return null;
      length = data.readUInt32BE(cursor);
      cursor += 4;
    } else {
      return null;
    }
  } else {
    tag = (header >>> 2) & 0x0f;
    const lengthType = header & 3;
    if (lengthType === 0) {
      if (cursor + 1 > data.length) return null;
      length = data[cursor] ?? 0;
      cursor += 1;
    } else if (lengthType === 1) {
      if (cursor + 2 > data.length) return null;
      length = data.readUInt16BE(cursor);
      cursor += 2;
    } else if (lengthType === 2) {
      if (cursor + 4 > data.length) return null;
      length = data.readUInt32BE(cursor);
      cursor += 4;
    } else {
      length = data.length - cursor;
    }
  }
  if (length > 256 * 1024 * 1024 || cursor + length > data.length) return null;
  return { tag, bodyStart: cursor, end: cursor + length };
}

export function validateOpenPgpSecretKeyring(data: Buffer, takeValidation: () => boolean = () => true): ContainerValidation | null {
  if (data.length < 16) return null;
  let cursor = 0;
  let packets = 0;
  let secretPackets = 0;
  while (cursor < data.length && packets < 100_000) {
    if (!takeValidation()) return null;
    const packet = openPgpPacket(data, cursor);
    if (packet === null || packet.end <= cursor) return null;
    if (packet.tag === 5 || packet.tag === 7) {
      const version = data[packet.bodyStart];
      if (![3, 4, 5, 6].includes(version ?? -1) || packet.end - packet.bodyStart < 8) return null;
      secretPackets += 1;
    }
    packets += 1;
    cursor = packet.end;
  }
  if (cursor !== data.length || packets === 0 || secretPackets === 0) return null;
  return {
    category: "openpgp-binary-secret-keyring",
    value: data,
    extension: ".gpg",
    confidence: "high",
    checks: { completePacketStream: true, packets, secretKeyPackets: secretPackets, packetCryptographyVerified: false },
  };
}

export function validateGnuPgPrivateSExpression(data: Buffer): ContainerValidation | null {
  if (data.length < 64 || data.length > 64 * 1024 * 1024 || data.includes(0)) return null;
  if (!data.includes(Buffer.from("(private-key", "ascii")) && !data.includes(Buffer.from("(protected-private-key", "ascii"))) return null;
  const text = data.toString("utf8");
  if (!/\((?:protected-)?private-key\s+\(/.test(text)) return null;
  let depth = 0;
  let hexLiteral = false;
  let quoted = false;
  let escaped = false;
  for (const character of text) {
    if (escaped) {
      escaped = false;
      continue;
    }
    if (quoted && character === "\\") {
      escaped = true;
      continue;
    }
    if (!hexLiteral && character === '"') quoted = !quoted;
    else if (!quoted && character === "#") hexLiteral = !hexLiteral;
    else if (!quoted && !hexLiteral && character === "(") depth += 1;
    else if (!quoted && !hexLiteral && character === ")") {
      depth -= 1;
      if (depth < 0) return null;
    }
  }
  if (depth !== 0 || hexLiteral || quoted || !/\((?:rsa|dsa|ecc|elg)\b/.test(text)) return null;
  return {
    category: "gnupg-private-key-s-expression",
    value: data,
    extension: ".gpg-private-key",
    confidence: "high",
    checks: { privateKeySExpression: true, balancedStructure: true, cryptographyVerified: false },
  };
}

export function validateStructuredContainer(data: Buffer, takeValidation: () => boolean = () => true): ContainerValidation | null {
  let exhausted = false;
  const boundedValidation = (): boolean => {
    const available = takeValidation();
    if (!available) exhausted = true;
    return available;
  };
  const jks = validateJks(data, boundedValidation);
  if (jks !== null || exhausted) return jks;
  const fixed = validatePasswordSafeV3(data)
    ?? validateKdbx(data)
    ?? validateBitcoinCoreBerkeleyWallet(data)
    ?? validateSensitiveSqlite(data)
    ?? validatePkcs12(data);
  if (fixed !== null) return fixed;
  const openPgp = validateOpenPgpSecretKeyring(data, boundedValidation);
  if (openPgp !== null || exhausted) return openPgp;
  return validateGnuPgPrivateSExpression(data);
}
