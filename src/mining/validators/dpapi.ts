const DPAPI_MAGIC = Buffer.from("01000000d08c9ddf0115d1118c7a00c04fc297eb", "hex");
export const MAX_DPAPI_BLOB_BYTES = 16 * 1024 * 1024;
const MAX_DPAPI_BASE64_BYTES = Math.ceil(MAX_DPAPI_BLOB_BYTES / 3) * 4;
const MAX_CHROMIUM_DPAPI_BASE64_BYTES = Math.ceil((MAX_DPAPI_BLOB_BYTES + 5) / 3) * 4;

export interface DpapiMasterKeyFileValidation {
  value: Buffer;
  guid: string;
  primaryBytes: number;
  backupBytes: number;
  credentialHistoryBytes: number;
  domainKeyBytes: number;
}

function u32(data: Buffer, offset: number): number {
  if (offset < 0 || offset + 4 > data.length) throw new Error("truncated DPAPI length");
  return data.readUInt32LE(offset);
}

export function dpapiMagic(): Buffer {
  return Buffer.from(DPAPI_MAGIC);
}

export function parseDpapiBlob(data: Buffer, offset = 0): Buffer | null {
  if (offset < 0 || offset + 44 > data.length || !data.subarray(offset, offset + DPAPI_MAGIC.length).equals(DPAPI_MAGIC)) {
    return null;
  }
  let cursor = 44;
  const variable = (): void => {
    const length = u32(data, offset + cursor);
    cursor += 4;
    if (length > MAX_DPAPI_BLOB_BYTES || cursor + length > MAX_DPAPI_BLOB_BYTES || offset + cursor + length > data.length) {
      throw new Error("invalid DPAPI field length");
    }
    cursor += length;
  };
  try {
    variable();
    if (offset + cursor + 8 > data.length) return null;
    cursor += 8;
    variable();
    variable();
    if (offset + cursor + 8 > data.length) return null;
    cursor += 8;
    variable();
    variable();
    variable();
  } catch {
    return null;
  }
  if (cursor < 100 || cursor > MAX_DPAPI_BLOB_BYTES || offset + cursor > data.length) return null;
  return data.subarray(offset, offset + cursor);
}

export function decodeChromiumDpapiWrapper(value: string): Buffer | null {
  try {
    if (value.length > MAX_CHROMIUM_DPAPI_BASE64_BYTES || !/^[A-Za-z0-9+/]+={0,2}$/.test(value) || value.length % 4 !== 0) return null;
    const decoded = Buffer.from(value, "base64");
    if (decoded.toString("base64") !== value) return null;
    if (!decoded.subarray(0, 5).equals(Buffer.from("DPAPI", "ascii"))) return null;
    const payload = decoded.subarray(5);
    const parsed = parseDpapiBlob(payload);
    return parsed?.length === payload.length ? parsed : null;
  } catch {
    return null;
  }
}

export function decodeBase64Dpapi(value: string): Buffer | null {
  try {
    if (value.length > MAX_DPAPI_BASE64_BYTES || !/^[A-Za-z0-9_-]+={0,2}$/.test(value)) return null;
    const normalized = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
    const decoded = Buffer.from(normalized, "base64");
    if (decoded.toString("base64").replace(/=+$/g, "") !== normalized.replace(/=+$/g, "")) return null;
    const parsed = parseDpapiBlob(decoded);
    return parsed?.length === decoded.length ? parsed : null;
  } catch {
    return null;
  }
}

function safeLength(value: bigint): number | null {
  return value <= BigInt(MAX_DPAPI_BLOB_BYTES) ? Number(value) : null;
}

function validMasterKeySection(data: Buffer): boolean {
  if (data.length < 96) return false;
  const version = data.readUInt32LE(0);
  const iterations = data.readUInt32LE(20);
  const hashAlgorithm = data.readUInt32LE(24);
  const cipherAlgorithm = data.readUInt32LE(28);
  const blockBytes = cipherAlgorithm === 0x6603 ? 8 : 16;
  return [1, 2].includes(version)
    && iterations >= 1
    && iterations <= 100_000_000
    && [0x8004, 0x8009, 0x800c, 0x800d, 0x800e].includes(hashAlgorithm)
    && [0x6603, 0x660e, 0x660f, 0x6610].includes(cipherAlgorithm)
    && (data.length - 32) % blockBytes === 0;
}

export function parseDpapiMasterKeyFile(data: Buffer): DpapiMasterKeyFileValidation | null {
  if (data.length < 128 || data.length > MAX_DPAPI_BLOB_BYTES) return null;
  const version = data.readUInt32LE(0);
  if (![1, 2].includes(version)) return null;
  const guid = data.subarray(12, 84).toString("utf16le");
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(guid)) return null;
  const primaryBytes = safeLength(data.readBigUInt64LE(96));
  const backupBytes = safeLength(data.readBigUInt64LE(104));
  const credentialHistoryBytes = safeLength(data.readBigUInt64LE(112));
  const domainKeyBytes = safeLength(data.readBigUInt64LE(120));
  if (primaryBytes === null || backupBytes === null || credentialHistoryBytes === null || domainKeyBytes === null) return null;
  const total = 128 + primaryBytes + backupBytes + credentialHistoryBytes + domainKeyBytes;
  if (total !== data.length || primaryBytes === 0) return null;
  const primary = data.subarray(128, 128 + primaryBytes);
  const backup = data.subarray(128 + primaryBytes, 128 + primaryBytes + backupBytes);
  if (!validMasterKeySection(primary) || (backupBytes > 0 && !validMasterKeySection(backup))) return null;
  return { value: data, guid, primaryBytes, backupBytes, credentialHistoryBytes, domainKeyBytes };
}
