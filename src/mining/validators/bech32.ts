const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const CHARSET_INDEX = new Map([...CHARSET].map((character, index) => [character, index]));

function polymod(values: number[]): number {
  const generators = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let checksum = 1;
  for (const value of values) {
    const top = checksum >>> 25;
    checksum = ((checksum & 0x1ffffff) << 5) ^ value;
    for (let bit = 0; bit < 5; bit += 1) {
      if (((top >>> bit) & 1) !== 0) checksum ^= generators[bit] ?? 0;
    }
  }
  return checksum >>> 0;
}

function expandHrp(hrp: string): number[] {
  return [
    ...[...hrp].map((character) => character.charCodeAt(0) >>> 5),
    0,
    ...[...hrp].map((character) => character.charCodeAt(0) & 31),
  ];
}

function convertFiveBit(data: number[]): Buffer | null {
  let accumulator = 0;
  let bits = 0;
  const bytes: number[] = [];
  for (const value of data) {
    accumulator = (accumulator << 5) | value;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      bytes.push((accumulator >>> bits) & 0xff);
    }
    accumulator = bits === 0 ? 0 : accumulator & ((1 << bits) - 1);
  }
  if (bits >= 5 || ((accumulator << (8 - bits)) & 0xff) !== 0) return null;
  return Buffer.from(bytes);
}

export function validateAgeSecretKey(value: string): boolean {
  if (value !== value.toUpperCase() || !value.startsWith("AGE-SECRET-KEY-1") || value.length !== 74) return false;
  const normalized = value.toLowerCase();
  const separator = normalized.lastIndexOf("1");
  const hrp = normalized.slice(0, separator);
  const encoded = normalized.slice(separator + 1);
  if (hrp !== "age-secret-key-" || encoded.length !== 58) return false;
  const values = [...encoded].map((character) => CHARSET_INDEX.get(character));
  if (values.some((item) => item === undefined)) return false;
  const numeric = values as number[];
  if (polymod([...expandHrp(hrp), ...numeric]) !== 1) return false;
  const decoded = convertFiveBit(numeric.slice(0, -6));
  return decoded?.length === 32;
}
