import { mkdtemp as createTemporaryDirectory, realpath } from "node:fs/promises";
import { doubleSha256 } from "../core/crypto.js";

// Windows runner TEMP can use an 8.3 alias. Fixtures that exercise canonical
// path contracts must use the real spelling, just like a completed CLI plan.
export async function mkdtemp(prefix: string): Promise<string> {
  return await realpath(await createTemporaryDirectory(prefix));
}

export const BITCOIN_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
export const RIPPLE_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

export function encodeRadix(value: Buffer, alphabet: string): string {
  let number = value.length === 0 ? 0n : BigInt(`0x${value.toString("hex")}`);
  let result = "";
  while (number > 0n) {
    const remainder = Number(number % BigInt(alphabet.length));
    result = (alphabet[remainder] ?? "") + result;
    number /= BigInt(alphabet.length);
  }
  let leading = 0;
  while (leading < value.length && value[leading] === 0) leading += 1;
  return (alphabet[0] ?? "").repeat(leading) + result;
}

export function encodeBase58Check(payload: Buffer, alphabet = BITCOIN_ALPHABET): string {
  return encodeRadix(Buffer.concat([payload, doubleSha256(payload).subarray(0, 4)]), alphabet);
}

export function base32Encode(value: Buffer): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let accumulator = 0;
  let bits = 0;
  let output = "";
  for (const byte of value) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      output += alphabet[(accumulator >>> bits) & 31] ?? "";
    }
    accumulator = bits === 0 ? 0 : accumulator & ((1 << bits) - 1);
  }
  if (bits > 0) output += alphabet[(accumulator << (5 - bits)) & 31] ?? "";
  return output;
}

export function crc16Xmodem(value: Buffer): number {
  let crc = 0;
  for (const byte of value) {
    crc ^= byte << 8;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc & 0x8000) !== 0 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
  }
  return crc;
}

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

function bech32Polymod(values: number[]): number {
  const generators = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let checksum = 1;
  for (const value of values) {
    const top = checksum >>> 25;
    checksum = ((checksum & 0x1ffffff) << 5) ^ value;
    for (let bit = 0; bit < 5; bit += 1) if (((top >>> bit) & 1) !== 0) checksum ^= generators[bit] ?? 0;
  }
  return checksum >>> 0;
}

function bech32Hrp(hrp: string): number[] {
  return [...[...hrp].map((character) => character.charCodeAt(0) >>> 5), 0, ...[...hrp].map((character) => character.charCodeAt(0) & 31)];
}

function toFiveBit(value: Buffer): number[] {
  let accumulator = 0;
  let bits = 0;
  const output: number[] = [];
  for (const byte of value) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      output.push((accumulator >>> bits) & 31);
    }
    accumulator = bits === 0 ? 0 : accumulator & ((1 << bits) - 1);
  }
  if (bits > 0) output.push((accumulator << (5 - bits)) & 31);
  return output;
}

export function ageSecretKey(payload: Buffer): string {
  const hrp = "age-secret-key-";
  const data = toFiveBit(payload);
  const polymod = bech32Polymod([...bech32Hrp(hrp), ...data, 0, 0, 0, 0, 0, 0]) ^ 1;
  const checksum = Array.from({ length: 6 }, (_, index) => (polymod >>> (5 * (5 - index))) & 31);
  return `${hrp}1${[...data, ...checksum].map((item) => BECH32_CHARSET[item] ?? "").join("")}`.toUpperCase();
}
