import { doubleSha256 } from "../../core/crypto.js";
import { decodeBase58Check } from "./base58.js";

const RIPPLE_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function decodeRadix(value: string, alphabet: string): Buffer | null {
  const indexes = new Map([...alphabet].map((character, index) => [character, index]));
  let number = 0n;
  for (const character of value) {
    const digit = indexes.get(character);
    if (digit === undefined) return null;
    number = number * BigInt(alphabet.length) + BigInt(digit);
  }
  let hex = number.toString(16);
  if (hex.length % 2 !== 0) hex = `0${hex}`;
  const body = number === 0n ? Buffer.alloc(0) : Buffer.from(hex, "hex");
  const leading = value.length - value.replace(new RegExp(`^${alphabet[0]}+`), "").length;
  return Buffer.concat([Buffer.alloc(leading), body]);
}

function decodeBase32(value: string): Buffer | null {
  let accumulator = 0;
  let bits = 0;
  const output: number[] = [];
  for (const character of value) {
    const digit = BASE32_ALPHABET.indexOf(character);
    if (digit < 0) return null;
    accumulator = (accumulator << 5) | digit;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      output.push((accumulator >>> bits) & 0xff);
    }
    accumulator = bits === 0 ? 0 : accumulator & ((1 << bits) - 1);
  }
  if (bits !== 0 && ((accumulator << (8 - bits)) & 0xff) !== 0) return null;
  return Buffer.from(output);
}

function crc16Xmodem(value: Buffer): number {
  let crc = 0;
  for (const byte of value) {
    crc ^= byte << 8;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc & 0x8000) !== 0 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
  }
  return crc;
}

export function validStellarSecretSeed(value: string): boolean {
  if (!/^S[A-Z2-7]{55}$/.test(value)) return false;
  const decoded = decodeBase32(value);
  if (decoded === null || decoded.length !== 35 || decoded[0] !== (18 << 3)) return false;
  const expected = crc16Xmodem(decoded.subarray(0, 33));
  return decoded.readUInt16LE(33) === expected;
}

export function validXrpFamilySeed(value: string): boolean {
  const decoded = decodeRadix(value, RIPPLE_ALPHABET);
  if (decoded === null || decoded.length !== 21 || decoded[0] !== 0x21) return false;
  return doubleSha256(decoded.subarray(0, 17)).subarray(0, 4).equals(decoded.subarray(17));
}

const TEZOS_PREFIXES = new Map<string, { prefix: Buffer; bytes: number; format: string }>([
  ["edsk", { prefix: Buffer.from("0d0f3a07", "hex"), bytes: 32, format: "ed25519-seed" }],
  ["edsk-long", { prefix: Buffer.from("2bf64e07", "hex"), bytes: 64, format: "ed25519-expanded" }],
  ["spsk", { prefix: Buffer.from("11a2e0c9", "hex"), bytes: 32, format: "secp256k1" }],
  ["p2sk", { prefix: Buffer.from("1051eebd", "hex"), bytes: 32, format: "p256" }],
]);

export function validTezosSecretKey(value: string): { format: string } | null {
  const payload = decodeBase58Check(value);
  if (payload === null) return null;
  const label = value.startsWith("edsk") && value.length > 80 ? "edsk-long" : value.slice(0, 4);
  const parameters = TEZOS_PREFIXES.get(label);
  if (parameters === undefined || payload.length !== parameters.prefix.length + parameters.bytes || !payload.subarray(0, parameters.prefix.length).equals(parameters.prefix)) return null;
  const key = payload.subarray(parameters.prefix.length);
  if (key.every((byte) => byte === 0)) return null;
  return { format: parameters.format };
}
