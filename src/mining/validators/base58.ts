import { doubleSha256 } from "../../core/crypto.js";

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const INDEX = new Map([...ALPHABET].map((character, index) => [character, index]));
export const SECP256K1_ORDER = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

export function decodeBase58(value: string): Buffer | null {
  let number = 0n;
  for (const character of value) {
    const digit = INDEX.get(character);
    if (digit === undefined) return null;
    number = number * 58n + BigInt(digit);
  }
  let hex = number.toString(16);
  if (hex.length % 2 !== 0) hex = `0${hex}`;
  const body = number === 0n ? Buffer.alloc(0) : Buffer.from(hex, "hex");
  const leading = value.length - value.replace(/^1+/, "").length;
  return Buffer.concat([Buffer.alloc(leading), body]);
}

export function decodeBase58Check(value: string): Buffer | null {
  const decoded = decodeBase58(value);
  if (decoded === null || decoded.length < 5) return null;
  const payload = decoded.subarray(0, -4);
  const checksum = decoded.subarray(-4);
  return doubleSha256(payload).subarray(0, 4).equals(checksum) ? payload : null;
}

export function validWif(value: string): { network: "mainnet" | "testnet"; compressed: boolean } | null {
  const payload = decodeBase58Check(value);
  if (payload === null || (payload[0] !== 0x80 && payload[0] !== 0xef)) return null;
  let scalarBytes: Buffer;
  let compressed = false;
  if (payload.length === 33) {
    scalarBytes = payload.subarray(1);
  } else if (payload.length === 34 && payload.at(-1) === 1) {
    scalarBytes = payload.subarray(1, -1);
    compressed = true;
  } else {
    return null;
  }
  const scalar = BigInt(`0x${scalarBytes.toString("hex")}`);
  if (scalar === 0n || scalar >= SECP256K1_ORDER) return null;
  return { network: payload[0] === 0x80 ? "mainnet" : "testnet", compressed };
}

const PRIVATE_VERSIONS = new Map<string, { network: "mainnet" | "testnet"; format: string }>([
  ["0488ade4", { network: "mainnet", format: "xprv" }],
  ["049d7878", { network: "mainnet", format: "yprv" }],
  ["04b2430c", { network: "mainnet", format: "zprv" }],
  ["0295b005", { network: "mainnet", format: "Yprv" }],
  ["02aa7a99", { network: "mainnet", format: "Zprv" }],
  ["04358394", { network: "testnet", format: "tprv" }],
  ["044a4e28", { network: "testnet", format: "uprv" }],
  ["045f18bc", { network: "testnet", format: "vprv" }],
  ["024285b5", { network: "testnet", format: "Uprv" }],
  ["02575048", { network: "testnet", format: "Vprv" }],
]);

export function validExtendedPrivateKey(value: string): { network: "mainnet" | "testnet"; format: string; depth: number } | null {
  const payload = decodeBase58Check(value);
  if (payload === null || payload.length !== 78) return null;
  const version = payload.subarray(0, 4).toString("hex");
  const parameters = PRIVATE_VERSIONS.get(version);
  if (parameters === undefined) return null;
  if (payload[45] !== 0) return null;
  const scalar = BigInt(`0x${payload.subarray(46, 78).toString("hex")}`);
  if (scalar === 0n || scalar >= SECP256K1_ORDER) return null;
  return { ...parameters, depth: payload[4] ?? 0 };
}
