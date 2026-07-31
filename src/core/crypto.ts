import { createHash, timingSafeEqual } from "node:crypto";

export function sha256(value: Uint8Array | string): Buffer {
  return createHash("sha256").update(value).digest();
}

export function doubleSha256(value: Uint8Array): Buffer {
  return sha256(sha256(value));
}

export function sha256Hex(value: Uint8Array | string): string {
  return sha256(value).toString("hex");
}

export function base64Url(value: Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}

export function shannonEntropy(value: Uint8Array): number {
  if (value.length === 0) return 0;
  const counts = new Map<number, number>();
  for (const byte of value) counts.set(byte, (counts.get(byte) ?? 0) + 1);
  let result = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    result -= probability * Math.log2(probability);
  }
  return result;
}

export function printableRatio(value: Uint8Array): number {
  if (value.length === 0) return 0;
  let printable = 0;
  for (const byte of value) {
    if (byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126)) printable += 1;
  }
  return printable / value.length;
}

export function timingSafeDigestEqual(left: Uint8Array, right: Uint8Array): boolean {
  return timingSafeEqual(sha256(left), sha256(right));
}
