interface CachedText {
  latin1?: string;
  utf8?: string;
}

const CACHE = new WeakMap<Buffer, CachedText>();

export function decodedText(data: Buffer, encoding: "latin1" | "utf8"): string {
  let cached = CACHE.get(data);
  if (cached === undefined) {
    cached = {};
    CACHE.set(data, cached);
  }
  const existing = cached[encoding];
  if (existing !== undefined) return existing;
  const decoded = data.toString(encoding);
  cached[encoding] = decoded;
  return decoded;
}
