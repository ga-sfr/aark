export interface AesScheduleHit {
  offset: number;
  bits: 128 | 192 | 256;
  key: Buffer;
  schedule: Buffer;
}

export interface ChaChaStateHit {
  offset: number;
  bits: 128 | 256;
  key: Buffer;
  state: Buffer;
}

const SBOX = Buffer.from([
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]);
const RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

function transformedPrevious(schedule: Buffer, word: number, keyWords: number): [number, number, number, number] {
  const base = (word - 1) * 4;
  let values: [number, number, number, number] = [
    schedule[base] ?? 0,
    schedule[base + 1] ?? 0,
    schedule[base + 2] ?? 0,
    schedule[base + 3] ?? 0,
  ];
  if (word % keyWords === 0) {
    values = [
      (SBOX[values[1]] ?? 0) ^ (RCON[word / keyWords] ?? 0),
      SBOX[values[2]] ?? 0,
      SBOX[values[3]] ?? 0,
      SBOX[values[0]] ?? 0,
    ];
  } else if (keyWords > 6 && word % keyWords === 4) {
    values = values.map((value) => SBOX[value] ?? 0) as [number, number, number, number];
  }
  return values;
}

export function expandAesKey(key: Buffer): Buffer {
  if (![16, 24, 32].includes(key.length)) throw new Error("AES keys must be 16, 24, or 32 bytes");
  const keyWords = key.length / 4;
  const rounds = keyWords + 6;
  const schedule = Buffer.alloc(16 * (rounds + 1));
  key.copy(schedule);
  for (let word = keyWords; word < schedule.length / 4; word += 1) {
    const transformed = transformedPrevious(schedule, word, keyWords);
    const prior = (word - keyWords) * 4;
    const destination = word * 4;
    for (let byte = 0; byte < 4; byte += 1) schedule[destination + byte] = (schedule[prior + byte] ?? 0) ^ (transformed[byte] ?? 0);
  }
  return schedule;
}

function firstExpandedWordMatches(data: Buffer, offset: number, keyBytes: number): boolean {
  const keyWords = keyBytes / 4;
  const last = offset + keyBytes - 4;
  const expected = [
    (SBOX[data[last + 1] ?? 0] ?? 0) ^ 1,
    SBOX[data[last + 2] ?? 0] ?? 0,
    SBOX[data[last + 3] ?? 0] ?? 0,
    SBOX[data[last] ?? 0] ?? 0,
  ];
  for (let byte = 0; byte < 4; byte += 1) {
    if (((data[offset + byte] ?? 0) ^ (expected[byte] ?? 0)) !== (data[offset + keyWords * 4 + byte] ?? -1)) return false;
  }
  return true;
}

export function findAesEncryptionSchedules(data: Buffer): AesScheduleHit[] {
  const hits: AesScheduleHit[] = [];
  for (const keyBytes of [16, 24, 32] as const) {
    const bits = (keyBytes * 8) as 128 | 192 | 256;
    const scheduleBytes = 16 * (keyBytes / 4 + 7);
    for (let offset = 0; offset + scheduleBytes <= data.length; offset += 1) {
      if (!firstExpandedWordMatches(data, offset, keyBytes)) continue;
      const key = Buffer.from(data.subarray(offset, offset + keyBytes));
      const expected = expandAesKey(key);
      const actual = data.subarray(offset, offset + scheduleBytes);
      if (expected.equals(actual)) hits.push({ offset, bits, key, schedule: Buffer.from(actual) });
    }
  }
  return hits;
}

function entropy(value: Buffer): number {
  const counts = new Map<number, number>();
  for (const byte of value) counts.set(byte, (counts.get(byte) ?? 0) + 1);
  let result = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    result -= probability * Math.log2(probability);
  }
  return result;
}

export function findChaChaStates(data: Buffer): ChaChaStateHit[] {
  const output: ChaChaStateHit[] = [];
  for (const [markerText, bits] of [["expand 32-byte k", 256], ["expand 16-byte k", 128]] as const) {
    const marker = Buffer.from(markerText, "ascii");
    let cursor = 0;
    while (cursor + 64 <= data.length) {
      const offset = data.indexOf(marker, cursor);
      if (offset < 0 || offset + 64 > data.length) break;
      const state = data.subarray(offset, offset + 64);
      const storedKey = state.subarray(16, 48);
      const key = bits === 256 ? storedKey : storedKey.subarray(0, 16);
      const duplicated128 = bits === 256 || storedKey.subarray(0, 16).equals(storedKey.subarray(16));
      if (duplicated128 && entropy(key) >= 3.5 && !key.every((byte) => byte === 0)) {
        output.push({ offset: offset + 16, bits, key: Buffer.from(key), state: Buffer.from(state) });
      }
      cursor = offset + 1;
    }
  }
  return output;
}
