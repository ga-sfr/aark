import type { Candidate } from "../../core/types.js";
import { parseCngPrivateBlob, CNG_MAGICS } from "../validators/cng.js";
import { dpapiMagic, parseDpapiBlob } from "../validators/dpapi.js";
import { validateAgeSecretKey } from "../validators/bech32.js";
import { findAesEncryptionSchedules, findChaChaStates } from "../validators/aes.js";
import { findPgpPrivateBlocks, findPrivateKeyBlocks, findPuttyPrivateKeys, findSsh2PrivateBlocks } from "../validators/pem.js";
import type { DetectionContext } from "./types.js";
import { decodedText } from "../text.js";

function armoredCandidate(offset: number, validation: ReturnType<typeof findPrivateKeyBlocks>[number]["validation"], context: DetectionContext): Candidate {
  return {
    category: validation.category,
    offset: context.baseOffset + offset,
    length: validation.value.length,
    value: validation.value,
    confidence: validation.confidence,
    validation: { method: "complete-armored-private-key", checks: validation.checks },
    extension: validation.extension,
  };
}

function* allIndexes(data: Buffer, needle: Buffer): Generator<number> {
  let cursor = 0;
  while (cursor <= data.length - needle.length) {
    const found = data.indexOf(needle, cursor);
    if (found < 0) break;
    yield found;
    cursor = found + 1;
  }
}

export function detectCryptographicKeys(data: Buffer, context: DetectionContext): Candidate[] {
  const output: Candidate[] = [];
  if (context.deepKeySchedules === true) output.push(...detectDeepKeySchedules(data, context));
  for (const finder of [findPrivateKeyBlocks, findPgpPrivateBlocks, findPuttyPrivateKeys, findSsh2PrivateBlocks]) {
    for (const hit of finder(data)) output.push(armoredCandidate(hit.offset, hit.validation, context));
  }

  for (const offset of allIndexes(data, dpapiMagic())) {
    const value = parseDpapiBlob(data, offset);
    if (value === null) continue;
    output.push({
      category: "windows-dpapi-blob",
      offset: context.baseOffset + offset,
      length: value.length,
      value,
      confidence: "high",
      validation: { method: "dpapi-structure", checks: { completeLengthDelimitedBlob: true, decrypted: false } },
      extension: ".dpapi",
    });
  }

  for (const magic of CNG_MAGICS) {
    for (const offset of allIndexes(data, magic)) {
      const parsed = parseCngPrivateBlob(data, offset);
      if (parsed === null) continue;
      const valueOffset = parsed.category === "cng-symmetric-key" ? offset + 12 : offset;
      output.push({
        category: parsed.category,
        offset: context.baseOffset + valueOffset,
        length: parsed.primary.length,
        value: parsed.primary,
        confidence: parsed.confidence,
        validation: { method: "windows-cng-cryptographic-consistency", checks: parsed.checks },
        extension: parsed.extension,
        derivedArtifacts: parsed.derived,
      });
    }
  }

  const text = decodedText(data, "latin1");
  const agePattern = /(?<![A-Z0-9-])AGE-SECRET-KEY-1[0-9A-Z]{58}(?![A-Z0-9])/g;
  for (const match of text.matchAll(agePattern)) {
    if (match.index === undefined || !validateAgeSecretKey(match[0])) continue;
    const value = Buffer.from(match[0], "ascii");
    output.push({
      category: "age-x25519-secret-key",
      offset: context.baseOffset + match.index,
      length: value.length,
      value,
      confidence: "authenticated",
      validation: { method: "age-bech32-checksum", checks: { humanReadablePrefixValid: true, checksumValid: true, payloadBytes: 32 } },
      extension: ".age-key",
    });
  }
  return output;
}

export function detectDeepKeySchedules(data: Buffer, context: DetectionContext): Candidate[] {
  const output: Candidate[] = [];
  for (const hit of findAesEncryptionSchedules(data)) {
    output.push({
      category: "aes-encryption-key-from-expanded-schedule",
      offset: context.baseOffset + hit.offset,
      length: hit.key.length,
      value: hit.key,
      confidence: "authenticated",
      validation: { method: "aes-key-expansion-recurrence", checks: { keyBits: hit.bits, completeEncryptionSchedule: true } },
      extension: `.aes-${hit.bits}.key`,
      derivedArtifacts: [{ filename: `expanded-aes-${hit.bits}-schedule.bin`, data: hit.schedule }],
    });
  }
  for (const hit of findChaChaStates(data)) {
    output.push({
      category: "chacha-key-from-initialized-state",
      offset: context.baseOffset + hit.offset,
      length: hit.key.length,
      value: hit.key,
      confidence: "high",
      validation: { method: "chacha-state-constant-and-layout", checks: { keyBits: hit.bits, stateBytes: 64, keyEntropyPlausible: true } },
      extension: `.chacha-${hit.bits}.key`,
      derivedArtifacts: [{ filename: `initialized-chacha-${hit.bits}-state.bin`, data: hit.state }],
    });
  }
  return output;
}
