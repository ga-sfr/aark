import type { Candidate } from "../../core/types.js";
import { validExtendedPrivateKey, validWif, SECP256K1_ORDER } from "../validators/base58.js";
import { findBip39Mnemonics } from "../validators/bip39.js";
import { validBitLockerRecoveryPassword } from "../validators/bitlocker.js";
import { validStellarSecretSeed, validTezosSecretKey, validXrpFamilySeed } from "../validators/wallet-formats.js";
import { MAX_CANDIDATES_PER_DETECTOR_JOB, MAX_STRUCTURAL_VALIDATIONS_PER_DETECTOR_JOB } from "../limits.js";
import { appendCandidate, markCandidateLimit, markValidationLimit, takeStructuralValidation } from "./types.js";
import type { DetectionContext } from "./types.js";
import { decodedText } from "../text.js";

function indexes(expression: RegExp, text: string): IterableIterator<RegExpMatchArray> {
  return text.matchAll(new RegExp(expression.source, expression.flags));
}

export function detectWalletSecrets(data: Buffer, context: DetectionContext): Candidate[] {
  const output: Candidate[] = [];
  for (const hit of findBip39Mnemonics(
    data,
    MAX_CANDIDATES_PER_DETECTOR_JOB,
    () => markCandidateLimit(context),
    MAX_STRUCTURAL_VALIDATIONS_PER_DETECTOR_JOB,
    () => markValidationLimit(context),
    () => takeStructuralValidation(context),
  )) {
    if (!appendCandidate(output, {
      category: "bip39-mnemonic",
      offset: context.baseOffset + hit.offset,
      length: hit.value.length,
      value: hit.value,
      confidence: "authenticated",
      validation: {
        method: "bip39-wordlist-and-checksum",
        checks: { checksumValid: true, words: hit.words, supportedWordlist: true },
      },
      extension: ".mnemonic.txt",
      sensitiveMetadata: { language: hit.language },
    }, context)) return output;
  }
  if (context.runtimeState?.validationLimitReached === true) return output;

  const text = decodedText(data, "latin1");
  const wifExpression = /(?<![1-9A-HJ-NP-Za-km-z])[5KL9c][1-9A-HJ-NP-Za-km-z]{50,51}(?![1-9A-HJ-NP-Za-km-z])/g;
  for (const match of indexes(wifExpression, text)) {
    if (match.index === undefined) continue;
    if (!takeStructuralValidation(context)) return output;
    const validation = validWif(match[0]);
    if (validation === null) continue;
    const value = Buffer.from(match[0], "ascii");
    if (!appendCandidate(output, {
      category: "bitcoin-wif-private-key",
      offset: context.baseOffset + match.index,
      length: value.length,
      value,
      confidence: "authenticated",
      validation: {
        method: "base58check-and-secp256k1-scalar",
        checks: { checksumValid: true, scalarInRange: true, compressed: validation.compressed },
      },
      extension: ".wif.txt",
      sensitiveMetadata: { network: validation.network },
    }, context)) return output;
  }

  const extendedExpression = /(?<![1-9A-HJ-NP-Za-km-z])(?:[xyzYZtuvUV]prv)[1-9A-HJ-NP-Za-km-z]{107}(?![1-9A-HJ-NP-Za-km-z])/g;
  for (const match of indexes(extendedExpression, text)) {
    if (match.index === undefined) continue;
    if (!takeStructuralValidation(context)) return output;
    const validation = validExtendedPrivateKey(match[0]);
    if (validation === null) continue;
    const value = Buffer.from(match[0], "ascii");
    if (!appendCandidate(output, {
      category: "bip32-extended-private-key",
      offset: context.baseOffset + match.index,
      length: value.length,
      value,
      confidence: "authenticated",
      validation: {
        method: "bip32-base58check-and-private-scalar",
        checks: { checksumValid: true, payloadBytes: 78, scalarInRange: true, depth: validation.depth },
      },
      extension: ".xprv.txt",
      sensitiveMetadata: { network: validation.network, format: validation.format },
    }, context)) return output;
  }

  const stellarExpression = /(?<![A-Z2-7])S[A-Z2-7]{55}(?![A-Z2-7])/g;
  for (const match of indexes(stellarExpression, text)) {
    if (match.index === undefined) continue;
    if (!takeStructuralValidation(context)) return output;
    if (!validStellarSecretSeed(match[0])) continue;
    const value = Buffer.from(match[0], "ascii");
    if (!appendCandidate(output, {
      category: "stellar-secret-seed",
      offset: context.baseOffset + match.index,
      length: value.length,
      value,
      confidence: "authenticated",
      validation: { method: "stellar-strkey-crc16", checks: { versionByteValid: true, payloadBytes: 32, crc16XmodemValid: true } },
      extension: ".stellar-secret.txt",
    }, context)) return output;
  }

  const xrpExpression = /(?<![1-9A-HJ-NP-Za-km-z])s[1-9A-HJ-NP-Za-km-z]{24,34}(?![1-9A-HJ-NP-Za-km-z])/g;
  for (const match of indexes(xrpExpression, text)) {
    if (match.index === undefined) continue;
    if (!takeStructuralValidation(context)) return output;
    if (!validXrpFamilySeed(match[0])) continue;
    const value = Buffer.from(match[0], "ascii");
    if (!appendCandidate(output, {
      category: "xrp-family-seed",
      offset: context.baseOffset + match.index,
      length: value.length,
      value,
      confidence: "authenticated",
      validation: { method: "xrp-base58check", checks: { familySeedVersion: true, payloadBytes: 16, checksumValid: true } },
      extension: ".xrp-seed.txt",
    }, context)) return output;
  }

  const tezosExpression = /(?<![1-9A-HJ-NP-Za-km-z])(?:edsk|spsk|p2sk)[1-9A-HJ-NP-Za-km-z]{50,94}(?![1-9A-HJ-NP-Za-km-z])/g;
  for (const match of indexes(tezosExpression, text)) {
    if (match.index === undefined) continue;
    if (!takeStructuralValidation(context)) return output;
    const validation = validTezosSecretKey(match[0]);
    if (validation === null) continue;
    const value = Buffer.from(match[0], "ascii");
    if (!appendCandidate(output, {
      category: "tezos-secret-key",
      offset: context.baseOffset + match.index,
      length: value.length,
      value,
      confidence: "authenticated",
      validation: { method: "tezos-base58check", checks: { prefixValid: true, payloadLengthValid: true, checksumValid: true } },
      extension: ".tezos-secret.txt",
      sensitiveMetadata: { format: validation.format },
    }, context)) return output;
  }

  const ethereumExpression = /(?:private[_ -]?key|secret[_ -]?key|wallet[_ -]?key|privkey)\s*["']?\s*[:=]\s*["']?((?:0x)?[A-Fa-f0-9]{64})(?![A-Fa-f0-9])/gi;
  for (const match of indexes(ethereumExpression, text)) {
    const scalarText = match[1];
    if (match.index === undefined || scalarText === undefined) continue;
    if (!takeStructuralValidation(context)) return output;
    const scalar = BigInt(`0x${scalarText.replace(/^0x/i, "")}`);
    if (scalar === 0n || scalar >= SECP256K1_ORDER) continue;
    const valueIndex = match[0].lastIndexOf(scalarText);
    if (valueIndex < 0) continue;
    const value = Buffer.from(scalarText, "ascii");
    if (!appendCandidate(output, {
      category: "context-bound-secp256k1-private-scalar",
      offset: context.baseOffset + match.index + valueIndex,
      length: value.length,
      value,
      confidence: "high",
      validation: {
        method: "private-key-label-and-secp256k1-range",
        checks: { privateKeyContextPresent: true, exactly32Bytes: true, scalarInRange: true },
      },
      extension: ".hex-key.txt",
    }, context)) return output;
  }

  const bitLockerExpression = /(?<!\d)\d{6}(?:-\d{6}){7}(?!\d)/g;
  for (const match of indexes(bitLockerExpression, text)) {
    if (match.index === undefined) continue;
    if (!takeStructuralValidation(context)) return output;
    if (!validBitLockerRecoveryPassword(match[0])) continue;
    const value = Buffer.from(match[0], "ascii");
    if (!appendCandidate(output, {
      category: "bitlocker-recovery-password",
      offset: context.baseOffset + match.index,
      length: value.length,
      value,
      confidence: "authenticated",
      validation: { method: "bitlocker-group-checksum", checks: { eightGroups: true, allGroupsDivisibleBy11: true } },
      extension: ".bitlocker.txt",
    }, context)) return output;
  }
  return output;
}
