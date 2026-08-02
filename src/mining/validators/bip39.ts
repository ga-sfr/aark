import { validateMnemonic } from "@scure/bip39";
import { wordlist as czech } from "@scure/bip39/wordlists/czech.js";
import { wordlist as english } from "@scure/bip39/wordlists/english.js";
import { wordlist as french } from "@scure/bip39/wordlists/french.js";
import { wordlist as italian } from "@scure/bip39/wordlists/italian.js";
import { wordlist as japanese } from "@scure/bip39/wordlists/japanese.js";
import { wordlist as korean } from "@scure/bip39/wordlists/korean.js";
import { wordlist as portuguese } from "@scure/bip39/wordlists/portuguese.js";
import { wordlist as simplifiedChinese } from "@scure/bip39/wordlists/simplified-chinese.js";
import { wordlist as spanish } from "@scure/bip39/wordlists/spanish.js";
import { wordlist as traditionalChinese } from "@scure/bip39/wordlists/traditional-chinese.js";
import { decodedText } from "../text.js";

export interface Bip39Hit {
  offset: number;
  value: Buffer;
  language: string;
  words: number;
}

interface Token {
  start: number;
  end: number;
  byteStart: number;
  byteEnd: number;
  normalized: string;
}

const LENGTHS = [24, 21, 18, 15, 12] as const;
const WORDLISTS = ([
  ["english", english],
  ["czech", czech],
  ["french", french],
  ["italian", italian],
  ["japanese", japanese],
  ["korean", korean],
  ["portuguese", portuguese],
  ["simplified-chinese", simplifiedChinese],
  ["spanish", spanish],
  ["traditional-chinese", traditionalChinese],
] as const).map(([language, words]) => ({ language, words, vocabulary: new Set(words) }));

function whitespaceCodePoint(value: number): boolean {
  return (value >= 0x09 && value <= 0x0d)
    || value === 0x20
    || value === 0xa0
    || value === 0x1680
    || (value >= 0x2000 && value <= 0x200a)
    || value === 0x2028
    || value === 0x2029
    || value === 0x202f
    || value === 0x205f
    || value === 0x3000
    || value === 0xfeff;
}

function whitespaceOnly(value: string, start: number, end: number): boolean {
  if (start >= end) return false;
  for (let cursor = start; cursor < end;) {
    const codePoint = value.codePointAt(cursor);
    if (codePoint === undefined || !whitespaceCodePoint(codePoint)) return false;
    cursor += codePoint > 0xffff ? 2 : 1;
  }
  return true;
}

function boundedCodePointPrefix(value: string, maximumCodePoints: number): string {
  let end = 0;
  let count = 0;
  for (const character of value) {
    if (count >= maximumCodePoints) break;
    end += character.length;
    count += 1;
  }
  return value.slice(0, end);
}

export function findBip39Mnemonics(
  data: Buffer,
  maximumHits = Number.MAX_SAFE_INTEGER,
  onLimit?: () => void,
  maximumValidations = Number.MAX_SAFE_INTEGER,
  onValidationLimit?: () => void,
  takeValidation?: () => boolean,
): Bip39Hit[] {
  if (!Number.isSafeInteger(maximumHits) || maximumHits < 1) throw new Error("BIP39 hit limit must be a positive safe integer");
  if (!Number.isSafeInteger(maximumValidations) || maximumValidations < 1) throw new Error("BIP39 validation limit must be a positive safe integer");
  const text = decodedText(data, "utf8");
  const provisional: Bip39Hit[] = [];

  const recentByLanguage = WORDLISTS.map((): Token[] => []);
  let previous: Token | undefined;
  let nextTokenByte = 0;
  let validations = 0;
  const expression = /[\p{L}\p{M}]+/gu;
  tokenLoop: for (const match of text.matchAll(expression)) {
    if (match.index === undefined) continue;
    const oversized = match[0].length > 64;
    const encodedPrefix = Buffer.from(oversized ? boundedCodePointPrefix(match[0], 32) : match[0], "utf8");
    const byteStart = data.indexOf(encodedPrefix, nextTokenByte);
    if (byteStart < 0) {
      previous = undefined;
      for (const recent of recentByLanguage) recent.length = 0;
      continue;
    }
    const encodedBytes = oversized ? Buffer.byteLength(match[0], "utf8") : encodedPrefix.length;
    nextTokenByte = byteStart + encodedBytes;
    if (nextTokenByte > data.length || oversized) {
      previous = undefined;
      for (const recent of recentByLanguage) recent.length = 0;
      continue;
    }
    const token: Token = {
      start: match.index,
      end: match.index + match[0].length,
      byteStart,
      byteEnd: nextTokenByte,
      normalized: match[0].normalize("NFKD").toLowerCase(),
    };
    const connected = previous !== undefined && whitespaceOnly(text, previous.end, token.start);
    for (let languageIndex = 0; languageIndex < WORDLISTS.length; languageIndex += 1) {
      const definition = WORDLISTS[languageIndex];
      const recent = recentByLanguage[languageIndex];
      if (definition === undefined || recent === undefined) continue;
      const recognized = definition.vocabulary.has(token.normalized);
      if (!connected || !recognized) recent.length = 0;
      if (recognized) {
        recent.push(token);
        if (recent.length > 24) recent.shift();
        for (const length of LENGTHS) {
          if (recent.length < length) continue;
          const phraseTokens = recent.slice(-length);
          const firstToken = phraseTokens[0];
          const lastToken = phraseTokens.at(-1);
          if (firstToken === undefined || lastToken === undefined) continue;
          const normalized = phraseTokens.map((item) => item.normalized).join(" ");
          if (validations >= maximumValidations) {
            onValidationLimit?.();
            break tokenLoop;
          }
          if (takeValidation?.() === false) break tokenLoop;
          validations += 1;
          if (!validateMnemonic(normalized, definition.words)) continue;
          const offset = firstToken.byteStart;
          const value = Buffer.from(data.subarray(offset, lastToken.byteEnd));
          if (provisional.length >= maximumHits) {
            onLimit?.();
            break tokenLoop;
          }
          provisional.push({ offset, value, language: definition.language, words: length });
        }
      }
    }
    previous = token;
  }

  provisional.sort((left, right) => left.offset - right.offset || right.value.length - left.value.length);
  const maximumEndByLanguage = new Map<string, number>();
  return provisional.filter((candidate) => {
    const end = candidate.offset + candidate.value.length;
    const maximumEnd = maximumEndByLanguage.get(candidate.language);
    if (maximumEnd === undefined || end > maximumEnd) maximumEndByLanguage.set(candidate.language, end);
    return maximumEnd === undefined || maximumEnd < end;
  });
}
