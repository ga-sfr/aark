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

function exactByteOffset(data: Buffer, raw: string, searchFrom: number): number {
  const encoded = Buffer.from(raw, "utf8");
  return data.indexOf(encoded, searchFrom);
}

export function findBip39Mnemonics(data: Buffer): Bip39Hit[] {
  const text = decodedText(data, "utf8");
  const provisional: Bip39Hit[] = [];
  const nextSearchByPhrase = new Map<string, number>();

  const recentByLanguage = WORDLISTS.map((): Token[] => []);
  let previous: Token | undefined;
  const expression = /[\p{L}\p{M}]+/gu;
  for (const match of text.matchAll(expression)) {
    if (match.index === undefined) continue;
    const token: Token = {
      start: match.index,
      end: match.index + match[0].length,
      normalized: match[0].length <= 64 ? match[0].normalize("NFKD").toLowerCase() : "",
    };
    const connected = previous !== undefined && /^\s+$/u.test(text.slice(previous.end, token.start));
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
          if (!validateMnemonic(normalized, definition.words)) continue;
          const raw = text.slice(firstToken.start, lastToken.end);
          const searchKey = `${definition.language}\0${raw}`;
          const offset = exactByteOffset(data, raw, nextSearchByPhrase.get(searchKey) ?? 0);
          if (offset < 0) continue;
          const value = Buffer.from(raw, "utf8");
          nextSearchByPhrase.set(searchKey, offset + value.length);
          provisional.push({ offset, value, language: definition.language, words: length });
        }
      }
    }
    previous = token;
  }

  provisional.sort((left, right) => left.offset - right.offset || right.value.length - left.value.length);
  return provisional.filter((candidate, index, all) => !all.some((other, otherIndex) => (
    otherIndex !== index
    && other.language === candidate.language
    && other.offset <= candidate.offset
    && other.offset + other.value.length >= candidate.offset + candidate.value.length
    && other.value.length > candidate.value.length
  )));
}
