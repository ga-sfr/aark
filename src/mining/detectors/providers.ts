import { shannonEntropy } from "../../core/crypto.js";
import type { Candidate, Confidence } from "../../core/types.js";
import { appendCandidate, takeStructuralValidation } from "./types.js";
import type { DetectionContext } from "./types.js";
import { decodedText } from "../text.js";

interface TokenPattern {
  category: string;
  provider: string;
  expression: RegExp;
  confidence: Confidence;
  minimumEntropy?: number;
}

const TOKEN_PATTERNS: TokenPattern[] = [
  { category: "github-access-token", provider: "github", expression: /(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{50,255})(?![A-Za-z0-9_])/g, confidence: "high", minimumEntropy: 4.0 },
  { category: "gitlab-access-token", provider: "gitlab", expression: /(?<![A-Za-z0-9_-])glpat-[A-Za-z0-9_-]{20,255}(?![A-Za-z0-9_-])/g, confidence: "high", minimumEntropy: 3.5 },
  { category: "npm-access-token", provider: "npm", expression: /(?<![A-Za-z0-9_])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9_])/g, confidence: "high", minimumEntropy: 4.0 },
  { category: "pypi-api-token", provider: "pypi", expression: /(?<![A-Za-z0-9_-])pypi-[A-Za-z0-9_-]{50,255}(?![A-Za-z0-9_-])/g, confidence: "high", minimumEntropy: 4.0 },
  { category: "slack-token", provider: "slack", expression: /(?<![A-Za-z0-9-])xox[baprs]-[A-Za-z0-9-]{20,255}(?![A-Za-z0-9-])/g, confidence: "high", minimumEntropy: 3.5 },
  { category: "stripe-secret-key", provider: "stripe", expression: /(?<![A-Za-z0-9_])sk_(?:live|test)_[A-Za-z0-9]{20,255}(?![A-Za-z0-9_])/g, confidence: "high", minimumEntropy: 3.5 },
  { category: "sendgrid-api-key", provider: "sendgrid", expression: /(?<![A-Za-z0-9_.-])SG\.[A-Za-z0-9_-]{16,64}\.[A-Za-z0-9_-]{20,128}(?![A-Za-z0-9_.-])/g, confidence: "high", minimumEntropy: 4.0 },
  { category: "google-api-key", provider: "google", expression: /(?<![A-Za-z0-9_-])AIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])/g, confidence: "high", minimumEntropy: 4.0 },
  { category: "twilio-api-key", provider: "twilio", expression: /(?<![A-Fa-f0-9])SK[A-Fa-f0-9]{32}(?![A-Fa-f0-9])/g, confidence: "high", minimumEntropy: 3.0 },
  { category: "digitalocean-access-token", provider: "digitalocean", expression: /(?<![A-Za-z0-9_])dop_v1_[A-Fa-f0-9]{64}(?![A-Za-z0-9_])/g, confidence: "high", minimumEntropy: 3.5 },
  { category: "shopify-access-token", provider: "shopify", expression: /(?<![A-Za-z0-9_])shp(?:at|ca|pa|ss)_[A-Fa-f0-9]{32}(?![A-Za-z0-9_])/g, confidence: "high", minimumEntropy: 3.0 },
  { category: "onepassword-service-token", provider: "1password", expression: /(?<![A-Za-z0-9_])ops_[A-Za-z0-9_-]{40,255}(?![A-Za-z0-9_])/g, confidence: "high", minimumEntropy: 4.0 },
  { category: "tailscale-auth-key", provider: "tailscale", expression: /(?<![A-Za-z0-9_-])tskey-(?:auth|api)-[A-Za-z0-9_-]{20,255}(?![A-Za-z0-9_-])/g, confidence: "high", minimumEntropy: 3.5 },
  { category: "telegram-bot-token", provider: "telegram", expression: /(?<!\d)\d{8,12}:[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])/g, confidence: "high", minimumEntropy: 3.5 },
  { category: "discord-bot-token", provider: "discord", expression: /(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{23,28}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}(?![A-Za-z0-9_-])/g, confidence: "medium", minimumEntropy: 4.0 },
  { category: "aws-access-key-id", provider: "aws", expression: /(?<![A-Z0-9])(?:AKIA|ASIA|AIDA|AROA)[A-Z0-9]{16}(?![A-Z0-9])/g, confidence: "medium", minimumEntropy: 3.0 },
  { category: "openai-api-key-shape", provider: "openai", expression: /(?<![A-Za-z0-9_-])sk-(?:(?:proj|svcacct)-)?[A-Za-z0-9_-]{32,255}(?![A-Za-z0-9_-])/g, confidence: "medium", minimumEntropy: 4.0 },
];

const SECRET_NAME = /(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|consumer[_-]?secret|secret[_-]?key|private[_-]?key|password|passwd|pwd|passphrase|refresh[_-]?token|recovery[_-]?key|wallet[_-]?seed|mnemonic|psk)/i;
const ASSIGNMENT = /(?:^|[\r\n,{;]\s*)(["']?)([A-Za-z][A-Za-z0-9_.-]{1,80})\1\s*[:=]\s*(?:"([^"\r\n]{8,4096})"|'([^'\r\n]{8,4096})'|([^\s,;}#]{8,1024}))/gm;
const CREDENTIAL_URL = /\b(?:https?|ftp|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?):\/\/[^\s<>"']{1,512}/g;
const JWT = /(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{8,2048})\.([A-Za-z0-9_-]{8,8192})\.([A-Za-z0-9_-]{8,4096})(?![A-Za-z0-9_-])/g;

function placeholder(value: string): boolean {
  const lowered = value.toLowerCase();
  if (/^(?:example|sample|dummy|test|testing|changeme|replace[_-]?me|redacted|secret|password|undefined|null|none|todo|xxx+|\*+)$/.test(lowered)) return true;
  if (/^(?:your|my)[_-]?(?:api[_-]?)?(?:key|token|secret|password)$/.test(lowered)) return true;
  if (/^\$\{[^}]+\}$/.test(value) || /^<[^>]+>$/.test(value) || /^%[^%]+%$/.test(value)) return true;
  return new Set(value).size < 5;
}

function candidate(
  category: string,
  value: Buffer,
  offset: number,
  confidence: Confidence,
  method: string,
  checks: Record<string, string | number | boolean>,
  provider?: string,
): Candidate {
  return {
    category,
    offset,
    length: value.length,
    value,
    confidence,
    validation: { method, checks },
    extension: ".txt",
    ...(provider === undefined ? {} : { sensitiveMetadata: { provider } }),
  };
}

function decodeBase64UrlJson(value: string): Record<string, unknown> | null {
  try {
    const decoded = Buffer.from(value, "base64url");
    if (decoded.length === 0 || decoded.toString("base64url").replace(/=+$/g, "") !== value.replace(/=+$/g, "")) return null;
    const parsed: unknown = JSON.parse(decoded.toString("utf8"));
    return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed) ? parsed as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function plausibleBase64UrlJsonObject(value: string): boolean {
  try {
    // Reject random base64url-shaped disk bytes before spending the shared
    // structural-validation budget on full decoding and JSON.parse. JWT
    // headers and payloads accepted below must decode to JSON objects.
    const prefix = Buffer.from(value.slice(0, 128), "base64url");
    for (const byte of prefix) {
      if (byte === 0x20 || byte === 0x09 || byte === 0x0a || byte === 0x0d) continue;
      return byte === 0x7b;
    }
    // An all-whitespace prefix is inconclusive, not invalid JSON. Let the
    // bounded full decoder decide when the object starts beyond this prefix.
    return value.length > 128;
  } catch {
    return false;
  }
}

export function detectProviderCredentials(data: Buffer, context: DetectionContext): Candidate[] {
  const text = decodedText(data, "latin1");
  const output: Candidate[] = [];
  for (const tokenPattern of TOKEN_PATTERNS) {
    const expression = new RegExp(tokenPattern.expression.source, tokenPattern.expression.flags);
    for (const match of text.matchAll(expression)) {
      if (match.index === undefined) continue;
      if (!takeStructuralValidation(context)) return output;
      const value = Buffer.from(match[0], "latin1");
      const entropy = shannonEntropy(value);
      if (placeholder(match[0]) || entropy < (tokenPattern.minimumEntropy ?? 0)) continue;
      if (!appendCandidate(output, candidate(
        tokenPattern.category,
        value,
        context.baseOffset + match.index,
        tokenPattern.confidence,
        "provider-token-shape",
        { prefixAndLengthValid: true, entropyBitsPerByte: Number(entropy.toFixed(3)), onlineValidityChecked: false },
        tokenPattern.provider,
      ), context)) return output;
    }
  }

  for (const match of text.matchAll(new RegExp(JWT.source, JWT.flags))) {
    if (match.index === undefined || match[1] === undefined || match[2] === undefined || match[3] === undefined) continue;
    if (!plausibleBase64UrlJsonObject(match[1]) || !plausibleBase64UrlJsonObject(match[2])) continue;
    if (!takeStructuralValidation(context)) return output;
    const header = decodeBase64UrlJson(match[1]);
    const payload = decodeBase64UrlJson(match[2]);
    const signature = Buffer.from(match[3], "base64url");
    if (header === null || payload === null || typeof header.alg !== "string" || header.alg.toLowerCase() === "none" || signature.length < 8) continue;
    const value = Buffer.from(match[0], "latin1");
    if (!appendCandidate(output, candidate("json-web-token", value, context.baseOffset + match.index, "high", "jwt-structural-validation", {
      headerJsonValid: true,
      payloadJsonValid: true,
      algorithmDeclared: true,
      signatureBytes: signature.length,
      signatureCryptographicallyVerified: false,
    }), context)) return output;
  }

  for (const match of text.matchAll(new RegExp(CREDENTIAL_URL.source, CREDENTIAL_URL.flags))) {
    if (match.index === undefined) continue;
    if (!takeStructuralValidation(context)) return output;
    try {
      const parsed = new URL(match[0]);
      if (parsed.username === "" || parsed.password === "" || placeholder(decodeURIComponent(parsed.password))) continue;
      const value = Buffer.from(match[0], "latin1");
      if (!appendCandidate(output, candidate("credential-bearing-url", value, context.baseOffset + match.index, "high", "url-credential-validation", {
        absoluteUrlParsed: true,
        usernamePresent: true,
        passwordPresent: true,
      }), context)) return output;
    } catch {
      // The regex intentionally over-selects; URL parsing is the validator.
    }
  }

  for (const match of text.matchAll(new RegExp(ASSIGNMENT.source, ASSIGNMENT.flags))) {
    const key = match[2];
    const rawValue = match[3] ?? match[4] ?? match[5];
    if (match.index === undefined || key === undefined || rawValue === undefined) continue;
    if (placeholder(rawValue)) continue;
    const normalizedKey = key.toLowerCase().replace(/-/g, "_");
    const awsCategory = normalizedKey === "aws_secret_access_key"
      ? "aws-secret-access-key"
      : normalizedKey === "aws_session_token" || normalizedKey === "aws_security_token"
        ? "aws-session-token"
        : undefined;
    if (awsCategory === undefined && !SECRET_NAME.test(key)) continue;
    if (!takeStructuralValidation(context)) return output;
    if (awsCategory === "aws-secret-access-key" && (rawValue.length !== 40 || !/^[A-Za-z0-9/+=]{40}$/.test(rawValue))) continue;
    if (awsCategory === "aws-session-token" && (rawValue.length < 16 || rawValue.length > 4096 || !/^[A-Za-z0-9/+=_-]+$/.test(rawValue))) continue;
    const entropy = shannonEntropy(Buffer.from(rawValue, "latin1"));
    if (entropy < 2.5 && rawValue.length < 20) continue;
    const valueIndex = match[0].lastIndexOf(rawValue);
    if (valueIndex < 0) continue;
    const value = Buffer.from(rawValue, "latin1");
    if (!appendCandidate(output, candidate(awsCategory ?? "secret-assignment", value, context.baseOffset + match.index + valueIndex, awsCategory === undefined ? "medium" : "high", "context-bound-secret-assignment", {
      sensitiveNameMatched: true,
      nonPlaceholder: true,
      entropyBitsPerByte: Number(entropy.toFixed(3)),
      onlineValidityChecked: false,
    }, awsCategory === undefined ? undefined : "aws"), context)) return output;
  }
  return output;
}
