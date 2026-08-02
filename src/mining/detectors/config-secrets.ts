import { createPrivateKey } from "node:crypto";
import type { Candidate } from "../../core/types.js";
import { parseDpapiBlob } from "../validators/dpapi.js";
import { MAX_EXPENSIVE_CRYPTO_VALIDATIONS_PER_DETECTOR_JOB } from "../limits.js";
import { appendCandidate, markValidationLimit, takeStructuralValidation } from "./types.js";
import type { DetectionContext } from "./types.js";
import { decodedText } from "../text.js";

function canonicalBase64(value: string): Buffer | null {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value) || value.length % 4 !== 0) return null;
  const decoded = Buffer.from(value, "base64");
  return decoded.toString("base64") === value ? decoded : null;
}

function textCandidate(category: string, value: string, offset: number, context: DetectionContext, checks: Record<string, string | number | boolean>): Candidate {
  const bytes = Buffer.from(value, "latin1");
  return {
    category,
    offset: context.baseOffset + offset,
    length: bytes.length,
    value: bytes,
    confidence: "high",
    validation: { method: "sensitive-configuration-structure", checks },
    extension: ".txt",
  };
}

export function detectConfigurationSecrets(data: Buffer, context: DetectionContext): Candidate[] {
  const text = decodedText(data, "latin1");
  const output: Candidate[] = [];
  let expensiveValidations = 0;
  const takeExpensiveValidation = (): boolean => {
    if (expensiveValidations >= MAX_EXPENSIVE_CRYPTO_VALIDATIONS_PER_DETECTOR_JOB) {
      markValidationLimit(context);
      return false;
    }
    expensiveValidations += 1;
    return true;
  };

  const wireGuard = /(?:^|\n)\s*PrivateKey\s*=\s*([A-Za-z0-9+/]{43}=)\s*(?=\r?$)/gm;
  for (const match of text.matchAll(wireGuard)) {
    const value = match[1];
    if (match.index === undefined || value === undefined) continue;
    if (!takeStructuralValidation(context)) return output;
    const decoded = canonicalBase64(value);
    if (decoded?.length !== 32) continue;
    const relative = match[0].indexOf(value);
    if (!appendCandidate(output, textCandidate("wireguard-x25519-private-key", value, match.index + relative, context, {
      privateKeyAssignment: true,
      canonicalBase64: true,
      decodedBytes: 32,
    }), context)) return output;
  }

  const openVpnBegin = "-----BEGIN OpenVPN Static key V1-----";
  const openVpnEnd = "-----END OpenVPN Static key V1-----";
  const openVpnEndBytes = Buffer.from(openVpnEnd, "ascii");
  let cursor = 0;
  while (cursor < text.length) {
    const offset = text.indexOf(openVpnBegin, cursor);
    if (offset < 0) break;
    if (!takeStructuralValidation(context) || !takeExpensiveValidation()) return output;
    const searchStart = offset + openVpnBegin.length;
    const relativeEnd = data.subarray(searchStart, Math.min(data.length, offset + 4096 + openVpnEndBytes.length)).indexOf(openVpnEndBytes);
    const end = relativeEnd < 0 ? -1 : searchStart + relativeEnd;
    if (end >= 0) {
      const complete = text.slice(offset, end + openVpnEnd.length);
      const body = complete.split(/\r?\n/).filter((line) => !line.startsWith("-----") && line.trim() !== "").join("");
      if (/^[A-Fa-f0-9]{512}$/.test(body)) {
        if (!appendCandidate(output, textCandidate("openvpn-static-key", complete, offset, context, {
          completeMatchingArmor: true,
          hexBytes: 256,
        }), context)) return output;
      }
    }
    cursor = offset + openVpnBegin.length;
  }

  const wifi = /<keyMaterial>([^<\r\n]{8,256})<\/keyMaterial>/gi;
  for (const match of text.matchAll(wifi)) {
    const value = match[1];
    if (match.index === undefined || value === undefined) continue;
    if (!takeStructuralValidation(context)) return output;
    if (/^(?:password|changeme|redacted)$/i.test(value)) continue;
    const relative = match[0].indexOf(value);
    if (!appendCandidate(output, textCandidate("windows-wlan-key-material", value, match.index + relative, context, {
      wlanProfileElement: true,
      protectedStateDetermined: false,
    }), context)) return output;
  }

  const rdp = /(?:^|\n)password\s+51:b:([A-Fa-f0-9]{200,2097152})(?=\r?$)/gm;
  for (const match of text.matchAll(rdp)) {
    const encoded = match[1];
    if (match.index === undefined || encoded === undefined || encoded.length % 2 !== 0) continue;
    if (!takeStructuralValidation(context) || !takeExpensiveValidation()) return output;
    const decoded = Buffer.from(encoded, "hex");
    const blob = parseDpapiBlob(decoded);
    if (blob === null || blob.length !== decoded.length) continue;
    const relative = match[0].indexOf(encoded);
    if (!appendCandidate(output, {
      category: "rdp-dpapi-password-blob",
      offset: context.baseOffset + match.index + relative,
      length: Buffer.byteLength(encoded, "ascii"),
      value: Buffer.from(encoded, "ascii"),
      confidence: "high",
      validation: { method: "rdp-password-dpapi-structure", checks: { rdpPasswordProperty: true, completeDpapiStructure: true } },
      extension: ".hex.txt",
      derivedArtifacts: [{ filename: "decoded-dpapi-blob.bin", data: blob }],
    }, context)) return output;
  }

  const kubePrivateKey = /(?:^|\n)\s*client-key-data:\s*([A-Za-z0-9+/]{40,8388608}={0,2})\s*(?=\r?$)/gm;
  for (const match of text.matchAll(kubePrivateKey)) {
    const encoded = match[1];
    if (match.index === undefined || encoded === undefined) continue;
    if (!takeStructuralValidation(context) || !takeExpensiveValidation()) return output;
    const decoded = canonicalBase64(encoded);
    if (decoded === null) continue;
    try {
      createPrivateKey(decoded);
    } catch {
      continue;
    }
    const relative = match[0].indexOf(encoded);
    if (!appendCandidate(output, {
      ...textCandidate("kubernetes-client-private-key-data", encoded, match.index + relative, context, {
        kubeconfigField: true,
        canonicalBase64: true,
        privateKeyParsed: true,
      }),
      confidence: "authenticated",
      extension: ".base64.txt",
      derivedArtifacts: [{ filename: "decoded-private-key.pem", data: decoded }],
    }, context)) return output;
  }
  const tlsKeyLog = /(?:^|\n)((?:CLIENT_RANDOM|CLIENT_EARLY_TRAFFIC_SECRET|CLIENT_HANDSHAKE_TRAFFIC_SECRET|SERVER_HANDSHAKE_TRAFFIC_SECRET|CLIENT_TRAFFIC_SECRET_0|SERVER_TRAFFIC_SECRET_0|EXPORTER_SECRET|EARLY_EXPORTER_SECRET)\s+[A-Fa-f0-9]{64}\s+[A-Fa-f0-9]{64,256})(?=\r?$)/gm;
  for (const match of text.matchAll(tlsKeyLog)) {
    const line = match[1];
    if (match.index === undefined || line === undefined) continue;
    if (!takeStructuralValidation(context)) return output;
    const relative = match[0].indexOf(line);
    if (!appendCandidate(output, textCandidate("tls-key-log-secret", line, match.index + relative, context, {
      standardKeyLogLabel: true,
      clientRandomBytes: 32,
      secretHexValid: true,
    }), context)) return output;
  }
  return output;
}
