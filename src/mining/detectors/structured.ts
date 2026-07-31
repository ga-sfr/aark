import { createPrivateKey, createPublicKey } from "node:crypto";
import type { Candidate, JsonValue } from "../../core/types.js";
import { decodeChromiumDpapiWrapper, parseDpapiMasterKeyFile } from "../validators/dpapi.js";
import { validateStructuredContainer } from "../validators/containers.js";
import type { DetectionContext } from "./types.js";

function record(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function nonemptyHex(value: unknown, minimumBytes = 1): value is string {
  return typeof value === "string" && value.length >= minimumBytes * 2 && value.length % 2 === 0 && /^[A-Fa-f0-9]+$/.test(value);
}

function wholeJsonCandidate(
  data: Buffer,
  context: DetectionContext,
  category: string,
  method: string,
  checks: Record<string, JsonValue>,
  derivedArtifacts?: Candidate["derivedArtifacts"],
): Candidate {
  return {
    category,
    offset: context.baseOffset,
    length: data.length,
    value: data,
    confidence: "high",
    validation: { method, checks },
    extension: ".json",
    ...(derivedArtifacts === undefined ? {} : { derivedArtifacts }),
  };
}

function ethereumV3(document: Record<string, unknown>, data: Buffer, context: DetectionContext): Candidate | null {
  const crypto = record(document.crypto ?? document.Crypto);
  if (document.version !== 3 || crypto === null) return null;
  const cipherParams = record(crypto.cipherparams);
  const kdfParams = record(crypto.kdfparams);
  if (
    typeof crypto.cipher !== "string"
    || !nonemptyHex(crypto.ciphertext, 16)
    || !nonemptyHex(crypto.mac, 16)
    || (crypto.kdf !== "scrypt" && crypto.kdf !== "pbkdf2")
    || cipherParams === null
    || !nonemptyHex(cipherParams.iv, 8)
    || kdfParams === null
    || !nonemptyHex(kdfParams.salt, 8)
  ) return null;
  return wholeJsonCandidate(data, context, "ethereum-v3-keystore", "ethereum-web3-keystore-structure", {
    version3: true,
    cipherDeclared: true,
    ciphertextHexValid: true,
    kdfParametersPresent: true,
    macPresent: true,
    passwordMacVerified: false,
  });
}

function electrum(document: Record<string, unknown>, data: Buffer, context: DetectionContext): Candidate | null {
  const keystore = record(document.keystore);
  if (typeof document.seed_version !== "number" || (keystore === null && typeof document.wallet_type !== "string")) return null;
  const hasPrivateMaterial = typeof keystore?.xprv === "string"
    || typeof keystore?.seed === "string"
    || typeof document.keystore === "string"
    || document.use_encryption === true;
  if (!hasPrivateMaterial) return null;
  return wholeJsonCandidate(data, context, "electrum-wallet", "electrum-wallet-structure", {
    seedVersionPresent: true,
    walletOrKeystorePresent: true,
    privateOrEncryptedMaterialPresent: true,
    passwordVerified: false,
  });
}

function metamaskVaultObject(value: unknown): Record<string, unknown> | null {
  const item = record(value);
  if (item === null || !nonemptyHex(item.data, 16) || !nonemptyHex(item.iv, 8) || !nonemptyHex(item.salt, 8)) return null;
  return item;
}

function metamask(document: Record<string, unknown>, data: Buffer, context: DetectionContext): Candidate | null {
  let vault = metamaskVaultObject(document);
  if (vault === null && typeof document.vault === "string") {
    try {
      vault = metamaskVaultObject(JSON.parse(document.vault) as unknown);
    } catch {
      vault = null;
    }
  }
  if (vault === null) return null;
  return wholeJsonCandidate(data, context, "metamask-encrypted-vault", "metamask-vault-structure", {
    ciphertextHexValid: true,
    ivHexValid: true,
    saltHexValid: true,
    passwordCryptographyVerified: false,
  });
}

function serviceAccount(document: Record<string, unknown>, data: Buffer, context: DetectionContext): Candidate | null {
  if (document.type !== "service_account" || typeof document.private_key !== "string" || typeof document.client_email !== "string") return null;
  try {
    createPrivateKey(document.private_key);
  } catch {
    return null;
  }
  return wholeJsonCandidate(data, context, "cloud-service-account", "service-account-private-key-parse", {
    serviceAccountType: true,
    clientIdentityPresent: true,
    privateKeyParsed: true,
  });
}

function dockerConfig(document: Record<string, unknown>, data: Buffer, context: DetectionContext): Candidate | null {
  const auths = record(document.auths);
  if (auths === null) return null;
  const decoded: Array<{ registry: string; credential: string }> = [];
  for (const [registry, entry] of Object.entries(auths)) {
    const auth = record(entry)?.auth;
    if (typeof auth !== "string" || auth.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(auth)) continue;
    const credentialBytes = Buffer.from(auth, "base64");
    if (credentialBytes.toString("base64") !== auth) continue;
    const credential = credentialBytes.toString("utf8");
    if (!Buffer.from(credential, "utf8").equals(credentialBytes)) continue;
    const separator = credential.indexOf(":");
    if (separator <= 0 || separator === credential.length - 1 || credential.includes("\0")) continue;
    decoded.push({ registry, credential });
  }
  if (decoded.length === 0) return null;
  return wholeJsonCandidate(data, context, "docker-registry-credentials", "docker-auth-base64-decode", {
    authsObjectPresent: true,
    decodableCredentialEntries: decoded.length,
  }, [{ filename: "decoded-registry-credentials.json", data: Buffer.from(`${JSON.stringify(decoded, null, 2)}\n`, "utf8") }]);
}

function kubernetesConfig(document: Record<string, unknown>, data: Buffer, context: DetectionContext): Candidate | null {
  if (document.kind !== "Config" || !Array.isArray(document.users)) return null;
  let sensitiveUsers = 0;
  for (const entry of document.users) {
    const user = record(record(entry)?.user);
    if (user !== null && ["token", "password", "client-key-data", "auth-provider", "exec"].some((key) => user[key] !== undefined)) sensitiveUsers += 1;
  }
  if (sensitiveUsers === 0) return null;
  return wholeJsonCandidate(data, context, "kubernetes-credential-config", "kubeconfig-sensitive-user-structure", {
    configKind: true,
    sensitiveUserEntries: sensitiveUsers,
  });
}

function firefoxLogins(document: Record<string, unknown>, data: Buffer, context: DetectionContext): Candidate | null {
  if (!Array.isArray(document.logins)) return null;
  const matches = document.logins.filter((entry) => {
    const login = record(entry);
    return login !== null && typeof login.encryptedUsername === "string" && typeof login.encryptedPassword === "string";
  }).length;
  if (matches === 0) return null;
  return wholeJsonCandidate(data, context, "firefox-logins-json", "firefox-encrypted-login-structure", {
    encryptedLoginEntries: matches,
    decrypted: false,
  });
}

function passwordManagerJson(document: Record<string, unknown>, data: Buffer, context: DetectionContext): Candidate | null {
  if (document.encrypted === true && typeof document.data === "string" && document.data.length >= 32) {
    const bitwardenMarkers = [
      typeof document.passwordProtected === "boolean",
      typeof document.salt === "string" && document.salt.length >= 8,
      Number.isSafeInteger(document.kdfType),
      Number.isSafeInteger(document.kdfIterations),
      typeof document.encKeyValidation_DO_NOT_EDIT === "string" && document.encKeyValidation_DO_NOT_EDIT.length >= 16,
    ].filter(Boolean).length;
    if (bitwardenMarkers < 3) return null;
    return wholeJsonCandidate(data, context, "bitwarden-encrypted-export", "bitwarden-export-structure", {
      encryptedExport: true,
      ciphertextPresent: true,
      formatSpecificFields: bitwardenMarkers,
      passwordCryptographyVerified: false,
    });
  }
  if (document.encrypted === false && Array.isArray(document.folders) && Array.isArray(document.items)) {
    const loginItems = document.items.filter((entry) => {
      const login = record(record(entry)?.login);
      return login !== null && (typeof login.password === "string" || typeof login.totp === "string");
    }).length;
    if (loginItems > 0) return wholeJsonCandidate(data, context, "bitwarden-json-export", "bitwarden-export-structure", { loginItems });
  }
  if (
    typeof document.masterKey === "string"
    && typeof document.overviewKey === "string"
    && typeof document.salt === "string"
    && typeof document.iterations === "number"
  ) {
    return wholeJsonCandidate(data, context, "onepassword-opvault-profile", "opvault-profile-structure", {
      encryptedMasterKeyPresent: true,
      encryptedOverviewKeyPresent: true,
      saltAndIterationsPresent: true,
      passwordCryptographyVerified: false,
    });
  }
  return null;
}

function chromiumLocalState(document: Record<string, unknown>, data: Buffer, context: DetectionContext): Candidate | null {
  const osCrypt = record(document.os_crypt);
  const wrapper = osCrypt?.encrypted_key;
  if (typeof wrapper !== "string") return null;
  const blob = decodeChromiumDpapiWrapper(wrapper);
  if (blob === null) return null;
  const decodedRepresentation = Buffer.from(wrapper, "utf8");
  const escapedRepresentation = Buffer.from(JSON.stringify(wrapper).slice(1, -1), "utf8");
  let rawWrapper = decodedRepresentation;
  let located = data.indexOf(rawWrapper);
  if (located < 0) {
    rawWrapper = escapedRepresentation;
    located = data.indexOf(rawWrapper);
  }
  if (located < 0) return null;
  return {
    category: "chromium-dpapi-encrypted-key",
    offset: context.baseOffset + located,
    length: rawWrapper.length,
    value: rawWrapper,
    confidence: "high",
    validation: { method: "chromium-local-state-dpapi-wrapper", checks: { base64Decoded: true, dpapiPrefixPresent: true, completeDpapiStructure: true, jsonEscapesPreserved: rawWrapper === escapedRepresentation } },
    extension: ".base64.txt",
    derivedArtifacts: [{ filename: "decoded-dpapi-blob.bin", data: blob }],
  };
}

function solanaKeypair(value: unknown, data: Buffer, context: DetectionContext): Candidate | null {
  const numbers = Array.isArray(value) ? value : record(value)?.secretKey;
  if (!Array.isArray(numbers) || numbers.length !== 64 || numbers.some((item) => !Number.isInteger(item) || Number(item) < 0 || Number(item) > 255)) return null;
  const bytes = Buffer.from(numbers as number[]);
  const seed = bytes.subarray(0, 32);
  try {
    const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
    const privateKey = createPrivateKey({ key: Buffer.concat([prefix, seed]), format: "der", type: "pkcs8" });
    const publicDer = Buffer.from(createPublicKey(privateKey).export({ format: "der", type: "spki" }));
    if (!publicDer.subarray(-32).equals(bytes.subarray(32))) return null;
    const privatePem = Buffer.from(privateKey.export({ format: "pem", type: "pkcs8" }));
    return wholeJsonCandidate(data, context, "solana-ed25519-keypair", "ed25519-public-private-consistency", {
      byteArrayLength: 64,
      publicPrivateConsistency: true,
      pkcs8Exported: true,
    }, [{ filename: "private-key-pkcs8.pem", data: privatePem }]);
  } catch {
    return null;
  }
}

function derPrivateKey(data: Buffer, context: DetectionContext): Candidate | null {
  if (data.length < 32 || data.length > 16 * 1024 * 1024 || !isCompleteDerSequence(data)) return null;
  for (const type of ["pkcs8", "pkcs1", "sec1"] as const) {
    try {
      const privateKey = createPrivateKey({ key: data, format: "der", type });
      if (privateKey.type !== "private") continue;
      const pem = Buffer.from(privateKey.export({ format: "pem", type: "pkcs8" }));
      const publicPem = Buffer.from(createPublicKey(privateKey).export({ format: "pem", type: "spki" }));
      return {
        category: "der-private-key",
        offset: context.baseOffset,
        length: data.length,
        value: data,
        confidence: "authenticated",
        validation: { method: "node-private-key-der-parse", checks: { completeDerPrivateKey: true, inputType: type, pkcs8AndPublicExported: true } },
        extension: `.${type}.der`,
        derivedArtifacts: [
          { filename: "private-key-pkcs8.pem", data: pem },
          { filename: "public-key-spki.pem", data: publicPem },
        ],
      };
    } catch {
      // Try the next standard DER private-key encoding.
    }
  }
  return null;
}

function isCompleteDerSequence(data: Buffer): boolean {
  if (data.length < 2 || data[0] !== 0x30) return false;
  const first = data[1];
  if (first === undefined || first === 0x80) return false;
  if (first < 0x80) return first + 2 === data.length;
  const lengthBytes = first & 0x7f;
  if (lengthBytes < 1 || lengthBytes > 4 || 2 + lengthBytes > data.length || data[2] === 0) return false;
  let payloadBytes = 0;
  for (const byte of data.subarray(2, 2 + lengthBytes)) payloadBytes = payloadBytes * 256 + byte;
  return payloadBytes >= 0x80 && 2 + lengthBytes + payloadBytes === data.length;
}

export function detectStructuredArtifacts(data: Buffer, context: DetectionContext): Candidate[] {
  if (!context.wholeFile) return [];
  const output: Candidate[] = [];
  const container = validateStructuredContainer(data);
  if (container !== null) {
    output.push({
      category: container.category,
      offset: context.baseOffset,
      length: container.value.length,
      value: container.value,
      confidence: container.confidence,
      validation: { method: "complete-sensitive-container", checks: container.checks },
      extension: container.extension,
    });
  }
  const der = derPrivateKey(data, context);
  if (der !== null) output.push(der);
  const dpapiMasterKey = parseDpapiMasterKeyFile(data);
  if (dpapiMasterKey !== null) {
    output.push({
      category: "windows-dpapi-master-key-file",
      offset: context.baseOffset,
      length: data.length,
      value: data,
      confidence: "high",
      validation: {
        method: "dpapi-master-key-file-structure",
        checks: {
          guidHeaderShape: true,
          primaryMasterKeySectionValid: true,
          primaryBytes: dpapiMasterKey.primaryBytes,
          backupBytes: dpapiMasterKey.backupBytes,
          credentialHistoryBytes: dpapiMasterKey.credentialHistoryBytes,
          domainKeyBytes: dpapiMasterKey.domainKeyBytes,
          decrypted: false,
        },
      },
      extension: ".dpapi-masterkey",
      sensitiveMetadata: { masterKeyGuid: dpapiMasterKey.guid },
    });
  }
  const textPrefix = data.subarray(0, Math.min(data.length, 2 * 1024 * 1024)).toString("utf8");
  const textSuffix = data.subarray(Math.max(0, data.length - 4096)).toString("utf8");
  if (/<KeePassFile(?:\s|>)/.test(textPrefix) && /<Key>\s*Password\s*<\/Key>/.test(textPrefix) && /<Value(?:\s[^>]*)?>/.test(textPrefix) && /<\/KeePassFile>\s*$/.test(textSuffix)) {
    output.push({
      category: "keepass-xml-export",
      offset: context.baseOffset,
      length: data.length,
      value: data,
      confidence: "high",
      validation: { method: "keepass-xml-export-structure", checks: { keepassRoot: true, passwordEntryPresent: true, xmlCryptographyVerified: false } },
      extension: ".xml",
    });
  }
  const firstLine = textPrefix.split(/\r?\n/, 1)[0]?.replace(/^\uFEFF/, "").toLowerCase();
  if (firstLine !== undefined && [
    "url,username,password,extra,name,grouping,fav",
    "url,username,password,totp,extra,name,grouping,fav",
  ].includes(firstLine)) {
    output.push({
      category: "lastpass-csv-export",
      offset: context.baseOffset,
      length: data.length,
      value: data,
      confidence: "high",
      validation: { method: "lastpass-csv-header", checks: { completeHeader: true, rowsPresent: /\r?\n.+/.test(textPrefix) } },
      extension: ".csv",
    });
  }

  try {
    const parsed: unknown = JSON.parse(data.toString("utf8"));
    const document = record(parsed);
    if (document !== null) {
      for (const validator of [ethereumV3, electrum, metamask, serviceAccount, dockerConfig, kubernetesConfig, firefoxLogins, passwordManagerJson, chromiumLocalState]) {
        const candidate = validator(document, data, context);
        if (candidate !== null) output.push(candidate);
      }
    }
    const solana = solanaKeypair(parsed, data, context);
    if (solana !== null) output.push(solana);
  } catch {
    // Non-JSON input is expected during broad recovery scans.
  }
  return output;
}
