import path from "node:path";
import type { SensitiveFinding, SensitiveScanInventory, MiningProgress } from "./types.js";

const DIRECT_WALLET_CATEGORIES = new Set([
  "bip39-mnemonic",
  "bitcoin-wif-private-key",
  "bip32-extended-private-key",
  "context-bound-secp256k1-private-scalar",
  "solana-ed25519-keypair",
  "stellar-secret-seed",
  "xrp-family-seed",
  "tezos-secret-key",
]);

const WALLET_CONTAINER_CATEGORIES = new Set([
  "ethereum-v3-keystore",
  "electrum-wallet",
  "metamask-encrypted-vault",
  "bitcoin-family-berkeley-wallet",
  "bitcoin-core-sqlite-wallet",
]);

function literal(value: string): string {
  return `\`${JSON.stringify(value).replace(/`/g, "\\u0060")}\``;
}

function cell(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/\|/g, "\\|").replace(/[\r\n]+/g, " ");
}

function counts(findings: SensitiveFinding[]): Array<{ category: string; unique: number; occurrences: number }> {
  const grouped = new Map<string, { unique: number; occurrences: number }>();
  for (const finding of findings) {
    const current = grouped.get(finding.category) ?? { unique: 0, occurrences: 0 };
    current.unique += 1;
    current.occurrences += finding.occurrences.length;
    grouped.set(finding.category, current);
  }
  return [...grouped].map(([category, value]) => ({ category, ...value })).sort((left, right) => left.category.localeCompare(right.category));
}

export function accessSummary(category: string): string {
  if (DIRECT_WALLET_CATEGORIES.has(category)) return "May directly control or restore a cryptocurrency wallet and its funds if the material is current and complete.";
  if (WALLET_CONTAINER_CATEGORIES.has(category)) return "May contain cryptocurrency wallet keys or seeds; encrypted containers still require their password or companion key material.";
  if (category.includes("bitlocker")) return "May unlock a BitLocker-protected Windows volume.";
  if (category.includes("password-safe") || category.includes("keepass") || category.includes("bitwarden") || category.includes("onepassword") || category.includes("lastpass")) return "May expose a password vault and the accounts or secrets stored in it; encrypted vaults still require authentication material.";
  if (category.includes("chromium") || category.includes("firefox") || category.includes("keychain")) return "May expose browser or operating-system saved logins, cookies, payment data, or encryption keys when paired with the required local profile keys.";
  if (category.includes("dpapi")) return "May help decrypt Windows user or machine secrets when matched with the correct profile, master key, SID, and authentication material.";
  if (category.includes("kubernetes")) return "May authenticate to Kubernetes clusters or reveal cluster client keys and tokens, subject to current authorization.";
  if (category.includes("docker")) return "May authenticate to container registries named in the recovered configuration.";
  if (category.includes("cloud-service-account")) return "May authenticate as a cloud service account with whatever permissions remain assigned to it.";
  if (category.includes("wireguard") || category.includes("openvpn") || category.includes("wlan") || category.includes("wifi")) return "May provide access to a VPN or wireless network described by the recovered configuration.";
  if (category.includes("rdp")) return "May help recover credentials used for a Windows Remote Desktop connection.";
  if (category.includes("tls-key-log")) return "May decrypt matching captured TLS sessions; it is not an account credential by itself.";
  if (category.includes("aes-") || category.includes("chacha") || category === "cng-symmetric-key") return "May decrypt or authenticate data from the process or application that held the corresponding symmetric key.";
  if (category === "aws-access-key-id") return "Identifies one half of an AWS credential pair; it cannot authenticate without the matching secret key and, for temporary credentials, session token.";
  if (category === "aws-secret-access-key") return "May authenticate to AWS when paired with its access-key ID and, for temporary credentials, the matching session token.";
  if (category === "aws-session-token") return "Completes a temporary AWS credential set when paired with its matching access-key ID and secret access key; it cannot authenticate alone.";
  if (category.includes("token") || category.includes("api-key") || category.includes("service-token")) return "May authenticate to the named provider or API if the credential is still active and authorized.";
  if (category === "credential-bearing-url") return "May authenticate to the service named in the recovered URL if the embedded credentials remain valid.";
  if (category === "secret-assignment") return "May authenticate to or decrypt the application named by the surrounding recovered configuration.";
  if (category.includes("private-key") || category.includes("cng-") || category.includes("pkcs12") || category.includes("jks") || category.includes("pgp") || category.includes("ssh") || category.includes("putty") || category.includes("age-")) return "May enable authentication, signing, or decryption for systems that trust the corresponding public key; encrypted keys still require a password.";
  return "Sensitive material whose exact capability depends on the originating application and whether it remains valid.";
}

function walletSummary(findings: SensitiveFinding[]): { direct: number; containers: number; total: number } {
  const direct = findings.filter((finding) => DIRECT_WALLET_CATEGORIES.has(finding.category)).length;
  const containers = findings.filter((finding) => WALLET_CONTAINER_CATEGORIES.has(finding.category)).length;
  return { direct, containers, total: direct + containers };
}

function walletResult(inventory: SensitiveScanInventory, total: number, redacted: boolean): string {
  if (total > 0) return redacted
    ? "Cryptocurrency-related material was detected in the local sensitive output."
    : "Cryptocurrency-related material was detected; review every referenced artifact offline before taking action.";
  if (inventory.status === "complete") return "No cryptocurrency key, seed, or wallet container recognized by the built-in validators was detected in the scanned inputs.";
  return "No cryptocurrency key, seed, or wallet container recognized by the built-in validators was detected in the material processed so far; the incomplete or error-bearing status means absence cannot be concluded for all inputs.";
}

function categoryTable(findings: SensitiveFinding[]): string[] {
  const grouped = counts(findings);
  if (grouped.length === 0) return ["No validated sensitive-material categories were found."];
  return [
    "| Category | Unique findings | Occurrences | What it may provide access to |",
    "| --- | ---: | ---: | --- |",
    ...grouped.map((entry) => `| ${cell(entry.category)} | ${entry.unique} | ${entry.occurrences} | ${cell(accessSummary(entry.category))} |`),
  ];
}

export function renderMiningSensitiveReport(inventory: SensitiveScanInventory, progress: MiningProgress): string {
  const wallet = walletSummary(inventory.findings);
  const lines = [
    "# Sensitive-material mining final report",
    "",
    "> Sensitive local report: it contains source paths, byte offsets, fingerprints, and artifact locations. Do not publish it.",
    "",
    `- Status: ${inventory.status}`,
    `- Generated: ${inventory.updatedAt}`,
    `- Regular files visited: ${progress.filesVisited}`,
    `- Files scanned successfully: ${progress.filesScanned}`,
    `- Bytes scanned: ${progress.bytesScanned}`,
    `- Unique findings: ${inventory.findings.length}`,
    `- Occurrences: ${inventory.findings.reduce((sum, finding) => sum + finding.occurrences.length, 0)}`,
    `- Scan errors: ${inventory.errors.length + inventory.errorsOmitted}`,
    ...(inventory.failureMessage === undefined ? [] : [`- Failure: ${literal(inventory.failureMessage)}`]),
    "",
    "## Local paths",
    "",
    `- Mining output folder: ${literal(inventory.outputRoot)}`,
    `- Exact recovered artifacts: ${literal(path.join(inventory.outputRoot, "artifacts"))}`,
    `- Sensitive machine-readable inventory: ${literal(path.join(inventory.outputRoot, "inventory-sensitive.json"))}`,
    `- Redacted manifest: ${literal(path.join(inventory.outputRoot, "manifest-redacted.json"))}`,
    `- Scanned roots: ${inventory.inputRoots.map(literal).join(", ")}`,
    "",
    "## Cryptocurrency and wallet findings",
    "",
    `- Direct key or seed findings: ${wallet.direct}`,
    `- Wallet or keystore container findings: ${wallet.containers}`,
    `- Total cryptocurrency-related unique findings: ${wallet.total}`,
    `- Result: ${walletResult(inventory, wallet.total, false)}`,
    "",
    "## Credential categories and possible access",
    "",
    ...categoryTable(inventory.findings),
    "",
    "## Finding locations",
    "",
  ];

  if (inventory.findings.length === 0) lines.push("No validated findings were recorded.", "");
  for (const finding of inventory.findings) {
    const id = `finding-${String(finding.id).padStart(6, "0")}`;
    lines.push(
      `### ${id} — ${cell(finding.category)}`,
      "",
      `- What it may provide: ${accessSummary(finding.category)}`,
      `- Confidence: ${finding.confidence}`,
      `- Validation: ${finding.validation.method}`,
      `- SHA-256 fingerprint: ${literal(finding.sha256)}`,
      `- Recovered bytes: ${finding.bytes}`,
      `- Exact local artifact files: ${finding.artifactFiles.length === 0 ? "none (marker only)" : finding.artifactFiles.map((filename) => literal(path.join(inventory.outputRoot, filename))).join(", ")}`,
      "- Source locations:",
      ...finding.occurrences.map((occurrence) => `  - ${literal(occurrence.sourcePath)}, byte offset ${occurrence.offset}, length ${occurrence.length}, provenance ${occurrence.provenance}`),
      "",
    );
  }
  lines.push("## Scan errors", "");
  if (inventory.errors.length === 0) lines.push("No scan errors were recorded.", "");
  for (const error of inventory.errors) {
    lines.push(`- ${literal(error.sourcePath)} during ${literal(error.operation)}: ${literal(error.message)}`);
  }
  if (inventory.errorsOmitted > 0) lines.push(`- ${inventory.errorsOmitted} additional errors were omitted to keep the inventory bounded.`);
  if (inventory.errors.length > 0) lines.push("");
  lines.push(
    "## Interpretation",
    "",
    "A structural match does not prove that an account is active, a wallet is funded, or a recovered credential has not already been exposed. A zero count does not rule out unsupported, encrypted, fragmented, corrupted, or physically overwritten material. Keep this report and its artifacts offline. For wallets, independently derive the expected public address and sweep assets to a newly generated wallet rather than continuing to use recovered keys.",
    "",
    "Exact values are preserved in the artifact files listed above; they are intentionally not duplicated into this report.",
    "",
  );
  return lines.join("\n");
}

export function renderMiningRedactedReport(inventory: SensitiveScanInventory, progress: MiningProgress): string {
  const wallet = walletSummary(inventory.findings);
  return [
    "# Sensitive-material mining final report (redacted)",
    "",
    "> This report omits recovered values, source paths, artifact paths, byte offsets, fingerprints, and sensitive metadata. Category names can still be sensitive.",
    "",
    `- Status: ${inventory.status}`,
    `- Generated: ${inventory.updatedAt}`,
    `- Regular files visited: ${progress.filesVisited}`,
    `- Files scanned successfully: ${progress.filesScanned}`,
    `- Bytes scanned: ${progress.bytesScanned}`,
    `- Unique findings: ${inventory.findings.length}`,
    `- Occurrences: ${inventory.findings.reduce((sum, finding) => sum + finding.occurrences.length, 0)}`,
    `- Scan errors: ${inventory.errors.length + inventory.errorsOmitted}`,
    "",
    "## Cryptocurrency and wallet findings",
    "",
    `- Direct key or seed findings: ${wallet.direct}`,
    `- Wallet or keystore container findings: ${wallet.containers}`,
    `- Total cryptocurrency-related unique findings: ${wallet.total}`,
    `- Result: ${walletResult(inventory, wallet.total, true)}`,
    "",
    "## Credential categories and possible access",
    "",
    ...categoryTable(inventory.findings),
    "",
    "No online validity, account access, or wallet balance checks were performed.",
    "A zero count does not rule out unsupported, encrypted, fragmented, corrupted, or physically overwritten material.",
    "",
  ].join("\n");
}
