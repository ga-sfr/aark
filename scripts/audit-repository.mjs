import { lstatSync, readFileSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const listing = spawnSync("git", ["ls-files", "--cached", "--others", "--exclude-standard", "-z"], {
  encoding: "utf8",
  shell: false,
});
if (listing.status !== 0) throw new Error("git file inventory failed");

const files = listing.stdout.split("\0").filter(Boolean);
const failures = [];
const forbiddenNames = [
  /(?:^|\/)\.codex(?:\/|$)/i,
  /(?:^|\/)\.env(?:\.|$)/i,
  /(?:^|\/)[^/]*sensitive[^/]*\.(?:bin|csv|json|log|md|txt)$/i,
  /(?:^|\/)inventory-sensitive\.json$/i,
  /(?:^|\/)case-sensitive\.json$/i,
  /(?:^|\/)\.agetnic-(?:recovery|mining)\.lock$/i,
  /(?:^|\/)(?:final-report-(?:sensitive|redacted)\.md|manifest-redacted\.json|plan-redacted\.json)$/i,
  /(?:^|\/)[^/]*final-report-(?:sensitive|redacted)\.md$/i,
  /(?:^|\/)[^/]*manifest-redacted\.json$/i,
  /(?:^|\/)artifacts\//i,
  /(?:^|\/)(?:LICENSE|LICENCE|COPYING|UNLICENSE)(?:\.[^/]*)?$/i,
  /(?:^|\/)(?:\.npmrc|\.pypirc|\.netrc|kubeconfig|wallet\.dat|Login Data|Local State|key4\.db|logins\.json)$/i,
  /\.(?:pem|key|p12|pfx|jks|kdbx|psafe3|wallet|seed|mnemonic|dpapi|masterkey)$/i,
  /\.(?:bin|der|ppk|sqlite|db)$/i,
  /\.(?:img|dd|raw|e01|vhdx?|qcow2|dmp|mem|hiber)$/i,
];
const privateKeyArmor = new RegExp([
  "-----BEGIN ",
  "(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?",
  "PRIVATE",
  " KEY-----",
].join(""));
const pgpPrivateKeyArmor = new RegExp([
  "-----BEGIN PGP ",
  "PRIVATE",
  " KEY BLOCK-----\\r?\\n",
  "(?:[A-Za-z-]+:[^\\r\\n]*\\r?\\n)*",
  "\\r?\\n?[A-Za-z0-9+/=\\r\\n]{32,}",
  "-----END PGP ",
  "PRIVATE",
  " KEY BLOCK-----",
].join(""));
const forbiddenContent = [
  ["private-key armor", privateKeyArmor],
  ["PGP private-key armor", pgpPrivateKeyArmor],
  ["age secret key", /AGE-SECRET-KEY-1[0-9A-Z]{58}/],
  ["GitHub token", /(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})/],
  ["provider token", /(?:glpat-|npm_|pypi-|xox[baprs]-|sk_live_|dop_v1_)[A-Za-z0-9_-]{20,}/],
  ["AWS secret assignment", /aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+]{40}/i],
  ["credential-bearing URL", /(?:https?|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s/:]+:[^\s/@]+@/i],
  ["global Codex path", /\/home\/ubuntu\/\.codex\//],
  ["GitHub PAT assignment", /GH_PAT\s*=/],
];
const runtimeNetworkApi = /(?:(?:from|import|require\s*\()\s*["'](?:(?:node:)?(?:http|https|http2|net|tls|dgram|dns)|axios|got|undici|node-fetch)\b|(?:^|\n)\s*(?:from|import)\s+(?:requests|httpx|aiohttp|socket|urllib|ftplib|smtplib|imaplib|paramiko|boto3)\b|\b(?:globalThis\.)?fetch\s*\(|\bnew\s+(?:WebSocket|EventSource)\s*\()/;
const runtimeNetworkCommand = /(?:(?:spawn|spawnSync|execFile|execFileSync)\s*\(\s*["'`](?:curl|wget|ftp|sftp|ssh|scp|nc|ncat|socat|rclone|aws|gcloud|az)["'`]|subprocess\.(?:run|Popen|call|check_call|check_output)\s*\(\s*(?:\[\s*)?["'](?:curl|wget|ftp|sftp|ssh|scp|nc|ncat|socat|rclone|aws|gcloud|az)["'])/;

for (const filename of files) {
  const normalized = filename.split(path.sep).join("/");
  for (const expression of forbiddenNames) {
    if (expression.test(normalized)) failures.push(`${normalized}: forbidden sensitive filename`);
  }
  const metadata = lstatSync(filename);
  if (metadata.isSymbolicLink()) {
    failures.push(`${normalized}: repository symbolic links are not allowed`);
    continue;
  }
  if (!metadata.isFile()) {
    failures.push(`${normalized}: repository entry is not a regular file`);
    continue;
  }
  const data = readFileSync(filename);
  if (data.length > 5 * 1024 * 1024) failures.push(`${normalized}: repository file exceeds 5 MiB review limit`);
  const text = data.toString("latin1");
  if ((normalized.startsWith("src/") || normalized.startsWith("optional/")) && /\.(?:[cm]?[jt]s|py)$/i.test(normalized) && runtimeNetworkApi.test(text)) {
    failures.push(`${normalized}: runtime network API is forbidden by the offline execution contract`);
  }
  if ((normalized.startsWith("src/") || normalized.startsWith("optional/")) && /\.(?:[cm]?[jt]s|py)$/i.test(normalized) && runtimeNetworkCommand.test(text)) {
    failures.push(`${normalized}: runtime network command is forbidden by the offline execution contract`);
  }
  for (const [label, expression] of forbiddenContent) {
    if (expression.test(text)) failures.push(`${normalized}: possible ${label}`);
  }
}

if (failures.length > 0) {
  process.stderr.write(`${failures.join("\n")}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write(`repository audit passed (${files.length} files; no forbidden fixtures, local paths, license file, runtime network code, or high-confidence secret shapes)\n`);
}
