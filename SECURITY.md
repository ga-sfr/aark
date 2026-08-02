# Security model

## Authorized use only

AARK is intended for recovery from media and accounts you own or are explicitly authorized to examine. It is not an endpoint collection agent and does not include remote acquisition, persistence, credential testing, or exfiltration features.

## Non-negotiable defaults

- Sources are opened read-only.
- By default, a writable mount of a block-device source is treated as a preflight failure; the explicit opt-out is strongly discouraged.
- Recovery output must be a different path and should be on a different physical device.
- External programs are spawned with argument arrays and `shell: false`.
- External programs use a fixed system executable path rather than inheriting project or user-writable `PATH` entries.
- External programs receive fixed locale/terminal values, no inherited shell, timezone, token, or credential variables, and a private case-local temporary directory during recovery.
- Recovery engines run from a private directory on the case destination, not from the operator's current directory, and cancellation targets their isolated process group including descendants.
- Scans never print secret values or place them in routine logs or redacted manifests.
- Online credential validation and telemetry are absent.
- No LLM, AI service, remote API, or upload integration receives recovered data.
- Recovery, mining, and the optional DPAPI bridge refuse known network-mounted inputs and outputs such as NFS, SMB, SSHFS, cloud-backed FUSE mounts, NBD, RBD, DRBD, iSCSI, FCoE, AoE, and TCP/RDMA block transports.
- Symlinks are not followed during mining unless future code adds an explicit, reviewed option.

## Sensitive output

`final-report-sensitive.md`, `inventory-sensitive.json`, tool logs, raw contexts, and every file under `artifacts/` should be handled as credentials. Artifact files contain the exact unredacted values so the operator can inspect and use their own recovered material. The sensitive final report locates those files and source occurrences without needlessly duplicating every value. The CLI attempts mode `0600` for sensitive files and `0700` for directories. FAT and exFAT do not enforce those permissions; use encrypted storage or physically secure the destination.

The redacted manifest and `final-report-redacted.md` omit source paths, byte offsets, hashes, token values, key identities, certificate subjects, mnemonic text, and local artifact paths. Category counts can still be sensitive. Both final reports are rendered by local deterministic code; no LLM or remote service receives report or evidence content.

`aark mine reveal` is the only built-in command that intentionally writes an artifact value to stdout. It requires an explicit artifact path under `artifacts/finding-NNNNNN/`, rejects hard-linked files, verifies that a finalized adjacent inventory references the file, checks its recorded size and SHA-256 hash before emitting bytes, and is never called by scanning or reporting code.

Normal CLI errors redact local paths. `AARK_SENSITIVE_DEBUG=1` is an explicit local troubleshooting override and must never be enabled in shared logs, CI, or support transcripts. `AGETNIC_SENSITIVE_DEBUG=1` remains accepted as a deprecated compatibility alias.

## Wallet recovery

Assume any recovered seed or private key may already have been exposed. Do not type it into a website or an internet-connected password form. Use a trusted offline environment, verify addresses independently, and sweep assets to a newly generated wallet rather than continuing to use the recovered key.

## Reporting vulnerabilities

Do not open a public issue containing a real key, credential, disk image, source path, or sensitive log. Open a minimal issue without the secret and ask the maintainers for a private disclosure channel.
