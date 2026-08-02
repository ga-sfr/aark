# Security model

## Authorized use only

AARK is intended for recovery from media and accounts you own or are explicitly authorized to examine. It is not an endpoint collection agent and does not include remote acquisition, persistence, credential testing, or exfiltration features.

An authorized software agent may operate AARK without an interactive human approval at every recovery or mining step. The authorization must be established before execution and bound the source, destination, stages, privilege level, quotas, and any permission to reveal exact values. [AGENTS.md](AGENTS.md) defines the recommended delegated workflow. Agent operation does not relax any source, destination, offline, or redaction control. Destructive cleanup always requires a fresh end-user decision after its final aggregate plan is available.

## Non-negotiable defaults

- Sources are opened read-only.
- By default, a writable mount of a block-device source is treated as a preflight failure; the explicit opt-out is strongly discouraged.
- Recovery output must be a different path and should be on a different physical device.
- External programs are spawned with argument arrays and `shell: false`.
- External programs use a fixed system executable path rather than inheriting project or user-writable `PATH` entries.
- External programs receive fixed locale/terminal values, no inherited shell, timezone, token, or credential variables, and a private case-local temporary directory during recovery.
- Recovery and mining hold both current and legacy compatibility locks so an older installed build cannot race a renamed AARK operation. Recovery engines run from a private directory on the case destination, not from the operator's current directory; cancellation targets their isolated process group, and leftover descendants are killed even after a normal parent exit.
- Scans never print secret values or place them in routine logs or redacted manifests.
- Online credential validation and telemetry are absent.
- No LLM, AI service, remote API, or upload integration receives recovered data.
- Orchestrating agents should consume command JSON and redacted reports. They must not open or inject sensitive reports, resume state, manifests, logs, recovery outputs, or artifacts into a hosted model context.
- Recovery, mining, and the optional DPAPI bridge refuse known network-mounted inputs and outputs such as NFS, SMB, SSHFS, cloud-backed FUSE mounts, NBD, RBD, DRBD, iSCSI, FCoE, AoE, and TCP/RDMA block transports. Layered FUSE types whose backing store cannot be proven from the mount record, including bindfs, mergerfs, encfs, and unionfs, fail closed as potentially remote.
- Symlinks are not followed during mining unless future code adds an explicit, reviewed option.
- Cleanup is never automatic. Its run command requires an unchanged approval token, `--execute`, and `--confirm-delete-recovered-copy`; evidence deletion has a separate opt-in and confirmation.

## Sensitive output

`final-report-sensitive.md`, `cleanup-final-report-sensitive.md`, `inventory-sensitive.json`, `scan-state-sensitive.json`, `scan-files-sensitive.ndjson`, tool logs, raw contexts, and every file under `artifacts/` should be handled as credentials. Artifact files contain the exact unredacted values so the operator can inspect and use their own recovered material. The sensitive final report locates those files and source occurrences without needlessly duplicating every value. The CLI attempts mode `0600` for sensitive files and `0700` for directories. FAT and exFAT do not enforce those permissions; use encrypted storage or physically secure the destination.

The redacted manifest and `final-report-redacted.md` omit source paths, byte offsets, hashes, token values, key identities, certificate subjects, mnemonic text, and local artifact paths. Category counts can still be sensitive. Both final reports are rendered by local deterministic code; no LLM or remote service receives report or evidence content.

`aark mine reveal` is the only built-in command that intentionally writes an artifact value to stdout. It requires an explicit artifact path under `artifacts/finding-NNNNNN/`, rejects hard-linked files, verifies that a finalized adjacent inventory references the file, checks its recorded size and SHA-256 hash before emitting bytes, and is never called by scanning or reporting code.

Normal CLI errors redact local paths. `AARK_SENSITIVE_DEBUG=1` is an explicit local troubleshooting override and must never be enabled in shared logs, CI, or support transcripts. `AGETNIC_SENSITIVE_DEBUG=1` remains accepted as a deprecated compatibility alias.

## Destructive cleanup

`aark cleanup plan` performs no deletion. It accepts only a completed recovery case and error-free mining outputs, requires retained recovery controls and reports to match their completed per-run copies, verifies the state/inventory cross-checkpoint, hashes every retained artifact and retained control/report, re-enumerates each frozen mining input, and proves that the union of those inputs covers every regular file in the selected `recovery/` and optional `evidence/` trees. Its approval token binds the case identity, recovery run, retained control/report hashes, scan checkpoints, every selected directory/file/link/special entry and its metadata, aggregate counts, and evidence choice.

`aark cleanup run` acquires both current and legacy recovery/mining locks, repeats all verification, and rejects a stale token before writing a deletion report. It deletes only the case's fixed `recovery/`, `logs/`, and `runs/` children, plus `evidence/` when separately approved. Each target is first atomically moved to an unpredictable case-local quarantine and fully reverified there, preventing a raced path replacement from being recursively deleted. Mining output directories may not overlap any deletion target. Case-root final reports/manifests and complete mining outputs—including `artifacts/`, the sensitive inventory, frozen scan manifest, and scan state—are retained. Those control files are necessary to locate, verify, and intentionally reveal an artifact after the source copy is gone.

Deletion is irreversible and cannot guarantee secure erasure from SSDs, copy-on-write filesystems, snapshots, backups, or storage-controller caches. A crash or filesystem error can leave a partially removed `.aark-cleanup-pending-*` tree; the cleanup report is written as `authorized-in-progress` first and updated to `failed-partial`, `interrupted-partial`, or `complete` when possible. AARK refuses another cleanup while that quarantine exists. Do not remove it, remove a stale operation lock, or retry a partial cleanup until the local state and mounted filesystems have been inspected.

## Wallet recovery

Assume any recovered seed or private key may already have been exposed. Do not type it into a website or an internet-connected password form. Use a trusted offline environment, verify addresses independently, and sweep assets to a newly generated wallet rather than continuing to use the recovered key.

## Reporting vulnerabilities

Do not open a public issue containing a real key, credential, disk image, source path, or sensitive log. Open a minimal issue without the secret and ask the maintainers for a private disclosure channel.
