# AARK

AARK (Agentic Artifact Recovery Kit) is an offline-first toolkit for recovering deleted data from disks and then mining the recovered material for private keys, cryptographic material, password-manager databases, wallet artifacts, and credentials.

Its reviewed plans, bounded commands, structured manifests, resumable checkpoints, and deterministic reports are designed for both direct human operation and fully delegated agentic workflows. The current implementation remains fully local and does not bundle an autonomous agent. See [AGENTS.md](AGENTS.md) for the recommended authorization and automation contract.

The project is deliberately split into three layers:

1. `recover` orchestrates mature Linux forensic tools against a read-only source and records provenance.
2. `mine` scans recovered files or unallocated-space streams, strictly validates candidate structures, and stores sensitive values without printing them.
3. `cleanup` proves that selected recovery copies were completely scanned, then can remove those copies while retaining final reports, exact findings, and their integrity metadata.

> [!CAUTION]
> Use this only on media and data you own or are authorized to examine. Never recover back onto the source disk. SSD TRIM, overwrite, fragmentation, encryption, and filesystem reuse make “recover everything” impossible to guarantee.

## Why this shape?

Node.js is a good fit for orchestration, streaming scans, manifests, validation, and a cross-tool CLI. It is not a good replacement for years of filesystem and forensic work in GNU ddrescue, The Sleuth Kit, TestDisk/PhotoRec, libvshadow, dislocker, bulk_extractor, or Impacket. AARK calls those projects with argument arrays instead of shell strings and keeps their output behind a consistent, auditable case layout.

No telemetry, LLM/API integration, cloud validation, or network lookup is performed by the CLI. Recovered secret values never leave the machine.

## Requirements

- Ubuntu or a compatible Linux distribution
- Node.js 22.12 or newer
- Root access for raw block-device work
- A separate destination disk with enough free space

Install the optional forensic engines you need:

```bash
sudo apt update
sudo apt install gddrescue testdisk sleuthkit ntfs-3g \
  libvshadow-utils dislocker libregfi-utils sqlite3 python3-impacket
```

`bulk_extractor` is optional and may need to be built from its upstream source if your Ubuntu release does not package it.

## Install from source

```bash
git clone https://github.com/ga-nyc/aark.git
cd aark
npm ci
npm run build
npm link
aark doctor
```

The legacy `agetnic` and `agetnic-tools` executable names remain available as compatibility aliases. New scripts should use `aark`.

## Quick start

An authorized person or agent can run the complete workflow. First inventory the machine without changing anything:

```bash
aark recover inventory --json
```

Create a case configuration and review its execution plan:

```bash
cp examples/recovery-case.example.json recovery-case.json
aark recover plan --config recovery-case.json
```

The generated plan defaults to dry-run behavior. Execution requires both a configuration that says `execute: true` and an explicit CLI confirmation flag:

```bash
sudo aark recover run --config recovery-case.json --execute
```

Mine one or more recovered directories. Detector work automatically uses up to four bounded worker threads, while the main thread retains verification and artifact ownership:

```bash
aark mine scan /mnt/recovery/case-001/recovered \
  --output /mnt/recovery/case-001/sensitive-mining \
  --provenance unallocated-carve \
  --min-free-gib 5 \
  --min-free-percent 5
```

`SIGINT`, `SIGTERM`, the free-space reserve, and an optional `--max-output-gib` cap produce a clean mining pause at a committed chunk boundary. A paused command returns JSON with `resumable: true` and exits `75`; preserve the output and use its `resumeCommand`:

```bash
aark mine resume --output /mnt/recovery/case-001/sensitive-mining
```

Recovery also checks the configured reserve while external engines run. A ddrescue quota pause is safely resumable from its mapfile and exits `75`; a quota stop in an engine without a trustworthy resume protocol is reported as a failure.

After every intended recovery folder has an error-free `complete` mining result, build a read-only cleanup plan. Supply every mining output needed to cover the files selected for deletion:

```bash
aark cleanup plan /mnt/recovery/case-001/sensitive-mining \
  --case /mnt/recovery/case-001
```

The path-redacted JSON gives aggregate filesystem-entry, regular-file, and byte counts, the number of marker-only locations without exported artifacts, and an approval token. Marker-only locations must be reviewed locally before cleanup. An agent must show that plan to the end user and ask whether to perform the irreversible cleanup; case-wide recovery authorization is not deletion approval. Only after the user agrees, run the unchanged plan with all three gates:

```bash
aark cleanup run /mnt/recovery/case-001/sensitive-mining \
  --case /mnt/recovery/case-001 \
  --approval-token <TOKEN_FROM_PLAN> \
  --execute \
  --confirm-delete-recovered-copy
```

This removes the AARK-managed `recovery/`, `logs/`, and `runs/` directories. It retains the root final reports and manifests plus each complete mining output, including exact artifacts, final reports, `inventory-sensitive.json`, and the frozen integrity/checkpoint files. The `evidence/` image is retained by default. Planning evidence deletion requires `--include-evidence`; execution then additionally requires `--confirm-delete-evidence`. See [Cleanup workflow](docs/cleanup.md).

The output contains:

- `final-report-sensitive.md`: the human-readable local answer—whether wallet material was found, credential categories, possible access, source locations, and exact artifact paths.
- `final-report-redacted.md`: the same aggregate conclusions without values, source paths, offsets, hashes, or artifact paths.
- `manifest-redacted.json`: counts, validation methods, confidence, generic finding IDs, and artifact counts; no values, source paths, offsets, hashes, or artifact paths.
- `inventory-sensitive.json`: source paths, offsets, fingerprints, artifact mappings, and size/SHA-256 integrity records for every exact and derived artifact. Treat it as secret.
- `scan-state-sensitive.json` and `scan-files-sensitive.ndjson`: integrity-linked resume state and the frozen, deterministic input manifest. Treat both as secret and do not modify them.
- `artifacts/`: exact, unredacted recovered values for local inspection, written with restrictive permissions where the filesystem supports them.

The recovery layer writes the same pair of final-report filenames at the case root. Its sensitive report records the restored-data folder, source and destination devices, stage status, provenance, and per-stage output locations. Reports are produced by deterministic local code; their content is not sent to an LLM or remote service.

Use `aark mine reveal <artifact>` when you intentionally want a validated artifact printed locally. It first checks that the file is referenced by a finalized adjacent inventory and still matches its recorded size and SHA-256 hash. The explicit reveal command is never invoked by a scan and its output is never copied into a log. Inventories created under the former `agetnic-tools` name remain supported.

## Recovery stages

The recovery planner can compose these stages:

- evidence imaging with GNU ddrescue and a resumable mapfile;
- deleted-metadata recovery with The Sleuth Kit (`fls`, `tsk_recover`) and NTFS `ntfsundelete`;
- unallocated-space extraction with `blkls`;
- signature carving with PhotoRec against the `blkls` unallocated-only stream, never the allocated source;
- Volume Shadow Copy inspection with libvshadow;
- BitLocker/dislocker availability inventory and safe read-only workflow guidance (credential-bearing mount commands are deliberately not automated);
- residual-memory scanning with bulk_extractor;
- deleted registry-cell recovery with reglookup tools.

See [Recovery architecture](docs/recovery.md) for source-safety rules and provenance labels.

## Mining coverage

The Node mining layer currently recognizes or validates:

- parseable PEM private keys and complete encrypted PEM blocks;
- PGP, OpenSSH, SSH2, PuTTY PPK, and age private-key structures;
- Windows DPAPI blobs and Chromium `encrypted_key` wrappers;
- Windows CNG RSA, ECC, and symmetric key blobs, including public/private consistency checks;
- opt-in memory recovery of AES-128/192/256 keys from complete expanded schedules and initialized ChaCha states;
- checksum-valid BIP-39 phrases in supported wordlists;
- Base58Check-valid BIP-32/SLIP-132 extended private keys and Bitcoin WIF keys;
- context-bound Ethereum private scalars, Ethereum V3 keystores, Electrum wallets, and MetaMask vaults;
- Solana, Stellar, XRP, and Tezos private-key formats;
- Bitcoin-family Berkeley/SQLite wallet databases, KeePass KDBX/XML, Password Safe v3, Bitwarden/1Password exports, and Java JKS structures;
- BitLocker recovery passwords;
- common provider-token shapes, JWTs, credential-bearing URLs, and strict secret assignments;
- TLS/NSS key-log secrets for offline traffic decryption;
- Chromium, Firefox, Wi-Fi, RDP, Kubernetes, Docker, cloud-service-account, and VPN markers.

Shape validation does not prove that an online credential is active. The tool intentionally does not test recovered credentials against providers.

## Safety and interpretation

- Block-device sources must report read-only unless the case explicitly opts out. Opting out is strongly discouraged.
- Commands are spawned without a shell. Credentials are never accepted as command-line arguments.
- Agents may plan, execute, monitor, pause, and resume a case after explicit case-wide authorization; they should consume redacted aggregates and must not place recovered values or sensitive control files into model context. Cleanup is the exception: an agent may build its read-only plan, but must present it and obtain fresh end-user approval before deleting anything.
- PhotoRec and raw carving can recover fragments and false positives. The miner separates marker-only, structurally valid, cryptographically consistent, and authenticated findings.
- Shadow-copy and hibernation artifacts can be historical or stale, but are not automatically labeled filesystem-deleted.
- FAT/exFAT cannot enforce Unix `0600` permissions. Physically secure removable destinations or use an encrypted Linux filesystem.
- Never import a recovered wallet key or seed into software on an internet-connected machine before assessing exposure. Prefer sweeping funds to a newly generated wallet from a trusted offline environment.

See [Security model](SECURITY.md), [data flow and failure behavior](docs/data-flow.md), [Recovery architecture](docs/recovery.md), [Mining architecture](docs/mining.md), [Cleanup workflow](docs/cleanup.md), the [OSS adapter matrix](docs/translation-matrix.md), and the [optional DPAPI bridge](docs/optional-dpapi.md).

## Project status

This is an early forensic toolkit. Review every plan before execution and retain original images and tool logs until recovery and scanning have been validated. Remove the managed recovered copy only through the separately approved cleanup workflow. Contributions that add deterministic validators, new read-only adapters, or synthetic tests are welcome.

The planned next layer is optional, offline OCR over recovered screenshots to locate candidate secrets, keys, and cryptocurrency material. It is not implemented yet; when added, it will preserve AARK's local-only processing, provenance, validation, and redaction boundaries.

## Usage rights

No software license is granted by this repository. All rights are reserved by `ga-nyc`. Contact the owner before copying, modifying, distributing, using commercially, or using the project without attribution.
