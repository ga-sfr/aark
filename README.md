# Agetnic Tools

Reusable, offline-first tools for recovering deleted data from disks and then mining the recovered material for private keys, cryptographic material, password-manager databases, wallet artifacts, and credentials.

The project is deliberately split into two layers:

1. `recover` orchestrates mature Linux forensic tools against a read-only source and records provenance.
2. `mine` scans recovered files or unallocated-space streams, strictly validates candidate structures, and stores sensitive values without printing them.

> [!CAUTION]
> Use this only on media and data you own or are authorized to examine. Never recover back onto the source disk. SSD TRIM, overwrite, fragmentation, encryption, and filesystem reuse make “recover everything” impossible to guarantee.

## Why this shape?

Node.js is a good fit for orchestration, streaming scans, manifests, validation, and a cross-tool CLI. It is not a good replacement for years of filesystem and forensic work in GNU ddrescue, The Sleuth Kit, TestDisk/PhotoRec, libvshadow, dislocker, bulk_extractor, or Impacket. Agetnic Tools calls those projects with argument arrays instead of shell strings and keeps their output behind a consistent, auditable case layout.

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
git clone https://github.com/ga-nyc/agetnic-tools.git
cd agetnic-tools
npm ci
npm run build
npm link
agetnic doctor
```

## Quick start

First inventory the machine without changing anything:

```bash
agetnic recover inventory --json
```

Create a case configuration and review its execution plan:

```bash
cp examples/recovery-case.example.json recovery-case.json
agetnic recover plan --config recovery-case.json
```

The generated plan defaults to dry-run behavior. Execution requires both a configuration that says `execute: true` and an explicit CLI confirmation flag:

```bash
sudo agetnic recover run --config recovery-case.json --execute
```

Mine one or more recovered directories:

```bash
agetnic mine scan /mnt/recovery/case-001/recovered \
  --output /mnt/recovery/case-001/sensitive-mining \
  --provenance unallocated-carve
```

The output contains:

- `final-report-sensitive.md`: the human-readable local answer—whether wallet material was found, credential categories, possible access, source locations, and exact artifact paths.
- `final-report-redacted.md`: the same aggregate conclusions without values, source paths, offsets, hashes, or artifact paths.
- `manifest-redacted.json`: counts, validation methods, confidence, and generic artifact paths; no values, source paths, offsets, or hashes.
- `inventory-sensitive.json`: source paths, offsets, fingerprints, artifact mappings, and size/SHA-256 integrity records for every exact and derived artifact. Treat it as secret.
- `artifacts/`: exact, unredacted recovered values for local inspection, written with restrictive permissions where the filesystem supports them.

The recovery layer writes the same pair of final-report filenames at the case root. Its sensitive report records the restored-data folder, source and destination devices, stage status, provenance, and per-stage output locations. Reports are produced by deterministic local code; their content is not sent to an LLM or remote service.

Use `agetnic mine reveal <artifact>` when you intentionally want a validated artifact printed locally. It first checks that the file is referenced by a finalized adjacent inventory and still matches its recorded size and SHA-256 hash. The explicit reveal command is never invoked by a scan and its output is never copied into a log.

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
- PhotoRec and raw carving can recover fragments and false positives. The miner separates marker-only, structurally valid, cryptographically consistent, and authenticated findings.
- Shadow-copy and hibernation artifacts can be historical or stale, but are not automatically labeled filesystem-deleted.
- FAT/exFAT cannot enforce Unix `0600` permissions. Physically secure removable destinations or use an encrypted Linux filesystem.
- Never import a recovered wallet key or seed into software on an internet-connected machine before assessing exposure. Prefer sweeping funds to a newly generated wallet from a trusted offline environment.

See [Security model](SECURITY.md), [data flow and failure behavior](docs/data-flow.md), [Mining architecture](docs/mining.md), the [OSS adapter matrix](docs/translation-matrix.md), and the [optional DPAPI bridge](docs/optional-dpapi.md).

## Project status

This is an early forensic toolkit. Review every plan before execution and retain original images and tool logs. Contributions that add deterministic validators, new read-only adapters, or synthetic tests are welcome.

## Usage rights

No software license is granted by this repository. All rights are reserved by `ga-nyc`. Contact the owner before copying, modifying, distributing, using commercially, or using the project without attribution.
