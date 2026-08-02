# Mining architecture

The mining layer is an offline scanner for local recovery outputs. It accepts regular files and directory trees, refuses known network-mounted inputs and outputs, does not follow symbolic links, and does not open network connections. It is designed for carved files, deleted-metadata exports, raw filesystem-unallocated streams, shadow-copy exports, and residual-memory files.

## Output contract

A scan writes three kinds of local output:

| Output | Contents | Handling |
| --- | --- | --- |
| `final-report-sensitive.md` | Human-readable wallet/credential summary, possible access, source locations, fingerprints, and exact artifact paths | Secret; mode `0600` |
| `final-report-redacted.md` | Human-readable counts, wallet result, categories, and possible access without local locations or identifiers | Shareable only after review; mode `0644` |
| `artifacts/finding-NNNNNN/` | Exact recovered values plus deterministic derived formats such as PKCS#8 | Secret; files are mode `0600` where supported |
| `inventory-sensitive.json` | Source paths, byte offsets, SHA-256 fingerprints, provenance, sensitive metadata, artifact mappings, and integrity hashes for every exact/derived artifact | Secret; mode `0600` |
| `manifest-redacted.json` | Aggregate counts, categories, validation methods, generic artifact IDs, and error counts | Values, paths, offsets, and fingerprints omitted |

“Redacted by default” applies to routine output and the shareable manifest, not the recovered artifacts. Exact bytes remain available to the owner for manual verification. `aark mine reveal <artifact>` is the only command that deliberately copies an artifact to stdout; it accepts only a file referenced by the finalized adjacent mining inventory and verifies its recorded size and SHA-256 hash before printing any bytes.

On completion, failure, or interruption after output initialization, the sensitive final report states the exact run status, whether cryptocurrency-related material was detected so far, separates direct keys/seeds from wallet or keystore containers, categorizes every credential type by possible access, and points to every exact artifact and source occurrence. It also lists local scan errors. The report does not duplicate secret values that already exist in the artifact files. Report generation is entirely local and deterministic. If the output itself becomes unsafe, substituted, or unwritable, report publication may be refused because writing there is no longer trustworthy.

The category counts in the redacted manifest can still reveal that a type of credential exists. Review even the redacted file before publishing it.

## Streaming behavior

Every file is scanned through 32 MiB chunks with a 17 MiB overlap by default. Files up to 64 MiB also receive a separate, bounded whole-file pass so complete containers and JSON formats can be validated. Seventeen MiB is the enforced minimum overlap because it covers the largest bounded streaming candidate (a DPAPI blob of up to 16 MiB) and therefore lets every built-in streaming format cross a chunk boundary without being lost. Adjust these values when necessary:

```bash
aark mine scan /case/recovery/unallocated/free-space.raw \
  --output /case/mining-unallocated \
  --provenance unallocated-stream \
  --chunk-mib 32 \
  --overlap-mib 17 \
  --whole-file-mib 128
```

Whole-file validation is capped at 256 MiB and streaming chunks at 128 MiB to keep accidental memory use bounded. Raising the whole-file limit is useful for unusually large browser databases or password vaults; it does not affect streaming detection of embedded keys and tokens.

The output directory must be new or empty, cannot be nested inside an input directory, and cannot be a filesystem mount root. Canonical duplicate or nested input roots are collapsed so a file is not scanned twice. An exclusive output lock prevents concurrent scans from racing in one result tree, and emptiness is rechecked while that lock is held. File identity, size, modification time, and change time are checked before and after streaming and again before whole-file validation; a mutation is recorded as an error instead of mixing different byte snapshots under one source location. An in-progress checkpoint is written every 25 visited files or 60 seconds. If a scan is interrupted, both final reports identify the interruption; preserve that output and rerun into a new directory because automatic in-place resume is not implemented yet.

Input-root identity and mount backing are revalidated while walking. The output directory, its mount, and the acquired lock are revalidated before sensitive writes and at streaming-window boundaries. A mount swap or disappearing lock fails the scan instead of silently redirecting exact artifacts.

### Deep expanded-key scan

For raw memory, hibernation, swap, or unallocated streams, `--deep-key-schedules` tests every byte position for a complete AES-128/192/256 encryption-key expansion recurrence and checks initialized ChaCha states. An AES match recovers the original key and preserves the full schedule as a derived artifact; a ChaCha match preserves the 64-byte state alongside its exact key bytes. This mode is CPU-intensive, so it is explicit rather than the unnoticed default. Its exhaustive pass is internally divided into overlapping 1 MiB slices with event-loop yields so cancellation and checkpoints are not blocked for an entire streaming window:

```bash
aark mine scan /case/recovery/residual-memory \
  --output /case/mining-aes \
  --provenance residual-memory \
  --deep-key-schedules
```

## Validation levels

- `authenticated`: an internal checksum, header hash, public/private consistency relationship, or parser round trip succeeded. It does not mean an online account was contacted.
- `high`: a complete, strongly structured format was parsed, but a password, HMAC, provider signature, or online state could not be verified.
- `medium`: a provider-specific shape or context-bound assignment passed entropy and placeholder checks.
- `marker-only`: a useful locator without enough bytes for a secret. Marker-only results are not exported as secret artifacts.

Provider tokens are never tested against their providers. JWT signatures are not verified without the issuer’s key. Encrypted containers are preserved even when their passwords are unknown.

## Built-in validator families

- PEM, OpenSSH, SSH2, PGP, PuTTY PPK, DER, age, OpenVPN, WireGuard, and Windows CNG private-key material;
- Windows DPAPI blobs, Chromium DPAPI wrappers, DPAPI master-key files, and RDP DPAPI properties;
- BIP-39 across ten standard wordlists, BIP-32/SLIP-132 extended private keys, Bitcoin WIF and Bitcoin-family Berkeley/SQLite wallet databases, Ethereum scalars and V3 keystores, Electrum, MetaMask, Solana, Stellar, XRP, and Tezos private formats;
- KeePass KDBX/XML, Password Safe v3, Bitwarden, 1Password OPVault, Java JKS, sensitive browser SQLite databases, Firefox login JSON, Docker auth files, Kubernetes credentials, cloud service accounts, and Windows WLAN keys;
- checksum-validated BitLocker recovery passwords, credential-bearing URLs, JWTs, provider-token shapes, and context-bound secret assignments.

Checksums and structure greatly reduce false positives, but they cannot prove that a recovered credential is current, uncompromised, or funded. A random 32-byte value is intentionally not labeled a private key unless a surrounding structure or key label supplies context.

## Provenance

Pass the provenance that actually produced each input. Do separate scans for separate sources if their provenance differs. `unallocated-stream` and `unallocated-carve` can establish that source clusters were unallocated at acquisition time; shadow copies and residual memory are historical but do not prove filesystem deletion.

## Handling recovered wallets

Treat every recovered private key or phrase as exposed. Inspect it offline, independently derive expected public addresses, and move funds to a newly generated wallet from a trusted environment. Do not paste recovered material into a website, support chat, issue, AI tool, or internet-connected “balance checker.”
