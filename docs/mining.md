# Mining architecture

The mining layer is an offline scanner for local recovery outputs. It accepts regular files and directory trees, refuses known network-mounted inputs and outputs, does not follow symbolic links, and does not open network connections. It is designed for carved files, deleted-metadata exports, raw filesystem-unallocated streams, shadow-copy exports, and residual-memory files. An authorized agent may run and resume it without human interaction; the safe automation contract is in [AGENTS.md](../AGENTS.md).

Mining supports Ubuntu-compatible Linux and native Windows 10/11. Windows
inputs and outputs must be on local drive-letter volumes; UNC paths, mapped
network drives, and paths absent from the local volume-manager inventory are
rejected. AARK obtains mount points from the fixed system `mountvol.exe` and
binds each reachable protected path to Node's exact volume identity. It stores
exact 64-bit Windows file identities as decimal strings when they cannot be
represented safely as JavaScript numbers.
The Windows open-handle check compares that exact identity with the authorized
path before publishing findings and after processing. Linux retains the
stronger `/proc/self/fd` handle-to-canonical-path check.

## Output contract

A scan writes these related local outputs:

| Output | Contents | Handling |
| --- | --- | --- |
| `final-report-sensitive.md` | Human-readable wallet/credential summary, possible access, source locations, fingerprints, and exact artifact paths | Secret; mode `0600` |
| `final-report-redacted.md` | Human-readable counts, wallet result, categories, and possible access without local locations or identifiers | Shareable only after review; mode `0644` |
| `artifacts/finding-NNNNNN/` | Exact recovered values plus deterministic derived formats such as PKCS#8 | Secret; files are mode `0600` where supported |
| `inventory-sensitive.json` | Source paths, byte offsets, SHA-256 fingerprints, provenance, sensitive metadata, artifact mappings, and integrity hashes for every exact/derived artifact | Secret; mode `0600` |
| `scan-state-sensitive.json` | Semantic options, operational settings, committed cursor, progress, and hashes of the frozen manifest and inventory | Secret; mode `0600`; do not edit |
| `scan-files-sensitive.ndjson` | Deterministically ordered, frozen identity/size/time snapshot for every input file | Secret; mode `0600`; do not edit |
| `manifest-redacted.json` | Aggregate counts, categories, validation methods, generic artifact IDs, and error counts | Values, paths, offsets, and fingerprints omitted |

“Redacted by default” applies to routine output and the shareable manifest, not the recovered artifacts. Exact bytes remain available to the owner for manual verification. `aark mine reveal <artifact>` is the only command that deliberately copies an artifact to stdout; it accepts only a file referenced by the finalized adjacent mining inventory and verifies its recorded size and SHA-256 hash before printing any bytes.

On completion, clean pause, or failure after output initialization, the sensitive final report states the exact run status, whether cryptocurrency-related material was detected so far, separates direct keys/seeds from wallet or keystore containers, categorizes every credential type by possible access, and points to every exact artifact and source occurrence. It also lists local scan errors. The report does not duplicate secret values that already exist in the artifact files. Report generation is entirely local and deterministic. If the output itself becomes unsafe, substituted, or unwritable, report publication may be refused because writing there is no longer trustworthy.

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

Before each sensitive artifact write, AARK verifies the exact output-directory and exclusive-lock identities through their live filesystem identities. It also re-enumerates and validates input/output mount topology periodically and before checkpoints. This keeps path substitution checks on the write path without making every finding invoke an expensive operating-system mount inventory.

Very large raw files can contain enough distinct validated material to reach the intentionally bounded per-run finding or occurrence limits. `scripts/scan-large-file-sharded.mjs` copies one bounded byte range at a time to a separate staging filesystem, scans that range with the normal mining command, records a sensitive source-identity/range/hash map, and removes only the temporary range after its scan completes without errors. Its redacted coverage report proves aggregate byte coverage without exposing the source path or hashes. Keep the sensitive controller state with every shard output; it is required to map shard-relative offsets back to the original file and to justify later cleanup of that original.

Pure detector families run in a bounded `worker_threads` pool. `--workers` accepts `1` through `4`; the default is the number of available CPUs minus one, bounded to that range. The four streaming families are fused into one request per source buffer, so the buffer is copied to a worker once while each detector keeps its own candidate, byte, and structural-validation limits. A complete small file also runs structured validation in that request.

For non-deep files that fit both one stream chunk and the configured whole-file limit, the scanner keeps up to `workers` files in flight under a hard 64 MiB aggregate source-buffer budget. Reads and pure worker execution may finish out of order, but the main thread validates the still-open descriptor and canonical path, verifies candidate bytes, commits findings/IDs/artifacts, updates the resumable cursor, and closes each file strictly in frozen-manifest order. A slow early file therefore applies bounded backpressure. Large-file windows use the same fused streaming request; deep scans keep their dedicated overlapping 1 MiB schedule slices. When a streaming buffer already contains the complete file, structured validation reuses it instead of reading the source a second time.

Whole-file binary/container validation may accept files up to the configured 256 MiB ceiling, but untrusted JSON parsing has a separate 32 MiB ceiling to bound parser amplification. A larger JSON-shaped file is left untouched, the structured detector records that its validation limit was reached, and the scan completes with an error rather than risking process exhaustion. Expensive cryptographic parses are likewise capped at 64 attempts per detector job.

Each streaming detector job may return at most 10,000 candidates, 64 MiB of aggregate primary-plus-derived candidate bytes, and 100,000 candidate-shaped structural validations; the single whole-file structured job has a 320 MiB result ceiling so it can retain one maximum-size 256 MiB container plus the 64 MiB derived-export allowance. Each armor parser applies tighter bounds of 1,000 markers and 64 MiB of aggregate bounded searches to avoid repeated multi-megabyte work through malformed data. Derived exports are limited to 16 files and 64 MiB in aggregate per candidate. If a bounded window reaches one of these limits, AARK retains and commits validated results already returned, records a detector error, and finishes as `complete-with-errors` unless another failure occurs. In-memory resume metadata is also bounded to 10,000 unique findings, 20,000 exact occurrences, 1,000 detailed errors, and a 128 MiB serialized inventory. Reaching a finding or occurrence bound is a non-resumable failure rather than an OOM or a false-complete result; already published exact artifacts remain in the failed output. Split exceptionally dense sources into smaller, separately labeled scans.

Use `--workers 1` for a lower-memory run. The 64 MiB small-file source-buffer budget is in addition to the worker pool's bounded transferable copies and returned candidates. Larger chunk and overlap settings multiply the bounded large-window cost; the default `32/17` MiB pair is recommended unless a known container requires a different whole-file limit.

The output directory must be new or empty, cannot be nested inside an input directory, and cannot be a filesystem mount root. A scan accepts at most 128 input roots; canonical duplicate or nested roots are collapsed so a file is not scanned twice. Deterministic directory inventory is bounded to 100,000 entries in one directory, a 100,000-entry pending frontier, and 100,000 visited directories. Crossing a bound fails a root inventory or records an incomplete nested-directory error instead of risking an out-of-memory exit; split an unusually wide or directory-heavy tree into smaller input roots. A current-and-legacy compatibility lock pair prevents concurrent AARK versions from racing in one result tree, and emptiness is rechecked while both locks are held. File identity, size, modification time, and change time are frozen in the scan manifest and checked at open, before ordered commit, and after processing; a mutation is recorded as an error instead of mixing different byte snapshots under one source location. A progress-aware full checkpoint is written after 60 seconds, plus forced terminal/pause boundaries; there is no file-count rewrite trigger.

Input-root identity and mount backing are snapshotted before scanning, refreshed at most every 30 seconds while inventorying/processing, and forced at checkpoints, clean pauses, and completion. Per-file `O_NOFOLLOW`, descriptor, canonical-path, inode, size, modification-time, and change-time validation remains independent of that cache. The output directory, its mount, and the acquired lock are forced through the same periodic/1 GiB scan guard and before sensitive writes. A detected root/mount swap or disappearing lock fails the scan instead of silently redirecting exact artifacts.

The aggregate `performance` member in the local command result contains invocation-local timing and bounded-work counters only: it records no source paths, output paths, hashes, categories, or values. It includes reads/bytes, validations, worker jobs/copies and peak queue bytes, ordered-commit/artifact/checkpoint timing, safety checks, and maximum outstanding small-file buffers. These measurements are not telemetry and are not sent anywhere.

## Capacity guard and pause/resume

Before and during a scan, AARK reserves the larger of `--min-free-gib` (default `5`) and `--min-free-percent` (default `5`) on the output filesystem. `--max-output-gib` optionally caps the logical size of the complete mining output tree. Capacity is checked before every artifact/control write and, for no-finding work, at the first committed progress boundary after 30 seconds or 1 GiB plus checkpoints and completion. A small amount of reserved space can still be used to publish the paused reports, inventory, and state; this may put final control metadata slightly above the logical cap.

`SIGINT`, `SIGTERM`, a reached reserve, or a reached cap discards or settles in-flight detector work, commits no partial chunk cursor, publishes a `paused` inventory and reports, and exits with code `75`. The JSON result includes `resumable: true`, `pauseReason`, and a `resumeCommand`. Preserve the entire output unchanged, correct the capacity condition if necessary, and run:

```bash
aark mine resume --output /case/mining-unallocated
```

If the pause happens while AARK is still freezing the deterministic input inventory, the partial manifest is discarded. Resume safely rebuilds that inventory from the unchanged input roots before detector work begins.

Resume reuses immutable semantic settings such as inputs, provenance, chunk geometry, whole-file threshold, and deep-scan mode. It can override operational settings with `--workers`, `--min-free-gib`, `--min-free-percent`, or `--max-output-gib`. The hashed paused inventory mirrors the state run ID, semantic settings, input-root identities, manifest, committed cursor, and progress. Before starting workers AARK requires that mirror to agree with the state file, then verifies every completed or partial input snapshot and every exact artifact directory, file size, and hash. Only a clean state marked `paused` and `resumable: true` is accepted. Failed, hard-killed, edited, or incomplete output trees must be retained for diagnosis and scanned again into a new directory.

### Deep expanded-key scan

For raw memory, hibernation, swap, or unallocated streams, `--deep-key-schedules` tests every byte position for a complete AES-128/192/256 encryption-key expansion recurrence and checks initialized ChaCha states. An AES match recovers the original key and preserves the full schedule as a derived artifact; a ChaCha match preserves the 64-byte state alongside its exact key bytes. This mode is CPU-intensive, so it is explicit rather than the unnoticed default. Its exhaustive pass is internally divided into overlapping 1 MiB worker jobs so the configured pool can process bounded slices in parallel:

```bash
aark mine scan /case/recovery/residual-memory \
  --output /case/mining-aes \
  --provenance residual-memory \
  --deep-key-schedules
```

## Post-scan cleanup

### Large raw files and shard boundaries

After `npm run build`, a local-only staging controller can split large regular
files into bounded scans without increasing the finding/occurrence limits:

```bash
node scripts/scan-large-file-sharded.mjs --source /case/source.img \
  --output-root /work/image-scans --staging-root /work/image-staging \
  --provenance allocated-reference --shard-mib 4096 --workers 4
```

Use canonical local paths; source, output, and staging must be separate and
non-nested. The same command works with quoted drive-letter paths in PowerShell.
The source is opened read-only. Temporary copies have SHA-256 checks, explicit
free-space reserves, and exclusive controller/staging locks. Each clean range
must have a matching finalized inventory, input manifest, and artifact hashes.
Only verified temporary copies are removed; failed attempts and originals remain.

Independent shards need their own boundary coverage: the controller additionally
scans 17 MiB **on both sides** of every split. Version-2 coverage is complete only
after these windows succeed. Repeating the original command upgrades version-1
byte-only coverage without rereading all completed shards; findings from overlap
windows may duplicate shard findings. The sensitive controller maps each staged
offset back to the original as `range.start + occurrence.offset`.

Keep the whole original, controller state, and all scan outputs together. This
helper does not reconstruct filesystem files from an image, supply whole-image
structured validation, or authorize deletion through `aark cleanup`. A hard-kill
lock or incomplete staging copy needs local review, not automatic lock removal.

### Approval and retention

Only an error-free result whose exact status is `complete` can authorize AARK cleanup. `complete-with-errors`, paused, interrupted, failed, edited, or changed-input scans are never accepted. Multiple complete mining outputs may collectively cover recovery directories scanned under different provenance labels. Cleanup retains each full mining output—especially exact artifacts, the sensitive inventory, and frozen integrity metadata—and moves every complete source file referenced by a finding into a dedicated retained tree before removing bulk recovered data after a fresh end-user decision. See [Cleanup workflow](cleanup.md).

## Future visual OCR coverage

Raw-byte mining does not clear text that is visible only after decoding an image or document. OCR is not implemented in the current scanner. Its reserved offline interface, resource bounds, provenance/retention rules, metadata, and independent coverage semantics are documented in [Future offline OCR layer: initial interface plan](ocr-plan.md).

## Synthetic performance benchmark

Run the local benchmark after a build:

```bash
npm run benchmark:small-files
```

It creates and removes a private temporary corpus containing many tiny ordinary files, duplicate synthetic finding-bearing files, a chunk-boundary finding, and a structured JSON input. It prints aggregate throughput, sampled RSS, logical/allocated output size, findings/counts, and the scanner's bounded-work metrics without paths or values. Tune the non-secret workload with `AARK_BENCH_FILES`, `AARK_BENCH_FINDING_EVERY`, and `AARK_BENCH_WORKERS`. Wall-clock speed is intentionally not a CI assertion; deterministic work counts are covered by tests.

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
