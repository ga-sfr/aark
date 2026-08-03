# Data flow, trust boundaries, and failure behavior

All three layers run locally. An authorized agent can orchestrate recovery and mining and can build a cleanup plan, but the CLI does not send evidence or sensitive control data to that agent's model provider. No layer contains an HTTP client, provider-validity check, telemetry hook, LLM integration, or automatic artifact reveal. External recovery engines receive a fixed minimal locale/terminal environment; inherited tokens, credentials, shell selectors, timezone paths, and other variables are removed. Executable lookup uses a fixed system path, home-directory lookup is disabled, and each recovery stage receives a private case-local temporary directory. Recovery engines start in a private case-local directory and run in isolated process groups. Known network filesystems, cloud/unknown FUSE mounts, and known network block transports (including NBD, RBD, DRBD, iSCSI, FCoE, AoE, and TCP/RDMA) are refused.

## Recovery layer

```text
strict case JSON
  -> deterministic reviewed plan
  -> two execution confirmations
  -> source/destination/read-only preflight (no destination writes yet)
  -> free-space reserve and optional case-size cap
  -> per-run state + redacted plan
  -> sequential local OSS recovery engines
  -> per-step status + private stderr log
  -> sensitive and redacted final reports + redacted manifest
```

The runner rebuilds the plan from the configuration immediately before execution and rejects any mismatch. For block devices it resolves every physical source and destination backing device, refuses an uncertain comparison, refuses any overlap, and—by default—requires the source to be kernel read-only with no writable source mounts. Regular image sources are canonicalized for command execution and their device/inode, size, modification time, and change time are rechecked before and after stages; a changing image fails the run. The physical/mount topology, destination backing, and block-device read-only state are likewise revalidated around every stage. During a long external command, the destination directory, mount identity, absence of nested case mounts, and exact lock inode are polled; a change terminates the engine's process group rather than silently redirecting later output. Planned outputs are type-checked, successful stages must create them, and existing output files may not hard-link to a protected source, analysis image, or one another. A destination must be a dedicated case subdirectory rather than `/`, a filesystem mount root, an unrelated non-empty directory, or a known network mount.

Deleted-record recovery and filesystem-unallocated recovery remain separate provenance classes. `blkls -A` produces `recovery/unallocated/free-space.raw`; PhotoRec can only run after that step and receives this derived stream rather than the original allocated source. Fixed residual-memory and registry inputs beneath a mounted source root are checked individually so a nested writable or network mount cannot bypass the root's read-only/local policy. Evidence imaging, shadow-copy inventory, and residual-memory scans retain different provenance and are never silently called deleted data.

Each invocation gets a unique run ID and holds both the current and legacy compatibility case locks, preventing current or older AARK recovery engines from racing over the same outputs. Case markers are bounded stable regular files, and the destination is revalidated after lock acquisition to close the preflight race window. Immutable per-run state, reports, manifests, and stdout/stderr logs live under `runs/` and `logs/<run-id>/`; case-root files point to the latest run. When stdout itself is a recovery artifact (for example `blkls` output), it is preserved at the planned recovery path rather than duplicated as a log. Directory outputs must be empty before their engine starts, so an engine cannot silently mix a new run with pre-existing recovery files. Required-stage failures stop later stages. Missing or failed optional stages yield `complete-with-warnings`; type-checked partial output from an ordinary optional failure is retained but not called complete. Cancellation sends `SIGTERM` to the engine's process group and escalates to `SIGKILL`; after a normal parent exit, any leftover group members are also killed before outputs are synchronized and accepted. A cancellation or other runner-initiated termination overrides an engine's eventual exit code, so an engine that handles `SIGTERM` and returns zero is still recorded as interrupted rather than completed. Other execution failures record `failed`. Finalization errors trigger a second attempt to publish an explicit failed status. A safety failure before the case directory is accepted—or a later destination/lock substitution—intentionally writes no further report to an untrusted destination.

Recovery capacity is checked before every stage and at one-second intervals while an external command runs. Crossing the boundary terminates the isolated process group. A ddrescue mapfile turns that condition into a reported `paused` state and exit code `75`; engines without a verified resume contract fail instead of being mislabeled resumable.

## Mining layer

```text
canonical local input roots
  -> deterministic frozen regular-file manifest
  -> bounded small-file batches or overlapping large stream windows
  -> one transferable copy per buffer; 1-4 workers run fused pure detector families
  -> main thread verifies exact bytes/offsets and commits bounded, backpressured results in order
  -> main-thread SHA-256 deduplication + capacity accounting
  -> private exact artifacts + resumable sensitive checkpoint
  -> redacted aggregate manifest + both final reports
```

Input roots are resolved, duplicate and nested roots are removed, and final-component symbolic links are rejected. Directory walking never follows symbolic links, refuses nested network mounts, and de-duplicates accepted directory device/inode pairs to stop bind-mount cycles without letting a rejected alias suppress a local one. Per-directory sorting and the pending walk frontier are each capped at 100,000 entries; an oversized root fails inventory, while an oversized nested directory is omitted with an explicit scan error. Mining output must be a dedicated subdirectory rather than a filesystem mount root. Current and legacy compatibility output locks prevent mixed-version concurrent writers, and the scanner rechecks that the previously empty output contains only those locks before artifact initialization. Every regular file goes through streaming detectors, so embedded material is still found in large files. On Ubuntu, the scanner resolves the opened descriptor through `/proc/self/fd` and requires it to match the canonical enumerated path, closing intermediate-symlink substitution gaps. File path identity and mutation metadata are checked at open, before ordered commit, and after processing. Complete small-file buffers are retained in the main thread for byte/offset verification and reused for structured validation; up to `workers` files are in flight under a 64 MiB aggregate source-buffer ceiling. Worker responses may complete in any order, but only the main thread commits them and advances the cursor in manifest order. A change is treated as a scan error rather than assigning findings to unstable offsets. The default whole-file limit is 64 MiB and the hard limit is 256 MiB.

During long scans, input-root identity and mount backing are cached for bounded batches and revalidated after 30 seconds of committed progress plus checkpoints, clean pauses, and completion. A 1 GiB progress trigger also forces the runtime safety/capacity guard. Per-file open-descriptor and canonical-path validation is not cached. The output directory identity, local mount, absence of nested output mounts, and exact lock inode are rechecked before sensitive writes and through the same forced guard. If any of them changes, the scan fails rather than redirecting recovered artifacts to a newly mounted or substituted location; if the destination itself is no longer trustworthy, final-report publication there is intentionally refused.

Validated exact bytes are stored under `artifacts/finding-NNNNNN/`. They are not redacted locally, because the owner needs them for offline verification. Candidate bytes must exactly match their recorded source window and offset before publication. Routine progress and command results contain counts only. `inventory-sensitive.json` contains paths, offsets, fingerprints, validation details, and artifact mappings/integrity hashes but not duplicate inline secret values. The redacted manifest and report omit values, source paths, offsets, fingerprints, and sensitive metadata; category names and generic finding IDs can still be sensitive.

Untrusted recovered data cannot make a worker or resumable inventory grow without bound. A streaming detector job is capped at 10,000 returned candidates, 64 MiB of aggregate primary-plus-derived result bytes, and 100,000 candidate-shaped structural validations. The single whole-file structured job permits 320 MiB so one 256 MiB container and its bounded derived export can be retained without multiplying that allowance across parallel streaming windows. Armor parsers have tighter 1,000-marker and 64 MiB aggregate-search bounds, and cryptographic parsers permit 64 expensive attempts. JSON-shaped whole-file inputs have a separate 32 MiB parse ceiling to bound object/string amplification even when binary container validation is configured up to 256 MiB. A candidate may carry at most 16 derived exports totaling 64 MiB. Validated capped results are retained and the incomplete window is recorded as an error. A scan inventory is capped at 10,000 unique findings, 20,000 occurrences, 1,000 detailed errors, and 128 MiB. Crossing a finding or occurrence bound fails truthfully and preserves artifacts already committed, instead of risking an out-of-memory exit or publishing unusable resume metadata.

Full checkpoints are progress-aware and time-based (60 seconds) rather than triggered every 25 files, and are forced for every clean pause. Normal scans end as `complete` or `complete-with-errors`. `SIGINT`, `SIGTERM`, the free-space reserve, and the optional output cap stop new scheduling, cancel or drain the bounded batch, commit no later out-of-order unit, publish both final reports and integrity-linked `paused` state, and return exit code `75`. The hashed inventory mirrors the committed run ID, semantic settings, input-root identities, manifest, cursor, and progress; resume requires that mirror, the state file, input snapshots, and exact artifact tree all agree before starting new workers. Fatal errors end as `failed` and are not resumable in place. If exact artifact persistence fails, scanning stops rather than claiming that a finding was safely retained.

Image/document bytes still pass through this raw-byte flow. Visual rendering and recognized text are a separate future trust boundary: see the [offline OCR interface plan](ocr-plan.md). Raw-byte completion and visual OCR completion must be reported independently.

## Cleanup layer

```text
completed recovery case + one or more completed mining outputs
  -> recovery state/final-manifest and per-run retained-copy cross-check
  -> mining state/inventory checkpoint and artifact-hash verification
  -> finding source-file index + exact selected-target snapshot and union coverage proof
  -> final exact live re-walk of every frozen mining input
  -> path-redacted aggregate deletion/retention plan + state/control/report-bound approval token
  -> fresh end-user decision
  -> explicit token + recovered-copy confirmation (+ separate evidence confirmation)
  -> repeat all verification under current and legacy operation locks
  -> authorized-in-progress report
  -> atomic target quarantine and complete finding-source moves into a dedicated retained tree
  -> removal of remaining fixed case-child data only
  -> complete or partial-failure cleanup reports
```

Planning is read-only. It rejects any mining result other than exact error-free `complete`, any changed input or artifact, incomplete recovery-stage accounting, incomplete coverage, retained-output overlap with a deletion target or the reserved retained-source namespace, active lock, network backing, mount root, nested mount, or unfinished cleanup quarantine. Execution recomputes the same token while holding both current and legacy recovery/mining locks and refuses a stale authorization before deletion; the token also binds the existing retained-source directory identity or its absence. Each fixed target is atomically moved to an unpredictable case-local quarantine and re-enumerated; source retention and recursive removal start only when its inode, bounded digest of every nested directory/file/link/special entry, aggregate entry count, regular-file count, logical size, and finding-source set still match the approved plan. Every complete finding-containing source file is moved into `retained-sensitive-source-files/<APPROVAL_TOKEN>/`; only then is the remainder removed. `recovery/`, `logs/`, and `runs/` are selected by default; `evidence/` requires a separate opt-in and confirmation. Root final reports and manifests plus full mining outputs also remain. The cleanup reports make interrupted or failed partial retention/deletion explicit, but filesystem deletion is irreversible and is not secure erasure.

## Important edge cases

| Condition | Behavior |
| --- | --- |
| Raw block-device source and destination share a physical disk | Recovery is refused before writes |
| Destination backing device cannot be established | Block-device recovery is refused conservatively |
| Source is writable while read-only enforcement is enabled | Recovery is refused |
| Output path contains a symbolic-link component | The affected operation is refused |
| Existing recovery stdout artifact would be overwritten | Exclusive creation fails; prior evidence is preserved |
| Optional recovery engine is absent or fails | Later independent stages continue; final status has warnings |
| Required engine is absent or fails | Later stages stop; failure reports are attempted |
| Child or descendant ignores cancellation | The isolated process group is terminated, escalating from `SIGTERM` to `SIGKILL` |
| Mining roots overlap or alias one another | Canonical roots are scanned once |
| Two processes target the same recovery or mining output | Current and legacy compatibility locks make the second operation fail before engine/artifact writes |
| Input entry becomes unreadable or changes | Error is recorded; other files continue unless artifact persistence failed |
| A directory or deterministic walk frontier exceeds 100,000 entries | Inventory stops or records an incomplete-directory error; split the tree into smaller roots |
| Mining signal or quota boundary is reached cleanly | Committed artifacts remain, both reports say `paused`, and verified in-place resume is available |
| Mining process is hard-killed or resume metadata changes | In-place resume is refused; retain the output and start a new scan directory |
| Recovery quota is reached during ddrescue | The process group stops, mapfile/image remain, and the case reports a resumable pause |
| Recovery quota is reached during another engine | The stage and run fail because safe in-place resume cannot be promised |
| Destination lacks enforceable Unix modes | Reports warn that physical security or encryption is required |
| Cleanup is planned from a paused or error-bearing scan | Planning is refused; deletion cannot be authorized |
| A recovered file is absent from all clean frozen scan inputs | Planning is refused with no deletion |
| Cleanup inputs change after the user approves | The approval token changes and execution is refused before deletion |
| Cleanup fails after one or more fixed targets are removed | Remaining data is left in place where possible and the case reports partial deletion |

No status claims that every deleted byte was recoverable or that a credential remains active, authorized, or funded. TRIM, overwrite, corruption, missing metadata, encryption, and false-positive carving remain physical and forensic limits outside the tool's control.
