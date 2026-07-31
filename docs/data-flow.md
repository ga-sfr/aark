# Data flow, trust boundaries, and failure behavior

Both layers run locally. Neither layer contains an HTTP client, provider-validity check, telemetry hook, LLM integration, or automatic artifact reveal. External recovery engines receive a fixed minimal locale/terminal environment; inherited tokens, credentials, shell selectors, timezone paths, and other variables are removed. Executable lookup uses a fixed system path, home-directory lookup is disabled, and each recovery stage receives a private case-local temporary directory. Recovery engines start in a private case-local directory and run in isolated process groups. Known network filesystems, cloud/unknown FUSE mounts, and known network block transports (including NBD, RBD, DRBD, iSCSI, FCoE, AoE, and TCP/RDMA) are refused.

## Recovery layer

```text
strict case JSON
  -> deterministic reviewed plan
  -> two execution confirmations
  -> source/destination/read-only preflight (no destination writes yet)
  -> per-run state + redacted plan
  -> sequential local OSS recovery engines
  -> per-step status + private stderr log
  -> sensitive and redacted final reports + redacted manifest
```

The runner rebuilds the plan from the configuration immediately before execution and rejects any mismatch. For block devices it resolves every physical source and destination backing device, refuses an uncertain comparison, refuses any overlap, and—by default—requires the source to be kernel read-only with no writable source mounts. Regular image sources are canonicalized for command execution and their device/inode, size, modification time, and change time are rechecked before and after stages; a changing image fails the run. The physical/mount topology, destination backing, and block-device read-only state are likewise revalidated around every stage. During a long external command, the destination directory, mount identity, absence of nested case mounts, and exact lock inode are polled; a change terminates the engine's process group rather than silently redirecting later output. Planned outputs are type-checked, successful stages must create them, and existing output files may not hard-link to a protected source, analysis image, or one another. A destination must be a dedicated case subdirectory rather than `/`, a filesystem mount root, an unrelated non-empty directory, or a known network mount.

Deleted-record recovery and filesystem-unallocated recovery remain separate provenance classes. `blkls -A` produces `recovery/unallocated/free-space.raw`; PhotoRec can only run after that step and receives this derived stream rather than the original allocated source. Fixed residual-memory and registry inputs beneath a mounted source root are checked individually so a nested writable or network mount cannot bypass the root's read-only/local policy. Evidence imaging, shadow-copy inventory, and residual-memory scans retain different provenance and are never silently called deleted data.

Each invocation gets a unique run ID and holds an exclusive case lock, preventing concurrent recovery engines from racing over the same outputs. Case markers are bounded stable regular files, and the destination is revalidated after lock acquisition to close the preflight race window. Immutable per-run state, reports, manifests, and stdout/stderr logs live under `runs/` and `logs/<run-id>/`; case-root files point to the latest run. When stdout itself is a recovery artifact (for example `blkls` output), it is preserved at the planned recovery path rather than duplicated as a log. Required-stage failures stop later stages. Missing or failed optional stages yield `complete-with-warnings`. Cancellation sends `SIGTERM` to the engine's process group, escalates to `SIGKILL` after a grace period, records `interrupted`, and still attempts both final reports. Other execution failures record `failed`. Finalization errors trigger a second attempt to publish an explicit failed status. A safety failure before the case directory is accepted—or a later destination/lock substitution—intentionally writes no further report to an untrusted destination.

## Mining layer

```text
canonical local input roots
  -> non-following regular-file walk
  -> bounded overlapping stream windows
  -> checksum/structure/cryptographic validators
  -> SHA-256 deduplication by category and exact bytes
  -> private exact artifacts + sensitive inventory
  -> redacted aggregate manifest + both final reports
```

Input roots are resolved, duplicate and nested roots are removed, and final-component symbolic links are rejected. Directory walking never follows symbolic links, refuses nested network mounts, and de-duplicates accepted directory device/inode pairs to stop bind-mount cycles without letting a rejected alias suppress a local one. Mining output must be a dedicated subdirectory rather than a filesystem mount root. An exclusive output lock prevents concurrent writers, and the scanner rechecks that the previously empty output still contains only its own lock before artifact initialization. Every regular file goes through streaming detectors, so embedded material is still found in large files. On Ubuntu, the scanner resolves the opened descriptor through `/proc/self/fd` and requires it to match the canonical enumerated path, closing intermediate-symlink substitution gaps. File path identity and mutation metadata are checked across the streaming pass; files at or below the whole-file limit get a second, size-bounded read for formats that require a complete container, with the same snapshot checked again. A change is treated as a scan error rather than assigning findings to unstable offsets. The default whole-file limit is 64 MiB and the hard limit is 256 MiB.

During long scans, input-root identity and mount backing are rechecked as files are processed and once more before completion. The output directory identity, local mount, absence of nested output mounts, and exact lock inode are rechecked before sensitive writes and at streaming-window boundaries. If any of them changes, the scan fails rather than redirecting recovered artifacts to a newly mounted or substituted location; if the destination itself is no longer trustworthy, final-report publication there is intentionally refused.

Validated exact bytes are stored under `artifacts/finding-NNNNNN/`. They are not redacted locally, because the owner needs them for offline verification. Candidate bytes must exactly match their recorded source window and offset before publication. Routine progress and command results contain counts only. `inventory-sensitive.json` contains paths, offsets, fingerprints, validation details, and artifact mappings/integrity hashes but not duplicate inline secret values. The redacted manifest and report omit values, source paths, offsets, fingerprints, and sensitive metadata; category names and generic finding IDs can still be sensitive.

Checkpoints are written periodically. Normal scans end as `complete` or `complete-with-errors`. Once the output is initialized, interruptions and fatal errors end as `interrupted` or `failed` and still produce both final reports. If exact artifact persistence fails, scanning stops rather than claiming that a finding was safely retained.

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
| Two processes target the same recovery or mining output | An exclusive local lock makes the second operation fail before engine/artifact writes |
| Input entry becomes unreadable or changes | Error is recorded; other files continue unless artifact persistence failed |
| Scan is interrupted | Checkpointed artifacts remain and both reports identify the incomplete status |
| Destination lacks enforceable Unix modes | Reports warn that physical security or encryption is required |

No status claims that every deleted byte was recoverable or that a credential remains active, authorized, or funded. TRIM, overwrite, corruption, missing metadata, encryption, and false-positive carving remain physical and forensic limits outside the tool's control.
