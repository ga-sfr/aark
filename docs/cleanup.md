# Cleanup workflow

Cleanup is AARK's optional destructive post-processing layer. Its purpose is to reduce the sensitive recovery footprint after recovery and mining are finished: keep the case-root final reports, each mining result, exact finding artifact files containing validated sensitive material, and the metadata needed to locate and verify those artifacts; remove the bulky recovered copy and intermediate recovery logs/state copies. It is safe for an authorized agent to build the plan, but only the end user can authorize execution after seeing that plan.

## What is retained and removed

The default cleanup selects these fixed children of the completed recovery case:

- `recovery/`, containing AARK-managed restored data;
- `logs/`, containing per-engine sensitive stdout/stderr; and
- `runs/`, containing intermediate and per-run state/report copies.

The case-root recovery final reports, redacted manifests, latest sensitive case state, reviewed plan, and cleanup reports remain. Every supplied mining output is retained in full, including `final-report-sensitive.md`, `final-report-redacted.md`, `manifest-redacted.json`, `inventory-sensitive.json`, `scan-state-sensitive.json`, `scan-files-sensitive.ndjson`, and `artifacts/`. The three mining control files are deliberately retained: they bind the completed scan to its exact inputs and provide the mapping and hashes used by `aark mine reveal` after the recovered source copy is gone.

The case `evidence/` directory—normally a ddrescue image and mapfile—is retained by default. Include it in planning only when the end user intends to discard that evidence copy and clean mining scans cover every regular file under it. Evidence deletion requires its own confirmation at execution time.

Cleanup does not delete arbitrary files elsewhere in the case, the original source device/image, any supplied mining output, snapshots or backups, or data outside the canonical case directory. It is ordinary filesystem deletion, not guaranteed secure erasure.

## Verification and approval flow

Run the read-only plan with every completed mining output whose frozen inputs collectively cover the selected recovered trees:

```bash
aark cleanup plan /case/mining-metadata /case/mining-unallocated \
  --case /case
```

To include the evidence copy:

```bash
aark cleanup plan /case/mining-metadata /case/mining-unallocated /case/mining-image \
  --case /case \
  --include-evidence
```

Planning requires all of the following:

1. The latest recovery state and redacted manifest describe the same `complete` or `complete-with-warnings` run, every planned stage has a valid ordered result, and every retained root state, plan, manifest, and final report exactly matches that run's copy under `runs/`.
2. Every mining state is exactly `complete`, not `complete-with-errors`, with every frozen manifest entry visited and scanned and zero omitted or recorded errors.
3. The sensitive inventory hash and mirrored checkpoint exactly match the mining state.
4. Every retained artifact path, size, and SHA-256 hash matches the inventory, with no unexpected artifact files.
5. Every mining input root has its original canonical identity and local mount backing, and a deterministic live walk exactly matches its frozen file manifest.
6. Every regular file selected for deletion lies under at least one of those unchanged, completely scanned input roots.
7. The case, mining outputs, and deletion targets are canonical local directories without symbolic-link roots, nested mounts, active operation locks, or overlaps between retained mining outputs and deletion targets.

The result contains no local paths or recovered values. It reports aggregate scan, finding, marker-only, artifact, filesystem-entry, regular-file, and byte counts; whether the recovery and evidence copies are selected; what remains; and a SHA-256 approval token binding the verified state, retained recovery/mining control and report hashes, and exact deletion choice. A marker-only finding has no exact exported artifact. Review every such location locally before approving deletion because its recovered source context will otherwise be removed.

An agent must present this result to the end user and ask whether to proceed. A prior request to recover and scan data is not deletion approval. If approved, execute with the same set of mining outputs and options:

```bash
aark cleanup run /case/mining-metadata /case/mining-unallocated \
  --case /case \
  --approval-token <TOKEN_FROM_PLAN> \
  --execute \
  --confirm-delete-recovered-copy
```

Evidence cleanup additionally requires both `--include-evidence` and `--confirm-delete-evidence`. If any verified identity, file snapshot, artifact, count, mount, checkpoint, or option changes, the token no longer authorizes the run. Build a new plan, show the changed aggregates, and ask again.

## Execution and failures

Before repeating verification, execution holds current and legacy recovery/mining locks so compatible AARK processes cannot start against the same case or result directories. Known lock files introduced by cleanup itself are excluded from live manifest comparison; no other manifest difference is tolerated. Each fixed target is atomically moved to a private, unpredictable `.aark-cleanup-pending-*` name in the same case, then AARK rechecks the case mount, absence of nested mounts, every lock inode, the moved directory inode, and a fresh bounded deterministic digest of every nested directory, regular file, symbolic link, and special entry, including identities, modes, sizes, timestamps, and link targets where applicable. Recursive deletion begins only if that quarantined tree is still the exact approved target.

Cleanup writes `cleanup-final-report-sensitive.md`, `cleanup-final-report-redacted.md`, and `cleanup-manifest-redacted.json` at the case root with status `authorized-in-progress` before removing data. On success they say `complete`. If interruption or an error happens after deletion begins, AARK attempts to publish `interrupted-partial` or `failed-partial` and lists completed target paths only in the sensitive report. Recursive deletion itself may not stop immediately on a signal, and a crash or filesystem failure can leave a `.aark-cleanup-pending-*` tree partly or wholly present. AARK refuses another cleanup while such a quarantine exists. Inspect it and the mounted filesystems locally before retrying or removing any stale lock.

Retained exact artifacts remain credentials. Do not upload them, feed them to a hosted model, or validate them with online services. Deleting the recovered copy also removes convenient forensic context; complete any authorized manual review that requires surrounding files before approving cleanup.
