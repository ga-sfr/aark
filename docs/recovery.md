# Recovery architecture

The recovery layer is an orchestrator, not a replacement filesystem implementation. It builds an auditable list of commands, performs preflight checks, and records which provenance class produced each output.

After every completed, failed, or interrupted plan whose destination remains trusted and writable, it writes `final-report-sensitive.md` and `final-report-redacted.md` at the case root. The sensitive version gives the original and analysis sources, case and restored-data folders, device-safety result, stage status, provenance, logs, failure detail, and per-stage output locations. The redacted version retains stage outcomes without local paths. Unique copies of state, logs, manifests, and reports are retained under `runs/` and `logs/<run-id>/`; case-root files describe the latest run. Both reports are generated locally without an LLM or upload. If the destination or lock is substituted during execution, further writes—including reports—are refused because that location is no longer trustworthy.

## Recommended sequence

1. Identify the exact source and destination devices with `agetnic recover inventory`.
2. Hardware-write-block the source where possible; otherwise use `blockdev --setro` before the case and verify `RO=1` with `lsblk`.
3. Image unhealthy media with GNU ddrescue. Work from the image after that point.
4. Recover deleted metadata with The Sleuth Kit and, for a directly addressable NTFS volume, `ntfsundelete`.
5. Extract filesystem-unallocated blocks with `blkls`.
6. Run PhotoRec against the `blkls` unallocated stream for formats whose metadata is gone.
7. Examine Volume Shadow Copies and residual-memory files as distinct historical sources.
8. Run `agetnic mine scan` over each recovery output with the correct provenance label.

The example configuration assumes `source` is a directly addressable filesystem partition. For a whole-disk image, use `mmls` or equivalent read-only inventory to identify the filesystem’s sector offset, set `sectorOffset` for The Sleuth Kit stages, and provide a partition/decrypted view as `analysisSource` for tools such as `ntfsundelete` that do not accept an image offset. `residualMemory` and `deletedRegistryCells` additionally require `mountedReadOnlyRoot`.

Regular source and analysis images must be stable for the duration of a run. The runner records their canonical identity, size, modification time, and change time and verifies those values around every relevant recovery stage. Read-only mounted roots are also rechecked around stages; every fixed residual/registry input path is independently required to stay on a local read-only mount and may not traverse symbolic links. Do not point a recovery run at an image that another acquisition process is still extending.

The destination must be a dedicated case subdirectory on the separate recovery filesystem, for example `/mnt/recovery-disk/case-001`; the filesystem mount root itself is rejected. Reusing a fully initialized Agetnic case is supported for resumable imaging and additional runs only when its bounded, stable control files contain a recognized terminal status and the recorded source, destination, case ID, sensitive plan, and redacted plan all match exactly. An exclusive case lock prevents concurrent runs, and the destination is checked again while the lock is held. If a process is killed without cleanup, inspect the sensitive state and running processes before treating the remaining lock as stale; unrelated or partially initialized non-empty directories are rejected.

Recovery engines run with the case's private log directory as their current directory and receive a separate private case-local temporary directory, so incidental engine files cannot land in the operator's working directory or on a mounted source. Cancellation targets the engine's isolated process group and escalates to `SIGKILL`, preventing a helper process from continuing to write after the parent exits. The same process-tree termination is triggered when periodic checks detect that the destination directory, backing mount, a nested mount inside the case, or the exact case-lock inode changed during a long stage. Before execution, planned files and directories are checked for the required type; file outputs may not be hard links to the source, analysis image, or another output, and a successful engine must leave every declared output present.

The match-based `ntfsundelete` recovery stage uses the tool's default percentage filter, which already attempts every matching deleted record. An explicit zero threshold is avoided because affected ntfs-3g versions can return exit 1 even after retaining recovered files. If ntfsundelete still returns the configured partial-result code, the runner records `completed-with-warnings` only when the current invocation added a recovery file; the same exit with no new output remains a failed optional stage.

When imaging is enabled, both the ddrescue image and mapfile must be files below the case's `evidence/` directory. A source may not live inside its own case, an explicit case-local `analysisSource` must stay below `evidence/` and may not be the mapfile, and the read-only mounted root may not contain (or be contained by) the destination. This reserved subtree and the containment checks prevent acquisition inputs from colliding with run state, reports, logs, or recovered outputs. When the planned ddrescue image is also the analysis source, its stable identity is established after imaging rather than incorrectly comparing it with its pre-imaging state.

The Sleuth Kit documents that `tsk_recover` recovers unallocated files by default. The plan intentionally does not add `-e`, which would also export allocated files: <https://www.sleuthkit.org/sleuthkit/man/tsk_recover.html>.

The orchestrator deliberately does not ask PhotoRec to distinguish allocated from unallocated clusters. Instead, `blkls` first extracts filesystem-unallocated units and PhotoRec receives only that derived stream. Signature carving therefore requires the unallocated-stream stage. PhotoRec's output directory must remain on the separate destination device: <https://www.cgsecurity.org/wiki/Scripted_run>.

## Provenance labels

| Label | Meaning | Can it prove filesystem deletion? |
| --- | --- | --- |
| `deleted-metadata` | An unallocated directory or metadata record referenced the file | Usually, subject to metadata reuse |
| `unallocated-stream` | Bytes came from filesystem-unallocated units | Yes for the units at acquisition time; not for a pathname |
| `unallocated-carve` | A signature carver reconstructed data from free space | Yes for source units; reconstruction may be partial |
| `shadow-copy` | Data differs from or predates the live volume | No; it is historical, not necessarily deleted |
| `residual-memory` | Data appeared in pagefile, swap, or hibernation memory | No |
| `allocated-reference` | Current data used only for comparison or key correlation | No |

## BitLocker

Keep the encrypted physical source read-only. Use dislocker or another audited implementation to expose a decrypted view, then mount the resulting filesystem read-only. Passwords and recovery keys should be read from a protected file or interactive input and must not be placed in process arguments, logs, JSON configuration, or shell history. Because dislocker’s credential modes vary, Agetnic Tools inventories its availability but does not automate a password-bearing command line.

## Volume Shadow Copies

`vshadowinfo` is safe to automate for inventory. Mounting and copying snapshots should be reviewed case by case because mount lifecycle, FUSE permissions, and volume layout differ. Treat snapshot results as historical deltas rather than automatically deleted files.

## “All and only deleted” limitation

No recovery engine can make that guarantee on real media. TRIM can zero SSD cells before acquisition; overwritten clusters no longer contain the old bytes; metadata can be reused; and signature carving can mistake random or embedded data for standalone files. The toolkit addresses this by retaining provenance, separating markers from validated structures, comparing against allocated references, and never silently relabeling historical data as deleted.
