# Recovery architecture

The recovery layer is an orchestrator, not a replacement filesystem implementation. It builds an auditable list of commands, performs preflight checks, and records which provenance class produced each output. An authorized agent may inventory, plan, execute, monitor, and retry a bounded case; see [AGENTS.md](../AGENTS.md) for the delegated-operation contract.

After every completed, paused, failed, or interrupted plan whose destination remains trusted and writable, AARK writes `final-report-sensitive.md` and `final-report-redacted.md` at the case root. The sensitive version gives the original and analysis sources, case and restored-data folders, device-safety result, stage status, provenance, logs, failure detail, and per-stage output locations. The redacted version retains stage outcomes without local paths. Unique copies of state, logs, manifests, and reports are retained under `runs/` and `logs/<run-id>/`; case-root files describe the latest run. Both reports are generated locally without an LLM or upload. If the destination or lock is substituted during execution, further writes—including reports—are refused because that location is no longer trustworthy.

A quota-paused ddrescue run is an explicit retry state, distinct from an interrupted or failed engine.

## Recommended sequence

1. Identify the exact source and destination devices with `aark recover inventory`.
2. Hardware-write-block the source where possible; otherwise use `blockdev --setro` before the case and verify `RO=1` with `lsblk`.
3. Image unhealthy media with GNU ddrescue. Work from the image after that point.
4. Recover deleted metadata with The Sleuth Kit and, for a directly addressable NTFS volume, `ntfsundelete`.
5. Extract filesystem-unallocated blocks with `blkls`.
6. Run PhotoRec against the `blkls` unallocated stream for formats whose metadata is gone.
7. Examine Volume Shadow Copies and residual-memory files as distinct historical sources.
8. Run `aark mine scan` over each recovery output with the correct provenance label.
9. After all intended scans are error-free and complete, optionally build `aark cleanup plan`; an agent must show its aggregate result and obtain fresh end-user approval before deletion. See [Cleanup workflow](cleanup.md).

The example configuration assumes `source` is a directly addressable filesystem partition. For a whole-disk image, use `mmls` or equivalent read-only inventory to identify the filesystem’s sector offset, set `sectorOffset` for The Sleuth Kit stages, and provide a partition/decrypted view as `analysisSource` for tools such as `ntfsundelete` that do not accept an image offset. `residualMemory` and `deletedRegistryCells` additionally require `mountedReadOnlyRoot`.

Regular source and analysis images must be stable for the duration of a run. The runner records their canonical identity, size, modification time, change time, filesystem device, and physical backing devices when resolvable, and verifies those values around every relevant recovery stage. A regular image may share the destination filesystem because it is an immutable file rather than the live source device, but the destination cannot contain the source and planned outputs cannot alias it. A case-local analysis image is allowed only below the reserved `evidence/` subtree because it is an intentional output of acquisition, not the protected primary source. Read-only mounted roots are also rechecked around stages; every fixed residual/registry input path is independently required to stay on a local read-only mount and may not traverse symbolic links. Do not point a recovery run at an image that another acquisition process is still extending.

The destination must be a dedicated case subdirectory, for example `/mnt/recovery-disk/case-001`; the filesystem mount root itself is rejected. A live block-device source requires an independently backed destination, while a stable regular image may share its evidence filesystem as described above. Reusing a fully initialized AARK case is allowed only for an explicitly recorded, quota-paused ddrescue stage. Its bounded, stable control files must identify that pause as the latest stage result, and the recorded source, destination, case ID, read-only requirement, sensitive plan, and redacted plan must match. Only the storage policy may change; sources, destinations, safety policy, stages, and commands must still match. Completed, failed, or interrupted cases require a new destination because the other engines do not share a verified overwrite or resume contract. Current and legacy compatibility case locks prevent mixed-version concurrent runs, and the destination is checked again while both locks are held. If a process is killed without cleanup, inspect the sensitive state and running processes before treating either remaining lock as stale; unrelated or partially initialized non-empty directories are rejected.

Recovery engines run with the case's private log directory as their current directory and receive a separate private case-local temporary directory, so incidental engine files cannot land in the operator's working directory or on a mounted source. Cancellation targets the engine's isolated process group and escalates to `SIGKILL`; any group member left after a normal parent exit is also killed before AARK accepts the outputs. The same process-tree termination is triggered when periodic checks detect that the destination directory, backing mount, a nested mount inside the case, or the exact case-lock inode changed during a long stage. Before execution, planned files and directories are checked for the required type; file outputs may not be hard links to the source, analysis image, or another output, directory outputs must be empty, and a successful engine must leave every declared output present.

## Storage policy and quota stops

The recovery configuration accepts an optional storage policy:

```json
{
  "storage": {
    "minFreeGiB": 5,
    "minFreePercent": 5,
    "maxOutputGiB": 500
  }
}
```

The default reserve is the larger of 5 GiB and 5% of the destination filesystem. `maxOutputGiB` is optional and measures the logical size of the whole case tree, including evidence, recovered files, logs, and reports. AARK checks capacity before each stage and every second while an external engine runs. Case-size accounting streams wide directory trees instead of retaining their full frontier in memory and rejects recursive or pathologically deep directory layouts. The boundary is conservative but not a byte-exact write limit: an engine can write during the polling interval, and reserved space remains available for termination and final reports.

When the guard stops ddrescue, AARK terminates its process group, retains the image and mapfile, records the stage as `paused-disk-quota-resumable`, finalizes the run as `paused`, prints that status as JSON, and exits `75`. Free space or explicitly authorize a revised storage policy, then rerun the same `aark recover run --config <case.json> --execute` command. The mapfile makes the retry authoritative.

Other recovery engines do not have a uniform, verified in-place resume protocol. A quota stop records `failed-disk-quota`, finalizes the run as failed, and exits nonzero. Retain the partial outputs and logs, but do not treat them as complete or blindly rerun into the same paths. An ordinary failed optional engine may likewise leave type-checked partial output; it is retained with a warning and later independent stages may continue, but the partial directory is never mislabeled complete.

The `ntfsundelete` listing uses `--verbose` with `--parent`, as required by the tool. Its percentage option filters scan output rather than selecting undelete candidates, so the match-based recovery stage omits it and attempts every matching deleted record. If some candidates cannot be reconstructed and ntfsundelete returns exit 1, the runner records `completed-with-warnings` only when the current invocation retained at least one new recovery file; the same exit with no new output remains a failed optional stage.

When imaging is enabled, both the ddrescue image and mapfile must be files below the case's `evidence/` directory. A source may not live inside its own case, an explicit case-local `analysisSource` must stay below `evidence/` and may not be the mapfile, and the read-only mounted root may not contain (or be contained by) the destination. This reserved subtree and the containment checks prevent acquisition inputs from colliding with run state, reports, logs, or recovered outputs. When the planned ddrescue image is also the analysis source, its stable identity is established after imaging rather than incorrectly comparing it with its pre-imaging state.

The ddrescue retry pass uses the supported `--idirect` input-direct-I/O option. It does not emit the unsupported `--direct` spelling.

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

Keep the encrypted physical source read-only. Use dislocker or another audited implementation to expose a decrypted view, then mount the resulting filesystem read-only. Passwords and recovery keys should be read from a protected file or interactive input and must not be placed in process arguments, logs, JSON configuration, or shell history. Because dislocker’s credential modes vary, AARK inventories its availability but does not automate a password-bearing command line.

## Volume Shadow Copies

`vshadowinfo` is safe to automate for inventory. Mounting and copying snapshots should be reviewed case by case because mount lifecycle, FUSE permissions, and volume layout differ. Treat snapshot results as historical deltas rather than automatically deleted files.

## “All and only deleted” limitation

No recovery engine can make that guarantee on real media. TRIM can zero SSD cells before acquisition; overwritten clusters no longer contain the old bytes; metadata can be reused; and signature carving can mistake random or embedded data for standalone files. The toolkit addresses this by retaining provenance, separating markers from validated structures, comparing against allocated references, and never silently relabeling historical data as deleted.
