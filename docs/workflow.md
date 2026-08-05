# Durable workflow continuity

`aark workflow run --until-blocked` is the durable controller for authorized multi-stage recovery work. It advances explicitly configured, non-destructive or already-authorized stages without waiting at child-command boundaries. It stops only for a user approval gate, a safety/test/capacity failure, an unrecoverable checkpoint condition, or terminal completion. Cleanup execution is not a workflow stage and is never automated.

Every structured CLI result declares the same continuation contract:

```json
{
  "workflowState": "ready-to-continue",
  "requiresUserInput": false,
  "safeToAutoContinue": true,
  "nextAction": "retention-or-cleanup-plan",
  "activeProcessExpected": false,
  "blocker": null
}
```

The other states are `running`, `blocked-user`, `blocked-safety`, `terminal`, and `invariant-failure`. A running result must identify an active action; a user blocker is the only state with `requiresUserInput: true`; only `ready-to-continue` is safe to auto-advance. An idle state that claims to be running is reported as `invariant-failure` rather than progress.

## Strict configuration

Workflow JSON is versioned, rejects unknown fields, uses absolute paths, and lists stages in their authorized order. Supported stage kinds are:

- `recovery`: loads an existing strict recovery config. Its normalized validated contents are bound into the durable outer workflow hash, so changing its source, destination, confirmations, or stages requires a new workflow checkpoint. Recovery still requires `execute: true` in that reviewed config and `--execute-recovery` on workflow run.
- `mining-batch`: partitions many closed roots into bounded child scans, resumes clean pauses, adapts later batch sizes to observed finding density, and globally deduplicates findings in one redacted aggregate.
- `retention`: verifies completed mining results and copies every finding-containing source file into content-addressed storage with whole-file hash verification.
- `cleanup-plan`: creates the ordinary completed-case deletion plan and then stops for the end user.
- `segmented-cleanup-plan`: snapshots selected immutable closed segments, proves terminal scan coverage, excludes active segments, creates an approval token, and then stops for the end user.

A cleanup planning stage must be last. There is deliberately no `cleanup-run` workflow kind.

```json
{
  "version": 1,
  "workflowId": "authorized-case-001",
  "directory": "/mnt/control/aark-workflow-001",
  "stages": [
    {
      "id": "closed-photorec-roots",
      "kind": "mining-batch",
      "inputs": [
        "/mnt/recovery/recup_dir.1",
        "/mnt/recovery/recup_dir.2"
      ],
      "output": "/mnt/reports/mining-batch-001",
      "provenance": "unallocated-carve",
      "workers": 4,
      "storage": {
        "minimumFreeGiB": 400,
        "minimumFreePercent": 10
      },
      "maximumRootsPerBatch": 128,
      "maximumFilesPerBatch": 50000,
      "maximumGiBPerBatch": 256
    },
    {
      "id": "closed-segment-cleanup-gate",
      "kind": "segmented-cleanup-plan",
      "segments": [
        "/mnt/recovery/recup_dir.1",
        "/mnt/recovery/recup_dir.2"
      ],
      "activeSegments": [
        "/mnt/recovery/recup_dir.3"
      ],
      "miningOutputs": [
        "/mnt/reports/mining-batch-001"
      ],
      "retentionDirectory": "/mnt/reports/retained-segment-sources",
      "errorSourceDisposition": "retain"
    }
  ]
}
```

Native batch roots can be supplied wherever a set of mining outputs is accepted. AARK expands only an exactly complete batch checkpoint, verifies every child scan, and holds the batch controller lock during destructive cleanup. Independent non-batch cleanup inputs remain capped at 128 so execution never attempts to hold an unbounded number of file-descriptor locks.

Validate and run:

```bash
aark workflow plan --config /secure/workflow.json
aark workflow run --config /secure/workflow.json --until-blocked --execute-recovery
aark workflow status --directory /mnt/control/aark-workflow-001
```

The state directory must be dedicated and must not overlap any source, case, scan, retained-data, or cleanup target. `workflow-state-sensitive.json` contains local paths and must remain out of agent/model context. `workflow-status-redacted.json` and the `workflow status` result contain stage IDs and aggregate counts only.

## Heartbeats, ETA, and restart behavior

The controller persists its PID, process group, kernel start time, executable identity, command fingerprint, boot identity, and heartbeat. `workflow status` distinguishes a fresh identity-verified controller from an idle, inaccessible, or stale `running` marker. `kill(pid, 0)` permission denial means the process exists but cannot be inspected: it is never treated as dead or safe to reclaim, but status also does not mislabel that inaccessible identity as verified. Dead workflow-owner locks can be reclaimed only when the complete stored process identity proves that the PID is missing or has been reused. Stale-lock reclamation claims the pathname by rename before removal so two reclaimers cannot unlink one another's newly created locks.

Status reports the current stage and batch, aggregate progress, free and reserved capacity, source/destination safety state when available, stage ETA when progress supports one, and `wallClockEtaAvailable: false` while blocked. It does not turn stage ETA into a false total calendar ETA.

Completion of one stage is checkpointed before the next begins, and the final stage atomically commits terminal state. A controller restart at a clean pending-stage boundary advances safely. An interrupted in-progress stage is re-entered only after the stored process identity proves that the prior controller is dead or its PID was reused. The recovery, batch, and retention layer then accepts only its own verified durable checkpoint; a dirty, active, or unverifiable child checkpoint becomes a safety/invariant blocker rather than being mislabeled resumable. Active-work duration excludes published blocked intervals, and a stage estimate is not presented as a total-work estimate while later stages remain unknown.

## Large mining batches

`aark mine batch` inventories the supplied closed roots, durably checkpoints root partitioning by bounded count or elapsed time, groups at most 128 roots per child scan, and uses configured file and byte ceilings. A signal during partitioning publishes every fully inventoried root as a clean pause; a crash can require only the most recent bounded partition window to be inventoried again. After completed children it reduces later file ceilings when observed finding or occurrence density approaches 80% of the per-scan inventory bounds. A single root that is itself too dense is blocked with an instruction to subdivide that root; findings already written are not relabeled as a successful scan.

Each child keeps the ordinary frozen manifest, exact artifact tree, reports, and clean-pause resume contract. The batch controller uses a durable active-child checkpoint, recognizes a child that completed just before a controller crash, and commits its aggregate idempotently. A signal between children publishes an explicit resumable pause. Advancement re-verifies the controller lock after the child exits, and aggregate counters are maintained incrementally rather than rescanning every prior root on each progress callback. Before terminal publication—and whenever a complete batch root is later consumed—AARK reconstructs the global aggregate from every exact child checkpoint and re-verifies each artifact tree. An explicit rerun after a safety blocker re-enters those checks and continues only if the underlying condition was actually remediated. `batch-aggregate-sensitive.json` holds only category/fingerprint deduplication keys and stays private; `batch-manifest-redacted.json` reports global category and occurrence counts without hashes, values, paths, or offsets.

The optional output cap is aggregate across the batch root. Before each new or resumed child, AARK subtracts already-used bytes and a bounded controller reserve, gives that child only its current bytes plus the remaining aggregate allowance (rounded down), and rechecks the aggregate before advancement. The private global fingerprint set also has a bounded control-state size; reaching it stops safely and requires a new workflow group.

## Standalone retention

`aark retain plan/run` is for finding-containing files outside the recovery-case cleanup namespace, especially allocated files on read-only source mounts. Planning verifies exact completed scans, frozen source metadata, artifact hashes, local mounts, whole-source SHA-256 hashes, and destination capacity. It reports both deduplicated logical object bytes and destination-cluster-rounded object-data bytes; runtime capacity checks additionally reserve conservative allocation-unit metadata for every new object entry, shard, and control artifact so tiny-file retention does not understate required free space. Running copies sources into `objects/<prefix>/<sha256>`, verifies existing single-link objects before deduplication, writes a sensitive source-to-object mapping, and can be rerun safely after interruption. A signal or storage-reserve stop during the copy phase publishes `status: paused`, a plan-bound redacted progress checkpoint, and `resumable: true`; the workflow controller treats that as a blocker rather than incorrectly advancing cleanup. The destination must be a dedicated canonical subdirectory with no nested mount or unexpected top-level entry. Once a completed mapping exists, that directory is bound to its plan token so a later unrelated retention run cannot overwrite the old source mapping; use another dedicated directory for a different plan. Orphaned unpublished object temporaries from an interrupted run are identity-checked and removed during resume. Long hashes and copies periodically recheck source/destination mount identity, the destination directory and operation-lock inodes, the read-only source requirement, the remaining free-space reserve, and the aggregate output cap. Immediately before publishing the mapping, AARK revalidates every source identity and refreshed mount state, including sources whose content object was deduplicated rather than copied. It never deletes or alters a source.

The CLI requires source mounts to be read-only. The library has an explicit `requireReadOnlySources: false` option for controlled synthetic tests and specialized local integrations; normal delegated operation must leave it enabled.

## Segmented cleanup

`aark cleanup segments plan` allows capacity recovery while a separate segment is still active. Every selected closed segment must be a canonical local directory on the same filesystem as its retained-source directory. Supplied exact scans—or one complete native batch root—must cover every regular file with unchanged frozen metadata. Symbolic links, special entries, ambiguous or omitted scan-error paths, active overlaps, retained-output overlaps, and operation locks stop planning.

The plan reports logical bytes, selected allocated bytes, filesystem allocation-unit size, and a conservative-to-maximum free-space gain range. Both bounds exclude a multiply-linked inode when its link count proves that a link exists outside the selected segment. Hard links spanning two independently selected segments are rejected up front because deleting the first segment would invalidate the second segment's approved inode checkpoint; select a common parent or rescan between cleanup runs. The lower bound over-reserves allocation units for retained-file entries, directories, and the bounded sizes of both token-scoped and top-level control reports. Scan-error source files default to whole-file retention. Choosing `delete` is token-bound and adds a separate `--confirm-delete-error-sources` gate.

Execution requires the exact approval token, `--execute`, and `--confirm-delete-segments`. Retention and mining trees must not overlap any active segment. Execution locks retained outputs, identity-checks but never locks or changes active segments, atomically renames each selected segment into a same-parent quarantine, re-snapshots it, moves finding/error source files into a token-specific retained tree, verifies each retained whole file by SHA-256, and re-verifies the exact remaining deletion set and mount boundaries immediately before recursive removal. Multiple protected names for one hard-linked inode are retained correctly. Every token keeps its own sensitive/redacted reports and manifest; top-level copies point to the latest result. A partial report and quarantine are intentionally left for inspection after failure.

## Tested upgrade boundary

Use `aark workflow upgrade plan/run` only with a separate candidate checkout or worktree. Planning requires a blocked or terminal workflow, no verifiable active controller, a clean candidate commit with no tracked or untracked changes, no ignored local inputs except replaceable `dist/` and `node_modules/`, and an explicit candidate package declaration for the active checkpoint schemas. Running the approved token holds both upgrade and workflow locks while it removes only the verified ignored `dist/` tree, performs `npm ci`, the candidate's full `npm run check`, and any declared `test:linux`, `test:integration:linux`, or `test:python` scripts. It rechecks the candidate commit, directory inode, canonical path, and cleanliness after the tests, and requires a freshly built bounded canonical CLI before automatic resume. Every retry gets an append-only token-scoped attempt directory while reusing one private token-bound package cache, so a failed test does not make the reviewed token unusable or needlessly duplicate package downloads; captured test logs are bounded and remain private below the workflow state directory.

Without `--resume-config`, a successful upgrade reports `readyToResume: true`. To resume automatically, supply the same `--resume-config` choice—and any `--execute-recovery` confirmation—to both upgrade `plan` and `run`; those choices and the matching workflow-config hash are approval-token-bound. After tests, the upgrade releases the workflow lock and invokes the tested candidate's built CLI to monitor `workflow run --until-blocked` to its next blocker or completion. The upgrade result carries that resumed workflow's exact redacted continuation state instead of claiming terminal completion merely because the test command exited. Cleanup approval and recovery's independent confirmation are not inferred or bypassed.
