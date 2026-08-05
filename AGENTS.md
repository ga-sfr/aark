# AARK agent operating guide

AARK is designed to be invoked by an authorized software agent as well as by a person at a terminal. Agent operation is recommended for long, repetitive recovery and mining runs when the agent can remain inside the authorization, storage, and data-handling boundaries below. The CLI itself remains deterministic and local; it does not send evidence to an AI service.

## Authorization boundary

Before changing disks or starting recovery, establish one explicit case-wide authorization that identifies:

- the source media and data the owner authorizes AARK to examine;
- the separate destination and an acceptable storage quota;
- the recovery and mining stages the agent may run;
- whether privileged raw-device commands are authorized; and
- whether the agent may ever reveal or inspect exact recovered values.

An agent may inventory, build and inspect plans, execute approved stages, monitor, pause, and resume without a person at the keyboard when those actions are within that authorization. Do not infer permission to scan additional media, weaken read-only protections, lower storage reserves, reveal secrets, contact providers, or move data off the host.

Deletion is intentionally outside that standing authorization. Even if the original request said to complete the whole case, an agent must obtain fresh end-user approval after presenting the exact aggregate cleanup plan. It may never assume, pre-answer, or automate that decision.

## Agent continuity: no idle stage boundaries

A completed command is a workflow boundary, not permission to leave an authorized case idle. After each bounded recovery, mining, verification, retention, or planning command exits, immediately inspect its redacted result and start the next safe, in-scope action. Read-only checks, non-destructive retention, monitoring, resumable continuation, and stages already covered by the case authorization do not require a second confirmation merely because the previous process ended. If the current command does not automatically start another batch or stage, the controlling agent must do so.

Before yielding control, an agent **MUST** establish exactly one of these states: (1) an active operation or explicit monitor with a freshly verified heartbeat and process identity; (2) a blocked state that names the exact user, safety, capacity, hardware, or test action required; or (3) terminal workflow completion. If none applies, the agent **MUST** start the next safe authorized action. A completed child command is not a blocker. Answering a status question, producing an interim summary, or reaching the end of an agent turn does not excuse leaving a workflow idle; the same invariant applies after that response.

An agent may wait only while an operation or explicit monitor is actually running, or when progress requires fresh deletion approval, additional authorization, operator-supplied hardware or information, remediation of a safety/test failure, or restoration of the configured free-space reserve. When waiting, state that no operation is active, name the exact blocker and requested response, and preserve a concrete resume command or next action. Never describe a case as progressing when all relevant processes are idle. Prefer `aark workflow run --until-blocked` for multi-stage or multi-day work, use `aark workflow status` to verify its redacted heartbeat and process identity, and advance at clean boundaries without waiting for the operator to ask for another status update.

This continuity rule never weakens the authorization, sensitive-data, cleanup-approval, read-only-source, or storage-reserve requirements below. A safe stop is preferable to guessing when one of those gates is unresolved.

## Safe delegated workflow

1. Run `aark recover inventory --json` and identify the exact source and a destination on a different physical device.
2. Create the strict case JSON. Keep `requireReadOnlySource: true`; set a storage policy explicitly when the defaults are not appropriate.
3. Run `aark recover plan --config <case.json>` and verify that every command, source, destination, and enabled stage stays inside the authorization.
4. Execute only when both confirmations are present: `execute: true` in the reviewed configuration and `aark recover run --config <case.json> --execute`.
5. Treat a JSON result with `status: "paused"`, or process exit code `75`, as a safe retry condition rather than success or failure. Free space and rerun the identical recovery command for a ddrescue quota pause.
6. Mine each intended local recovery output with the correct provenance. Use the default bounded worker pool unless the case requires `--workers 1`.
7. On mining exit code `75`, preserve the output unchanged and run the returned `resumeCommand`, normally `aark mine resume --output <directory>`.
8. Use aggregate JSON, `manifest-redacted.json`, and `final-report-redacted.md` for automation. Review redacted material before sharing it.
9. When recovery and all intended scans are complete, run `aark cleanup plan <MINING_OUTPUTS...> --case <CASE_DIRECTORY>`. The command is read-only and succeeds only when the recovery case is terminal-successful, every supplied scan is exactly `complete` with zero errors, its frozen inputs are unchanged, every artifact hash verifies, and the scans collectively cover every selected recovery file.
10. Show the path-redacted plan, filesystem-entry/regular-file deletion counts and byte totals, retained-artifact count, retained whole-source file count and bytes, marker-only count, evidence disposition, and approval token to the end user. Ask explicitly whether AARK should delete the bulk recovered copy while keeping the root final reports, complete mining outputs, exact sensitive artifacts, every complete finding-containing source file, and minimal integrity metadata. Do not continue until the user says yes.
11. After approval, run the unchanged command with `--approval-token <TOKEN> --execute --confirm-delete-recovered-copy`. Evidence images remain by default. If the user separately approves evidence deletion, use `--include-evidence` in both commands and `--confirm-delete-evidence` during execution.

## Sensitive-data boundary

Routine agent operation must not open, quote, summarize, attach, upload, or place these files in model context:

- `inventory-sensitive.json`, `scan-state-sensitive.json`, or `scan-files-sensitive.ndjson`;
- `case-sensitive.json`, sensitive run state, or sensitive tool logs;
- `final-report-sensitive.md` or `cleanup-final-report-sensitive.md`; or
- anything under `artifacts/`, `evidence/`, `retained-sensitive-source-files/`, or raw recovery output directories.

Do not invoke `aark mine reveal` unless the case authorization explicitly requires disclosure of that exact artifact to the local operator. Never use an online login, provider API, search service, hosted OCR system, hosted model, or other network service to validate recovered material. A future OCR layer must remain offline and apply the same artifact, provenance, checkpoint, and redaction rules.

## Pause, quota, and failure rules

- Mining stops at committed chunk boundaries for `SIGINT`, `SIGTERM`, the free-space reserve, or the logical output cap. Only a result explicitly marked `paused` and `resumable: true` may be resumed in place.
- The default free-space reserve is the larger of 5 GiB and 5% of the destination filesystem. `--max-output-gib` and recovery `storage.maxOutputGiB` add an optional logical output cap.
- Resume verifies the frozen file manifest, input identities, state and inventory hashes, and the exact artifact tree. Do not edit a paused output.
- A ddrescue quota stop is resumable because its mapfile is authoritative. Quota stops for other recovery engines are failures; retain their outputs and reports, but do not assume an in-place retry is safe.
- A hard kill, host crash, failed scan, changed input, missing lock, or modified checkpoint is not a clean pause. Inspect locally and start a new output rather than bypassing validation.
- Cleanup never accepts a paused, failed, interrupted, or `complete-with-errors` scan. A changed plan token, file, artifact, mount, directory identity, or operation lock stops deletion and requires a new plan and a new end-user decision.
- Cleanup is irreversible. It moves finding-containing source files into the dedicated retained tree, removes only fixed AARK-managed case directories, writes an `authorized-in-progress` report before deletion, and records `failed-partial` or `interrupted-partial` if it cannot finish. A `.aark-cleanup-pending-*` tree means protected retention or deletion stopped partway; inspect it locally and do not bypass the retry refusal, coverage, or confirmation gates.

## Repository changes

Detector workers must remain pure: they receive bounded bytes and return candidates or errors. The main thread exclusively verifies candidate bytes and source offsets, assigns deterministic IDs, deduplicates, writes artifacts, accounts for capacity, and publishes checkpoints. Preserve deterministic ordering across worker counts 1 through 4, add synthetic tests, and run `npm run check` on Ubuntu before proposing a change.

Never add network validation, telemetry, automatic reveal, automatic cleanup approval, shell-string execution, real recovered fixtures, or a safety bypass intended only to make an agent's workflow easier.
