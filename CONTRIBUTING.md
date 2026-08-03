# Contributing

Contributions are welcome when they preserve the project’s read-only and offline-first guarantees.

Before opening a pull request:

1. Add synthetic tests for every new detector or external-tool adapter.
2. Do not commit real disk images, credentials, wallet phrases, key files, machine identifiers, or recovered artifacts.
3. Keep marker detection separate from structural or cryptographic validation.
4. Never add provider login checks, telemetry, or automatic network validation.
5. Run `npm run check` and inspect the staged diff for secrets. The repository audit intentionally rejects license files and private-key/wallet fixture extensions.

External commands must be invoked with an argument array and `shell: false`. Any command capable of modifying source media must be rejected or require a narrowly scoped, explicit opt-in with documented consequences.

Mining detector workers must stay pure and accept only bounded byte buffers plus immutable detection context. Candidate byte/offset verification, deterministic ordering and IDs, deduplication, capacity accounting, checkpoints, reports, and artifact writes belong to the main thread. Tests for detector changes must demonstrate equivalent findings with worker counts `1` and `4`; pause/resume changes must test a committed mid-file chunk and tampered-state rejection.

For scanner performance work, run `npm run benchmark:small-files` and record the workload variables, revision, files/second, MiB/second where applicable, sampled RSS, output bytes, and aggregate work counters. Do not turn local wall-clock timing into a fragile CI threshold. Tests should instead assert deterministic inventories/artifacts and bounded counts such as reads, transferable copies, checkpoints, outstanding files, and outstanding bytes.
