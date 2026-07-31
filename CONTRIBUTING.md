# Contributing

Contributions are welcome when they preserve the project’s read-only and offline-first guarantees.

Before opening a pull request:

1. Add synthetic tests for every new detector or external-tool adapter.
2. Do not commit real disk images, credentials, wallet phrases, key files, machine identifiers, or recovered artifacts.
3. Keep marker detection separate from structural or cryptographic validation.
4. Never add provider login checks, telemetry, or automatic network validation.
5. Run `npm run check` and inspect the staged diff for secrets. The repository audit intentionally rejects license files and private-key/wallet fixture extensions.

External commands must be invoked with an argument array and `shell: false`. Any command capable of modifying source media must be rejected or require a narrowly scoped, explicit opt-in with documented consequences.
