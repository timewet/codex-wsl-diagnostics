# Contributing

Thanks for helping improve `codex-wsl-diagnostics`.

## Issues

Before opening an issue, search existing reports for the same behavior. Include:

- A short, repeatable description of the problem.
- Expected and observed behavior, including the diagnostic status or error category.
- Relevant Codex Desktop, Windows, PowerShell, and WSL versions when known.
- The smallest steps that reproduce the issue.

Do not attach raw diagnostic reports by default. Reports may contain environment-derived fingerprints, distribution names, security summaries, or other identifying details even when paths are redacted. Share only the fields needed to reproduce the behavior.

Before posting, remove usernames, machine names, full paths, project identifiers, tokens, keys, cookies, environment dumps, and unrelated logs. Replace them with stable placeholders such as `<USER>`, `<WORKSPACE>`, and `<REDACTED>`.

## Pull requests

1. Open an issue first for behavior changes or substantial additions.
2. Keep changes focused and explain the diagnostic question they address.
3. Add or update tests for changed behavior.
4. Run both PowerShell test suites and report their results.
5. Check the diff for credentials, personal paths, generated reports, and unrelated files.
6. Describe any safety or platform limitations in the documentation.

The project must remain read-only with respect to Windows permissions, ACLs, owners, security settings, and WSL configuration. Do not add automatic elevation, security bypasses, installations, or repair actions.

## License

By contributing, you agree that your contributions are distributed under the [MIT License](LICENSE).
