# Troubleshooting

Use this checklist to distinguish a WSL service problem from a Codex execution-context or path-mapping problem. The tools collect evidence; they do not repair the system.

## WSL command is denied

1. Record which application and execution context ran the command.
2. Run `diagnostics/wsl-check.ps1` from that same context.
3. Compare it with a report produced by `diagnostics/environment-check.ps1` in a non-elevated Windows session.
4. Treat `E_ACCESSDENIED` as evidence about that execution boundary. Do not infer that Ubuntu is corrupt or change permissions based on this result alone.

The context field is an operator-supplied label, not independent detection of the active Codex Agent.

## A Linux working directory is not found

Check the path observed inside the WSL Agent, not only the integrated terminal. Use `diagnostics/path-diagnostics.ps1` to compare an absolute Windows drive path with the default `/mnt/<drive>` form. A mismatch identifies a path-shape difference; it does not identify which client component created it or prove that the target exists.

The checker does not handle custom automount roots, UNC paths, or network shares. It reports UNC paths as unsupported.

## Ubuntu is not probed

The collector never starts a stopped distribution. Its Linux probe runs only when Ubuntu is already listed as running and the preceding WSL enumeration succeeds. Other registered distributions are listed but are not started or probed.

## Reports cannot be compared

Use reports with compatible schema versions and context fields. A report can be marked not comparable when a required field is missing or the execution identities differ. Do not interpret a comparison as proof of causation.

## Before asking for help

Run the local tests, retain only the relevant error category and command stage, and remove full paths, usernames, machine names, project identifiers, credentials, and unrelated output before sharing any details. See [Contributing](../CONTRIBUTING.md).
