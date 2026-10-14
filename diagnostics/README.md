# Diagnostic entry points

- `wsl-check.ps1` creates the combined WSL and host-environment report. The context label is supplied by the caller.
- `environment-check.ps1` runs the same collector with the `NormalUserSession` label, for comparison from a non-elevated Windows session.
- `path-diagnostics.ps1` compares a Windows drive path with an observed Linux path using the default `/mnt/<drive>` mapping. It does not invoke WSL.

See the root README for commands and limitations.
