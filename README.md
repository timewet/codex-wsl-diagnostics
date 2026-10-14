# codex-wsl-diagnostics

A small, read-only diagnostic toolkit for investigating integration issues between Codex Desktop and WSL 2. It also reports general WSL and Windows execution-environment information.

## Use cases

- A Codex WSL Agent fails to start or reports that a working directory cannot be found.
- A Windows path appears malformed after being passed to a Linux process.
- The same task behaves differently in Codex Desktop and a normal Windows session.
- You need a concise, redacted report of WSL availability and selected host-environment details.

## What it does

- Checks WSL version, status, and registered/running distributions.
- Collects selected PowerShell and Windows environment metadata, safe configuration values, and summarized project ACL information.
- Probes Ubuntu only when it is already running; it does not start a stopped distribution.
- Produces JSON and Markdown reports and compares compatible reports from different execution contexts.
- Compares a Windows drive path with an observed Linux path using the default `/mnt/<drive>` mapping.
- Redacts paths and common sensitive values from generated reports.

The context label (`CodexSandbox` or `NormalUserSession`) is supplied by the operator. The report does not independently prove which Codex Agent environment is active.

## Requirements

- Windows with WSL 2 and `wsl.exe` for WSL checks.
- PowerShell 7 (`pwsh`) for the diagnostic scripts and tests.
- No additional runtime packages.

## Usage

Run the full WSL and environment report from the context you want to inspect:

```powershell
pwsh -NoProfile -File .\diagnostics\wsl-check.ps1 -Context CodexSandbox -ProjectRoot .
```

For a comparison report, first create a `CodexSandbox` report, then run this from a non-elevated normal Windows PowerShell session:

```powershell
pwsh -NoProfile -File .\diagnostics\environment-check.ps1 -ProjectRoot .
```

The normal-session report looks for a compatible earlier sandbox report. Reports are written under `logs/diagnostics/`, which is ignored by Git. Review generated reports before sharing them; redaction reduces exposure but does not guarantee that every environment-specific value is anonymous.

To compare one Windows path with the working directory observed inside a WSL Agent, pass both values to the standalone path checker:

```powershell
pwsh -NoProfile -File .\diagnostics\path-diagnostics.ps1 `
  -WindowsPath 'C:\workspace\sample' `
  -ObservedLinuxPath '/mnt/c/workspace/sample'
```

By default, the JSON result omits both paths. Add `-IncludePaths` only when you need to see the exact comparison locally. The checker performs a lexical comparison; it does not run WSL or prove that either path exists.

Run the offline test suites with:

```powershell
pwsh -NoProfile -File .\tests\Test-WslDiagnostics.ps1
pwsh -NoProfile -File .\tests\Test-PathDiagnostics.ps1
```

## Limits and safety

This project is a diagnostic aid, not a repair tool. It does not change Windows permissions, ACLs, owners, security policy, Codex settings, or WSL configuration. It does not disable sandbox protections, elevate privileges, install software, or reinstall WSL. A path match only confirms the default path-mapping shape; it does not establish the cause of a launch failure.

For custom WSL automount locations, network shares, or non-drive paths, the path checker reports the limits of its default mapping rather than guessing.

## Documentation

- [Troubleshooting](docs/troubleshooting.md)
- [Architecture](docs/architecture.md)
- [Sanitized path-translation example](docs/examples/path-translation-case.md)
- [Contributing](CONTRIBUTING.md)

## License

MIT. See [LICENSE](LICENSE).
