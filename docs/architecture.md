# Architecture

## Components

`diagnostics/wsl-check.ps1` is the command-line entry point. It validates the operator-supplied context label and delegates collection and report comparison to `diagnostics/WslDiagnostics.psm1`.

The module separates the work into four parts:

1. **Environment collection** reads selected PowerShell/Windows metadata, approved Codex configuration keys, and summarized ACL information. Full paths and identity values are not intended as report fields.
2. **WSL collection** resolves `wsl.exe`, checks WSL version and status, and lists distributions. It probes the Ubuntu Linux environment only if Ubuntu is already running; it does not start a stopped distribution.
3. **Classification and redaction** assigns a category to each command result and removes common path and secret patterns before report generation.
4. **Report comparison** checks schema compatibility and compares stage-level results without assuming that similar error codes have the same cause.

`diagnostics/environment-check.ps1` is a convenience entry point for a normal, non-elevated Windows session. It sets the context label to `NormalUserSession` and produces the same report shape so it can be compared with a prior Codex sandbox report.

`diagnostics/path-diagnostics.ps1` is independent of WSL execution. It converts an absolute drive-letter path to the default `/mnt/<drive>` form and compares that result with a caller-provided Linux path. It does not inspect the filesystem, custom mount settings, or Codex Desktop internals.

## Data flow

```text
operator context and project root
              |
              v
   wsl-check.ps1 / environment-check.ps1
              |
              v
       WslDiagnostics.psm1
       |       |        |
 environment  WSL   comparison
       \       |       /
         redaction and classification
                    |
                    v
          JSON + Markdown reports
```

The path checker has a separate flow:

```text
Windows drive path + observed Linux path -> default mapping comparison -> status JSON
```

## Safety boundaries

The tools do not edit configuration, permissions, ACLs, owners, system security policy, or WSL settings. Reports are local artifacts under `logs/diagnostics/`; the directory is ignored by Git. Redaction is defense in depth, not a guarantee that a report is safe to publish. Review any report manually before sharing it.

## Tests

`tests/Test-WslDiagnostics.ps1` exercises collection, classification, redaction, and report comparison. `tests/Test-PathDiagnostics.ps1` covers path mapping and the default omission of input paths.
