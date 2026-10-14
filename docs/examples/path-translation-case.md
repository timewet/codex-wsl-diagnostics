# Sanitized path-translation example

This synthetic example shows how to recognize a Windows path that has been appended to a Linux working directory.

## Inputs

- Windows workspace: `C:\workspace\sample`
- Expected default WSL path: `/mnt/c/workspace/sample`
- Example observed path: `/mnt/c/Program Files/App/resources/<WINDOWS_WORKSPACE_PATH>`

The observed value mixes a Linux directory with an opaque Windows path placeholder. It does not identify a real user, machine, project, or client build.

## Reproduce the comparison

```powershell
pwsh -NoProfile -File .\diagnostics\path-diagnostics.ps1 `
  -WindowsPath 'C:\workspace\sample' `
  -ObservedLinuxPath '/mnt/c/Program Files/App/resources/<WINDOWS_WORKSPACE_PATH>'
```

Expected result: `Status` is `Mismatch`, the process exits with code `1`, and the default JSON omits both path values. A normal mapping such as `/mnt/c/workspace/sample` returns `Match` and exit code `0`.

## Interpretation

A mismatch confirms only that the observed path differs from the default drive-mount mapping. Collect the actual working directory from the Codex WSL Agent itself; an integrated terminal running Linux does not prove that the Agent uses the same environment. The result does not prove the target exists or identify the layer responsible for constructing the path.
