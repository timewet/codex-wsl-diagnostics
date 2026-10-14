[CmdletBinding()]
param(
    [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$OutputRoot,
    [string]$CompareWith,
    [ValidateRange(1,120)][int]$TimeoutSeconds = 10
)

$entry = Join-Path $PSScriptRoot 'wsl-check.ps1'
& $entry -Context 'NormalUserSession' -ProjectRoot $ProjectRoot -OutputRoot $OutputRoot -CompareWith $CompareWith -TimeoutSeconds $TimeoutSeconds
exit $LASTEXITCODE
