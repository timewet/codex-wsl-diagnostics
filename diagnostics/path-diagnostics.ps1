[CmdletBinding()]
param(
    [string]$WindowsPath,
    [string]$ObservedLinuxPath,
    [switch]$IncludePaths
)

function New-PathDiagnosticResult {
    param(
        [Parameter(Mandatory)][string]$Status,
        [Parameter(Mandatory)][bool]$Matches,
        [Parameter(Mandatory)][string]$Message,
        [string]$ExpectedPath,
        [string]$ObservedPath,
        [switch]$IncludePaths
    )

    $result = [ordered]@{
        Status = $Status
        Matches = $Matches
        ContainsPaths = $IncludePaths.IsPresent
        Message = $Message
    }
    if ($IncludePaths) {
        $result.ExpectedPath = $ExpectedPath
        $result.ObservedPath = $ObservedPath
    }
    [pscustomobject]$result
}

function Test-WslPathTranslation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$WindowsPath,
        [Parameter(Mandatory)][AllowEmptyString()][string]$ObservedLinuxPath,
        [switch]$IncludePaths
    )

    if ([string]::IsNullOrWhiteSpace($WindowsPath) -or [string]::IsNullOrWhiteSpace($ObservedLinuxPath)) {
        return New-PathDiagnosticResult -Status 'InvalidInput' -Matches $false -Message 'Provide a Windows drive path and an observed absolute Linux path.' -IncludePaths:$IncludePaths
    }
    if ($WindowsPath -match '^(\\\\|//)') {
        return New-PathDiagnosticResult -Status 'UnsupportedPath' -Matches $false -Message 'UNC paths are not covered by the default WSL drive-mount mapping.' -IncludePaths:$IncludePaths
    }
    $windowsMatch = [regex]::Match($WindowsPath, '^([A-Za-z]):[\\/](.*)$')
    if (-not $windowsMatch.Success -or $ObservedLinuxPath -notmatch '^/') {
        return New-PathDiagnosticResult -Status 'InvalidInput' -Matches $false -Message 'Use an absolute drive-letter Windows path and an absolute Linux path.' -IncludePaths:$IncludePaths
    }

    $drive = $windowsMatch.Groups[1].Value.ToLowerInvariant()
    $relativePath = $windowsMatch.Groups[2].Value -replace '\\', '/'
    $expectedPath = "/mnt/$drive/$relativePath"
    $normalizedExpected = if ($expectedPath.Length -gt 1) { $expectedPath.TrimEnd('/') } else { $expectedPath }
    $normalizedObserved = if ($ObservedLinuxPath.Length -gt 1) { $ObservedLinuxPath.TrimEnd('/') } else { $ObservedLinuxPath }
    $matches = [string]::Equals($normalizedExpected, $normalizedObserved, [StringComparison]::Ordinal)
    if ($matches) {
        return New-PathDiagnosticResult -Status 'Match' -Matches $true -Message 'The observed path matches the default /mnt/<drive> mapping.' -ExpectedPath $expectedPath -ObservedPath $ObservedLinuxPath -IncludePaths:$IncludePaths
    }
    New-PathDiagnosticResult -Status 'Mismatch' -Matches $false -Message 'The observed path differs from the default /mnt/<drive> mapping; custom automount settings are not evaluated.' -ExpectedPath $expectedPath -ObservedPath $ObservedLinuxPath -IncludePaths:$IncludePaths
}

if ($MyInvocation.InvocationName -ne '.') {
    $result = Test-WslPathTranslation -WindowsPath $WindowsPath -ObservedLinuxPath $ObservedLinuxPath -IncludePaths:$IncludePaths
    $result | ConvertTo-Json -Compress
    switch ($result.Status) {
        'Match' { exit 0 }
        'Mismatch' { exit 1 }
        default { exit 2 }
    }
}