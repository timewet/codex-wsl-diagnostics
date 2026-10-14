$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$toolPath = Join-Path $projectRoot 'diagnostics/path-diagnostics.ps1'
if (-not (Test-Path -LiteralPath $toolPath -PathType Leaf)) {
    throw 'Expected diagnostics/path-diagnostics.ps1 to provide the path comparison functions.'
}
. $toolPath

function Assert-Equal([object]$Actual, [object]$Expected, [string]$Name) {
    if ($Actual -cne $Expected) { throw "$Name`: expected '$Expected', got '$Actual'." }
}
function Assert-True([bool]$Value, [string]$Name) {
    if (-not $Value) { throw "$Name`: expected true." }
}

$result = Test-WslPathTranslation -WindowsPath 'C:\workspace\project' -ObservedLinuxPath '/mnt/c/workspace/project'
Assert-Equal $result.Status 'Match' 'Drive path maps to default WSL mount'
Assert-True $result.Matches 'Matched path status'

$result = Test-WslPathTranslation -WindowsPath 'D:/Work/project/' -ObservedLinuxPath '/mnt/d/Work/project'
Assert-Equal $result.Status 'Match' 'Forward slashes and trailing separator are normalized'

$result = Test-WslPathTranslation -WindowsPath 'D:\work\project' -ObservedLinuxPath '/mnt/c/work/project'
Assert-Equal $result.Status 'Mismatch' 'Wrong mount is reported'
Assert-True (-not $result.ContainsPaths) 'Default report omits input paths'

$result = Test-WslPathTranslation -WindowsPath 'relative\project' -ObservedLinuxPath '/mnt/c/project'
Assert-Equal $result.Status 'InvalidInput' 'Relative Windows paths are rejected'

$result = Test-WslPathTranslation -WindowsPath '\\server\share\project' -ObservedLinuxPath '/mnt/c/project'
Assert-Equal $result.Status 'UnsupportedPath' 'UNC paths are identified as unsupported'

$result = Test-WslPathTranslation -WindowsPath 'C:\workspace\project' -ObservedLinuxPath '/mnt/c/workspace/project' -IncludePaths
Assert-True $result.ContainsPaths 'Explicit path display is available'
Assert-Equal $result.ExpectedPath '/mnt/c/workspace/project' 'Expected path can be shown on request'

'RESULT passed=6 failed=0'