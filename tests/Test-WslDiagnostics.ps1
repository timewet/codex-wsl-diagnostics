param([string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference = 'Stop'
$script:Passed = 0
$script:Failed = 0
function Assert-True($Value, [string]$Message) { if (-not $Value) { throw $Message } }
function Test-Case([string]$Name, [scriptblock]$Body) {
    try { & $Body; $script:Passed++; Write-Host ('PASS ' + $Name) }
    catch { $script:Failed++; Write-Host ('FAIL ' + $Name + ': ' + $_.Exception.Message) }
}
function New-DiagnosticCommandResult {
    param([string]$Stage,[string[]]$Arguments,[AllowNull()]$ExitCode,[string]$Stdout='',[string]$Stderr='')
    [pscustomobject]@{Stage=$Stage;Command='wsl.exe';Arguments=$Arguments;StartedUtc=[DateTime]::UtcNow.ToString('o');EndedUtc=[DateTime]::UtcNow.ToString('o');DurationMs=0;ExitCode=$ExitCode;TimedOut=$false;StartError='';CaptureIncomplete=$false;Stdout=$Stdout;Stderr=$Stderr;StdoutEncoding='test';StderrEncoding='test';StdoutBytes=0;StderrBytes=0}
}
function New-TimedComparisonReport {
    param([string]$Label,$Utc)
    [pscustomobject]@{SchemaVersion=1;Context=[pscustomobject]@{Label=$Label};Commands=@();Identity=[pscustomobject]@{UserFingerprint='same-user';HostFingerprint='same-host';Token=[pscustomobject]@{IsAdministrator=$false}};Tool=[pscustomobject]@{Version='1';ModuleSha256='same-hash'};Time=[pscustomobject]@{Utc=$Utc}}
}
$modulePath = Join-Path $ProjectRoot 'diagnostics/WslDiagnostics.psm1'
Test-Case 'core module is present' { Assert-True (Test-Path -LiteralPath $modulePath) 'The diagnostic core has not been implemented.' }
if (-not (Test-Path -LiteralPath $modulePath)) { Write-Host ('RESULT passed={0} failed={1}' -f $script:Passed,$script:Failed); exit 1 }
$module = Import-Module $modulePath -Force -PassThru
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('wsl-diagnostics-tests-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($testRoot)
$psExe = Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
try {
    Test-Case 'UTF16LE Chinese output has no null characters' {
        $r = ConvertFrom-DiagnosticBytes ([Text.Encoding]::Unicode.GetBytes('Ubuntu 正在运行'))
        Assert-True ($r.Text -eq 'Ubuntu 正在运行' -and $r.Encoding -eq 'utf-16le') 'UTF16LE was not decoded.'
    }
    Test-Case 'UTF8 Chinese stderr is decoded' {
        $r = ConvertFrom-DiagnosticBytes ([Text.Encoding]::UTF8.GetBytes('权限拒绝'))
        Assert-True ($r.Text -eq '权限拒绝' -and $r.Encoding -eq 'utf-8') 'UTF8 was not decoded.'
    }
    Test-Case 'empty stream is supported' { Assert-True ((ConvertFrom-DiagnosticBytes ([byte[]]@())).Text -eq '') 'Empty stream failed.' }
    Test-Case 'real process preserves separate output streams and exit code' {
        $r = Invoke-DiagnosticCommand -FilePath $psExe -Arguments @('-NoProfile','-NonInteractive','-Command','[Console]::Out.Write("out"); [Console]::Error.Write("err"); exit 7') -Stage 'test' -TimeoutSeconds 5
        Assert-True ($r.Stdout -eq 'out' -and $r.Stderr -eq 'err' -and $r.ExitCode -eq 7 -and -not $r.TimedOut) 'Process streams or exit code changed.'
    }
    Test-Case 'real process Unicode byte streams are decoded independently' {
        $code = '$o=[Text.Encoding]::Unicode.GetBytes([char]0x6743 + [string][char]0x9650); $e=[Text.Encoding]::UTF8.GetBytes([char]0x9519 + [string][char]0x8bef); [Console]::OpenStandardOutput().Write($o,0,$o.Length); [Console]::OpenStandardError().Write($e,0,$e.Length)'
        $r = Invoke-DiagnosticCommand $psExe @('-NoProfile','-NonInteractive','-Command',$code) 'test' 5
        Assert-True ($r.Stdout -eq '权限' -and $r.Stderr -eq '错误' -and $r.StdoutEncoding -eq 'utf-16le' -and $r.StderrEncoding -eq 'utf-8') 'Raw byte stream decode failed.'
    }
    Test-Case 'real process timeout is bounded' {
        $r = Invoke-DiagnosticCommand $psExe @('-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 20') 'test' 1
        Assert-True ($r.TimedOut -and $r.DurationMs -lt 6000) 'Timeout did not stop the started process.'
    }
    Test-Case 'quoted arguments with spaces and trailing slash survive' {
        $path = Join-Path $testRoot 'argument fixture.ps1'
        [IO.File]::WriteAllText($path,'param([string]$Value) [Console]::Out.Write($Value)',[Text.UTF8Encoding]::new($true))
        $wanted = 'a b"c\'
        $allowedPsExe = (Get-Process -Id $PID).Path
        $r = Invoke-DiagnosticCommand $allowedPsExe @('-NoProfile','-NonInteractive','-File',$path,'-Value',$wanted) 'test' 5
        Assert-True ($r.Stdout -eq $wanted -and $r.ExitCode -eq 0) 'Windows argument quoting changed the argument.'
    }
    Test-Case 'start errors become structured results' {
        $r = Invoke-DiagnosticCommand (Join-Path $testRoot 'missing.exe') @() 'path' 1
        Assert-True ($r.StartError -and $null -eq $r.ExitCode -and $r.Stage -eq 'path') 'Missing executable was not captured.'
    }
    Test-Case 'identities SIDs paths and secrets are redacted' {
        $inputText = 'User=private-person Host=private-host SID=S-1-5-21-111-222-333-1001 C:\Users\private-person\secret.txt token=abc123 password:xyz Bearer a.b.c Cookie: session=private'
        $r = Protect-DiagnosticText $inputText @('private-person','private-host')
        foreach ($private in @('private-person','private-host','S-1-5-21-111','abc123','xyz','a.b.c','session=private','secret.txt')) { Assert-True (-not $r.Contains($private)) ('Sensitive data remained: ' + $private) }
    }
    Test-Case 'quoted JSON secret properties and URL credentials are redacted' {
        $r = Protect-DiagnosticText '{"api_key":"private-key","password": "private-password"} https://user:password@example.invalid/'
        Assert-True ($r -notmatch 'private-key|private-password|private-credential|person:') 'Structured secret or URL credentials remained.'
    }
    Test-Case 'access denial retains the enumeration stage' {
        $r = Get-WslFailureCategory -Stage 'enumeration' -ExitCode -1 -Stdout 'Wsl/Service/EnumerateDistros/Service/E_ACCESSDENIED' -Context 'CodexSandbox'
        Assert-True ($r.Category -eq 'AccessDenied' -and $r.Stage -eq 'enumeration' -and $r.Scope -eq 'RestrictedContext' -and $r.Conclusion -match '不能') 'Access-denied stage or boundary was lost.'
    }
    Test-Case 'normal context access denial is not assumed to be sandbox' {
        $r = Get-WslFailureCategory -Stage 'status' -ExitCode -1 -Stderr 'E_ACCESSDENIED' -Context 'NormalUserSession'
        Assert-True ($r.Scope -eq 'Undetermined') 'Context label was treated as proof.'
    }
    Test-Case 'localized explicit invalid argument is classified' {
        $r = Get-WslFailureCategory 'enumeration' 1 '无效的命令行参数: --bogus' '' 'CodexSandbox'
        Assert-True ($r.Category -eq 'ArgumentError') 'Argument error was missed.'
    }
    Test-Case 'nonzero help output is not classified as invalid arguments' {
        $r = Get-WslFailureCategory 'version' -1 'Usage: wsl.exe [Argument] [Options]' '' 'CodexSandbox'
        Assert-True ($r.Category -eq 'UnknownFailure') 'Help text was treated as parameter failure.'
    }
    Test-Case 'WSL service errors are distinct' { Assert-True ((Get-WslFailureCategory 'status' 1 'Wsl/Service/WSL_E_SERVICE_NOT_AVAILABLE' '' 'CodexSandbox').Category -eq 'ServiceError') 'Service error missed.' }
    Test-Case 'distribution-not-found errors are distinct' { Assert-True ((Get-WslFailureCategory 'linux-true' 1 'Wsl/Service/WSL_E_DISTRO_NOT_FOUND' '' 'CodexSandbox').Category -eq 'DistributionError') 'Distribution error missed.' }
    Test-Case 'timeout results are partial' { Assert-True ((Get-WslFailureCategory 'status' $null '' '' 'CodexSandbox' -TimedOut).Category -eq 'Timeout') 'Timeout category missed.' }
    Test-Case 'safe config parser stores only sandbox whitelist' {
        $path = Join-Path $testRoot 'config.toml'
        [IO.File]::WriteAllText($path,'api_key="do-not-save"' + "`n[windows]`nsandbox = `"unelevated`"`n[other]`npassword = `"private`"`n",[Text.UTF8Encoding]::new($true))
        $r = Get-SafeDiagnosticConfig $path 'global'
        $json = $r | ConvertTo-Json -Depth 8
        Assert-True ($json -match 'unelevated' -and $json -notmatch 'do-not-save|private|api_key|password') 'Config whitelist leaked unrelated data.'
    }
    Test-Case 'missing project configuration is explicit' { Assert-True ((Get-SafeDiagnosticConfig (Join-Path $testRoot 'no-config.toml') 'project').Status -eq 'Missing') 'Missing override was omitted.' }
    Test-Case 'enumeration rejection never starts a distribution' {
        $script:Calls = [Collections.Generic.List[string]]::new()
        $runner = { param($FilePath,$Arguments,$Stage,$TimeoutSeconds) $script:Calls.Add($Stage); New-DiagnosticCommandResult $Stage $Arguments -1 'Wsl/Service/EnumerateDistros/Service/E_ACCESSDENIED' '' }
        $report = & $module { param($Root,$Out,$Runner) Invoke-WslDiagnosticCollection -Context CodexSandbox -ProjectRoot $Root -OutputRoot $Out -CommandRunner $Runner } $ProjectRoot $testRoot $runner
        Assert-True (-not ($script:Calls -contains 'linux-true') -and -not ($script:Calls -contains 'linux-environment') -and $report.ExitCode -eq 10) 'Enumeration failure caused startup or hid failure.'
        Assert-True ($report.LinuxChecks.Status -eq 'SkippedEnumerationUnavailable') 'Skipped Linux checks were not explicit.'
    }
    Test-Case 'stopped distribution never starts' {
        $runner = { param($FilePath,$Arguments,$Stage,$TimeoutSeconds) $out=''; if($Stage -eq 'enumeration'){$out='  NAME STATE VERSION' + "`n* Ubuntu Stopped 2"}; if($Stage -eq 'list-quiet'){$out='Ubuntu'}; New-DiagnosticCommandResult $Stage $Arguments 0 $out '' }
        $report = & $module { param($Root,$Out,$Runner) Invoke-WslDiagnosticCollection -Context CodexSandbox -ProjectRoot $Root -OutputRoot $Out -CommandRunner $Runner } $ProjectRoot $testRoot $runner
        Assert-True ($report.LinuxChecks.Status -eq 'SkippedNoRunningDistribution' -and $report.ExitCode -eq 20) 'Stopped distribution was probed.'
    }
    Test-Case 'running-list drives localized distribution selection' {
        $script:Calls = [Collections.Generic.List[string]]::new()
        $runner = { param($FilePath,$Arguments,$Stage,$TimeoutSeconds) $script:Calls.Add($Stage); $out=''; if($Stage -eq 'enumeration'){$out='名称 状态 版本' + "`n* Ubuntu 正在运行 2"}; if($Stage -in @('list-quiet','list-running')){$out='Ubuntu'}; if($Stage -eq 'linux-environment'){$out='WSL_DISTRO_NAME=Ubuntu' + "`nPWD=/mnt/c/Users/private-person`nUID=1000`nOS=Linux"}; New-DiagnosticCommandResult $Stage $Arguments 0 $out '' }
        $report = & $module { param($Root,$Out,$Runner) Invoke-WslDiagnosticCollection -Context CodexSandbox -ProjectRoot $Root -OutputRoot $Out -CommandRunner $Runner } $ProjectRoot $testRoot $runner
        Assert-True ($script:Calls -contains 'linux-true' -and $script:Calls -contains 'linux-environment' -and $report.LinuxChecks.Status -eq 'Completed') 'Running distribution was not validated.'
    }
    Test-Case 'running unrelated distributions are never probed' {
        $script:Calls=[Collections.Generic.List[string]]::new()
        $runner={param($FilePath,$Arguments,$Stage,$TimeoutSeconds) $script:Calls.Add($Stage); $out=''; if($Stage -eq 'enumeration'){$out='Ubuntu Stopped 2'}; if($Stage -eq 'list-quiet'){$out='Ubuntu' + "`n" + 'docker-desktop'}; if($Stage -eq 'list-running'){$out='docker-desktop'}; New-DiagnosticCommandResult $Stage $Arguments 0 $out ''}
        $report=& $module {param($Root,$Out,$Runner) Invoke-WslDiagnosticCollection -Context CodexSandbox -ProjectRoot $Root -OutputRoot $Out -CommandRunner $Runner} $ProjectRoot $testRoot $runner
        Assert-True ($report.LinuxChecks.Status -eq 'SkippedTargetNotRunning' -and $report.ExitCode -eq 20 -and -not ($script:Calls -contains 'linux-true')) 'A distribution outside the Ubuntu target was probed.'
    }
    Test-Case 'repeated reports have unique directories and structured Chinese report' {
        $runner = { param($FilePath,$Arguments,$Stage,$TimeoutSeconds) New-DiagnosticCommandResult $Stage $Arguments 0 '' '' }
        $first = & $module { param($Root,$Out,$Runner) Invoke-WslDiagnosticCollection -Context CodexSandbox -ProjectRoot $Root -OutputRoot $Out -CommandRunner $Runner } $ProjectRoot $testRoot $runner
        $second = & $module { param($Root,$Out,$Runner) Invoke-WslDiagnosticCollection -Context CodexSandbox -ProjectRoot $Root -OutputRoot $Out -CommandRunner $Runner } $ProjectRoot $testRoot $runner
        Assert-True ($first.RunId -ne $second.RunId -and (Test-Path -LiteralPath $first.JsonPath) -and (Test-Path -LiteralPath $first.MarkdownPath)) 'Repeated run overwrote a report.'
        $saved = Get-Content -LiteralPath $first.JsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $md = Get-Content -LiteralPath $first.MarkdownPath -Raw -Encoding UTF8
        Assert-True ($saved.Time.AsiaShanghai -and $saved.Context.LabelIsOperatorDeclaration -and $md -match '不表示.*修复') 'Report evidence boundary is missing.'
        Assert-True (-not ((Get-Content -LiteralPath $first.JsonPath -Raw -Encoding UTF8).Contains($env:USERPROFILE))) 'Report leaked current user path.'
    }
    Test-Case 'comparison identifies per-stage changes and refuses incompatible schema' {
        $a = [pscustomobject]@{SchemaVersion=1; Context=[pscustomobject]@{Label='CodexSandbox'}; Commands=@([pscustomobject]@{Stage='enumeration';ExitCode=-1;Stdout='E_ACCESSDENIED';Stderr='';Classification=[pscustomobject]@{Category='AccessDenied'}})}
        $b = [pscustomobject]@{SchemaVersion=1; Context=[pscustomobject]@{Label='NormalUserSession'}; Commands=@([pscustomobject]@{Stage='enumeration';ExitCode=0;Stdout='Ubuntu';Stderr='';Classification=[pscustomobject]@{Category='Success'}})}
        $c = Compare-WslDiagnosticReport $a $b
        Assert-True ($c.Changes.Count -eq 1 -and $c.Changes[0].Stage -eq 'enumeration') 'Comparison lost stage change.'
        $b.SchemaVersion=999; $threw=$false; try { Compare-WslDiagnosticReport $a $b | Out-Null } catch { $threw=$true }; Assert-True $threw 'Incompatible schema was accepted.'
    }
    Test-Case 'two existing reports can be compared without collecting WSL' {
        $a=[pscustomobject]@{SchemaVersion=1;Context=[pscustomobject]@{Label='CodexSandbox'};Commands=@([pscustomobject]@{Stage='enumeration';ExitCode=-1;Stdout='E_ACCESSDENIED';Stderr='';Classification=[pscustomobject]@{Category='AccessDenied'}})}
        $b=[pscustomobject]@{SchemaVersion=1;Context=[pscustomobject]@{Label='NormalUserSession'};Commands=@([pscustomobject]@{Stage='enumeration';ExitCode=0;Stdout='Ubuntu';Stderr='';Classification=[pscustomobject]@{Category='Success'}})}
        $aPath=Join-Path $testRoot 'a.json';$bPath=Join-Path $testRoot 'b.json'
        [IO.File]::WriteAllText($aPath,($a|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($true));[IO.File]::WriteAllText($bPath,($b|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($true))
        $r=Invoke-WslDiagnosticComparison $aPath $bPath $testRoot
        Assert-True ($r.ExitCode -eq 0 -and (Test-Path -LiteralPath $r.JsonPath) -and (Test-Path -LiteralPath $r.MarkdownPath)) 'Pure report comparison did not create outputs.'
    }
    Test-Case 'missing comparison identity and tool fields are marked unverified' {
        $a=[pscustomobject]@{SchemaVersion=1;Context=[pscustomobject]@{Label='CodexSandbox'};Commands=@()}
        $b=[pscustomobject]@{SchemaVersion=1;Context=[pscustomobject]@{Label='NormalUserSession'};Commands=@()}
        $r=Compare-WslDiagnosticReport $a $b
        Assert-True ($r.Validity.Status -eq 'NotVerified' -and $r.Validity.Warnings.Count -gt 0) 'Missing comparison evidence was accepted.'
    }
    Test-Case 'different user or module evidence is marked not comparable' {
        $a=[pscustomobject]@{SchemaVersion=1;Context=[pscustomobject]@{Label='CodexSandbox'};Commands=@();Identity=[pscustomobject]@{UserFingerprint='user-a';HostFingerprint='host';Token=[pscustomobject]@{IsAdministrator=$false}};Tool=[pscustomobject]@{Version='1';ModuleSha256='hash-a'};Time=[pscustomobject]@{Utc=[DateTime]::UtcNow.ToString('o')}}
        $b=[pscustomobject]@{SchemaVersion=1;Context=[pscustomobject]@{Label='NormalUserSession'};Commands=@();Identity=[pscustomobject]@{UserFingerprint='user-b';HostFingerprint='host';Token=[pscustomobject]@{IsAdministrator=$false}};Tool=[pscustomobject]@{Version='1';ModuleSha256='hash-b'};Time=[pscustomobject]@{Utc=[DateTime]::UtcNow.ToString('o')}}
        $r=Compare-WslDiagnosticReport $a $b
        Assert-True ($r.Validity.Status -eq 'NotComparable') 'Changed user/module was accepted as a valid comparison.'
        $b.Identity.UserFingerprint='user-a';$b.Tool.ModuleSha256='hash-a'
        Assert-True ((Compare-WslDiagnosticReport $a $b).Validity.Status -eq 'Comparable') 'Matching valid evidence was rejected.'
        $b.Identity.Token.IsAdministrator=$true
        Assert-True ((Compare-WslDiagnosticReport $a $b).Validity.Status -eq 'NotComparable') 'Elevated normal session was accepted.'
    }
    Test-Case 'mixed JSON DateTime and ISO string preserve exact UTC interval' {
        $parsed='{"Time":{"Utc":"2026-10-13T16:22:08.4430703Z"}}'|ConvertFrom-Json
        $a=New-TimedComparisonReport 'CodexSandbox' $parsed.Time.Utc
        $b=New-TimedComparisonReport 'NormalUserSession' '2026-10-13T16:35:26.5121138Z'
        $r=Compare-WslDiagnosticReport $a $b
        Assert-True ([Math]::Abs($r.Validity.CollectionIntervalHours-0.22168584541666667) -lt 0.0000000001) ('UTC DateTime/string comparison is wrong: ' + $r.Validity.CollectionIntervalHours)
        $a.Time.Utc='2026-10-13T16:22:08.4430703Z'
        $b.Time.Utc=[DateTime]::Parse('2026-10-13T16:35:26.5121138Z',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind)
        $r=Compare-WslDiagnosticReport $a $b
        Assert-True ([Math]::Abs($r.Validity.CollectionIntervalHours-0.22168584541666667) -lt 0.0000000001) 'Reversed mixed types changed the UTC interval.'
    }
    Test-Case 'two deserialized real-report timestamps preserve fractional seconds' {
        $parsed='{"a":"2026-10-13T16:22:08.4430703Z","b":"2026-10-13T16:35:26.5121138Z"}'|ConvertFrom-Json
        $a=New-TimedComparisonReport 'CodexSandbox' $parsed.a
        $b=New-TimedComparisonReport 'NormalUserSession' $parsed.b
        $r=Compare-WslDiagnosticReport $a $b
        Assert-True ([Math]::Abs($r.Validity.CollectionIntervalHours-0.22168584541666667) -lt 0.0000000001) 'Deserialized DateTime fractions were discarded.'
    }
    Test-Case 'UTC comparison crossing midnight is independent of local offset' {
        $utc=[DateTime]::Parse('2026-10-13T23:59:50.100Z',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind)
        $a=New-TimedComparisonReport 'CodexSandbox' $utc
        $b=New-TimedComparisonReport 'NormalUserSession' '2026-10-14T00:00:10.200Z'
        $r=Compare-WslDiagnosticReport $a $b
        Assert-True ([Math]::Abs($r.Validity.CollectionIntervalHours-(20.1/3600)) -lt 0.0000000001) 'Midnight crossing introduced a timezone shift.'
    }
    Test-Case '24-hour warning uses precise UTC interval for mixed types' {
        $utc=[DateTime]::Parse('2026-10-13T16:00:00.000Z',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind)
        $a=New-TimedComparisonReport 'CodexSandbox' $utc
        $b=New-TimedComparisonReport 'NormalUserSession' '2026-10-14T15:30:00.000Z'
        $r=Compare-WslDiagnosticReport $a $b
        Assert-True ($r.Validity.Checks.CollectionTime -eq 'Within24Hours' -and $r.Validity.CollectionIntervalHours -eq 23.5) 'A 23.5-hour interval was incorrectly marked older than 24 hours.'
        $b.Time.Utc=[DateTime]::Parse('2026-10-14T16:00:00.001Z',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind)
        $r=Compare-WslDiagnosticReport $a $b
        Assert-True ($r.Validity.Checks.CollectionTime -eq 'MoreThan24Hours' -and [Math]::Abs($r.Validity.CollectionIntervalHours-(24+0.001/3600)) -lt 0.0000000001) 'The fraction above 24 hours was lost.'
    }
    Test-Case 'untrusted comparison fields cannot leak secrets or corrupt JSON' {
        $a=[pscustomobject]@{SchemaVersion=1;Context=[pscustomobject]@{Label='token=FAKE_COMPARE_MARKER'};Commands=@([pscustomobject]@{Stage='password=FAKE_COMPARE_MARKER';ExitCode='token=FAKE_COMPARE_MARKER';Stdout='';Stderr='';Classification=[pscustomobject]@{Category='token=FAKE_COMPARE_MARKER'}})}
        $b=[pscustomobject]@{SchemaVersion=1;Context=[pscustomobject]@{Label='NormalUserSession'};Commands=@()}
        $json=(Compare-WslDiagnosticReport $a $b)|ConvertTo-Json -Depth 12
        Assert-True ($json -notmatch 'FAKE_COMPARE_MARKER') 'Untrusted comparison fields leaked a fake secret.'
        $aPath=Join-Path $testRoot 'untrusted-a.json';$bPath=Join-Path $testRoot 'untrusted-b.json'
        [IO.File]::WriteAllText($aPath,($a|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($true));[IO.File]::WriteAllText($bPath,($b|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($true))
        $r=Invoke-WslDiagnosticComparison $aPath $bPath $testRoot
        Assert-True ($r.ExitCode -eq 0) 'Comparison of supported schema failed.'
        $saved=Get-Content -LiteralPath $r.JsonPath -Raw -Encoding UTF8
        Assert-True ($saved -notmatch 'FAKE_COMPARE_MARKER') 'Saved comparison leaked a fake secret.'
        $parsed=$saved|ConvertFrom-Json
        Assert-True ($parsed.SchemaVersion -eq 1) 'Saved comparison was not valid JSON.'
    }
    Test-Case 'report failure has explicit internal exit status' {
        $obstruction = Join-Path $testRoot 'not-a-directory'; [IO.File]::WriteAllText($obstruction,'x')
        $report = Invoke-WslDiagnostics -Context CodexSandbox -ProjectRoot $ProjectRoot -OutputRoot $obstruction
        Assert-True ($report.ExitCode -eq 30 -and $report.Error) 'Report-write error was not internal status 30.'
    }
    Test-Case 'required configuration read failures produce partial status' {
        $runner={param($FilePath,$Arguments,$Stage,$TimeoutSeconds) $out='';if($Stage -in @('list-quiet','list-running')){$out='Ubuntu'};New-DiagnosticCommandResult $Stage $Arguments 0 $out ''}
        $report=& $module {
            param($Root,$Out,$Runner)
            function Get-SafeDiagnosticConfig {param($Path,$Source) [pscustomobject]@{Source=$Source;Status='ReadError';Settings=[pscustomobject]@{};Error='Permission denied';RawContentSaved=$false}}
            Invoke-WslDiagnosticCollection -Context CodexSandbox -ProjectRoot $Root -OutputRoot $Out -CommandRunner $Runner
        } $ProjectRoot $testRoot $runner
        Assert-True ($report.ExitCode -eq 20 -and $report.LinuxChecks.Status -eq 'Completed') 'Configuration read failures were reported as full success.'
    }
    Test-Case 'normal user entry rejects administrator before WSL commands' {
        $r = & $module { Test-DiagnosticSessionPermission -Context 'NormalUserSession' -IsAdministrator $true }
        Assert-True (-not $r.Allowed -and $r.ExitCode -eq 20) 'Administrative normal-session comparison was accepted.'
    }
    Test-Case 'invalid entry context returns internal status without WSL output' {
        $entry=Join-Path $ProjectRoot 'diagnostics/wsl-check.ps1';$invalidOut=Join-Path $testRoot 'invalid-context-output'
        $r=Invoke-DiagnosticCommand (Get-Process -Id $PID).Path @('-NoProfile','-NonInteractive','-File',$entry,'-Context','InvalidContext','-ProjectRoot',$ProjectRoot,'-OutputRoot',$invalidOut) 'test' 5
        Assert-True ($r.ExitCode -eq 30 -and -not (Test-Path -LiteralPath $invalidOut)) 'Invalid context did not stop before collection with status 30.'
    }
} finally {
    $resolvedTest = [IO.Path]::GetFullPath($testRoot)
    $resolvedTemp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if ($resolvedTest.StartsWith($resolvedTemp,[StringComparison]::OrdinalIgnoreCase) -and (Split-Path -Leaf $resolvedTest) -like 'wsl-diagnostics-tests-*') { Remove-Item -LiteralPath $resolvedTest -Recurse -Force }
}
Write-Host ('RESULT passed={0} failed={1}' -f $script:Passed,$script:Failed)
if ($script:Failed -gt 0) { exit 1 }; exit 0
