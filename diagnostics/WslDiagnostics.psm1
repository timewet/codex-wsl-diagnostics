Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function ConvertFrom-DiagnosticBytes {
    param([AllowEmptyCollection()][byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return [pscustomobject]@{Text='';Encoding='empty'} }
    $encoding = 'utf-8'; $offset = 0
    if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 255 -and $Bytes[1] -eq 254) { $encoding='utf-16le';$offset=2 }
    elseif ($Bytes.Length -ge 2 -and $Bytes[0] -eq 254 -and $Bytes[1] -eq 255) { $encoding='utf-16be';$offset=2 }
    elseif ($Bytes.Length -ge 3 -and $Bytes[0] -eq 239 -and $Bytes[1] -eq 187 -and $Bytes[2] -eq 191) { $offset=3 }
    else {
        $evenZero=0; $oddZero=0; $pairs=[Math]::Floor([Math]::Min($Bytes.Length,256)/2)
        for ($i=0;$i -lt $pairs;$i++) { if($Bytes[2*$i] -eq 0){$evenZero++};if($Bytes[2*$i+1] -eq 0){$oddZero++} }
        if ($pairs -gt 0 -and $oddZero -ge [Math]::Max(1,$pairs*0.25) -and $oddZero -gt $evenZero) { $encoding='utf-16le' }
        elseif ($pairs -gt 0 -and $evenZero -ge [Math]::Max(1,$pairs*0.25) -and $evenZero -gt $oddZero) { $encoding='utf-16be' }
    }
    if($encoding -eq 'utf-16le'){$decoder=[Text.Encoding]::Unicode}
    elseif($encoding -eq 'utf-16be'){$decoder=[Text.Encoding]::BigEndianUnicode}
    else{
        $decoder=[Text.UTF8Encoding]::new($false,$true)
        try { [void]$decoder.GetString($Bytes,$offset,$Bytes.Length-$offset) }
        catch { if(($Bytes.Length-$offset)%2 -eq 0){$encoding='utf-16le';$decoder=[Text.Encoding]::Unicode}else{$decoder=[Text.Encoding]::UTF8;$encoding='utf-8-with-replacement'} }
    }
    [pscustomobject]@{Text=$decoder.GetString($Bytes,$offset,$Bytes.Length-$offset).TrimStart([char]0xFEFF);Encoding=$encoding}
}

function Protect-DiagnosticText {
    param([AllowNull()][string]$Text,[string[]]$SensitiveValues=@())
    if ($null -eq $Text) { return '' }
    $result=$Text
    # Remove whole paths before replacing their identity components, so placeholders do not split paths.
    $result=[regex]::Replace($result,'(?i)\b[A-Z]:[\\/][^\r\n"''<>|]*','<PATH>')
    $result=[regex]::Replace($result,'(?i)\\\\[^\s\\]+\\[^\r\n"''<>|]*','<PATH>')
    $result=[regex]::Replace($result,'(?i)/(?:home|mnt/[a-z]/Users)/[^\s"''<>]+','<PATH>')
    $values=@($SensitiveValues) + @($env:USERPROFILE,$env:USERNAME,$env:COMPUTERNAME,$env:USERDOMAIN)
    foreach($value in @($values | Where-Object { $_ -and $_.Length -ge 3 } | Sort-Object Length -Descending -Unique)) {
        $result=[regex]::Replace($result,[regex]::Escape($value),'<REDACTED>',[Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }
    $result=[regex]::Replace($result,'(?i)S-1-\d+(?:-\d+){1,15}','<SID>')
    $result=[regex]::Replace($result,'(?i)\b(?:Bearer)\s+[^\s,;]+','Bearer <REDACTED>')
    $result=[regex]::Replace($result,'(?im)\b(?:cookie|set-cookie)\s*:\s*[^\r\n]+','Cookie: <REDACTED>')
    $result=[regex]::Replace($result,'(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|token|password|passwd|secret|authorization)\s*[=:]\s*(?:"[^"]*"|''[^'']*''|[^\s,;]+)','$1=<REDACTED>')
    $result=[regex]::Replace($result,'(?i)(["''](?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|password|passwd|secret|authorization)["'']\s*:\s*)["''][^"'']*["'']','$1"<REDACTED>"')
    $result=[regex]::Replace($result,'(?i)(https?://)[^\s/@:]+:[^\s/@]+@','$1<REDACTED>@')
    $result=[regex]::Replace($result,'(?i)\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{12,})\b','<REDACTED>')
    $result=[regex]::Replace($result,'(?is)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----','<REDACTED_PRIVATE_KEY>')
    $result=[regex]::Replace($result,'(?i)\b[A-Z]:[\\/][^\r\n"''<>|]*','<PATH>')
    $result=[regex]::Replace($result,'(?i)\\\\[^\s\\]+\\[^\r\n"''<>|]*','<PATH>')
    $result=[regex]::Replace($result,'(?i)/(?:home|mnt/[a-z]/Users)/[^\s"''<>]+','<PATH>')
    return $result
}

function Join-NativeArguments {
    param([string[]]$Arguments)
    $quoted = foreach($arg in $Arguments) {
        if($null -eq $arg){$arg=''}
        if($arg -notmatch '[\s"]' -and $arg.Length -gt 0){$arg;continue}
        $builder=[Text.StringBuilder]::new();[void]$builder.Append('"');$slashes=0
        foreach($c in $arg.ToCharArray()) {
            if($c -eq '\'){$slashes++;continue}
            if($c -eq '"'){[void]$builder.Append(('\' * ($slashes*2+1)));[void]$builder.Append('"')}
            else{if($slashes){[void]$builder.Append(('\' * $slashes))};[void]$builder.Append($c)}
            $slashes=0
        }
        if($slashes){[void]$builder.Append(('\' * ($slashes*2)))}
        [void]$builder.Append('"');$builder.ToString()
    }
    return ($quoted -join ' ')
}

function Invoke-DiagnosticCommand {
    param([Parameter(Mandatory=$true)][string]$FilePath,[string[]]$Arguments=@(),[string]$Stage='command',[ValidateRange(1,120)][int]$TimeoutSeconds=10)
    $start=[DateTime]::UtcNow;$watch=[Diagnostics.Stopwatch]::StartNew();$process=[Diagnostics.Process]::new()
    $stdout=[IO.MemoryStream]::new();$stderr=[IO.MemoryStream]::new();$exitCode=$null;$timeout=$false;$startError='';$captureIncomplete=$false
    try {
        $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$FilePath;$info.Arguments=Join-NativeArguments $Arguments
        $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
        $process.StartInfo=$info
        [void]$process.Start()
        $outTask=$process.StandardOutput.BaseStream.CopyToAsync($stdout);$errTask=$process.StandardError.BaseStream.CopyToAsync($stderr)
        if(-not $process.WaitForExit($TimeoutSeconds*1000)) {
            $timeout=$true
            try { $process.Kill() } catch { $captureIncomplete=$true }
            [void]$process.WaitForExit(1000)
        }
        if($process.HasExited){$exitCode=$process.ExitCode}
        if(-not $outTask.Wait(1000)){$captureIncomplete=$true}
        if(-not $errTask.Wait(1000)){$captureIncomplete=$true}
    } catch { $startError=Protect-DiagnosticText $_.Exception.Message }
    finally { $watch.Stop() }
    $outBytes=$stdout.ToArray();$errBytes=$stderr.ToArray()
    $out=ConvertFrom-DiagnosticBytes $outBytes;$err=ConvertFrom-DiagnosticBytes $errBytes
    $result=[pscustomobject]@{
        Stage=$Stage;Command=Protect-DiagnosticText ([IO.Path]::GetFileName($FilePath));Arguments=@($Arguments | ForEach-Object { Protect-DiagnosticText $_ })
        StartedUtc=$start.ToString('o');EndedUtc=[DateTime]::UtcNow.ToString('o');DurationMs=$watch.ElapsedMilliseconds
        ExitCode=$exitCode;TimedOut=$timeout;StartError=$startError;CaptureIncomplete=$captureIncomplete
        Stdout=Protect-DiagnosticText $out.Text;Stderr=Protect-DiagnosticText $err.Text
        StdoutEncoding=$out.Encoding;StderrEncoding=$err.Encoding;StdoutBytes=$outBytes.Length;StderrBytes=$errBytes.Length
    }
    $process.Dispose();$stdout.Dispose();$stderr.Dispose()
    return $result
}

function Get-WslFailureCategory {
    param([string]$Stage,[AllowNull()]$ExitCode,[string]$Stdout='',[string]$Stderr='',[string]$Context='CodexSandbox',[switch]$TimedOut,[string]$StartError='')
    $text=$Stdout + "`n" + $Stderr;$scope='Undetermined';$category='Success';$conclusion='本命令完成；不表示权限故障已修复。'
    if($TimedOut){$category='Timeout';$conclusion='命令超时；结果不完整，未自动重试。'}
    elseif($StartError){$category='InvocationError';$conclusion='进程未正常启动或输出捕获失败；须独立核实执行入口。'}
    elseif($text -match '(?i)E_ACCESSDENIED|0x80070005|access (?:is )?denied|拒绝访问|访问被拒绝') {
        $category='AccessDenied';if($Context -eq 'CodexSandbox'){$scope='RestrictedContext'}
        $conclusion='访问在该阶段被拒绝；上下文标签不能证明沙箱机制，不能据此判断 WSL 损坏或唯一根因。'
    }
    elseif($text -match '(?i)WSL_E_DISTRO_NOT_FOUND|WSL_E_DISTRO_NOT_INSTALLED|distribution.+(?:not found|not installed)|没有.+分发|不存在.+发行版'){$category='DistributionError';$conclusion='输出指向发行版查询故障；需结合正常会话核实。'}
    elseif($text -match '(?i)WSL_E_SERVICE|Wsl/Service/(?:CreateInstance|CreateVm).+(?:ERROR|E_)|HCS_E_|service.+(?:not available|not running)|服务.+(?:不可用|未运行)'){$category='ServiceError';$conclusion='输出指向 WSL 或虚拟化服务故障；不自动修改服务。'}
    elseif($text -match '(?i)invalid (?:command.line )?(?:argument|option|parameter)|unrecognized (?:option|argument)|无效.{0,8}(?:参数|选项)|无法识别.{0,8}(?:参数|选项)|E_INVALIDARG'){$category='ArgumentError';$conclusion='输出明确报告命令参数错误；核对调用方式。'}
    elseif($null -eq $ExitCode -or $ExitCode -ne 0){$category='UnknownFailure';$conclusion='退出异常但证据不足；不能仅凭非零退出码或帮助文本判断参数错误。'}
    [pscustomobject]@{Stage=$Stage;Category=$category;Scope=$scope;Conclusion=$conclusion}
}

function Get-SafeDiagnosticConfig {
    param([string]$Path,[string]$Source)
    $settings=[ordered]@{};$status='Missing';$errorText=''
    if(Test-Path -LiteralPath $Path -PathType Leaf) {
        try {
            $status='Read';$section=''
            foreach($line in [IO.File]::ReadAllLines($Path)) {
                if($line -match '^\s*\[([^\]]+)\]\s*(?:#.*)?$'){$section=$matches[1];continue}
                if($line -match '^\s*(sandbox_mode|approval_policy|sandbox)\s*=\s*["'']([^"'']+)["'']\s*(?:#.*)?$') {
                    $key=$matches[1];$value=$matches[2]
                    if(($section -eq '' -and $key -in @('sandbox_mode','approval_policy')) -or ($section -eq 'windows' -and $key -eq 'sandbox')) {
                        $safeValues=@('read-only','workspace-write','danger-full-access','untrusted','on-failure','on-request','never','unelevated','elevated')
                        if($value -in $safeValues){$settings[($section + '.' + $key).TrimStart('.')]=$value}else{$settings[($section + '.' + $key).TrimStart('.')]='<UNRECOGNIZED_VALUE>'}
                    }
                }
            }
        } catch {$status='ReadError';$errorText=Protect-DiagnosticText $_.Exception.Message}
    }
    [pscustomobject]@{Source=$Source;Status=$status;Settings=[pscustomobject]$settings;Error=$errorText;RawContentSaved=$false}
}

function Get-DiagnosticFingerprint {
    param([string]$Value)
    $sha=[Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))).Replace('-','').Substring(0,16).ToLowerInvariant()) }
    finally {$sha.Dispose()}
}

function Get-DiagnosticToken {
    $data=[ordered]@{Status='Unavailable';IsAdministrator=$null;IsElevated=$null;IsRestricted=$null;IsAppContainer=$null;IntegrityRid=$null;IntegrityLevel='Unknown';ElevationType=$null;Error=''}
    try {
        $identity=[Security.Principal.WindowsIdentity]::GetCurrent();$principal=[Security.Principal.WindowsPrincipal]::new($identity)
        $data.IsAdministrator=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if(-not ('WslDiagnosticNative.TokenReader' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace WslDiagnosticNative {
 public static class TokenReader {
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr p,uint a,out IntPtr t);
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool GetTokenInformation(IntPtr t,int c,IntPtr b,int n,out int l);
  [DllImport("advapi32.dll")] static extern bool IsTokenRestricted(IntPtr t);
  [DllImport("advapi32.dll")] static extern IntPtr GetSidSubAuthorityCount(IntPtr s);
  [DllImport("advapi32.dll")] static extern IntPtr GetSidSubAuthority(IntPtr s,uint n);
  static int Read(IntPtr t,int c) { int n;GetTokenInformation(t,c,IntPtr.Zero,0,out n);if(n<=0) return -1;IntPtr b=Marshal.AllocHGlobal(n);try {if(!GetTokenInformation(t,c,b,n,out n))return -1;if(c==25){IntPtr s=Marshal.ReadIntPtr(b);byte count=Marshal.ReadByte(GetSidSubAuthorityCount(s));return count==0?-1:Marshal.ReadInt32(GetSidSubAuthority(s,(uint)(count-1)));}return Marshal.ReadInt32(b);}finally{Marshal.FreeHGlobal(b);} }
  public static int[] ReadCurrent() {IntPtr t;if(!OpenProcessToken(GetCurrentProcess(),8,out t))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());try{return new[]{Read(t,20),IsTokenRestricted(t)?1:0,Read(t,29),Read(t,25),Read(t,18)};}finally{CloseHandle(t);} }
 }
}
'@ | Out-Null
        }
        $values=[WslDiagnosticNative.TokenReader]::ReadCurrent()
        $data.IsElevated=if($values[0] -ge 0){$values[0] -ne 0}else{$null}
        $data.IsRestricted=$values[1] -ne 0;$data.IsAppContainer=if($values[2] -ge 0){$values[2] -ne 0}else{$null}
        $data.IntegrityRid=$values[3];$data.ElevationType=$values[4]
        if($values[3] -ge 16384){$data.IntegrityLevel='System'}elseif($values[3] -ge 12288){$data.IntegrityLevel='High'}elseif($values[3] -ge 8192){$data.IntegrityLevel='Medium'}elseif($values[3] -ge 4096){$data.IntegrityLevel='Low'}elseif($values[3] -ge 0){$data.IntegrityLevel='Untrusted'}
        $data.Status=if($values -contains -1){'Partial'}else{'Read'}
    }catch{$data.Error=Protect-DiagnosticText $_.Exception.Message}
    [pscustomobject]$data
}

function Get-DiagnosticAcl {
    param([string]$Path,[string]$Label)
    try {
        if(-not (Test-Path -LiteralPath $Path)){return [pscustomobject]@{Label=$Label;Status='Missing'}}
        $acl=Get-Acl -LiteralPath $Path;$current=[Security.Principal.WindowsIdentity]::GetCurrent()
        $owner=[Security.Principal.NTAccount]::new($acl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value
        [pscustomobject]@{Label=$Label;Status='Read';OwnerRelation=if($owner -eq $current.User.Value){'CurrentUser'}else{'OtherIdentity'};InheritanceDisabled=$acl.AreAccessRulesProtected;AllowRuleCount=@($acl.Access | Where-Object {$_.AccessControlType -eq 'Allow'}).Count;DenyRuleCount=@($acl.Access | Where-Object {$_.AccessControlType -eq 'Deny'}).Count;Error=''}
    }catch{[pscustomobject]@{Label=$Label;Status='ReadError';Error=Protect-DiagnosticText $_.Exception.Message}}
}

function Test-DiagnosticSessionPermission {
    param([string]$Context,[AllowNull()]$IsAdministrator)
    if($Context -eq 'NormalUserSession' -and $IsAdministrator -ne $false){return [pscustomobject]@{Allowed=$false;ExitCode=20;Reason='正常会话对照必须确认为非管理员；未知或管理员令牌均不运行 WSL。'}}
    [pscustomobject]@{Allowed=$true;ExitCode=0;Reason=''}
}

function ConvertTo-DiagnosticUtcInstant {
    param($Value)
    # PS7 ConvertFrom-Json may produce DateTime values. Do not let Parse stringify
    # those values: its default format loses the UTC marker and fractional seconds.
    if($Value -is [DateTimeOffset]){return $Value.UtcDateTime}
    if($Value -is [DateTime]){
        if($Value.Kind -eq [DateTimeKind]::Unspecified){throw 'Collection time has no verified timezone.'}
        return $Value.ToUniversalTime()
    }
    if($Value -isnot [string] -or $Value -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})$'){throw 'Collection time must be an ISO timestamp with an explicit timezone.'}
    return [DateTimeOffset]::Parse($Value,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None).UtcDateTime
}

function Compare-WslDiagnosticReport {
    param([Parameter(Mandatory=$true)]$Reference,[Parameter(Mandatory=$true)]$Current)
    if($Reference.SchemaVersion -ne 1 -or $Current.SchemaVersion -ne 1){throw '报告版本不兼容；仅支持 SchemaVersion=1。'}
    $changes=[Collections.Generic.List[object]]::new()
    $stages=@(@($Reference.Commands | ForEach-Object {$_.Stage}) + @($Current.Commands | ForEach-Object {$_.Stage}) | Sort-Object -Unique)
    foreach($stage in $stages){
        $before=@($Reference.Commands | Where-Object {$_.Stage -eq $stage});$after=@($Current.Commands | Where-Object {$_.Stage -eq $stage})
        $old=if($before.Count){$before[0]}else{$null};$new=if($after.Count){$after[0]}else{$null}
        $allowedCategories=@('Success','Timeout','InvocationError','AccessDenied','DistributionError','ServiceError','ArgumentError','UnknownFailure','NotCollected')
        $oldCategory=if($old){$old.Classification.Category}else{'NotCollected'};$newCategory=if($new){$new.Classification.Category}else{'NotCollected'}
        if($oldCategory -notin $allowedCategories){$oldCategory='UntrustedCategory'};if($newCategory -notin $allowedCategories){$newCategory='UntrustedCategory'}
        $oldCode=$null;$newCode=$null;$parsedCode=0L
        if($old -and [long]::TryParse([string]$old.ExitCode,[ref]$parsedCode)){$oldCode=$parsedCode}
        if($new -and [long]::TryParse([string]$new.ExitCode,[ref]$parsedCode)){$newCode=$parsedCode}
        $safeStage=if($stage -in @('version','status','enumeration','list-quiet','list-running','linux-true','linux-environment')){$stage}else{'UntrustedStage'}
        if($oldCategory -ne $newCategory -or $oldCode -ne $newCode -or ($old -and $new -and ($old.Stdout -ne $new.Stdout -or $old.Stderr -ne $new.Stderr))){$changes.Add([pscustomobject]@{Stage=$safeStage;ReferenceCategory=$oldCategory;CurrentCategory=$newCategory;ReferenceExitCode=$oldCode;CurrentExitCode=$newCode})}
    }
    $warnings=[Collections.Generic.List[string]]::new();$validity='Comparable';$checks=[ordered]@{}
    foreach($field in @('UserFingerprint','HostFingerprint')){
        $before=$null;$after=$null
        if($Reference.PSObject.Properties['Identity'] -and $Reference.Identity.PSObject.Properties[$field]){$before=$Reference.Identity.$field}
        if($Current.PSObject.Properties['Identity'] -and $Current.Identity.PSObject.Properties[$field]){$after=$Current.Identity.$field}
        if(-not $before -or -not $after -or $before -eq 'Unavailable' -or $after -eq 'Unavailable'){$checks[$field]='NotVerified';$warnings.Add($field + '缺项；身份或主机一致性未验证。');if($validity -ne 'NotComparable'){$validity='NotVerified'}}
        elseif($before -ne $after){$checks[$field]='Different';$warnings.Add($field + '不同；两份报告不可直接作为同环境权限对照。');$validity='NotComparable'}
        else{$checks[$field]='Matched'}
    }
    $beforeHash=$null;$afterHash=$null
    if($Reference.PSObject.Properties['Tool'] -and $Reference.Tool.PSObject.Properties['ModuleSha256']){$beforeHash=$Reference.Tool.ModuleSha256}
    if($Current.PSObject.Properties['Tool'] -and $Current.Tool.PSObject.Properties['ModuleSha256']){$afterHash=$Current.Tool.ModuleSha256}
    if(-not $beforeHash -or -not $afterHash){$checks.ModuleSha256='NotVerified';$warnings.Add('工具模块 SHA256 缺项；采集代码一致性未验证。');if($validity -ne 'NotComparable'){$validity='NotVerified'}}
    elseif($beforeHash -ne $afterHash){$checks.ModuleSha256='Different';$warnings.Add('工具模块 SHA256 不同；须使用同一版本重采集。');$validity='NotComparable'}else{$checks.ModuleSha256='Matched'}
    $normal=$null
    if($Reference.Context.Label -eq 'NormalUserSession'){$normal=$Reference}
    elseif($Current.Context.Label -eq 'NormalUserSession'){$normal=$Current}
    $normalAdmin=$null
    if($normal -and $normal.PSObject.Properties['Identity'] -and $normal.Identity.PSObject.Properties['Token'] -and $normal.Identity.Token.PSObject.Properties['IsAdministrator']){$normalAdmin=$normal.Identity.Token.IsAdministrator}
    if($normalAdmin -eq $true){$checks.NormalSessionNonAdmin='Rejected';$warnings.Add('普通会话报告实际为管理员；该对照不等价。');$validity='NotComparable'}
    elseif($normalAdmin -ne $false){$checks.NormalSessionNonAdmin='NotVerified';$warnings.Add('普通会话非管理员令牌未确认。');if($validity -ne 'NotComparable'){$validity='NotVerified'}}else{$checks.NormalSessionNonAdmin='Confirmed'}
    $interval=$null
    try{
        if(-not $Reference.PSObject.Properties['Time'] -or -not $Current.PSObject.Properties['Time']){throw 'Missing collection time'}
        $currentUtc=ConvertTo-DiagnosticUtcInstant $Current.Time.Utc
        $referenceUtc=ConvertTo-DiagnosticUtcInstant $Reference.Time.Utc
        $interval=[Math]::Abs(($currentUtc-$referenceUtc).TotalHours)
        $checks.CollectionTime=if($interval -le 24){'Within24Hours'}else{'MoreThan24Hours'}
        if($interval -gt 24){$warnings.Add('采集相隔超过24小时；环境可能已变化。');if($validity -ne 'NotComparable'){$validity='NotVerified'}}
    }catch{$checks.CollectionTime='NotVerified';$warnings.Add('采集时间缺项或格式无效。');if($validity -ne 'NotComparable'){$validity='NotVerified'}}
    $referenceLabel=if($Reference.Context.Label -in @('CodexSandbox','NormalUserSession')){$Reference.Context.Label}else{'UntrustedContext'}
    $currentLabel=if($Current.Context.Label -in @('CodexSandbox','NormalUserSession')){$Current.Context.Label}else{'UntrustedContext'}
    if($referenceLabel -eq 'UntrustedContext' -or $currentLabel -eq 'UntrustedContext'){$warnings.Add('输入报告的环境标签不在允许范围，原始值未写入。');if($validity -ne 'NotComparable'){$validity='NotVerified'}}
    [pscustomobject]@{SchemaVersion=1;ReferenceContext=$referenceLabel;CurrentContext=$currentLabel;Changes=@($changes.ToArray());Validity=[pscustomobject]@{Status=$validity;Checks=[pscustomobject]$checks;CollectionIntervalHours=$interval;Warnings=@($warnings.ToArray())};Conclusion='对比仅描述已采集差异；须检查有效性，标签不同不能单独证明根因或修复。'}
}

function Write-DiagnosticReport {
    param($Report,[string]$RunDirectory)
    $jsonPath=Join-Path $RunDirectory 'report.json';$mdPath=Join-Path $RunDirectory 'report.md'
    $lines=[Collections.Generic.List[string]]::new()
    $lines.Add('# WSL 只读诊断报告');$lines.Add('');$lines.Add('诊断工具成功运行不表示 WSL 权限故障已修复。')
    $lines.Add('');$lines.Add('- 运行编号：' + $Report.RunId);$lines.Add('- 时间（Asia/Shanghai）：' + $Report.Time.AsiaShanghai);$lines.Add('- UTC：' + $Report.Time.Utc)
    $lines.Add('- 声明环境：' + $Report.Context.Label + '（操作者标签，不能证明沙箱身份）');$lines.Add('- 退出状态：' + $Report.ExitCode)
    $lines.Add('- Linux 检查：' + $Report.LinuxChecks.Status);$lines.Add('- 对照报告：' + $Report.ComparisonStatus);$lines.Add('')
    $lines.Add('## 命令结果');$lines.Add('');$lines.Add('| 阶段 | 命令 | 退出码 | 分类 | 超时 |');$lines.Add('|---|---|---|---|---|')
    foreach($cmd in $Report.Commands){$display=($cmd.Command + ' ' + ($cmd.Arguments -join ' ')).Replace('|','\|').Replace("`n",' ');$lines.Add(('| {0} | `{1}` | {2} | {3} | {4} |' -f $cmd.Stage,$display,$cmd.ExitCode,$cmd.Classification.Category,$cmd.TimedOut))}
    $lines.Add('');$lines.Add('## 令牌与配置');$lines.Add('');$lines.Add('身份和主机仅保存稳定摘要，不保存名称、SID 或完整路径。令牌证据与环境标签分别记录。')
    $lines.Add('');$lines.Add('- 令牌读取：' + $Report.Identity.Token.Status + '；完整性：' + $Report.Identity.Token.IntegrityLevel + '；管理员：' + $Report.Identity.Token.IsAdministrator)
    foreach($config in $Report.Configurations){$lines.Add('- 配置 ' + $config.Source + '：' + $config.Status + '；仅保存沙箱白名单字段。')}
    $lines.Add('');$lines.Add('## 限制');$lines.Add('');foreach($note in $Report.Limitations){$lines.Add('- ' + $note)}
    $lines.Add('');$lines.Add('标准输出、标准错误、编码、时间和分类完整记录在同目录 report.json；仅保存脱敏文本。')
    $utf8=[Text.UTF8Encoding]::new($true)
    [IO.File]::WriteAllText($jsonPath,($Report | ConvertTo-Json -Depth 16),$utf8)
    [IO.File]::WriteAllLines($mdPath,$lines,$utf8)
    return [pscustomobject]@{JsonPath=$jsonPath;MarkdownPath=$mdPath}
}

function Invoke-WslDiagnosticCollection {
    param([ValidateSet('CodexSandbox','NormalUserSession')][string]$Context,[string]$ProjectRoot,[string]$OutputRoot,[string]$CompareWith,[int]$TimeoutSeconds=10,[scriptblock]$CommandRunner)
    # CommandRunner is a module-private test seam. The public script never accepts injected commands.
    $ProjectRoot=[IO.Path]::GetFullPath($ProjectRoot)
    if(-not (Test-Path -LiteralPath $ProjectRoot -PathType Container)){throw 'ProjectRoot 必须为存在的项目目录。'}
    if(-not $OutputRoot){$OutputRoot=Join-Path $ProjectRoot 'logs/diagnostics'}
    $OutputRoot=[IO.Path]::GetFullPath($OutputRoot)
    $now=[DateTime]::UtcNow;$local=$now.AddHours(8);$runId=$now.ToString('yyyyMMddTHHmmssfffZ') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8)
    $runDirectory=Join-Path $OutputRoot $runId
    [void][IO.Directory]::CreateDirectory($runDirectory)
    $token=Get-DiagnosticToken
    $identity=[ordered]@{UserFingerprint='Unavailable';HostFingerprint=Get-DiagnosticFingerprint ([Environment]::MachineName);Token=$token;PowerShellVersion=$PSVersionTable.PSVersion.ToString();ProcessArchitecture=if([Environment]::Is64BitProcess){'64-bit'}else{'32-bit'};ExecutionPolicy=@()}
    try{$id=[Security.Principal.WindowsIdentity]::GetCurrent();$identity.UserFingerprint=Get-DiagnosticFingerprint $id.User.Value}catch{}
    try{$identity.ExecutionPolicy=@(Get-ExecutionPolicy -List | Select-Object Scope,ExecutionPolicy)}catch{}
    $configs=@(Get-SafeDiagnosticConfig (Join-Path $(if($env:CODEX_HOME){$env:CODEX_HOME}else{Join-Path $env:USERPROFILE '.codex'}) 'config.toml') 'global';Get-SafeDiagnosticConfig (Join-Path $ProjectRoot '.codex/config.toml') 'project')
    $acl=@(Get-DiagnosticAcl $ProjectRoot 'ProjectRoot';Get-DiagnosticAcl (Join-Path $ProjectRoot '.git') 'ProjectGit')
    $services=foreach($name in @('WslService','LxssManager')){
        try{$s=Get-Service -Name $name -ErrorAction Stop;[pscustomobject]@{Name=$name;Status=$s.Status.ToString();ReadStatus='Read'}}
        catch{$readStatus=if($_.FullyQualifiedErrorId -match 'NoServiceFoundForGivenName'){'Missing'}else{'ReadError'};[pscustomobject]@{Name=$name;Status='Unavailable';ReadStatus=$readStatus;Error=Protect-DiagnosticText $_.Exception.Message}}
    }
    $commands=[Collections.Generic.List[object]]::new();$limitations=[Collections.Generic.List[string]]::new()
    $limitations.Add('没有修改 ACL、Owner、服务、全局配置、执行策略或沙箱；没有提权、安装或自动重试。')
    $limitations.Add('当前目录与选定 ProjectRoot 可能不同；仅记录关系，不保存完整路径。')
    $permission=Test-DiagnosticSessionPermission $Context $token.IsAdministrator
    $wslPath='';$pathStatus='Missing'
    $candidate=Join-Path $env:SystemRoot 'System32/wsl.exe';if(Test-Path -LiteralPath $candidate){$wslPath=$candidate;$pathStatus='SystemResolved'}
    if(-not $wslPath -and -not [Environment]::Is64BitProcess){$candidate=Join-Path $env:SystemRoot 'Sysnative/wsl.exe';if(Test-Path -LiteralPath $candidate){$wslPath=$candidate;$pathStatus='SystemResolved'}}
    if(-not $wslPath){try{$candidate=Get-Command wsl.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1;$wslPath=$candidate.Source;$pathStatus='PathFallback'}catch{}}
    $wslInfo=[pscustomobject]@{Status=$pathStatus;FileName='wsl.exe';LocationKind=if($wslPath -and $wslPath.StartsWith($env:SystemRoot,[StringComparison]::OrdinalIgnoreCase)){'WindowsSystemDirectory'}else{'OtherOrUnavailable'};PathSaved=$false}
    $linux=[pscustomobject]@{Status='NotCollected';Distribution='';Reason=''}
    if(-not $permission.Allowed){$linux.Status='SkippedAdministratorOrUnknownToken';$linux.Reason=$permission.Reason;$limitations.Add($permission.Reason)}
    elseif(-not $wslPath){$linux.Status='SkippedWslExecutableMissing';$limitations.Add('未找到 wsl.exe，未运行 WSL 命令。')}
    else {
        $specs=@(@{Stage='version';Args=@('--version')},@{Stage='status';Args=@('--status')},@{Stage='enumeration';Args=@('--list','--verbose')},@{Stage='list-quiet';Args=@('--list','--quiet')})
        foreach($spec in $specs){
            if($CommandRunner){$result=& $CommandRunner $wslPath $spec.Args $spec.Stage $TimeoutSeconds}else{$result=Invoke-DiagnosticCommand $wslPath $spec.Args $spec.Stage $TimeoutSeconds}
            $result.Stdout=Protect-DiagnosticText $result.Stdout;$result.Stderr=Protect-DiagnosticText $result.Stderr
            $classification=Get-WslFailureCategory $spec.Stage $result.ExitCode $result.Stdout $result.Stderr $Context -TimedOut:$result.TimedOut -StartError $result.StartError
            $result | Add-Member -NotePropertyName Classification -NotePropertyValue $classification -Force;$commands.Add($result)
        }
        $enumeration=@($commands | Where-Object {$_.Stage -eq 'enumeration'})[0];$quiet=@($commands | Where-Object {$_.Stage -eq 'list-quiet'})[0]
        if($enumeration.Classification.Category -ne 'Success' -or $quiet.Classification.Category -ne 'Success'){$linux.Status='SkippedEnumerationUnavailable';$linux.Reason='枚举不可用；不启动或探测任何发行版。'}
        else {
            $arguments=@('--list','--running','--quiet')
            if($CommandRunner){$running=& $CommandRunner $wslPath $arguments 'list-running' $TimeoutSeconds}else{$running=Invoke-DiagnosticCommand $wslPath $arguments 'list-running' $TimeoutSeconds}
            $running.Stdout=Protect-DiagnosticText $running.Stdout;$running.Stderr=Protect-DiagnosticText $running.Stderr
            $running | Add-Member -NotePropertyName Classification -NotePropertyValue (Get-WslFailureCategory 'list-running' $running.ExitCode $running.Stdout $running.Stderr $Context -TimedOut:$running.TimedOut -StartError $running.StartError) -Force;$commands.Add($running)
            if($running.Classification.Category -ne 'Success'){$linux.Status='SkippedRunningStateUnavailable';$linux.Reason='无法确认 Running 状态，未启动发行版。'}
            else {
                $names=@($running.Stdout -split '\r?\n' | ForEach-Object {$_.Trim().TrimStart('*').Trim()} | Where-Object {$_})
                if($names.Count -eq 0){$linux.Status='SkippedNoRunningDistribution';$linux.Reason='当前没有已确认运行的发行版；默认不启动。'}
                elseif($names -notcontains 'Ubuntu'){$linux.Status='SkippedTargetNotRunning';$linux.Reason='Ubuntu 未确认运行；不探测 docker-desktop 或其他项目发行版。'}
                else {
                    $distribution='Ubuntu';$linux.Distribution=$distribution
                    $envQuery='printf "WSL_DISTRO_NAME=%s\nPWD=%s\nUID=%s\nOS=%s\n" "${WSL_DISTRO_NAME:-}" "$PWD" "$(id -u)" "$(uname -s)"'
                    foreach($spec in @(@{Stage='linux-true';Args=@('--distribution',$distribution,'--exec','/bin/true')},@{Stage='linux-environment';Args=@('--distribution',$distribution,'--exec','/bin/sh','-c',$envQuery)})) {
                        if($CommandRunner){$result=& $CommandRunner $wslPath $spec.Args $spec.Stage $TimeoutSeconds}else{$result=Invoke-DiagnosticCommand $wslPath $spec.Args $spec.Stage $TimeoutSeconds}
                        $result.Stdout=Protect-DiagnosticText $result.Stdout;$result.Stderr=Protect-DiagnosticText $result.Stderr
                        $result | Add-Member -NotePropertyName Classification -NotePropertyValue (Get-WslFailureCategory $spec.Stage $result.ExitCode $result.Stdout $result.Stderr $Context -TimedOut:$result.TimedOut -StartError $result.StartError) -Force;$commands.Add($result)
                    }
                    $linux.Status=if(@($commands | Where-Object {$_.Stage -like 'linux-*' -and $_.Classification.Category -ne 'Success'}).Count){'Failed'}else{'Completed'}
                }
            }
        }
    }
    $exitCode=0
    if(@($commands | Where-Object {$_.Classification.Category -in @('AccessDenied','DistributionError','ServiceError','ArgumentError','UnknownFailure')}).Count){$exitCode=10}
    elseif(-not $permission.Allowed -or -not $wslPath -or $linux.Status -ne 'Completed' -or @($commands | Where-Object {$_.Classification.Category -in @('Timeout','InvocationError') -or $_.CaptureIncomplete}).Count -or $token.Status -ne 'Read' -or @($configs | Where-Object {$_.Status -eq 'ReadError'}).Count -or @($acl | Where-Object {$_.Status -eq 'ReadError'}).Count -or @($services | Where-Object {$_.ReadStatus -eq 'ReadError'}).Count){$exitCode=20}
    $comparisonStatus='NotProvided';$reference=$null
    if(-not $CompareWith -and $Context -eq 'NormalUserSession' -and (Test-Path -LiteralPath (Join-Path $ProjectRoot 'logs/diagnostics'))) {
        $previous=@(Get-ChildItem -LiteralPath (Join-Path $ProjectRoot 'logs/diagnostics') -Filter 'report.json' -File -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc -Descending)
        foreach($file in $previous){try{$candidate=Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 | ConvertFrom-Json;if($candidate.SchemaVersion -eq 1 -and $candidate.Context.Label -eq 'CodexSandbox'){$CompareWith=$file.FullName;break}}catch{}}
    }
    if($CompareWith){$reference=Get-Content -LiteralPath $CompareWith -Raw -Encoding UTF8 | ConvertFrom-Json;$comparisonStatus='Completed'}
    elseif($Context -eq 'NormalUserSession'){$comparisonStatus='NoSandboxReference';$limitations.Add('未找到有效 CodexSandbox 报告；暂无沙箱与普通会话对照。')}
    else{$limitations.Add('普通 Windows 用户会话报告未在本次提供；该数据仍待采集。')}
    $moduleHash=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $report=[pscustomobject]@{SchemaVersion=1;Tool=[pscustomobject]@{Version='1.0.1';ModuleSha256=$moduleHash};RunId=$runId;Time=[pscustomobject]@{Utc=$now.ToString('o');AsiaShanghai=$local.ToString('yyyy-MM-dd HH:mm:ss') + ' +08:00'};Context=[pscustomobject]@{Label=$Context;LabelIsOperatorDeclaration=$true;WorkingDirectoryRelation=if([IO.Path]::GetFullPath((Get-Location).Path) -eq $ProjectRoot){'ProjectRoot'}else{'DifferentFromProjectRoot'}};Identity=[pscustomobject]$identity;WslExecutable=$wslInfo;Configurations=$configs;AclSummaries=$acl;Services=@($services);Commands=@($commands.ToArray());LinuxChecks=$linux;ExitCode=$exitCode;ComparisonStatus=$comparisonStatus;Limitations=@($limitations.ToArray())}
    if($reference){
        $comparison=Compare-WslDiagnosticReport $reference $report;$utf8=[Text.UTF8Encoding]::new($true)
        if($comparison.Validity.Status -ne 'Comparable'){$report.ComparisonStatus='Generated' + $comparison.Validity.Status}
        [IO.File]::WriteAllText((Join-Path $runDirectory 'comparison.json'),($comparison | ConvertTo-Json -Depth 12),$utf8)
        $text="# WSL 诊断对照`r`n`r`n" + $comparison.Conclusion + "`r`n`r`n" + '有效性：' + $comparison.Validity.Status + "`r`n" + '参照：' + $comparison.ReferenceContext + '；本次：' + $comparison.CurrentContext + "`r`n"
        foreach($warning in $comparison.Validity.Warnings){$text += "`r`n- 警告：" + $warning}
        foreach($change in $comparison.Changes){$text += "`r`n- " + $change.Stage + ': ' + $change.ReferenceCategory + ' → ' + $change.CurrentCategory}
        [IO.File]::WriteAllText((Join-Path $runDirectory 'comparison.md'),$text,$utf8)
    }
    $paths=Write-DiagnosticReport $report $runDirectory
    $report | Add-Member -NotePropertyName JsonPath -NotePropertyValue $paths.JsonPath
    $report | Add-Member -NotePropertyName MarkdownPath -NotePropertyValue $paths.MarkdownPath
    return $report
}

function Invoke-WslDiagnostics {
    param([ValidateSet('CodexSandbox','NormalUserSession')][string]$Context='CodexSandbox',[string]$ProjectRoot=(Split-Path -Parent $PSScriptRoot),[string]$OutputRoot,[string]$CompareWith,[ValidateRange(1,120)][int]$TimeoutSeconds=10)
    try { Invoke-WslDiagnosticCollection -Context $Context -ProjectRoot $ProjectRoot -OutputRoot $OutputRoot -CompareWith $CompareWith -TimeoutSeconds $TimeoutSeconds }
    catch { [pscustomobject]@{ExitCode=30;Error=Protect-DiagnosticText $_.Exception.Message;JsonPath=$null;MarkdownPath=$null} }
}

function Invoke-WslDiagnosticComparison {
    param([string]$ReferencePath,[string]$CurrentPath,[string]$OutputRoot=(Join-Path (Split-Path -Parent $PSScriptRoot) 'logs/diagnostics'))
    try {
        $reference=Get-Content -LiteralPath $ReferencePath -Raw -Encoding UTF8 | ConvertFrom-Json
        $current=Get-Content -LiteralPath $CurrentPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $comparison=Compare-WslDiagnosticReport $reference $current
        $runId='compare-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8)
        $runDirectory=Join-Path ([IO.Path]::GetFullPath($OutputRoot)) $runId;[void][IO.Directory]::CreateDirectory($runDirectory)
        $jsonPath=Join-Path $runDirectory 'comparison.json';$mdPath=Join-Path $runDirectory 'comparison.md'
        $utf8=[Text.UTF8Encoding]::new($true)
        # Do not save arbitrary imported stdout/stderr or paths in comparison outputs.
        [IO.File]::WriteAllText($jsonPath,($comparison | ConvertTo-Json -Depth 12),$utf8)
        $lines=@('# WSL 诊断对照','',$comparison.Conclusion,'',('有效性：' + $comparison.Validity.Status),('参照：' + $comparison.ReferenceContext + '；本次：' + $comparison.CurrentContext))
        foreach($warning in $comparison.Validity.Warnings){$lines += '- 警告：' + $warning}
        foreach($change in $comparison.Changes){$lines += '- ' + $change.Stage + ': ' + $change.ReferenceCategory + ' → ' + $change.CurrentCategory}
        [IO.File]::WriteAllText($mdPath,(Protect-DiagnosticText ($lines -join "`r`n")),$utf8)
        return [pscustomobject]@{ExitCode=0;JsonPath=$jsonPath;MarkdownPath=$mdPath}
    }catch{return [pscustomobject]@{ExitCode=30;Error=Protect-DiagnosticText $_.Exception.Message;JsonPath=$null;MarkdownPath=$null}}
}

Export-ModuleMember -Function Invoke-WslDiagnostics,Invoke-WslDiagnosticComparison,Invoke-DiagnosticCommand,ConvertFrom-DiagnosticBytes,Protect-DiagnosticText,Get-WslFailureCategory,Get-SafeDiagnosticConfig,Compare-WslDiagnosticReport
