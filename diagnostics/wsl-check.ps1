[CmdletBinding()]
param(
    [string]$Context='CodexSandbox',
    [string]$ProjectRoot=(Split-Path -Parent $PSScriptRoot),
    [string]$OutputRoot,
    [string]$CompareWith,
    [string]$ReferenceReport,
    [string]$CurrentReport,
    [ValidateRange(1,120)][int]$TimeoutSeconds=10
)
$ErrorActionPreference='Stop'
try {
    if($Context -notin @('CodexSandbox','NormalUserSession')){Write-Host '无效的环境标签。允许 CodexSandbox 或 NormalUserSession；未运行 WSL 命令。';exit 30}
    Import-Module (Join-Path $PSScriptRoot 'WslDiagnostics.psm1') -Force
    if($ReferenceReport -or $CurrentReport){
        if(-not $ReferenceReport -or -not $CurrentReport){Write-Host '纯报告对比需要同时指定 ReferenceReport 与 CurrentReport。';exit 30}
        if(-not $OutputRoot){$OutputRoot=Join-Path $ProjectRoot 'logs/diagnostics'}
        $report=Invoke-WslDiagnosticComparison -ReferencePath $ReferenceReport -CurrentPath $CurrentReport -OutputRoot $OutputRoot
    }else{$report=Invoke-WslDiagnostics -Context $Context -ProjectRoot $ProjectRoot -OutputRoot $OutputRoot -CompareWith $CompareWith -TimeoutSeconds $TimeoutSeconds}
    if($report.JsonPath){Write-Host ('诊断 JSON：' + $report.JsonPath);Write-Host ('中文报告：' + $report.MarkdownPath)}
    if($report.PSObject.Properties.Name -contains 'Error'){Write-Host ('诊断未完成：' + $report.Error)}
    Write-Host ('退出状态：' + $report.ExitCode + '；诊断完成不表示权限故障已修复。')
    exit $report.ExitCode
} catch {
    Write-Host '诊断入口未完成。请检查脚本执行策略、文件完整性与现有 PowerShell 运行环境；本工具不会改变策略。'
    exit 30
}
