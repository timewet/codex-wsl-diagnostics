@echo off
setlocal
if "%~1"=="" goto usage
if "%~2"=="" goto usage
set "DIAGNOSTIC_ROOT=%~dp0.."
set "DIAGNOSTIC_PS="
for /f "delims=" %%P in ('where pwsh.exe 2^>nul') do if not defined DIAGNOSTIC_PS set "DIAGNOSTIC_PS=%%P"
if not defined DIAGNOSTIC_PS if exist "%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\native\powershell\pwsh.exe" set "DIAGNOSTIC_PS=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\native\powershell\pwsh.exe"
if not defined DIAGNOSTIC_PS set "DIAGNOSTIC_PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
echo Comparing existing reports. No WSL command is executed.
"%DIAGNOSTIC_PS%" -NoLogo -NoProfile -NonInteractive -File "%DIAGNOSTIC_ROOT%\diagnostics\wsl-check.ps1" -ReferenceReport "%~1" -CurrentReport "%~2" -ProjectRoot "%DIAGNOSTIC_ROOT%"
set "DIAGNOSTIC_NATIVE_EXIT=%ERRORLEVEL%"
set "DIAGNOSTIC_EXIT=%DIAGNOSTIC_NATIVE_EXIT%"
if not "%DIAGNOSTIC_NATIVE_EXIT%"=="0" if not "%DIAGNOSTIC_NATIVE_EXIT%"=="10" if not "%DIAGNOSTIC_NATIVE_EXIT%"=="20" if not "%DIAGNOSTIC_NATIVE_EXIT%"=="30" set "DIAGNOSTIC_EXIT=30"
echo Native runtime exit status: %DIAGNOSTIC_NATIVE_EXIT%; diagnostic exit status: %DIAGNOSTIC_EXIT%
exit /b %DIAGNOSTIC_EXIT%
:usage
echo Usage: Compare-WslDiagnostics.cmd "reference report.json" "current report.json"
exit /b 30
