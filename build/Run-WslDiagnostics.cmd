@echo off
setlocal
set "DIAGNOSTIC_ROOT=%~dp0.."
set "DIAGNOSTIC_PS="
for /f "delims=" %%P in ('where pwsh.exe 2^>nul') do if not defined DIAGNOSTIC_PS set "DIAGNOSTIC_PS=%%P"
if not defined DIAGNOSTIC_PS if exist "%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\native\powershell\pwsh.exe" set "DIAGNOSTIC_PS=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\native\powershell\pwsh.exe"
if not defined DIAGNOSTIC_PS set "DIAGNOSTIC_PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
"%DIAGNOSTIC_PS%" -NoLogo -NoProfile -NonInteractive -File "%DIAGNOSTIC_ROOT%\diagnostics\wsl-check.ps1" -Context NormalUserSession -ProjectRoot "%DIAGNOSTIC_ROOT%"
set "DIAGNOSTIC_NATIVE_EXIT=%ERRORLEVEL%"
set "DIAGNOSTIC_EXIT=%DIAGNOSTIC_NATIVE_EXIT%"
if not "%DIAGNOSTIC_NATIVE_EXIT%"=="0" if not "%DIAGNOSTIC_NATIVE_EXIT%"=="10" if not "%DIAGNOSTIC_NATIVE_EXIT%"=="20" if not "%DIAGNOSTIC_NATIVE_EXIT%"=="30" set "DIAGNOSTIC_EXIT=30"
echo.
echo Exit status: %DIAGNOSTIC_EXIT% (0=complete, 10=fault, 20=partial, 30=internal error)
echo Native runtime exit status: %DIAGNOSTIC_NATIVE_EXIT%
if "%DIAGNOSTIC_NATIVE_EXIT%"=="1" echo Script execution may be blocked by policy. No policy has been changed. Use an existing permitted PowerShell runtime.
pause
exit /b %DIAGNOSTIC_EXIT%
