@echo off
setlocal EnableExtensions

set "REPO_ROOT=%~dp0"
if "%REPO_ROOT:~-1%"=="\" set "REPO_ROOT=%REPO_ROOT:~0,-1%"

set "LOG_DIR=%REPO_ROOT%\out\logs\runtime"
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%" >nul 2>&1

set "BOOT_LOG=%LOG_DIR%\latest-bootstrap.log"
set "CONSOLE_LOG=%LOG_DIR%\latest-console.log"

> "%BOOT_LOG%" echo timestamp_local: %date% %time%
>> "%BOOT_LOG%" echo cwd: %CD%
>> "%BOOT_LOG%" echo launcher: vpn.cmd
>> "%BOOT_LOG%" echo script: %REPO_ROOT%\vpn.ps1
>> "%BOOT_LOG%" echo args: %*
>> "%BOOT_LOG%" echo.

> "%CONSOLE_LOG%" echo [%date% %time%] vpn.cmd start
powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%REPO_ROOT%\vpn.ps1" %*
set "EXITCODE=%ERRORLEVEL%"
>> "%CONSOLE_LOG%" echo.
>> "%CONSOLE_LOG%" echo exit_code: %EXITCODE%

echo.
if "%EXITCODE%"=="0" (
  echo Command finished.
) else (
  echo Command failed ^(code %EXITCODE%^).
  echo Logs:
  echo   %CONSOLE_LOG%
  echo   %LOG_DIR%\latest-error.log
  echo   %LOG_DIR%\latest-transcript.log
  echo   %BOOT_LOG%
)

if not defined VPN_NO_PAUSE (
  echo.
  pause
)

exit /b %EXITCODE%
