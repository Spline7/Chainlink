@echo off
rem Chainlink launcher: asks for admin rights, then opens the Chainlink window.
rem __APPDIR__ is supplied by cmd.exe itself; clearing a caller override exposes the trusted value.
set "__APPDIR__="
set "CHAINLINK_POWERSHELL=%__APPDIR__%WindowsPowerShell\v1.0\powershell.exe"
net session >nul 2>&1
if %errorlevel% neq 0 (
    set "CHAINLINK_LAUNCHER=%~f0"
    "%CHAINLINK_POWERSHELL%" -NoProfile -WindowStyle Hidden -Command "Start-Process -LiteralPath ([Environment]::GetEnvironmentVariable('CHAINLINK_LAUNCHER')) -Verb RunAs"
    exit /b
)
start "" "%CHAINLINK_POWERSHELL%" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0Chainlink\Chainlink.ps1"
