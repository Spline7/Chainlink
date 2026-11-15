@echo off
rem Chainlink launcher: opens the Chainlink window, which asks for admin rights itself.
rem __APPDIR__ is supplied by cmd.exe itself; clearing a caller override exposes the trusted value.
set "__APPDIR__="
start "" "%__APPDIR__%WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0Chainlink\Chainlink.ps1"
