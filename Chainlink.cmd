@echo off
rem Chainlink launcher: asks for admin rights, then opens the Chainlink menu.
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell.exe -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Chainlink\Chainlink.ps1"
