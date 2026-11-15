@echo off
rem Chainlink launcher: asks for admin rights, then opens the Chainlink window.
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell.exe -NoProfile -WindowStyle Hidden -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
start "" powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0Chainlink\Chainlink.ps1"
