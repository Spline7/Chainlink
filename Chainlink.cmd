@echo off
rem Chainlink Rust launcher. Build once with build-usb.cmd if the executable is absent.
if not exist "%~dp0Chainlink\chainlink.exe" (
    echo Chainlink\chainlink.exe is missing.
    echo Run build-usb.cmd on a Windows PC with the Rust toolchain installed.
    pause
    exit /b 1
)
start "" "%~dp0Chainlink\chainlink.exe"
