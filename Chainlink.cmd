@echo off
rem Chainlink Python launcher. The application requests elevation itself.
where py.exe >nul 2>&1
if %errorlevel% equ 0 (
    start "" py.exe -3 -I -B "%~dp0Chainlink\chainlink.py"
    exit /b
)
where python.exe >nul 2>&1
if %errorlevel% equ 0 (
    start "" python.exe -I -B "%~dp0Chainlink\chainlink.py"
    exit /b
)
echo Chainlink requires Python 3.10 or newer installed for all users.
echo Download Python from python.org, then run Chainlink.cmd again.
pause
exit /b 1
