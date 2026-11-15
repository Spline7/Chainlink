@echo off
rem Chainlink Python launcher. The application requests elevation itself.
rem Each candidate is asked to run a one-line version check first, because Windows ships a
rem "python.exe" placeholder that only opens the Microsoft Store.
py.exe -3 -c "import sys; raise SystemExit(sys.version_info < (3, 10))" >nul 2>&1
if not errorlevel 1 (
    start "" py.exe -3 -I -B "%~dp0Chainlink\chainlink.py"
    exit /b
)
python.exe -c "import sys; raise SystemExit(sys.version_info < (3, 10))" >nul 2>&1
if not errorlevel 1 (
    start "" python.exe -I -B "%~dp0Chainlink\chainlink.py"
    exit /b
)
echo Chainlink requires Python 3.10 or newer installed for all users.
echo Download Python from python.org, choose "Install for all users", then run Chainlink.cmd again.
pause
exit /b 1
