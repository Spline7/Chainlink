@echo off
setlocal
where cargo.exe >nul 2>&1
if %errorlevel% neq 0 (
    echo Rust is not installed. Install the stable MSVC Rust toolchain and try again.
    exit /b 1
)
pushd "%~dp0"
cargo.exe build --release --locked
if %errorlevel% neq 0 (
    popd
    exit /b 1
)
copy /y "target\release\chainlink.exe" "Chainlink\chainlink.exe" >nul
popd
echo Built Chainlink\chainlink.exe
endlocal
