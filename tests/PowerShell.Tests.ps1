$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$repository = Split-Path -Parent $PSScriptRoot
$modulePath = Join-Path $repository 'Chainlink\Chainlink.Common.psm1'
Import-Module $modulePath -Force
$script:tests = 0

function Assert-Equal($Expected, $Actual, [string]$Name) {
    $script:tests++
    if ($Expected -cne $Actual) { throw "$Name failed. Expected '$Expected', got '$Actual'." }
}

function Assert-True([bool]$Value, [string]$Name) {
    $script:tests++
    if (-not $Value) { throw "$Name failed." }
}

function Assert-Throws([scriptblock]$Action, [string]$Name) {
    $script:tests++
    try { & $Action; throw "$Name failed: no exception was thrown." }
    catch {
        if ($_.Exception.Message -eq "$Name failed: no exception was thrown.") { throw }
    }
}

Assert-Equal 'example.com/path' (ConvertTo-ChainlinkEntry ' HTTPS://WWW.Example.COM/path/ ') 'normalizes URL'
$idnUrl = 'https://b{0}cher.example' -f [char]0x00fc
Assert-Equal 'xn--bcher-kva.example' (ConvertTo-ChainlinkEntry $idnUrl) 'normalizes IDN'
Assert-Equal 'youtube.com/@SomeCreator' (ConvertTo-ChainlinkChannel '@SomeCreator') 'normalizes channel handle'
Assert-Equal 'youtube.com/channel/UC123' (ConvertTo-ChainlinkChannel 'https://youtube.com/channel/UC123/videos') 'normalizes channel URL'
Assert-Equal '[::1]:8080/path' (ConvertTo-ChainlinkEntry 'http://[::1]:8080/path/') 'normalizes IPv6 URL'
Assert-Throws { ConvertTo-ChainlinkEntry 'file:///C:/Windows' } 'rejects non-web schemes'
Assert-Throws { ConvertTo-ChainlinkEntry 'https://user:pass@example.com' } 'rejects credentials'
Assert-Throws { ConvertTo-ChainlinkEntry 'https://example.com/?token=secret' } 'rejects query strings'
Assert-Throws { ConvertTo-ChainlinkChannel 'https://example.com/not-youtube' } 'rejects non-YouTube channel URL'
Assert-Throws { ConvertTo-ChainlinkChannel 'bad\handle' } 'rejects malformed channel handle'

$left = [byte[]](1, 2, 3)
Assert-True (Test-ChainlinkFixedTimeEqual $left ([byte[]](1, 2, 3))) 'fixed-time equality accepts equal values'
Assert-True (-not (Test-ChainlinkFixedTimeEqual $left ([byte[]](1, 2, 4)))) 'fixed-time equality rejects different values'
Assert-Equal 64 (Get-ChainlinkSha256Hex 'chainlink').Length 'SHA-256 hex length'

$watchdogPath = 'C:\ProgramData\Chainlink\watchdog.ps1'
$powershellPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$validTask = [pscustomobject]@{
    Principal = [pscustomobject]@{ UserId = 'SYSTEM' }
    Actions = @([pscustomobject]@{
        Execute = $powershellPath
        Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$watchdogPath`""
    })
}
Assert-True (Test-ChainlinkScheduledTaskObject $validTask $powershellPath $watchdogPath) 'accepts exact SYSTEM watchdog task'
$validTask.Principal.UserId = 'ordinary-user'
Assert-True (-not (Test-ChainlinkScheduledTaskObject $validTask $powershellPath $watchdogPath)) 'rejects non-SYSTEM task collision'
$validTask.Principal.UserId = 'SYSTEM'
$validTask.Actions[0].Arguments += ' -Command malicious'
Assert-True (-not (Test-ChainlinkScheduledTaskObject $validTask $powershellPath $watchdogPath)) 'rejects altered watchdog action'

$tempDirectory = Join-Path ([IO.Path]::GetTempPath()) ('chainlink-tests-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempDirectory | Out-Null
try {
    $blocklist = Join-Path $tempDirectory 'blocklist.txt'
    Set-ChainlinkTextFileAtomic -Path $blocklist -Lines @('# comment', 'Example.com', 'https://example.com/', 'youtube.com/shorts')
    $entries = @(Get-ChainlinkBlocklist -Path $blocklist)
    Assert-Equal 2 $entries.Count 'deduplicates blocklist'
    Assert-Equal 'example.com' $entries[0] 'first normalized entry'
    Assert-Equal 'youtube.com/shorts' $entries[1] 'second normalized entry'
    Set-ChainlinkTextFileAtomic -Path $blocklist -Lines @('# an intentionally empty blocklist')
    Assert-Equal 0 @(Get-ChainlinkBlocklist -Path $blocklist).Count 'accepts empty blocklist'
} finally {
    Remove-Item -LiteralPath $tempDirectory -Recurse -Force
}

foreach ($relativePath in @('Chainlink\Chainlink.ps1', 'Chainlink\watchdog.ps1', 'Chainlink\Chainlink.Common.psm1', 'tests\PowerShell.Tests.ps1')) {
    $tokens = $null; $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile((Join-Path $repository $relativePath), [ref]$tokens, [ref]$errors)
    Assert-Equal 0 @($errors).Count "PowerShell parse: $relativePath"
}

Write-Output "PASS: $script:tests PowerShell checks"
