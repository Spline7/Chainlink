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

Assert-Equal 'example.com' (ConvertTo-ChainlinkEntry '*.example.com') 'accepts legacy subdomain wildcard'
Assert-Equal 'example.com/videos' (ConvertTo-ChainlinkEntry 'https://example.com/videos/*') 'accepts legacy trailing wildcard'
Assert-Equal 'example.com:8080' (ConvertTo-ChainlinkEntry 'example.com:8080') 'accepts host and port without a scheme'
Assert-Equal 'localhost:3000/app' (ConvertTo-ChainlinkEntry 'localhost:3000/app/') 'accepts localhost port with path'
Assert-Throws { ConvertTo-ChainlinkEntry 'mailto:someone@example.com' } 'rejects schemes without slashes'
Assert-Throws { ConvertTo-ChainlinkEntry '*' } 'rejects a bare wildcard'

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
$validTask.Actions[0].Execute = 'powershell.exe'
Assert-True (Test-ChainlinkScheduledTaskObject $validTask $powershellPath $watchdogPath) 'accepts the task shape of the original release'
$validTask.Actions[0].Execute = 'C:\Users\Public\powershell.exe'
Assert-True (-not (Test-ChainlinkScheduledTaskObject $validTask $powershellPath $watchdogPath)) 'rejects another executable'
Assert-True (Test-ChainlinkTaskReferencesDirectory $validTask 'C:\ProgramData\Chainlink') 'detects a task that runs from the program folder'
Assert-True (-not (Test-ChainlinkTaskReferencesDirectory $validTask 'C:\ProgramData\Chain')) 'does not match a different folder with the same prefix'
$validTask.Actions[0].Execute = $powershellPath
$validTask.Principal.UserId = 'ordinary-user'
Assert-True (-not (Test-ChainlinkScheduledTaskObject $validTask $powershellPath $watchdogPath)) 'rejects non-SYSTEM task collision'
$validTask.Principal.UserId = 'SYSTEM'
$validTask.Actions[0].Arguments += ' -Command malicious'
Assert-True (-not (Test-ChainlinkScheduledTaskObject $validTask $powershellPath $watchdogPath)) 'rejects altered watchdog action'

# ---- list merging must never collapse a one-element collection into a string
$single = @('a.example')
Assert-Equal 3 @(Merge-ChainlinkValues $single @('a.example') @('x.example', 'y.example')).Count 'merges a single-element list as a list'
Assert-Equal 0 @(Merge-ChainlinkValues @() $null @('')).Count 'merging nothing yields nothing'
Assert-Equal 2 @(Get-ChainlinkFirefoxPatterns @('example.com')).Count 'Firefox host patterns'
Assert-Equal '*://*/*' @(Get-ChainlinkFirefoxPatterns @('*'))[0] 'Firefox block-everything pattern'

# ---- browser policy round trips against a scratch registry key (never the real policy keys)
function Get-TestList([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $key = Get-Item -LiteralPath $Path
    foreach ($name in ($key.GetValueNames() | Sort-Object { [int]$_ })) { [string]$key.GetValue($name) }
}
function Get-TestValue([string]$Path, [string]$Name) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    return (Get-Item -LiteralPath $Path).GetValue($Name, $null)
}
function New-TestBaseline([string]$Root) {
    return ((Get-ChainlinkPolicyBaseline -Root $Root | ConvertTo-Json -Depth 8) | ConvertFrom-Json)
}

$root = 'HKCU:\Software\ChainlinkTests-' + [Guid]::NewGuid().ToString('N')
$chrome = Join-Path $root 'Google\Chrome'
$chromeList = Join-Path $chrome 'URLBlocklist'
$firefox = Join-Path $root 'Mozilla\Firefox'
$firefoxList = Join-Path $firefox 'WebsiteFilter\Block'
try {
    # Case 1: a clean machine. Lock, tamper, unlock; nothing may be left behind.
    New-Item -Path $root -Force | Out-Null
    $baseline = New-TestBaseline $root
    Assert-True (Test-ChainlinkPolicyBaseline $baseline) 'captured baseline is valid'
    $entries = @('x.example', 'youtube.com/shorts')
    Set-ChainlinkPolicyLock -Root $root -Entries $entries -PreviousEntries @() -Baseline $baseline
    Assert-Equal 'x.example|youtube.com/shorts' (@(Get-TestList $chromeList) -join '|') 'clean lock writes the blocklist'
    Assert-Equal 1 (Get-TestValue $chrome 'IncognitoModeAvailability') 'clean lock disables Incognito'
    Assert-Equal 1 (Get-TestValue (Join-Path $root 'BraveSoftware\Brave') 'TorDisabled') 'clean lock disables Brave Tor'
    Assert-Equal 1 (Get-TestValue $firefox 'DisablePrivateBrowsing') 'clean lock disables Firefox private browsing'
    Assert-True (@(Get-TestList $firefoxList) -contains '*://*.x.example/*') 'clean lock writes Firefox patterns'
    Assert-True (Test-ChainlinkPolicyLock -Root $root -Entries $entries) 'clean lock is intact'
    Remove-ItemProperty -LiteralPath $chrome -Name 'IncognitoModeAvailability'
    Assert-True (-not (Test-ChainlinkPolicyLock -Root $root -Entries $entries)) 'detects a removed policy value'
    Set-ChainlinkPolicyLock -Root $root -Entries $entries -PreviousEntries $entries -Baseline $baseline
    Remove-Item -LiteralPath $firefoxList -Recurse -Force
    Assert-True (-not (Test-ChainlinkPolicyLock -Root $root -Entries $entries)) 'detects a removed Firefox list'
    Set-ChainlinkPolicyLock -Root $root -Entries $entries -PreviousEntries $entries -Baseline $baseline
    Remove-ChainlinkPolicyLock -Root $root -Entries $entries -Baseline $baseline
    Assert-Equal 0 @(Get-ChildItem -LiteralPath $root).Count 'clean unlock leaves no keys behind'

    # Case 2: exactly one pre-existing entry per list, and pre-existing values.
    New-Item -Path $chromeList -Force | Out-Null
    New-ItemProperty -LiteralPath $chromeList -Name '1' -Value 'corp.example' -PropertyType String | Out-Null
    New-ItemProperty -LiteralPath $chrome -Name 'IncognitoModeAvailability' -Value 2 -PropertyType DWord | Out-Null
    New-ItemProperty -LiteralPath $chrome -Name 'HomepageLocation' -Value 'https://corp.example' -PropertyType String | Out-Null
    $baseline = New-TestBaseline $root
    Set-ChainlinkPolicyLock -Root $root -Entries $entries -PreviousEntries @() -Baseline $baseline
    Assert-Equal 'corp.example|x.example|youtube.com/shorts' (@(Get-TestList $chromeList) -join '|') 'lock keeps a single pre-existing entry intact'
    Assert-True (Test-ChainlinkPolicyLock -Root $root -Entries $entries) 'lock with pre-existing entry is intact'
    # The blocklist changes while locked: the old entry is replaced, not mistaken for foreign policy.
    Set-ChainlinkPolicyLock -Root $root -Entries @('z.example') -PreviousEntries $entries -Baseline $baseline
    Assert-Equal 'corp.example|z.example' (@(Get-TestList $chromeList) -join '|') 'relock replaces previously applied entries'
    # Someone else adds an entry while locked; it must survive unlock.
    New-ItemProperty -LiteralPath $chromeList -Name '99' -Value 'later.example' -PropertyType String | Out-Null
    Remove-ChainlinkPolicyLock -Root $root -Entries @('z.example', 'x.example', 'youtube.com/shorts') -Baseline $baseline
    Assert-Equal 'corp.example|later.example' (@(Get-TestList $chromeList) -join '|') 'unlock keeps foreign entries and removes managed ones'
    Assert-Equal 2 (Get-TestValue $chrome 'IncognitoModeAvailability') 'unlock restores the pre-existing value'
    Assert-Equal 'https://corp.example' (Get-TestValue $chrome 'HomepageLocation') 'unlock leaves unrelated policy alone'
    Assert-True ($null -eq (Get-TestValue $chrome 'BrowserGuestModeEnabled')) 'unlock removes values Chainlink added'
    Assert-True (-not (Test-Path -LiteralPath $firefox)) 'unlock removes the empty Firefox key'

    # Case 3: no usable baseline. Chainlink removes only what it manages.
    Set-ChainlinkPolicyLock -Root $root -Entries $entries -PreviousEntries @() -Baseline $null
    Remove-ChainlinkPolicyLock -Root $root -Entries $entries -Baseline $null
    Assert-Equal 'corp.example|later.example' (@(Get-TestList $chromeList) -join '|') 'unlock without baseline keeps foreign entries'
    Assert-True ($null -eq (Get-TestValue $chrome 'IncognitoModeAvailability')) 'unlock without baseline removes the managed value'
    Assert-True (-not (Test-ChainlinkPolicyBaseline ([pscustomobject]@{ Version = 1 }))) 'rejects an incomplete baseline'
} finally {
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
}

$originalProgramData = $env:ProgramData
try {
    $env:ProgramData = 'C:\Chainlink-Evil'
    $trustedProgramData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    Assert-True ($trustedProgramData -ne $env:ProgramData) 'ignores spoofed ProgramData environment variable'
} finally {
    $env:ProgramData = $originalProgramData
}

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
    # The watchdog lock: one holder at a time, and the holder's process id is readable.
    $lockPath = Join-Path $tempDirectory 'watchdog.lock'
    $lock = Open-ChainlinkWatchdogLock -Path $lockPath
    try {
        Assert-True ($null -ne $lock) 'takes the watchdog lock'
        Assert-True ($null -eq (Open-ChainlinkWatchdogLock -Path $lockPath)) 'refuses a second holder'
        Assert-Equal $PID (Get-ChainlinkWatchdogLockOwner -Path $lockPath) 'reports the lock holder'
    } finally { $lock.Dispose() }
    $lock = Open-ChainlinkWatchdogLock -Path $lockPath
    Assert-True ($null -ne $lock) 'lock is free again after release'
    $lock.Dispose()
} finally {
    Remove-Item -LiteralPath $tempDirectory -Recurse -Force
}

$isAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    # Directory protection needs the right to assign the Administrators group as owner.
    $protected = Join-Path ([IO.Path]::GetTempPath()) ('chainlink-acl-' + [Guid]::NewGuid().ToString('N'))
    $loose = Join-Path ([IO.Path]::GetTempPath()) ('chainlink-loose-' + [Guid]::NewGuid().ToString('N'))
    try {
        New-ChainlinkProtectedDirectory $protected
        Assert-True (Test-ChainlinkProtectedDirectory $protected) 'new program directory is protected'
        Assert-Equal 'S-1-5-32-544' (Get-ChainlinkOwnerSid $protected) 'new program directory is owned by Administrators'
        $sddl = [IO.Directory]::GetAccessControl($protected).GetSecurityDescriptorSddlForm('Access')
        Assert-True ($sddl -match '^D:P(AI)?\(A;OICI;FA;;;SY\)\(A;OICI;FA;;;BA\)$') "new program directory grants only SYSTEM and Administrators (got $sddl)"
        Assert-Throws { New-ChainlinkProtectedDirectory $protected } 'refuses to adopt an existing directory'

        New-Item -ItemType Directory -Path $loose | Out-Null
        Assert-True (-not (Test-ChainlinkProtectedDirectory $loose)) 'an ordinary directory is not protected'
        Set-ChainlinkProtectedDirectoryAcl $loose
        Assert-True (Test-ChainlinkProtectedDirectory $loose) 'repair re-applies the protected ACL'
    } finally {
        foreach ($path in @($protected, $loose)) { if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force } }
    }
} else {
    Write-Output 'SKIP: directory protection checks need an elevated PowerShell.'
}

# ---- watchdog behaviour, with every path redirected to scratch locations
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('chainlink-watchdog-' + [Guid]::NewGuid().ToString('N'))
$scratchRoot = 'HKCU:\Software\ChainlinkTests-' + [Guid]::NewGuid().ToString('N')
New-Item -ItemType Directory -Path $scratch | Out-Null
New-Item -ItemType Directory -Path (Join-Path $scratch 'app') | Out-Null
New-Item -ItemType Directory -Path (Join-Path $scratch 'usb\Chainlink') | Out-Null
New-Item -Path $scratchRoot -Force | Out-Null
try {
    . (Join-Path $repository 'Chainlink\watchdog.ps1')
    $AppDir        = Join-Path $scratch 'app'
    $PairFile      = Join-Path $AppDir 'pair.txt'
    $BlocklistFile = Join-Path $AppDir 'blocklist.txt'
    $AppliedFile   = Join-Path $AppDir 'applied-blocklist.txt'
    $BaselineFile  = Join-Path $AppDir 'policy-baseline.json'
    $LockFile      = Join-Path $AppDir 'watchdog.lock'
    $LogFile       = Join-Path $AppDir 'log.txt'
    $StatusFile    = Join-Path $AppDir 'status.txt'
    $PolicyRoot    = $scratchRoot
    $script:FakeUsb = $null
    function Find-Key { return $script:FakeUsb }
    $usbBlocklist = Join-Path $scratch 'usb\Chainlink\blocklist.txt'
    $scratchChrome = Join-Path $scratchRoot 'Google\Chrome\URLBlocklist'

    Set-ChainlinkTextFileAtomic -Path $BlocklistFile -Lines @('x.example')
    Save-Baseline
    Assert-True (Test-Path -LiteralPath $BaselineFile) 'watchdog saves a baseline'
    Assert-True ($null -ne (Read-Baseline)) 'watchdog reads its own baseline'

    Invoke-WatchdogCycle
    Assert-Equal 'locked' $script:State 'locks when no key is present'
    Assert-Equal 'x.example' (@(Get-TestList $scratchChrome) -join '|') 'lock applies the installed blocklist'
    Assert-Equal 'x.example' (@(Read-AppliedEntries) -join '|') 'lock records what it applied'
    Assert-True ((Get-Content -LiteralPath $StatusFile -Raw) -like 'LOCKED*') 'status file says locked'

    Set-ChainlinkTextFileAtomic -Path $usbBlocklist -Lines @('y.example')
    $script:FakeUsb = (Join-Path $scratch 'usb') + '\'
    Invoke-WatchdogCycle
    Assert-Equal 'unlocked' $script:State 'unlocks when the key is present'
    Assert-Equal 0 @(Get-ChildItem -LiteralPath $scratchRoot).Count 'unlock removes every policy key it created'
    Assert-True (-not (Test-Path -LiteralPath $AppliedFile)) 'unlock clears the applied record'
    Assert-Equal 'y.example' (@(Get-ChainlinkBlocklist -Path $BlocklistFile) -join '|') 'blocklist syncs from the USB'

    # A broken blocklist on the USB must not lock a PC whose key is plugged in.
    Set-ChainlinkTextFileAtomic -Path $usbBlocklist -Lines @('y.example', 'not a host name')
    Invoke-WatchdogCycle
    Assert-Equal 'unlocked' $script:State 'an invalid USB blocklist does not lock the PC'
    Assert-True ($script:UsbProblem -ne '') 'an invalid USB blocklist is reported'
    Assert-Equal 'y.example' (@(Get-ChainlinkBlocklist -Path $BlocklistFile) -join '|') 'an invalid USB blocklist is not installed'
    Assert-Equal 0 @(Get-ChildItem -LiteralPath $AppDir -Filter '.blocklist-*').Count 'no temporary blocklist is left behind'
    Remove-Item -LiteralPath $usbBlocklist -Force
    Invoke-WatchdogCycle
    Assert-Equal 'unlocked' $script:State 'a missing USB blocklist does not lock the PC'

    $script:FakeUsb = $null
    Invoke-WatchdogCycle
    Assert-Equal 'y.example' (@(Get-TestList $scratchChrome) -join '|') 'relock applies the synced blocklist'

    # The installed blocklist is damaged while locked: block everything, and still unlock cleanly.
    [IO.File]::WriteAllText($BlocklistFile, "not a host name`r`n")
    $script:Tick = 0
    Invoke-WatchdogCycle
    Assert-True (@(Get-TestList $scratchChrome) -contains '*') 'a damaged installed blocklist blocks everything'
    $script:FakeUsb = (Join-Path $scratch 'usb') + '\'
    Set-ChainlinkTextFileAtomic -Path $usbBlocklist -Lines @('z.example')
    Invoke-WatchdogCycle
    Assert-Equal 'unlocked' $script:State 'the key still unlocks after the installed blocklist was damaged'
    Assert-Equal 0 @(Get-ChildItem -LiteralPath $scratchRoot).Count 'entries written before the damage are still removed'
    Assert-Equal 'z.example' (@(Get-ChainlinkBlocklist -Path $BlocklistFile) -join '|') 'the USB repairs a damaged installed blocklist'

    # An unreadable baseline must not stop the key from unlocking.
    $script:FakeUsb = $null
    Invoke-WatchdogCycle
    [IO.File]::WriteAllText($BaselineFile, '{ not json')
    $script:FakeUsb = (Join-Path $scratch 'usb') + '\'
    Invoke-WatchdogCycle
    Assert-Equal 'unlocked' $script:State 'unlocks without a readable baseline'
    Assert-Equal 0 @(Get-ChildItem -LiteralPath $scratchRoot).Count 'unlock without a baseline removes the managed values'
} finally {
    if (Test-Path -LiteralPath $scratchRoot) { Remove-Item -LiteralPath $scratchRoot -Recurse -Force }
    Remove-Item -LiteralPath $scratch -Recurse -Force
}

# ---- install, repair, and uninstall, with Task Scheduler and the watchdog child process stubbed
if ($isAdmin) {
    $scratch = Join-Path ([IO.Path]::GetTempPath()) ('chainlink-install-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path (Join-Path $scratch 'usb') | Out-Null
    Copy-Item -LiteralPath (Join-Path $repository 'Chainlink') -Destination (Join-Path $scratch 'usb') -Recurse
    try {
        . (Join-Path $scratch 'usb\Chainlink\Chainlink.ps1')
        $UsbRoot       = (Split-Path -Path $env:SystemRoot -Qualifier) + '\'   # any real volume, for its serial number
        $AppDir        = Join-Path $scratch 'app'
        $PairFile      = Join-Path $AppDir 'pair.txt'
        $RecoveryFile  = Join-Path $AppDir 'recovery.txt'
        $RecoveryAttemptsFile = Join-Path $AppDir 'recovery-attempts.txt'
        $LockFile      = Join-Path $AppDir 'watchdog.lock'
        $InstalledWatchdog = Join-Path $AppDir 'watchdog.ps1'
        $ShortcutPath  = Join-Path $scratch 'Chainlink Emergency Uninstall.lnk'
        $TaskName      = 'ChainlinkTests-' + [Guid]::NewGuid().ToString('N')
        $WatchdogStopTimeoutSeconds = 1

        $script:Calls = New-Object 'System.Collections.Generic.List[string]'
        $script:FakeTasks = @()
        $script:FailRegister = $false
        # Task Scheduler is replaced by Chainlink's own wrapper functions. The real cmdlets are
        # also turned into tripwires, after loading their module so it cannot redefine them later.
        Import-Module ScheduledTasks
        foreach ($name in @('Register-ScheduledTask', 'Unregister-ScheduledTask', 'Start-ScheduledTask', 'Stop-ScheduledTask', 'Get-ScheduledTask')) {
            Set-Item -LiteralPath "function:$name" -Value { throw 'The tests must never reach the real Task Scheduler.' }
            if ((Get-Command $name).ModuleName) { throw "Could not isolate $name; refusing to run the install tests." }
        }
        function Get-NamedTasks { return $script:FakeTasks }
        function Stop-NamedTask { $script:Calls.Add('stop') }
        function Unregister-NamedTask { $script:Calls.Add('unregister'); $script:FakeTasks = @() }
        function Register-ChainlinkTask {
            if ($script:FailRegister) { throw 'simulated Task Scheduler failure' }
            $script:Calls.Add('register')
            $script:FakeTasks = @([pscustomobject]@{
                Principal = [pscustomobject]@{ UserId = 'SYSTEM' }
                Actions = @([pscustomobject]@{ Execute = $PowerShellExe; Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$InstalledWatchdog`"" })
            })
        }
        function Stop-LegacyWatchdogProcesses { }
        function Invoke-Watchdog([string]$path, [string]$mode) {
            $script:Calls.Add("watchdog $mode")
            if ($mode -eq '-CaptureBaseline') { [IO.File]::WriteAllText((Join-Path $AppDir 'policy-baseline.json'), '{}') }
            return $true
        }

        # A folder somebody else filled must never be adopted.
        New-Item -ItemType Directory -Path $AppDir | Out-Null
        [IO.File]::WriteAllText((Join-Path $AppDir 'watchdog.ps1'), 'planted')
        Assert-Throws { Install-Chainlink } 'refuses a pre-filled program folder with no Chainlink task'
        Assert-Equal 'planted' ([IO.File]::ReadAllText((Join-Path $AppDir 'watchdog.ps1'))) 'leaves the pre-filled folder untouched'
        Remove-Item -LiteralPath $AppDir -Recurse -Force

        # A failed first link leaves nothing behind.
        $script:FailRegister = $true
        Assert-Throws { Install-Chainlink } 'surfaces a Task Scheduler failure'
        Assert-True (-not (Test-Path -LiteralPath $AppDir)) 'a failed first link removes the program folder'
        Assert-True (-not (Test-Path -LiteralPath $ShortcutPath)) 'a failed first link removes the shortcut'
        $script:FailRegister = $false

        # First link.
        $script:Calls.Clear()
        $words = @(Install-Chainlink)
        Assert-Equal 6 $words.Count 'first link returns six recovery words'
        Assert-True (Test-ChainlinkProtectedDirectory $AppDir) 'first link protects the program folder'
        foreach ($name in @('Chainlink.ps1', 'Chainlink.Common.psm1', 'watchdog.ps1', 'blocklist.txt', 'pair.txt', 'recovery.txt', 'policy-baseline.json')) {
            Assert-True (Test-Path -LiteralPath (Join-Path $AppDir $name) -PathType Leaf) "first link installs $name"
        }
        Assert-True ((Get-Content -LiteralPath $PairFile -Raw).Trim() -match '^[a-f0-9]{64}$') 'pair file holds one hash'
        Assert-True (Test-Path -LiteralPath $ShortcutPath) 'first link creates the emergency shortcut'
        Assert-Equal 'stop|watchdog -CaptureBaseline|register' ($script:Calls -join '|') 'first link call order'
        Assert-True (Test-UsbMatchesPc) 'the linked USB matches this PC'
        Assert-True (Test-RecoveryWords $words) 'recovery words verify'
        $wrong = @($words); $wrong[5] = if ($words[5] -eq 'apple') { 'arrow' } else { 'apple' }
        Assert-True (-not (Test-RecoveryWords $wrong)) 'wrong recovery words are rejected'
        Register-RecoveryFailure
        Assert-True ((Get-RecoveryDelaySeconds) -gt 0) 'a failed recovery attempt starts a delay'

        # Repair keeps the recovery words and unlocks with the installed watchdog first.
        $script:Calls.Clear()
        $before = Get-Content -LiteralPath $RecoveryFile -Raw
        $repairWords = Install-Chainlink
        Assert-True (-not $repairWords) 'repair returns no new recovery words'
        Assert-Equal $before (Get-Content -LiteralPath $RecoveryFile -Raw) 'repair keeps the recovery record'
        Assert-Equal 'stop|watchdog -Unlock|register' ($script:Calls -join '|') 'repair call order'

        # While a watchdog holds the lock, uninstall must not touch anything.
        $held = Open-ChainlinkWatchdogLock -Path $LockFile
        try {
            $script:Calls.Clear()
            Assert-Throws { Uninstall-Chainlink } 'uninstall waits for a running watchdog'
            Assert-Equal 'stop' ($script:Calls -join '|') 'uninstall does nothing else while the watchdog runs'
        } finally { $held.Dispose() }

        # Uninstall: task first, then unlock, then files.
        $script:Calls.Clear()
        Uninstall-Chainlink
        Assert-Equal 'stop|unregister|watchdog -Unlock' ($script:Calls -join '|') 'uninstall call order'
        Assert-True (-not (Test-Path -LiteralPath $AppDir)) 'uninstall removes the program folder'
        Assert-True (-not (Test-Path -LiteralPath $ShortcutPath)) 'uninstall removes the shortcut'

        # A task of the same name that is not Chainlink's blocks linking and is never removed.
        $script:FakeTasks = @([pscustomobject]@{
            Principal = [pscustomobject]@{ UserId = 'SYSTEM' }
            Actions = @([pscustomobject]@{ Execute = 'C:\Windows\System32\cmd.exe'; Arguments = '/c exit' })
        })
        Assert-Throws { Install-Chainlink } 'refuses to replace a foreign task of the same name'
        $script:Calls.Clear()
        Remove-ChainlinkTask
        Assert-Equal '' ($script:Calls -join '|') 'leaves a foreign task alone'
    } finally {
        Remove-Item -LiteralPath $scratch -Recurse -Force
    }
}

foreach ($relativePath in @('Chainlink\Chainlink.ps1', 'Chainlink\watchdog.ps1', 'Chainlink\Chainlink.Common.psm1', 'tests\PowerShell.Tests.ps1')) {
    $tokens = $null; $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile((Join-Path $repository $relativePath), [ref]$tokens, [ref]$errors)
    Assert-Equal 0 @($errors).Count "PowerShell parse: $relativePath"
}

Write-Output "PASS: $script:tests PowerShell checks"
