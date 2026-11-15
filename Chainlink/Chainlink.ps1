# Chainlink - settings window
# Started by double-clicking Chainlink.cmd on the USB drive (which asks for admin rights).
# Lets you edit the blocklist, link this PC to the USB key, or uninstall Chainlink.
# This script makes no network requests and sends no telemetry.

param(
    [switch]$Emergency   # Uninstall without the USB key, using your accountability partner's recovery words.
)

$ErrorActionPreference = 'Stop'
$DotSourced = ($MyInvocation.InvocationName -eq '.')   # the tests load the functions this way

# Always the 64-bit Windows PowerShell that ships with Windows, whatever host started this script.
$PowerShellExe = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
if (-not $DotSourced -and [Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    # A 32-bit host would write browser policy to the wrong registry view. Start again in 64-bit.
    $native = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)) 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    $relaunch = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`""
    if ($Emergency) { $relaunch += ' -Emergency' }
    try { Start-Process $native -WindowStyle Hidden -ArgumentList $relaunch } catch {}
    exit
}

# Ask for admin rights if we don't have them yet (e.g. when started from the Start menu shortcut).
$me = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $DotSourced -and -not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $relaunch = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`""
    if ($Emergency) { $relaunch += ' -Emergency' }
    try { Start-Process $PowerShellExe -Verb RunAs -WindowStyle Hidden -ArgumentList $relaunch } catch {}
    exit
}

$UsbDir        = $PSScriptRoot                                  # e.g. D:\Chainlink
$UsbRoot       = (Split-Path -Path $UsbDir -Qualifier) + '\'    # e.g. D:\
$KeyFile       = Join-Path $UsbDir 'chainlink.key'
$BlocklistPath = Join-Path $UsbDir 'blocklist.txt'
$ProgramData   = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
if ([string]::IsNullOrWhiteSpace($ProgramData)) { throw 'Windows did not provide the ProgramData directory.' }
$TaskName      = 'Chainlink'
$TaskPath      = '\'
$ShortsEntry   = 'youtube.com/shorts'
$ShortcutPath  = Join-Path $ProgramData 'Microsoft\Windows\Start Menu\Programs\Chainlink Emergency Uninstall.lnk'

# Every path inside the program folder is derived here, in one place.
function Set-AppDir([string]$path) {
    $script:AppDir        = $path
    $script:PairFile      = Join-Path $path 'pair.txt'
    $script:RecoveryFile  = Join-Path $path 'recovery.txt'
    $script:RecoveryAttemptsFile = Join-Path $path 'recovery-attempts.txt'
    $script:LockFile      = Join-Path $path 'watchdog.lock'
    $script:InstalledWatchdog = Join-Path $path 'watchdog.ps1'
    $script:UninstallMarker = Join-Path $path 'uninstalling'
}
Set-AppDir (Join-Path $ProgramData 'Chainlink')
$WordCount     = 6
$WatchdogStopTimeoutSeconds = 15
$CommonModule  = Join-Path $PSScriptRoot 'Chainlink.Common.psm1'
Import-Module $CommonModule -Force

# Recovery words are picked from this list.
$WordList = @(
    'apple','arrow','badge','baker','bamboo','banjo','barn','basket','beach','bean','bear','beaver','bell','bench','berry','bike',
    'bird','bison','blanket','boat','bonfire','book','boot','bottle','bread','brick','bridge','broom','bucket','bunny','butter','button',
    'cabin','cactus','cake','camel','camera','candle','canoe','canyon','carpet','carrot','castle','cedar','chair','cheese','cherry','chess',
    'cider','circus','cliff','clock','cloud','clover','coast','cobra','cocoa','comet','cookie','copper','coral','cotton','cougar','cowboy',
    'crab','crane','crayon','cricket','crown','daisy','desert','dolphin','donkey','dragon','drum','eagle','easel','elbow','ember','falcon',
    'fern','ferry','fiddle','field','flag','flute','forest','fossil','fox','frog','garden','garlic','geyser','ginger','glove','goat',
    'gopher','grape','guitar','hammer','harbor','hawk','hazel','helmet','heron','hill','honey','hornet','horse','igloo','island','ivy',
    'jacket','jaguar','jelly','jungle','kayak','kettle','kite','koala','ladder','lagoon','lantern','lemon','lily','lion','lizard','llama',
    'lobster','magnet','mango','maple','marble','meadow','melon','mitten','moose','moss','mountain','muffin','needle','nest','noodle','oak',
    'oasis','ocean','olive','onion','orange','orchid','otter','owl','paddle','panda','parrot','peach','peanut','pearl','pebble','pelican',
    'pencil','pepper','piano','pickle','pigeon','pillow','pine','planet','plum','pony','popcorn','potato','puffin','pumpkin','puzzle','quail',
    'quilt','rabbit','radio','raft','rain','raven','reef','ribbon','river','robin','rocket','rose','saddle','salmon','sandal','scarf',
    'seal','shell','shovel','silver','skunk','sled','sloth','snail','socks','sparrow','spider','spoon','squash','squid','stable','star',
    'storm','sugar','summit','sunset','swan','table','taco','tiger','tomato','torch','tower','tractor','trail','tulip','tundra','turkey',
    'turtle','umbrella','valley','velvet','violin','volcano','waffle','wagon','walnut','walrus','whale','wheat','willow','window','wizard','wolf',
    'yogurt','zebra','anchor','acorn','bagel','beetle','biscuit','blossom','breeze','canary','chimney','compass','cupcake','dune','feather','glacier'
)   # exactly 256 simple words

# ================================================================ helpers

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-Hash([string]$text) {
    return Get-ChainlinkSha256Hex $text
}

function Get-UsbHash {
    if (-not (Test-Path -LiteralPath $KeyFile)) { return $null }
    $token  = (Get-Content -LiteralPath $KeyFile -Raw).Trim()
    try { $keyBytes = [Convert]::FromBase64String($token) } catch { return $null }
    if ($keyBytes.Length -ne 32) { return $null }
    $letter = $UsbRoot.TrimEnd('\')
    if ($letter -notmatch '^[A-Za-z]:$') { return $null }
    $serial = [string](Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$letter'").VolumeSerialNumber
    if ([string]::IsNullOrWhiteSpace($serial)) { return $null }
    return Get-Hash "$token|$serial"
}

function Get-NamedTasks {
    return @(Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue)
}

function Test-ChainlinkTask {
    foreach ($task in @(Get-NamedTasks)) {
        if (Test-ChainlinkScheduledTaskObject -Task $task -PowerShellExe $PowerShellExe -WatchdogPath $InstalledWatchdog) { return $true }
    }
    return $false
}

function Test-Installed {
    return (Test-ChainlinkTask) -or (Test-Path -LiteralPath $InstalledWatchdog -PathType Leaf)
}

# Stops the watchdog and returns the open watchdog lock, which keeps any new watchdog from
# starting until the caller disposes it. Returns $null when Chainlink has no program folder.
# The original release took no lock, so its watchdog is found by command line instead.
function Stop-LegacyWatchdogProcesses {
    Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
        Where-Object { $_.ProcessId -ne $PID -and $_.CommandLine -like '*Chainlink\watchdog.ps1*' } |
        ForEach-Object { try { Invoke-CimMethod -InputObject $_ -MethodName Terminate -ErrorAction Stop | Out-Null } catch { } }   # it may already have exited
}

function Stop-NamedTask {
    Stop-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
}

function Test-OwnTask($task) {
    return (Test-ChainlinkScheduledTaskObject -Task $task -PowerShellExe $PowerShellExe -WatchdogPath $InstalledWatchdog) -or
           (Test-ChainlinkTaskReferencesDirectory -Task $task -Directory $AppDir)
}

# The watchdog only looks for <drive>:\Chainlink\chainlink.key, so linking from anywhere else
# would create a key it can never find and lock the PC a few seconds later.
function Test-UsbLayout {
    return ($UsbDir.TrimEnd('\') -ieq (Join-Path $UsbRoot 'Chainlink'))
}

# Refuses to go on when the program folder could have been written by a non-administrator.
function Assert-TrustedProgramFolder {
    if ((Test-Path -LiteralPath $AppDir) -and -not (Test-ChainlinkTrustedDirectory $AppDir)) {
        throw "$AppDir was not created by Chainlink, or another account has been able to change it. Nothing in it was used. Delete that folder as Administrator and try again."
    }
}

function Unregister-NamedTask {
    Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false -ErrorAction Stop
}

# Scheduled task: starts at boot, and every minute makes sure the watchdog is still running.
function Register-ChainlinkTask {
    $action = New-ScheduledTaskAction -Execute $PowerShellExe `
        -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$InstalledWatchdog`""
    $atBoot = New-ScheduledTaskTrigger -AtStartup
    $every  = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)
    $who    = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $set    = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
                -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew `
                -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Action $action -Trigger $atBoot, $every -Principal $who -Settings $set `
        -Description 'Chainlink: blocks distracting websites unless the paired USB key is plugged in.' -Force | Out-Null
    Start-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath
}

function Stop-Watchdog {
    if (@(Get-NamedTasks | Where-Object { Test-OwnTask $_ }).Count -gt 0) { Stop-NamedTask }
    Stop-LegacyWatchdogProcesses
    if (-not (Test-Path -LiteralPath $AppDir -PathType Container)) { return $null }

    $deadline = (Get-Date).AddSeconds($WatchdogStopTimeoutSeconds)
    while ($true) {
        $lock = Open-ChainlinkWatchdogLock -Path $LockFile
        if ($null -ne $lock) { return $lock }
        $owner = Get-ChainlinkWatchdogLockOwner -Path $LockFile
        if ($owner -gt 0 -and $owner -ne $PID) {
            Get-CimInstance Win32_Process -Filter "ProcessId=$owner" -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -ieq 'powershell.exe' -and $_.CommandLine -like '*watchdog.ps1*' } |
                ForEach-Object { try { Invoke-CimMethod -InputObject $_ -MethodName Terminate -ErrorAction Stop | Out-Null } catch { } }
        }
        if ((Get-Date) -gt $deadline) { throw 'The Chainlink watchdog is still running and could not be stopped. Wait a minute and try again.' }
        Start-Sleep -Milliseconds 300
    }
}

# Removes the scheduled task if it is Chainlink's, or if it would run anything from the
# Chainlink program folder. An unrelated task that merely shares the name is left alone.
function Remove-ChainlinkTask {
    foreach ($task in @(Get-NamedTasks)) {
        if (Test-OwnTask $task) { Unregister-NamedTask }
    }
}

function Test-UsbMatchesPc {
    if (-not (Test-Path $PairFile)) { return $false }
    $h = Get-UsbHash
    if (-not $h) { return $false }
    return (@(Get-Content $PairFile | ForEach-Object { $_.Trim() }) -contains $h)
}

# ================================================================ blocklist file <-> window

# Cleans a website entry: "https://www.MangaDex.org/" -> "mangadex.org"
function Format-Site([string]$s) {
    return ConvertTo-ChainlinkEntry $s
}

# Cleans a channel entry. Accepts "@Name", "Name", or any link to the channel.
# Returns "youtube.com/@Name" or "youtube.com/channel/UC...".
function Format-Channel([string]$s) {
    return ConvertTo-ChainlinkChannel $s
}

# Splits blocklist.txt into websites, channels, and the Shorts on/off switch.
function Read-Blocklist {
    $sites = @(); $channels = @(); $shorts = $false; $invalid = @()
    if (Test-Path -LiteralPath $BlocklistPath) {
        # Read as UTF-8, the way the watchdog reads it and Save writes it.
        foreach ($line in [IO.File]::ReadAllLines($BlocklistPath)) {
            $e = $line.Trim()
            if ($e -eq '' -or $e.StartsWith('#')) { continue }
            # A line that is not valid is shown as written so it can be fixed, never dropped.
            try { $e = Format-Site $e } catch { $sites += $e; $invalid += $e; continue }
            if ($e -ieq $ShortsEntry) { $shorts = $true }
            elseif ($e -match '^youtube\.com/(@|channel/|c/|user/)') { $channels += ($e -replace '^youtube\.com/', '') }
            else { $sites += $e }
        }
    }
    return @{ Sites = $sites; Channels = $channels; Shorts = $shorts; Invalid = $invalid }
}

function Save-Blocklist([string[]]$sites, [string[]]$channels, [bool]$shorts) {
    $out = @(
        '# Chainlink blocklist - edit with Chainlink.cmd (or by hand, one entry per line).',
        '# Lines starting with # are ignored.',
        '',
        '# Websites'
    )
    $out += @($sites | ForEach-Object { Format-Site $_ } | Where-Object { $_ -ne '' } | Select-Object -Unique)
    $out += ''
    $out += '# YouTube'
    if ($shorts) { $out += $ShortsEntry }
    $out += @($channels | ForEach-Object { Format-Channel $_ } | Where-Object { $_ -ne '' } | Select-Object -Unique)
    if (@($out | Where-Object { $_ -ne '' -and -not $_.StartsWith('#') }).Count -gt 2048) {
        throw 'The blocklist can hold at most 2,048 entries.'
    }
    Set-ChainlinkTextFileAtomic -Path $BlocklistPath -Lines $out
}

# ================================================================ recovery words

# Picks $WordCount random words. The list has exactly 256 words, so one random byte = one fair pick.
function New-RecoveryWords {
    $bytes = New-Object byte[] $WordCount
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return @($bytes | ForEach-Object { $WordList[$_] })
}

function Get-PhraseHash([string[]]$words, [byte[]]$salt, [int]$rounds = 300000) {
    $phrase = (@($words | ForEach-Object { $_.Trim().ToLower() }) -join ' ')
    $kdf = New-Object Security.Cryptography.Rfc2898DeriveBytes($phrase, $salt, $rounds)
    try { return $kdf.GetBytes(32) } finally { $kdf.Dispose() }
}

# Stores only a salted, slow hash of the words on this PC - never the words themselves.
function Save-RecoveryWords([string[]]$words) {
    $salt = New-Object byte[] 16
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($salt) } finally { $rng.Dispose() }
    $rounds = 300000
    $hash = [Convert]::ToBase64String((Get-PhraseHash $words $salt $rounds))
    Set-ChainlinkTextFileAtomic -Path $RecoveryFile -Lines @("v1:${rounds}:$([Convert]::ToBase64String($salt)):$hash")
}

function Test-RecoveryWords([string[]]$words) {
    if (-not (Test-Path -LiteralPath $RecoveryFile -PathType Leaf)) { return $false }
    try {
        $parts = (Get-Content -LiteralPath $RecoveryFile -Raw).Trim().Split(':')
        if ($parts.Count -eq 2) {
            $rounds = 100000; $saltText = $parts[0]; $hashText = $parts[1]
        } elseif ($parts.Count -eq 4 -and $parts[0] -eq 'v1') {
            $rounds = [int]$parts[1]; $saltText = $parts[2]; $hashText = $parts[3]
            if ($rounds -lt 100000 -or $rounds -gt 2000000) { return $false }
        } else { return $false }
        $salt = [Convert]::FromBase64String($saltText)
        $expected = [Convert]::FromBase64String($hashText)
        if ($salt.Length -ne 16 -or $expected.Length -ne 32) { return $false }
        return Test-ChainlinkFixedTimeEqual (Get-PhraseHash $words $salt $rounds) $expected
    } catch { return $false }
}

function Get-RecoveryDelaySeconds {
    if (-not (Test-Path -LiteralPath $RecoveryAttemptsFile -PathType Leaf)) { return 0 }
    try {
        $parts = (Get-Content -LiteralPath $RecoveryAttemptsFile -Raw).Trim().Split(':')
        if ($parts.Count -ne 2) { return 0 }
        $until = [DateTime]::FromBinary([int64]$parts[1])
        return [Math]::Max(0, [Math]::Ceiling(($until.ToUniversalTime() - [DateTime]::UtcNow).TotalSeconds))
    } catch { return 0 }
}

function Register-RecoveryFailure {
    $failures = 0
    if (Test-Path -LiteralPath $RecoveryAttemptsFile -PathType Leaf) {
        try { $failures = [int]((Get-Content -LiteralPath $RecoveryAttemptsFile -Raw).Trim().Split(':')[0]) } catch { $failures = 0 }
    }
    $failures = [Math]::Min(6, $failures + 1)
    $delay = [Math]::Min(60, [Math]::Pow(2, $failures + 1))
    $until = [DateTime]::UtcNow.AddSeconds($delay).ToBinary()
    Set-ChainlinkTextFileAtomic -Path $RecoveryAttemptsFile -Lines @("${failures}:$until")
}

# ================================================================ link / uninstall

function Test-BaselineFile([string]$path) {
    try { return (Test-ChainlinkPolicyBaseline (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json)) }
    catch { return $false }
}

# Runs a watchdog script in one of its one-shot modes (-Unlock or -CaptureBaseline).
function Invoke-Watchdog([string]$path, [string]$mode) {
    & $PowerShellExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $path $mode | Out-Null
    return ($LASTEXITCODE -eq 0)
}

function Install-Chainlink {
    foreach ($name in @('Chainlink.ps1', 'Chainlink.Common.psm1', 'watchdog.ps1')) {
        if (-not (Test-Path -LiteralPath (Join-Path $UsbDir $name) -PathType Leaf)) { throw "The USB is missing Chainlink\$name." }
    }
    if (-not (Test-UsbLayout)) {
        throw "Chainlink has to be started from the Chainlink folder at the top level of the USB drive (for example E:\Chainlink). It is running from $UsbDir."
    }
    Assert-TrustedProgramFolder
    $hasExistingChainlinkTask = Test-ChainlinkTask
    if (@(Get-NamedTasks).Count -gt 0 -and -not $hasExistingChainlinkTask) {
        throw "A scheduled task named '$TaskName' already exists and does not belong to Chainlink. Rename it before linking this PC."
    }

    # 1. Create the secret key file on the USB the first time (reused for every PC you link).
    if (-not (Test-Path -LiteralPath $KeyFile)) {
        $bytes = New-Object byte[] 32
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
        [IO.File]::WriteAllText($KeyFile, [Convert]::ToBase64String($bytes), [Text.Encoding]::ASCII)
        $kf = Get-Item -LiteralPath $KeyFile -Force
        $kf.Attributes = $kf.Attributes -bor [IO.FileAttributes]::Hidden
    }
    $hash = Get-UsbHash
    if (-not $hash) { throw 'Could not validate the USB key and volume serial number.' }

    # 2. Program folder that only SYSTEM and Administrators can read or change. Everything in it
    #    runs as SYSTEM, so a folder another account created or owns is never reused.
    $existing = $hasExistingChainlinkTask
    $createdAppDir = $false
    if (Test-Path -LiteralPath $AppDir) {
        $appItem = Get-Item -LiteralPath $AppDir -Force
        if (-not $appItem.PSIsContainer -or ($appItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "$AppDir must be a real directory, not a file, junction, or symbolic link."
        }
        if (-not $existing) {
            if (@(Get-ChildItem -LiteralPath $AppDir -Force).Count -eq 0) {
                Remove-Item -LiteralPath $AppDir -Force
            } elseif ((Test-ChainlinkProtectedDirectory $AppDir) -and (Test-Path -LiteralPath $InstalledWatchdog -PathType Leaf)) {
                # A Chainlink folder only administrators could have written, whose task is gone
                # (for example after an interrupted uninstall). Repair it like any other install,
                # so its blocks are lifted before a new policy baseline could ever be taken.
                $existing = $true
            } else {
                throw "$AppDir already contains files but no Chainlink scheduled task exists. If Chainlink is installed, use Uninstall (or Chainlink Emergency Uninstall) first; otherwise delete that folder as Administrator, then link again."
            }
        }
    }
    if (Test-Path -LiteralPath $AppDir) { Set-ChainlinkProtectedDirectoryAcl $AppDir }
    else { New-ChainlinkProtectedDirectory $AppDir; $createdAppDir = $true }

    try {
        $newRecoveryWords = Install-ChainlinkFiles $hash $existing
    } catch {
        if ($createdAppDir) {
            # A first-time link that fails leaves nothing behind, so it can simply be tried again.
            # The folder goes only once the task is gone: a SYSTEM task must never be left
            # pointing at a path that any account could then recreate.
            $taskGone = $false
            try { Stop-NamedTask; Remove-ChainlinkTask; $taskGone = $true } catch { }
            if ($taskGone) {
                Remove-Item -LiteralPath $ShortcutPath -Force -ErrorAction SilentlyContinue
                Remove-Item -LiteralPath $AppDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        throw
    }
    return $newRecoveryWords
}

function Install-ChainlinkFiles([string]$hash, [bool]$upgrade) {
    $baselinePath = Join-Path $AppDir 'policy-baseline.json'
    $newRecoveryWords = $null

    # Hold the watchdog lock while files change, so no watchdog runs a half-replaced copy.
    $lock = Stop-Watchdog
    try {
        if (Test-Path -LiteralPath $UninstallMarker) { Remove-Item -LiteralPath $UninstallMarker -Force }
        if ($upgrade) {
            # Lift the old copy's blocks with the old copy's own code before replacing it.
            if (-not (Test-Path -LiteralPath $InstalledWatchdog -PathType Leaf)) {
                throw 'The existing Chainlink task has no installed watchdog; installation was stopped.'
            }
            if (-not (Invoke-Watchdog $InstalledWatchdog '-Unlock')) { throw 'Could not prepare the existing installation for upgrade.' }
        }

        Copy-Item -LiteralPath (Join-Path $UsbDir 'Chainlink.Common.psm1') -Destination $AppDir -Force
        Copy-Item -LiteralPath (Join-Path $UsbDir 'watchdog.ps1') -Destination $AppDir -Force
        if ((Test-Path -LiteralPath $baselinePath) -and -not (Test-BaselineFile $baselinePath)) {
            # Unreadable, so the unlock above already fell back to removing Chainlink's own values.
            Remove-Item -LiteralPath $baselinePath -Force
        }
        if (-not (Test-Path -LiteralPath $baselinePath)) {
            if (-not (Invoke-Watchdog $InstalledWatchdog '-CaptureBaseline') -or -not (Test-Path -LiteralPath $baselinePath)) {
                throw 'Could not save the existing browser policies; installation was stopped to avoid overwriting them.'
            }
        }

        # 3. Remember this USB (only a hash is stored, never the key itself).
        $known = @()
        if (Test-Path -LiteralPath $PairFile) { $known = @(Get-Content -LiteralPath $PairFile | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ -match '^[a-f0-9]{64}$' }) }
        if ($known -notcontains $hash) { $known += $hash }
        Set-ChainlinkTextFileAtomic -Path $PairFile -Lines @($known | Select-Object -Unique)

        # 4. Copy the blocklist and this program (for emergency uninstall) to this PC.
        [void]@(Get-ChainlinkBlocklist -Path $BlocklistPath)   # refuse to install a list the watchdog would reject
        Copy-Item -LiteralPath $BlocklistPath -Destination $AppDir -Force
        if ($PSCommandPath -ne (Join-Path $AppDir 'Chainlink.ps1')) {
            Copy-Item -LiteralPath $PSCommandPath -Destination $AppDir -Force
        }
        Get-ChildItem -LiteralPath $AppDir -File | Unblock-File -ErrorAction SilentlyContinue

        # Start menu shortcut for emergency uninstall (needs the recovery words).
        $sh = New-Object -ComObject WScript.Shell
        $lnk = $sh.CreateShortcut($ShortcutPath)
        $installedMain = (Join-Path $AppDir 'Chainlink.ps1').Replace("'", "''")
        $quotedPowerShell = $PowerShellExe.Replace("'", "''")
        $elevate = "Start-Process -FilePath '$quotedPowerShell' -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-WindowStyle','Hidden','-File','$installedMain','-Emergency')"
        $encodedElevate = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($elevate))
        $lnk.TargetPath = $PowerShellExe
        $lnk.Arguments = "-NoProfile -WindowStyle Hidden -EncodedCommand $encodedElevate"
        $lnk.Description = 'Remove Chainlink without the USB key, using your recovery words.'
        $lnk.Save()
    } finally {
        if ($null -ne $lock) { $lock.Dispose() }
    }

    # 5. Register and start the background task.
    Register-ChainlinkTask

    # 6. First time on this PC: recovery words for the accountability partner. Made last, so
    #    that if anything above fails the words are not stored without ever being shown.
    if (-not (Test-Path -LiteralPath $RecoveryFile)) {
        $newRecoveryWords = New-RecoveryWords
        Save-RecoveryWords $newRecoveryWords
    }

    return $newRecoveryWords
}

function Uninstall-Chainlink {
    # Order matters. First make sure no watchdog is running and none can start (the task fires
    # every minute and would re-apply the blocks behind our back), then lift the blocks, and
    # only then delete the files.
    Assert-TrustedProgramFolder
    $lock = Stop-Watchdog
    try {
        Remove-ChainlinkTask

        $wd = $InstalledWatchdog
        if (-not (Test-Path -LiteralPath $wd)) { $wd = Join-Path $UsbDir 'watchdog.ps1' }
        if (-not (Test-Path -LiteralPath $wd)) { throw 'The installed watchdog is missing; browser policies were not changed.' }
        if (-not (Invoke-Watchdog $wd '-Unlock')) { throw 'Could not restore browser policies. Chainlink files were left in place so you can try again.' }
        # Tell any watchdog that was already starting to exit instead of locking again. It can
        # only get the lock after this point, and it checks for the marker once it has it.
        if (Test-Path -LiteralPath $AppDir -PathType Container) { [IO.File]::WriteAllText($UninstallMarker, '') }
    } finally {
        if ($null -ne $lock) { $lock.Dispose() }
    }

    if (Test-Path -LiteralPath $ShortcutPath) { Remove-Item -LiteralPath $ShortcutPath -Force }
    if (Test-Path -LiteralPath $AppDir) {
        if ((Get-Item -LiteralPath $AppDir -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "$AppDir is a link, not a folder; it was not removed."
        }
        # A watchdog that is just exiting can hold the lock file for a moment; retry briefly.
        for ($attempt = 1; ; $attempt++) {
            try { Remove-Item -LiteralPath $AppDir -Recurse -Force -ErrorAction Stop; break }
            catch { if ($attempt -ge 10) { throw }; Start-Sleep -Milliseconds 500 }
        }
    }
}

# Dot-sourcing this file (as the tests do) defines the functions above without opening a window.
if ($DotSourced) { return }

# ================================================================ window

Add-Type -AssemblyName System.Windows.Forms, System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()

function Show-Message([string]$text, [string]$icon = 'Information') {
    [void][Windows.Forms.MessageBox]::Show($text, 'Chainlink', 'OK', $icon)
}

# ---------------------------------------------------------------- recovery words popups

# Shows new recovery words for the user to give to their accountability partner.
function Show-RecoveryWords([string[]]$words) {
    $f = New-Object Windows.Forms.Form
    $f.Text = 'Chainlink - recovery words'
    $f.Font = New-Object Drawing.Font('Segoe UI', 10)
    $f.StartPosition = 'CenterScreen'; $f.AutoScaleMode = 'Dpi'
    $f.FormBorderStyle = 'FixedDialog'; $f.MaximizeBox = $false; $f.MinimizeBox = $false
    $f.ControlBox = $false   # must use the button, so the words can't be skipped by accident
    $f.BackColor = [Drawing.Color]::White
    $f.AutoSize = $true; $f.AutoSizeMode = 'GrowAndShrink'

    $p = New-Object Windows.Forms.FlowLayoutPanel
    $p.FlowDirection = 'TopDown'; $p.WrapContents = $false; $p.AutoSize = $true
    $p.Padding = New-Object Windows.Forms.Padding(20)
    $f.Controls.Add($p)

    $h = New-Object Windows.Forms.Label
    $h.Text = 'Give these words to your accountability partner'
    $h.Font = New-Object Drawing.Font('Segoe UI', 13, [Drawing.FontStyle]::Bold); $h.AutoSize = $true
    $p.Controls.Add($h)

    $t = New-Object Windows.Forms.Label
    $t.AutoSize = $true; $t.MaximumSize = New-Object Drawing.Size(460, 0)
    $t.Margin = New-Object Windows.Forms.Padding(0, 8, 0, 12)
    $t.Text = "If your USB key is ever lost, these words are the only way to remove Chainlink from this PC ($env:COMPUTERNAME). " +
              "Send them to your partner and don't keep a copy yourself. They won't be shown again."
    $p.Controls.Add($t)

    $grid = New-Object Windows.Forms.TableLayoutPanel
    $grid.ColumnCount = 2; $grid.RowCount = 3; $grid.AutoSize = $true
    for ($i = 0; $i -lt $words.Count; $i++) {
        $w = New-Object Windows.Forms.Label
        $w.Text = "$($i + 1).  $($words[$i])"
        $w.Font = New-Object Drawing.Font('Segoe UI', 14, [Drawing.FontStyle]::Bold)
        $w.Size = New-Object Drawing.Size(210, 44); $w.TextAlign = 'MiddleLeft'
        $w.BackColor = [Drawing.Color]::FromArgb(240, 243, 248)
        $w.Margin = New-Object Windows.Forms.Padding(4)
        $w.Padding = New-Object Windows.Forms.Padding(10, 0, 0, 0)
        $grid.Controls.Add($w, ($i % 2), [Math]::Floor($i / 2))
    }
    $p.Controls.Add($grid)

    $copy = New-Object Windows.Forms.Button
    $copy.Text = 'Copy words'; $copy.AutoSize = $true
    $copy.Margin = New-Object Windows.Forms.Padding(0, 12, 0, 0)
    $copy.Add_Click({ [Windows.Forms.Clipboard]::SetText(($words -join ' ')); $copy.Text = 'Copied!' })
    $p.Controls.Add($copy)

    $chk = New-Object Windows.Forms.CheckBox
    $chk.Text = 'My accountability partner has these words.'; $chk.AutoSize = $true
    $chk.Margin = New-Object Windows.Forms.Padding(0, 14, 0, 0)
    $p.Controls.Add($chk)

    $done = New-Object Windows.Forms.Button
    $done.Text = 'Done'; $done.AutoSize = $true; $done.Enabled = $false
    $done.Margin = New-Object Windows.Forms.Padding(0, 10, 0, 0)
    $done.DialogResult = 'OK'
    $chk.Add_CheckedChanged({ $done.Enabled = $chk.Checked })
    $p.Controls.Add($done)

    [void]$f.ShowDialog()
    [Windows.Forms.Clipboard]::Clear()
}

# Asks for the recovery words in separate boxes. Returns $true when they match.
function Show-EmergencyForm {
    $f = New-Object Windows.Forms.Form
    $f.Text = 'Chainlink - emergency uninstall'
    $f.Font = New-Object Drawing.Font('Segoe UI', 10)
    $f.StartPosition = 'CenterScreen'; $f.AutoScaleMode = 'Dpi'
    $f.FormBorderStyle = 'FixedDialog'; $f.MaximizeBox = $false; $f.MinimizeBox = $false
    $f.BackColor = [Drawing.Color]::White
    $f.AutoSize = $true; $f.AutoSizeMode = 'GrowAndShrink'

    $p = New-Object Windows.Forms.FlowLayoutPanel
    $p.FlowDirection = 'TopDown'; $p.WrapContents = $false; $p.AutoSize = $true
    $p.Padding = New-Object Windows.Forms.Padding(20)
    $f.Controls.Add($p)

    $h = New-Object Windows.Forms.Label
    $h.Text = 'Emergency uninstall'
    $h.Font = New-Object Drawing.Font('Segoe UI', 13, [Drawing.FontStyle]::Bold); $h.AutoSize = $true
    $p.Controls.Add($h)

    $t = New-Object Windows.Forms.Label
    $t.AutoSize = $true; $t.MaximumSize = New-Object Drawing.Size(460, 0)
    $t.Margin = New-Object Windows.Forms.Padding(0, 8, 0, 12)
    $t.Text = "Lost your USB key? Ask your accountability partner for the $WordCount recovery words for this PC ($env:COMPUTERNAME) and enter them below."
    $p.Controls.Add($t)

    $auto = New-Object Windows.Forms.AutoCompleteStringCollection
    $auto.AddRange([string[]]$WordList)

    $grid = New-Object Windows.Forms.TableLayoutPanel
    $grid.ColumnCount = 2; $grid.RowCount = 3; $grid.AutoSize = $true
    $boxes = @()
    for ($i = 0; $i -lt $WordCount; $i++) {
        $cell = New-Object Windows.Forms.FlowLayoutPanel
        $cell.AutoSize = $true; $cell.WrapContents = $false
        $n = New-Object Windows.Forms.Label
        $n.Text = "$($i + 1)."; $n.Size = New-Object Drawing.Size(28, 30); $n.TextAlign = 'MiddleRight'
        $b = New-Object Windows.Forms.TextBox
        $b.Font = New-Object Drawing.Font('Segoe UI', 13); $b.Width = 170
        $b.AutoCompleteMode = 'SuggestAppend'; $b.AutoCompleteSource = 'CustomSource'; $b.AutoCompleteCustomSource = $auto
        $cell.Controls.Add($n); $cell.Controls.Add($b)
        $grid.Controls.Add($cell, ($i % 2), [Math]::Floor($i / 2))
        $boxes += $b
    }
    $p.Controls.Add($grid)

    $msg = New-Object Windows.Forms.Label
    $msg.AutoSize = $true; $msg.ForeColor = [Drawing.Color]::FromArgb(190, 60, 30)
    $msg.Margin = New-Object Windows.Forms.Padding(0, 8, 0, 0)
    $p.Controls.Add($msg)

    $row = New-Object Windows.Forms.FlowLayoutPanel
    $row.AutoSize = $true; $row.Margin = New-Object Windows.Forms.Padding(0, 10, 0, 0)
    $go = New-Object Windows.Forms.Button
    $go.Text = 'Uninstall Chainlink'; $go.AutoSize = $true
    $cancel = New-Object Windows.Forms.Button
    $cancel.Text = 'Cancel'; $cancel.AutoSize = $true; $cancel.DialogResult = 'Cancel'
    $row.Controls.Add($go); $row.Controls.Add($cancel)
    $p.Controls.Add($row)
    $f.CancelButton = $cancel

    $f.Tag = $false
    $go.Add_Click({
        $entered = @($boxes | ForEach-Object { $_.Text.Trim() })
        if (@($entered | Where-Object { $_ -eq '' }).Count -gt 0) { $msg.Text = "Please fill in all $WordCount words."; return }
        $remaining = Get-RecoveryDelaySeconds
        if ($remaining -gt 0) { $msg.Text = "Please wait $remaining seconds before trying again."; return }
        $f.UseWaitCursor = $true; $go.Enabled = $false
        $ok = Test-RecoveryWords $entered
        if (-not $ok) { Register-RecoveryFailure; Start-Sleep -Seconds 1 }
        $f.UseWaitCursor = $false; $go.Enabled = $true
        if ($ok) { Remove-Item -LiteralPath $RecoveryAttemptsFile -Force -ErrorAction SilentlyContinue; $f.Tag = $true; $f.Close() }
        else { $msg.Text = 'Those words do not match. Check the spelling and the order.' }
    })

    [void]$f.ShowDialog()
    return ($f.Tag -eq $true)
}

# ---------------------------------------------------------------- emergency mode

if ($Emergency) {
    if (-not (Test-Installed)) { Show-Message 'Chainlink is not installed on this PC.'; exit 0 }
    if (-not (Test-Path $RecoveryFile)) {
        Show-Message 'This installation has no recovery words. Plug in its paired USB, open Chainlink, and choose "Repair / update this PC" before using emergency uninstall.' 'Warning'
        exit 1
    } elseif (-not (Show-EmergencyForm)) { exit 0 }
    try {
        Uninstall-Chainlink
        Show-Message 'Chainlink has been removed from this PC.'
    } catch { Show-Message "Uninstall failed:`n$_" 'Error' }
    exit 0
}

$font     = New-Object Drawing.Font('Segoe UI', 10)
$fontBold = New-Object Drawing.Font('Segoe UI', 10, [Drawing.FontStyle]::Bold)
$fontHint = New-Object Drawing.Font('Segoe UI', 9)
$fontBig  = New-Object Drawing.Font('Segoe UI', 16, [Drawing.FontStyle]::Bold)
$grey     = [Drawing.Color]::FromArgb(110, 110, 110)

$form = New-Object Windows.Forms.Form
$form.Text = 'Chainlink'
$form.Font = $font
$form.StartPosition = 'CenterScreen'
$form.AutoScaleMode = 'Dpi'
$form.ClientSize = New-Object Drawing.Size(520, 640)
$form.MinimumSize = New-Object Drawing.Size(460, 560)
$form.BackColor = [Drawing.Color]::White

$layout = New-Object Windows.Forms.TableLayoutPanel
$layout.Dock = 'Fill'
$layout.Padding = New-Object Windows.Forms.Padding(18)
$layout.ColumnCount = 1
$layout.RowCount = 9
foreach ($i in 0..8) {
    if ($i -eq 3 -or $i -eq 6) { $style = New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent, 50) }
    else { $style = New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::AutoSize) }
    [void]$layout.RowStyles.Add($style)
}
$form.Controls.Add($layout)

function New-Label([string]$text, $f, $color = $null) {
    $l = New-Object Windows.Forms.Label
    $l.Text = $text; $l.Font = $f; $l.AutoSize = $true
    $l.Margin = New-Object Windows.Forms.Padding(0, 6, 0, 2)
    if ($color) { $l.ForeColor = $color }
    return $l
}

function New-Box {
    $t = New-Object Windows.Forms.TextBox
    $t.Multiline = $true; $t.ScrollBars = 'Vertical'; $t.AcceptsReturn = $true; $t.WordWrap = $false
    $t.Dock = 'Fill'; $t.Font = New-Object Drawing.Font('Consolas', 10)
    return $t
}

$title  = New-Label 'Chainlink' $fontBig
$status = New-Label '' $fontHint
$layout.Controls.Add($title, 0, 0)
$layout.Controls.Add($status, 0, 1)

$layout.Controls.Add((New-Label "Websites to block  -  one per line, e.g. mangadex.org" $fontBold), 0, 2)
$sitesBox = New-Box
$layout.Controls.Add($sitesBox, 0, 3)

$shortsCheck = New-Object Windows.Forms.CheckBox
$shortsCheck.Text = 'Block YouTube Shorts'
$shortsCheck.AutoSize = $true
$shortsCheck.Margin = New-Object Windows.Forms.Padding(0, 10, 0, 0)
$layout.Controls.Add($shortsCheck, 0, 4)

$layout.Controls.Add((New-Label "YouTube channels to block  -  one per line: @ChannelName or the channel's link" $fontBold), 0, 5)
$channelsBox = New-Box
$layout.Controls.Add($channelsBox, 0, 6)

$layout.Controls.Add((New-Label 'Changes reach your PC within ~10 seconds while this USB is plugged in.' $fontHint $grey), 0, 7)

$buttons = New-Object Windows.Forms.FlowLayoutPanel
$buttons.AutoSize = $true
$buttons.Dock = 'Fill'
$buttons.Margin = New-Object Windows.Forms.Padding(0, 10, 0, 0)
$layout.Controls.Add($buttons, 0, 8)

function New-Button([string]$text) {
    $b = New-Object Windows.Forms.Button
    $b.Text = $text; $b.AutoSize = $true
    $b.Padding = New-Object Windows.Forms.Padding(8, 4, 8, 4)
    $b.Margin = New-Object Windows.Forms.Padding(0, 0, 8, 0)
    [void]$buttons.Controls.Add($b)
    return $b
}
$saveBtn      = New-Button 'Save blocklist'
$linkBtn      = New-Button 'Link this PC'
$uninstallBtn = New-Button 'Uninstall from this PC'
$wordsBtn     = New-Button 'New recovery words'
$form.AcceptButton = $null   # Enter adds a new line in the boxes instead of clicking a button

function Update-Status {
    if (-not (Test-Installed)) {
        $status.Text = 'This PC is not linked yet. Click "Link this PC" to start.'
        $status.ForeColor = $grey
        $linkBtn.Text = 'Link this PC'
        $linkBtn.Enabled = $true; $uninstallBtn.Enabled = $false; $wordsBtn.Enabled = $false
    } elseif (Test-UsbMatchesPc) {
        $status.Text = 'This PC is linked to this USB. Blocks are OFF while it is plugged in.'
        $status.ForeColor = [Drawing.Color]::FromArgb(20, 130, 60)
        $linkBtn.Text = 'Repair / update this PC'
        $linkBtn.Enabled = $true; $uninstallBtn.Enabled = $true; $wordsBtn.Enabled = $true
    } else {
        $status.Text = 'This PC is linked to a different USB key.'
        $status.ForeColor = [Drawing.Color]::FromArgb(190, 60, 30)
        $linkBtn.Text = 'Link this PC'
        $linkBtn.Enabled = $false; $uninstallBtn.Enabled = $false; $wordsBtn.Enabled = $false
    }
}

function Get-Lines([Windows.Forms.TextBox]$box) {
    return @($box.Lines | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
}

function Save-FromWindow {
    Save-Blocklist (Get-Lines $sitesBox) (Get-Lines $channelsBox) $shortsCheck.Checked
    Load-IntoWindow   # show the cleaned-up entries
    $script:saved = Get-Snapshot
}

function Get-Snapshot { return ($sitesBox.Text + '|' + $channelsBox.Text + '|' + $shortsCheck.Checked) }

function Load-IntoWindow {
    $b = Read-Blocklist
    $script:invalidLines = @($b.Invalid)
    $sitesBox.Lines    = [string[]]$b.Sites
    $channelsBox.Lines = [string[]]$b.Channels
    $shortsCheck.Checked = $b.Shorts
}

$saveBtn.Add_Click({
    try { Save-FromWindow; Show-Message 'Blocklist saved.' }
    catch { Show-Message "Could not save the blocklist:`n$_" 'Error' }
})

$linkBtn.Add_Click({
    try {
        $form.UseWaitCursor = $true
        Save-FromWindow
        $newWords = Install-Chainlink
        Update-Status
        $form.UseWaitCursor = $false
        if ($newWords) { Show-RecoveryWords $newWords }
        Show-Message "This PC is now linked to this USB.`n`nTest it: unplug the USB, wait about 10 seconds, and try opening a blocked site. Plug it back in to lift the blocks."
    } catch { Show-Message "Linking failed:`n$_" 'Error' }
    finally { $form.UseWaitCursor = $false }
})

$wordsBtn.Add_Click({
    $r = [Windows.Forms.MessageBox]::Show("Make new recovery words for this PC? The old words will stop working, so your partner will need the new ones.", 'Chainlink', 'YesNo', 'Question')
    if ($r -ne 'Yes') { return }
    try {
        $w = New-RecoveryWords
        Save-RecoveryWords $w
        Show-RecoveryWords $w
    } catch { Show-Message "Could not make new recovery words:`n$_" 'Error' }
})

$uninstallBtn.Add_Click({
    $answer = [Windows.Forms.MessageBox]::Show('Remove Chainlink and all of its blocks from this PC?', 'Chainlink', 'YesNo', 'Question')
    if ($answer -ne 'Yes') { return }
    try {
        $form.UseWaitCursor = $true
        Uninstall-Chainlink
        Update-Status
        Show-Message 'Chainlink has been removed from this PC. Your USB key still works for any other linked PCs.'
    } catch { Show-Message "Uninstall failed:`n$_" 'Error' }
    finally { $form.UseWaitCursor = $false }
})

# Offer to save unsaved edits when closing.
$script:saved = $null
$form.Add_Shown({ $script:saved = Get-Snapshot })
$form.Add_FormClosing({
    param($sender, $e)
    $now = Get-Snapshot
    if ($script:saved -ne $null -and $now -ne $script:saved) {
        $r = [Windows.Forms.MessageBox]::Show('Save your blocklist changes before closing?', 'Chainlink', 'YesNoCancel', 'Question')
        if ($r -eq 'Cancel') { $e.Cancel = $true }
        elseif ($r -eq 'Yes') { try { Save-FromWindow } catch { Show-Message "Could not save:`n$_" 'Error'; $e.Cancel = $true } }
    }
})

$script:invalidLines = @()
try { Load-IntoWindow } catch { Show-Message "Could not read blocklist.txt:`n$_" 'Warning' }
try { Update-Status } catch { Show-Message "Could not check whether this PC is linked:`n$_" 'Warning' }
if ($script:invalidLines.Count -gt 0) {
    $form.Add_Shown({
        Show-Message ("blocklist.txt has lines Chainlink cannot use. They are shown as written in the website box; fix or delete them, then save. Until then this PC keeps using the last good list.`n`n" + (($script:invalidLines | Select-Object -First 10) -join "`n")) 'Warning'
    })
}
[void]$form.ShowDialog()
