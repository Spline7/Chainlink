# Chainlink watchdog
# Runs in the background as SYSTEM (started by the "Chainlink" scheduled task).
# Every 5 seconds it looks for the paired Chainlink USB key:
#   - key NOT found -> browser blocks are ON
#   - key found     -> browser blocks are OFF, and the blocklist is synced from the USB
# This script makes no network requests and sends no telemetry.

param(
    [switch]$Unlock   # One-shot: remove every block Chainlink added, then exit. Used by uninstall.
)

$ErrorActionPreference = 'Continue'

$AppDir        = Join-Path $env:ProgramData 'Chainlink'
$PairFile      = Join-Path $AppDir 'pair.txt'
$BlocklistFile = Join-Path $AppDir 'blocklist.txt'
$LogFile       = Join-Path $AppDir 'log.txt'
$StatusFile    = Join-Path $AppDir 'status.txt'
$KeyRelPath    = 'Chainlink\chainlink.key'   # location of the key file on the USB drive

# Chromium-based browsers all read the same style of policy from the registry.
$Chromium = @(
    @{ Name = 'Chrome'; Key = 'HKLM:\SOFTWARE\Policies\Google\Chrome';       Private = 'IncognitoModeAvailability'; AddProfile = 'BrowserAddPersonEnabled' },
    @{ Name = 'Edge';   Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge';      Private = 'InPrivateModeAvailability'; AddProfile = 'BrowserAddProfileEnabled' },
    @{ Name = 'Brave';  Key = 'HKLM:\SOFTWARE\Policies\BraveSoftware\Brave'; Private = 'IncognitoModeAvailability'; AddProfile = 'BrowserAddPersonEnabled' }
)
$FirefoxKey = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'

# ---------------------------------------------------------------- helpers

function Write-Log([string]$msg) {
    try {
        if ((Test-Path $LogFile) -and (Get-Item $LogFile).Length -gt 200KB) {
            Move-Item $LogFile "$LogFile.old" -Force
        }
        Add-Content -Path $LogFile -Value ("{0}  {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $msg)
    } catch {}
}

function Set-Status([string]$s) {
    try { Set-Content -Path $StatusFile -Value $s } catch {}
}

function Get-Hash([string]$text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    $bytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text))
    return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Ensure-Key([string]$path) {
    # Note: New-Item -Force on an existing registry key would wipe it, so only create when missing.
    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
}

function Set-Dword([string]$path, [string]$name, [int]$value) {
    Ensure-Key $path
    New-ItemProperty -Path $path -Name $name -Value $value -PropertyType DWord -Force | Out-Null
}

# Reads blocklist.txt and returns clean entries like "mangadex.org" or "youtube.com/shorts".
function Get-Blocklist {
    $entries = @()
    if (-not (Test-Path $BlocklistFile)) { return $entries }
    foreach ($line in Get-Content -Path $BlocklistFile) {
        $e = $line.Trim()
        if ($e -eq '' -or $e.StartsWith('#')) { continue }
        $e = $e -replace '^[a-zA-Z]+://', ''   # drop http:// or https://
        $e = $e -replace '^\*\.', ''           # drop leading *.
        $e = $e -replace '^www\.', ''          # drop www. so every subdomain is covered
        $e = $e -replace '[/\*]+$', ''         # drop trailing / or *
        if ($e -ne '' -and $entries -notcontains $e) { $entries += $e }
    }
    return $entries
}

# Turns "youtube.com/shorts" into Firefox match patterns.
function Get-FirefoxPatterns([string]$entry) {
    $slash = $entry.IndexOf('/')
    if ($slash -lt 0) { return @("*://*.$entry/*") }
    $hostPart = $entry.Substring(0, $slash)
    $pathPart = $entry.Substring($slash)
    return @("*://*.$hostPart$pathPart", "*://*.$hostPart$pathPart/*", "*://*.${hostPart}${pathPart}?*")
}

# ---------------------------------------------------------------- key detection

# Returns the root of the drive holding a valid paired key (e.g. "D:\"), or $null.
function Find-Key {
    if (-not (Test-Path $PairFile)) { return $null }
    $expected = @(Get-Content -Path $PairFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
    if ($expected.Count -eq 0) { return $null }

    foreach ($d in [IO.DriveInfo]::GetDrives()) {
        try {
            if ($d.DriveType -eq 'Network' -or $d.DriveType -eq 'CDRom') { continue }
            if (-not $d.IsReady) { continue }
            $root = $d.RootDirectory.FullName
            $keyPath = Join-Path $root $KeyRelPath
            if (-not (Test-Path -LiteralPath $keyPath)) { continue }

            $token  = (Get-Content -LiteralPath $keyPath -Raw).Trim()
            $letter = $root.TrimEnd('\')
            $serial = (Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$letter'").VolumeSerialNumber
            if ($expected -contains (Get-Hash "$token|$serial")) { return $root }
        } catch {}
    }
    return $null
}

# Copies the blocklist from the USB to this PC when it has changed.
function Sync-Blocklist([string]$usbRoot) {
    $src = Join-Path $usbRoot 'Chainlink\blocklist.txt'
    if (-not (Test-Path -LiteralPath $src)) { return }
    $same = (Test-Path $BlocklistFile) -and
            ((Get-FileHash -LiteralPath $src).Hash -eq (Get-FileHash $BlocklistFile).Hash)
    if (-not $same) {
        Copy-Item -LiteralPath $src -Destination $BlocklistFile -Force
        Write-Log 'Blocklist updated from USB.'
    }
}

# ---------------------------------------------------------------- lock / unlock

function Set-Lock {
    $list = @(Get-Blocklist)

    foreach ($b in $Chromium) {
        Ensure-Key $b.Key
        $ul = Join-Path $b.Key 'URLBlocklist'
        if (Test-Path $ul) { Remove-Item $ul -Recurse -Force }
        New-Item -Path $ul -Force | Out-Null
        $i = 1
        foreach ($u in $list) {
            New-ItemProperty -Path $ul -Name "$i" -Value $u -PropertyType String -Force | Out-Null
            $i++
        }
        Set-Dword $b.Key $b.Private 1               # no Incognito / InPrivate windows
        Set-Dword $b.Key 'BrowserGuestModeEnabled' 0 # no guest windows
        Set-Dword $b.Key $b.AddProfile 0             # no new (policy-free) profiles
        if ($b.Name -eq 'Brave') { Set-Dword $b.Key 'TorDisabled' 1 }
    }

    # Firefox (applies the next time Firefox starts)
    Set-Dword $FirefoxKey 'DisablePrivateBrowsing' 1
    $wf = Join-Path $FirefoxKey 'WebsiteFilter'
    if (Test-Path $wf) { Remove-Item $wf -Recurse -Force }
    $block = Join-Path $wf 'Block'
    New-Item -Path $block -Force | Out-Null
    $i = 1
    foreach ($u in $list) {
        foreach ($p in (Get-FirefoxPatterns $u)) {
            New-ItemProperty -Path $block -Name "$i" -Value $p -PropertyType String -Force | Out-Null
            $i++
        }
    }
}

function Remove-Lock {
    foreach ($b in $Chromium) {
        if (-not (Test-Path $b.Key)) { continue }
        $ul = Join-Path $b.Key 'URLBlocklist'
        if (Test-Path $ul) { Remove-Item $ul -Recurse -Force }
        foreach ($name in @($b.Private, 'BrowserGuestModeEnabled', $b.AddProfile, 'TorDisabled')) {
            Remove-ItemProperty -Path $b.Key -Name $name -ErrorAction SilentlyContinue
        }
    }
    if (Test-Path $FirefoxKey) {
        Remove-ItemProperty -Path $FirefoxKey -Name 'DisablePrivateBrowsing' -ErrorAction SilentlyContinue
        $wf = Join-Path $FirefoxKey 'WebsiteFilter'
        if (Test-Path $wf) { Remove-Item $wf -Recurse -Force }
    }
}

# True if the blocks in the registry still match what they should be (catches manual tampering).
function Test-LockIntact {
    $want = (@(Get-Blocklist) -join '|')
    foreach ($b in $Chromium) {
        try {
            $p = Get-ItemProperty -Path $b.Key -ErrorAction Stop
            if ($p.($b.Private) -ne 1) { return $false }
            $ul = Join-Path $b.Key 'URLBlocklist'
            $vals = @()
            if (Test-Path $ul) {
                $item = Get-Item $ul
                $vals = @($item.GetValueNames() | Sort-Object { [int]$_ } | ForEach-Object { $item.GetValue($_) })
            }
            if (($vals -join '|') -ne $want) { return $false }
        } catch { return $false }
    }
    return $true
}

# ---------------------------------------------------------------- main

if ($Unlock) {
    Remove-Lock
    Write-Log 'All blocks removed (uninstall).'
    exit 0
}

Write-Log 'Watchdog started.'
$state = ''
$tick  = 0

while ($true) {
    try {
        $usb = Find-Key
        if ($usb) {
            if ($state -ne 'unlocked') {
                Remove-Lock
                $state = 'unlocked'
                Set-Status "UNLOCKED - key found on $usb"
                Write-Log "Key found on $usb - blocks lifted."
            }
            Sync-Blocklist $usb
        } else {
            if ($state -ne 'locked') {
                Set-Lock
                $state = 'locked'
                Set-Status 'LOCKED - key not present'
                Write-Log 'Key not present - blocks applied.'
            } elseif (($tick % 12) -eq 0 -and -not (Test-LockIntact)) {
                Set-Lock
                Write-Log 'Blocks were changed outside Chainlink - re-applied.'
            }
        }
    } catch {
        Write-Log "Error: $_"
    }
    $tick++
    Start-Sleep -Seconds 5
}
