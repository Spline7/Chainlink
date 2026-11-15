# Chainlink watchdog. Runs as SYSTEM from the Chainlink scheduled task.
# Every 5 seconds it looks for the paired Chainlink USB key:
#   - key NOT found -> browser blocks are ON
#   - key found     -> browser blocks are OFF, and the blocklist is synced from the USB
# This script makes no network requests and sends no telemetry.
[CmdletBinding(DefaultParameterSetName = 'Watch')]
param(
    [Parameter(ParameterSetName = 'Unlock')][switch]$Unlock,
    [Parameter(ParameterSetName = 'Capture')][switch]$CaptureBaseline
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$ProgramData   = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
if ([string]::IsNullOrWhiteSpace($ProgramData)) { throw 'Windows did not provide the ProgramData directory.' }
$AppDir        = Join-Path $ProgramData 'Chainlink'
$PairFile      = Join-Path $AppDir 'pair.txt'
$BlocklistFile = Join-Path $AppDir 'blocklist.txt'
$AppliedFile   = Join-Path $AppDir 'applied-blocklist.txt'
$BaselineFile  = Join-Path $AppDir 'policy-baseline.json'
$LockFile      = Join-Path $AppDir 'watchdog.lock'
$LogFile       = Join-Path $AppDir 'log.txt'
$StatusFile    = Join-Path $AppDir 'status.txt'
$KeyRelPath    = 'Chainlink\chainlink.key'
$PolicyRoot    = 'HKLM:\SOFTWARE\Policies'
$MaxUsbBlocklistBytes = 1MB
$CommonModule  = Join-Path $PSScriptRoot 'Chainlink.Common.psm1'
Import-Module $CommonModule -Force

$script:LastLogMessage = ''

function Write-Log {
    param([Parameter(Mandatory = $true)][string]$Message, [switch]$Once)
    # -Once: a fault that repeats every cycle is logged once, not every five seconds.
    if ($Once -and $Message -eq $script:LastLogMessage) { return }
    $script:LastLogMessage = $Message
    try {
        if ((Test-Path -LiteralPath $LogFile) -and (Get-Item -LiteralPath $LogFile).Length -gt 200KB) {
            Move-Item -LiteralPath $LogFile -Destination "$LogFile.old" -Force
        }
        Add-Content -LiteralPath $LogFile -Value ('{0}  {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message) -Encoding UTF8
    } catch { }
}

function Set-Status {
    param([Parameter(Mandatory = $true)][string]$Status)
    try { Set-ChainlinkTextFileAtomic -Path $StatusFile -Lines @($Status) } catch { }
}

function Save-Baseline {
    if (Test-Path -LiteralPath $BaselineFile) { return }
    $baseline = Get-ChainlinkPolicyBaseline -Root $PolicyRoot
    Set-ChainlinkTextFileAtomic -Path $BaselineFile -Lines @(($baseline | ConvertTo-Json -Depth 8))
    Write-Log 'Captured pre-install browser policy baseline.'
}

function Read-Baseline {
    if (-not (Test-Path -LiteralPath $BaselineFile -PathType Leaf)) { return $null }
    try {
        $baseline = Get-Content -LiteralPath $BaselineFile -Raw | ConvertFrom-Json
        if (-not (Test-ChainlinkPolicyBaseline $baseline)) { throw 'unsupported or incomplete baseline' }
        return $baseline
    } catch {
        Write-Log "Policy baseline is unreadable; Chainlink will remove only its own values: $($_.Exception.Message)" -Once
        return $null
    }
}

# The installed blocklist, or "*" (block everything) when it is missing or corrupt.
function Get-Blocklist {
    try {
        if (-not (Test-Path -LiteralPath $BlocklistFile -PathType Leaf)) { throw 'Installed blocklist is missing.' }
        return @(Get-ChainlinkBlocklist -Path $BlocklistFile)
    } catch {
        Write-Log "Installed blocklist is invalid; blocking all URLs as a fail-safe: $($_.Exception.Message)" -Once
        return @('*')
    }
}

# The entries the last lock wrote. Unlock removes exactly these, even if blocklist.txt has
# changed or been damaged since.
function Read-AppliedEntries {
    if (-not (Test-Path -LiteralPath $AppliedFile -PathType Leaf)) { return }
    foreach ($line in [IO.File]::ReadAllLines($AppliedFile)) {
        if ($line -ne '' -and $line.Length -le 4096) { $line }
    }
}

function Set-Lock {
    $list = @(Get-Blocklist)
    $previous = @(Read-AppliedEntries)
    # Record the entries before writing them, so an interrupted lock can still be undone.
    Set-ChainlinkTextFileAtomic -Path $AppliedFile -Lines @(Merge-ChainlinkValues $previous $list)
    Set-ChainlinkPolicyLock -Root $PolicyRoot -Entries $list -PreviousEntries $previous -Baseline (Read-Baseline)
    Set-ChainlinkTextFileAtomic -Path $AppliedFile -Lines $list
}

function Remove-Lock {
    $managed = @(Merge-ChainlinkValues @(Read-AppliedEntries) @(Get-Blocklist))
    Remove-ChainlinkPolicyLock -Root $PolicyRoot -Entries $managed -Baseline (Read-Baseline)
    if (Test-Path -LiteralPath $AppliedFile) { Remove-Item -LiteralPath $AppliedFile -Force }
}

function Test-LockIntact {
    return (Test-ChainlinkPolicyLock -Root $PolicyRoot -Entries @(Get-Blocklist))
}

function Get-VolumeSerial {
    param([Parameter(Mandatory = $true)][string]$Root)
    $deviceId = $Root.TrimEnd('\')
    if ($deviceId -notmatch '^[A-Za-z]:$') { return $null }
    $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$deviceId'" -ErrorAction Stop
    return [string]$disk.VolumeSerialNumber
}

function Read-KeyToken {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ((Get-Item -LiteralPath $Path -Force).Length -gt 1024) { return $null }
    $token = (Get-Content -LiteralPath $Path -Raw -ErrorAction Stop).Trim()
    try { $bytes = [Convert]::FromBase64String($token) } catch { return $null }
    if ($bytes.Length -ne 32) { return $null }
    return $token
}

# Returns the root of the drive holding a valid paired key (e.g. "D:\"), or $null.
function Find-Key {
    if (-not (Test-Path -LiteralPath $PairFile -PathType Leaf)) { return $null }
    $expected = @(Get-Content -LiteralPath $PairFile | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ -match '^[a-f0-9]{64}$' })
    if ($expected.Count -eq 0) { return $null }
    foreach ($drive in [IO.DriveInfo]::GetDrives()) {
        try {
            if ($drive.DriveType -notin @([IO.DriveType]::Removable, [IO.DriveType]::Fixed)) { continue }
            if (-not $drive.IsReady) { continue }
            $root = $drive.RootDirectory.FullName
            $keyPath = Join-Path $root $KeyRelPath
            if (-not (Test-Path -LiteralPath $keyPath -PathType Leaf)) { continue }
            $token = Read-KeyToken $keyPath
            $serial = Get-VolumeSerial $root
            if ($null -eq $token -or [string]::IsNullOrWhiteSpace($serial)) { continue }
            if ($expected -contains (Get-ChainlinkSha256Hex "$token|$serial")) { return $root }
        } catch { Write-Log "Could not inspect drive $($drive.Name): $($_.Exception.Message)" -Once }
    }
    return $null
}

# Copies the blocklist from the USB when it has changed and is valid. Returns '' on success, or
# a short description of what is wrong with the USB copy. A bad USB blocklist never prevents
# the key from unlocking this PC; the previously installed list simply stays in force.
function Sync-Blocklist {
    param([Parameter(Mandatory = $true)][string]$UsbRoot)
    $source = Join-Path $UsbRoot 'Chainlink\blocklist.txt'
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { return 'the USB has no Chainlink\blocklist.txt' }
    if ((Get-Item -LiteralPath $source -Force).Length -gt $MaxUsbBlocklistBytes) { return 'blocklist.txt on the USB is too large' }

    $installed = Test-Path -LiteralPath $BlocklistFile -PathType Leaf
    if ($installed -and ((Get-FileHash -LiteralPath $source).Hash -eq (Get-FileHash -LiteralPath $BlocklistFile).Hash)) { return '' }

    # Validate the same bytes that get installed: copy first, check the copy, then swap it in.
    $temporary = Join-Path $AppDir ('.blocklist-{0}.tmp' -f [Guid]::NewGuid().ToString('N'))
    try {
        Copy-Item -LiteralPath $source -Destination $temporary -Force
        try { [void]@(Get-ChainlinkBlocklist -Path $temporary) }
        catch { return "blocklist.txt on the USB has a problem: $($_.Exception.Message)" }
        Move-Item -LiteralPath $temporary -Destination $BlocklistFile -Force
    } finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
    }
    Write-Log 'Blocklist updated from USB.'
    return ''
}

$script:State = ''        # '', 'locked', or 'unlocked'
$script:UsbProblem = ''
$script:Tick = 0

# One pass of the watchdog loop.
function Invoke-WatchdogCycle {
    $usb = $null
    try {
        $usb = Find-Key
        if ($usb) {
            if ($script:State -ne 'unlocked') {
                Remove-Lock
                $script:State = 'unlocked'
                $script:UsbProblem = ''
                Set-Status "UNLOCKED - key found on $usb"
                Write-Log "Key found on $usb - blocks lifted."
            }
            $problem = Sync-Blocklist $usb
            if ($problem -ne $script:UsbProblem) {
                $script:UsbProblem = $problem
                if ($problem) {
                    Set-Status "UNLOCKED - key found on $usb. The previous blocklist is still in use: $problem"
                    Write-Log "Blocklist not updated: $problem"
                } else { Set-Status "UNLOCKED - key found on $usb" }
            }
        } elseif ($script:State -ne 'locked' -or (($script:Tick % 12) -eq 0 -and -not (Test-LockIntact))) {
            Set-Lock
            if ($script:State -eq 'locked') { Write-Log 'Blocks were changed outside Chainlink - re-applied.' }
            else { Write-Log 'Key not present - blocks applied.' }
            $script:State = 'locked'
            Set-Status 'LOCKED - key not present'
        }
    } catch {
        Write-Log "Watchdog cycle failed: $($_.Exception.Message)" -Once
        # With the key present there is nothing to enforce; the unlock is retried next cycle.
        # Without it, make sure the blocks are on.
        $script:State = ''
        if (-not $usb) {
            try { Set-Lock; $script:State = 'locked'; Set-Status 'LOCKED - fail-safe after an error' }
            catch { Write-Log "Fail-safe lock also failed: $($_.Exception.Message)" -Once }
        }
    }
    $script:Tick++
}

# Dot-sourcing this file (as the tests do) defines the functions above without running anything.
if ($MyInvocation.InvocationName -eq '.') { return }

if ($CaptureBaseline) { Save-Baseline; exit 0 }
if ($Unlock) { Remove-Lock; Write-Log 'Chainlink browser policies removed and prior policies restored.'; exit 0 }

if (-not (Test-Path -LiteralPath $AppDir -PathType Container)) { exit 0 }   # uninstalled
$lock = Open-ChainlinkWatchdogLock -Path $LockFile
if ($null -eq $lock) { exit 0 }   # another watchdog, or an install or uninstall, holds the lock

try {
    Write-Log 'Watchdog started.'
    while ($true) {
        Invoke-WatchdogCycle
        Start-Sleep -Seconds 5
    }
} finally {
    $lock.Dispose()
}
