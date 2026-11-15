# Chainlink watchdog. Runs as SYSTEM from the Chainlink scheduled task.
[CmdletBinding(DefaultParameterSetName = 'Watch')]
param(
    [Parameter(ParameterSetName = 'Unlock')][switch]$Unlock,
    [Parameter(ParameterSetName = 'Capture')][switch]$CaptureBaseline
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$AppDir        = Join-Path $env:ProgramData 'Chainlink'
$PairFile      = Join-Path $AppDir 'pair.txt'
$BlocklistFile = Join-Path $AppDir 'blocklist.txt'
$BaselineFile  = Join-Path $AppDir 'policy-baseline.json'
$LogFile       = Join-Path $AppDir 'log.txt'
$StatusFile    = Join-Path $AppDir 'status.txt'
$KeyRelPath    = 'Chainlink\chainlink.key'
$CommonModule  = Join-Path $PSScriptRoot 'Chainlink.Common.psm1'
Import-Module $CommonModule -Force

$Chromium = @(
    @{ Name = 'Chrome'; Key = 'HKLM:\SOFTWARE\Policies\Google\Chrome';       Private = 'IncognitoModeAvailability'; AddProfile = 'BrowserAddPersonEnabled' },
    @{ Name = 'Edge';   Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge';      Private = 'InPrivateModeAvailability'; AddProfile = 'BrowserAddProfileEnabled' },
    @{ Name = 'Brave';  Key = 'HKLM:\SOFTWARE\Policies\BraveSoftware\Brave'; Private = 'IncognitoModeAvailability'; AddProfile = 'BrowserAddPersonEnabled' }
)
$FirefoxKey = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'

function Write-Log {
    param([Parameter(Mandatory = $true)][string]$Message)
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

function Ensure-Key {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
}

function Set-Dword {
    param([string]$Path, [string]$Name, [int]$Value)
    Ensure-Key $Path
    New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
}

function Get-ValueSnapshot {
    param([string]$Path, [string]$Name)
    if (-not (Test-Path -LiteralPath $Path)) { return [pscustomobject]@{ Present = $false; Value = $null; Kind = $null } }
    $key = Get-Item -LiteralPath $Path
    if ($key.GetValueNames() -notcontains $Name) { return [pscustomobject]@{ Present = $false; Value = $null; Kind = $null } }
    return [pscustomobject]@{ Present = $true; Value = $key.GetValue($Name, $null, 'DoNotExpandEnvironmentNames'); Kind = $key.GetValueKind($Name).ToString() }
}

function Get-ListSnapshot {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return ,@() }
    $key = Get-Item -LiteralPath $Path
    $values = @()
    foreach ($name in $key.GetValueNames()) {
        $values += [pscustomobject]@{ Name = $name; Value = [string]$key.GetValue($name, $null, 'DoNotExpandEnvironmentNames'); Kind = $key.GetValueKind($name).ToString() }
    }
    return ,$values
}

function Save-Baseline {
    if (Test-Path -LiteralPath $BaselineFile) { return }
    $items = @{}
    foreach ($browser in $Chromium) {
        $properties = @{}
        foreach ($name in @($browser.Private, 'BrowserGuestModeEnabled', $browser.AddProfile, 'TorDisabled')) {
            $properties[$name] = Get-ValueSnapshot $browser.Key $name
        }
        $items[$browser.Name] = [pscustomobject]@{
            Properties = $properties
            Blocklist = @(Get-ListSnapshot (Join-Path $browser.Key 'URLBlocklist'))
        }
    }
    $baseline = [pscustomobject]@{
        Version = 1
        Chromium = $items
        Firefox = [pscustomobject]@{
            Properties = @{ DisablePrivateBrowsing = (Get-ValueSnapshot $FirefoxKey 'DisablePrivateBrowsing') }
            Blocklist = @(Get-ListSnapshot (Join-Path $FirefoxKey 'WebsiteFilter\Block'))
        }
    }
    Set-ChainlinkTextFileAtomic -Path $BaselineFile -Lines @(($baseline | ConvertTo-Json -Depth 8))
    Write-Log 'Captured pre-install browser policy baseline.'
}

function Read-Baseline {
    if (-not (Test-Path -LiteralPath $BaselineFile -PathType Leaf)) { return $null }
    try {
        $baseline = Get-Content -LiteralPath $BaselineFile -Raw | ConvertFrom-Json
        if ($baseline.Version -ne 1) { throw 'Unsupported baseline version.' }
        return $baseline
    } catch {
        Write-Log "Policy baseline is invalid; existing policies will be preserved: $($_.Exception.Message)"
        return $null
    }
}

function Get-Blocklist { return @(Get-ChainlinkBlocklist -Path $BlocklistFile) }

function Get-FirefoxPatterns {
    param([Parameter(Mandatory = $true)][string]$Entry)
    $slash = $Entry.IndexOf('/')
    if ($slash -lt 0) { return @("*://$Entry/*", "*://*.$Entry/*") }
    $hostPart = $Entry.Substring(0, $slash)
    $pathPart = $Entry.Substring($slash)
    return @("*://$hostPart$pathPart", "*://$hostPart$pathPart/*", "*://$hostPart$pathPart?*", "*://*.$hostPart$pathPart", "*://*.$hostPart$pathPart/*", "*://*.${hostPart}${pathPart}?*")
}

function Get-UniqueStrings {
    param([AllowEmptyCollection()][object[]]$Values)
    $result = New-Object 'System.Collections.Generic.List[string]'
    $seen = @{}
    foreach ($value in $Values) {
        $text = [string]$value
        if ($text -ne '' -and -not $seen.ContainsKey($text)) { $seen[$text] = $true; $result.Add($text) }
    }
    return ,$result.ToArray()
}

function Set-ListValues {
    param([string]$Path, [string[]]$Values)
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Recurse -Force }
    if ($Values.Count -eq 0) { return }
    New-Item -Path $Path -Force | Out-Null
    for ($i = 0; $i -lt $Values.Count; $i++) {
        New-ItemProperty -LiteralPath $Path -Name ([string]($i + 1)) -Value $Values[$i] -PropertyType String -Force | Out-Null
    }
}

function Get-BaselineListValues {
    param($Snapshot)
    if ($null -eq $Snapshot) { return ,@() }
    return ,@($Snapshot | ForEach-Object { [string]$_.Value })
}

function Restore-Property {
    param([string]$Path, [string]$Name, $Snapshot, [int]$ManagedValue)
    if ($null -eq $Snapshot) { return }
    $current = Get-ValueSnapshot $Path $Name
    if ($current.Present -and [int]$current.Value -ne $ManagedValue) { return }
    if ($Snapshot.Present) {
        Ensure-Key $Path
        New-ItemProperty -LiteralPath $Path -Name $Name -Value $Snapshot.Value -PropertyType $Snapshot.Kind -Force | Out-Null
    } elseif ($current.Present) {
        Remove-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
    }
}

function Get-UnmanagedCurrentValues {
    param([string]$Path, [string[]]$ManagedValues)
    $managed = @{}
    foreach ($value in $ManagedValues) { $managed[$value] = $true }
    return ,@(Get-ListSnapshot $Path | ForEach-Object { [string]$_.Value } | Where-Object { -not $managed.ContainsKey($_) })
}

function Set-Lock {
    $list = @(Get-Blocklist)
    $baseline = Read-Baseline
    foreach ($browser in $Chromium) {
        $urlKey = Join-Path $browser.Key 'URLBlocklist'
        $baseBrowser = if ($null -ne $baseline) { $baseline.Chromium.($browser.Name) } else { $null }
        $existing = @(Get-UnmanagedCurrentValues $urlKey $list)
        $baseValues = if ($null -ne $baseBrowser) { @(Get-BaselineListValues $baseBrowser.Blocklist) } else { @() }
        Set-ListValues $urlKey @(Get-UniqueStrings @($baseValues + $existing + $list))
        Set-Dword $browser.Key $browser.Private 1
        Set-Dword $browser.Key 'BrowserGuestModeEnabled' 0
        Set-Dword $browser.Key $browser.AddProfile 0
        if ($browser.Name -eq 'Brave') { Set-Dword $browser.Key 'TorDisabled' 1 }
    }

    $patterns = @($list | ForEach-Object { Get-FirefoxPatterns $_ })
    $firefoxBlock = Join-Path $FirefoxKey 'WebsiteFilter\Block'
    $baseFirefox = if ($null -ne $baseline) { $baseline.Firefox } else { $null }
    $existingFirefox = @(Get-UnmanagedCurrentValues $firefoxBlock $patterns)
    $baseFirefoxValues = if ($null -ne $baseFirefox) { @(Get-BaselineListValues $baseFirefox.Blocklist) } else { @() }
    Set-ListValues $firefoxBlock @(Get-UniqueStrings @($baseFirefoxValues + $existingFirefox + $patterns))
    Set-Dword $FirefoxKey 'DisablePrivateBrowsing' 1
}

function Remove-Lock {
    $list = @(Get-Blocklist)
    $baseline = Read-Baseline
    foreach ($browser in $Chromium) {
        $urlKey = Join-Path $browser.Key 'URLBlocklist'
        $remaining = @(Get-UnmanagedCurrentValues $urlKey $list)
        $baseBrowser = if ($null -ne $baseline) { $baseline.Chromium.($browser.Name) } else { $null }
        if ($null -ne $baseBrowser) { $remaining = @(Get-UniqueStrings @((Get-BaselineListValues $baseBrowser.Blocklist) + $remaining)) }
        Set-ListValues $urlKey $remaining
        if ($null -ne $baseBrowser) {
            Restore-Property $browser.Key $browser.Private $baseBrowser.Properties.($browser.Private) 1
            Restore-Property $browser.Key 'BrowserGuestModeEnabled' $baseBrowser.Properties.BrowserGuestModeEnabled 0
            Restore-Property $browser.Key $browser.AddProfile $baseBrowser.Properties.($browser.AddProfile) 0
            if ($browser.Name -eq 'Brave') { Restore-Property $browser.Key 'TorDisabled' $baseBrowser.Properties.TorDisabled 1 }
        }
    }

    $patterns = @($list | ForEach-Object { Get-FirefoxPatterns $_ })
    $firefoxBlock = Join-Path $FirefoxKey 'WebsiteFilter\Block'
    $remainingFirefox = @(Get-UnmanagedCurrentValues $firefoxBlock $patterns)
    if ($null -ne $baseline) { $remainingFirefox = @(Get-UniqueStrings @((Get-BaselineListValues $baseline.Firefox.Blocklist) + $remainingFirefox)) }
    Set-ListValues $firefoxBlock $remainingFirefox
    if ($null -ne $baseline) { Restore-Property $FirefoxKey 'DisablePrivateBrowsing' $baseline.Firefox.Properties.DisablePrivateBrowsing 1 }
}

function Test-LockIntact {
    $list = @(Get-Blocklist)
    foreach ($browser in $Chromium) {
        try {
            $policy = Get-ItemProperty -LiteralPath $browser.Key -ErrorAction Stop
            if ($policy.($browser.Private) -ne 1 -or $policy.BrowserGuestModeEnabled -ne 0 -or $policy.($browser.AddProfile) -ne 0) { return $false }
            if ($browser.Name -eq 'Brave' -and $policy.TorDisabled -ne 1) { return $false }
            $actual = @(Get-ListSnapshot (Join-Path $browser.Key 'URLBlocklist') | ForEach-Object { [string]$_.Value })
            foreach ($entry in $list) { if ($actual -notcontains $entry) { return $false } }
        } catch { return $false }
    }
    return $true
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
    $token = (Get-Content -LiteralPath $Path -Raw -ErrorAction Stop).Trim()
    try { $bytes = [Convert]::FromBase64String($token) } catch { return $null }
    if ($bytes.Length -ne 32) { return $null }
    return $token
}

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
        } catch { Write-Log "Could not inspect drive $($drive.Name): $($_.Exception.Message)" }
    }
    return $null
}

function Sync-Blocklist {
    param([Parameter(Mandatory = $true)][string]$UsbRoot)
    $source = Join-Path $UsbRoot 'Chainlink\blocklist.txt'
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw 'The paired USB is missing blocklist.txt.' }
    [void](Get-ChainlinkBlocklist -Path $source)
    $same = (Test-Path -LiteralPath $BlocklistFile -PathType Leaf) -and ((Get-FileHash -LiteralPath $source).Hash -eq (Get-FileHash -LiteralPath $BlocklistFile).Hash)
    if (-not $same) {
        $temporary = Join-Path $AppDir ('.blocklist-{0}.tmp' -f [Guid]::NewGuid().ToString('N'))
        try {
            Copy-Item -LiteralPath $source -Destination $temporary -Force
            Move-Item -LiteralPath $temporary -Destination $BlocklistFile -Force
        } finally { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
        Write-Log 'Blocklist updated from USB.'
    }
}

if ($CaptureBaseline) { Save-Baseline; exit 0 }
if ($Unlock) { Remove-Lock; Write-Log 'Chainlink browser policies removed and prior policies restored.'; exit 0 }

$created = $false
$mutex = New-Object Threading.Mutex($true, 'Global\ChainlinkWatchdog', [ref]$created)
if (-not $created) { Write-Log 'A watchdog instance is already running; exiting duplicate.'; $mutex.Dispose(); exit 0 }

try {
    Write-Log 'Watchdog started.'
    $state = ''
    $tick = 0
    while ($true) {
        try {
            $usb = Find-Key
            if ($usb) {
                Sync-Blocklist $usb
                if ($state -ne 'unlocked') {
                    Remove-Lock
                    $state = 'unlocked'
                    Set-Status "UNLOCKED - key found on $usb"
                    Write-Log "Key found on $usb - blocks lifted."
                }
            } elseif ($state -ne 'locked' -or (($tick % 12) -eq 0 -and -not (Test-LockIntact))) {
                Set-Lock
                if ($state -eq 'locked') { Write-Log 'Blocks were changed outside Chainlink - re-applied.' }
                else { Write-Log 'Key not present - blocks applied.' }
                $state = 'locked'
                Set-Status 'LOCKED - key not present'
            }
        } catch {
            Write-Log "Watchdog cycle failed: $($_.Exception.Message)"
            try { Set-Lock; $state = 'locked'; Set-Status 'LOCKED - fail-safe after an error' }
            catch { Write-Log "Fail-safe lock also failed: $($_.Exception.Message)" }
        }
        $tick++
        Start-Sleep -Seconds 5
    }
} finally {
    try { $mutex.ReleaseMutex() } catch { }
    $mutex.Dispose()
}
