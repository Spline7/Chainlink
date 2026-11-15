# Chainlink - settings window
# Started by double-clicking Chainlink.cmd on the USB drive (which asks for admin rights).
# Lets you edit the blocklist, link this PC to the USB key, or uninstall Chainlink.
# This script makes no network requests and sends no telemetry.

param(
    [switch]$Emergency   # Uninstall without the USB key (for a lost or broken key). Run from an admin PowerShell.
)

$ErrorActionPreference = 'Stop'

$UsbDir        = $PSScriptRoot                                  # e.g. D:\Chainlink
$UsbRoot       = (Split-Path -Path $UsbDir -Qualifier) + '\'    # e.g. D:\
$KeyFile       = Join-Path $UsbDir 'chainlink.key'
$BlocklistPath = Join-Path $UsbDir 'blocklist.txt'
$AppDir        = Join-Path $env:ProgramData 'Chainlink'
$PairFile      = Join-Path $AppDir 'pair.txt'
$TaskName      = 'Chainlink'
$ShortsEntry   = 'youtube.com/shorts'

# ================================================================ helpers

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-Hash([string]$text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    $bytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text))
    return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Get-UsbHash {
    if (-not (Test-Path -LiteralPath $KeyFile)) { return $null }
    $token  = (Get-Content -LiteralPath $KeyFile -Raw).Trim()
    $letter = $UsbRoot.TrimEnd('\')
    $serial = (Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$letter'").VolumeSerialNumber
    return Get-Hash "$token|$serial"
}

function Test-Installed { return [bool](Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) }

function Test-UsbMatchesPc {
    if (-not (Test-Path $PairFile)) { return $false }
    $h = Get-UsbHash
    if (-not $h) { return $false }
    return (@(Get-Content $PairFile | ForEach-Object { $_.Trim() }) -contains $h)
}

# ================================================================ blocklist file <-> window

# Cleans a website entry: "https://www.MangaDex.org/" -> "mangadex.org"
function Format-Site([string]$s) {
    $s = $s.Trim() -replace '^[a-zA-Z]+://', '' -replace '^www\.', '' -replace '/+$', ''
    $slash = $s.IndexOf('/')
    if ($slash -lt 0) { return $s.ToLower() }
    return $s.Substring(0, $slash).ToLower() + $s.Substring($slash)
}

# Cleans a channel entry. Accepts "@Name", "Name", or any link to the channel.
# Returns "youtube.com/@Name" or "youtube.com/channel/UC...".
function Format-Channel([string]$s) {
    $s = $s.Trim() -replace '^[a-zA-Z]+://', '' -replace '^(www\.|m\.)', ''
    if ($s -eq '') { return '' }
    if ($s -match '^youtube\.com/(@[^/?#\s]+)')             { return "youtube.com/$($Matches[1])" }
    if ($s -match '^youtube\.com/(channel|c|user)/([^/?#\s]+)') { return "youtube.com/$($Matches[1])/$($Matches[2])" }
    if ($s -match '^(channel|c|user)/([^/?#\s]+)')           { return "youtube.com/$($Matches[1])/$($Matches[2])" }
    if ($s -match '^@?([^/?#\s]+)$')                          { return "youtube.com/@$($Matches[1])" }
    return $s
}

# Splits blocklist.txt into websites, channels, and the Shorts on/off switch.
function Read-Blocklist {
    $sites = @(); $channels = @(); $shorts = $false
    if (Test-Path -LiteralPath $BlocklistPath) {
        foreach ($line in Get-Content -LiteralPath $BlocklistPath) {
            $e = $line.Trim()
            if ($e -eq '' -or $e.StartsWith('#')) { continue }
            $e = Format-Site $e
            if ($e -ieq $ShortsEntry) { $shorts = $true }
            elseif ($e -match '^youtube\.com/(@|channel/|c/|user/)') { $channels += ($e -replace '^youtube\.com/', '') }
            else { $sites += $e }
        }
    }
    return @{ Sites = $sites; Channels = $channels; Shorts = $shorts }
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
    Set-Content -LiteralPath $BlocklistPath -Value $out
}

# ================================================================ link / uninstall

function Install-Chainlink {
    # 1. Create the secret key file on the USB the first time (reused for every PC you link).
    if (-not (Test-Path -LiteralPath $KeyFile)) {
        $bytes = New-Object byte[] 32
        [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
        Set-Content -LiteralPath $KeyFile -Value ([Convert]::ToBase64String($bytes)) -NoNewline
        $kf = Get-Item -LiteralPath $KeyFile -Force
        $kf.Attributes = $kf.Attributes -bor [IO.FileAttributes]::Hidden
    }

    # 2. Program folder that only SYSTEM and Administrators can change.
    if (-not (Test-Path $AppDir)) { New-Item -ItemType Directory -Path $AppDir | Out-Null }
    & icacls.exe $AppDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null

    # 3. Remember this USB (only a hash is stored, never the key itself).
    $hash = Get-UsbHash
    $known = @()
    if (Test-Path $PairFile) { $known = @(Get-Content $PairFile | ForEach-Object { $_.Trim() }) }
    if ($known -notcontains $hash) { Add-Content -Path $PairFile -Value $hash }

    # 4. Copy the background watchdog and the blocklist to this PC.
    Copy-Item -LiteralPath (Join-Path $UsbDir 'watchdog.ps1') -Destination $AppDir -Force
    Copy-Item -LiteralPath $BlocklistPath -Destination $AppDir -Force
    Get-ChildItem $AppDir -File | Unblock-File -ErrorAction SilentlyContinue

    # 5. Scheduled task: starts at boot, and every minute makes sure it is still running.
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$AppDir\watchdog.ps1`""
    $atBoot = New-ScheduledTaskTrigger -AtStartup
    $every  = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)
    $who    = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $set    = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
                -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew `
                -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $atBoot, $every -Principal $who -Settings $set `
        -Description 'Chainlink: blocks distracting websites unless the paired USB key is plugged in.' -Force | Out-Null
    Start-ScheduledTask -TaskName $TaskName
}

function Uninstall-Chainlink {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
        Where-Object { $_.CommandLine -like '*Chainlink\watchdog.ps1*' } |
        ForEach-Object { Invoke-CimMethod -InputObject $_ -MethodName Terminate | Out-Null }

    # Remove every browser block using the watchdog's own unlock routine.
    $wd = Join-Path $UsbDir 'watchdog.ps1'
    if (-not (Test-Path $wd)) { $wd = Join-Path $AppDir 'watchdog.ps1' }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $wd -Unlock

    if (Test-Path $AppDir) { Remove-Item $AppDir -Recurse -Force }
}

# ================================================================ emergency (console only)

if ($Emergency) {
    if (-not (Test-Admin)) { Write-Host 'Run this from PowerShell opened with "Run as administrator".' -ForegroundColor Red; exit 1 }
    Write-Host 'EMERGENCY UNINSTALL: removing Chainlink without the USB key.' -ForegroundColor Yellow
    if ((Read-Host 'Type UNINSTALL to continue') -ceq 'UNINSTALL') {
        Uninstall-Chainlink
        Write-Host 'Chainlink has been removed from this PC.' -ForegroundColor Green
    } else { Write-Host 'Cancelled.' }
    exit 0
}

# ================================================================ window

Add-Type -AssemblyName System.Windows.Forms, System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()

function Show-Message([string]$text, [string]$icon = 'Information') {
    [void][Windows.Forms.MessageBox]::Show($text, 'Chainlink', 'OK', $icon)
}

if (-not (Test-Admin)) {
    Show-Message 'Chainlink needs administrator rights. Please start it by double-clicking Chainlink.cmd.' 'Error'
    exit 1
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
$form.AcceptButton = $null   # Enter adds a new line in the boxes instead of clicking a button

function Update-Status {
    if (-not (Test-Installed)) {
        $status.Text = 'This PC is not linked yet. Click "Link this PC" to start.'
        $status.ForeColor = $grey
        $linkBtn.Enabled = $true; $uninstallBtn.Enabled = $false
    } elseif (Test-UsbMatchesPc) {
        $status.Text = 'This PC is linked to this USB. Blocks are OFF while it is plugged in.'
        $status.ForeColor = [Drawing.Color]::FromArgb(20, 130, 60)
        $linkBtn.Enabled = $false; $uninstallBtn.Enabled = $true
    } else {
        $status.Text = 'This PC is linked to a different USB key.'
        $status.ForeColor = [Drawing.Color]::FromArgb(190, 60, 30)
        $linkBtn.Enabled = $false; $uninstallBtn.Enabled = $false
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
        Install-Chainlink
        Update-Status
        Show-Message "This PC is now linked to this USB.`n`nTest it: unplug the USB, wait about 10 seconds, and try opening a blocked site. Plug it back in to lift the blocks."
    } catch { Show-Message "Linking failed:`n$_" 'Error' }
    finally { $form.UseWaitCursor = $false }
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

try { Load-IntoWindow } catch { Show-Message "Could not read blocklist.txt:`n$_" 'Warning' }
Update-Status
[void]$form.ShowDialog()
