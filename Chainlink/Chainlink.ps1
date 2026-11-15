# Chainlink - settings window
# Started by double-clicking Chainlink.cmd on the USB drive (which asks for admin rights).
# Lets you edit the blocklist, link this PC to the USB key, or uninstall Chainlink.
# This script makes no network requests and sends no telemetry.

param(
    [switch]$Emergency   # Uninstall without the USB key, using your accountability partner's recovery words.
)

$ErrorActionPreference = 'Stop'
$PowerShellExe = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName

# Ask for admin rights if we don't have them yet (e.g. when started from the Start menu shortcut).
$me = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
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
$AppDir        = Join-Path $ProgramData 'Chainlink'
$PairFile      = Join-Path $AppDir 'pair.txt'
$TaskName      = 'Chainlink'
$TaskPath      = '\'
$ShortsEntry   = 'youtube.com/shorts'
$RecoveryFile  = Join-Path $AppDir 'recovery.txt'
$RecoveryAttemptsFile = Join-Path $AppDir 'recovery-attempts.txt'
$ShortcutPath  = Join-Path $ProgramData 'Microsoft\Windows\Start Menu\Programs\Chainlink Emergency Uninstall.lnk'
$WordCount     = 6
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

function Test-ChainlinkTask {
    $tasks = @(Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue)
    foreach ($task in $tasks) {
        if (Test-ChainlinkScheduledTaskObject -Task $task -PowerShellExe $PowerShellExe -WatchdogPath (Join-Path $AppDir 'watchdog.ps1')) { return $true }
    }
    return $false
}

function Test-Installed {
    return (Test-ChainlinkTask) -or (Test-Path -LiteralPath (Join-Path $AppDir 'watchdog.ps1') -PathType Leaf)
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

function Install-Chainlink {
    $hasExistingChainlinkTask = Test-ChainlinkTask
    $namedTasks = @(Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue)
    if ($namedTasks.Count -gt 0 -and -not $hasExistingChainlinkTask) {
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

    # 2. Program folder that only SYSTEM and Administrators can change.
    if (Test-Path -LiteralPath $AppDir) {
        $appItem = Get-Item -LiteralPath $AppDir -Force
        if (-not $appItem.PSIsContainer -or ($appItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "$AppDir must be a real directory, not a file, junction, or symbolic link."
        }
        if (-not $hasExistingChainlinkTask -and @(Get-ChildItem -LiteralPath $AppDir -Force).Count -gt 0) {
            throw "$AppDir already contains files but no genuine Chainlink scheduled task exists. Move that directory aside before linking so untrusted files cannot be executed as Administrator."
        }
    } else { New-Item -ItemType Directory -Path $AppDir | Out-Null }
    & icacls.exe $AppDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not secure the Chainlink program directory.' }
    & icacls.exe $AppDir /remove:g '*S-1-5-32-545' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not remove ordinary-user access from the Chainlink program directory.' }

    # Stop and unlock the old copy before replacing its blocklist or watchdog.
    Stop-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
    $installedWatchdog = Join-Path $AppDir 'watchdog.ps1'
    $baselinePath = Join-Path $AppDir 'policy-baseline.json'
    if ($hasExistingChainlinkTask) {
        if (-not (Test-Path -LiteralPath $installedWatchdog -PathType Leaf)) {
            throw 'The existing Chainlink task has no installed watchdog; installation was stopped.'
        }
        & $PowerShellExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $installedWatchdog -Unlock
        if ($LASTEXITCODE -ne 0) { throw 'Could not prepare the existing installation for upgrade.' }
    }

    Copy-Item -LiteralPath (Join-Path $UsbDir 'Chainlink.Common.psm1') -Destination $AppDir -Force
    Copy-Item -LiteralPath (Join-Path $UsbDir 'watchdog.ps1') -Destination $AppDir -Force
    if (-not (Test-Path -LiteralPath $baselinePath)) {
        & $PowerShellExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $AppDir 'watchdog.ps1') -CaptureBaseline
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $baselinePath)) {
            throw 'Could not save the existing browser policies; installation was stopped to avoid overwriting them.'
        }
    }

    # 3. Remember this USB (only a hash is stored, never the key itself).
    $hash = Get-UsbHash
    $known = @()
    if (-not $hash) { throw 'Could not validate the USB key and volume serial number.' }
    if (Test-Path -LiteralPath $PairFile) { $known = @(Get-Content -LiteralPath $PairFile | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ -match '^[a-f0-9]{64}$' }) }
    if ($known -notcontains $hash) { $known += $hash }
    Set-ChainlinkTextFileAtomic -Path $PairFile -Lines @($known | Select-Object -Unique)

    # 4. Copy the background watchdog, the blocklist, and this program (for emergency uninstall) to this PC.
    Copy-Item -LiteralPath $BlocklistPath -Destination $AppDir -Force
    if ($PSCommandPath -ne (Join-Path $AppDir 'Chainlink.ps1')) {
        Copy-Item -LiteralPath $PSCommandPath -Destination $AppDir -Force
    }
    Get-ChildItem $AppDir -File | Unblock-File -ErrorAction SilentlyContinue

    $newRecoveryWords = $null
    if (-not (Test-Path $RecoveryFile)) {
        $newRecoveryWords = New-RecoveryWords
        Save-RecoveryWords $newRecoveryWords
    }

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

    # 5. Scheduled task: starts at boot, and every minute makes sure it is still running.
    $action = New-ScheduledTaskAction -Execute $PowerShellExe `
        -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$AppDir\watchdog.ps1`""
    $atBoot = New-ScheduledTaskTrigger -AtStartup
    $every  = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)
    $who    = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $set    = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
                -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew `
                -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Action $action -Trigger $atBoot, $every -Principal $who -Settings $set `
        -Description 'Chainlink: blocks distracting websites unless the paired USB key is plugged in.' -Force | Out-Null
    Start-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath

    return $newRecoveryWords
}

function Uninstall-Chainlink {
    Stop-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
    Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
        Where-Object { $_.CommandLine -like '*Chainlink\watchdog.ps1*' } |
        ForEach-Object { Invoke-CimMethod -InputObject $_ -MethodName Terminate | Out-Null }

    # Remove every browser block using the watchdog's own unlock routine.
    $wd = Join-Path $AppDir 'watchdog.ps1'
    if (-not (Test-Path -LiteralPath $wd)) { $wd = Join-Path $UsbDir 'watchdog.ps1' }
    if (-not (Test-Path -LiteralPath $wd)) { throw 'The installed watchdog is missing; browser policies were not changed.' }
    & $PowerShellExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $wd -Unlock
    if ($LASTEXITCODE -ne 0) { throw 'Could not restore browser policies; Chainlink files were left in place for recovery.' }

    if (Test-ChainlinkTask) {
        Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $ShortcutPath) { Remove-Item -LiteralPath $ShortcutPath -Force }
    if (Test-Path -LiteralPath $AppDir) { Remove-Item -LiteralPath $AppDir -Recurse -Force }
}

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

try { Load-IntoWindow } catch { Show-Message "Could not read blocklist.txt:`n$_" 'Warning' }
Update-Status
[void]$form.ShowDialog()
