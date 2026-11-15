Set-StrictMode -Version 2.0

$script:MaximumEntryLength = 2048
$script:MaximumBlocklistEntries = 2048

function Get-ChainlinkSha256Hex {
    param([Parameter(Mandatory = $true)][string]$Text)

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))
        return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally {
        $sha.Dispose()
    }
}

function Test-ChainlinkFixedTimeEqual {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Left,
        [Parameter(Mandatory = $true)][byte[]]$Right
    )

    if ($Left.Length -ne $Right.Length) { return $false }
    $difference = 0
    for ($i = 0; $i -lt $Left.Length; $i++) {
        $difference = $difference -bor ($Left[$i] -bxor $Right[$i])
    }
    return ($difference -eq 0)
}

function ConvertTo-ChainlinkEntry {
    param([AllowEmptyString()][string]$Value)

    $value = $Value.Trim()
    if ($value -eq '') { return '' }
    if ($value.Length -gt $script:MaximumEntryLength) {
        throw "Blocklist entries must be $($script:MaximumEntryLength) characters or fewer."
    }
    if ($value -match '[\x00-\x20\x7f]') {
        throw "Blocklist entries cannot contain whitespace or control characters: $Value"
    }
    # "example.com:8080" is a host and port; "mailto:someone" or "file:///C:/" is another scheme.
    if ($value -match '^([a-zA-Z][a-zA-Z0-9+.-]*)://') {
        if ($Matches[1] -notin @('http', 'https')) { throw "Only http:// and https:// URLs are supported: $Value" }
    } elseif ($value -match '^[a-zA-Z][a-zA-Z0-9+.-]*:' -and $value -notmatch '^[^:/]+:[0-9]{1,5}(/|$)') {
        throw "Only http:// and https:// URLs are supported: $Value"
    }

    # The original release accepted "*.example.com" and "example.com/*"; both mean the plain entry.
    $scheme = ''
    $rest = $value
    if ($value -match '^([a-zA-Z][a-zA-Z0-9+.-]*://)(.*)$') { $scheme = $Matches[1]; $rest = $Matches[2] }
    $rest = ($rest -replace '^\*\.', '') -replace '[/*]+$', ''
    if ($rest -eq '') { throw "Invalid website or URL: $Value" }

    $candidate = "$scheme$rest"
    if ($scheme -eq '') { $candidate = "https://$rest" }
    try { $uri = New-Object Uri($candidate, [UriKind]::Absolute) }
    catch { throw "Invalid website or URL: $Value" }

    if ($uri.Scheme -notin @('http', 'https') -or [string]::IsNullOrWhiteSpace($uri.Host)) {
        throw "Invalid website or URL: $Value"
    }
    if ($uri.UserInfo) { throw "URLs containing a username or password are not supported: $Value" }
    if ($uri.Query -or $uri.Fragment) {
        throw "Query strings and fragments are not supported in blocklist entries: $Value"
    }

    $hostName = $uri.IdnHost.TrimEnd('.').ToLowerInvariant()
    if ($uri.HostNameType -eq [UriHostNameType]::IPv6) {
        $hostName = '[' + [Net.IPAddress]::Parse($uri.Host.Trim('[', ']')).ToString() + ']'
    } elseif ($hostName.StartsWith('www.')) { $hostName = $hostName.Substring(4) }
    if ($uri.HostNameType -ne [UriHostNameType]::IPv6 -and $hostName -notmatch '^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$') {
        throw "Invalid website hostname: $Value"
    }

    $port = ''
    if (-not $uri.IsDefaultPort) { $port = ":$($uri.Port)" }
    $path = $uri.AbsolutePath.TrimEnd('/')
    if ($path -eq '/') { $path = '' }
    return "$hostName$port$path"
}

function ConvertTo-ChainlinkChannel {
    param([AllowEmptyString()][string]$Value)

    $value = $Value.Trim()
    if ($value -eq '') { return '' }
    if ($value -match '^@?([a-zA-Z0-9._-]{1,100})$') { return "youtube.com/@$($Matches[1])" }

    $entry = ConvertTo-ChainlinkEntry $value
    $entry = $entry -replace '^m\.youtube\.com/', 'youtube.com/'
    if ($entry -match '^youtube\.com/(@[a-zA-Z0-9._-]{1,100})(?:/(?:videos|shorts|featured|streams|playlists|community|about))?$') { return "youtube.com/$($Matches[1])" }
    if ($entry -match '^youtube\.com/(channel|c|user)/([a-zA-Z0-9._-]{1,128})(?:/(?:videos|shorts|featured|streams|playlists|community|about))?$') {
        return "youtube.com/$($Matches[1])/$($Matches[2])"
    }
    throw "Not a supported YouTube channel name or URL: $Value"
}

function Get-ChainlinkBlocklist {
    param([Parameter(Mandatory = $true)][string]$Path)

    $entries = New-Object 'System.Collections.Generic.List[string]'
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }

    # ReadAllLines closes the file before parsing; a lazy reader would keep it open when a line is rejected.
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        $trimmed = $line.Trim()
        if ($trimmed -eq '' -or $trimmed.StartsWith('#')) { continue }
        $entry = ConvertTo-ChainlinkEntry $trimmed
        if ($entry -eq '') { continue }
        if ($seen.Add($entry)) {
            if ($entries.Count -ge $script:MaximumBlocklistEntries) {
                throw "Blocklist contains more than $script:MaximumBlocklistEntries entries."
            }
            $entries.Add($entry)
        }
    }
    return $entries.ToArray()
}

function Set-ChainlinkTextFileAtomic {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Lines
    )

    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        throw "The destination directory does not exist: $directory"
    }
    $tempPath = Join-Path $directory ('.chainlink-{0}.tmp' -f [Guid]::NewGuid().ToString('N'))
    $encoding = New-Object Text.UTF8Encoding($false)
    try {
        [IO.File]::WriteAllLines($tempPath, $Lines, $encoding)
        Move-Item -LiteralPath $tempPath -Destination $Path -Force
    } finally {
        if (Test-Path -LiteralPath $tempPath) { Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue }
    }
}

function Test-ChainlinkScheduledTaskObject {
    param(
        [Parameter(Mandatory = $true)]$Task,
        [Parameter(Mandatory = $true)][string]$PowerShellExe,
        [Parameter(Mandatory = $true)][string]$WatchdogPath
    )

    if ($null -eq $Task.Principal) { return $false }
    $userId = [string]$Task.Principal.UserId
    if ($userId -notin @('SYSTEM', 'S-1-5-18')) { return $false }

    # The original release registered the bare name "powershell.exe"; later versions use the full path.
    $executables = @($PowerShellExe, 'powershell.exe', 'powershell')
    $currentArguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$WatchdogPath`""
    $legacyArguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$WatchdogPath`""
    foreach ($action in @($Task.Actions)) {
        $execute = ([string]$action.Execute).Trim('"')
        $known = $false
        foreach ($candidate in $executables) {
            if ([StringComparer]::OrdinalIgnoreCase.Equals($execute, $candidate)) { $known = $true }
        }
        if ($known -and
            ([StringComparer]::OrdinalIgnoreCase.Equals([string]$action.Arguments, $currentArguments) -or
             [StringComparer]::OrdinalIgnoreCase.Equals([string]$action.Arguments, $legacyArguments))) {
            return $true
        }
    }
    return $false
}

# True when any action of the task would run something from the given directory. Uninstall uses
# this looser test so that it never leaves a SYSTEM task pointing at a directory it just deleted.
function Test-ChainlinkTaskReferencesDirectory {
    param(
        [Parameter(Mandatory = $true)]$Task,
        [Parameter(Mandatory = $true)][string]$Directory
    )

    $needle = $Directory.TrimEnd('\') + '\'
    foreach ($action in @($Task.Actions)) {
        foreach ($text in @([string]$action.Execute, [string]$action.Arguments)) {
            if ($text.IndexOf($needle, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
        }
    }
    return $false
}

# ================================================================ protected program directory

# Owner: Administrators. Protected DACL: SYSTEM and Administrators only, inherited by children.
$script:ProtectedDirectorySddl = 'O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
$script:TrustedOwnerSids = @('S-1-5-18', 'S-1-5-32-544')

function Get-ChainlinkOwnerSid {
    param([Parameter(Mandatory = $true)][string]$Path)

    $sections = [Security.AccessControl.AccessControlSections]::Owner
    if (Test-Path -LiteralPath $Path -PathType Container) { $security = [IO.Directory]::GetAccessControl($Path, $sections) }
    else { $security = [IO.File]::GetAccessControl($Path, $sections) }
    return $security.GetOwner([Security.Principal.SecurityIdentifier]).Value
}

# True when the directory is a real directory owned by SYSTEM or Administrators whose DACL
# grants access to nobody else. Anything looser lets a non-administrator swap files run as SYSTEM.
function Test-ChainlinkProtectedDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { return $false }
    $security = [IO.Directory]::GetAccessControl($Path, ([Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access))
    if ($security.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $script:TrustedOwnerSids) { return $false }
    if (-not $security.AreAccessRulesProtected) { return $false }
    foreach ($rule in $security.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            $rule.IdentityReference.Value -notin $script:TrustedOwnerSids) { return $false }
    }
    return $true
}

# Creates the directory with its final owner and ACL in one step, so there is no moment at which
# another account can put files into it. Fails if anything already exists at the path.
function New-ChainlinkProtectedDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (Test-Path -LiteralPath $Path) { throw "$Path already exists." }
    $security = New-Object Security.AccessControl.DirectorySecurity
    $security.SetSecurityDescriptorSddlForm($script:ProtectedDirectorySddl)
    [void][IO.Directory]::CreateDirectory($Path, $security)
    # CreateDirectory silently succeeds if someone else created the path first; verify the result.
    if (-not (Test-ChainlinkProtectedDirectory $Path) -or @(Get-ChildItem -LiteralPath $Path -Force).Count -gt 0) {
        throw "$Path was created by another account while Chainlink was installing. Remove it and try again."
    }
}

# Re-applies the protected ACL to an existing, trusted-owner directory (repair and upgrade).
function Set-ChainlinkProtectedDirectoryAcl {
    param([Parameter(Mandatory = $true)][string]$Path)

    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Path must be a real directory, not a file, junction, or symbolic link."
    }
    $owner = Get-ChainlinkOwnerSid $Path
    if ($owner -notin $script:TrustedOwnerSids) {
        throw "$Path is owned by an account other than SYSTEM or Administrators ($owner). Uninstall Chainlink, delete that folder, and link again."
    }
    $security = New-Object Security.AccessControl.DirectorySecurity
    $security.SetSecurityDescriptorSddlForm($script:ProtectedDirectorySddl, [Security.AccessControl.AccessControlSections]::Access)
    [IO.Directory]::SetAccessControl($Path, $security)
    if (-not (Test-ChainlinkProtectedDirectory $Path)) { throw "Could not secure $Path." }
    foreach ($child in @(Get-ChildItem -LiteralPath $Path -Force -Recurse)) {
        if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$($child.FullName) is a link; remove it and try again." }
        if ((Get-ChainlinkOwnerSid $child.FullName) -notin $script:TrustedOwnerSids) {
            throw "$($child.FullName) is owned by an account other than SYSTEM or Administrators; remove it and try again."
        }
    }
}

# ================================================================ watchdog lock

# The watchdog keeps this file open for as long as it runs. Install and uninstall take the same
# lock, which both proves that no watchdog is running and stops a new one from starting meanwhile.
# The file lives in the protected program directory, so other accounts cannot hold it.
function Open-ChainlinkWatchdogLock {
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::Read)
    } catch [IO.DirectoryNotFoundException] { throw }
    catch [IO.FileNotFoundException] { throw }
    catch [IO.IOException] { return $null }   # sharing violation: another process holds the lock
    $bytes = [Text.Encoding]::ASCII.GetBytes([string]$PID)
    $stream.SetLength(0)
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush()
    return $stream
}

function Get-ChainlinkWatchdogLockOwner {
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        try {
            $reader = New-Object IO.StreamReader($stream, [Text.Encoding]::ASCII)
            $text = $reader.ReadToEnd().Trim()
        } finally { $stream.Dispose() }
        if ($text -match '^[0-9]{1,10}$') { return [int]$text }
    } catch { }
    return 0
}

# ================================================================ browser policy

function Get-ChainlinkPolicyTargets {
    param([string]$Root = 'HKLM:\SOFTWARE\Policies')

    return @(
        [pscustomobject]@{ Name = 'Chrome';  Key = (Join-Path $Root 'Google\Chrome');       List = 'URLBlocklist';        Firefox = $false
            Values = [ordered]@{ IncognitoModeAvailability = 1; BrowserGuestModeEnabled = 0; BrowserAddPersonEnabled = 0 };  Extra = @('TorDisabled') },
        [pscustomobject]@{ Name = 'Edge';    Key = (Join-Path $Root 'Microsoft\Edge');      List = 'URLBlocklist';        Firefox = $false
            Values = [ordered]@{ InPrivateModeAvailability = 1; BrowserGuestModeEnabled = 0; BrowserAddProfileEnabled = 0 }; Extra = @('TorDisabled') },
        [pscustomobject]@{ Name = 'Brave';   Key = (Join-Path $Root 'BraveSoftware\Brave'); List = 'URLBlocklist';        Firefox = $false
            Values = [ordered]@{ IncognitoModeAvailability = 1; BrowserGuestModeEnabled = 0; BrowserAddPersonEnabled = 0; TorDisabled = 1 }; Extra = @() },
        [pscustomobject]@{ Name = 'Firefox'; Key = (Join-Path $Root 'Mozilla\Firefox');     List = 'WebsiteFilter\Block'; Firefox = $true
            Values = [ordered]@{ DisablePrivateBrowsing = 1 }; Extra = @() }
    )
}

# Ordered union of any number of string collections. Takes care never to treat a one-element
# collection as a scalar, which in PowerShell would turn "+" into string concatenation.
function Merge-ChainlinkValues {
    $result = New-Object 'System.Collections.Generic.List[string]'
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($group in $args) {
        foreach ($value in @($group)) {
            if ($null -eq $value) { continue }
            $text = [string]$value
            if ($text -ne '' -and $seen.Add($text)) { $result.Add($text) }
        }
    }
    return $result.ToArray()
}

function Get-ChainlinkFirefoxPatterns {
    param([AllowEmptyCollection()][string[]]$Entries)

    $patterns = New-Object 'System.Collections.Generic.List[string]'
    foreach ($entry in @($Entries)) {
        if ([string]::IsNullOrEmpty($entry)) { continue }
        if ($entry -eq '*') { $patterns.Add('*://*/*'); continue }
        $slash = $entry.IndexOf('/')
        if ($slash -lt 0) {
            $patterns.Add("*://$entry/*"); $patterns.Add("*://*.$entry/*")
            continue
        }
        $hostPart = $entry.Substring(0, $slash)
        $pathPart = $entry.Substring($slash)
        foreach ($prefix in @("*://$hostPart", "*://*.$hostPart")) {
            $patterns.Add("$prefix$pathPart"); $patterns.Add("$prefix$pathPart/*"); $patterns.Add("$prefix${pathPart}?*")
        }
    }
    return $patterns.ToArray()
}

function Get-ChainlinkValueSnapshot {
    param([string]$Path, [string]$Name)

    $absent = [pscustomobject]@{ Present = $false; Value = $null; Kind = $null }
    if (-not (Test-Path -LiteralPath $Path)) { return $absent }
    $key = Get-Item -LiteralPath $Path
    if ($key.GetValueNames() -notcontains $Name) { return $absent }
    return [pscustomobject]@{
        Present = $true
        Value = $key.GetValue($Name, $null, 'DoNotExpandEnvironmentNames')
        Kind = $key.GetValueKind($Name).ToString()
    }
}

function Get-ChainlinkListSnapshot {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }
    $key = Get-Item -LiteralPath $Path
    foreach ($name in $key.GetValueNames()) {
        [pscustomobject]@{ Name = $name; Value = [string]$key.GetValue($name, $null, 'DoNotExpandEnvironmentNames'); Kind = $key.GetValueKind($name).ToString() }
    }
}

function Get-ChainlinkListValues {
    param([string]$Path)
    foreach ($item in @(Get-ChainlinkListSnapshot $Path)) { $item.Value }
}

# Writes the list as values "1".."N" in place, then drops leftovers, so the policy is never
# momentarily absent. An empty list removes the key.
function Set-ChainlinkListValues {
    param([string]$Path, [AllowEmptyCollection()][string[]]$Values)

    $values = @($Values)
    if ($values.Count -eq 0) {
        if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Recurse -Force }
        return
    }
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
    $wanted = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    for ($i = 0; $i -lt $values.Count; $i++) {
        $name = [string]($i + 1)
        [void]$wanted.Add($name)
        New-ItemProperty -LiteralPath $Path -Name $name -Value $values[$i] -PropertyType String -Force | Out-Null
    }
    foreach ($name in @((Get-Item -LiteralPath $Path).GetValueNames())) {
        if (-not $wanted.Contains($name)) { Remove-ItemProperty -LiteralPath $Path -Name $name -Force }
    }
}

function Remove-ChainlinkEmptyKeys {
    param([string]$Path, [string]$Root)

    $stop = $Root.TrimEnd('\')
    $current = $Path.TrimEnd('\')
    while ($current.Length -gt $stop.Length -and $current.StartsWith($stop + '\', [StringComparison]::OrdinalIgnoreCase)) {
        if (Test-Path -LiteralPath $current) {
            $key = Get-Item -LiteralPath $current
            if ($key.SubKeyCount -gt 0 -or $key.ValueCount -gt 0) { return }
            Remove-Item -LiteralPath $current -Force
        }
        $current = Split-Path -Parent $current
    }
}

function Get-ChainlinkPolicyBaseline {
    param([string]$Root = 'HKLM:\SOFTWARE\Policies')

    $sections = @{}
    foreach ($target in @(Get-ChainlinkPolicyTargets $Root)) {
        $properties = @{}
        foreach ($name in @(@($target.Values.Keys) + @($target.Extra))) {
            $properties[$name] = Get-ChainlinkValueSnapshot $target.Key $name
        }
        $sections[$target.Name] = [pscustomobject]@{
            Properties = $properties
            Blocklist = @(Get-ChainlinkListSnapshot (Join-Path $target.Key $target.List))
        }
    }
    return [pscustomobject]@{
        Version = 1
        Chromium = @{ Chrome = $sections['Chrome']; Edge = $sections['Edge']; Brave = $sections['Brave'] }
        Firefox = $sections['Firefox']
    }
}

function Get-ChainlinkBaselineSection {
    param($Baseline, [string]$Name)

    if ($null -eq $Baseline) { return $null }
    if ($Name -eq 'Firefox') { $holder = $Baseline; $member = 'Firefox' } else { $holder = $Baseline.Chromium; $member = $Name }
    if ($null -eq $holder -or -not ($holder.PSObject.Properties.Name -contains $member)) { return $null }
    return $holder.$member
}

# True when a parsed baseline has every section and property this version relies on.
function Test-ChainlinkPolicyBaseline {
    param($Baseline)

    try {
        if ($null -eq $Baseline -or $Baseline.Version -ne 1) { return $false }
        foreach ($target in @(Get-ChainlinkPolicyTargets)) {
            $section = Get-ChainlinkBaselineSection $Baseline $target.Name
            if ($null -eq $section) { return $false }
            if (-not ($section.PSObject.Properties.Name -contains 'Blocklist')) { return $false }
            foreach ($name in $target.Values.Keys) {
                if (-not ($section.Properties.PSObject.Properties.Name -contains $name)) { return $false }
                if ($section.Properties.$name.Present -isnot [bool]) { return $false }
            }
        }
        return $true
    } catch { return $false }
}

function Get-ChainlinkBaselineList {
    param($Baseline, [string]$Name)

    $section = Get-ChainlinkBaselineSection $Baseline $Name
    if ($null -eq $section) { return }
    foreach ($item in @($section.Blocklist)) {
        if ($null -ne $item -and -not [string]::IsNullOrEmpty([string]$item.Value)) { [string]$item.Value }
    }
}

function Test-ChainlinkManagedValue {
    param($Snapshot, [int]$Managed)
    return ($Snapshot.Present -and $Snapshot.Kind -eq 'DWord' -and [int64]$Snapshot.Value -eq $Managed)
}

# Puts one policy value back the way it was before Chainlink, unless someone else has changed
# it since. Without a baseline the value is simply removed, as the original release did.
function Restore-ChainlinkPolicyValue {
    param([string]$Path, [string]$Name, $Snapshot, [int]$Managed)

    $current = Get-ChainlinkValueSnapshot $Path $Name
    if ($current.Present -and -not (Test-ChainlinkManagedValue $current $Managed)) { return }
    if ($null -ne $Snapshot -and $Snapshot.Present -and $Snapshot.Kind -in @('DWord', 'QWord', 'String', 'ExpandString', 'MultiString')) {
        if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
        New-ItemProperty -LiteralPath $Path -Name $Name -Value $Snapshot.Value -PropertyType $Snapshot.Kind -Force | Out-Null
    } elseif ($current.Present) {
        Remove-ItemProperty -LiteralPath $Path -Name $Name -Force
    }
}

# Applies the block. $PreviousEntries are entries an earlier lock wrote; they are replaced
# rather than mistaken for somebody else's policy.
function Set-ChainlinkPolicyLock {
    param(
        [string]$Root = 'HKLM:\SOFTWARE\Policies',
        [AllowEmptyCollection()][string[]]$Entries,
        [AllowEmptyCollection()][string[]]$PreviousEntries,
        $Baseline
    )

    $Entries = @($Entries | Where-Object { -not [string]::IsNullOrEmpty($_) })
    $managedEntries = @(Merge-ChainlinkValues $Entries $PreviousEntries)
    foreach ($target in @(Get-ChainlinkPolicyTargets $Root)) {
        $wanted = @($Entries)
        $managed = $managedEntries
        if ($target.Firefox) {
            $wanted = @(Get-ChainlinkFirefoxPatterns $Entries)
            $managed = @(Get-ChainlinkFirefoxPatterns $managedEntries)
        }
        $listKey = Join-Path $target.Key $target.List
        $managedSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
        foreach ($value in $managed) { [void]$managedSet.Add($value) }
        $others = @(Get-ChainlinkListValues $listKey | Where-Object { -not $managedSet.Contains($_) })
        $base = @(Get-ChainlinkBaselineList $Baseline $target.Name)
        Set-ChainlinkListValues $listKey @(Merge-ChainlinkValues $base $others $wanted)
        if (-not (Test-Path -LiteralPath $target.Key)) { New-Item -Path $target.Key -Force | Out-Null }
        foreach ($name in $target.Values.Keys) {
            New-ItemProperty -LiteralPath $target.Key -Name $name -Value ([int]$target.Values[$name]) -PropertyType DWord -Force | Out-Null
        }
    }
}

# Lifts the block: removes exactly the entries Chainlink manages, keeps everything else, and
# restores the values recorded in the baseline.
function Remove-ChainlinkPolicyLock {
    param(
        [string]$Root = 'HKLM:\SOFTWARE\Policies',
        [AllowEmptyCollection()][string[]]$Entries,
        $Baseline
    )

    $Entries = @($Entries | Where-Object { -not [string]::IsNullOrEmpty($_) })
    foreach ($target in @(Get-ChainlinkPolicyTargets $Root)) {
        $managed = @($Entries)
        if ($target.Firefox) { $managed = @(Get-ChainlinkFirefoxPatterns $Entries) }
        $listKey = Join-Path $target.Key $target.List
        $managedSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
        foreach ($value in $managed) { [void]$managedSet.Add($value) }
        $others = @(Get-ChainlinkListValues $listKey | Where-Object { -not $managedSet.Contains($_) })
        $base = @(Get-ChainlinkBaselineList $Baseline $target.Name)
        Set-ChainlinkListValues $listKey @(Merge-ChainlinkValues $base $others)

        $section = Get-ChainlinkBaselineSection $Baseline $target.Name
        foreach ($name in $target.Values.Keys) {
            $snapshot = $null
            if ($null -ne $section -and ($section.Properties.PSObject.Properties.Name -contains $name)) { $snapshot = $section.Properties.$name }
            Restore-ChainlinkPolicyValue $target.Key $name $snapshot ([int]$target.Values[$name])
        }
        Remove-ChainlinkEmptyKeys $listKey $Root
        Remove-ChainlinkEmptyKeys $target.Key $Root
    }
}

function Test-ChainlinkPolicyLock {
    param(
        [string]$Root = 'HKLM:\SOFTWARE\Policies',
        [AllowEmptyCollection()][string[]]$Entries
    )

    $Entries = @($Entries | Where-Object { -not [string]::IsNullOrEmpty($_) })
    try {
        foreach ($target in @(Get-ChainlinkPolicyTargets $Root)) {
            foreach ($name in $target.Values.Keys) {
                if (-not (Test-ChainlinkManagedValue (Get-ChainlinkValueSnapshot $target.Key $name) ([int]$target.Values[$name]))) { return $false }
            }
            $wanted = @($Entries)
            if ($target.Firefox) { $wanted = @(Get-ChainlinkFirefoxPatterns $Entries) }
            $actual = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
            foreach ($value in @(Get-ChainlinkListValues (Join-Path $target.Key $target.List))) { [void]$actual.Add($value) }
            foreach ($value in $wanted) { if (-not $actual.Contains($value)) { return $false } }
        }
        return $true
    } catch { return $false }
}

Export-ModuleMember -Function @(
    'Get-ChainlinkSha256Hex',
    'Test-ChainlinkFixedTimeEqual',
    'ConvertTo-ChainlinkEntry',
    'ConvertTo-ChainlinkChannel',
    'Get-ChainlinkBlocklist',
    'Set-ChainlinkTextFileAtomic',
    'Test-ChainlinkScheduledTaskObject',
    'Test-ChainlinkTaskReferencesDirectory',
    'Get-ChainlinkOwnerSid',
    'Test-ChainlinkProtectedDirectory',
    'New-ChainlinkProtectedDirectory',
    'Set-ChainlinkProtectedDirectoryAcl',
    'Open-ChainlinkWatchdogLock',
    'Get-ChainlinkWatchdogLockOwner',
    'Merge-ChainlinkValues',
    'Get-ChainlinkFirefoxPatterns',
    'Get-ChainlinkPolicyBaseline',
    'Test-ChainlinkPolicyBaseline',
    'Set-ChainlinkPolicyLock',
    'Remove-ChainlinkPolicyLock',
    'Test-ChainlinkPolicyLock'
)
