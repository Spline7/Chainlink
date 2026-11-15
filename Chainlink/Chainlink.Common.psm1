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
    if ($value -match '^([a-zA-Z][a-zA-Z0-9+.-]*):' -and $Matches[1] -notin @('http', 'https')) {
        throw "Only http:// and https:// URLs are supported: $Value"
    }

    $candidate = $value
    if ($candidate -notmatch '^[a-zA-Z][a-zA-Z0-9+.-]*://') { $candidate = "https://$candidate" }
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
    if ($hostName.StartsWith('www.')) { $hostName = $hostName.Substring(4) }
    if ($hostName -notmatch '^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$' -and $uri.HostNameType -ne [UriHostNameType]::IPv6) {
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
    if ($value -match '^@?([^/?#\s]+)$') { return "youtube.com/@$($Matches[1])" }

    $entry = ConvertTo-ChainlinkEntry $value
    if ($entry -match '^youtube\.com/(@[^/?#]+)(?:/(?:videos|shorts|featured|streams|playlists|community|about))?$') { return "youtube.com/$($Matches[1])" }
    if ($entry -match '^youtube\.com/(channel|c|user)/([^/?#]+)(?:/(?:videos|shorts|featured|streams|playlists|community|about))?$') {
        return "youtube.com/$($Matches[1])/$($Matches[2])"
    }
    throw "Not a supported YouTube channel name or URL: $Value"
}

function Get-ChainlinkBlocklist {
    param([Parameter(Mandatory = $true)][string]$Path)

    $entries = New-Object 'System.Collections.Generic.List[string]'
    $seen = @{}
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return ,([string[]]@()) }

    foreach ($line in [IO.File]::ReadLines($Path)) {
        $trimmed = $line.Trim()
        if ($trimmed -eq '' -or $trimmed.StartsWith('#')) { continue }
        $entry = ConvertTo-ChainlinkEntry $trimmed
        if ($entry -eq '') { continue }
        if (-not $seen.ContainsKey($entry)) {
            if ($entries.Count -ge $script:MaximumBlocklistEntries) {
                throw "Blocklist contains more than $script:MaximumBlocklistEntries entries."
            }
            $seen[$entry] = $true
            $entries.Add($entry)
        }
    }
    return ,$entries.ToArray()
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

Export-ModuleMember -Function @(
    'Get-ChainlinkSha256Hex',
    'Test-ChainlinkFixedTimeEqual',
    'ConvertTo-ChainlinkEntry',
    'ConvertTo-ChainlinkChannel',
    'Get-ChainlinkBlocklist',
    'Set-ChainlinkTextFileAtomic'
)
