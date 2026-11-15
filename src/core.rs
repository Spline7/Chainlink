use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::Path;
use subtle::ConstantTimeEq;
use tempfile::NamedTempFile;
use url::{Host, Url};

pub const MAX_ENTRY_LENGTH: usize = 2048;
pub const MAX_BLOCKLIST_ENTRIES: usize = 2048;
pub const RECOVERY_ROUNDS: u32 = 300_000;
pub const SHORTS_ENTRY: &str = "youtube.com/shorts";

pub const WORD_LIST: [&str; 256] = include!("word_list.rs");

pub fn normalize_entry(input: &str) -> Result<String> {
    let value = input.trim();
    if value.is_empty() {
        return Ok(String::new());
    }
    if value.len() > MAX_ENTRY_LENGTH {
        bail!("entries must be {MAX_ENTRY_LENGTH} characters or fewer");
    }
    if value
        .chars()
        .any(|c| c.is_ascii_control() || c.is_whitespace())
    {
        bail!("entries cannot contain whitespace or control characters");
    }
    // "example.com:8080" is a host and port; "mailto:someone" or "file:///C:/" is another scheme.
    let scheme_end = value.find("://").filter(|end| is_scheme(&value[..*end]));
    let rest = match scheme_end {
        Some(end) => {
            if !matches!(value[..end].to_ascii_lowercase().as_str(), "http" | "https") {
                bail!("only http:// and https:// URLs are supported");
            }
            &value[end + 3..]
        }
        None => {
            if let Some((prefix, after)) = value.split_once(':')
                && is_scheme(prefix)
                && !is_port_and_path(after)
            {
                bail!("only http:// and https:// URLs are supported");
            }
            value
        }
    };
    // The original release accepted "*.example.com" and "example.com/*"; both mean the plain entry.
    let rest = rest
        .strip_prefix("*.")
        .unwrap_or(rest)
        .trim_end_matches(['/', '*']);
    if rest.is_empty() {
        bail!("invalid website or URL");
    }
    let candidate = match scheme_end {
        Some(end) => format!("{}{rest}", &value[..end + 3]),
        None => format!("https://{rest}"),
    };
    let url = Url::parse(&candidate).context("invalid website or URL")?;
    if !matches!(url.scheme(), "http" | "https") || url.host().is_none() {
        bail!("invalid website or URL");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("URLs containing credentials are not supported");
    }
    if url.query().is_some() || url.fragment().is_some() {
        bail!("query strings and fragments are not supported");
    }

    let mut host = match url.host().context("invalid website hostname")? {
        Host::Domain(domain) => {
            let domain = domain.trim_end_matches('.').to_ascii_lowercase();
            if !domain.split('.').all(is_host_label) {
                bail!("invalid website hostname");
            }
            domain
        }
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => format!("[{address}]"),
    };
    if let Some(stripped) = host.strip_prefix("www.") {
        host = stripped.to_owned();
    }
    let port = match url.port() {
        Some(80) if url.scheme() == "http" => String::new(),
        Some(443) if url.scheme() == "https" => String::new(),
        Some(port) => format!(":{port}"),
        None => String::new(),
    };
    let path = url.path().trim_end_matches('/');
    Ok(format!("{host}{port}{path}"))
}

fn is_scheme(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && characters.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
}

/// True for "8080" or "8080/path": what follows the colon in "host:port".
fn is_port_and_path(value: &str) -> bool {
    let port = value.split('/').next().unwrap_or("");
    (1..=5).contains(&port.len()) && port.chars().all(|c| c.is_ascii_digit())
}

fn is_host_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

pub fn normalize_channel(input: &str) -> Result<String> {
    let value = input.trim();
    if value.is_empty() {
        return Ok(String::new());
    }
    let handle = value.strip_prefix('@').unwrap_or(value);
    if valid_channel_component(handle, 100) {
        return Ok(format!("youtube.com/@{handle}"));
    }
    let mut entry = normalize_entry(value)?;
    if let Some(rest) = entry.strip_prefix("m.youtube.com/") {
        entry = format!("youtube.com/{rest}");
    }
    let rest = entry
        .strip_prefix("youtube.com/")
        .context("not a supported YouTube channel name or URL")?;
    let parts: Vec<_> = rest.split('/').collect();
    let suffix_ok = |suffix: Option<&&str>| {
        suffix.is_none_or(|value| {
            matches!(
                *value,
                "videos" | "shorts" | "featured" | "streams" | "playlists" | "community" | "about"
            )
        })
    };
    if let Some(handle) = parts.first().and_then(|part| part.strip_prefix('@'))
        && parts.len() <= 2
        && valid_channel_component(handle, 100)
        && suffix_ok(parts.get(1))
    {
        return Ok(format!("youtube.com/@{handle}"));
    }
    if parts.len() >= 2
        && parts.len() <= 3
        && matches!(parts[0], "channel" | "c" | "user")
        && valid_channel_component(parts[1], 128)
        && suffix_ok(parts.get(2))
    {
        return Ok(format!("youtube.com/{}/{}", parts[0], parts[1]));
    }
    bail!("not a supported YouTube channel name or URL")
}

fn valid_channel_component(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

pub fn parse_blocklist(text: &str) -> Result<Vec<String>> {
    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let entry = normalize_entry(line)?;
        if seen.insert(entry.clone()) {
            if entries.len() >= MAX_BLOCKLIST_ENTRIES {
                bail!("blocklist contains more than {MAX_BLOCKLIST_ENTRIES} entries");
            }
            entries.push(entry);
        }
    }
    Ok(entries)
}

pub fn parse_blocklist_bytes(bytes: &[u8]) -> Result<Vec<String>> {
    let text = std::str::from_utf8(bytes).context("the blocklist is not UTF-8 text")?;
    parse_blocklist(text.trim_start_matches('\u{feff}'))
}

pub fn read_blocklist(path: &Path) -> Result<Vec<String>> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    parse_blocklist_bytes(&bytes)
}

/// Ordered union of any number of string lists, without empty strings.
pub fn merge(groups: &[&[String]]) -> Vec<String> {
    let mut seen = HashSet::new();
    groups
        .iter()
        .flat_map(|group| group.iter())
        .filter(|value| !value.is_empty() && seen.insert(value.as_str()))
        .cloned()
        .collect()
}

pub fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .context("destination has no parent directory")?;
    let mut temporary = NamedTempFile::new_in(parent)?;
    temporary.write_all(contents)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("replace {}", path.display()))?;
    Ok(())
}

pub fn new_key_token() -> Result<String> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|error| anyhow!("secure random generation failed: {error}"))?;
    Ok(STANDARD.encode(bytes))
}

pub fn read_key_token(path: &Path) -> Result<String> {
    let bytes = fs::read(path)?;
    let text = if bytes.starts_with(&[0xff, 0xfe]) || bytes.iter().take(4).any(|byte| *byte == 0) {
        let start = usize::from(bytes.starts_with(&[0xff, 0xfe])) * 2;
        let units: Vec<u16> = bytes[start..]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        String::from_utf16(&units)?
    } else {
        String::from_utf8(bytes)?
            .trim_start_matches('\u{feff}')
            .to_owned()
    };
    let token = text.trim().to_owned();
    let decoded = STANDARD.decode(&token)?;
    if decoded.len() != 32 {
        bail!("key file must contain exactly 32 random bytes");
    }
    Ok(token)
}

pub fn pairing_hash(token: &str, volume_serial: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{token}|{volume_serial}"));
    format!("{:x}", hasher.finalize())
}

pub fn new_recovery_words() -> Result<Vec<String>> {
    let mut bytes = [0_u8; 6];
    getrandom::fill(&mut bytes)
        .map_err(|error| anyhow!("secure random generation failed: {error}"))?;
    Ok(bytes
        .iter()
        .map(|index| WORD_LIST[*index as usize].to_owned())
        .collect())
}

fn phrase(words: &[String]) -> String {
    words
        .iter()
        .map(|word| word.trim().to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn make_recovery_record(words: &[String], rounds: u32) -> Result<String> {
    let mut salt = [0_u8; 16];
    let mut digest = [0_u8; 32];
    getrandom::fill(&mut salt)
        .map_err(|error| anyhow!("secure random generation failed: {error}"))?;
    pbkdf2_hmac::<Sha256>(phrase(words).as_bytes(), &salt, rounds, &mut digest);
    Ok(format!(
        "v2:{rounds}:{}:{}",
        STANDARD.encode(salt),
        STANDARD.encode(digest)
    ))
}

pub fn verify_recovery_record(record: &str, words: &[String]) -> bool {
    verify_recovery_record_inner(record, words).unwrap_or(false)
}

fn verify_recovery_record_inner(record: &str, words: &[String]) -> Result<bool> {
    let parts: Vec<_> = record.trim().split(':').collect();
    let (algorithm, rounds, salt_text, digest_text) = match parts.as_slice() {
        [salt, digest] => ("sha1", 100_000, *salt, *digest),
        [version @ ("v1" | "v2"), rounds, salt, digest] => {
            (*version, rounds.parse::<u32>()?, *salt, *digest)
        }
        _ => return Ok(false),
    };
    if !(100_000..=2_000_000).contains(&rounds) {
        return Ok(false);
    }
    let salt = STANDARD.decode(salt_text)?;
    let expected = STANDARD.decode(digest_text)?;
    if salt.len() != 16 || expected.len() != 32 {
        return Ok(false);
    }
    let mut actual = [0_u8; 32];
    if algorithm == "v2" {
        pbkdf2_hmac::<Sha256>(phrase(words).as_bytes(), &salt, rounds, &mut actual);
    } else {
        pbkdf2_hmac::<Sha1>(phrase(words).as_bytes(), &salt, rounds, &mut actual);
    }
    Ok(bool::from(actual.as_slice().ct_eq(expected.as_slice())))
}

pub fn firefox_patterns(entry: &str) -> Vec<String> {
    if entry == "*" {
        // the watchdog's block-everything fail-safe
        return vec!["*://*/*".to_owned()];
    }
    match entry.split_once('/') {
        None => vec![format!("*://{entry}/*"), format!("*://*.{entry}/*")],
        Some((host, path)) => {
            let path = format!("/{path}");
            vec![
                format!("*://{host}{path}"),
                format!("*://{host}{path}/*"),
                format!("*://{host}{path}?*"),
                format!("*://*.{host}{path}"),
                format!("*://*.{host}{path}/*"),
                format!("*://*.{host}{path}?*"),
            ]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use tempfile::tempdir;

    fn words() -> Vec<String> {
        ["apple", "arrow", "badge", "baker", "bamboo", "banjo"]
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    #[test]
    fn normalizes_urls_and_channels() {
        assert_eq!(
            normalize_entry(" HTTPS://WWW.Example.COM/path/ ").unwrap(),
            "example.com/path"
        );
        assert_eq!(
            normalize_entry("https://bücher.example").unwrap(),
            "xn--bcher-kva.example"
        );
        assert_eq!(
            normalize_entry("http://[::1]:8080/path/").unwrap(),
            "[::1]:8080/path"
        );
        assert_eq!(
            normalize_channel("@SomeCreator").unwrap(),
            "youtube.com/@SomeCreator"
        );
        assert_eq!(
            normalize_channel("https://m.youtube.com/channel/UC123/videos").unwrap(),
            "youtube.com/channel/UC123"
        );
    }

    #[test]
    fn accepts_ports_and_legacy_wildcards() {
        for (input, expected) in [
            ("*.example.com", "example.com"),
            ("https://example.com/videos/*", "example.com/videos"),
            ("example.com:8080", "example.com:8080"),
            ("localhost:3000/app/", "localhost:3000/app"),
            ("Example.com/Path/", "example.com/Path"),
        ] {
            assert_eq!(normalize_entry(input).unwrap(), expected, "{input}");
        }
    }

    #[test]
    fn merge_and_patterns() {
        let one = vec!["a.example".to_owned()];
        let two = vec!["x.example".to_owned(), "y.example".to_owned()];
        assert_eq!(
            merge(&[&one, &one, &two]),
            ["a.example", "x.example", "y.example"]
        );
        assert!(merge(&[&[], &[String::new()]]).is_empty());
        assert_eq!(firefox_patterns("*"), ["*://*/*"]);
        assert!(firefox_patterns("example.com").contains(&"*://*.example.com/*".to_owned()));
    }

    #[test]
    fn rejects_ambiguous_input() {
        for value in [
            "file:///C:/Windows",
            "https://user:pass@example.com",
            "https://example.com/?secret=x",
            "bad host",
            "mailto:someone@example.com",
            "javascript:alert(1)",
            "*",
            "exa_mple.com",
            "*.*.example.com",
        ] {
            assert!(normalize_entry(value).is_err(), "{value}");
        }
        assert!(normalize_channel(r"bad\handle").is_err());
    }

    #[test]
    fn blocklist_deduplicates_and_limits() {
        let parsed =
            parse_blocklist("Example.com\nhttps://example.com/\nyoutube.com/shorts\n").unwrap();
        assert_eq!(parsed, ["example.com", "youtube.com/shorts"]);
        let too_many = (0..=MAX_BLOCKLIST_ENTRIES)
            .map(|index| format!("site{index}.example"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(parse_blocklist(&too_many).is_err());
    }

    #[test]
    fn recovery_records_are_compatible() {
        let words = words();
        let record = make_recovery_record(&words, 100_000).unwrap();
        assert!(verify_recovery_record(&record, &words));
        let salt = [0_u8; 16];
        let mut digest = [0_u8; 32];
        pbkdf2_hmac::<Sha1>(phrase(&words).as_bytes(), &salt, 100_000, &mut digest);
        let legacy = format!("{}:{}", STANDARD.encode(salt), STANDARD.encode(digest));
        assert!(verify_recovery_record(&legacy, &words));
    }

    #[test]
    fn atomic_write_and_utf16_key_work() {
        let directory = tempdir().unwrap();
        let state = directory.path().join("state.txt");
        atomic_write(&state, b"first\n").unwrap();
        atomic_write(&state, b"second\n").unwrap();
        assert_eq!(fs::read_to_string(&state).unwrap(), "second\n");
        let token = STANDARD.encode([7_u8; 32]);
        let mut bytes = vec![0xff, 0xfe];
        for unit in token.encode_utf16() {
            bytes.extend(unit.to_le_bytes());
        }
        fs::write(&state, bytes).unwrap();
        assert_eq!(read_key_token(&state).unwrap(), token);
    }
}
