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
    if let Some((scheme, _)) = value.split_once("://")
        && !matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https")
    {
        bail!("only http:// and https:// URLs are supported");
    }
    if !value.contains("://")
        && let Some((prefix, _)) = value.split_once(':')
        && prefix.chars().all(|c| c.is_ascii_alphabetic())
    {
        bail!("only http:// and https:// URLs are supported");
    }

    let candidate = if value.contains("://") {
        value.to_owned()
    } else {
        format!("https://{value}")
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
        Host::Domain(domain) => domain.trim_end_matches('.').to_ascii_lowercase(),
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

pub fn read_blocklist(path: &Path) -> Result<Vec<String>> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    parse_blocklist(text.trim_start_matches('\u{feff}'))
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
    fn rejects_ambiguous_input() {
        for value in [
            "file:///C:/Windows",
            "https://user:pass@example.com",
            "https://example.com/?secret=x",
            "bad host",
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
