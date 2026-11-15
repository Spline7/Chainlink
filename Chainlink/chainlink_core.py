"""Pure, cross-platform helpers shared by the Chainlink UI and watchdog."""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

MAX_ENTRY_LENGTH = 2048
MAX_BLOCKLIST_ENTRIES = 2048
RECOVERY_ROUNDS = 300_000
SHORTS_ENTRY = "youtube.com/shorts"

WORD_LIST = (
    "apple arrow badge baker bamboo banjo barn basket beach bean bear beaver bell bench berry bike "
    "bird bison blanket boat bonfire book boot bottle bread brick bridge broom bucket bunny butter button "
    "cabin cactus cake camel camera candle canoe canyon carpet carrot castle cedar chair cheese cherry chess "
    "cider circus cliff clock cloud clover coast cobra cocoa comet cookie copper coral cotton cougar cowboy "
    "crab crane crayon cricket crown daisy desert dolphin donkey dragon drum eagle easel elbow ember falcon "
    "fern ferry fiddle field flag flute forest fossil fox frog garden garlic geyser ginger glove goat "
    "gopher grape guitar hammer harbor hawk hazel helmet heron hill honey hornet horse igloo island ivy "
    "jacket jaguar jelly jungle kayak kettle kite koala ladder lagoon lantern lemon lily lion lizard llama "
    "lobster magnet mango maple marble meadow melon mitten moose moss mountain muffin needle nest noodle oak "
    "oasis ocean olive onion orange orchid otter owl paddle panda parrot peach peanut pearl pebble pelican "
    "pencil pepper piano pickle pigeon pillow pine planet plum pony popcorn potato puffin pumpkin puzzle quail "
    "quilt rabbit radio raft rain raven reef ribbon river robin rocket rose saddle salmon sandal scarf "
    "seal shell shovel silver skunk sled sloth snail socks sparrow spider spoon squash squid stable star "
    "storm sugar summit sunset swan table taco tiger tomato torch tower tractor trail tulip tundra turkey "
    "turtle umbrella valley velvet violin volcano waffle wagon walnut walrus whale wheat willow window wizard wolf "
    "yogurt zebra anchor acorn bagel beetle biscuit blossom breeze canary chimney compass cupcake dune feather glacier"
).split()

if len(WORD_LIST) != 256:  # pragma: no cover - import-time invariant
    raise RuntimeError("the recovery word list must contain exactly 256 words")


class ValidationError(ValueError):
    """Raised when user-controlled Chainlink input is invalid."""


def normalize_entry(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if len(value) > MAX_ENTRY_LENGTH:
        raise ValidationError(f"entries must be {MAX_ENTRY_LENGTH} characters or fewer")
    if any(ord(character) <= 0x20 or ord(character) == 0x7F for character in value):
        raise ValidationError("entries cannot contain whitespace or control characters")

    # "example.com:8080" is a host and port; "mailto:someone" or "file:///C:/" is another scheme.
    scheme_match = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*)://", value)
    if scheme_match:
        if scheme_match.group(1).lower() not in {"http", "https"}:
            raise ValidationError("only http:// and https:// URLs are supported")
    elif re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", value) and not re.match(r"^[^:/]+:[0-9]{1,5}(/|$)", value):
        raise ValidationError("only http:// and https:// URLs are supported")

    # The original release accepted "*.example.com" and "example.com/*"; both mean the plain entry.
    scheme, rest = (scheme_match.group(0), value[scheme_match.end():]) if scheme_match else ("https://", value)
    rest = re.sub(r"[/*]+$", "", re.sub(r"^\*\.", "", rest))
    if not rest:
        raise ValidationError("invalid website or URL")
    candidate = scheme + rest
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError as error:
        raise ValidationError("invalid website or URL") from error
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValidationError("invalid website or URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValidationError("URLs containing credentials are not supported")
    if parsed.query or parsed.fragment:
        raise ValidationError("query strings and fragments are not supported")

    host = parsed.hostname.rstrip(".")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii").lower()
        except UnicodeError as error:
            raise ValidationError("invalid website hostname") from error
        if host.startswith("www.") and "." in host[4:]:
            host = host[4:]
        labels = host.split(".")
        if any(not label or len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) for label in labels):
            raise ValidationError("invalid website hostname")
    else:
        host = f"[{ip.compressed}]" if ip.version == 6 else str(ip)

    # Default ports are dropped whichever scheme was typed, so a saved entry re-reads the same.
    port_text = "" if port in (None, 80, 443) else f":{port}"
    path = parsed.path.rstrip("/")
    return f"{host}{port_text}{path}"


def normalize_channel(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    match = re.fullmatch(r"@?([A-Za-z0-9._-]{1,100})", value)
    if match:
        return f"youtube.com/@{match.group(1)}"
    # The window shows saved channels without "youtube.com/", so that form must be accepted back.
    match = re.fullmatch(r"(channel|c|user)/([A-Za-z0-9._-]{1,128})", value)
    if match:
        return f"youtube.com/{match.group(1)}/{match.group(2)}"

    entry = re.sub(r"^m\.youtube\.com/", "youtube.com/", normalize_entry(value))
    suffix = r"(?:/(?:videos|shorts|featured|streams|playlists|community|about))?"
    match = re.fullmatch(rf"youtube\.com/(@[A-Za-z0-9._-]{{1,100}}){suffix}", entry)
    if match:
        return f"youtube.com/{match.group(1)}"
    match = re.fullmatch(rf"youtube\.com/(channel|c|user)/([A-Za-z0-9._-]{{1,128}}){suffix}", entry)
    if match:
        return f"youtube.com/{match.group(1)}/{match.group(2)}"
    raise ValidationError("not a supported YouTube channel name or URL")


def parse_blocklist_lines(lines: list[str] | tuple[str, ...] | object) -> list[str]:
    entries: list[str] = []
    seen: set[str] = set()
    for line in lines:  # type: ignore[union-attr]
        stripped = str(line).strip()
        if not stripped or stripped.startswith("#"):
            continue
        entry = normalize_entry(stripped)
        if entry not in seen:
            if len(entries) >= MAX_BLOCKLIST_ENTRIES:
                raise ValidationError(f"blocklist contains more than {MAX_BLOCKLIST_ENTRIES} entries")
            seen.add(entry)
            entries.append(entry)
    return entries


def parse_blocklist_bytes(data: bytes) -> list[str]:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise ValidationError("the blocklist is not UTF-8 text") from error
    return parse_blocklist_lines(text.splitlines())


def read_blocklist(path: Path) -> list[str]:
    return parse_blocklist_bytes(path.read_bytes())


def atomic_write_bytes(path: Path, data: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=".chainlink-", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def atomic_write_text(path: Path, text: str) -> None:
    atomic_write_bytes(path, text.encode("utf-8"))


def read_key_token(path: Path) -> str:
    data = path.read_bytes()
    encodings = ("utf-8-sig", "utf-16") if b"\x00" in data[:4] else ("utf-8-sig",)
    token = ""
    for encoding in encodings:
        try:
            token = data.decode(encoding).strip()
            break
        except UnicodeError:
            continue
    try:
        decoded = base64.b64decode(token, validate=True)
    except (ValueError, TypeError) as error:
        raise ValidationError("key file is not valid base64") from error
    if len(decoded) != 32:
        raise ValidationError("key file must contain exactly 32 random bytes")
    return token


def new_key_token() -> str:
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


def pairing_hash(token: str, volume_serial: str) -> str:
    return hashlib.sha256(f"{token}|{volume_serial}".encode()).hexdigest()


def new_recovery_words() -> list[str]:
    return [WORD_LIST[secrets.randbelow(256)] for _ in range(6)]


def recovery_phrase(words: list[str] | tuple[str, ...]) -> str:
    return " ".join(word.strip().lower() for word in words)


def make_recovery_record(words: list[str] | tuple[str, ...], rounds: int = RECOVERY_ROUNDS) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", recovery_phrase(words).encode(), salt, rounds, dklen=32)
    return f"v2:{rounds}:{base64.b64encode(salt).decode()}:{base64.b64encode(digest).decode()}"


def verify_recovery_record(record: str, words: list[str] | tuple[str, ...]) -> bool:
    try:
        parts = record.strip().split(":")
        if len(parts) == 2:  # Original PowerShell release.
            algorithm, rounds, salt_text, digest_text = "sha1", 100_000, parts[0], parts[1]
        elif len(parts) == 4 and parts[0] in {"v1", "v2"}:
            algorithm = "sha1" if parts[0] == "v1" else "sha256"
            rounds, salt_text, digest_text = int(parts[1]), parts[2], parts[3]
        else:
            return False
        if not 100_000 <= rounds <= 2_000_000:
            return False
        salt = base64.b64decode(salt_text, validate=True)
        expected = base64.b64decode(digest_text, validate=True)
        if len(salt) != 16 or len(expected) != 32:
            return False
        actual = hashlib.pbkdf2_hmac(algorithm, recovery_phrase(words).encode(), salt, rounds, dklen=32)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def firefox_patterns(entry: str) -> list[str]:
    if entry == "*":  # the watchdog's block-everything fail-safe
        return ["*://*/*"]
    if "/" not in entry:
        return [f"*://{entry}/*", f"*://*.{entry}/*"]
    host, path = entry.split("/", 1)
    path = "/" + path
    return [
        f"*://{host}{path}",
        f"*://{host}{path}/*",
        f"*://{host}{path}?*",
        f"*://*.{host}{path}",
        f"*://*.{host}{path}/*",
        f"*://*.{host}{path}?*",
    ]


def unique(*groups: object) -> list[str]:
    """Ordered union of any number of string collections, without empty strings."""
    return list(dict.fromkeys(str(value) for group in groups for value in group if str(value)))  # type: ignore[union-attr]
