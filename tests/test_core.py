from __future__ import annotations

import base64
import hashlib
import py_compile
import sys
import tempfile
import unittest
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
SOURCE = REPOSITORY / "Chainlink"
sys.path.insert(0, str(SOURCE))

from chainlink_core import (  # noqa: E402
    ValidationError,
    atomic_write_text,
    firefox_patterns,
    make_recovery_record,
    normalize_channel,
    normalize_entry,
    pairing_hash,
    parse_blocklist_lines,
    read_key_token,
    unique,
    verify_recovery_record,
)


class NormalizationTests(unittest.TestCase):
    def test_normalizes_urls(self) -> None:
        self.assertEqual("example.com/path", normalize_entry(" HTTPS://WWW.Example.COM/path/ "))
        self.assertEqual("xn--bcher-kva.example", normalize_entry("https://bücher.example"))
        self.assertEqual("[::1]:8080/path", normalize_entry("http://[::1]:8080/path/"))

    def test_accepts_ports_and_legacy_wildcards(self) -> None:
        self.assertEqual("example.com", normalize_entry("*.example.com"))
        self.assertEqual("example.com/videos", normalize_entry("https://example.com/videos/*"))
        self.assertEqual("example.com:8080", normalize_entry("example.com:8080"))
        self.assertEqual("localhost:3000/app", normalize_entry("localhost:3000/app/"))

    def test_normalizes_channels(self) -> None:
        self.assertEqual("youtube.com/@SomeCreator", normalize_channel("@SomeCreator"))
        self.assertEqual("youtube.com/channel/UC123", normalize_channel("https://m.youtube.com/channel/UC123/videos"))

    def test_rejects_ambiguous_input(self) -> None:
        for value in ("file:///C:/Windows", "https://user:pass@example.com", "https://example.com/?secret=x", "bad host", "mailto:someone@example.com", "*", "exa_mple.com"):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                normalize_entry(value)
        with self.assertRaises(ValidationError):
            normalize_channel(r"bad\handle")

    def test_blocklist_deduplicates_and_limits(self) -> None:
        self.assertEqual(["example.com", "youtube.com/shorts"], parse_blocklist_lines(["Example.com", "https://example.com/", "youtube.com/shorts"]))
        self.assertEqual([], parse_blocklist_lines(["# empty", " "]))
        with self.assertRaises(ValidationError):
            parse_blocklist_lines(f"site{index}.example" for index in range(2049))


class CryptoAndFileTests(unittest.TestCase):
    WORDS = ["apple", "arrow", "badge", "baker", "bamboo", "banjo"]

    def test_recovery_record_round_trip_and_wrong_phrase(self) -> None:
        record = make_recovery_record(self.WORDS, rounds=100_000)
        self.assertTrue(verify_recovery_record(record, self.WORDS))
        self.assertFalse(verify_recovery_record(record, [*self.WORDS[:-1], "barn"]))

    def test_legacy_powershell_recovery_record(self) -> None:
        salt = bytes(range(16))
        phrase = " ".join(self.WORDS).encode()
        digest = hashlib.pbkdf2_hmac("sha1", phrase, salt, 100_000, dklen=32)
        record = f"{base64.b64encode(salt).decode()}:{base64.b64encode(digest).decode()}"
        self.assertTrue(verify_recovery_record(record, self.WORDS))

    def test_atomic_replace_and_legacy_utf16_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.txt"
            atomic_write_text(path, "first\n")
            atomic_write_text(path, "second\n")
            self.assertEqual("second\n", path.read_text())
            token = base64.b64encode(bytes(range(32))).decode()
            path.write_text(token, encoding="utf-16")
            self.assertEqual(token, read_key_token(path))

    def test_pairing_hash_is_stable(self) -> None:
        self.assertEqual(64, len(pairing_hash("token", "A1B2C3D4")))

    def test_firefox_patterns_cover_apex_and_subdomains(self) -> None:
        patterns = firefox_patterns("example.com")
        self.assertIn("*://example.com/*", patterns)
        self.assertIn("*://*.example.com/*", patterns)
        self.assertEqual(["*://*/*"], firefox_patterns("*"))

    def test_unique_keeps_single_element_groups_separate(self) -> None:
        self.assertEqual(["a.example", "x.example", "y.example"], unique(["a.example"], ["a.example"], ["x.example", "y.example"]))
        self.assertEqual([], unique([], [""]))


class SourceTests(unittest.TestCase):
    def test_all_python_sources_compile(self) -> None:
        for path in [*SOURCE.glob("*.py"), *SOURCE.glob("*.pyw"), *Path(__file__).parent.glob("*.py")]:
            with self.subTest(path=path):
                py_compile.compile(str(path), doraise=True)


if __name__ == "__main__":
    unittest.main()
