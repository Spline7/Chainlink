"""Windows integration for Chainlink: registry policy, drives, tasks, and ACLs."""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
import xml.sax.saxutils
from ctypes import wintypes
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from chainlink_core import (
    atomic_write_text,
    firefox_patterns,
    pairing_hash,
    read_blocklist,
    read_key_token,
    unique,
)

if os.name != "nt":  # pragma: no cover - imported only on Windows in production
    raise RuntimeError("windows_support is available only on Windows")

import winreg  # noqa: E402

APP_DIR = Path(os.environ["ProgramData"]) / "Chainlink"
PAIR_FILE = APP_DIR / "pair.txt"
BLOCKLIST_FILE = APP_DIR / "blocklist.txt"
BASELINE_FILE = APP_DIR / "policy-baseline.json"
LOG_FILE = APP_DIR / "log.txt"
STATUS_FILE = APP_DIR / "status.txt"
PID_FILE = APP_DIR / "watchdog.pid"
TASK_NAME = r"\Chainlink"
KEY_RELATIVE_PATH = Path("Chainlink") / "chainlink.key"

CHROMIUM = (
    ("Chrome", r"SOFTWARE\Policies\Google\Chrome", "IncognitoModeAvailability", "BrowserAddPersonEnabled"),
    ("Edge", r"SOFTWARE\Policies\Microsoft\Edge", "InPrivateModeAvailability", "BrowserAddProfileEnabled"),
    ("Brave", r"SOFTWARE\Policies\BraveSoftware\Brave", "IncognitoModeAvailability", "BrowserAddPersonEnabled"),
)
FIREFOX = r"SOFTWARE\Policies\Mozilla\Firefox"


def system_executable(name: str) -> Path:
    return Path(os.environ["SystemRoot"]) / "System32" / name


def run_checked(arguments: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(arguments, check=True, text=True, capture_output=True, **kwargs)


def is_admin() -> bool:
    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def relaunch_elevated(arguments: list[str]) -> bool:
    parameters = subprocess.list2cmdline(arguments)
    result = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, parameters, None, 0)
    return result > 32


def is_reparse_point(path: Path) -> bool:
    attributes = ctypes.windll.kernel32.GetFileAttributesW(str(path))
    if attributes == 0xFFFFFFFF:
        raise ctypes.WinError()
    return bool(attributes & 0x400)


def secure_app_directory(path: Path = APP_DIR) -> None:
    icacls = system_executable("icacls.exe")
    run_checked([str(icacls), str(path), "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"])
    run_checked([str(icacls), str(path), "/remove:g", "*S-1-5-32-545"])


def log(message: str) -> None:
    try:
        if LOG_FILE.exists() and LOG_FILE.stat().st_size > 200 * 1024:
            os.replace(LOG_FILE, LOG_FILE.with_suffix(".txt.old"))
        with LOG_FILE.open("a", encoding="utf-8") as output:
            output.write(f"{datetime.now():%Y-%m-%d %H:%M:%S}  {message}\n")
    except OSError:
        pass


def set_status(message: str) -> None:
    try:
        atomic_write_text(STATUS_FILE, message + "\n")
    except OSError:
        pass


def _open_key(path: str, access: int, create: bool = False) -> Any:
    if create:
        return winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, path, 0, access)
    return winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, access)


def value_snapshot(path: str, name: str) -> dict[str, Any]:
    try:
        with _open_key(path, winreg.KEY_READ) as key:
            value, kind = winreg.QueryValueEx(key, name)
        return {"present": True, "value": value, "kind": kind}
    except FileNotFoundError:
        return {"present": False, "value": None, "kind": None}


def list_snapshot(path: str) -> list[dict[str, Any]]:
    try:
        with _open_key(path, winreg.KEY_READ) as key:
            result = []
            index = 0
            while True:
                try:
                    name, value, kind = winreg.EnumValue(key, index)
                except OSError:
                    break
                result.append({"name": name, "value": str(value), "kind": kind})
                index += 1
            return result
    except FileNotFoundError:
        return []


def set_dword(path: str, name: str, value: int) -> None:
    with _open_key(path, winreg.KEY_SET_VALUE, create=True) as key:
        winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, value)


def replace_list(path: str, values: list[str]) -> None:
    try:
        with _open_key(path, winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
            names = [winreg.EnumValue(key, index)[0] for index in range(winreg.QueryInfoKey(key)[1])]
            for name in names:
                winreg.DeleteValue(key, name)
    except FileNotFoundError:
        if not values:
            return
    if values:
        with _open_key(path, winreg.KEY_SET_VALUE, create=True) as key:
            for index, value in enumerate(values, 1):
                winreg.SetValueEx(key, str(index), 0, winreg.REG_SZ, value)


def _get(mapping: Any, *names: str, default: Any = None) -> Any:
    if isinstance(mapping, dict):
        for name in names:
            if name in mapping:
                return mapping[name]
    return default


def capture_baseline() -> None:
    if BASELINE_FILE.exists():
        return
    chromium: dict[str, Any] = {}
    for browser, path, private, add_profile in CHROMIUM:
        properties = {
            name: value_snapshot(path, name)
            for name in (private, "BrowserGuestModeEnabled", add_profile, "TorDisabled")
        }
        chromium[browser] = {"properties": properties, "blocklist": list_snapshot(path + r"\URLBlocklist")}
    baseline = {
        "version": 2,
        "chromium": chromium,
        "firefox": {
            "properties": {"DisablePrivateBrowsing": value_snapshot(FIREFOX, "DisablePrivateBrowsing")},
            "blocklist": list_snapshot(FIREFOX + r"\WebsiteFilter\Block"),
        },
    }
    atomic_write_text(BASELINE_FILE, json.dumps(baseline, indent=2) + "\n")
    log("Captured pre-install browser policy baseline.")


def read_baseline() -> dict[str, Any] | None:
    try:
        baseline = json.loads(BASELINE_FILE.read_text(encoding="utf-8-sig"))
        version = _get(baseline, "version", "Version")
        if version not in {1, 2}:
            raise ValueError("unsupported baseline version")
        chromium = _get(baseline, "chromium", "Chromium")
        firefox = _get(baseline, "firefox", "Firefox")
        if not isinstance(chromium, dict) or not isinstance(firefox, dict):
            raise ValueError("baseline is missing browser sections")
        for browser, _path, private, add_profile in CHROMIUM:
            item = _get(chromium, browser)
            if not isinstance(item, dict) or not isinstance(_get(item, "blocklist", "Blocklist"), list):
                raise ValueError(f"baseline is missing {browser} blocklist state")
            properties = _get(item, "properties", "Properties")
            if not isinstance(properties, dict):
                raise ValueError(f"baseline is missing {browser} property state")
            for name in (private, "BrowserGuestModeEnabled", add_profile, "TorDisabled"):
                snapshot = _get(properties, name)
                if not isinstance(snapshot, dict) or _get(snapshot, "present", "Present") is None:
                    raise ValueError(f"baseline is missing {browser}/{name}")
        if not isinstance(_get(firefox, "blocklist", "Blocklist"), list):
            raise ValueError("baseline is missing Firefox blocklist state")
        firefox_properties = _get(firefox, "properties", "Properties")
        firefox_snapshot = _get(firefox_properties, "DisablePrivateBrowsing")
        if not isinstance(firefox_snapshot, dict) or _get(firefox_snapshot, "present", "Present") is None:
            raise ValueError("baseline is missing Firefox private-browsing state")
        return baseline
    except (OSError, ValueError, TypeError) as error:
        log(f"Policy baseline is unavailable or invalid; unrelated policies will be preserved: {error}")
        return None


def _baseline_browser(baseline: dict[str, Any] | None, browser: str) -> dict[str, Any] | None:
    if not baseline:
        return None
    chromium = _get(baseline, "chromium", "Chromium", default={})
    return _get(chromium, browser)


def _baseline_firefox(baseline: dict[str, Any] | None) -> dict[str, Any] | None:
    return _get(baseline, "firefox", "Firefox") if baseline else None


def _snapshot_values(snapshot: Any) -> list[str]:
    return [str(_get(item, "value", "Value", default="")) for item in snapshot or [] if _get(item, "value", "Value", default="")]


def _property_snapshot(properties: Any, name: str) -> dict[str, Any] | None:
    return _get(properties, name) if properties else None


def _normalize_snapshot(snapshot: dict[str, Any]) -> tuple[bool, Any, int | None]:
    present = bool(_get(snapshot, "present", "Present", default=False))
    value = _get(snapshot, "value", "Value")
    kind = _get(snapshot, "kind", "Kind")
    if isinstance(kind, str):
        kind = getattr(winreg, "REG_" + kind.upper(), None)
    return present, value, kind


def restore_property(path: str, name: str, snapshot: dict[str, Any] | None, managed: int) -> None:
    if not snapshot:
        return
    current = value_snapshot(path, name)
    if current["present"] and current["value"] != managed:
        return
    present, value, kind = _normalize_snapshot(snapshot)
    if present and kind is not None:
        with _open_key(path, winreg.KEY_SET_VALUE, create=True) as key:
            winreg.SetValueEx(key, name, 0, kind, value)
    elif current["present"]:
        with _open_key(path, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, name)


def installed_blocklist() -> list[str]:
    try:
        if not BLOCKLIST_FILE.is_file():
            raise FileNotFoundError("installed blocklist is missing")
        return read_blocklist(BLOCKLIST_FILE)
    except (OSError, ValueError) as error:
        log(f"Installed blocklist is invalid; blocking all URLs as a fail-safe: {error}")
        return ["*"]


def _unmanaged(path: str, managed: list[str]) -> list[str]:
    managed_set = set(managed)
    return [item["value"] for item in list_snapshot(path) if item["value"] not in managed_set]


def set_lock() -> None:
    entries = installed_blocklist()
    baseline = read_baseline()
    for browser, path, private, add_profile in CHROMIUM:
        block_path = path + r"\URLBlocklist"
        base = _baseline_browser(baseline, browser)
        base_values = _snapshot_values(_get(base, "blocklist", "Blocklist", default=[])) if base else []
        replace_list(block_path, unique(base_values + _unmanaged(block_path, entries) + entries))
        set_dword(path, private, 1)
        set_dword(path, "BrowserGuestModeEnabled", 0)
        set_dword(path, add_profile, 0)
        if browser == "Brave":
            set_dword(path, "TorDisabled", 1)

    patterns = [pattern for entry in entries for pattern in firefox_patterns(entry)]
    firefox_path = FIREFOX + r"\WebsiteFilter\Block"
    base = _baseline_firefox(baseline)
    base_values = _snapshot_values(_get(base, "blocklist", "Blocklist", default=[])) if base else []
    replace_list(firefox_path, unique(base_values + _unmanaged(firefox_path, patterns) + patterns))
    set_dword(FIREFOX, "DisablePrivateBrowsing", 1)


def remove_lock() -> None:
    entries = installed_blocklist()
    baseline = read_baseline()
    if baseline is None:
        raise RuntimeError("cannot restore browser policy without a valid pre-install baseline")
    for browser, path, private, add_profile in CHROMIUM:
        block_path = path + r"\URLBlocklist"
        remaining = _unmanaged(block_path, entries)
        base = _baseline_browser(baseline, browser)
        if base:
            remaining = unique(_snapshot_values(_get(base, "blocklist", "Blocklist", default=[])) + remaining)
        replace_list(block_path, remaining)
        if base:
            properties = _get(base, "properties", "Properties", default={})
            restore_property(path, private, _property_snapshot(properties, private), 1)
            restore_property(path, "BrowserGuestModeEnabled", _property_snapshot(properties, "BrowserGuestModeEnabled"), 0)
            restore_property(path, add_profile, _property_snapshot(properties, add_profile), 0)
            if browser == "Brave":
                restore_property(path, "TorDisabled", _property_snapshot(properties, "TorDisabled"), 1)

    patterns = [pattern for entry in entries for pattern in firefox_patterns(entry)]
    firefox_path = FIREFOX + r"\WebsiteFilter\Block"
    remaining = _unmanaged(firefox_path, patterns)
    base = _baseline_firefox(baseline)
    if base:
        remaining = unique(_snapshot_values(_get(base, "blocklist", "Blocklist", default=[])) + remaining)
    replace_list(firefox_path, remaining)
    if base:
        properties = _get(base, "properties", "Properties", default={})
        restore_property(FIREFOX, "DisablePrivateBrowsing", _property_snapshot(properties, "DisablePrivateBrowsing"), 1)


def lock_intact() -> bool:
    entries = installed_blocklist()
    try:
        for browser, path, private, add_profile in CHROMIUM:
            if value_snapshot(path, private)["value"] != 1:
                return False
            if value_snapshot(path, "BrowserGuestModeEnabled")["value"] != 0:
                return False
            if value_snapshot(path, add_profile)["value"] != 0:
                return False
            if browser == "Brave" and value_snapshot(path, "TorDisabled")["value"] != 1:
                return False
            actual = {item["value"] for item in list_snapshot(path + r"\URLBlocklist")}
            if not set(entries).issubset(actual):
                return False
        return True
    except OSError:
        return False


def volume_serial(root: str) -> str:
    serial = wintypes.DWORD()
    maximum = wintypes.DWORD()
    flags = wintypes.DWORD()
    if not ctypes.windll.kernel32.GetVolumeInformationW(root, None, 0, ctypes.byref(serial), ctypes.byref(maximum), ctypes.byref(flags), None, 0):
        raise ctypes.WinError()
    return f"{serial.value:08X}"


def find_key() -> Path | None:
    if not PAIR_FILE.is_file():
        return None
    expected = {line.strip().lower() for line in PAIR_FILE.read_text(encoding="utf-8-sig").splitlines() if len(line.strip()) == 64}
    mask = ctypes.windll.kernel32.GetLogicalDrives()
    for index in range(26):
        if not mask & (1 << index):
            continue
        root = f"{chr(65 + index)}:\\"
        drive_type = ctypes.windll.kernel32.GetDriveTypeW(root)
        if drive_type not in {2, 3}:
            continue
        try:
            token = read_key_token(Path(root) / KEY_RELATIVE_PATH)
            if pairing_hash(token, volume_serial(root)) in expected:
                return Path(root)
        except (OSError, ValueError):
            continue
    return None


def validate_usb_blocklist(root: Path) -> Path:
    source = root / "Chainlink" / "blocklist.txt"
    read_blocklist(source)
    return source


def sync_blocklist(root: Path) -> None:
    source = validate_usb_blocklist(root)
    data = source.read_bytes()
    if not BLOCKLIST_FILE.exists() or BLOCKLIST_FILE.read_bytes() != data:
        temporary = APP_DIR / f".blocklist-{os.getpid()}.tmp"
        try:
            temporary.write_bytes(data)
            os.replace(temporary, BLOCKLIST_FILE)
        finally:
            temporary.unlink(missing_ok=True)
        log("Blocklist updated from USB.")


def task_xml(python_executable: Path, watchdog: Path) -> str:
    command = xml.sax.saxutils.escape(str(python_executable))
    arguments = xml.sax.saxutils.escape(subprocess.list2cmdline(["-B", str(watchdog)]))
    start = datetime.now(timezone.utc).astimezone().replace(microsecond=0).isoformat()
    return f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Chainlink watchdog</Description><URI>{TASK_NAME}</URI></RegistrationInfo>
  <Triggers>
    <BootTrigger><Enabled>true</Enabled></BootTrigger>
    <TimeTrigger><Repetition><Interval>PT1M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition><StartBoundary>{start}</StartBoundary><Enabled>true</Enabled></TimeTrigger>
  </Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><StartWhenAvailable>true</StartWhenAvailable><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure></Settings>
  <Actions Context="Author"><Exec><Command>{command}</Command><Arguments>{arguments}</Arguments></Exec></Actions>
</Task>'''


def query_task_xml() -> str | None:
    result = subprocess.run([str(system_executable("schtasks.exe")), "/Query", "/TN", TASK_NAME, "/XML"], text=True, capture_output=True)
    return result.stdout if result.returncode == 0 else None


def genuine_task() -> bool:
    xml = query_task_xml()
    return bool(xml and any(str(APP_DIR / name).lower() in xml.lower() for name in ("watchdog.py", "watchdog.ps1")))


def create_task(python_executable: Path, watchdog: Path) -> None:
    xml_path = APP_DIR / "task.xml"
    try:
        xml_path.write_text(task_xml(python_executable, watchdog), encoding="utf-16")
        run_checked([str(system_executable("schtasks.exe")), "/Create", "/TN", TASK_NAME, "/XML", str(xml_path), "/F"])
    finally:
        xml_path.unlink(missing_ok=True)
    run_checked([str(system_executable("schtasks.exe")), "/Run", "/TN", TASK_NAME])


def stop_task() -> None:
    subprocess.run([str(system_executable("schtasks.exe")), "/End", "/TN", TASK_NAME], capture_output=True)


def delete_task() -> None:
    result = subprocess.run([str(system_executable("schtasks.exe")), "/Delete", "/TN", TASK_NAME, "/F"], text=True, capture_output=True)
    if result.returncode and query_task_xml() is not None:
        raise RuntimeError(result.stderr.strip() or "could not delete scheduled task")
