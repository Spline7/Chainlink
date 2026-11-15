"""Windows integration for Chainlink: registry policy, drives, tasks, and ACLs."""

from __future__ import annotations

import ctypes
import json
import msvcrt
import os
import re
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as element_tree
import xml.sax.saxutils
from ctypes import wintypes
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO

from chainlink_core import (
    atomic_write_bytes,
    atomic_write_text,
    firefox_patterns,
    pairing_hash,
    parse_blocklist_bytes,
    read_blocklist,
    read_key_token,
    unique,
)

if os.name != "nt":  # pragma: no cover - imported only on Windows in production
    raise RuntimeError("windows_support is available only on Windows")

import winreg  # noqa: E402

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)
ole32 = ctypes.WinDLL("ole32", use_last_error=True)

INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
ERROR_SHARING_VIOLATION = 32
ERROR_ALREADY_EXISTS = 183

kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
kernel32.CreateFileW.restype = wintypes.HANDLE
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p]
kernel32.CreateDirectoryW.restype = wintypes.BOOL
kernel32.GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
kernel32.GetFileAttributesW.restype = wintypes.DWORD
kernel32.GetWindowsDirectoryW.argtypes = [wintypes.LPWSTR, wintypes.UINT]
kernel32.GetWindowsDirectoryW.restype = wintypes.UINT
kernel32.GetVolumeInformationW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR, wintypes.DWORD]
kernel32.GetVolumeInformationW.restype = wintypes.BOOL
kernel32.GetLogicalDrives.restype = wintypes.DWORD
kernel32.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
kernel32.GetDriveTypeW.restype = wintypes.UINT
kernel32.LocalFree.argtypes = [ctypes.c_void_p]
kernel32.LocalFree.restype = ctypes.c_void_p
advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wintypes.BOOL
advapi32.GetNamedSecurityInfoW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
advapi32.SetNamedSecurityInfoW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
advapi32.GetSecurityDescriptorDacl.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL), ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)]
advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
shell32.IsUserAnAdmin.restype = wintypes.BOOL
shell32.ShellExecuteW.argtypes = [wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_int]
shell32.ShellExecuteW.restype = wintypes.HINSTANCE
ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]
ole32.CoTaskMemFree.restype = None


class _Guid(ctypes.Structure):
    _fields_ = [
        ("data1", wintypes.DWORD),
        ("data2", wintypes.WORD),
        ("data3", wintypes.WORD),
        ("data4", ctypes.c_ubyte * 8),
    ]


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [
        ("length", wintypes.DWORD),
        ("security_descriptor", ctypes.c_void_p),
        ("inherit_handle", wintypes.BOOL),
    ]


def known_folder(identifier: str) -> Path:
    guid = _Guid.from_buffer_copy(uuid.UUID(identifier).bytes_le)
    raw = ctypes.c_void_p()
    function = shell32.SHGetKnownFolderPath
    function.argtypes = [ctypes.POINTER(_Guid), wintypes.DWORD, wintypes.HANDLE, ctypes.POINTER(ctypes.c_void_p)]
    function.restype = ctypes.c_long
    result = function(ctypes.byref(guid), 0, None, ctypes.byref(raw))
    try:
        if result != 0 or not raw.value:
            raise OSError(f"SHGetKnownFolderPath failed with HRESULT 0x{result & 0xFFFFFFFF:08X}")
        return Path(ctypes.wstring_at(raw.value))
    finally:
        ole32.CoTaskMemFree(raw)


def _program_files_roots() -> tuple[Path, ...]:
    roots = []
    for identifier in (
        "905e63b6-c1bf-494e-b29c-65b732d3d21a",
        "7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e",
    ):
        try:
            roots.append(known_folder(identifier).resolve())
        except OSError:
            continue
    if not roots:
        raise OSError("Windows did not provide a trusted Program Files directory")
    return tuple(dict.fromkeys(roots))


PROGRAM_DATA = known_folder("62ab5d82-fdc1-4dc3-a9dd-070d1d495d97")
PROGRAM_FILES_ROOTS = _program_files_roots()
APP_DIR = PROGRAM_DATA / "Chainlink"
TASK_NAME = r"\Chainlink"
KEY_RELATIVE_PATH = Path("Chainlink") / "chainlink.key"
MAX_USB_BLOCKLIST_BYTES = 1024 * 1024

# Browser policy lives here. The tests point these at a scratch key under HKEY_CURRENT_USER.
POLICY_HIVE = winreg.HKEY_LOCAL_MACHINE
POLICY_ROOT = r"SOFTWARE\Policies"
_VIEW = winreg.KEY_WOW64_64KEY  # the browsers read the 64-bit view even if this Python is 32-bit


@dataclass(frozen=True)
class Target:
    name: str
    key: str  # relative to POLICY_ROOT
    list_key: str  # relative to key
    values: dict[str, int]  # policy values Chainlink sets while locked
    extra: tuple[str, ...] = ()  # recorded in the baseline for compatibility, never written
    firefox: bool = False
    baseline_names: tuple[str, ...] = field(init=False, default=())

    def __post_init__(self) -> None:
        object.__setattr__(self, "baseline_names", (*self.values, *self.extra))


TARGETS = (
    Target("Chrome", r"Google\Chrome", "URLBlocklist", {"IncognitoModeAvailability": 1, "BrowserGuestModeEnabled": 0, "BrowserAddPersonEnabled": 0}, ("TorDisabled",)),
    Target("Edge", r"Microsoft\Edge", "URLBlocklist", {"InPrivateModeAvailability": 1, "BrowserGuestModeEnabled": 0, "BrowserAddProfileEnabled": 0}, ("TorDisabled",)),
    Target("Brave", r"BraveSoftware\Brave", "URLBlocklist", {"IncognitoModeAvailability": 1, "BrowserGuestModeEnabled": 0, "BrowserAddPersonEnabled": 0, "TorDisabled": 1}),
    Target("Firefox", r"Mozilla\Firefox", r"WebsiteFilter\Block", {"DisablePrivateBrowsing": 1}, firefox=True),
)


def app_file(name: str) -> Path:
    return APP_DIR / name


def system_executable(name: str) -> Path:
    buffer = ctypes.create_unicode_buffer(32768)
    length = kernel32.GetWindowsDirectoryW(buffer, len(buffer))
    if not length or length >= len(buffer):
        raise ctypes.WinError(ctypes.get_last_error())
    return Path(buffer.value) / "System32" / name


def is_admin() -> bool:
    return bool(shell32.IsUserAnAdmin())


def relaunch_elevated(executable: Path, arguments: list[str]) -> bool:
    parameters = subprocess.list2cmdline(arguments)
    result = shell32.ShellExecuteW(None, "runas", str(executable), parameters, None, 1)  # SW_SHOWNORMAL
    return (result or 0) > 32


def is_reparse_point(path: Path) -> bool:
    attributes = kernel32.GetFileAttributesW(str(path))
    if attributes == 0xFFFFFFFF:
        raise ctypes.WinError(ctypes.get_last_error())
    return bool(attributes & 0x400)


# ---------------------------------------------------------------- protected program directory

# Owner: Administrators. Protected DACL: SYSTEM and Administrators only, inherited by children.
PROTECTED_SDDL = "O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
_TRUSTED = {"SY", "BA", "S-1-5-18", "S-1-5-32-544"}
_OWNER, _DACL, _PROTECTED_DACL = 0x1, 0x4, 0x80000000
_SE_FILE_OBJECT = 1


def _security_descriptor(sddl: str) -> ctypes.c_void_p:
    descriptor = ctypes.c_void_p()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    return descriptor


def path_sddl(path: Path) -> str:
    """Owner and DACL of a file or directory in SDDL form, e.g. O:BAD:P(A;OICI;FA;;;SY)."""
    descriptor = ctypes.c_void_p()
    error = advapi32.GetNamedSecurityInfoW(str(path), _SE_FILE_OBJECT, _OWNER | _DACL, None, None, None, None, ctypes.byref(descriptor))
    if error:
        raise ctypes.WinError(error)
    text = ctypes.c_void_p()
    try:
        if not advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, 1, _OWNER | _DACL, ctypes.byref(text), None):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return ctypes.wstring_at(text.value)
        finally:
            kernel32.LocalFree(text)
    finally:
        kernel32.LocalFree(descriptor)


def has_trusted_owner(path: Path) -> bool:
    match = re.match(r"O:([A-Z0-9-]+?)(?:G:|D:|$)", path_sddl(path))
    return bool(match and match.group(1) in _TRUSTED)


def is_protected_directory(path: Path) -> bool:
    """True for a real directory owned by SYSTEM or Administrators that grants access to nobody else."""
    if not path.is_dir() or is_reparse_point(path):
        return False
    match = re.fullmatch(r"O:(?P<owner>[A-Z0-9-]+?)D:(?P<flags>[A-Z]*)(?P<aces>(?:\([^)]*\))*)", path_sddl(path))
    if not match or match.group("owner") not in _TRUSTED or "P" not in match.group("flags"):
        return False
    for ace in re.findall(r"\(([^)]*)\)", match.group("aces")):
        parts = ace.split(";")
        if len(parts) != 6 or parts[0] != "A" or parts[5] not in _TRUSTED:
            return False
    return True


def _rights_are_read_only(rights: str) -> bool:
    """True when an SDDL rights field grants nothing beyond reading and executing."""
    read_execute = 0x1200A9  # FILE_GENERIC_READ | FILE_GENERIC_EXECUTE
    if rights.lower().startswith("0x"):
        try:
            return int(rights, 16) & ~read_execute == 0
        except ValueError:
            return False
    codes = [rights[index:index + 2] for index in range(0, len(rights), 2)]
    return bool(codes) and all(code in {"FR", "FX", "GR", "GX"} for code in codes)


def is_trusted_directory(path: Path) -> bool:
    """True when nobody but SYSTEM and Administrators could have put or changed anything here.

    The directory and everything in it are owned by them, nothing in it is a link, and any
    other account has at most read access (the original release let Users read the folder).
    Uninstall and repair check this before they read state from, or run code in, an existing
    folder.
    """
    if not path.is_dir() or is_reparse_point(path):
        return False
    match = re.fullmatch(r"O:(?P<owner>[A-Z0-9-]+?)D:(?P<flags>[A-Z]*)(?P<aces>(?:\([^)]*\))*)", path_sddl(path))
    if not match or match.group("owner") not in _TRUSTED:
        return False
    for ace in re.findall(r"\(([^)]*)\)", match.group("aces")):
        parts = ace.split(";")
        if len(parts) != 6:
            return False
        if parts[0] == "D" or parts[5] in _TRUSTED:
            continue
        if parts[0] != "A" or not _rights_are_read_only(parts[2]):
            return False
    for directory, directories, files in os.walk(path):
        for name in (*directories, *files):
            child = Path(directory) / name
            try:
                if is_reparse_point(child) or not has_trusted_owner(child):
                    return False
            except FileNotFoundError:
                continue  # a temporary file that has since been renamed
    return True


def create_protected_directory(path: Path) -> None:
    """Create the directory with its final owner and ACL in one call.

    There is no moment at which another account can put files into it, and the call fails if
    anything already exists at the path.
    """
    descriptor = _security_descriptor(PROTECTED_SDDL)
    try:
        attributes = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False)
        if not kernel32.CreateDirectoryW(str(path), ctypes.byref(attributes)):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel32.LocalFree(descriptor)
    if not is_protected_directory(path) or any(path.iterdir()):
        raise RuntimeError(f"{path} could not be created with protected permissions")


def protect_existing_directory(path: Path) -> None:
    """Re-apply the protected ACL to the directory of an existing installation (repair, upgrade)."""
    if not path.is_dir() or is_reparse_point(path):
        raise RuntimeError(f"{path} must be a real directory, not a file, junction, or symbolic link")
    if not has_trusted_owner(path):
        raise RuntimeError(f"{path} is owned by an account other than SYSTEM or Administrators; uninstall Chainlink, delete that folder, and link again")
    descriptor = _security_descriptor(PROTECTED_SDDL)
    try:
        present, defaulted, dacl = wintypes.BOOL(), wintypes.BOOL(), ctypes.c_void_p()
        if not advapi32.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)):
            raise ctypes.WinError(ctypes.get_last_error())
        error = advapi32.SetNamedSecurityInfoW(str(path), _SE_FILE_OBJECT, _DACL | _PROTECTED_DACL, None, None, dacl, None)
        if error:
            raise ctypes.WinError(error)
    finally:
        kernel32.LocalFree(descriptor)
    if not is_protected_directory(path):
        raise RuntimeError(f"could not secure {path}")
    for directory, directories, files in os.walk(path):
        for name in (*directories, *files):
            child = Path(directory) / name
            try:
                if is_reparse_point(child):
                    raise RuntimeError(f"{child} is a link; remove it and try again")
                if not has_trusted_owner(child):
                    raise RuntimeError(f"{child} is owned by an account other than SYSTEM or Administrators; remove it and try again")
            except FileNotFoundError:
                continue  # a temporary file that has since been renamed


# ---------------------------------------------------------------- watchdog lock

# The watchdog keeps this file open for as long as it runs. Install and uninstall take the same
# lock, which both proves that no watchdog is running and stops a new one from starting meanwhile.
# The file lives in the protected program directory, so other accounts cannot hold it.


def open_watchdog_lock(path: Path) -> BinaryIO | None:
    """Take the lock and return it (close it to release), or None if another process holds it."""
    generic_read_write, share_read, open_always, normal = 0xC0000000, 0x1, 4, 0x80
    handle = kernel32.CreateFileW(str(path), generic_read_write, share_read, None, open_always, normal, None)
    if handle is None or handle == INVALID_HANDLE_VALUE:
        error = ctypes.get_last_error()
        if error == ERROR_SHARING_VIOLATION:
            return None
        raise ctypes.WinError(error)
    try:
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
    except OSError:
        kernel32.CloseHandle(handle)
        raise
    lock = os.fdopen(descriptor, "r+b", buffering=0)
    lock.truncate(0)
    lock.write(str(os.getpid()).encode("ascii"))
    return lock


def watchdog_lock_owner(path: Path) -> int:
    """Process id recorded by the current lock holder, or 0."""
    try:
        text = path.read_bytes().decode("ascii").strip()
        return int(text) if re.fullmatch(r"[0-9]{1,10}", text) else 0
    except (OSError, ValueError):
        return 0


def _run_hidden(arguments: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(arguments, capture_output=True, text=True, errors="replace", creationflags=subprocess.CREATE_NO_WINDOW)


def terminate_watchdog_process(process_id: int) -> None:
    """End a leftover watchdog. taskkill only acts if that process id really is a Python process."""
    for image in ("python.exe", "pythonw.exe", "powershell.exe"):
        _run_hidden([str(system_executable("taskkill.exe")), "/F", "/FI", f"PID eq {process_id}", "/FI", f"IMAGENAME eq {image}"])


def stop_legacy_watchdogs() -> None:
    """End watchdogs of the original PowerShell release, which took no lock."""
    if not app_file("watchdog.ps1").is_file():
        return
    script = (
        "Get-CimInstance Win32_Process -Filter \"Name='powershell.exe'\" | "
        "Where-Object { $_.CommandLine -like '*Chainlink\\watchdog.ps1*' } | "
        "ForEach-Object { try { Invoke-CimMethod -InputObject $_ -MethodName Terminate -ErrorAction Stop | Out-Null } catch { } }"
    )
    _run_hidden([str(system_executable(r"WindowsPowerShell\v1.0\powershell.exe")), "-NoProfile", "-NonInteractive", "-Command", script])


def uninstall_marker() -> Path:
    """Written by uninstall just before it deletes the program folder; tells a watchdog to exit."""
    return app_file("uninstalling")


def stop_watchdog(timeout: float = 15.0) -> BinaryIO | None:
    """Stop the watchdog and return the held lock, or None when there is no program directory."""
    task = query_task_xml()
    if task and (task_xml_is_genuine(task) or task_xml_references_app_dir(task)):
        stop_task()
    stop_legacy_watchdogs()
    if not APP_DIR.is_dir():
        return None
    lock_path = app_file("watchdog.lock")
    deadline = time.monotonic() + timeout
    while True:
        lock = open_watchdog_lock(lock_path)
        if lock is not None:
            return lock
        owner = watchdog_lock_owner(lock_path)
        if owner and owner != os.getpid():
            terminate_watchdog_process(owner)
        if time.monotonic() > deadline:
            raise RuntimeError("the Chainlink watchdog is still running and could not be stopped; wait a minute and try again")
        time.sleep(0.3)


# ---------------------------------------------------------------- logging and status

_last_once_message = ""


def log(message: str, once: bool = False) -> None:
    """Append to the log. With once=True a message that repeats every cycle is written one time."""
    global _last_once_message
    if once and message == _last_once_message:
        return
    _last_once_message = message
    try:
        log_file = app_file("log.txt")
        if log_file.exists() and log_file.stat().st_size > 200 * 1024:
            os.replace(log_file, app_file("log.txt.old"))
        with log_file.open("a", encoding="utf-8") as output:
            output.write(f"{datetime.now():%Y-%m-%d %H:%M:%S}  {message}\n")
    except OSError:
        pass


def set_status(message: str) -> None:
    try:
        atomic_write_text(app_file("status.txt"), message + "\n")
    except OSError:
        pass


# ---------------------------------------------------------------- registry helpers

_KINDS = {"DWord": winreg.REG_DWORD, "QWord": winreg.REG_QWORD, "String": winreg.REG_SZ, "ExpandString": winreg.REG_EXPAND_SZ, "MultiString": winreg.REG_MULTI_SZ}
_RESTORABLE = set(_KINDS.values())


def _policy_path(*parts: str) -> str:
    return "\\".join((POLICY_ROOT, *parts))


def _open_key(path: str, access: int) -> Any:
    return winreg.OpenKey(POLICY_HIVE, path, 0, access | _VIEW)


def _create_key(path: str) -> Any:
    return winreg.CreateKeyEx(POLICY_HIVE, path, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE | _VIEW)


def value_snapshot(path: str, name: str) -> dict[str, Any]:
    try:
        with _open_key(path, winreg.KEY_READ) as key:
            value, kind = winreg.QueryValueEx(key, name)
        if isinstance(value, bytes):
            value = list(value)
        return {"present": True, "value": value, "kind": kind}
    except FileNotFoundError:
        return {"present": False, "value": None, "kind": None}


def list_snapshot(path: str) -> list[dict[str, Any]]:
    try:
        with _open_key(path, winreg.KEY_READ) as key:
            result = []
            for index in range(winreg.QueryInfoKey(key)[1]):
                name, value, kind = winreg.EnumValue(key, index)
                result.append({"name": name, "value": str(value), "kind": kind})
            return result
    except FileNotFoundError:
        return []


def list_values(path: str) -> list[str]:
    return [item["value"] for item in list_snapshot(path)]


def write_list(path: str, values: list[str]) -> None:
    """Write the list as values "1".."N" in place, then drop leftovers. An empty list removes the key."""
    if not values:
        try:
            with _open_key(path, winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
                for name in [winreg.EnumValue(key, index)[0] for index in range(winreg.QueryInfoKey(key)[1])]:
                    winreg.DeleteValue(key, name)
        except FileNotFoundError:
            return
        remove_empty_keys(path)
        return
    with _create_key(path) as key:
        wanted = set()
        for index, value in enumerate(values, 1):
            winreg.SetValueEx(key, str(index), 0, winreg.REG_SZ, value)
            wanted.add(str(index))
        for name in [winreg.EnumValue(key, index)[0] for index in range(winreg.QueryInfoKey(key)[1])]:
            if name not in wanted:
                winreg.DeleteValue(key, name)


def remove_empty_keys(path: str) -> None:
    """Delete the key if it is empty, then its parents likewise, stopping below POLICY_ROOT."""
    prefix = POLICY_ROOT.lower() + "\\"
    while path.lower().startswith(prefix):
        try:
            with _open_key(path, winreg.KEY_READ) as key:
                subkeys, values, _ = winreg.QueryInfoKey(key)
            if subkeys or values:
                return
            winreg.DeleteKeyEx(POLICY_HIVE, path, _VIEW, 0)
        except FileNotFoundError:
            pass
        path = path.rpartition("\\")[0]


def _get(mapping: Any, *names: str, default: Any = None) -> Any:
    if isinstance(mapping, dict):
        for name in names:
            if name in mapping:
                return mapping[name]
    return default


# ---------------------------------------------------------------- policy baseline

def capture_baseline_data() -> dict[str, Any]:
    sections: dict[str, Any] = {}
    for target in TARGETS:
        key = _policy_path(target.key)
        sections[target.name] = {
            "properties": {name: value_snapshot(key, name) for name in target.baseline_names},
            "blocklist": list_snapshot(_policy_path(target.key, target.list_key)),
        }
    firefox = sections.pop("Firefox")
    return {"version": 2, "chromium": sections, "firefox": firefox}


def capture_baseline() -> None:
    path = app_file("policy-baseline.json")
    if path.exists():
        return
    atomic_write_text(path, json.dumps(capture_baseline_data(), indent=2) + "\n")
    log("Captured pre-install browser policy baseline.")


def baseline_file_is_valid() -> bool:
    try:
        return baseline_is_valid(json.loads(app_file("policy-baseline.json").read_text(encoding="utf-8-sig")))
    except (OSError, ValueError, TypeError):
        return False


def _baseline_section(baseline: Any, name: str) -> Any:
    if name == "Firefox":
        return _get(baseline, "firefox", "Firefox")
    return _get(_get(baseline, "chromium", "Chromium"), name)


def baseline_is_valid(baseline: Any) -> bool:
    """True when a parsed baseline (this version's or the PowerShell one) has everything we rely on."""
    if _get(baseline, "version", "Version") not in (1, 2):
        return False
    for target in TARGETS:
        section = _baseline_section(baseline, target.name)
        if not isinstance(_get(section, "blocklist", "Blocklist"), list):
            return False
        properties = _get(section, "properties", "Properties")
        for name in target.values:
            if not isinstance(_get(_get(properties, name), "present", "Present"), bool):
                return False
    return True


def read_baseline() -> dict[str, Any] | None:
    try:
        baseline = json.loads(app_file("policy-baseline.json").read_text(encoding="utf-8-sig"))
        if not baseline_is_valid(baseline):
            raise ValueError("unsupported or incomplete baseline")
        return baseline
    except (OSError, ValueError, TypeError) as error:
        log(f"Policy baseline is unreadable; Chainlink will remove only its own values: {error}", once=True)
        return None


def _baseline_list(baseline: Any, name: str) -> list[str]:
    items = _get(_baseline_section(baseline, name), "blocklist", "Blocklist", default=[])
    return [str(value) for value in (_get(item, "value", "Value") for item in items) if value]


def _baseline_value(baseline: Any, target: Target, name: str) -> dict[str, Any] | None:
    snapshot = _get(_get(_baseline_section(baseline, target.name), "properties", "Properties"), name)
    return snapshot if isinstance(snapshot, dict) else None


def _is_managed(snapshot: dict[str, Any], managed: int) -> bool:
    return bool(snapshot["present"]) and snapshot["kind"] == winreg.REG_DWORD and snapshot["value"] == managed


def restore_value(path: str, name: str, snapshot: dict[str, Any] | None, managed: int) -> None:
    """Put one policy value back the way it was before Chainlink, unless someone changed it since.

    Without a baseline the value is simply removed, as the original release did.
    """
    current = value_snapshot(path, name)
    if current["present"] and not _is_managed(current, managed):
        return
    present = bool(_get(snapshot, "present", "Present", default=False))
    value = _get(snapshot, "value", "Value")
    kind = _get(snapshot, "kind", "Kind")
    if isinstance(kind, str):
        kind = _KINDS.get(kind)
    if present and kind in _RESTORABLE and value is not None:
        if kind == winreg.REG_DWORD and isinstance(value, int):
            value &= 0xFFFFFFFF  # PowerShell records large DWORDs as negative numbers
        with _create_key(path) as key:
            winreg.SetValueEx(key, name, 0, kind, value)
    elif current["present"]:
        with _open_key(path, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, name)


# ---------------------------------------------------------------- lock / unlock

def _for_target(target: Target, entries: list[str]) -> list[str]:
    if not target.firefox:
        return list(entries)
    return [pattern for entry in entries for pattern in firefox_patterns(entry)]


def apply_lock(entries: list[str], previous: list[str], baseline: Any) -> None:
    """Apply the block. `previous` are entries an earlier lock wrote; they are replaced, not kept."""
    managed_entries = unique(entries, previous)
    first_error: Exception | None = None
    for target in TARGETS:
        # A failure on one browser must not leave the others unblocked.
        try:
            list_path = _policy_path(target.key, target.list_key)
            managed = set(_for_target(target, managed_entries))
            others = [value for value in list_values(list_path) if value not in managed]
            write_list(list_path, unique(_baseline_list(baseline, target.name), others, _for_target(target, entries)))
            with _create_key(_policy_path(target.key)) as key:
                for name, value in target.values.items():
                    winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, value)
        except OSError as error:
            first_error = first_error or error
    if first_error is not None:
        raise first_error


def lift_lock(entries: list[str], baseline: Any) -> None:
    """Remove exactly the managed entries, keep everything else, and restore the baseline values."""
    for target in TARGETS:
        key_path = _policy_path(target.key)
        list_path = _policy_path(target.key, target.list_key)
        managed = set(_for_target(target, entries))
        others = [value for value in list_values(list_path) if value not in managed]
        write_list(list_path, unique(_baseline_list(baseline, target.name), others))
        for name, value in target.values.items():
            restore_value(key_path, name, _baseline_value(baseline, target, name), value)
        remove_empty_keys(list_path)
        remove_empty_keys(key_path)


def lock_is_applied(entries: list[str]) -> bool:
    try:
        for target in TARGETS:
            key_path = _policy_path(target.key)
            if not all(_is_managed(value_snapshot(key_path, name), value) for name, value in target.values.items()):
                return False
            actual = set(list_values(_policy_path(target.key, target.list_key)))
            if not set(_for_target(target, entries)).issubset(actual):
                return False
        return True
    except OSError:
        return False


def installed_blocklist() -> list[str]:
    """The installed blocklist, or "*" (block everything) when it is missing or corrupt."""
    try:
        return read_blocklist(app_file("blocklist.txt"))
    except (OSError, ValueError) as error:
        log(f"Installed blocklist is invalid; blocking all URLs as a fail-safe: {error}", once=True)
        return ["*"]


def applied_entries() -> list[str]:
    """The entries the last lock wrote. Unlock removes exactly these, whatever blocklist.txt says now."""
    try:
        lines = app_file("applied-blocklist.txt").read_text(encoding="utf-8-sig").splitlines()
    except (OSError, ValueError):
        return []
    return [line for line in lines if line and len(line) <= 4096]


def _write_applied(entries: list[str]) -> None:
    atomic_write_text(app_file("applied-blocklist.txt"), "".join(f"{entry}\n" for entry in entries))


def set_lock() -> None:
    entries = installed_blocklist()
    previous = applied_entries()
    # Record the entries before writing them, so an interrupted lock can still be undone. The
    # record is a convenience for unlock; failing to write it must never stop the lock itself.
    try:
        _write_applied(unique(previous, entries))
    except OSError as error:
        log(f"Could not record applied entries: {error}", once=True)
    apply_lock(entries, previous, read_baseline())
    try:
        _write_applied(entries)
    except OSError:
        pass


def remove_lock() -> None:
    lift_lock(unique(applied_entries(), installed_blocklist()), read_baseline())
    app_file("applied-blocklist.txt").unlink(missing_ok=True)


def lock_intact() -> bool:
    return lock_is_applied(installed_blocklist())


# ---------------------------------------------------------------- key detection and sync

def volume_serials(root: str) -> tuple[str, ...]:
    """The volume serial as text. The first form is used for new pairings.

    The second, without leading zeros, is accepted when matching so that pairings made by the
    PowerShell release keep working whichever way Windows formatted the number for it.
    """
    serial = wintypes.DWORD()
    if not kernel32.GetVolumeInformationW(root, None, 0, ctypes.byref(serial), None, None, None, 0):
        raise ctypes.WinError(ctypes.get_last_error())
    return tuple(dict.fromkeys((f"{serial.value:08X}", f"{serial.value:X}")))


def volume_serial(root: str) -> str:
    return volume_serials(root)[0]


def paired_hashes() -> set[str]:
    try:
        lines = app_file("pair.txt").read_text(encoding="utf-8-sig").splitlines()
    except (OSError, ValueError):
        return set()
    return {line.strip().lower() for line in lines if re.fullmatch(r"[0-9a-fA-F]{64}", line.strip())}


def key_matches(key_file: Path, root: str, expected: set[str]) -> bool:
    try:
        # The watchdog runs as SYSTEM, so it must not follow a link on the USB to another file.
        if is_reparse_point(key_file) or key_file.stat().st_size > 1024:
            return False
        token = read_key_token(key_file)
        return any(pairing_hash(token, serial) in expected for serial in volume_serials(root))
    except (OSError, ValueError):
        return False


def find_key() -> Path | None:
    expected = paired_hashes()
    if not expected:
        return None
    mask = kernel32.GetLogicalDrives()
    for index in range(26):
        if not mask & (1 << index):
            continue
        root = f"{chr(65 + index)}:\\"
        if kernel32.GetDriveTypeW(root) not in {2, 3}:  # removable or fixed
            continue
        if key_matches(Path(root) / KEY_RELATIVE_PATH, root, expected):
            return Path(root)
    return None


def sync_blocklist(root: Path) -> str:
    """Install the USB blocklist when it has changed and is valid.

    Returns "" on success, or a short description of what is wrong with the USB copy. A bad USB
    blocklist never prevents the key from unlocking this PC; the installed list stays in force.
    """
    source = root / "Chainlink" / "blocklist.txt"
    try:
        if is_reparse_point(source):
            return "blocklist.txt on the USB is a link, not a file"
        if source.stat().st_size > MAX_USB_BLOCKLIST_BYTES:
            return "blocklist.txt on the USB is too large"
        data = source.read_bytes()  # validate the same bytes that get installed
    except OSError:
        return "the USB has no readable Chainlink\\blocklist.txt"
    installed = app_file("blocklist.txt")
    try:
        if installed.read_bytes() == data:
            return ""
    except OSError:
        pass
    try:
        parse_blocklist_bytes(data)
    except ValueError as error:
        return f"blocklist.txt on the USB has a problem: {error}"
    atomic_write_bytes(installed, data)
    log("Blocklist updated from USB.")
    return ""


class Watchdog:
    """The watchdog loop, one cycle at a time."""

    def __init__(self) -> None:
        self.state = ""  # "", "locked", or "unlocked"
        self.usb_problem = ""
        self.tick = 0

    def cycle(self) -> None:
        usb = None
        try:
            usb = find_key()
            if usb:
                if self.state != "unlocked":
                    remove_lock()
                    self.state = "unlocked"
                    self.usb_problem = ""
                    set_status(f"UNLOCKED - key found on {usb}")
                    log(f"Key found on {usb} - blocks lifted.")
                problem = sync_blocklist(usb)
                if problem != self.usb_problem:
                    self.usb_problem = problem
                    if problem:
                        set_status(f"UNLOCKED - key found on {usb}. The previous blocklist is still in use: {problem}")
                        log(f"Blocklist not updated: {problem}")
                    else:
                        set_status(f"UNLOCKED - key found on {usb}")
            elif self.state != "locked" or (self.tick % 12 == 0 and not lock_intact()):
                set_lock()
                log("Blocks were changed outside Chainlink - re-applied." if self.state == "locked" else "Key not present - blocks applied.")
                self.state = "locked"
                set_status("LOCKED - key not present")
        except Exception as error:  # keep a SYSTEM watchdog alive
            log(f"Watchdog cycle failed: {error}", once=True)
            # With the key present there is nothing to enforce; the unlock is retried next cycle.
            # Without it, make sure the blocks are on.
            self.state = ""
            if not usb:
                try:
                    set_lock()
                    self.state = "locked"
                    set_status("LOCKED - fail-safe after an error")
                except Exception as fail_safe_error:
                    log(f"Fail-safe lock also failed: {fail_safe_error}", once=True)
        self.tick += 1


# ---------------------------------------------------------------- scheduled task

def watchdog_arguments(watchdog: Path) -> str:
    # -I: ignore PYTHON* environment variables and per-user site-packages. -B: write no .pyc files.
    return subprocess.list2cmdline(["-I", "-B", str(watchdog)])


def task_xml(python_executable: Path, watchdog: Path) -> str:
    command = xml.sax.saxutils.escape(str(python_executable))
    arguments = xml.sax.saxutils.escape(watchdog_arguments(watchdog))
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


def _schtasks(*arguments: str) -> subprocess.CompletedProcess[str]:
    """The only place that talks to Task Scheduler."""
    return _run_hidden([str(system_executable("schtasks.exe")), *arguments])


def query_task_xml() -> str | None:
    result = _schtasks("/Query", "/TN", TASK_NAME, "/XML")
    return result.stdout if result.returncode == 0 else None


def _task_actions(xml: str) -> tuple[set[str], list[tuple[str, str]]] | None:
    try:
        root = element_tree.fromstring(xml)
    except element_tree.ParseError:
        return None
    user_ids = {str(node.text or "").strip().upper() for node in root.findall(".//{*}UserId")}
    actions = [
        (str(action.findtext("{*}Command") or "").strip().strip('"'), str(action.findtext("{*}Arguments") or "").strip())
        for action in root.findall(".//{*}Exec")
    ]
    return user_ids, actions


def task_xml_is_genuine(xml: str) -> bool:
    """True when the task runs as SYSTEM and its action is exactly a Chainlink watchdog."""
    parsed = _task_actions(xml)
    if parsed is None:
        return False
    user_ids, actions = parsed
    if not user_ids or not user_ids.issubset({"SYSTEM", "S-1-5-18"}):
        return False

    python_name = re.compile(r"python(?:3(?:\.\d+)?)?\.exe", re.IGNORECASE)
    python_arguments = watchdog_arguments(app_file("watchdog.py")).lower()
    # The PowerShell releases: the original registered the bare name, later ones the full path.
    powershell_commands = {str(system_executable(r"WindowsPowerShell\v1.0\powershell.exe")).lower(), "powershell.exe", "powershell"}
    powershell_script = app_file("watchdog.ps1")
    powershell_arguments = {
        f'-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "{powershell_script}"'.lower(),
        f'-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{powershell_script}"'.lower(),
    }
    for command, arguments in actions:
        command_path = Path(command)
        if (
            command_path.is_absolute()
            and python_name.fullmatch(command_path.name)
            and any(command_path.resolve().is_relative_to(root_path) for root_path in PROGRAM_FILES_ROOTS)
            and arguments.lower() == python_arguments
        ):
            return True
        if command.lower() in powershell_commands and arguments.lower() in powershell_arguments:
            return True
    return False


def task_xml_references_app_dir(xml: str) -> bool:
    """True when any action would run something from the program directory.

    Uninstall uses this looser test so that it never leaves a SYSTEM task pointing at a
    directory it has just deleted.
    """
    parsed = _task_actions(xml)
    if parsed is None:
        return False
    needle = str(APP_DIR).lower().rstrip("\\") + "\\"
    return any(needle in command.lower() or needle in arguments.lower() for command, arguments in parsed[1])


def genuine_task() -> bool:
    xml = query_task_xml()
    return bool(xml and task_xml_is_genuine(xml))


def create_task(python_executable: Path, watchdog: Path) -> None:
    xml_path = app_file("task.xml")
    try:
        xml_path.write_text(task_xml(python_executable, watchdog), encoding="utf-16")
        result = _schtasks("/Create", "/TN", TASK_NAME, "/XML", str(xml_path), "/F")
    finally:
        xml_path.unlink(missing_ok=True)
    if result.returncode == 0:
        result = _schtasks("/Run", "/TN", TASK_NAME)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout).strip() or "could not register the Chainlink scheduled task")


def stop_task() -> None:
    _schtasks("/End", "/TN", TASK_NAME)


def delete_task() -> None:
    """Remove the task if it is Chainlink's or runs from the program directory; leave any other."""
    xml = query_task_xml()
    if xml is None or not (task_xml_is_genuine(xml) or task_xml_references_app_dir(xml)):
        return
    result = _schtasks("/Delete", "/TN", TASK_NAME, "/F")
    if result.returncode and query_task_xml() is not None:
        raise RuntimeError(result.stderr.strip() or "could not delete the Chainlink scheduled task")
