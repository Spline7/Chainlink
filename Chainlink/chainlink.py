"""Chainlink's Windows settings, installation, recovery, and uninstall UI."""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import time
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

from chainlink_core import (
    SHORTS_ENTRY,
    WORD_LIST,
    atomic_write_text,
    make_recovery_record,
    new_key_token,
    new_recovery_words,
    normalize_channel,
    normalize_entry,
    pairing_hash,
    read_blocklist,
    read_key_token,
    verify_recovery_record,
)
from windows_support import (
    APP_DIR,
    BASELINE_FILE,
    BLOCKLIST_FILE,
    PAIR_FILE,
    capture_baseline,
    create_task,
    delete_task,
    genuine_task,
    is_admin,
    is_reparse_point,
    relaunch_elevated,
    read_baseline,
    remove_lock,
    secure_app_directory,
    stop_task,
    system_executable,
    volume_serial,
)

USB_DIR = Path(__file__).resolve().parent
USB_ROOT = Path(USB_DIR.anchor)
KEY_FILE = USB_DIR / "chainlink.key"
USB_BLOCKLIST = USB_DIR / "blocklist.txt"
RECOVERY_FILE = APP_DIR / "recovery.txt"
RECOVERY_ATTEMPTS = APP_DIR / "recovery-attempts.json"
START_MENU = Path(os.environ["ProgramData"]) / "Microsoft" / "Windows" / "Start Menu" / "Programs"
EMERGENCY_COMMAND = START_MENU / "Chainlink Emergency Uninstall.cmd"
EMERGENCY_LAUNCHER = START_MENU / "Chainlink Emergency Uninstall.pyw"
INSTALL_FILES = ("chainlink.py", "chainlink_core.py", "windows_support.py", "watchdog.py")


def pythonw_executable() -> Path:
    candidate = Path(sys.executable).with_name("pythonw.exe")
    return candidate if candidate.is_file() else Path(sys.executable)


def validated_runtime() -> Path:
    executable = Path(sys.executable).resolve()
    if not executable.is_file() or executable.suffix.lower() != ".exe":
        raise RuntimeError("Chainlink requires a normal Windows Python executable")
    trusted_roots = [Path(value).resolve() for name in ("ProgramFiles", "ProgramFiles(x86)") if (value := os.environ.get(name))]
    if not any(executable.is_relative_to(root) for root in trusted_roots):
        raise RuntimeError("the SYSTEM background task requires Python under Program Files; install Python 3.10+ for all users and run Chainlink again")
    return executable


def usb_hash() -> str:
    if not USB_ROOT.anchor:
        raise RuntimeError("Chainlink must be run from a drive with a Windows volume serial number")
    return pairing_hash(read_key_token(KEY_FILE), volume_serial(str(USB_ROOT)))


def usb_matches_pc() -> bool:
    try:
        expected = {line.strip().lower() for line in PAIR_FILE.read_text(encoding="utf-8-sig").splitlines()}
        return usb_hash() in expected
    except (OSError, ValueError):
        return False


def copy_atomic(source: Path, destination: Path) -> None:
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    try:
        shutil.copy2(source, temporary)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def create_key_if_needed() -> None:
    if KEY_FILE.exists():
        read_key_token(KEY_FILE)
        return
    KEY_FILE.write_text(new_key_token(), encoding="ascii")
    attributes = 0x2  # FILE_ATTRIBUTE_HIDDEN
    if not __import__("ctypes").windll.kernel32.SetFileAttributesW(str(KEY_FILE), attributes):
        raise __import__("ctypes").WinError()


def write_recovery(words: list[str]) -> None:
    atomic_write_text(RECOVERY_FILE, make_recovery_record(words) + "\n")


def recovery_delay() -> int:
    try:
        state = json.loads(RECOVERY_ATTEMPTS.read_text(encoding="utf-8"))
        return max(0, int(state["until"] - time.time() + 0.999))
    except (OSError, ValueError, TypeError, KeyError):
        return 0


def register_recovery_failure() -> None:
    try:
        state = json.loads(RECOVERY_ATTEMPTS.read_text(encoding="utf-8"))
        failures = int(state.get("failures", 0))
    except (OSError, ValueError, TypeError):
        failures = 0
    failures = min(6, failures + 1)
    atomic_write_text(RECOVERY_ATTEMPTS, json.dumps({"failures": failures, "until": time.time() + min(60, 2 ** (failures + 1))}) + "\n")


def install_chainlink() -> list[str] | None:
    for name in (*INSTALL_FILES, "emergency_launcher.pyw"):
        if not (USB_DIR / name).is_file():
            raise RuntimeError(f"the USB is missing Chainlink/{name}")
    read_blocklist(USB_BLOCKLIST)
    runtime = validated_runtime()

    has_task = genuine_task()
    task_xml = subprocess.run(
        [str(system_executable("schtasks.exe")), "/Query", "/TN", r"\Chainlink", "/XML"],
        text=True,
        capture_output=True,
    )
    if task_xml.returncode == 0 and not has_task:
        raise RuntimeError("a scheduled task named Chainlink already exists and does not belong to this application")

    create_key_if_needed()
    current_hash = usb_hash()
    if APP_DIR.exists():
        if not APP_DIR.is_dir() or is_reparse_point(APP_DIR):
            raise RuntimeError(f"{APP_DIR} must be a real directory, not a file, junction, or symbolic link")
        if not has_task and any(APP_DIR.iterdir()):
            raise RuntimeError(f"{APP_DIR} contains files but no genuine Chainlink task exists; move it aside before linking")
    else:
        APP_DIR.mkdir()
    secure_app_directory()

    stop_task()
    if has_task and not BASELINE_FILE.exists():
        old_python = APP_DIR / "watchdog.py"
        old_powershell = APP_DIR / "watchdog.ps1"
        if old_python.is_file():
            subprocess.run([sys.executable, "-B", str(old_python), "--unlock"], check=True)
        elif old_powershell.is_file():
            subprocess.run(
                [str(system_executable(r"WindowsPowerShell\v1.0\powershell.exe")), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(old_powershell), "-Unlock"],
                check=True,
            )
        else:
            raise RuntimeError("the existing Chainlink task has no watchdog to migrate")

    for name in INSTALL_FILES:
        copy_atomic(USB_DIR / name, APP_DIR / name)
    if not BASELINE_FILE.exists():
        capture_baseline()
    if read_baseline() is None:
        raise RuntimeError("could not save existing browser policy; installation stopped")

    known = []
    if PAIR_FILE.exists():
        known = [line.strip().lower() for line in PAIR_FILE.read_text(encoding="utf-8-sig").splitlines() if re_full_hash(line.strip())]
    if current_hash not in known:
        known.append(current_hash)
    atomic_write_text(PAIR_FILE, "".join(f"{item}\n" for item in dict.fromkeys(known)))
    copy_atomic(USB_BLOCKLIST, BLOCKLIST_FILE)

    copy_atomic(USB_DIR / "emergency_launcher.pyw", EMERGENCY_LAUNCHER)
    command = f'@echo off\r\nstart "" "{pythonw_executable()}" -B "{EMERGENCY_LAUNCHER}" "{APP_DIR / "chainlink.py"}"\r\n'
    atomic_write_text(EMERGENCY_COMMAND, command)

    create_task(runtime, APP_DIR / "watchdog.py")
    for obsolete in ("Chainlink.ps1", "Chainlink.Common.psm1", "watchdog.ps1"):
        (APP_DIR / obsolete).unlink(missing_ok=True)

    if not RECOVERY_FILE.exists():
        words = new_recovery_words()
        write_recovery(words)
        return words
    return None


def re_full_hash(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdefABCDEF" for character in value)


def uninstall_chainlink() -> None:
    stop_task()
    time.sleep(0.75)
    remove_lock()
    delete_task()
    EMERGENCY_COMMAND.unlink(missing_ok=True)
    EMERGENCY_LAUNCHER.unlink(missing_ok=True)
    if APP_DIR.exists():
        if is_reparse_point(APP_DIR):
            raise RuntimeError("refusing to remove a reparse-point program directory")
        shutil.rmtree(APP_DIR)


def blocklist_for_ui() -> tuple[list[str], list[str], bool]:
    sites: list[str] = []
    channels: list[str] = []
    shorts = False
    for entry in read_blocklist(USB_BLOCKLIST):
        if entry.lower() == SHORTS_ENTRY:
            shorts = True
        elif entry.startswith(("youtube.com/@", "youtube.com/channel/", "youtube.com/c/", "youtube.com/user/")):
            channels.append(entry.removeprefix("youtube.com/"))
        else:
            sites.append(entry)
    return sites, channels, shorts


def save_blocklist(sites: list[str], channels: list[str], shorts: bool) -> None:
    normalized_sites = list(dict.fromkeys(filter(None, (normalize_entry(value) for value in sites))))
    normalized_channels = list(dict.fromkeys(filter(None, (normalize_channel(value) for value in channels))))
    lines = [
        "# Chainlink blocklist - edit with Chainlink.cmd (or by hand, one entry per line).",
        "# Lines starting with # are ignored.",
        "",
        "# Websites",
        *normalized_sites,
        "",
        "# YouTube",
    ]
    if shorts:
        lines.append(SHORTS_ENTRY)
    lines.extend(normalized_channels)
    atomic_write_text(USB_BLOCKLIST, "\n".join(lines) + "\n")


def show_recovery_words(parent: tk.Misc, words: list[str]) -> None:
    dialog = tk.Toplevel(parent)
    dialog.title("Chainlink - recovery words")
    dialog.resizable(False, False)
    dialog.transient(parent)
    dialog.grab_set()
    ttk.Label(dialog, text="Give these words to your accountability partner", font=("Segoe UI", 13, "bold")).grid(row=0, column=0, columnspan=2, padx=20, pady=(20, 8))
    ttk.Label(dialog, text="They are the only emergency-uninstall phrase for this PC. They will not be shown again.", wraplength=480).grid(row=1, column=0, columnspan=2, padx=20, pady=(0, 12))
    for index, word in enumerate(words):
        ttk.Label(dialog, text=f"{index + 1}.  {word}", font=("Segoe UI", 13, "bold"), width=20).grid(row=2 + index // 2, column=index % 2, padx=8, pady=5)
    confirmed = tk.BooleanVar()
    checkbox = ttk.Checkbutton(dialog, text="My accountability partner has these words.", variable=confirmed)
    checkbox.grid(row=5, column=0, columnspan=2, padx=20, pady=(14, 6))
    done = ttk.Button(dialog, text="Done", command=dialog.destroy, state="disabled")
    done.grid(row=6, column=0, columnspan=2, pady=(0, 20))
    confirmed.trace_add("write", lambda *_: done.configure(state="normal" if confirmed.get() else "disabled"))
    dialog.protocol("WM_DELETE_WINDOW", lambda: None)
    parent.wait_window(dialog)


def emergency_ui() -> int:
    root = tk.Tk()
    root.title("Chainlink - emergency uninstall")
    root.resizable(False, False)
    if not RECOVERY_FILE.is_file():
        messagebox.showwarning("Chainlink", "This installation has no recovery words. Repair it using the paired USB first.", parent=root)
        root.destroy()
        return 1
    ttk.Label(root, text="Emergency uninstall", font=("Segoe UI", 14, "bold")).grid(row=0, column=0, columnspan=2, padx=20, pady=(20, 8))
    ttk.Label(root, text="Ask your accountability partner for the six recovery words and enter them in order.", wraplength=460).grid(row=1, column=0, columnspan=2, padx=20, pady=(0, 12))
    entries: list[ttk.Entry] = []
    for index in range(6):
        entry = ttk.Entry(root, width=24)
        entry.grid(row=2 + index // 2, column=index % 2, padx=10, pady=5)
        entries.append(entry)
    status = ttk.Label(root, foreground="#b03020")
    status.grid(row=5, column=0, columnspan=2, pady=8)

    def attempt() -> None:
        delay = recovery_delay()
        if delay:
            status.configure(text=f"Please wait {delay} seconds before trying again.")
            return
        words = [entry.get().strip() for entry in entries]
        if any(not word for word in words):
            status.configure(text="Please fill in all six words.")
            return
        if not verify_recovery_record(RECOVERY_FILE.read_text(encoding="utf-8-sig"), words):
            register_recovery_failure()
            status.configure(text="Those words do not match. Check spelling and order.")
            return
        RECOVERY_ATTEMPTS.unlink(missing_ok=True)
        if not messagebox.askyesno("Chainlink", "Recovery words accepted. Remove Chainlink from this PC?", parent=root):
            return
        try:
            uninstall_chainlink()
            messagebox.showinfo("Chainlink", "Chainlink has been removed.", parent=root)
            root.destroy()
        except Exception as error:
            messagebox.showerror("Chainlink", f"Uninstall failed:\n{error}", parent=root)

    ttk.Button(root, text="Uninstall Chainlink", command=attempt).grid(row=6, column=0, padx=8, pady=(4, 20))
    ttk.Button(root, text="Cancel", command=root.destroy).grid(row=6, column=1, padx=8, pady=(4, 20))
    root.mainloop()
    return 0


class ChainlinkApp:
    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title("Chainlink")
        self.root.geometry("620x700")
        self.root.minsize(520, 600)
        frame = ttk.Frame(self.root, padding=18)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Chainlink", font=("Segoe UI", 18, "bold")).pack(anchor="w")
        self.status = ttk.Label(frame)
        self.status.pack(anchor="w", pady=(2, 14))
        ttk.Label(frame, text="Websites to block - one per line", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.sites = tk.Text(frame, height=12, wrap="none", font=("Consolas", 10))
        self.sites.pack(fill="both", expand=True, pady=(3, 8))
        self.shorts = tk.BooleanVar()
        ttk.Checkbutton(frame, text="Block YouTube Shorts", variable=self.shorts).pack(anchor="w", pady=5)
        ttk.Label(frame, text="YouTube channels - @Name or a channel URL", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.channels = tk.Text(frame, height=10, wrap="none", font=("Consolas", 10))
        self.channels.pack(fill="both", expand=True, pady=(3, 10))
        buttons = ttk.Frame(frame)
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Save blocklist", command=self.save).pack(side="left", padx=(0, 6))
        self.link_button = ttk.Button(buttons, text="Link this PC", command=self.link)
        self.link_button.pack(side="left", padx=6)
        self.uninstall_button = ttk.Button(buttons, text="Uninstall", command=self.uninstall)
        self.uninstall_button.pack(side="left", padx=6)
        self.words_button = ttk.Button(buttons, text="New recovery words", command=self.new_words)
        self.words_button.pack(side="left", padx=6)
        self.load()
        self.update_status()

    @staticmethod
    def lines(widget: tk.Text) -> list[str]:
        return [line.strip() for line in widget.get("1.0", "end").splitlines() if line.strip()]

    def load(self) -> None:
        sites, channels, shorts = blocklist_for_ui()
        self.sites.delete("1.0", "end")
        self.sites.insert("1.0", "\n".join(sites))
        self.channels.delete("1.0", "end")
        self.channels.insert("1.0", "\n".join(channels))
        self.shorts.set(shorts)

    def save(self, announce: bool = True) -> bool:
        try:
            save_blocklist(self.lines(self.sites), self.lines(self.channels), self.shorts.get())
            self.load()
            if announce:
                messagebox.showinfo("Chainlink", "Blocklist saved.", parent=self.root)
            return True
        except Exception as error:
            messagebox.showerror("Chainlink", f"Could not save blocklist:\n{error}", parent=self.root)
            return False

    def update_status(self) -> None:
        installed = genuine_task() or (APP_DIR / "watchdog.py").is_file()
        if not installed:
            self.status.configure(text='This PC is not linked. Click "Link this PC" to start.')
            self.link_button.configure(text="Link this PC", state="normal")
            self.uninstall_button.configure(state="disabled")
            self.words_button.configure(state="disabled")
        elif usb_matches_pc():
            self.status.configure(text="This PC is linked to this USB. Blocks are off while it is plugged in.")
            self.link_button.configure(text="Repair / update this PC", state="normal")
            self.uninstall_button.configure(state="normal")
            self.words_button.configure(state="normal")
        else:
            self.status.configure(text="This PC is linked to a different USB key.")
            self.link_button.configure(text="Link this PC", state="disabled")
            self.uninstall_button.configure(state="disabled")
            self.words_button.configure(state="disabled")

    def link(self) -> None:
        if not self.save(announce=False):
            return
        try:
            words = install_chainlink()
            self.update_status()
            if words:
                show_recovery_words(self.root, words)
            messagebox.showinfo("Chainlink", "This PC is linked. Unplug the USB and wait about 10 seconds to test it.", parent=self.root)
        except Exception as error:
            messagebox.showerror("Chainlink", f"Linking failed:\n{error}", parent=self.root)

    def uninstall(self) -> None:
        if not messagebox.askyesno("Chainlink", "Remove Chainlink and restore prior browser policy?", parent=self.root):
            return
        try:
            uninstall_chainlink()
            self.update_status()
            messagebox.showinfo("Chainlink", "Chainlink has been removed from this PC.", parent=self.root)
        except Exception as error:
            messagebox.showerror("Chainlink", f"Uninstall failed:\n{error}", parent=self.root)

    def new_words(self) -> None:
        if not messagebox.askyesno("Chainlink", "Replace the current recovery words?", parent=self.root):
            return
        words = new_recovery_words()
        write_recovery(words)
        show_recovery_words(self.root, words)

    def run(self) -> None:
        self.root.mainloop()


def main() -> int:
    parser = argparse.ArgumentParser(description="Chainlink settings")
    parser.add_argument("--emergency", action="store_true")
    arguments = parser.parse_args()
    if not is_admin():
        relaunch_elevated(["-B", str(Path(__file__).resolve()), *( ["--emergency"] if arguments.emergency else [] )])
        return 0
    if arguments.emergency:
        return emergency_ui()
    ChainlinkApp().run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
