"""Chainlink's Windows settings, installation, recovery, and uninstall UI.

Started by Chainlink.cmd on the USB drive. Makes no network requests and sends no telemetry.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import json
import shutil
import sys
import time
from pathlib import Path

# Python is started in isolated mode, which does not add this folder to the import path.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import tkinter as tk  # noqa: E402
from tkinter import messagebox, ttk  # noqa: E402

import windows_support as ws  # noqa: E402
from chainlink_core import (  # noqa: E402
    SHORTS_ENTRY,
    ValidationError,
    atomic_write_bytes,
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

USB_DIR = Path(__file__).resolve().parent
USB_ROOT = Path(USB_DIR.anchor)
KEY_FILE = USB_DIR / "chainlink.key"
USB_BLOCKLIST = USB_DIR / "blocklist.txt"
START_MENU = ws.PROGRAM_DATA / "Microsoft" / "Windows" / "Start Menu" / "Programs"
EMERGENCY_SHORTCUT = START_MENU / "Chainlink Emergency Uninstall.lnk"
MAX_ENTRIES = 2048
INSTALL_FILES = ("chainlink.py", "chainlink_core.py", "windows_support.py", "watchdog.py")
PYTHON_FLAGS = ("-I", "-B")  # isolated from PYTHON* variables and per-user site-packages; no .pyc files


def recovery_file() -> Path:
    return ws.app_file("recovery.txt")


def recovery_attempts_file() -> Path:
    return ws.app_file("recovery-attempts.json")


def pythonw_executable() -> Path:
    candidate = Path(sys.executable).with_name("pythonw.exe")
    return candidate if candidate.is_file() else Path(sys.executable)


def validated_runtime() -> Path:
    executable = Path(sys.executable).resolve()
    if not executable.is_file() or executable.suffix.lower() != ".exe":
        raise RuntimeError("Chainlink requires a normal Windows Python executable")
    if not re_python_executable(executable.name) or not any(executable.is_relative_to(root) for root in ws.PROGRAM_FILES_ROOTS):
        raise RuntimeError("the SYSTEM background task requires Python under Program Files; install Python 3.10+ for all users and run Chainlink again")
    return executable


def re_python_executable(name: str) -> bool:
    lower = name.lower()
    if lower in {"python.exe", "python3.exe"}:
        return True
    if not lower.startswith("python3.") or not lower.endswith(".exe"):
        return False
    return lower[8:-4].isdigit()


def usb_hash() -> str:
    if not USB_ROOT.anchor:
        raise RuntimeError("Chainlink must be run from a drive with a Windows volume serial number")
    return pairing_hash(read_key_token(KEY_FILE), ws.volume_serial(str(USB_ROOT)))


def usb_matches_pc() -> bool:
    return bool(USB_ROOT.anchor) and ws.key_matches(KEY_FILE, str(USB_ROOT), ws.paired_hashes())


def copy_atomic(source: Path, destination: Path) -> None:
    atomic_write_bytes(destination, source.read_bytes())


def create_key_if_needed() -> None:
    if KEY_FILE.exists():
        read_key_token(KEY_FILE)
        return
    KEY_FILE.write_text(new_key_token(), encoding="ascii")
    ws.kernel32.SetFileAttributesW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
    if not ws.kernel32.SetFileAttributesW(str(KEY_FILE), 0x2):  # FILE_ATTRIBUTE_HIDDEN
        raise ctypes.WinError(ctypes.get_last_error())


def write_recovery(words: list[str]) -> None:
    atomic_write_text(recovery_file(), make_recovery_record(words) + "\n")


def recovery_delay() -> int:
    try:
        state = json.loads(recovery_attempts_file().read_text(encoding="utf-8"))
        return max(0, int(state["until"] - time.time() + 0.999))
    except (OSError, ValueError, TypeError, KeyError):
        return 0


def register_recovery_failure() -> None:
    try:
        state = json.loads(recovery_attempts_file().read_text(encoding="utf-8"))
        failures = int(state.get("failures", 0))
    except (OSError, ValueError, TypeError, AttributeError):
        failures = 0
    failures = min(6, failures + 1)
    atomic_write_text(recovery_attempts_file(), json.dumps({"failures": failures, "until": time.time() + min(60, 2 ** (failures + 1))}) + "\n")


def powershell_executable() -> Path:
    return ws.system_executable(r"WindowsPowerShell\v1.0\powershell.exe")


def run_powershell(script: str) -> None:
    """Run a short PowerShell script without a window. The script travels encoded, never quoted."""
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    result = ws._run_hidden([str(powershell_executable()), "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded])
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout).strip() or "PowerShell reported an error")


def run_powershell_watchdog(script: Path, mode: str) -> None:
    """Run a watchdog left by a PowerShell release in one of its one-shot modes."""
    result = ws._run_hidden([str(powershell_executable()), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script), mode])
    if result.returncode:
        raise RuntimeError("the existing PowerShell watchdog could not lift its blocks")


def quoted(value: object) -> str:
    """A PowerShell single-quoted string literal."""
    return "'" + str(value).replace("'", "''") + "'"


def create_emergency_shortcut() -> None:
    """Start menu shortcut for emergency uninstall.

    The shortcut runs PowerShell (which everyone can read) only to ask for elevation; the
    elevated Python then opens the program in the protected folder. A real .lnk is used
    because the Start menu lists shortcuts, and it replaces the one the PowerShell release made.
    """
    script = ws.app_file("chainlink.py")
    arguments = ", ".join(quoted(item) for item in (*PYTHON_FLAGS, f'"{script}"', "--emergency"))
    elevate = f"Start-Process -FilePath {quoted(pythonw_executable())} -Verb RunAs -ArgumentList @({arguments})"
    encoded = base64.b64encode(elevate.encode("utf-16-le")).decode("ascii")
    run_powershell(
        f"$shortcut = (New-Object -ComObject WScript.Shell).CreateShortcut({quoted(EMERGENCY_SHORTCUT)}); "
        f"$shortcut.TargetPath = {quoted(powershell_executable())}; "
        f"$shortcut.Arguments = {quoted('-NoProfile -WindowStyle Hidden -EncodedCommand ' + encoded)}; "
        "$shortcut.Description = 'Remove Chainlink without the USB key, using your recovery words.'; "
        "$shortcut.Save()"
    )


def unlock_installed() -> None:
    """Lift the blocks of whatever is installed on this PC."""
    old_powershell = ws.app_file("watchdog.ps1")
    if old_powershell.is_file() and not ws.app_file("policy-baseline.json").exists():
        # The original release kept no record of earlier policy; its own code undoes what it did.
        run_powershell_watchdog(old_powershell, "-Unlock")
    else:
        ws.remove_lock()


def usb_layout_ok() -> bool:
    """The watchdog only looks for <drive>:\\Chainlink\\chainlink.key.

    Linking from anywhere else would create a key it can never find and lock the PC a few
    seconds later.
    """
    return bool(USB_ROOT.anchor) and str(USB_DIR).lower() == str(USB_ROOT / "Chainlink").lower()


def require_trusted_program_folder() -> None:
    """Refuse to go on when the program folder could have been written by a non-administrator."""
    app_dir = ws.APP_DIR
    if (app_dir.exists() or app_dir.is_symlink()) and not ws.is_trusted_directory(app_dir):
        raise RuntimeError(
            f"{app_dir} was not created by Chainlink, or another account has been able to change it. "
            "Nothing in it was used. Delete that folder as Administrator and try again."
        )


def install_chainlink() -> list[str] | None:
    for name in INSTALL_FILES:
        if not (USB_DIR / name).is_file():
            raise RuntimeError(f"the USB is missing Chainlink/{name}")
    if not usb_layout_ok():
        raise RuntimeError(f"Chainlink has to be started from the Chainlink folder at the top level of the USB drive (for example E:\\Chainlink). It is running from {USB_DIR}.")
    read_blocklist(USB_BLOCKLIST)
    runtime = validated_runtime()
    require_trusted_program_folder()

    task = ws.query_task_xml()
    has_task = bool(task and ws.task_xml_is_genuine(task))
    if task and not has_task:
        raise RuntimeError("a scheduled task named Chainlink already exists and does not belong to this application")

    create_key_if_needed()
    current_hash = usb_hash()

    # Program folder that only SYSTEM and Administrators can read or change. Everything in it
    # runs as SYSTEM, so a folder another account created or owns is never reused.
    app_dir = ws.APP_DIR
    existing = has_task
    if app_dir.exists():
        if not existing:
            if not any(app_dir.iterdir()):
                app_dir.rmdir()
            elif ws.is_protected_directory(app_dir) and any(ws.app_file(name).is_file() for name in ("watchdog.py", "watchdog.ps1")):
                # A Chainlink folder only administrators could have written, whose task is gone
                # (for example after an interrupted uninstall). Repair it like any other install,
                # so its blocks are lifted before a new policy baseline could ever be taken.
                existing = True
            else:
                raise RuntimeError(
                    f"{app_dir} already contains files but no Chainlink scheduled task exists. If Chainlink is installed, "
                    "use Uninstall (or Chainlink Emergency Uninstall) first; otherwise delete that folder as Administrator, then link again."
                )
    created = not app_dir.exists()
    if created:
        ws.create_protected_directory(app_dir)
    else:
        ws.protect_existing_directory(app_dir)

    try:
        return install_files(runtime, current_hash, existing)
    except BaseException:
        if created:
            # A first-time link that fails leaves nothing behind, so it can simply be tried again.
            # The folder goes only once the task is gone: a SYSTEM task must never be left
            # pointing at a path that any account could then recreate.
            try:
                ws.stop_task()
                ws.delete_task()
                task_gone = ws.query_task_xml() is None
            except Exception:
                task_gone = False
            if task_gone:
                EMERGENCY_SHORTCUT.unlink(missing_ok=True)
                shutil.rmtree(app_dir, ignore_errors=True)
        raise


def install_files(runtime: Path, current_hash: str, upgrade: bool) -> list[str] | None:
    # Hold the watchdog lock while files change, so no watchdog runs a half-replaced copy.
    lock = ws.stop_watchdog()
    try:
        ws.uninstall_marker().unlink(missing_ok=True)
        if upgrade:
            unlock_installed()  # lift the old copy's blocks before replacing it

        for name in INSTALL_FILES:
            copy_atomic(USB_DIR / name, ws.app_file(name))
        if ws.app_file("policy-baseline.json").exists() and not ws.baseline_file_is_valid():
            # Unreadable, so the unlock above already fell back to removing Chainlink's own values.
            ws.app_file("policy-baseline.json").unlink()
        ws.capture_baseline()
        if not ws.baseline_file_is_valid():
            raise RuntimeError("could not save existing browser policy; installation stopped")

        known = sorted(ws.paired_hashes() | {current_hash})
        atomic_write_text(ws.app_file("pair.txt"), "".join(f"{item}\n" for item in known))
        copy_atomic(USB_BLOCKLIST, ws.app_file("blocklist.txt"))
        read_blocklist(ws.app_file("blocklist.txt"))
        create_emergency_shortcut()
    finally:
        if lock is not None:
            lock.close()

    # The original release's watchdog takes no lock; make sure none started in the meantime.
    ws.stop_legacy_watchdogs()
    ws.create_task(runtime, ws.app_file("watchdog.py"))
    for obsolete in ("Chainlink.ps1", "Chainlink.Common.psm1", "watchdog.ps1"):
        ws.app_file(obsolete).unlink(missing_ok=True)

    # First time on this PC: recovery words for the accountability partner. Made last, so that
    # if anything above fails the words are not stored without ever being shown.
    if not recovery_file().exists():
        words = new_recovery_words()
        write_recovery(words)
        return words
    return None


def uninstall_chainlink() -> None:
    # Order matters. First make sure no watchdog is running and none can start (the task fires
    # every minute and would re-apply the blocks behind our back), then lift the blocks, and
    # only then delete the files.
    require_trusted_program_folder()
    lock = ws.stop_watchdog()
    try:
        ws.delete_task()
        unlock_installed()
        # Tell any watchdog that was already starting to exit instead of locking again. It can
        # only get the lock after this point, and it checks for the marker once it has it.
        if ws.APP_DIR.is_dir():
            ws.uninstall_marker().write_bytes(b"")
    finally:
        if lock is not None:
            lock.close()
    EMERGENCY_SHORTCUT.unlink(missing_ok=True)
    app_dir = ws.APP_DIR
    if app_dir.exists():
        if ws.is_reparse_point(app_dir):
            raise RuntimeError("refusing to remove a reparse-point program directory")
        # A watchdog that is just exiting can hold the lock file for a moment; retry briefly.
        for attempt in range(10):
            try:
                shutil.rmtree(app_dir)
                break
            except OSError:
                if attempt == 9:
                    raise
                time.sleep(0.5)


def blocklist_for_ui() -> tuple[list[str], list[str], bool, list[str]]:
    """Websites, channels, the Shorts switch, and any lines that are not valid.

    A line that is not valid is shown as written so it can be fixed; it is never dropped.
    """
    sites: list[str] = []
    channels: list[str] = []
    invalid: list[str] = []
    shorts = False
    try:
        lines = USB_BLOCKLIST.read_bytes().decode("utf-8-sig", errors="replace").splitlines()
    except FileNotFoundError:
        lines = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            entry = normalize_entry(line)
        except ValidationError:
            sites.append(line)
            invalid.append(line)
            continue
        if entry.lower() == SHORTS_ENTRY:
            shorts = True
        elif entry.startswith(("youtube.com/@", "youtube.com/channel/", "youtube.com/c/", "youtube.com/user/")):
            channels.append(entry.removeprefix("youtube.com/"))
        elif entry not in sites:
            sites.append(entry)
    return sites, channels, shorts, invalid


def save_blocklist(sites: list[str], channels: list[str], shorts: bool) -> None:
    normalized_sites = list(dict.fromkeys(filter(None, (normalize_entry(value) for value in sites))))
    normalized_channels = list(dict.fromkeys(filter(None, (normalize_channel(value) for value in channels))))
    if len(normalized_sites) + len(normalized_channels) + int(shorts) > MAX_ENTRIES:
        raise ValidationError(f"the blocklist can hold at most {MAX_ENTRIES:,} entries")
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

    def copy_words() -> None:
        dialog.clipboard_clear()
        dialog.clipboard_append(" ".join(words))
        copy.configure(text="Copied!")

    copy = ttk.Button(dialog, text="Copy words", command=copy_words)
    copy.grid(row=5, column=0, columnspan=2, pady=(12, 0))
    confirmed = tk.BooleanVar()
    checkbox = ttk.Checkbutton(dialog, text="My accountability partner has these words.", variable=confirmed)
    checkbox.grid(row=6, column=0, columnspan=2, padx=20, pady=(14, 6))
    done = ttk.Button(dialog, text="Done", command=dialog.destroy, state="disabled")
    done.grid(row=7, column=0, columnspan=2, pady=(0, 20))
    confirmed.trace_add("write", lambda *_: done.configure(state="normal" if confirmed.get() else "disabled"))
    dialog.protocol("WM_DELETE_WINDOW", lambda: None)  # must use the button, so the words can't be skipped by accident
    parent.wait_window(dialog)
    try:
        parent.clipboard_clear()  # don't leave the words on the clipboard
    except tk.TclError:
        pass


def emergency_ui() -> int:
    root = tk.Tk()
    root.title("Chainlink - emergency uninstall")
    root.resizable(False, False)
    if not recovery_file().is_file():
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
        if not verify_recovery_record(recovery_file().read_text(encoding="utf-8-sig"), words):
            register_recovery_failure()
            status.configure(text="Those words do not match. Check spelling and order.")
            return
        recovery_attempts_file().unlink(missing_ok=True)
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
        self.saved = ""
        invalid = self.load()
        self.update_status()
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        if invalid:
            shown = "\n".join(invalid[:10])
            self.root.after(200, lambda: messagebox.showwarning(
                "Chainlink",
                "blocklist.txt has lines Chainlink cannot use. They are shown as written in the website box; "
                "fix or delete them, then save. Until then this PC keeps using the last good list.\n\n" + shown,
                parent=self.root,
            ))

    @staticmethod
    def lines(widget: tk.Text) -> list[str]:
        return [line.strip() for line in widget.get("1.0", "end").splitlines() if line.strip()]

    def snapshot(self) -> str:
        return "\n".join(self.lines(self.sites)) + "|" + "\n".join(self.lines(self.channels)) + "|" + str(self.shorts.get())

    def load(self) -> list[str]:
        sites, channels, shorts, invalid = blocklist_for_ui()
        self.sites.delete("1.0", "end")
        self.sites.insert("1.0", "\n".join(sites))
        self.channels.delete("1.0", "end")
        self.channels.insert("1.0", "\n".join(channels))
        self.shorts.set(shorts)
        self.saved = self.snapshot()
        return invalid

    def close(self) -> None:
        # Offer to save unsaved edits when closing.
        if self.snapshot() != self.saved:
            answer = messagebox.askyesnocancel("Chainlink", "Save your blocklist changes before closing?", parent=self.root)
            if answer is None or (answer and not self.save(announce=False)):
                return
        self.root.destroy()

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
        installed = ws.genuine_task() or any(ws.app_file(name).is_file() for name in ("watchdog.py", "watchdog.ps1"))
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
        if not messagebox.askyesno("Chainlink", "Make new recovery words for this PC? The old words will stop working, so your partner will need the new ones.", parent=self.root):
            return
        try:
            words = new_recovery_words()
            write_recovery(words)
        except Exception as error:
            messagebox.showerror("Chainlink", f"Could not make new recovery words:\n{error}", parent=self.root)
            return
        show_recovery_words(self.root, words)

    def run(self) -> None:
        self.root.mainloop()


def main() -> int:
    parser = argparse.ArgumentParser(description="Chainlink settings")
    parser.add_argument("--emergency", action="store_true")
    arguments = parser.parse_args()
    if not ws.is_admin():
        # pythonw has no console window, so the elevated copy shows only the Chainlink window.
        ws.relaunch_elevated(pythonw_executable(), [*PYTHON_FLAGS, str(Path(__file__).resolve()), *(["--emergency"] if arguments.emergency else [])])
        return 0
    try:
        if arguments.emergency:
            return emergency_ui()
        ChainlinkApp().run()
        return 0
    except Exception as error:  # under pythonw an uncaught error would otherwise show nothing at all
        messagebox.showerror("Chainlink", f"Chainlink could not start:\n{error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
