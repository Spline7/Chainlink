"""Chainlink background watchdog. This file is installed and run as SYSTEM."""

from __future__ import annotations

import argparse
import ctypes
import os
import time

from windows_support import (
    PID_FILE,
    capture_baseline,
    find_key,
    lock_intact,
    log,
    remove_lock,
    set_lock,
    set_status,
    sync_blocklist,
    validate_usb_blocklist,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Chainlink watchdog")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--unlock", action="store_true", help="restore browser policy and exit")
    group.add_argument("--capture-baseline", action="store_true", help="capture browser policy and exit")
    arguments = parser.parse_args()

    if arguments.capture_baseline:
        capture_baseline()
        return 0
    if arguments.unlock:
        remove_lock()
        log("Chainlink browser policies removed and prior policies restored.")
        return 0

    mutex = ctypes.windll.kernel32.CreateMutexW(None, True, "Global\\ChainlinkWatchdog")
    if not mutex:
        raise ctypes.WinError()
    if ctypes.windll.kernel32.GetLastError() == 183:
        log("A watchdog instance is already running; exiting duplicate.")
        ctypes.windll.kernel32.CloseHandle(mutex)
        return 0

    try:
        PID_FILE.write_text(str(os.getpid()), encoding="ascii")
        log("Watchdog started.")
        state = ""
        tick = 0
        while True:
            try:
                usb = find_key()
                if usb:
                    validate_usb_blocklist(usb)
                    if state != "unlocked":
                        remove_lock()
                        state = "unlocked"
                        set_status(f"UNLOCKED - key found on {usb}")
                        log(f"Key found on {usb} - blocks lifted.")
                    sync_blocklist(usb)
                elif state != "locked" or (tick % 12 == 0 and not lock_intact()):
                    set_lock()
                    log("Blocks were changed outside Chainlink - re-applied." if state == "locked" else "Key not present - blocks applied.")
                    state = "locked"
                    set_status("LOCKED - key not present")
            except Exception as error:  # keep a SYSTEM watchdog alive and fail closed
                log(f"Watchdog cycle failed: {error}")
                try:
                    set_lock()
                    state = "locked"
                    set_status("LOCKED - fail-safe after an error")
                except Exception as fail_safe_error:
                    log(f"Fail-safe lock also failed: {fail_safe_error}")
            tick += 1
            time.sleep(5)
    finally:
        PID_FILE.unlink(missing_ok=True)
        ctypes.windll.kernel32.ReleaseMutex(mutex)
        ctypes.windll.kernel32.CloseHandle(mutex)


if __name__ == "__main__":
    raise SystemExit(main())
