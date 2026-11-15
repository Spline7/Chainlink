"""Chainlink background watchdog. This file is installed and run as SYSTEM.

Every 5 seconds it looks for the paired Chainlink USB key:
  - key NOT found -> browser blocks are ON
  - key found     -> browser blocks are OFF, and the blocklist is synced from the USB
It makes no network requests and sends no telemetry.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

# The task runs Python in isolated mode, which does not add this folder to the import path.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from windows_support import (  # noqa: E402
    APP_DIR,
    Watchdog,
    app_file,
    capture_baseline,
    log,
    open_watchdog_lock,
    remove_lock,
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

    if not APP_DIR.is_dir():  # uninstalled
        return 0
    lock = open_watchdog_lock(app_file("watchdog.lock"))
    if lock is None:  # another watchdog, or an install or uninstall, holds the lock
        return 0
    try:
        log("Watchdog started.")
        watchdog = Watchdog()
        while True:
            watchdog.cycle()
            time.sleep(5)
    finally:
        lock.close()


if __name__ == "__main__":
    raise SystemExit(main())
