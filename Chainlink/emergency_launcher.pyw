"""Small public launcher that elevates before reading protected installed files."""

from __future__ import annotations

import ctypes
import subprocess
import sys


def main() -> None:
    if len(sys.argv) != 2:
        return
    arguments = subprocess.list2cmdline(["-B", sys.argv[1], "--emergency"])
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, arguments, None, 0)


if __name__ == "__main__":
    main()
