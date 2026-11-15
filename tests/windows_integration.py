"""Read-only/safe helpers for validating Windows integration from CI or Herdr."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "Chainlink"
sys.path.insert(0, str(SOURCE))

from windows_support import secure_app_directory, task_xml, volume_serial  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    serial = subparsers.add_parser("serial")
    serial.add_argument("root")
    xml = subparsers.add_parser("disabled-task-xml")
    xml.add_argument("output", type=Path)
    secure = subparsers.add_parser("secure-directory")
    secure.add_argument("path", type=Path)
    arguments = parser.parse_args()

    if arguments.command == "serial":
        print(volume_serial(arguments.root))
        return 0
    if arguments.command == "secure-directory":
        arguments.path.mkdir(exist_ok=False)
        secure_app_directory(arguments.path)
        return 0
    generated = task_xml(Path(sys.executable), Path(r"C:\ProgramData\Chainlink\watchdog.py"))
    generated = generated.replace("<Settings>", "<Settings><Enabled>false</Enabled>")
    arguments.output.write_text(generated, encoding="utf-16")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
