"""Windows-only checks.

Nothing here touches real browser policy, the real Chainlink folder, or real scheduled tasks:
policy code runs against a scratch key under HKEY_CURRENT_USER, files live in temporary
folders, and Task Scheduler is replaced by a recorder.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

REPOSITORY = Path(__file__).resolve().parents[1]
SOURCE = REPOSITORY / "Chainlink"
sys.path.insert(0, str(SOURCE))

if os.name != "nt":
    raise unittest.SkipTest("Windows-only tests")

import winreg  # noqa: E402

import windows_support as ws  # noqa: E402

ENTRIES = ["x.example", "youtube.com/shorts"]


def forbidden(*_arguments, **_keywords):
    raise AssertionError("the tests must never reach the real Task Scheduler")


class ScratchPolicy(unittest.TestCase):
    """Redirects every policy read and write to HKCU\\Software\\ChainlinkTests-<random>."""

    def setUp(self) -> None:
        self.root = "Software\\ChainlinkTests-" + uuid.uuid4().hex
        winreg.CloseKey(winreg.CreateKey(winreg.HKEY_CURRENT_USER, self.root))
        for name, value in (("POLICY_HIVE", winreg.HKEY_CURRENT_USER), ("POLICY_ROOT", self.root), ("_schtasks", forbidden)):
            patcher = mock.patch.object(ws, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(self.delete_tree, self.root)

    def delete_tree(self, path: str) -> None:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_READ) as key:
                children = [winreg.EnumKey(key, index) for index in range(winreg.QueryInfoKey(key)[0])]
        except FileNotFoundError:
            return
        for child in children:
            self.delete_tree(path + "\\" + child)
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)

    def subkeys(self) -> list[str]:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.root, 0, winreg.KEY_READ) as key:
            return [winreg.EnumKey(key, index) for index in range(winreg.QueryInfoKey(key)[0])]

    def values(self, sub: str) -> list[str]:
        items = ws.list_snapshot(self.root + "\\" + sub)
        return [item["value"] for item in sorted(items, key=lambda item: int(item["name"]))]

    def value(self, sub: str, name: str):
        return ws.value_snapshot(self.root + "\\" + sub, name)["value"]

    def set_value(self, sub: str, name: str, kind: int, value) -> None:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, self.root + "\\" + sub, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, name, 0, kind, value)

    def baseline(self):
        return json.loads(json.dumps(ws.capture_baseline_data()))


class PolicyTests(ScratchPolicy):
    CHROME = "Google\\Chrome"
    CHROME_LIST = "Google\\Chrome\\URLBlocklist"
    FIREFOX_LIST = "Mozilla\\Firefox\\WebsiteFilter\\Block"

    def test_clean_machine_round_trip_leaves_nothing_behind(self) -> None:
        baseline = self.baseline()
        self.assertTrue(ws.baseline_is_valid(baseline))
        ws.apply_lock(ENTRIES, [], baseline)
        self.assertEqual(ENTRIES, self.values(self.CHROME_LIST))
        self.assertEqual(1, self.value(self.CHROME, "IncognitoModeAvailability"))
        self.assertEqual(1, self.value("BraveSoftware\\Brave", "TorDisabled"))
        self.assertEqual(1, self.value("Mozilla\\Firefox", "DisablePrivateBrowsing"))
        self.assertIn("*://*.x.example/*", self.values(self.FIREFOX_LIST))
        self.assertTrue(ws.lock_is_applied(ENTRIES))

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.root + "\\" + self.CHROME, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, "IncognitoModeAvailability")
        self.assertFalse(ws.lock_is_applied(ENTRIES))
        ws.apply_lock(ENTRIES, ENTRIES, baseline)
        ws.write_list(self.root + "\\" + self.FIREFOX_LIST, [])
        self.assertFalse(ws.lock_is_applied(ENTRIES))
        ws.apply_lock(ENTRIES, ENTRIES, baseline)

        ws.lift_lock(ENTRIES, baseline)
        self.assertEqual([], self.subkeys())

    def test_preexisting_policy_survives(self) -> None:
        self.set_value(self.CHROME_LIST, "1", winreg.REG_SZ, "corp.example")
        self.set_value(self.CHROME, "IncognitoModeAvailability", winreg.REG_DWORD, 2)
        self.set_value(self.CHROME, "HomepageLocation", winreg.REG_SZ, "https://corp.example")
        baseline = self.baseline()

        ws.apply_lock(ENTRIES, [], baseline)
        self.assertEqual(["corp.example", *ENTRIES], self.values(self.CHROME_LIST))
        # The blocklist changes while locked: old entries are replaced, not mistaken for foreign policy.
        ws.apply_lock(["z.example"], ENTRIES, baseline)
        self.assertEqual(["corp.example", "z.example"], self.values(self.CHROME_LIST))
        # Someone else adds an entry while locked; it must survive unlock.
        self.set_value(self.CHROME_LIST, "99", winreg.REG_SZ, "later.example")

        ws.lift_lock(["z.example", *ENTRIES], baseline)
        self.assertEqual(["corp.example", "later.example"], self.values(self.CHROME_LIST))
        self.assertEqual(2, self.value(self.CHROME, "IncognitoModeAvailability"))
        self.assertEqual("https://corp.example", self.value(self.CHROME, "HomepageLocation"))
        self.assertIsNone(self.value(self.CHROME, "BrowserGuestModeEnabled"))
        self.assertNotIn("Mozilla", self.subkeys())

    def test_unlock_without_a_baseline_removes_only_managed_values(self) -> None:
        self.set_value(self.CHROME_LIST, "1", winreg.REG_SZ, "corp.example")
        ws.apply_lock(ENTRIES, [], None)
        ws.lift_lock(ENTRIES, None)
        self.assertEqual(["corp.example"], self.values(self.CHROME_LIST))
        self.assertIsNone(self.value(self.CHROME, "IncognitoModeAvailability"))
        self.assertFalse(ws.baseline_is_valid({"version": 2}))

    def test_baseline_written_by_the_powershell_release(self) -> None:
        baseline = json.loads((Path(__file__).parent / "powershell-baseline.json").read_text(encoding="utf-8"))
        self.assertTrue(ws.baseline_is_valid(baseline))
        ws.apply_lock(ENTRIES, [], baseline)
        self.assertEqual(["corp.example", *ENTRIES], self.values(self.CHROME_LIST))
        ws.lift_lock(ENTRIES, baseline)
        self.assertEqual(["corp.example"], self.values(self.CHROME_LIST))
        self.assertEqual(2, self.value(self.CHROME, "IncognitoModeAvailability"))
        self.assertEqual(["*://a.example/*", "*://b.example/*"], self.values(self.FIREFOX_LIST))


class WatchdogTests(ScratchPolicy):
    def setUp(self) -> None:
        super().setUp()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        base = Path(self.temporary.name)
        self.app = base / "app"
        self.usb = base / "usb"
        self.app.mkdir()
        (self.usb / "Chainlink").mkdir(parents=True)
        self.key_present = False
        for name, value in (("APP_DIR", self.app), ("find_key", lambda: self.usb if self.key_present else None)):
            patcher = mock.patch.object(ws, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        (self.app / "blocklist.txt").write_text("x.example\n", encoding="utf-8")
        ws.capture_baseline()
        self.usb_blocklist = self.usb / "Chainlink" / "blocklist.txt"

    def chrome(self) -> list[str]:
        return self.values("Google\\Chrome\\URLBlocklist")

    def installed(self) -> list[str]:
        return ws.read_blocklist(self.app / "blocklist.txt")

    def test_lock_unlock_and_sync(self) -> None:
        watchdog = ws.Watchdog()
        watchdog.cycle()
        self.assertEqual("locked", watchdog.state)
        self.assertEqual(["x.example"], self.chrome())
        self.assertEqual(["x.example"], ws.applied_entries())
        self.assertTrue((self.app / "status.txt").read_text().startswith("LOCKED"))

        self.usb_blocklist.write_text("y.example\n", encoding="utf-8")
        self.key_present = True
        watchdog.cycle()
        self.assertEqual("unlocked", watchdog.state)
        self.assertEqual([], self.subkeys())
        self.assertFalse((self.app / "applied-blocklist.txt").exists())
        self.assertEqual(["y.example"], self.installed())

    def test_bad_usb_blocklist_does_not_lock_a_pc_whose_key_is_present(self) -> None:
        watchdog = ws.Watchdog()
        self.key_present = True
        self.usb_blocklist.write_text("y.example\nnot a host name\n", encoding="utf-8")
        watchdog.cycle()
        self.assertEqual("unlocked", watchdog.state)
        self.assertNotEqual("", watchdog.usb_problem)
        self.assertEqual(["x.example"], self.installed())
        self.assertIn("previous blocklist", (self.app / "status.txt").read_text())
        self.usb_blocklist.unlink()
        watchdog.cycle()
        self.assertEqual("unlocked", watchdog.state)
        self.assertEqual([], [path.name for path in self.app.glob(".chainlink-*")])

    def test_damaged_installed_blocklist_blocks_everything_and_still_unlocks_cleanly(self) -> None:
        watchdog = ws.Watchdog()
        watchdog.cycle()
        (self.app / "blocklist.txt").write_text("not a host name\n", encoding="utf-8")
        watchdog.tick = 0
        watchdog.cycle()
        self.assertIn("*", self.chrome())
        self.usb_blocklist.write_text("z.example\n", encoding="utf-8")
        self.key_present = True
        watchdog.cycle()
        self.assertEqual("unlocked", watchdog.state)
        self.assertEqual([], self.subkeys())
        self.assertEqual(["z.example"], self.installed())

    def test_unlocks_without_a_readable_baseline(self) -> None:
        watchdog = ws.Watchdog()
        watchdog.cycle()
        (self.app / "policy-baseline.json").write_text("{ not json", encoding="utf-8")
        self.usb_blocklist.write_text("x.example\n", encoding="utf-8")
        self.key_present = True
        watchdog.cycle()
        self.assertEqual("unlocked", watchdog.state)
        self.assertEqual([], self.subkeys())

    def test_lock_file_has_one_holder(self) -> None:
        path = self.app / "watchdog.lock"
        lock = ws.open_watchdog_lock(path)
        self.assertIsNotNone(lock)
        try:
            self.assertIsNone(ws.open_watchdog_lock(path))
            self.assertEqual(os.getpid(), ws.watchdog_lock_owner(path))
        finally:
            lock.close()
        again = ws.open_watchdog_lock(path)
        self.assertIsNotNone(again)
        again.close()


class TaskAndDriveTests(unittest.TestCase):
    def test_task_recognition(self) -> None:
        python = ws.PROGRAM_FILES_ROOTS[0] / "Python312" / "python.exe"
        xml = ws.task_xml(python, ws.app_file("watchdog.py"))
        self.assertIn("<UserId>S-1-5-18</UserId>", xml)
        self.assertIn("-I -B", xml)
        self.assertTrue(ws.task_xml_is_genuine(xml))
        self.assertTrue(ws.task_xml_references_app_dir(xml))
        self.assertFalse(ws.task_xml_is_genuine(xml.replace("S-1-5-18", "S-1-5-21-1-2-3-1001")))
        self.assertFalse(ws.task_xml_is_genuine(xml.replace(str(python), r"C:\Users\Public\python.exe")))
        self.assertFalse(ws.task_xml_is_genuine(xml.replace("-I -B", "-c evil -B")))

        script = ws.app_file("watchdog.ps1")
        legacy = f'-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "{script}"'
        template = '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Principals><Principal><UserId>S-1-5-18</UserId></Principal></Principals><Actions><Exec><Command>{}</Command><Arguments>{}</Arguments></Exec></Actions></Task>'
        from xml.sax.saxutils import escape
        self.assertTrue(ws.task_xml_is_genuine(template.format("powershell.exe", escape(legacy))), "task of the original release")
        self.assertTrue(ws.task_xml_is_genuine(template.format(ws.system_executable(r"WindowsPowerShell\v1.0\powershell.exe"), escape(legacy))))
        foreign = template.format(r"C:\Windows\System32\cmd.exe", "/c exit")
        self.assertFalse(ws.task_xml_is_genuine(foreign))
        self.assertFalse(ws.task_xml_references_app_dir(foreign))
        self.assertTrue(ws.task_xml_references_app_dir(template.format("cmd.exe", escape(f'/c "{script}"'))))

    def test_trusted_paths_ignore_environment(self) -> None:
        with mock.patch.dict(os.environ, {"ProgramData": r"C:\Chainlink-Evil", "SystemRoot": r"C:\Chainlink-Evil"}):
            self.assertNotIn("Chainlink-Evil", str(ws.known_folder("62ab5d82-fdc1-4dc3-a9dd-070d1d495d97")))
            self.assertNotIn("Chainlink-Evil", str(ws.system_executable("schtasks.exe")))

    def test_volume_serial_matches_windows(self) -> None:
        root = os.environ.get("SystemDrive", "C:") + "\\"
        serials = ws.volume_serials(root)
        self.assertRegex(serials[0], r"^[0-9A-F]{8}$")
        powershell = ws.system_executable(r"WindowsPowerShell\v1.0\powershell.exe")
        query = f"(Get-CimInstance Win32_LogicalDisk -Filter \"DeviceID='{root[:2]}'\").VolumeSerialNumber"
        reported = subprocess.run([str(powershell), "-NoProfile", "-NonInteractive", "-Command", query], capture_output=True, text=True, check=True).stdout.strip()
        self.assertIn(reported, serials)


@unittest.skipUnless(ws.is_admin(), "needs an elevated prompt to assign the Administrators group as owner")
class ProtectedDirectoryTests(unittest.TestCase):
    def test_new_directory_is_protected_and_existing_is_never_adopted(self) -> None:
        with tempfile.TemporaryDirectory() as base:
            path = Path(base) / "protected"
            ws.create_protected_directory(path)
            self.assertTrue(ws.is_protected_directory(path))
            self.assertRegex(ws.path_sddl(path), r"^O:BAD:P(AI)?\(A;OICI;FA;;;SY\)\(A;OICI;FA;;;BA\)$")
            with self.assertRaises(OSError):
                ws.create_protected_directory(path)

            loose = Path(base) / "loose"
            loose.mkdir()
            self.assertFalse(ws.is_protected_directory(loose))
            ws.protect_existing_directory(loose)
            self.assertTrue(ws.is_protected_directory(loose))


@unittest.skipUnless(ws.is_admin(), "needs an elevated prompt to create the protected folder")
class InstallTests(unittest.TestCase):
    """Install, repair, and uninstall with Task Scheduler and policy changes recorded, not performed."""

    def setUp(self) -> None:
        import chainlink

        self.chainlink = chainlink
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        base = Path(self.temporary.name)
        self.app = base / "app"
        usb = base / "usb"
        usb.mkdir()
        for name in (*chainlink.INSTALL_FILES, "emergency_launcher.pyw", "blocklist.txt"):
            (usb / name).write_bytes((SOURCE / name).read_bytes())
        self.calls: list[str] = []
        self.task_xml: str | None = None
        self.fail_create = False

        def create_task(python: Path, watchdog: Path) -> None:
            if self.fail_create:
                raise RuntimeError("simulated Task Scheduler failure")
            self.calls.append("create")
            self.task_xml = ws.task_xml(ws.PROGRAM_FILES_ROOTS[0] / "Python312" / "python.exe", watchdog)

        def delete_task() -> None:
            if self.task_xml and (ws.task_xml_is_genuine(self.task_xml) or ws.task_xml_references_app_dir(self.task_xml)):
                self.calls.append("delete")
                self.task_xml = None

        patches = [
            (ws, "APP_DIR", self.app),
            (ws, "_schtasks", forbidden),
            (ws, "stop_task", lambda: self.calls.append("stop")),
            (ws, "create_task", create_task),
            (ws, "delete_task", delete_task),
            (ws, "query_task_xml", lambda: self.task_xml),
            (ws, "capture_baseline", lambda: (self.calls.append("baseline"), ws.app_file("policy-baseline.json").write_text(json.dumps({"version": 2})))),
            (ws, "read_baseline", lambda: {"version": 2}),
            (ws, "remove_lock", lambda: self.calls.append("unlock")),
            (chainlink, "run_powershell_watchdog", lambda script, mode: self.calls.append(f"powershell {mode}")),
            (chainlink, "validated_runtime", lambda: Path(sys.executable)),
            (chainlink, "USB_DIR", usb),
            (chainlink, "USB_ROOT", Path(Path(os.environ.get("SystemDrive", "C:") + "\\"))),
            (chainlink, "KEY_FILE", usb / "chainlink.key"),
            (chainlink, "USB_BLOCKLIST", usb / "blocklist.txt"),
            (chainlink, "EMERGENCY_COMMAND", base / "Chainlink Emergency Uninstall.cmd"),
            (chainlink, "EMERGENCY_LAUNCHER", base / "Chainlink Emergency Uninstall.pyw"),
        ]
        for target, name, value in patches:
            patcher = mock.patch.object(target, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_prefilled_folder_is_never_adopted(self) -> None:
        self.app.mkdir()
        (self.app / "watchdog.py").write_text("planted")
        with self.assertRaises(RuntimeError):
            self.chainlink.install_chainlink()
        self.assertEqual("planted", (self.app / "watchdog.py").read_text())

    def test_failed_first_link_leaves_nothing_behind(self) -> None:
        self.fail_create = True
        with self.assertRaises(RuntimeError):
            self.chainlink.install_chainlink()
        self.assertFalse(self.app.exists())
        self.assertFalse(self.chainlink.EMERGENCY_COMMAND.exists())
        self.assertFalse(self.chainlink.EMERGENCY_LAUNCHER.exists())

    def test_foreign_task_blocks_linking_and_is_left_alone(self) -> None:
        self.task_xml = '<Task><Principals><Principal><UserId>S-1-5-18</UserId></Principal></Principals><Actions><Exec><Command>C:\\Windows\\System32\\cmd.exe</Command><Arguments>/c exit</Arguments></Exec></Actions></Task>'
        with self.assertRaises(RuntimeError):
            self.chainlink.install_chainlink()
        self.assertFalse(self.app.exists())
        ws.delete_task()
        self.assertIsNotNone(self.task_xml)

    def test_link_repair_and_uninstall(self) -> None:
        chainlink = self.chainlink
        words = chainlink.install_chainlink()
        self.assertEqual(6, len(words))
        self.assertTrue(ws.is_protected_directory(self.app))
        for name in (*chainlink.INSTALL_FILES, "blocklist.txt", "pair.txt", "recovery.txt", "policy-baseline.json"):
            self.assertTrue((self.app / name).is_file(), name)
        self.assertRegex((self.app / "pair.txt").read_text().strip(), r"^[0-9a-f]{64}$")
        self.assertIn("-I -B", chainlink.EMERGENCY_COMMAND.read_text())
        self.assertEqual(["stop", "baseline", "create"], self.calls)
        self.assertTrue(chainlink.usb_matches_pc())
        record = chainlink.recovery_file().read_text()
        self.assertTrue(chainlink.verify_recovery_record(record, words))
        chainlink.register_recovery_failure()
        self.assertGreater(chainlink.recovery_delay(), 0)

        # Repair keeps the recovery words and lifts the old copy's blocks first.
        self.calls.clear()
        self.assertIsNone(chainlink.install_chainlink())
        self.assertEqual(record, chainlink.recovery_file().read_text())
        self.assertEqual(["stop", "unlock", "baseline", "create"], self.calls)

        # While a watchdog holds the lock, uninstall must not touch anything.
        held = ws.open_watchdog_lock(ws.app_file("watchdog.lock"))
        try:
            self.calls.clear()
            with mock.patch.object(ws.time, "monotonic", side_effect=[0.0, 100.0, 200.0]), self.assertRaises(RuntimeError):
                chainlink.uninstall_chainlink()
            self.assertEqual(["stop"], self.calls)
        finally:
            held.close()

        # Uninstall: task first, then unlock, then files.
        self.calls.clear()
        chainlink.uninstall_chainlink()
        self.assertEqual(["stop", "delete", "unlock"], self.calls)
        self.assertFalse(self.app.exists())
        self.assertFalse(chainlink.EMERGENCY_COMMAND.exists())

    def test_upgrade_from_the_original_powershell_release(self) -> None:
        ws.create_protected_directory(self.app)
        script = self.app / "watchdog.ps1"
        script.write_text("# original watchdog")
        legacy = f'-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "{script}"'
        from xml.sax.saxutils import escape
        self.task_xml = f'<Task><Principals><Principal><UserId>S-1-5-18</UserId></Principal></Principals><Actions><Exec><Command>powershell.exe</Command><Arguments>{escape(legacy)}</Arguments></Exec></Actions></Task>'
        self.chainlink.install_chainlink()
        self.assertEqual(["stop", "powershell -Unlock", "baseline", "create"], self.calls)
        self.assertFalse(script.exists())


class UiSmokeTests(unittest.TestCase):
    """Builds the settings window without showing dialogs or touching the PC."""

    def test_invalid_lines_are_shown_and_never_silently_dropped(self) -> None:
        import tkinter as tk

        import chainlink

        with tempfile.TemporaryDirectory() as base:
            blocklist = Path(base) / "blocklist.txt"
            blocklist.write_text("# comment\nExample.com\nnot a host name\nyoutube.com/shorts\nyoutube.com/@SomeCreator\n", encoding="utf-8")
            with mock.patch.object(chainlink, "USB_BLOCKLIST", blocklist), \
                 mock.patch.object(ws, "APP_DIR", Path(base) / "app"), \
                 mock.patch.object(ws, "genuine_task", lambda: False), \
                 mock.patch.object(chainlink, "messagebox") as boxes:
                try:
                    app = chainlink.ChainlinkApp()
                except tk.TclError as error:
                    self.skipTest(f"no desktop available: {error}")
                try:
                    self.assertEqual(["example.com", "not a host name"], app.lines(app.sites))
                    self.assertEqual(["@SomeCreator"], app.lines(app.channels))
                    self.assertTrue(app.shorts.get())
                    self.assertFalse(app.save(announce=False), "a list with an invalid line must not be saved")
                    boxes.showerror.assert_called_once()
                    self.assertIn("not a host name", blocklist.read_text(encoding="utf-8"))

                    app.sites.delete("1.0", "end")
                    app.sites.insert("1.0", "https://www.Example.com/\n*.second.example\n")
                    self.assertTrue(app.save(announce=False))
                    self.assertEqual(["example.com", "second.example", "youtube.com/shorts", "youtube.com/@SomeCreator"], ws.read_blocklist(blocklist))
                    self.assertEqual(app.saved, app.snapshot())
                finally:
                    app.root.destroy()


if __name__ == "__main__":
    unittest.main()
