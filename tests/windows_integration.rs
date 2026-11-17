//! Windows-only checks.
//!
//! Nothing here touches real browser policy, the real Chainlink folder, or real scheduled
//! tasks: policy code runs against a scratch key under HKEY_CURRENT_USER, files live in
//! temporary folders, and Task Scheduler is replaced by a recorder.

#![cfg(windows)]

use anyhow::{Result, bail};
use chainlink_blocker::core::read_blocklist;
use chainlink_blocker::windows::{
    self, Baseline, Env, Host, LockState, PolicyRoot, Scheduler, Watchdog,
};
use std::cell::RefCell;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tempfile::TempDir;
use winreg::HKCU;
use winreg::enums::{KEY_READ, KEY_WRITE};

static NEXT: AtomicU32 = AtomicU32::new(0);

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(ToString::to_string).collect()
}

/// A scratch policy key that is deleted again when the test ends.
struct Scratch {
    path: String,
}

impl Scratch {
    fn new() -> Self {
        let path = format!(
            r"Software\ChainlinkTests-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        );
        HKCU.create_subkey(&path).expect("create scratch key");
        Self { path }
    }

    fn root(&self) -> PolicyRoot {
        PolicyRoot {
            hive: HKCU,
            path: self.path.clone(),
        }
    }

    fn subkeys(&self) -> Vec<String> {
        HKCU.open_subkey(&self.path)
            .expect("open scratch key")
            .enum_keys()
            .filter_map(Result::ok)
            .collect()
    }

    fn list(&self, sub: &str) -> Vec<String> {
        let Ok(key) = HKCU.open_subkey(format!(r"{}\{sub}", self.path)) else {
            return Vec::new();
        };
        let mut values = key
            .enum_values()
            .filter_map(Result::ok)
            .map(|(name, value)| (name.parse::<u32>().unwrap_or(0), value.to_string()))
            .collect::<Vec<_>>();
        values.sort();
        values.into_iter().map(|(_, value)| value).collect()
    }

    fn dword(&self, sub: &str, name: &str) -> Option<u32> {
        HKCU.open_subkey(format!(r"{}\{sub}", self.path))
            .ok()?
            .get_value(name)
            .ok()
    }

    fn set_string(&self, sub: &str, name: &str, value: &str) {
        let (key, _) = HKCU
            .create_subkey(format!(r"{}\{sub}", self.path))
            .expect("create key");
        key.set_value(name, &value).expect("set value");
    }

    fn set_dword(&self, sub: &str, name: &str, value: u32) {
        let (key, _) = HKCU
            .create_subkey(format!(r"{}\{sub}", self.path))
            .expect("create key");
        key.set_value(name, &value).expect("set value");
    }

    fn delete_value(&self, sub: &str, name: &str) {
        HKCU.open_subkey_with_flags(format!(r"{}\{sub}", self.path), KEY_READ | KEY_WRITE)
            .expect("open key")
            .delete_value(name)
            .expect("delete value");
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = HKCU.delete_subkey_all(&self.path);
    }
}

const CHROME: &str = r"Google\Chrome";
const CHROME_LIST: &str = r"Google\Chrome\URLBlocklist";
const FIREFOX_LIST: &str = r"Mozilla\Firefox\WebsiteFilter\Block";

fn entries() -> Vec<String> {
    strings(&["x.example", "youtube.com/shorts"])
}

#[test]
fn clean_machine_round_trip_leaves_nothing_behind() {
    let scratch = Scratch::new();
    let policy = scratch.root();
    let baseline = policy.capture_baseline();
    let entries = entries();

    policy.apply_lock(&entries, &[], Some(&baseline)).unwrap();
    assert_eq!(scratch.list(CHROME_LIST), entries);
    assert_eq!(scratch.dword(CHROME, "IncognitoModeAvailability"), Some(1));
    assert_eq!(
        scratch.dword(r"BraveSoftware\Brave", "TorDisabled"),
        Some(1)
    );
    assert_eq!(
        scratch.dword(r"Mozilla\Firefox", "DisablePrivateBrowsing"),
        Some(1)
    );
    assert!(
        scratch
            .list(FIREFOX_LIST)
            .contains(&"*://*.x.example/*".to_owned())
    );
    assert!(policy.lock_is_applied(&entries));

    scratch.delete_value(CHROME, "IncognitoModeAvailability");
    assert!(!policy.lock_is_applied(&entries), "removed value");
    policy
        .apply_lock(&entries, &entries, Some(&baseline))
        .unwrap();
    scratch.delete_value(FIREFOX_LIST, "1");
    assert!(!policy.lock_is_applied(&entries), "removed Firefox pattern");
    policy
        .apply_lock(&entries, &entries, Some(&baseline))
        .unwrap();

    policy.lift_lock(&entries, Some(&baseline)).unwrap();
    assert!(scratch.subkeys().is_empty(), "{:?}", scratch.subkeys());
}

#[test]
fn preexisting_policy_survives() {
    let scratch = Scratch::new();
    let policy = scratch.root();
    scratch.set_string(CHROME_LIST, "1", "corp.example");
    scratch.set_dword(CHROME, "IncognitoModeAvailability", 2);
    scratch.set_string(CHROME, "HomepageLocation", "https://corp.example");
    let baseline = policy.capture_baseline();
    let entries = entries();

    policy.apply_lock(&entries, &[], Some(&baseline)).unwrap();
    assert_eq!(
        scratch.list(CHROME_LIST),
        ["corp.example", "x.example", "youtube.com/shorts"]
    );
    // The blocklist changes while locked: old entries are replaced, not mistaken for foreign policy.
    let changed = strings(&["z.example"]);
    policy
        .apply_lock(&changed, &entries, Some(&baseline))
        .unwrap();
    assert_eq!(scratch.list(CHROME_LIST), ["corp.example", "z.example"]);
    // Someone else adds an entry while locked; it must survive unlock.
    scratch.set_string(CHROME_LIST, "99", "later.example");

    let managed = strings(&["z.example", "x.example", "youtube.com/shorts"]);
    policy.lift_lock(&managed, Some(&baseline)).unwrap();
    assert_eq!(scratch.list(CHROME_LIST), ["corp.example", "later.example"]);
    assert_eq!(scratch.dword(CHROME, "IncognitoModeAvailability"), Some(2));
    assert_eq!(scratch.dword(CHROME, "BrowserGuestModeEnabled"), None);
    assert_eq!(scratch.subkeys(), ["Google"]);
}

#[test]
fn unlock_without_a_baseline_removes_only_managed_values() {
    let scratch = Scratch::new();
    let policy = scratch.root();
    scratch.set_string(CHROME_LIST, "1", "corp.example");
    let entries = entries();
    policy.apply_lock(&entries, &[], None).unwrap();
    policy.lift_lock(&entries, None).unwrap();
    assert_eq!(scratch.list(CHROME_LIST), ["corp.example"]);
    assert_eq!(scratch.dword(CHROME, "IncognitoModeAvailability"), None);
    assert!(Baseline::parse(br#"{"version": 3}"#).is_err());
    assert!(Baseline::parse(b"{ not json").is_err());
}

#[test]
fn baseline_written_by_the_powershell_release_is_understood() {
    let scratch = Scratch::new();
    let policy = scratch.root();
    let baseline = Baseline::parse(include_bytes!("powershell-baseline.json")).unwrap();
    let entries = entries();
    policy.apply_lock(&entries, &[], Some(&baseline)).unwrap();
    assert_eq!(
        scratch.list(CHROME_LIST),
        ["corp.example", "x.example", "youtube.com/shorts"]
    );
    policy.lift_lock(&entries, Some(&baseline)).unwrap();
    assert_eq!(scratch.list(CHROME_LIST), ["corp.example"]);
    assert_eq!(scratch.dword(CHROME, "IncognitoModeAvailability"), Some(2));
    assert_eq!(
        scratch.list(FIREFOX_LIST),
        ["*://a.example/*", "*://b.example/*"]
    );
}

/// A temporary program folder, USB folder, and scratch policy key.
struct World {
    _directory: TempDir,
    scratch: Scratch,
    env: Env,
    usb: PathBuf,
}

impl World {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("temporary directory");
        let scratch = Scratch::new();
        let usb = directory.path().join("usb");
        fs::create_dir_all(usb.join("Chainlink")).unwrap();
        let mut env = Env::new(
            directory.path().join("app"),
            scratch.root(),
            directory
                .path()
                .join("stub")
                .join(windows::EMERGENCY_STUB_NAME),
            directory.path().join("Chainlink Emergency Uninstall.lnk"),
        );
        env.require_usb_layout = false; // the tests cannot write to a drive root
        Self {
            _directory: directory,
            scratch,
            env,
            usb,
        }
    }

    fn with_app_dir(self) -> Self {
        fs::create_dir(&self.env.app_dir).unwrap();
        fs::write(self.env.file("blocklist.txt"), "x.example\n").unwrap();
        self.env.capture_baseline().unwrap();
        self
    }

    fn usb_blocklist(&self) -> PathBuf {
        self.usb.join("Chainlink").join("blocklist.txt")
    }

    fn installed(&self) -> Vec<String> {
        read_blocklist(&self.env.file("blocklist.txt")).unwrap()
    }
}

#[test]
fn watchdog_locks_unlocks_and_syncs() {
    let world = World::new().with_app_dir();
    let mut watchdog = Watchdog::default();
    watchdog.cycle(&world.env, None);
    assert_eq!(watchdog.state, LockState::Locked);
    assert_eq!(world.scratch.list(CHROME_LIST), ["x.example"]);
    assert_eq!(world.env.applied_entries(), ["x.example"]);
    assert!(
        fs::read_to_string(world.env.file("status.txt"))
            .unwrap()
            .starts_with("LOCKED")
    );

    fs::write(world.usb_blocklist(), "y.example\n").unwrap();
    watchdog.cycle(&world.env, Some(&world.usb));
    assert_eq!(watchdog.state, LockState::Unlocked);
    assert!(world.scratch.subkeys().is_empty());
    assert!(!world.env.file("applied-blocklist.txt").exists());
    assert_eq!(world.installed(), ["y.example"]);
}

#[test]
fn bad_usb_blocklist_does_not_lock_a_pc_whose_key_is_present() {
    let world = World::new().with_app_dir();
    let mut watchdog = Watchdog::default();
    fs::write(world.usb_blocklist(), "y.example\nnot a host name\n").unwrap();
    watchdog.cycle(&world.env, Some(&world.usb));
    assert_eq!(watchdog.state, LockState::Unlocked);
    assert!(!watchdog.usb_problem.is_empty());
    assert_eq!(world.installed(), ["x.example"]);
    assert!(
        fs::read_to_string(world.env.file("status.txt"))
            .unwrap()
            .contains("previous blocklist")
    );
    fs::remove_file(world.usb_blocklist()).unwrap();
    watchdog.cycle(&world.env, Some(&world.usb));
    assert_eq!(watchdog.state, LockState::Unlocked);
}

#[test]
fn damaged_installed_blocklist_blocks_everything_and_still_unlocks_cleanly() {
    let world = World::new().with_app_dir();
    let mut watchdog = Watchdog::default();
    watchdog.cycle(&world.env, None);
    fs::write(world.env.file("blocklist.txt"), "not a host name\n").unwrap();
    watchdog.tick = 0;
    watchdog.cycle(&world.env, None);
    assert!(world.scratch.list(CHROME_LIST).contains(&"*".to_owned()));

    fs::write(world.usb_blocklist(), "z.example\n").unwrap();
    watchdog.cycle(&world.env, Some(&world.usb));
    assert_eq!(watchdog.state, LockState::Unlocked);
    assert!(
        world.scratch.subkeys().is_empty(),
        "entries written before the damage must still be removed"
    );
    assert_eq!(world.installed(), ["z.example"]);
}

#[test]
fn unlocks_without_a_readable_baseline() {
    let world = World::new().with_app_dir();
    let mut watchdog = Watchdog::default();
    watchdog.cycle(&world.env, None);
    fs::write(world.env.file("policy-baseline.json"), "{ not json").unwrap();
    fs::write(world.usb_blocklist(), "x.example\n").unwrap();
    watchdog.cycle(&world.env, Some(&world.usb));
    assert_eq!(watchdog.state, LockState::Unlocked);
    assert!(world.scratch.subkeys().is_empty());
}

#[test]
fn watchdog_lock_has_one_holder() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("watchdog.lock");
    let lock = windows::open_watchdog_lock(&path).unwrap();
    assert!(lock.is_some());
    assert!(windows::open_watchdog_lock(&path).unwrap().is_none());
    assert_eq!(windows::watchdog_lock_owner(&path), std::process::id());
    drop(lock);
    assert!(windows::open_watchdog_lock(&path).unwrap().is_some());
}

fn task(user: &str, command: &str, arguments: &str) -> String {
    let escape = |value: &str| {
        value
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('"', "&quot;")
    };
    format!(
        "<Task><Principals><Principal><UserId>{user}</UserId></Principal></Principals><Actions><Exec><Command>{}</Command><Arguments>{}</Arguments></Exec></Actions></Task>",
        escape(command),
        escape(arguments)
    )
}

#[test]
fn task_recognition() {
    let world = World::new();
    let env = &world.env;
    let installed = env.file("chainlink.exe");
    let xml = windows::task_xml(&installed, true);
    assert!(xml.contains("<UserId>S-1-5-18</UserId>"));
    assert!(xml.contains(&installed.display().to_string()));
    assert!(env.task_xml_is_genuine(&xml));
    assert!(env.task_xml_references_app_dir(&xml));
    assert!(!env.task_xml_is_genuine(&xml.replace("S-1-5-18", "S-1-5-21-1-2-3-1001")));
    assert!(!env.task_xml_is_genuine(&xml.replace("--watchdog", "--watchdog --extra")));
    assert!(!env.task_xml_is_genuine(&task(
        "S-1-5-18",
        r"C:\Users\Public\chainlink.exe",
        "--watchdog"
    )));

    let script = env.file("watchdog.ps1").display().to_string();
    let legacy = format!(
        "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File \"{script}\""
    );
    assert!(
        env.task_xml_is_genuine(&task("S-1-5-18", "powershell.exe", &legacy)),
        "task of the original release"
    );
    assert!(!env.task_xml_is_genuine(&task(
        "S-1-5-18",
        "powershell.exe",
        &format!("{legacy} -Command evil")
    )));
    let foreign = task("S-1-5-18", r"C:\Windows\System32\cmd.exe", "/c exit");
    assert!(!env.task_xml_is_genuine(&foreign));
    assert!(!env.task_xml_references_app_dir(&foreign));
    assert!(env.task_xml_references_app_dir(&task(
        "S-1-5-18",
        "cmd.exe",
        &format!("/c \"{script}\"")
    )));
}

#[test]
fn volume_serial_matches_windows_inventory() {
    let serials = windows::volume_serials(Path::new(r"C:\")).expect("read the C: volume serial");
    assert_eq!(serials[0].len(), 8);
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            r#"(Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'").VolumeSerialNumber"#,
        ])
        .output()
        .expect("query Windows volume inventory");
    assert!(output.status.success());
    let reported = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    assert!(serials.contains(&reported), "{reported} not in {serials:?}");
}

fn icacls(path: &Path, grant: &str) {
    let status = Command::new("icacls.exe")
        .arg(path)
        .args(["/grant", grant])
        .output()
        .expect("run icacls");
    assert!(status.status.success());
}

#[test]
fn only_folders_non_administrators_could_not_write_are_trusted() {
    if !windows::is_admin() {
        eprintln!("skipped: needs an elevated prompt to assign the Administrators group as owner");
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let plain = directory.path().join("plain");
    fs::create_dir(&plain).unwrap();
    assert!(
        !windows::is_trusted_directory(&plain).unwrap(),
        "an ordinary folder under the user's profile"
    );

    let path = directory.path().join("protected");
    windows::create_protected_directory(&path).unwrap();
    fs::write(path.join("state.txt"), "x").unwrap();
    assert!(windows::is_trusted_directory(&path).unwrap());
    icacls(&path, "*S-1-5-32-545:(OI)(CI)RX");
    assert!(
        windows::is_trusted_directory(&path).unwrap(),
        "read access for Users, as in the original release"
    );
    icacls(&path, "*S-1-5-32-545:(OI)(CI)M");
    assert!(
        !windows::is_trusted_directory(&path).unwrap(),
        "write access for Users"
    );
}

#[test]
fn protected_directory_is_created_closed_and_cannot_replace_an_existing_one() {
    if !windows::is_admin() {
        eprintln!("skipped: needs an elevated prompt to assign the Administrators group as owner");
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("protected");
    windows::create_protected_directory(&path).unwrap();
    assert!(windows::is_protected_directory(&path).unwrap());
    let sddl = windows::path_sddl(&path).unwrap();
    assert!(
        sddl == "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
            || sddl == "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
        "{sddl}"
    );
    assert!(windows::create_protected_directory(&path).is_err());

    let loose = directory.path().join("loose");
    fs::create_dir(&loose).unwrap();
    assert!(!windows::is_protected_directory(&loose).unwrap());
    windows::protect_existing_directory(&loose).unwrap();
    assert!(windows::is_protected_directory(&loose).unwrap());
}

/// Records what install and uninstall ask of Task Scheduler instead of doing it.
#[derive(Default)]
struct FakeHost {
    calls: RefCell<Vec<String>>,
    task: RefCell<Option<String>>,
    fail_create: bool,
}

impl FakeHost {
    fn take_calls(&self) -> Vec<String> {
        self.calls.borrow_mut().drain(..).collect()
    }
}

impl Host for FakeHost {
    fn query_task_xml(&self) -> Option<String> {
        self.task.borrow().clone()
    }

    fn create_task(&self, env: &Env) -> Result<()> {
        if self.fail_create {
            bail!("simulated Task Scheduler failure");
        }
        self.calls.borrow_mut().push("create".to_owned());
        *self.task.borrow_mut() = Some(windows::task_xml(&env.file("chainlink.exe"), true));
        Ok(())
    }

    fn stop_task(&self) {
        self.calls.borrow_mut().push("stop".to_owned());
    }

    fn delete_task(&self) -> Result<()> {
        self.calls.borrow_mut().push("delete".to_owned());
        *self.task.borrow_mut() = None;
        Ok(())
    }

    fn powershell_unlock(&self, _script: &Path) -> Result<()> {
        self.calls.borrow_mut().push("powershell unlock".to_owned());
        Ok(())
    }

    fn stop_legacy_watchdogs(&self) {
        self.calls.borrow_mut().push("stop legacy".to_owned());
    }

    fn terminate_watchdog(&self, _process_id: u32) {
        self.calls.borrow_mut().push("terminate".to_owned());
    }

    fn create_shortcut(&self, shortcut: &Path, target: &Path) -> Result<()> {
        fs::write(shortcut, target.display().to_string())?;
        Ok(())
    }
}

const SHORT: Duration = Duration::from_millis(400);

fn install_world() -> Option<(World, PathBuf, PathBuf)> {
    if !windows::is_admin() {
        eprintln!("skipped: needs an elevated prompt to create the protected folder");
        return None;
    }
    let world = World::new();
    let usb_dir = world.usb.join("Chainlink");
    fs::write(
        usb_dir.join("blocklist.txt"),
        "x.example\nyoutube.com/shorts\n",
    )
    .unwrap();
    let source = world.usb.join("chainlink.exe");
    fs::write(&source, b"not really an executable").unwrap();
    Some((world, usb_dir, source))
}

#[test]
fn folder_chainlink_did_not_create_is_never_used() {
    let Some((world, usb_dir, source)) = install_world() else {
        return;
    };
    fs::create_dir(&world.env.app_dir).unwrap();
    fs::write(world.env.file("chainlink.exe"), "planted").unwrap();
    fs::write(world.env.file("watchdog.ps1"), "planted").unwrap();
    let host = FakeHost::default();
    let error = world
        .env
        .install(&host, &usb_dir, &source, SHORT)
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("another account"),
        "{error:#}"
    );
    let error = world.env.uninstall(&host, SHORT).unwrap_err();
    assert!(
        format!("{error:#}").contains("another account"),
        "{error:#}"
    );
    assert!(
        host.take_calls().is_empty(),
        "nothing may be run from, or because of, an untrusted folder"
    );
    assert_eq!(
        fs::read_to_string(world.env.file("chainlink.exe")).unwrap(),
        "planted"
    );
}

#[test]
fn linking_from_outside_the_usb_chainlink_folder_is_refused() {
    let Some((mut world, usb_dir, source)) = install_world() else {
        return;
    };
    world.env.require_usb_layout = true;
    let host = FakeHost::default();
    let error = world
        .env
        .install(&host, &usb_dir, &source, SHORT)
        .unwrap_err();
    assert!(format!("{error:#}").contains("top level"), "{error:#}");
    assert!(!world.env.app_dir.exists());
}

#[test]
fn failed_first_link_leaves_nothing_behind() {
    let Some((world, usb_dir, source)) = install_world() else {
        return;
    };
    let host = FakeHost {
        fail_create: true,
        ..Default::default()
    };
    let error = world
        .env
        .install(&host, &usb_dir, &source, SHORT)
        .unwrap_err();
    assert!(format!("{error:#}").contains("simulated"), "{error:#}");
    assert!(!world.env.app_dir.exists());
    assert!(!world.env.emergency_stub.exists());
    assert!(!world.env.emergency_shortcut.exists());
}

#[test]
fn foreign_task_blocks_linking() {
    let Some((world, usb_dir, source)) = install_world() else {
        return;
    };
    let host = FakeHost::default();
    *host.task.borrow_mut() = Some(task("S-1-5-18", r"C:\Windows\System32\cmd.exe", "/c exit"));
    let error = world
        .env
        .install(&host, &usb_dir, &source, SHORT)
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("does not belong"),
        "{error:#}"
    );
    assert!(!world.env.app_dir.exists());
    assert!(host.task.borrow().is_some());
    assert!(
        host.take_calls().is_empty(),
        "a foreign task is neither stopped nor deleted"
    );
}

#[test]
fn link_repair_and_uninstall() {
    let Some((world, usb_dir, source)) = install_world() else {
        return;
    };
    let env = &world.env;
    let host = FakeHost::default();

    let words = env
        .install(&host, &usb_dir, &source, SHORT)
        .unwrap()
        .expect("first link returns recovery words");
    assert_eq!(words.len(), 6);
    assert!(windows::is_protected_directory(&env.app_dir).unwrap());
    for name in [
        "chainlink.exe",
        "blocklist.txt",
        "pair.txt",
        "recovery.txt",
        "policy-baseline.json",
    ] {
        assert!(env.file(name).is_file(), "{name}");
    }
    assert!(env.emergency_stub.is_file());
    assert!(env.emergency_shortcut.is_file());
    assert!(env.read_baseline().is_some());
    assert_eq!(host.take_calls(), ["create"]);
    assert!(env.usb_matches_pc(&usb_dir));
    assert!(env.verify_recovery(&words));
    let mut wrong = words.clone();
    wrong[5] = if words[5] == "apple" {
        "arrow"
    } else {
        "apple"
    }
    .to_owned();
    assert!(!env.verify_recovery(&wrong));
    env.register_recovery_failure().unwrap();
    assert!(env.recovery_delay() > 0);
    assert!(!env.verify_recovery(&words), "no attempts during the delay");
    env.clear_recovery_failures();

    // Lock for real (against the scratch key), then repair: the blocks must be lifted first.
    env.set_lock().unwrap();
    assert!(env.lock_intact());
    let record = fs::read_to_string(env.file("recovery.txt")).unwrap();
    assert!(
        env.install(&host, &usb_dir, &source, SHORT)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        fs::read_to_string(env.file("recovery.txt")).unwrap(),
        record
    );
    assert_eq!(host.take_calls(), ["stop", "create"]);
    assert!(
        world.scratch.subkeys().is_empty(),
        "repair lifts the blocks"
    );

    // A damaged baseline is replaced during repair instead of blocking it for good.
    fs::write(env.file("policy-baseline.json"), "{ not json").unwrap();
    env.install(&host, &usb_dir, &source, SHORT).unwrap();
    assert!(env.read_baseline().is_some());

    // The task is gone but the protected folder remains (interrupted uninstall): repair works.
    *host.task.borrow_mut() = None;
    host.take_calls();
    env.install(&host, &usb_dir, &source, SHORT).unwrap();
    assert_eq!(host.take_calls(), ["create"]);

    // While a watchdog holds the lock, uninstall must not touch anything.
    env.set_lock().unwrap();
    let held = windows::open_watchdog_lock(&env.file("watchdog.lock")).unwrap();
    assert!(env.uninstall(&host, SHORT).is_err());
    assert_eq!(host.take_calls(), ["stop"]);
    assert!(env.lock_intact());
    drop(held);

    // Uninstall: task first, then the blocks, then the files.
    env.uninstall(&host, SHORT).unwrap();
    assert_eq!(host.take_calls(), ["stop", "delete"]);
    assert!(host.task.borrow().is_none());
    assert!(world.scratch.subkeys().is_empty());
    assert!(!env.app_dir.exists());
    assert!(!env.emergency_stub.exists());
    assert!(!env.emergency_shortcut.exists());
}

#[test]
fn leftover_watchdog_holding_the_lock_is_asked_to_stop() {
    let Some((world, usb_dir, source)) = install_world() else {
        return;
    };
    let env = &world.env;
    let host = FakeHost::default();
    env.install(&host, &usb_dir, &source, SHORT).unwrap();
    // Another process holds the lock and wrote its id, as a running watchdog does.
    let lock_path = env.file("watchdog.lock");
    let script = format!(
        "$f = [IO.File]::Open('{}', 'OpenOrCreate', 'ReadWrite', 'Read'); $b = [Text.Encoding]::ASCII.GetBytes([string]$PID); $f.SetLength(0); $f.Write($b, 0, $b.Length); $f.Flush(); 'held'; Start-Sleep -Seconds 60",
        lock_path.display()
    );
    let mut holder = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("start lock holder");
    let mut line = String::new();
    std::io::BufRead::read_line(
        &mut std::io::BufReader::new(holder.stdout.as_mut().unwrap()),
        &mut line,
    )
    .unwrap();
    assert_eq!(line.trim(), "held");
    assert_eq!(windows::watchdog_lock_owner(&lock_path), holder.id());
    host.take_calls();
    let outcome = env.uninstall(&host, SHORT);
    holder.kill().unwrap();
    holder.wait().unwrap();
    assert!(outcome.is_err(), "the fake host does not really end it");
    let calls = host.take_calls();
    assert!(calls.contains(&"terminate".to_owned()), "{calls:?}");
    assert!(env.app_dir.exists(), "nothing is removed while it runs");
}

#[test]
fn upgrade_from_the_original_powershell_release() {
    let Some((world, usb_dir, source)) = install_world() else {
        return;
    };
    let env = &world.env;
    windows::create_protected_directory(&env.app_dir).unwrap();
    let script = env.file("watchdog.ps1");
    fs::write(&script, "# original watchdog").unwrap();
    icacls(&env.app_dir, "*S-1-5-32-545:(OI)(CI)RX"); // the original let Users read the folder
    let host = FakeHost::default();
    *host.task.borrow_mut() = Some(task(
        "S-1-5-18",
        "powershell.exe",
        &format!(
            "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File \"{}\"",
            script.display()
        ),
    ));
    env.install(&host, &usb_dir, &source, SHORT).unwrap();
    assert_eq!(
        host.take_calls(),
        [
            "stop",
            "stop legacy",
            "powershell unlock",
            "stop legacy",
            "create"
        ]
    );
    assert!(!script.exists());
    assert!(env.genuine_task(&host));
    assert!(
        windows::is_protected_directory(&env.app_dir).unwrap(),
        "the upgrade closes the folder to Users"
    );
}

#[test]
fn real_shortcut_is_created() {
    // The only test that uses the real host: it writes one .lnk into a temporary folder.
    let directory = tempfile::tempdir().unwrap();
    let shortcut = directory.path().join("Chainlink Emergency Uninstall.lnk");
    let target = directory.path().join("it's a target.exe");
    fs::write(&target, b"x").unwrap();
    Scheduler.create_shortcut(&shortcut, &target).unwrap();
    let bytes = fs::read(&shortcut).unwrap();
    assert!(bytes.len() > 76 && bytes[0] == 0x4c, "a shell link file");
}
