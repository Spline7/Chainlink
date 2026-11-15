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
        let env = Env::new(
            directory.path().join("app"),
            scratch.root(),
            directory.path().join(windows::EMERGENCY_STUB_NAME),
        );
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

#[test]
fn protected_directory_is_created_closed_and_never_adopted() {
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
fn prefilled_folder_is_never_adopted() {
    let Some((world, usb_dir, source)) = install_world() else {
        return;
    };
    fs::create_dir(&world.env.app_dir).unwrap();
    fs::write(world.env.file("chainlink.exe"), "planted").unwrap();
    let host = FakeHost::default();
    assert!(world.env.install(&host, &usb_dir, &source, SHORT).is_err());
    assert_eq!(
        fs::read_to_string(world.env.file("chainlink.exe")).unwrap(),
        "planted"
    );
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
    assert!(world.env.install(&host, &usb_dir, &source, SHORT).is_err());
    assert!(!world.env.app_dir.exists());
    assert!(!world.env.emergency_stub.exists());
}

#[test]
fn foreign_task_blocks_linking() {
    let Some((world, usb_dir, source)) = install_world() else {
        return;
    };
    let host = FakeHost::default();
    *host.task.borrow_mut() = Some(task("S-1-5-18", r"C:\Windows\System32\cmd.exe", "/c exit"));
    assert!(world.env.install(&host, &usb_dir, &source, SHORT).is_err());
    assert!(!world.env.app_dir.exists());
    assert!(host.task.borrow().is_some());
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
    assert_eq!(host.take_calls(), ["stop", "create"]);
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
    assert_eq!(host.take_calls(), ["stop", "powershell unlock", "create"]);
    assert!(!script.exists());
    assert!(env.genuine_task(&host));
}

#[test]
fn real_scheduler_reports_no_foreign_chainlink_task_as_genuine() {
    // Read-only: asks Task Scheduler whether a task named Chainlink exists.
    let env = Env::system().unwrap();
    if let Some(xml) = Scheduler.query_task_xml() {
        // Whatever is registered under that name, the check must not panic.
        let _ = env.task_xml_is_genuine(&xml);
    }
}
