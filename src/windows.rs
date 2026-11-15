use crate::core::{
    RECOVERY_ROUNDS, atomic_write, firefox_patterns, make_recovery_record, new_key_token,
    new_recovery_words, pairing_hash, read_blocklist, read_key_token, verify_recovery_record,
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE, S_OK, SYSTEMTIME,
};
use windows_sys::Win32::Storage::FileSystem::{
    GetDriveTypeW, GetLogicalDrives, GetVolumeInformationW,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::SystemInformation::{GetLocalTime, GetWindowsDirectoryW};
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::System::WindowsProgramming::{DRIVE_FIXED, DRIVE_REMOVABLE};
use windows_sys::Win32::UI::Shell::{
    FOLDERID_ProgramData, IsUserAnAdmin, SHGetKnownFolderPath, ShellExecuteW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;
use winreg::enums::{KEY_READ, KEY_WOW64_64KEY, KEY_WRITE};
use winreg::types::FromRegValue;
use winreg::{HKLM, RegKey};

const TASK_NAME: &str = r"\Chainlink";
const REPARSE_POINT: u32 = 0x400;
const CHROMIUM: [(&str, &str, &str, &str); 3] = [
    (
        "Chrome",
        r"SOFTWARE\Policies\Google\Chrome",
        "IncognitoModeAvailability",
        "BrowserAddPersonEnabled",
    ),
    (
        "Edge",
        r"SOFTWARE\Policies\Microsoft\Edge",
        "InPrivateModeAvailability",
        "BrowserAddProfileEnabled",
    ),
    (
        "Brave",
        r"SOFTWARE\Policies\BraveSoftware\Brave",
        "IncognitoModeAvailability",
        "BrowserAddPersonEnabled",
    ),
];
const FIREFOX: &str = r"SOFTWARE\Policies\Mozilla\Firefox";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PropertySnapshot {
    present: bool,
    value: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BrowserBaseline {
    properties: HashMap<String, PropertySnapshot>,
    blocklist: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Baseline {
    version: u32,
    chromium: HashMap<String, BrowserBaseline>,
    firefox: BrowserBaseline,
}

fn program_data_dir() -> Result<PathBuf> {
    let mut raw = std::ptr::null_mut();
    let status =
        unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, std::ptr::null_mut(), &mut raw) };
    if status != S_OK {
        unsafe { CoTaskMemFree(raw.cast()) };
        bail!("Windows could not resolve the ProgramData known folder (HRESULT {status:#x})");
    }
    let mut length = 0;
    unsafe {
        while *raw.add(length) != 0 {
            length += 1;
        }
    }
    let path = unsafe { OsString::from_wide(std::slice::from_raw_parts(raw, length)) };
    unsafe { CoTaskMemFree(raw.cast()) };
    Ok(PathBuf::from(path))
}

pub fn app_dir() -> PathBuf {
    program_data_dir()
        .expect("Windows could not resolve the trusted ProgramData directory")
        .join("Chainlink")
}

pub fn pair_file() -> PathBuf {
    app_dir().join("pair.txt")
}
pub fn blocklist_file() -> PathBuf {
    app_dir().join("blocklist.txt")
}
pub fn baseline_file() -> PathBuf {
    app_dir().join("policy-baseline.json")
}
pub fn recovery_file() -> PathBuf {
    app_dir().join("recovery.txt")
}
pub fn attempts_file() -> PathBuf {
    app_dir().join("recovery-attempts.json")
}
pub fn installed_exe() -> PathBuf {
    app_dir().join("chainlink.exe")
}
fn log_file() -> PathBuf {
    app_dir().join("log.txt")
}
fn status_file() -> PathBuf {
    app_dir().join("status.txt")
}

fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

pub fn is_admin() -> bool {
    unsafe { IsUserAnAdmin() != 0 }
}

pub fn launch_elevated(executable: &Path, arguments: &[&str]) -> Result<()> {
    let parameters = arguments
        .iter()
        .map(|argument| format!("\"{}\"", argument.replace('"', "\\\"")))
        .collect::<Vec<_>>()
        .join(" ");
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            wide("runas").as_ptr(),
            wide(executable.as_os_str()).as_ptr(),
            wide(parameters).as_ptr(),
            std::ptr::null(),
            SW_HIDE,
        )
    };
    if result as usize <= 32 {
        bail!(
            "Windows refused elevation (ShellExecute error {})",
            result as usize
        );
    }
    Ok(())
}

pub fn relaunch_elevated(arguments: &[&str]) -> Result<()> {
    launch_elevated(&env::current_exe()?, arguments)
}

pub fn is_reparse(path: &Path) -> Result<bool> {
    Ok(fs::symlink_metadata(path)?.file_attributes() & REPARSE_POINT != 0)
}

fn system_executable(name: &str) -> PathBuf {
    let mut buffer = vec![0_u16; 32_768];
    let length = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    assert!(
        length > 0 && (length as usize) < buffer.len(),
        "Windows could not resolve its trusted system directory"
    );
    PathBuf::from(OsString::from_wide(&buffer[..length as usize]))
        .join("System32")
        .join(name)
}

fn usb_root(usb_dir: &Path) -> Result<PathBuf> {
    let display = usb_dir.display().to_string();
    if display.len() < 2
        || display.as_bytes()[1] != b':'
        || !display.as_bytes()[0].is_ascii_alphabetic()
    {
        bail!("Chainlink must run from a Windows drive");
    }
    Ok(PathBuf::from(format!("{}:\\", &display[..1])))
}

pub fn usb_hash(usb_dir: &Path) -> Result<String> {
    let root = usb_root(usb_dir)?;
    let token = read_key_token(&usb_dir.join("chainlink.key"))?;
    Ok(pairing_hash(&token, &volume_serial(&root)?))
}

pub fn usb_matches_pc(usb_dir: &Path) -> bool {
    let Ok(hash) = usb_hash(usb_dir) else {
        return false;
    };
    fs::read_to_string(pair_file()).is_ok_and(|contents| {
        contents
            .lines()
            .any(|line| line.trim().eq_ignore_ascii_case(&hash))
    })
}

fn run_checked(program: &Path, arguments: &[&OsStr]) -> Result<()> {
    let output = Command::new(program).args(arguments).output()?;
    if !output.status.success() {
        bail!(
            "{} failed: {}{}",
            program.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

pub fn secure_app_directory(path: &Path) -> Result<()> {
    let icacls = system_executable("icacls.exe");
    run_checked(
        &icacls,
        &[
            path.as_os_str(),
            OsStr::new("/inheritance:r"),
            OsStr::new("/grant:r"),
            OsStr::new("*S-1-5-18:(OI)(CI)F"),
            OsStr::new("*S-1-5-32-544:(OI)(CI)F"),
        ],
    )?;
    run_checked(
        &icacls,
        &[
            path.as_os_str(),
            OsStr::new("/remove:g"),
            OsStr::new("*S-1-5-32-545"),
        ],
    )
}

pub fn log(message: &str) {
    let path = log_file();
    if path
        .metadata()
        .is_ok_and(|metadata| metadata.len() > 200 * 1024)
    {
        let _ = fs::rename(&path, path.with_extension("txt.old"));
    }
    if let Ok(mut output) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(output, "{message}");
    }
}

fn set_status(message: &str) {
    let _ = atomic_write(&status_file(), format!("{message}\n").as_bytes());
}

fn open_hklm(path: &str, access: u32) -> std::io::Result<RegKey> {
    HKLM.open_subkey_with_flags(path, access | KEY_WOW64_64KEY)
}

fn create_hklm(path: &str) -> std::io::Result<RegKey> {
    let (key, _) = HKLM.create_subkey_with_flags(path, KEY_WRITE | KEY_WOW64_64KEY)?;
    Ok(key)
}

fn property_snapshot(path: &str, name: &str) -> PropertySnapshot {
    let value = open_hklm(path, KEY_READ).and_then(|key| key.get_value::<u32, _>(name));
    match value {
        Ok(value) => PropertySnapshot {
            present: true,
            value: Some(value),
        },
        Err(_) => PropertySnapshot {
            present: false,
            value: None,
        },
    }
}

fn list_snapshot(path: &str) -> Vec<String> {
    open_hklm(path, KEY_READ)
        .ok()
        .into_iter()
        .flat_map(|key| key.enum_values().collect::<Vec<_>>())
        .filter_map(Result::ok)
        .filter_map(|(_, value)| String::from_reg_value(&value).ok())
        .collect()
}

fn set_dword(path: &str, name: &str, value: u32) -> Result<()> {
    create_hklm(path)?.set_value(name, &value)?;
    Ok(())
}

fn replace_list(path: &str, values: &[String]) -> Result<()> {
    let key = create_hklm(path)?;
    let names = key
        .enum_values()
        .filter_map(Result::ok)
        .map(|(name, _)| name)
        .collect::<Vec<_>>();
    for name in names {
        key.delete_value(name)?;
    }
    for (index, value) in values.iter().enumerate() {
        key.set_value((index + 1).to_string(), value)?;
    }
    Ok(())
}

fn unique(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = HashSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

fn capture_current_baseline() -> Baseline {
    let mut chromium = HashMap::new();
    for (browser, path, private, profile) in CHROMIUM {
        let properties = [private, "BrowserGuestModeEnabled", profile, "TorDisabled"]
            .into_iter()
            .map(|name| (name.to_owned(), property_snapshot(path, name)))
            .collect();
        chromium.insert(
            browser.to_owned(),
            BrowserBaseline {
                properties,
                blocklist: list_snapshot(&format!(r"{path}\URLBlocklist")),
            },
        );
    }
    let firefox = BrowserBaseline {
        properties: HashMap::from([(
            "DisablePrivateBrowsing".to_owned(),
            property_snapshot(FIREFOX, "DisablePrivateBrowsing"),
        )]),
        blocklist: list_snapshot(&format!(r"{FIREFOX}\WebsiteFilter\Block")),
    };
    Baseline {
        version: 3,
        chromium,
        firefox,
    }
}

pub fn capture_baseline() -> Result<()> {
    if baseline_file().exists() {
        read_baseline()?;
        return Ok(());
    }
    let baseline = capture_current_baseline();
    atomic_write(
        &baseline_file(),
        format!("{}\n", serde_json::to_string_pretty(&baseline)?).as_bytes(),
    )?;
    log("Captured pre-install browser policy baseline.");
    Ok(())
}

fn read_baseline() -> Result<Baseline> {
    let value: Value = serde_json::from_slice(&fs::read(baseline_file())?)?;
    if value.get("version").is_some() {
        let baseline: Baseline = serde_json::from_value(value)?;
        validate_baseline(&baseline)?;
        return Ok(baseline);
    }
    convert_powershell_baseline(&value)
}

fn convert_powershell_baseline(value: &Value) -> Result<Baseline> {
    if value.get("Version").and_then(Value::as_u64) != Some(1) {
        bail!("unsupported policy baseline format");
    }
    let chromium_value = value
        .get("Chromium")
        .and_then(Value::as_object)
        .context("missing Chromium baseline")?;
    let mut chromium = HashMap::new();
    for (browser, _, private, profile) in CHROMIUM {
        let item = chromium_value
            .get(browser)
            .context("missing browser baseline")?;
        chromium.insert(
            browser.to_owned(),
            convert_ps_browser(
                item,
                &[private, "BrowserGuestModeEnabled", profile, "TorDisabled"],
            )?,
        );
    }
    let firefox = convert_ps_browser(
        value.get("Firefox").context("missing Firefox baseline")?,
        &["DisablePrivateBrowsing"],
    )?;
    let baseline = Baseline {
        version: 3,
        chromium,
        firefox,
    };
    validate_baseline(&baseline)?;
    Ok(baseline)
}

fn convert_ps_browser(value: &Value, names: &[&str]) -> Result<BrowserBaseline> {
    let properties_value = value
        .get("Properties")
        .and_then(Value::as_object)
        .context("missing Properties")?;
    let mut properties = HashMap::new();
    for name in names {
        let snapshot = properties_value
            .get(*name)
            .context("missing property snapshot")?;
        properties.insert(
            (*name).to_owned(),
            PropertySnapshot {
                present: snapshot
                    .get("Present")
                    .and_then(Value::as_bool)
                    .context("invalid Present")?,
                value: snapshot
                    .get("Value")
                    .and_then(Value::as_u64)
                    .map(|value| value as u32),
            },
        );
    }
    let blocklist = value
        .get("Blocklist")
        .and_then(Value::as_array)
        .context("missing Blocklist")?
        .iter()
        .map(|item| {
            item.get("Value")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .context("invalid list value")
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(BrowserBaseline {
        properties,
        blocklist,
    })
}

fn validate_baseline(baseline: &Baseline) -> Result<()> {
    for (browser, _, private, profile) in CHROMIUM {
        let item = baseline
            .chromium
            .get(browser)
            .context("missing browser baseline")?;
        for name in [private, "BrowserGuestModeEnabled", profile, "TorDisabled"] {
            if !item.properties.contains_key(name) {
                bail!("missing baseline property {browser}/{name}");
            }
        }
    }
    if !baseline
        .firefox
        .properties
        .contains_key("DisablePrivateBrowsing")
    {
        bail!("missing Firefox baseline property");
    }
    Ok(())
}

fn installed_blocklist() -> Vec<String> {
    match read_blocklist(&blocklist_file()) {
        Ok(entries) => entries,
        Err(error) => {
            log(&format!(
                "Installed blocklist invalid; blocking all URLs: {error:#}"
            ));
            vec!["*".to_owned()]
        }
    }
}

fn unmanaged(path: &str, managed: &[String]) -> Vec<String> {
    let managed: HashSet<_> = managed.iter().collect();
    list_snapshot(path)
        .into_iter()
        .filter(|value| !managed.contains(value))
        .collect()
}

pub fn set_lock() -> Result<()> {
    let entries = installed_blocklist();
    let baseline = read_baseline().ok();
    for (browser, path, private, profile) in CHROMIUM {
        let list_path = format!(r"{path}\URLBlocklist");
        let base = baseline
            .as_ref()
            .and_then(|baseline| baseline.chromium.get(browser));
        let values = unique(
            base.into_iter()
                .flat_map(|item| item.blocklist.clone())
                .chain(unmanaged(&list_path, &entries))
                .chain(entries.clone()),
        );
        replace_list(&list_path, &values)?;
        set_dword(path, private, 1)?;
        set_dword(path, "BrowserGuestModeEnabled", 0)?;
        set_dword(path, profile, 0)?;
        if browser == "Brave" {
            set_dword(path, "TorDisabled", 1)?;
        }
    }
    let patterns = entries
        .iter()
        .flat_map(|entry| firefox_patterns(entry))
        .collect::<Vec<_>>();
    let list_path = format!(r"{FIREFOX}\WebsiteFilter\Block");
    let values = unique(
        baseline
            .as_ref()
            .into_iter()
            .flat_map(|baseline| baseline.firefox.blocklist.clone())
            .chain(unmanaged(&list_path, &patterns))
            .chain(patterns),
    );
    replace_list(&list_path, &values)?;
    set_dword(FIREFOX, "DisablePrivateBrowsing", 1)
}

fn restore_property(
    path: &str,
    name: &str,
    snapshot: &PropertySnapshot,
    managed: u32,
) -> Result<()> {
    let current = property_snapshot(path, name);
    if current.present && current.value != Some(managed) {
        return Ok(());
    }
    let key = create_hklm(path)?;
    if snapshot.present {
        key.set_value(
            name,
            &snapshot.value.context("baseline property has no value")?,
        )?;
    } else if current.present {
        key.delete_value(name)?;
    }
    Ok(())
}

pub fn remove_lock() -> Result<()> {
    let entries = installed_blocklist();
    let baseline =
        read_baseline().context("cannot restore browser policy without a valid baseline")?;
    for (browser, path, private, profile) in CHROMIUM {
        let base = baseline
            .chromium
            .get(browser)
            .context("missing browser baseline")?;
        let list_path = format!(r"{path}\URLBlocklist");
        replace_list(
            &list_path,
            &unique(
                base.blocklist
                    .clone()
                    .into_iter()
                    .chain(unmanaged(&list_path, &entries)),
            ),
        )?;
        restore_property(path, private, &base.properties[private], 1)?;
        restore_property(
            path,
            "BrowserGuestModeEnabled",
            &base.properties["BrowserGuestModeEnabled"],
            0,
        )?;
        restore_property(path, profile, &base.properties[profile], 0)?;
        if browser == "Brave" {
            restore_property(path, "TorDisabled", &base.properties["TorDisabled"], 1)?;
        }
    }
    let patterns = entries
        .iter()
        .flat_map(|entry| firefox_patterns(entry))
        .collect::<Vec<_>>();
    let list_path = format!(r"{FIREFOX}\WebsiteFilter\Block");
    replace_list(
        &list_path,
        &unique(
            baseline
                .firefox
                .blocklist
                .clone()
                .into_iter()
                .chain(unmanaged(&list_path, &patterns)),
        ),
    )?;
    restore_property(
        FIREFOX,
        "DisablePrivateBrowsing",
        &baseline.firefox.properties["DisablePrivateBrowsing"],
        1,
    )
}

pub fn lock_intact() -> bool {
    let entries = installed_blocklist();
    CHROMIUM.iter().all(|(browser, path, private, profile)| {
        property_snapshot(path, private).value == Some(1)
            && property_snapshot(path, "BrowserGuestModeEnabled").value == Some(0)
            && property_snapshot(path, profile).value == Some(0)
            && (*browser != "Brave" || property_snapshot(path, "TorDisabled").value == Some(1))
            && {
                let actual: HashSet<_> = list_snapshot(&format!(r"{path}\URLBlocklist"))
                    .into_iter()
                    .collect();
                entries.iter().all(|entry| actual.contains(entry))
            }
    })
}

pub fn volume_serial(root: &Path) -> Result<String> {
    let mut serial = 0_u32;
    let result = unsafe {
        GetVolumeInformationW(
            wide(root.as_os_str()).as_ptr(),
            std::ptr::null_mut(),
            0,
            &mut serial,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
        )
    };
    if result == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(format!("{serial:08X}"))
}

pub fn find_key() -> Option<PathBuf> {
    let expected = fs::read_to_string(pair_file())
        .ok()?
        .lines()
        .filter(|line| line.len() == 64)
        .map(|line| line.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    let mask = unsafe { GetLogicalDrives() };
    for index in 0..26 {
        if mask & (1 << index) == 0 {
            continue;
        }
        let root = PathBuf::from(format!("{}:\\", (b'A' + index) as char));
        let drive_type = unsafe { GetDriveTypeW(wide(root.as_os_str()).as_ptr()) };
        if !matches!(drive_type, DRIVE_REMOVABLE | DRIVE_FIXED) {
            continue;
        }
        let token = read_key_token(&root.join("Chainlink").join("chainlink.key"));
        let serial = volume_serial(&root);
        if let (Ok(token), Ok(serial)) = (token, serial)
            && expected.contains(&pairing_hash(&token, &serial))
        {
            return Some(root);
        }
    }
    None
}

pub fn validate_usb_blocklist(root: &Path) -> Result<PathBuf> {
    let source = root.join("Chainlink").join("blocklist.txt");
    read_blocklist(&source)?;
    Ok(source)
}

pub fn sync_blocklist(root: &Path) -> Result<()> {
    let source = validate_usb_blocklist(root)?;
    let source_bytes = fs::read(source)?;
    if fs::read(blocklist_file()).ok().as_deref() != Some(source_bytes.as_slice()) {
        atomic_write(&blocklist_file(), &source_bytes)?;
        log("Blocklist updated from USB.");
    }
    Ok(())
}

fn start_menu_emergency() -> PathBuf {
    program_data_dir()
        .expect("Windows could not resolve the trusted ProgramData directory")
        .join("Microsoft")
        .join("Windows")
        .join("Start Menu")
        .join("Programs")
        .join("Chainlink Emergency Uninstall.exe")
}

fn task_exists() -> bool {
    query_task_xml().is_some()
}

pub fn install(usb_dir: &Path) -> Result<Option<Vec<String>>> {
    let source_exe = env::current_exe()?;
    read_blocklist(&usb_dir.join("blocklist.txt"))?;
    let has_task = genuine_task();
    if task_exists() && !has_task {
        bail!("a scheduled task named Chainlink exists and does not belong to this application");
    }

    let key_file = usb_dir.join("chainlink.key");
    if key_file.exists() {
        read_key_token(&key_file)?;
    } else {
        atomic_write(&key_file, new_key_token()?.as_bytes())?;
        let _ = Command::new(system_executable("attrib.exe"))
            .args(["+h", &key_file.display().to_string()])
            .output();
    }
    let current_hash = usb_hash(usb_dir)?;
    let app = app_dir();
    if app.exists() {
        if !app.is_dir() || is_reparse(&app)? {
            bail!("{} must be a real directory", app.display());
        }
        if !has_task && fs::read_dir(&app)?.next().is_some() {
            bail!(
                "{} contains files but no genuine Chainlink task exists; move it aside first",
                app.display()
            );
        }
    } else {
        fs::create_dir(&app)?;
    }
    secure_app_directory(&app)?;
    stop_task();

    if has_task && !baseline_file().exists() {
        let old_exe = installed_exe();
        let old_powershell = app.join("watchdog.ps1");
        if old_exe.is_file() {
            let status = Command::new(&old_exe).arg("--unlock").status()?;
            if !status.success() {
                bail!("existing Rust watchdog could not unlock for migration");
            }
        } else if old_powershell.is_file() {
            let status = Command::new(system_executable(r"WindowsPowerShell\v1.0\powershell.exe"))
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                ])
                .arg(&old_powershell)
                .arg("-Unlock")
                .status()?;
            if !status.success() {
                bail!("existing PowerShell watchdog could not unlock for migration");
            }
        } else {
            bail!("existing Chainlink task has no trusted watchdog to migrate");
        }
    }

    atomic_write(&installed_exe(), &fs::read(source_exe)?)?;
    capture_baseline()?;
    let _ = read_baseline()?;

    let mut known = fs::read_to_string(pair_file())
        .unwrap_or_default()
        .lines()
        .filter(|line| line.len() == 64 && line.chars().all(|c| c.is_ascii_hexdigit()))
        .map(|line| line.to_ascii_lowercase())
        .collect::<Vec<_>>();
    if !known.contains(&current_hash) {
        known.push(current_hash);
    }
    known.sort();
    known.dedup();
    atomic_write(&pair_file(), format!("{}\n", known.join("\n")).as_bytes())?;
    atomic_write(&blocklist_file(), &fs::read(usb_dir.join("blocklist.txt"))?)?;
    atomic_write(&start_menu_emergency(), &fs::read(env::current_exe()?)?)?;
    create_task()?;

    for obsolete in [
        "Chainlink.ps1",
        "Chainlink.Common.psm1",
        "watchdog.ps1",
        "watchdog.py",
    ] {
        let _ = fs::remove_file(app.join(obsolete));
    }
    if !recovery_file().exists() {
        let words = new_recovery_words()?;
        let record = make_recovery_record(&words, RECOVERY_ROUNDS)?;
        atomic_write(&recovery_file(), format!("{record}\n").as_bytes())?;
        return Ok(Some(words));
    }
    Ok(None)
}

pub fn replace_recovery_words() -> Result<Vec<String>> {
    let words = new_recovery_words()?;
    let record = make_recovery_record(&words, RECOVERY_ROUNDS)?;
    atomic_write(&recovery_file(), format!("{record}\n").as_bytes())?;
    Ok(words)
}

#[derive(Default, Serialize, Deserialize)]
struct AttemptState {
    failures: u32,
    until: u64,
}

fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn recovery_delay() -> u64 {
    let state = fs::read(attempts_file())
        .ok()
        .and_then(|bytes| serde_json::from_slice::<AttemptState>(&bytes).ok())
        .unwrap_or_default();
    state.until.saturating_sub(epoch_seconds())
}

pub fn verify_recovery(words: &[String]) -> bool {
    if recovery_delay() > 0 {
        return false;
    }
    fs::read_to_string(recovery_file()).is_ok_and(|record| verify_recovery_record(&record, words))
}

pub fn register_recovery_failure() -> Result<()> {
    let mut state = fs::read(attempts_file())
        .ok()
        .and_then(|bytes| serde_json::from_slice::<AttemptState>(&bytes).ok())
        .unwrap_or_default();
    state.failures = (state.failures + 1).min(6);
    state.until = epoch_seconds() + (1_u64 << (state.failures + 1)).min(60);
    atomic_write(
        &attempts_file(),
        format!("{}\n", serde_json::to_string(&state)?).as_bytes(),
    )
}

pub fn clear_recovery_failures() {
    let _ = fs::remove_file(attempts_file());
}

pub fn uninstall() -> Result<()> {
    stop_task();
    thread::sleep(Duration::from_millis(750));
    remove_lock()?;
    delete_task()?;
    let _ = fs::remove_file(start_menu_emergency());
    let app = app_dir();
    if app.exists() && is_reparse(&app)? {
        bail!("refusing to remove a reparse-point program directory");
    }
    let running_installed = env::current_exe()
        .ok()
        .and_then(|path| path.canonicalize().ok())
        == installed_exe().canonicalize().ok();
    if running_installed {
        let command = format!(
            "timeout /t 2 /nobreak >nul & rmdir /s /q \"{}\"",
            app.display()
        );
        Command::new(system_executable("cmd.exe"))
            .args(["/d", "/s", "/c", &command])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
    } else if app.exists() {
        fs::remove_dir_all(app)?;
    }
    Ok(())
}

fn task_xml(executable: &Path, enabled: bool) -> String {
    let mut time = SYSTEMTIME::default();
    unsafe { GetLocalTime(&mut time) };
    let start = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond
    );
    let escape = |value: &str| {
        value
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<RegistrationInfo><Description>Chainlink watchdog</Description><URI>\Chainlink</URI></RegistrationInfo>
<Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger><TimeTrigger><Repetition><Interval>PT1M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition><StartBoundary>{start}</StartBoundary><Enabled>true</Enabled></TimeTrigger></Triggers>
<Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
<Settings><Enabled>{enabled}</Enabled><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><StartWhenAvailable>true</StartWhenAvailable><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure></Settings>
<Actions Context="Author"><Exec><Command>{}</Command><Arguments>--watchdog</Arguments></Exec></Actions></Task>"#,
        escape(&executable.display().to_string())
    )
}

pub fn query_task_xml() -> Option<String> {
    Command::new(system_executable("schtasks.exe"))
        .args(["/Query", "/TN", TASK_NAME, "/XML"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
}

pub fn genuine_task() -> bool {
    query_task_xml().is_some_and(|xml| {
        let lower = xml.to_ascii_lowercase();
        lower.contains(&installed_exe().display().to_string().to_ascii_lowercase())
            || lower.contains(
                &app_dir()
                    .join("watchdog.ps1")
                    .display()
                    .to_string()
                    .to_ascii_lowercase(),
            )
    })
}

pub fn create_task() -> Result<()> {
    let xml_path = app_dir().join("task.xml");
    let xml = task_xml(&installed_exe(), true);
    let mut bytes = vec![0xff, 0xfe];
    for unit in xml.encode_utf16() {
        bytes.extend(unit.to_le_bytes());
    }
    atomic_write(&xml_path, &bytes)?;
    let result = run_checked(
        &system_executable("schtasks.exe"),
        &[
            OsStr::new("/Create"),
            OsStr::new("/TN"),
            OsStr::new(TASK_NAME),
            OsStr::new("/XML"),
            xml_path.as_os_str(),
            OsStr::new("/F"),
        ],
    );
    let _ = fs::remove_file(&xml_path);
    result?;
    run_checked(
        &system_executable("schtasks.exe"),
        &[OsStr::new("/Run"), OsStr::new("/TN"), OsStr::new(TASK_NAME)],
    )
}

pub fn stop_task() {
    let _ = Command::new(system_executable("schtasks.exe"))
        .args(["/End", "/TN", TASK_NAME])
        .output();
}

pub fn delete_task() -> Result<()> {
    let output = Command::new(system_executable("schtasks.exe"))
        .args(["/Delete", "/TN", TASK_NAME, "/F"])
        .output()?;
    if !output.status.success() && query_task_xml().is_some() {
        bail!("could not delete Chainlink scheduled task");
    }
    Ok(())
}

pub fn acquire_watchdog_mutex() -> Result<HANDLE> {
    let handle = unsafe {
        CreateMutexW(
            std::ptr::null(),
            1,
            wide("Global\\ChainlinkWatchdog").as_ptr(),
        )
    };
    if handle.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        unsafe { CloseHandle(handle) };
        bail!("watchdog is already running");
    }
    Ok(handle)
}

pub fn watchdog() -> Result<()> {
    let _mutex = match acquire_watchdog_mutex() {
        Ok(handle) => handle,
        Err(error) if error.to_string().contains("already running") => return Ok(()),
        Err(error) => return Err(error),
    };
    log("Watchdog started.");
    let mut state = "";
    let mut tick = 0_u64;
    loop {
        let cycle = (|| -> Result<()> {
            if let Some(root) = find_key() {
                validate_usb_blocklist(&root)?;
                if state != "unlocked" {
                    remove_lock()?;
                    state = "unlocked";
                    set_status(&format!("UNLOCKED - key found on {}", root.display()));
                    log("Paired key found - blocks lifted.");
                }
                sync_blocklist(&root)?;
            } else if state != "locked" || (tick % 12 == 0 && !lock_intact()) {
                set_lock()?;
                log(if state == "locked" {
                    "Blocks changed outside Chainlink - re-applied."
                } else {
                    "Key not present - blocks applied."
                });
                state = "locked";
                set_status("LOCKED - key not present");
            }
            Ok(())
        })();
        if let Err(error) = cycle {
            log(&format!("Watchdog cycle failed: {error:#}"));
            if let Err(error) = set_lock() {
                log(&format!("Fail-safe lock also failed: {error:#}"));
            } else {
                state = "locked";
                set_status("LOCKED - fail-safe after an error");
            }
        }
        tick += 1;
        thread::sleep(Duration::from_secs(5));
    }
}

pub fn write_disabled_task_xml(path: &Path) -> Result<()> {
    let xml = task_xml(&installed_exe(), false);
    let mut bytes = vec![0xff, 0xfe];
    for unit in xml.encode_utf16() {
        bytes.extend(unit.to_le_bytes());
    }
    fs::write(path, bytes)?;
    Ok(())
}
