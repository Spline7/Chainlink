//! Windows integration: browser policy in the registry, the paired drive, the scheduled task,
//! and the protected program folder.
//!
//! Everything that reads or writes machine state goes through [`Env`] (where files and policy
//! live) and [`Host`] (Task Scheduler and other processes), so the tests can run the real logic
//! against a scratch registry key and temporary folders.

use crate::core::{
    RECOVERY_ROUNDS, atomic_write, firefox_patterns, make_recovery_record, merge, new_key_token,
    new_recovery_words, pairing_hash, parse_blocklist_bytes, read_blocklist, read_key_token,
    verify_recovery_record,
};
use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Foundation::{ERROR_SHARING_VIOLATION, LocalFree, S_OK, SYSTEMTIME};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, FILE_SHARE_READ, GetDriveTypeW, GetLogicalDrives, GetVolumeInformationW,
    MOVEFILE_DELAY_UNTIL_REBOOT, MoveFileExW,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::SystemInformation::{GetLocalTime, GetWindowsDirectoryW};
use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;
use windows_sys::Win32::System::WindowsProgramming::{DRIVE_FIXED, DRIVE_REMOVABLE};
use windows_sys::Win32::UI::Shell::{
    FOLDERID_ProgramData, FOLDERID_ProgramFiles, IsUserAnAdmin, SHGetKnownFolderPath, ShellExecuteW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use winreg::enums::{KEY_READ, KEY_WOW64_64KEY, KEY_WRITE};
use winreg::types::FromRegValue;
use winreg::{HKLM, RegKey};

const TASK_NAME: &str = r"\Chainlink";
const REPARSE_POINT: u32 = 0x400;
const MAX_USB_BLOCKLIST_BYTES: u64 = 1024 * 1024;
pub const EMERGENCY_STUB_NAME: &str = "Chainlink Emergency Uninstall.exe";
const EMERGENCY_SHORTCUT_NAME: &str = "Chainlink Emergency Uninstall.lnk";

// ---------------------------------------------------------------- small helpers

fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

/// Reads a NUL-terminated UTF-16 string.
///
/// # Safety
/// `pointer` must point to a valid NUL-terminated UTF-16 string.
unsafe fn from_wide_pointer(pointer: *const u16) -> OsString {
    let mut length = 0;
    unsafe {
        while *pointer.add(length) != 0 {
            length += 1;
        }
        OsString::from_wide(std::slice::from_raw_parts(pointer, length))
    }
}

fn known_folder(id: &windows_sys::core::GUID, what: &str) -> Result<PathBuf> {
    let mut raw = std::ptr::null_mut();
    let status = unsafe { SHGetKnownFolderPath(id, 0, std::ptr::null_mut(), &mut raw) };
    if status != S_OK || raw.is_null() {
        unsafe { CoTaskMemFree(raw.cast()) };
        bail!("Windows could not resolve the {what} known folder (HRESULT {status:#x})");
    }
    let path = unsafe { from_wide_pointer(raw) };
    unsafe { CoTaskMemFree(raw.cast()) };
    Ok(PathBuf::from(path))
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
            SW_SHOWNORMAL,
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

fn local_timestamp() -> String {
    let mut time = SYSTEMTIME::default();
    unsafe { GetLocalTime(&mut time) };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond
    )
}

fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn same_path(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

// ---------------------------------------------------------------- protected program folder

/// Owner: Administrators. Protected DACL: SYSTEM and Administrators only, inherited by children.
const PROTECTED_SDDL: &str = "O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
const TRUSTED_SIDS: [&str; 4] = ["SY", "BA", "S-1-5-18", "S-1-5-32-544"];

/// A security descriptor allocated by Windows and released with LocalFree.
struct LocalDescriptor(PSECURITY_DESCRIPTOR);

impl LocalDescriptor {
    fn from_sddl(sddl: &str) -> Result<Self> {
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(sddl).as_ptr(),
                1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if converted == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self(descriptor))
    }
}

impl Drop for LocalDescriptor {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}

/// Owner and DACL of a file or directory in SDDL form, e.g. `O:BAD:P(A;OICI;FA;;;SY)`.
pub fn path_sddl(path: &Path) -> Result<String> {
    let information = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let error = unsafe {
        GetNamedSecurityInfoW(
            wide(path.as_os_str()).as_ptr(),
            SE_FILE_OBJECT,
            information,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if error != 0 {
        return Err(std::io::Error::from_raw_os_error(error as i32).into());
    }
    let descriptor = LocalDescriptor(descriptor);
    let mut text = std::ptr::null_mut();
    let converted = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor.0,
            1,
            information,
            &mut text,
            std::ptr::null_mut(),
        )
    };
    if converted == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let sddl = unsafe { from_wide_pointer(text) };
    unsafe { LocalFree(text.cast()) };
    Ok(sddl.to_string_lossy().into_owned())
}

/// Splits `O:<owner>D:<flags>(ace)(ace)` into owner, DACL flags, and ACE bodies.
fn parse_sddl(sddl: &str) -> Option<(&str, &str, Vec<&str>)> {
    let rest = sddl.strip_prefix("O:")?;
    let (owner, dacl) = rest.split_once("D:")?;
    let owner = owner.split("G:").next()?;
    let (flags, aces) = match dacl.find('(') {
        Some(start) => (&dacl[..start], &dacl[start..]),
        None => (dacl, ""),
    };
    let aces = aces
        .split(')')
        .filter(|ace| !ace.is_empty())
        .map(|ace| ace.strip_prefix('('))
        .collect::<Option<Vec<_>>>()?;
    Some((owner, flags, aces))
}

pub fn has_trusted_owner(path: &Path) -> Result<bool> {
    let sddl = path_sddl(path)?;
    Ok(parse_sddl(&sddl).is_some_and(|(owner, _, _)| TRUSTED_SIDS.contains(&owner)))
}

/// True for a real directory owned by SYSTEM or Administrators that grants access to nobody
/// else. Anything looser lets a non-administrator replace a program that runs as SYSTEM.
pub fn is_protected_directory(path: &Path) -> Result<bool> {
    if !path.is_dir() || is_reparse(path)? {
        return Ok(false);
    }
    let sddl = path_sddl(path)?;
    let Some((owner, flags, aces)) = parse_sddl(&sddl) else {
        return Ok(false);
    };
    Ok(TRUSTED_SIDS.contains(&owner)
        && flags.contains('P')
        && aces.iter().all(|ace| {
            let parts = ace.split(';').collect::<Vec<_>>();
            parts.len() == 6 && parts[0] == "A" && TRUSTED_SIDS.contains(&parts[5])
        }))
}

/// True when an SDDL rights field grants nothing beyond reading and executing.
fn rights_are_read_only(rights: &str) -> bool {
    const READ_EXECUTE: u32 = 0x1200A9; // FILE_GENERIC_READ | FILE_GENERIC_EXECUTE
    if let Some(hex) = rights
        .strip_prefix("0x")
        .or_else(|| rights.strip_prefix("0X"))
    {
        return u32::from_str_radix(hex, 16).is_ok_and(|mask| mask & !READ_EXECUTE == 0);
    }
    !rights.is_empty()
        && rights.len().is_multiple_of(2)
        && rights
            .as_bytes()
            .chunks(2)
            .all(|code| matches!(code, b"FR" | b"FX" | b"GR" | b"GX"))
}

fn children_are_trusted(directory: &Path) -> Result<bool> {
    for entry in fs::read_dir(directory)? {
        let child = entry?.path();
        if fs::symlink_metadata(&child).is_err() {
            continue; // a temporary file that has since been renamed
        }
        if is_reparse(&child)? || !has_trusted_owner(&child)? {
            return Ok(false);
        }
        if child.is_dir() && !children_are_trusted(&child)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// True when nobody but SYSTEM and Administrators could have put or changed anything in the
/// directory: it and everything in it are owned by them, nothing in it is a link, and any other
/// account has at most read access (the original release let Users read the folder). Uninstall
/// and repair check this before they read state from, or run anything in, an existing folder.
pub fn is_trusted_directory(path: &Path) -> Result<bool> {
    if !path.is_dir() || is_reparse(path)? {
        return Ok(false);
    }
    let sddl = path_sddl(path)?;
    let Some((owner, _, aces)) = parse_sddl(&sddl) else {
        return Ok(false);
    };
    let acl_ok = aces.iter().all(|ace| {
        let parts = ace.split(';').collect::<Vec<_>>();
        parts.len() == 6
            && (parts[0] == "D"
                || TRUSTED_SIDS.contains(&parts[5])
                || (parts[0] == "A" && rights_are_read_only(parts[2])))
    });
    Ok(TRUSTED_SIDS.contains(&owner) && acl_ok && children_are_trusted(path)?)
}

/// Creates the directory with its final owner and ACL in one call, so there is no moment at
/// which another account can put files into it. Fails if anything already exists at the path.
pub fn create_protected_directory(path: &Path) -> Result<()> {
    let descriptor = LocalDescriptor::from_sddl(PROTECTED_SDDL)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    if unsafe { CreateDirectoryW(wide(path.as_os_str()).as_ptr(), &attributes) } == 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("create {}", path.display()));
    }
    if !is_protected_directory(path)? || fs::read_dir(path)?.next().is_some() {
        bail!(
            "{} could not be created with protected permissions",
            path.display()
        );
    }
    Ok(())
}

/// Re-applies the protected ACL to the folder of an existing installation (repair, upgrade).
pub fn protect_existing_directory(path: &Path) -> Result<()> {
    if !path.is_dir() || is_reparse(path)? {
        bail!("{} must be a real directory", path.display());
    }
    if !has_trusted_owner(path)? {
        bail!(
            "{} is owned by an account other than SYSTEM or Administrators; uninstall Chainlink, delete that folder, and link again",
            path.display()
        );
    }
    let descriptor = LocalDescriptor::from_sddl(PROTECTED_SDDL)?;
    let (mut present, mut defaulted) = (0, 0);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    if unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted) }
        == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let error = unsafe {
        SetNamedSecurityInfoW(
            wide(path.as_os_str()).as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null(),
        )
    };
    if error != 0 {
        return Err(std::io::Error::from_raw_os_error(error as i32).into());
    }
    if !is_protected_directory(path)? {
        bail!("could not secure {}", path.display());
    }
    check_children(path)
}

fn check_children(directory: &Path) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let child = entry?.path();
        if fs::symlink_metadata(&child).is_err() {
            continue; // a temporary file that has since been renamed
        }
        if is_reparse(&child)? {
            bail!("{} is a link; remove it and try again", child.display());
        }
        if !has_trusted_owner(&child)? {
            bail!(
                "{} is owned by an account other than SYSTEM or Administrators; remove it and try again",
                child.display()
            );
        }
        if child.is_dir() {
            check_children(&child)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- watchdog lock

// The watchdog keeps this file open for as long as it runs. Install and uninstall take the same
// lock, which both proves that no watchdog is running and stops a new one from starting
// meanwhile. The file lives in the protected program folder, so other accounts cannot hold it.

/// Takes the lock (drop the file to release it), or returns None if another process holds it.
pub fn open_watchdog_lock(path: &Path) -> Result<Option<File>> {
    let opened = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(FILE_SHARE_READ)
        .open(path);
    let mut lock = match opened {
        Ok(lock) => lock,
        Err(error) if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION as i32) => {
            return Ok(None);
        }
        Err(error) => return Err(error).with_context(|| format!("open {}", path.display())),
    };
    lock.set_len(0)?;
    lock.write_all(std::process::id().to_string().as_bytes())?;
    Ok(Some(lock))
}

/// Process id recorded by the current lock holder, or 0.
pub fn watchdog_lock_owner(path: &Path) -> u32 {
    fs::read_to_string(path)
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(0)
}

// ---------------------------------------------------------------- browser policy

struct Target {
    name: &'static str,
    key: &'static str,
    list: &'static str,
    /// Policy values Chainlink sets while locked.
    values: &'static [(&'static str, u32)],
    firefox: bool,
}

const TARGETS: [Target; 4] = [
    Target {
        name: "Chrome",
        key: r"Google\Chrome",
        list: "URLBlocklist",
        values: &[
            ("IncognitoModeAvailability", 1),
            ("BrowserGuestModeEnabled", 0),
            ("BrowserAddPersonEnabled", 0),
        ],
        firefox: false,
    },
    Target {
        name: "Edge",
        key: r"Microsoft\Edge",
        list: "URLBlocklist",
        values: &[
            ("InPrivateModeAvailability", 1),
            ("BrowserGuestModeEnabled", 0),
            ("BrowserAddProfileEnabled", 0),
        ],
        firefox: false,
    },
    Target {
        name: "Brave",
        key: r"BraveSoftware\Brave",
        list: "URLBlocklist",
        values: &[
            ("IncognitoModeAvailability", 1),
            ("BrowserGuestModeEnabled", 0),
            ("BrowserAddPersonEnabled", 0),
            ("TorDisabled", 1),
        ],
        firefox: false,
    },
    Target {
        name: "Firefox",
        key: r"Mozilla\Firefox",
        list: r"WebsiteFilter\Block",
        values: &[("DisablePrivateBrowsing", 1)],
        firefox: true,
    },
];

impl Target {
    fn list_entries(&self, entries: &[String]) -> Vec<String> {
        if self.firefox {
            entries
                .iter()
                .flat_map(|entry| firefox_patterns(entry))
                .collect()
        } else {
            entries.to_vec()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PropertySnapshot {
    pub present: bool,
    pub value: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BrowserBaseline {
    pub properties: BTreeMap<String, PropertySnapshot>,
    pub blocklist: Vec<String>,
}

/// Browser policy as it was before Chainlink first applied a block.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Baseline {
    pub version: u32,
    pub chromium: BTreeMap<String, BrowserBaseline>,
    pub firefox: BrowserBaseline,
}

impl Baseline {
    fn section(&self, target: &Target) -> Option<&BrowserBaseline> {
        if target.firefox {
            Some(&self.firefox)
        } else {
            self.chromium.get(target.name)
        }
    }

    fn is_complete(&self) -> bool {
        TARGETS.iter().all(|target| {
            self.section(target).is_some_and(|section| {
                target
                    .values
                    .iter()
                    .all(|(name, _)| section.properties.contains_key(*name))
            })
        })
    }

    /// Parses a baseline written by this version or by the PowerShell release.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(bytes)?.trim_start_matches('\u{feff}');
        let value: Value = serde_json::from_str(text)?;
        let baseline = if value.get("version").and_then(Value::as_u64) == Some(3) {
            serde_json::from_value(value)?
        } else if value.get("Version").and_then(Value::as_u64) == Some(1) {
            Self::from_powershell(&value)?
        } else {
            bail!("unsupported policy baseline format");
        };
        if !baseline.is_complete() {
            bail!("incomplete policy baseline");
        }
        Ok(baseline)
    }

    fn from_powershell(value: &Value) -> Result<Self> {
        let convert = |section: &Value| -> Result<BrowserBaseline> {
            let properties = section
                .get("Properties")
                .and_then(Value::as_object)
                .context("missing Properties")?
                .iter()
                .map(|(name, snapshot)| {
                    let present = snapshot
                        .get("Present")
                        .and_then(Value::as_bool)
                        .context("invalid Present")?;
                    // PowerShell records large DWORDs as negative numbers.
                    let value = snapshot
                        .get("Value")
                        .and_then(Value::as_i64)
                        .map(|value| value as u32);
                    let is_dword = snapshot.get("Kind").and_then(Value::as_str) == Some("DWord");
                    Ok((
                        name.clone(),
                        PropertySnapshot {
                            present: present && is_dword && value.is_some(),
                            value: value.filter(|_| is_dword),
                        },
                    ))
                })
                .collect::<Result<BTreeMap<_, _>>>()?;
            let blocklist = section
                .get("Blocklist")
                .and_then(Value::as_array)
                .context("missing Blocklist")?
                .iter()
                .filter_map(|item| item.get("Value").and_then(Value::as_str))
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .collect();
            Ok(BrowserBaseline {
                properties,
                blocklist,
            })
        };
        let chromium_value = value.get("Chromium").context("missing Chromium baseline")?;
        let mut chromium = BTreeMap::new();
        for target in TARGETS.iter().filter(|target| !target.firefox) {
            let section = chromium_value
                .get(target.name)
                .context("missing browser baseline")?;
            chromium.insert(target.name.to_owned(), convert(section)?);
        }
        Ok(Self {
            version: 3,
            chromium,
            firefox: convert(value.get("Firefox").context("missing Firefox baseline")?)?,
        })
    }
}

/// Where browser policy lives: `HKLM\SOFTWARE\Policies` in production, a scratch key in tests.
pub struct PolicyRoot {
    pub hive: &'static RegKey,
    pub path: String,
}

impl PolicyRoot {
    pub fn system() -> Self {
        Self {
            hive: HKLM,
            path: r"SOFTWARE\Policies".to_owned(),
        }
    }

    fn key_path(&self, target: &Target) -> String {
        format!(r"{}\{}", self.path, target.key)
    }

    fn list_path(&self, target: &Target) -> String {
        format!(r"{}\{}\{}", self.path, target.key, target.list)
    }

    // The browsers read the 64-bit registry view, whatever this executable was built as.
    fn open(&self, path: &str, access: u32) -> std::io::Result<RegKey> {
        self.hive
            .open_subkey_with_flags(path, access | KEY_WOW64_64KEY)
    }

    fn create(&self, path: &str) -> std::io::Result<RegKey> {
        let (key, _) = self
            .hive
            .create_subkey_with_flags(path, KEY_READ | KEY_WRITE | KEY_WOW64_64KEY)?;
        Ok(key)
    }

    fn dword(&self, path: &str, name: &str) -> Option<u32> {
        self.open(path, KEY_READ)
            .and_then(|key| key.get_value::<u32, _>(name))
            .ok()
    }

    fn list_values(&self, path: &str) -> Vec<String> {
        self.open(path, KEY_READ)
            .ok()
            .into_iter()
            .flat_map(|key| key.enum_values().collect::<Vec<_>>())
            .filter_map(Result::ok)
            .filter_map(|(_, value)| String::from_reg_value(&value).ok())
            .collect()
    }

    /// Writes the list as values "1".."N" in place, then drops leftovers, so the policy is
    /// never momentarily absent. An empty list removes the key.
    fn write_list(&self, path: &str, values: &[String]) -> Result<()> {
        let key = if values.is_empty() {
            match self.open(path, KEY_READ | KEY_WRITE) {
                Ok(key) => key,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(error.into()),
            }
        } else {
            self.create(path)?
        };
        let mut wanted = HashSet::new();
        for (index, value) in values.iter().enumerate() {
            let name = (index + 1).to_string();
            key.set_value(&name, value)?;
            wanted.insert(name);
        }
        let names = key
            .enum_values()
            .filter_map(Result::ok)
            .map(|(name, _)| name)
            .collect::<Vec<_>>();
        for name in names {
            if !wanted.contains(&name) {
                key.delete_value(name)?;
            }
        }
        drop(key);
        if values.is_empty() {
            self.remove_empty_keys(path);
        }
        Ok(())
    }

    /// Deletes the key if it is empty, then its parents likewise, stopping below the root.
    fn remove_empty_keys(&self, path: &str) {
        let prefix = format!(r"{}\", self.path.to_ascii_lowercase());
        let mut path = path;
        while path.to_ascii_lowercase().starts_with(&prefix) {
            match self.open(path, KEY_READ).and_then(|key| key.query_info()) {
                Ok(info) if info.sub_keys > 0 || info.values > 0 => return,
                Ok(_) => {
                    if self
                        .hive
                        .delete_subkey_with_flags(path, KEY_WOW64_64KEY)
                        .is_err()
                    {
                        return;
                    }
                }
                Err(_) => {}
            }
            match path.rsplit_once('\\') {
                Some((parent, _)) => path = parent,
                None => return,
            }
        }
    }

    pub fn capture_baseline(&self) -> Baseline {
        let capture = |target: &Target| BrowserBaseline {
            properties: target
                .values
                .iter()
                .map(|(name, _)| {
                    let value = self.dword(&self.key_path(target), name);
                    (
                        (*name).to_owned(),
                        PropertySnapshot {
                            present: value.is_some(),
                            value,
                        },
                    )
                })
                .collect(),
            blocklist: self.list_values(&self.list_path(target)),
        };
        Baseline {
            version: 3,
            chromium: TARGETS
                .iter()
                .filter(|target| !target.firefox)
                .map(|target| (target.name.to_owned(), capture(target)))
                .collect(),
            firefox: capture(&TARGETS[3]),
        }
    }

    /// Applies the block. `previous` are entries an earlier lock wrote; they are replaced
    /// rather than mistaken for somebody else's policy.
    pub fn apply_lock(
        &self,
        entries: &[String],
        previous: &[String],
        baseline: Option<&Baseline>,
    ) -> Result<()> {
        let managed_entries = merge(&[entries, previous]);
        let mut first_error = None;
        for target in &TARGETS {
            // A failure on one browser must not leave the others unblocked.
            let applied = (|| -> Result<()> {
                let list_path = self.list_path(target);
                let managed: HashSet<_> =
                    target.list_entries(&managed_entries).into_iter().collect();
                let others = self
                    .list_values(&list_path)
                    .into_iter()
                    .filter(|value| !managed.contains(value))
                    .collect::<Vec<_>>();
                let base = baseline
                    .and_then(|baseline| baseline.section(target))
                    .map(|section| section.blocklist.clone())
                    .unwrap_or_default();
                self.write_list(
                    &list_path,
                    &merge(&[&base, &others, &target.list_entries(entries)]),
                )?;
                let key = self.create(&self.key_path(target))?;
                for (name, value) in target.values {
                    key.set_value(name, value)?;
                }
                Ok(())
            })();
            if let Err(error) = applied {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    /// Lifts the block: removes exactly the managed entries, keeps everything else, and
    /// restores the values recorded in the baseline. Without a baseline the values Chainlink
    /// manages are simply removed, as the original release did.
    pub fn lift_lock(&self, managed: &[String], baseline: Option<&Baseline>) -> Result<()> {
        for target in &TARGETS {
            let key_path = self.key_path(target);
            let list_path = self.list_path(target);
            let section = baseline.and_then(|baseline| baseline.section(target));
            let managed: HashSet<_> = target.list_entries(managed).into_iter().collect();
            let others = self
                .list_values(&list_path)
                .into_iter()
                .filter(|value| !managed.contains(value))
                .collect::<Vec<_>>();
            let base = section
                .map(|section| section.blocklist.clone())
                .unwrap_or_default();
            self.write_list(&list_path, &merge(&[&base, &others]))?;

            for (name, managed_value) in target.values {
                let exists = self
                    .open(&key_path, KEY_READ)
                    .is_ok_and(|key| key.get_raw_value(name).is_ok());
                if exists && self.dword(&key_path, name) != Some(*managed_value) {
                    continue; // somebody else has changed it since; leave it alone
                }
                let before = section
                    .and_then(|section| section.properties.get(*name))
                    .filter(|snapshot| snapshot.present)
                    .and_then(|snapshot| snapshot.value);
                match before {
                    Some(value) => self.create(&key_path)?.set_value(name, &value)?,
                    None if exists => self
                        .open(&key_path, KEY_READ | KEY_WRITE)?
                        .delete_value(name)?,
                    None => {}
                }
            }
            self.remove_empty_keys(&list_path);
            self.remove_empty_keys(&key_path);
        }
        Ok(())
    }

    pub fn lock_is_applied(&self, entries: &[String]) -> bool {
        TARGETS.iter().all(|target| {
            let key_path = self.key_path(target);
            let actual: HashSet<_> = self
                .list_values(&self.list_path(target))
                .into_iter()
                .collect();
            target
                .values
                .iter()
                .all(|(name, value)| self.dword(&key_path, name) == Some(*value))
                && target
                    .list_entries(entries)
                    .iter()
                    .all(|entry| actual.contains(entry))
        })
    }
}

// ---------------------------------------------------------------- the host: tasks and processes

/// Task Scheduler and other processes. The real implementation is [`Scheduler`].
pub trait Host {
    fn query_task_xml(&self) -> Option<String>;
    fn create_task(&self, env: &Env) -> Result<()>;
    fn stop_task(&self);
    fn delete_task(&self) -> Result<()>;
    /// Runs the watchdog of the original PowerShell release in its one-shot unlock mode.
    fn powershell_unlock(&self, script: &Path) -> Result<()>;
    /// Ends watchdogs of the original PowerShell release, which took no lock.
    fn stop_legacy_watchdogs(&self);
    /// Ends a leftover watchdog that still holds the lock.
    fn terminate_watchdog(&self, process_id: u32);
    /// Creates a Start menu shortcut that opens `target`.
    fn create_shortcut(&self, shortcut: &Path, target: &Path) -> Result<()>;
}

pub struct Scheduler;

fn run_hidden(program: &Path, arguments: &[&OsStr]) -> Result<std::process::Output> {
    Ok(Command::new(program)
        .args(arguments)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .output()?)
}

fn powershell() -> PathBuf {
    system_executable(r"WindowsPowerShell\v1.0\powershell.exe")
}

/// Runs a short PowerShell script without a window. The script travels encoded, never quoted.
fn run_powershell(script: &str) -> Result<()> {
    let bytes = script
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let encoded = STANDARD.encode(bytes);
    let output = run_hidden(
        &powershell(),
        &[
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            encoded.as_str(),
        ]
        .map(OsStr::new),
    )?;
    if !output.status.success() {
        bail!(
            "PowerShell reported an error: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// A PowerShell single-quoted string literal.
fn quoted(value: &Path) -> String {
    format!("'{}'", value.display().to_string().replace('\'', "''"))
}

impl Scheduler {
    fn schtasks(arguments: &[&OsStr]) -> Result<std::process::Output> {
        run_hidden(&system_executable("schtasks.exe"), arguments)
    }
}

impl Host for Scheduler {
    fn query_task_xml(&self) -> Option<String> {
        Self::schtasks(&["/Query", "/TN", TASK_NAME, "/XML"].map(OsStr::new))
            .ok()
            .filter(|output| output.status.success())
            .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
    }

    fn create_task(&self, env: &Env) -> Result<()> {
        let xml_path = env.file("task.xml");
        let mut bytes = vec![0xff, 0xfe];
        for unit in task_xml(&env.file("chainlink.exe"), true).encode_utf16() {
            bytes.extend(unit.to_le_bytes());
        }
        atomic_write(&xml_path, &bytes)?;
        let created = Self::schtasks(&[
            OsStr::new("/Create"),
            OsStr::new("/TN"),
            OsStr::new(TASK_NAME),
            OsStr::new("/XML"),
            xml_path.as_os_str(),
            OsStr::new("/F"),
        ]);
        let _ = fs::remove_file(&xml_path);
        let mut output = created?;
        if output.status.success() {
            output = Self::schtasks(&["/Run", "/TN", TASK_NAME].map(OsStr::new))?;
        }
        if !output.status.success() {
            bail!(
                "could not register the Chainlink scheduled task: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }

    fn stop_task(&self) {
        let _ = Self::schtasks(&["/End", "/TN", TASK_NAME].map(OsStr::new));
    }

    fn delete_task(&self) -> Result<()> {
        let output = Self::schtasks(&["/Delete", "/TN", TASK_NAME, "/F"].map(OsStr::new))?;
        if !output.status.success() && self.query_task_xml().is_some() {
            bail!("could not delete the Chainlink scheduled task");
        }
        Ok(())
    }

    fn powershell_unlock(&self, script: &Path) -> Result<()> {
        let output = run_hidden(
            &powershell(),
            &[
                OsStr::new("-NoProfile"),
                OsStr::new("-NonInteractive"),
                OsStr::new("-ExecutionPolicy"),
                OsStr::new("Bypass"),
                OsStr::new("-File"),
                script.as_os_str(),
                OsStr::new("-Unlock"),
            ],
        )?;
        if !output.status.success() {
            bail!("the existing PowerShell watchdog could not lift its blocks");
        }
        Ok(())
    }

    fn stop_legacy_watchdogs(&self) {
        let _ = run_powershell(
            r#"Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -like '*Chainlink\watchdog.ps1*' } | ForEach-Object { try { Invoke-CimMethod -InputObject $_ -MethodName Terminate -ErrorAction Stop | Out-Null } catch { } }"#,
        );
    }

    fn terminate_watchdog(&self, process_id: u32) {
        // taskkill only acts if that process id really is a Chainlink or PowerShell process.
        let pid = format!("PID eq {process_id}");
        for image in ["chainlink.exe", "powershell.exe"] {
            let image = format!("IMAGENAME eq {image}");
            let _ = run_hidden(
                &system_executable("taskkill.exe"),
                &["/F", "/FI", pid.as_str(), "/FI", image.as_str()].map(OsStr::new),
            );
        }
    }

    fn create_shortcut(&self, shortcut: &Path, target: &Path) -> Result<()> {
        run_powershell(&format!(
            "$shortcut = (New-Object -ComObject WScript.Shell).CreateShortcut({}); \
             $shortcut.TargetPath = {}; \
             $shortcut.Description = 'Remove Chainlink without the USB key, using your recovery words.'; \
             $shortcut.Save()",
            quoted(shortcut),
            quoted(target)
        ))
    }
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn xml_unescape(value: &str) -> String {
    value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

pub fn task_xml(executable: &Path, enabled: bool) -> String {
    let start = local_timestamp().replace(' ', "T");
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<RegistrationInfo><Description>Chainlink watchdog</Description><URI>\Chainlink</URI></RegistrationInfo>
<Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger><TimeTrigger><Repetition><Interval>PT1M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition><StartBoundary>{start}</StartBoundary><Enabled>true</Enabled></TimeTrigger></Triggers>
<Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
<Settings><Enabled>{enabled}</Enabled><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><StartWhenAvailable>true</StartWhenAvailable><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure></Settings>
<Actions Context="Author"><Exec><Command>{}</Command><Arguments>--watchdog</Arguments></Exec></Actions></Task>"#,
        xml_escape(&executable.display().to_string())
    )
}

/// The text of every `<tag>...</tag>` element, unescaped. Tag names match without regard to case.
fn element_texts(xml: &str, tag: &str) -> Vec<String> {
    let lower = xml.to_ascii_lowercase();
    let (open, close) = (
        format!("<{}>", tag.to_ascii_lowercase()),
        format!("</{}>", tag.to_ascii_lowercase()),
    );
    let mut texts = Vec::new();
    let mut position = 0;
    while let Some(start) = lower[position..].find(&open) {
        let start = position + start + open.len();
        let Some(length) = lower[start..].find(&close) else {
            break;
        };
        texts.push(xml_unescape(xml[start..start + length].trim()));
        position = start + length + close.len();
    }
    texts
}

/// (command, arguments) of every Exec action in a task definition.
fn task_actions(xml: &str) -> Vec<(String, String)> {
    element_texts(xml, "Exec")
        .iter()
        .map(|exec| {
            // element_texts unescaped the block once already; its children are plain text now.
            let child = |tag: &str| {
                let lower = exec.to_ascii_lowercase();
                let (open, close) = (
                    format!("<{}>", tag.to_ascii_lowercase()),
                    format!("</{}>", tag.to_ascii_lowercase()),
                );
                lower
                    .find(&open)
                    .and_then(|start| {
                        let start = start + open.len();
                        lower[start..]
                            .find(&close)
                            .map(|length| exec[start..start + length].trim().to_owned())
                    })
                    .unwrap_or_default()
            };
            (
                child("Command").trim_matches('"').to_owned(),
                child("Arguments"),
            )
        })
        .collect()
}

// ---------------------------------------------------------------- the environment

/// Where Chainlink keeps its files and which registry key holds browser policy.
pub struct Env {
    pub app_dir: PathBuf,
    pub policy: PolicyRoot,
    /// A copy of the executable that everyone can read and that offers emergency uninstall.
    /// It lives under Program Files, which only administrators can write.
    pub emergency_stub: PathBuf,
    /// The Start menu shortcut that opens the emergency stub.
    pub emergency_shortcut: PathBuf,
    /// The watchdog only looks for `<drive>:\Chainlink\chainlink.key`, so linking is refused
    /// from anywhere else. The tests, which cannot write to a drive root, turn this off.
    pub require_usb_layout: bool,
    last_once_message: Mutex<String>,
}

#[derive(Default, Serialize, Deserialize)]
struct AttemptState {
    failures: u32,
    until: u64,
}

impl Env {
    pub fn new(
        app_dir: PathBuf,
        policy: PolicyRoot,
        emergency_stub: PathBuf,
        emergency_shortcut: PathBuf,
    ) -> Self {
        Self {
            app_dir,
            policy,
            emergency_stub,
            emergency_shortcut,
            require_usb_layout: true,
            last_once_message: Mutex::new(String::new()),
        }
    }

    /// The real locations, resolved through Windows APIs rather than environment variables.
    pub fn system() -> Result<Self> {
        let program_data = known_folder(&FOLDERID_ProgramData, "ProgramData")?;
        let program_files = known_folder(&FOLDERID_ProgramFiles, "Program Files")?;
        Ok(Self::new(
            program_data.join("Chainlink"),
            PolicyRoot::system(),
            program_files.join("Chainlink").join(EMERGENCY_STUB_NAME),
            program_data
                .join("Microsoft")
                .join("Windows")
                .join("Start Menu")
                .join("Programs")
                .join(EMERGENCY_SHORTCUT_NAME),
        ))
    }

    /// Written by uninstall just before it deletes the program folder; tells a watchdog to exit.
    pub fn uninstall_marker(&self) -> PathBuf {
        self.file("uninstalling")
    }

    pub fn file(&self, name: &str) -> PathBuf {
        self.app_dir.join(name)
    }

    pub fn log(&self, message: &str) {
        self.write_log(message, false);
    }

    /// Logs a message that may repeat every cycle only once.
    fn log_once(&self, message: &str) {
        self.write_log(message, true);
    }

    fn write_log(&self, message: &str, once: bool) {
        if let Ok(mut last) = self.last_once_message.lock() {
            if once && *last == message {
                return;
            }
            message.clone_into(&mut last);
        }
        let path = self.file("log.txt");
        if path
            .metadata()
            .is_ok_and(|metadata| metadata.len() > 200 * 1024)
        {
            let _ = fs::rename(&path, self.file("log.txt.old"));
        }
        if let Ok(mut output) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(output, "{}  {message}", local_timestamp());
        }
    }

    fn set_status(&self, message: &str) {
        let _ = atomic_write(&self.file("status.txt"), format!("{message}\n").as_bytes());
    }

    // ---- baseline, blocklist, and the record of applied entries

    pub fn capture_baseline(&self) -> Result<()> {
        let path = self.file("policy-baseline.json");
        if path.exists() {
            return Ok(());
        }
        let baseline = self.policy.capture_baseline();
        atomic_write(
            &path,
            format!("{}\n", serde_json::to_string_pretty(&baseline)?).as_bytes(),
        )?;
        self.log("Captured pre-install browser policy baseline.");
        Ok(())
    }

    pub fn read_baseline(&self) -> Option<Baseline> {
        let parsed = fs::read(self.file("policy-baseline.json"))
            .map_err(anyhow::Error::from)
            .and_then(|bytes| Baseline::parse(&bytes));
        match parsed {
            Ok(baseline) => Some(baseline),
            Err(error) => {
                self.log_once(&format!(
                    "Policy baseline is unreadable; Chainlink will remove only its own values: {error:#}"
                ));
                None
            }
        }
    }

    /// The installed blocklist, or "*" (block everything) when it is missing or corrupt.
    fn installed_blocklist(&self) -> Vec<String> {
        match read_blocklist(&self.file("blocklist.txt")) {
            Ok(entries) => entries,
            Err(error) => {
                self.log_once(&format!(
                    "Installed blocklist is invalid; blocking all URLs as a fail-safe: {error:#}"
                ));
                vec!["*".to_owned()]
            }
        }
    }

    /// The entries the last lock wrote. Unlock removes exactly these, whatever blocklist.txt
    /// says now.
    pub fn applied_entries(&self) -> Vec<String> {
        fs::read_to_string(self.file("applied-blocklist.txt"))
            .unwrap_or_default()
            .trim_start_matches('\u{feff}')
            .lines()
            .filter(|line| !line.is_empty() && line.len() <= 4096)
            .map(ToOwned::to_owned)
            .collect()
    }

    fn write_applied(&self, entries: &[String]) -> Result<()> {
        let text = entries
            .iter()
            .map(|entry| format!("{entry}\n"))
            .collect::<String>();
        atomic_write(&self.file("applied-blocklist.txt"), text.as_bytes())
    }

    pub fn set_lock(&self) -> Result<()> {
        let entries = self.installed_blocklist();
        let previous = self.applied_entries();
        // Record the entries before writing them, so an interrupted lock can still be undone.
        // The record is a convenience for unlock; failing to write it must never stop the lock.
        if let Err(error) = self.write_applied(&merge(&[&previous, &entries])) {
            self.log_once(&format!("Could not record applied entries: {error:#}"));
        }
        self.policy
            .apply_lock(&entries, &previous, self.read_baseline().as_ref())?;
        let _ = self.write_applied(&entries);
        Ok(())
    }

    pub fn remove_lock(&self) -> Result<()> {
        let managed = merge(&[&self.applied_entries(), &self.installed_blocklist()]);
        self.policy
            .lift_lock(&managed, self.read_baseline().as_ref())?;
        match fs::remove_file(self.file("applied-blocklist.txt")) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.into()),
            _ => Ok(()),
        }
    }

    pub fn lock_intact(&self) -> bool {
        self.policy.lock_is_applied(&self.installed_blocklist())
    }

    // ---- the paired key

    pub fn paired_hashes(&self) -> HashSet<String> {
        fs::read_to_string(self.file("pair.txt"))
            .unwrap_or_default()
            .trim_start_matches('\u{feff}')
            .lines()
            .map(str::trim)
            .filter(|line| line.len() == 64 && line.chars().all(|c| c.is_ascii_hexdigit()))
            .map(str::to_ascii_lowercase)
            .collect()
    }

    /// The root of the drive holding a valid paired key, e.g. `D:\`.
    pub fn find_key(&self) -> Option<PathBuf> {
        let expected = self.paired_hashes();
        if expected.is_empty() {
            return None;
        }
        let mask = unsafe { GetLogicalDrives() };
        (0..26_u8)
            .filter(|index| mask & (1 << index) != 0)
            .map(|index| PathBuf::from(format!("{}:\\", (b'A' + index) as char)))
            .filter(|root| {
                let drive_type = unsafe { GetDriveTypeW(wide(root.as_os_str()).as_ptr()) };
                matches!(drive_type, DRIVE_REMOVABLE | DRIVE_FIXED)
            })
            .find(|root| {
                key_matches(
                    &root.join("Chainlink").join("chainlink.key"),
                    root,
                    &expected,
                )
            })
    }

    pub fn usb_matches_pc(&self, usb_dir: &Path) -> bool {
        usb_root(usb_dir).is_ok_and(|root| {
            key_matches(&usb_dir.join("chainlink.key"), &root, &self.paired_hashes())
        })
    }

    /// Installs the USB blocklist when it has changed and is valid. Returns "" on success, or
    /// a short description of what is wrong with the USB copy. A bad USB blocklist never
    /// prevents the key from unlocking this PC; the installed list simply stays in force.
    pub fn sync_blocklist(&self, root: &Path) -> String {
        let source = root.join("Chainlink").join("blocklist.txt");
        // The watchdog runs as SYSTEM, so it must not follow a link on the USB to another file.
        if is_reparse(&source).unwrap_or(false) {
            return "blocklist.txt on the USB is a link, not a file".to_owned();
        }
        match fs::metadata(&source) {
            Ok(metadata) if metadata.len() > MAX_USB_BLOCKLIST_BYTES => {
                return "blocklist.txt on the USB is too large".to_owned();
            }
            Ok(_) => {}
            Err(_) => return r"the USB has no readable Chainlink\blocklist.txt".to_owned(),
        }
        // Validate the same bytes that get installed.
        let Ok(bytes) = fs::read(&source) else {
            return r"the USB has no readable Chainlink\blocklist.txt".to_owned();
        };
        let installed = self.file("blocklist.txt");
        if fs::read(&installed).ok().as_deref() == Some(bytes.as_slice()) {
            return String::new();
        }
        if let Err(error) = parse_blocklist_bytes(&bytes) {
            return format!("blocklist.txt on the USB has a problem: {error:#}");
        }
        match atomic_write(&installed, &bytes) {
            Ok(()) => {
                self.log("Blocklist updated from USB.");
                String::new()
            }
            Err(error) => format!("the blocklist could not be copied from the USB: {error:#}"),
        }
    }

    // ---- scheduled task ownership

    /// True when the task runs as SYSTEM and its action is exactly a Chainlink watchdog.
    pub fn task_xml_is_genuine(&self, xml: &str) -> bool {
        let users = element_texts(xml, "UserId");
        if users.is_empty()
            || !users.iter().all(|user| {
                user.eq_ignore_ascii_case("S-1-5-18") || user.eq_ignore_ascii_case("SYSTEM")
            })
        {
            return false;
        }
        let installed = self.file("chainlink.exe").display().to_string();
        // The PowerShell releases: the original registered the bare name, later ones the path.
        let powershell = system_executable(r"WindowsPowerShell\v1.0\powershell.exe")
            .display()
            .to_string();
        let script = self.file("watchdog.ps1").display().to_string();
        let powershell_arguments = [
            format!(
                "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File \"{script}\""
            ),
            format!("-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"{script}\""),
        ];
        task_actions(xml).iter().any(|(command, arguments)| {
            (command.eq_ignore_ascii_case(&installed) && arguments == "--watchdog")
                || ([powershell.as_str(), "powershell.exe", "powershell"]
                    .iter()
                    .any(|candidate| command.eq_ignore_ascii_case(candidate))
                    && powershell_arguments
                        .iter()
                        .any(|candidate| arguments.eq_ignore_ascii_case(candidate)))
        })
    }

    /// True when any action would run something from the program folder. Uninstall uses this
    /// looser test so that it never leaves a SYSTEM task pointing at a folder it just deleted.
    pub fn task_xml_references_app_dir(&self, xml: &str) -> bool {
        let needle = format!(
            r"{}\",
            self.app_dir
                .display()
                .to_string()
                .trim_end_matches('\\')
                .to_ascii_lowercase()
        );
        task_actions(xml).iter().any(|(command, arguments)| {
            command.to_ascii_lowercase().contains(&needle)
                || arguments.to_ascii_lowercase().contains(&needle)
        })
    }

    pub fn genuine_task(&self, host: &dyn Host) -> bool {
        host.query_task_xml()
            .is_some_and(|xml| self.task_xml_is_genuine(&xml))
    }

    /// Removes the task if it is Chainlink's or runs from the program folder; leaves any other.
    fn delete_own_task(&self, host: &dyn Host) -> Result<()> {
        match host.query_task_xml() {
            Some(xml)
                if self.task_xml_is_genuine(&xml) || self.task_xml_references_app_dir(&xml) =>
            {
                host.delete_task()
            }
            _ => Ok(()),
        }
    }

    // ---- install, repair, uninstall

    fn owns_task(&self, xml: &str) -> bool {
        self.task_xml_is_genuine(xml) || self.task_xml_references_app_dir(xml)
    }

    /// Stops the watchdog and returns the held lock, which keeps any new watchdog from starting
    /// until it is dropped. Returns None when there is no program folder.
    pub fn stop_watchdog(&self, host: &dyn Host, timeout: Duration) -> Result<Option<File>> {
        if host
            .query_task_xml()
            .is_some_and(|xml| self.owns_task(&xml))
        {
            host.stop_task();
        }
        if self.file("watchdog.ps1").is_file() {
            host.stop_legacy_watchdogs();
        }
        if !self.app_dir.is_dir() {
            return Ok(None);
        }
        let lock_path = self.file("watchdog.lock");
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(lock) = open_watchdog_lock(&lock_path)? {
                return Ok(Some(lock));
            }
            let owner = watchdog_lock_owner(&lock_path);
            if owner != 0 && owner != std::process::id() {
                host.terminate_watchdog(owner);
            }
            if Instant::now() > deadline {
                bail!(
                    "the Chainlink watchdog is still running and could not be stopped; wait a minute and try again"
                );
            }
            thread::sleep(Duration::from_millis(300));
        }
    }

    /// Lifts the blocks of whatever is installed on this PC.
    fn unlock_installed(&self, host: &dyn Host) -> Result<()> {
        let old_powershell = self.file("watchdog.ps1");
        if old_powershell.is_file() && !self.file("policy-baseline.json").exists() {
            // The original release kept no record of earlier policy; its own code undoes it.
            host.powershell_unlock(&old_powershell)
        } else {
            self.remove_lock()
        }
    }

    /// Refuses to go on when the program folder could have been written by a non-administrator.
    fn require_trusted_program_folder(&self) -> Result<()> {
        if fs::symlink_metadata(&self.app_dir).is_ok() && !is_trusted_directory(&self.app_dir)? {
            bail!(
                "{} was not created by Chainlink, or another account has been able to change it. Nothing in it was used. Delete that folder as Administrator and try again.",
                self.app_dir.display()
            );
        }
        Ok(())
    }

    /// Links this PC to the USB in `usb_dir`, or repairs an existing link. Returns new recovery
    /// words when this is the first link.
    pub fn install(
        &self,
        host: &dyn Host,
        usb_dir: &Path,
        source_exe: &Path,
        stop_timeout: Duration,
    ) -> Result<Option<Vec<String>>> {
        if self.require_usb_layout && !usb_layout_ok(usb_dir) {
            bail!(
                r"Chainlink has to be started from the Chainlink folder at the top level of the USB drive (for example E:\Chainlink). It is running from {}.",
                usb_dir.display()
            );
        }
        read_blocklist(&usb_dir.join("blocklist.txt"))?;
        self.require_trusted_program_folder()?;
        let task = host.query_task_xml();
        let has_task = task
            .as_deref()
            .is_some_and(|xml| self.task_xml_is_genuine(xml));
        if task.is_some() && !has_task {
            bail!(
                "a scheduled task named Chainlink exists and does not belong to this application"
            );
        }

        let key_file = usb_dir.join("chainlink.key");
        if key_file.exists() {
            read_key_token(&key_file)?;
        } else {
            atomic_write(&key_file, new_key_token()?.as_bytes())?;
            let _ = run_hidden(
                &system_executable("attrib.exe"),
                &[OsStr::new("+h"), key_file.as_os_str()],
            );
        }
        let current_hash = usb_hash(usb_dir)?;

        // Program folder that only SYSTEM and Administrators can read or change. Everything in
        // it runs as SYSTEM, so a folder another account created or owns is never reused.
        let app = &self.app_dir;
        let mut existing = has_task;
        if fs::symlink_metadata(app).is_ok() && !existing {
            if fs::read_dir(app)?.next().is_none() {
                fs::remove_dir(app)?;
            } else if is_protected_directory(app)?
                && ["chainlink.exe", "watchdog.ps1", "watchdog.py"]
                    .iter()
                    .any(|name| self.file(name).is_file())
            {
                // A Chainlink folder only administrators could have written, whose task is gone
                // (for example after an interrupted uninstall). Repair it like any other
                // install, so its blocks are lifted before a new baseline could ever be taken.
                existing = true;
            } else {
                bail!(
                    "{} already contains files but no Chainlink scheduled task exists. If Chainlink is installed, use Uninstall (or Chainlink Emergency Uninstall) first; otherwise delete that folder as Administrator, then link again.",
                    app.display()
                );
            }
        }
        let created = fs::symlink_metadata(app).is_err();
        if created {
            create_protected_directory(app)?;
        } else {
            protect_existing_directory(app)?;
        }

        let result = self.install_files(
            host,
            usb_dir,
            source_exe,
            current_hash,
            existing,
            stop_timeout,
        );
        if result.is_err() && created {
            // A first-time link that fails leaves nothing behind, so it can simply be retried.
            // The folder goes only once the task is gone: a SYSTEM task must never be left
            // pointing at a path that any account could then recreate.
            host.stop_task();
            if self.delete_own_task(host).is_ok() && host.query_task_xml().is_none() {
                self.remove_emergency_entry();
                let _ = fs::remove_dir_all(app);
            }
        }
        result
    }

    fn install_files(
        &self,
        host: &dyn Host,
        usb_dir: &Path,
        source_exe: &Path,
        current_hash: String,
        upgrade: bool,
        stop_timeout: Duration,
    ) -> Result<Option<Vec<String>>> {
        // Hold the watchdog lock while files change, so no watchdog runs a half-replaced copy.
        let lock = self.stop_watchdog(host, stop_timeout)?;
        let files = || -> Result<()> {
            let _ = fs::remove_file(self.uninstall_marker());
            if upgrade {
                self.unlock_installed(host)?; // lift the old copy's blocks before replacing it
            }
            let executable = fs::read(source_exe)?;
            atomic_write(&self.file("chainlink.exe"), &executable)?;
            let baseline = self.file("policy-baseline.json");
            if baseline.exists() && self.read_baseline().is_none() {
                // Unreadable, so the unlock above already fell back to removing Chainlink's
                // own values. Take a fresh one.
                fs::remove_file(&baseline)?;
            }
            self.capture_baseline()?;
            if self.read_baseline().is_none() {
                bail!("could not save existing browser policy; installation stopped");
            }

            let mut known = self.paired_hashes().into_iter().collect::<Vec<_>>();
            if !known.contains(&current_hash) {
                known.push(current_hash.clone());
            }
            known.sort();
            atomic_write(
                &self.file("pair.txt"),
                format!("{}\n", known.join("\n")).as_bytes(),
            )?;
            let blocklist = fs::read(usb_dir.join("blocklist.txt"))?;
            parse_blocklist_bytes(&blocklist)?;
            atomic_write(&self.file("blocklist.txt"), &blocklist)?;

            // Emergency uninstall: a readable copy of the program under Program Files, and a
            // Start menu shortcut to it (which replaces the PowerShell release's shortcut).
            if let Some(directory) = self.emergency_stub.parent() {
                fs::create_dir_all(directory)?;
            }
            atomic_write(&self.emergency_stub, &executable)?;
            host.create_shortcut(&self.emergency_shortcut, &self.emergency_stub)
        }();
        drop(lock);
        files?;

        // The original release's watchdog takes no lock; make sure none started meanwhile.
        if self.file("watchdog.ps1").is_file() {
            host.stop_legacy_watchdogs();
        }
        host.create_task(self)?;
        for obsolete in [
            "Chainlink.ps1",
            "Chainlink.Common.psm1",
            "watchdog.ps1",
            "watchdog.py",
        ] {
            let _ = fs::remove_file(self.file(obsolete));
        }

        // First time on this PC: recovery words for the accountability partner. Made last, so
        // that if anything above fails the words are not stored without ever being shown.
        if self.file("recovery.txt").exists() {
            Ok(None)
        } else {
            self.replace_recovery_words().map(Some)
        }
    }

    /// Removes Chainlink from this PC.
    ///
    /// Order matters. First make sure no watchdog is running and none can start (the task fires
    /// every minute and would re-apply the blocks behind our back), then lift the blocks, and
    /// only then delete the files.
    pub fn uninstall(&self, host: &dyn Host, stop_timeout: Duration) -> Result<()> {
        self.require_trusted_program_folder()?;
        let lock = self.stop_watchdog(host, stop_timeout)?;
        let unlocked = self
            .delete_own_task(host)
            .and_then(|()| self.unlock_installed(host))
            .and_then(|()| {
                // Tell any watchdog that was already starting to exit instead of locking again.
                // It can only get the lock after this point, and it checks for the marker once
                // it has it.
                if self.app_dir.is_dir() {
                    fs::write(self.uninstall_marker(), b"")?;
                }
                Ok(())
            });
        drop(lock);
        unlocked?;

        let app = &self.app_dir;
        if fs::symlink_metadata(app).is_ok() {
            if is_reparse(app)? {
                bail!("refusing to remove a reparse-point program directory");
            }
            // A watchdog that is just exiting can hold the lock file for a moment; retry briefly.
            let mut attempt = 0;
            while let Err(error) = fs::remove_dir_all(app) {
                attempt += 1;
                if attempt >= 10 {
                    return Err(error).with_context(|| format!("remove {}", app.display()));
                }
                thread::sleep(Duration::from_millis(500));
            }
        }
        self.remove_emergency_entry();
        Ok(())
    }

    fn running_from_stub(&self) -> bool {
        env::current_exe().is_ok_and(|current| same_path(&current, &self.emergency_stub))
    }

    /// Removes the Start menu shortcut and the emergency copy. A copy that is running right now
    /// (emergency uninstall) stays until [`Env::remove_stub_after_exit`] is called.
    fn remove_emergency_entry(&self) {
        let _ = fs::remove_file(&self.emergency_shortcut);
        if !self.running_from_stub() {
            let _ = fs::remove_file(&self.emergency_stub);
            if let Some(directory) = self.emergency_stub.parent() {
                let _ = fs::remove_dir(directory); // only if empty
            }
        }
    }

    /// Call as the last thing before the emergency copy exits after a successful uninstall.
    ///
    /// A running executable cannot delete itself, so a short-lived helper retries for about
    /// half a minute until this process is gone. The ping to the loopback address is only a
    /// one-second delay that works without a console; nothing leaves this PC.
    pub fn remove_stub_after_exit(&self) {
        if !self.running_from_stub() || self.app_dir.exists() {
            return;
        }
        let stub = self.emergency_stub.display().to_string();
        let directory = self
            .emergency_stub
            .parent()
            .map(|parent| parent.display().to_string())
            .unwrap_or_default();
        let command = format!(
            "/d /s /c \"for /l %i in (1,1,30) do @(del /f /q \"{stub}\" >nul 2>&1 & if not exist \"{stub}\" (rmdir \"{directory}\" >nul 2>&1 & exit) else (ping -n 2 127.0.0.1 >nul))\""
        );
        let spawned = Command::new(system_executable("cmd.exe"))
            .raw_arg(command)
            .current_dir(system_executable(""))
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        if spawned.is_err() {
            // Fall back to removal at the next restart.
            unsafe {
                MoveFileExW(
                    wide(self.emergency_stub.as_os_str()).as_ptr(),
                    std::ptr::null(),
                    MOVEFILE_DELAY_UNTIL_REBOOT,
                );
            }
        }
    }

    // ---- recovery words

    pub fn replace_recovery_words(&self) -> Result<Vec<String>> {
        let words = new_recovery_words()?;
        let record = make_recovery_record(&words, RECOVERY_ROUNDS)?;
        atomic_write(&self.file("recovery.txt"), format!("{record}\n").as_bytes())?;
        Ok(words)
    }

    fn attempt_state(&self) -> AttemptState {
        fs::read(self.file("recovery-attempts.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    /// Seconds until another recovery attempt is allowed.
    pub fn recovery_delay(&self) -> u64 {
        self.attempt_state().until.saturating_sub(epoch_seconds())
    }

    pub fn verify_recovery(&self, words: &[String]) -> bool {
        self.recovery_delay() == 0
            && fs::read_to_string(self.file("recovery.txt"))
                .is_ok_and(|record| verify_recovery_record(&record, words))
    }

    pub fn register_recovery_failure(&self) -> Result<()> {
        let mut state = self.attempt_state();
        state.failures = (state.failures + 1).min(6);
        state.until = epoch_seconds() + (1_u64 << (state.failures + 1)).min(60);
        atomic_write(
            &self.file("recovery-attempts.json"),
            format!("{}\n", serde_json::to_string(&state)?).as_bytes(),
        )
    }

    pub fn clear_recovery_failures(&self) {
        let _ = fs::remove_file(self.file("recovery-attempts.json"));
    }
}

// ---------------------------------------------------------------- drives

fn usb_root(usb_dir: &Path) -> Result<PathBuf> {
    let display = usb_dir.display().to_string();
    let display = display.strip_prefix(r"\\?\").unwrap_or(&display);
    if display.len() < 2
        || display.as_bytes()[1] != b':'
        || !display.as_bytes()[0].is_ascii_alphabetic()
    {
        bail!("Chainlink must run from a Windows drive");
    }
    Ok(PathBuf::from(format!("{}:\\", &display[..1])))
}

/// True when `usb_dir` is `<drive>:\Chainlink`, the only place the watchdog looks for the key.
fn usb_layout_ok(usb_dir: &Path) -> bool {
    usb_root(usb_dir).is_ok_and(|root| same_path(usb_dir, &root.join("Chainlink")))
}

/// The volume serial as text. The first form is used for new pairings. The second, without
/// leading zeros, is accepted when matching so that pairings made by the PowerShell release
/// keep working whichever way Windows formatted the number for it.
pub fn volume_serials(root: &Path) -> Result<Vec<String>> {
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
    let mut serials = vec![format!("{serial:08X}")];
    let short = format!("{serial:X}");
    if short != serials[0] {
        serials.push(short);
    }
    Ok(serials)
}

pub fn usb_hash(usb_dir: &Path) -> Result<String> {
    let root = usb_root(usb_dir)?;
    let token = read_key_token(&usb_dir.join("chainlink.key"))?;
    let serial = volume_serials(&root)?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("the drive has no volume serial number"))?;
    Ok(pairing_hash(&token, &serial))
}

fn key_matches(key_file: &Path, root: &Path, expected: &HashSet<String>) -> bool {
    if is_reparse(key_file).unwrap_or(true)
        || !fs::metadata(key_file).is_ok_and(|metadata| metadata.len() <= 1024)
    {
        return false;
    }
    let (Ok(token), Ok(serials)) = (read_key_token(key_file), volume_serials(root)) else {
        return false;
    };
    serials
        .iter()
        .any(|serial| expected.contains(&pairing_hash(&token, serial)))
}

// ---------------------------------------------------------------- the watchdog

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockState {
    Unknown,
    Locked,
    Unlocked,
}

/// The watchdog loop, one cycle at a time.
pub struct Watchdog {
    pub state: LockState,
    pub usb_problem: String,
    pub tick: u64,
}

impl Default for Watchdog {
    fn default() -> Self {
        Self {
            state: LockState::Unknown,
            usb_problem: String::new(),
            tick: 0,
        }
    }
}

impl Watchdog {
    /// One pass. `key` is the root of the drive holding the paired key, if one is plugged in.
    pub fn cycle(&mut self, env: &Env, key: Option<&Path>) {
        let outcome = match key {
            Some(root) => self.with_key(env, root),
            None => self.without_key(env),
        };
        if let Err(error) = outcome {
            env.log_once(&format!("Watchdog cycle failed: {error:#}"));
            // With the key present there is nothing to enforce; the unlock is retried next
            // cycle. Without it, make sure the blocks are on.
            self.state = LockState::Unknown;
            if key.is_none() {
                match env.set_lock() {
                    Ok(()) => {
                        self.state = LockState::Locked;
                        env.set_status("LOCKED - fail-safe after an error");
                    }
                    Err(error) => env.log_once(&format!("Fail-safe lock also failed: {error:#}")),
                }
            }
        }
        self.tick += 1;
    }

    fn with_key(&mut self, env: &Env, root: &Path) -> Result<()> {
        if self.state != LockState::Unlocked {
            env.remove_lock()?;
            self.state = LockState::Unlocked;
            self.usb_problem.clear();
            env.set_status(&format!("UNLOCKED - key found on {}", root.display()));
            env.log(&format!("Key found on {} - blocks lifted.", root.display()));
        }
        let problem = env.sync_blocklist(root);
        if problem != self.usb_problem {
            if problem.is_empty() {
                env.set_status(&format!("UNLOCKED - key found on {}", root.display()));
            } else {
                env.set_status(&format!(
                    "UNLOCKED - key found on {}. The previous blocklist is still in use: {problem}",
                    root.display()
                ));
                env.log(&format!("Blocklist not updated: {problem}"));
            }
            self.usb_problem = problem;
        }
        Ok(())
    }

    fn without_key(&mut self, env: &Env) -> Result<()> {
        if self.state != LockState::Locked || (self.tick.is_multiple_of(12) && !env.lock_intact()) {
            env.set_lock()?;
            env.log(if self.state == LockState::Locked {
                "Blocks were changed outside Chainlink - re-applied."
            } else {
                "Key not present - blocks applied."
            });
            self.state = LockState::Locked;
            env.set_status("LOCKED - key not present");
        }
        Ok(())
    }
}

/// Runs the watchdog until the process is stopped or Chainlink is uninstalled.
pub fn run_watchdog(env: &Env) -> Result<()> {
    if !env.app_dir.is_dir() {
        return Ok(()); // uninstalled
    }
    let Some(_lock) = open_watchdog_lock(&env.file("watchdog.lock"))? else {
        return Ok(()); // another watchdog, or an install or uninstall, holds the lock
    };
    // Checked only after the lock is held: uninstall writes the marker while it holds the lock,
    // so a watchdog that was already starting can never slip in behind it and lock again.
    if env.uninstall_marker().exists() {
        return Ok(());
    }
    env.log("Watchdog started.");
    let mut watchdog = Watchdog::default();
    while !env.uninstall_marker().exists() {
        watchdog.cycle(env, env.find_key().as_deref());
        thread::sleep(Duration::from_secs(5));
    }
    Ok(())
}
