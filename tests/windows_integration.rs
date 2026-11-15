#![cfg(windows)]

use chainlink_blocker::windows;
use std::fs;
use std::process::Command;

fn decode_utf16le(bytes: &[u8]) -> String {
    let bytes = bytes.strip_prefix(&[0xff, 0xfe]).unwrap_or(bytes);
    let units = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    String::from_utf16(&units).expect("valid UTF-16 task XML")
}

#[test]
fn volume_serial_matches_windows_inventory() {
    let actual =
        windows::volume_serial(std::path::Path::new(r"C:\")).expect("read the C: volume serial");
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
    let expected = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    assert_eq!(actual, expected);
}

#[test]
fn generated_task_xml_is_trusted_and_accepted() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let xml_path = temporary.path().join("task.xml");
    windows::write_disabled_task_xml(&xml_path).expect("write task XML");
    let xml = decode_utf16le(&fs::read(&xml_path).expect("read task XML"));
    assert!(xml.contains("<UserId>S-1-5-18</UserId>"));
    assert!(xml.contains("<Enabled>false</Enabled>"));
    assert!(xml.contains(&windows::installed_exe().display().to_string()));
    assert!(!xml.contains("%ProgramData%"));
    assert!(windows::task_xml_is_genuine(&xml));
    assert!(!windows::task_xml_is_genuine(&format!(
        "<Task><UserId>S-1-5-21-1</UserId><Description>{}</Description></Task>",
        windows::installed_exe().display()
    )));

    let task_name = format!(r"\ChainlinkRustValidation-{}", std::process::id());
    let create = Command::new("schtasks.exe")
        .args(["/Create", "/TN", &task_name, "/XML"])
        .arg(&xml_path)
        .arg("/F")
        .output()
        .expect("invoke Task Scheduler");
    if !create.status.success() {
        panic!(
            "Task Scheduler rejected generated XML: {}{}",
            String::from_utf8_lossy(&create.stdout),
            String::from_utf8_lossy(&create.stderr)
        );
    }
    let delete = Command::new("schtasks.exe")
        .args(["/Delete", "/TN", &task_name, "/F"])
        .output()
        .expect("delete validation task");
    assert!(delete.status.success());
}

#[test]
fn secured_directory_excludes_builtin_users() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    windows::secure_app_directory(temporary.path()).expect("apply hardened ACL");
    let output = Command::new("icacls.exe")
        .arg(temporary.path())
        .output()
        .expect("read hardened ACL");
    assert!(output.status.success());
    let acl = String::from_utf8_lossy(&output.stdout);
    assert!(acl.contains("SYSTEM:(OI)(CI)(F)"), "{acl}");
    assert!(acl.contains("Administrators:(OI)(CI)(F)"), "{acl}");
    assert!(!acl.contains("Users:"), "{acl}");
}
