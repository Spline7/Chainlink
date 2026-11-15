#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
mod ui;

#[cfg(windows)]
fn run() -> anyhow::Result<()> {
    use chainlink_blocker::windows;
    use std::env;
    use std::fs;
    use std::path::{Path, PathBuf};

    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    let mode = arguments
        .first()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    match mode {
        "--watchdog" => return windows::watchdog(),
        "--unlock" => return windows::remove_lock(),
        "--capture-baseline" => return windows::capture_baseline(),
        "--volume-serial" => {
            let root = arguments
                .get(1)
                .map(PathBuf::from)
                .ok_or_else(|| anyhow::anyhow!("missing root"))?;
            println!("{}", windows::volume_serial(&root)?);
            return Ok(());
        }
        "--write-disabled-task-xml" => {
            let path = arguments
                .get(1)
                .map(PathBuf::from)
                .ok_or_else(|| anyhow::anyhow!("missing output path"))?;
            return windows::write_disabled_task_xml(&path);
        }
        "--secure-directory" => {
            let path = arguments
                .get(1)
                .map(PathBuf::from)
                .ok_or_else(|| anyhow::anyhow!("missing directory path"))?;
            fs::create_dir(&path)?;
            return windows::secure_app_directory(&path);
        }
        _ => {}
    }

    let executable = env::current_exe()?;
    let file_name = executable
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    if file_name.eq_ignore_ascii_case("Chainlink Emergency Uninstall.exe") {
        return windows::launch_elevated(&windows::installed_exe(), &["--emergency"]);
    }
    if mode == "--emergency" {
        if !windows::is_admin() {
            return windows::relaunch_elevated(&["--emergency"]);
        }
        return ui::run_emergency();
    }
    if !windows::is_admin() {
        return windows::relaunch_elevated(&[]);
    }
    let usb_dir = executable
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow::anyhow!("executable has no parent"))?;
    ui::run_settings(usb_dir)
}

#[cfg(windows)]
fn main() {
    if let Err(error) = run() {
        native_windows_gui::error_message("Chainlink", &format!("{error:#}"));
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!(
        "Chainlink's executable is supported only on Windows; run `cargo test` for cross-platform core checks."
    );
}
