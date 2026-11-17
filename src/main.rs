#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
mod ui;

#[cfg(windows)]
fn run() -> anyhow::Result<()> {
    use chainlink_blocker::windows::{self, Env};
    use std::env;
    use std::path::Path;

    let mode = env::args().nth(1).unwrap_or_default();
    if mode == "--watchdog" {
        // Started by the scheduled task as SYSTEM, where nobody can see or dismiss a message
        // box. An error ends the process so that Task Scheduler starts it again.
        let outcome = Env::system().and_then(|system| {
            let outcome = windows::run_watchdog(&system);
            if let Err(error) = &outcome {
                system.log(&format!("Watchdog stopped: {error:#}"));
            }
            outcome
        });
        std::process::exit(i32::from(outcome.is_err()));
    }
    let system = Env::system()?;

    let executable = env::current_exe()?;
    let is_stub = executable
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case(windows::EMERGENCY_STUB_NAME));
    if is_stub || mode == "--emergency" {
        // The Start menu copy is readable by everyone, so it can ask for elevation itself and
        // never needs the protected program folder until it is elevated.
        if !windows::is_admin() {
            return windows::relaunch_elevated(&["--emergency"]);
        }
        return ui::run_emergency(system);
    }

    if !windows::is_admin() {
        return windows::relaunch_elevated(&[]);
    }
    let usb_dir = executable
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow::anyhow!("executable has no parent"))?;
    if windows::same_path(&usb_dir, &system.app_dir) {
        anyhow::bail!(
            "This copy of Chainlink is the installed background program. Open Chainlink from the USB drive instead."
        );
    }
    ui::run_settings(system, usb_dir)
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
