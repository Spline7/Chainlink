use anyhow::Result;
use chainlink_blocker::core::{
    SHORTS_ENTRY, atomic_write, normalize_channel, normalize_entry, read_blocklist,
};
use chainlink_blocker::windows;
use native_windows_gui as nwg;
use std::path::PathBuf;
use std::rc::Rc;

fn confirm(parent: &nwg::Window, content: &str) -> bool {
    nwg::modal_message(
        parent,
        &nwg::MessageParams {
            title: "Chainlink",
            content,
            buttons: nwg::MessageButtons::YesNo,
            icons: nwg::MessageIcons::Question,
        },
    ) == nwg::MessageChoice::Yes
}

fn show_error(parent: &nwg::Window, context: &str, error: &anyhow::Error) {
    nwg::modal_error_message(parent, "Chainlink", &format!("{context}:\r\n{error:#}"));
}

fn show_words(parent: &nwg::Window, words: &[String]) {
    nwg::modal_info_message(
        parent,
        "Chainlink - recovery words",
        &format!(
            "Give these words to your accountability partner. They will not be shown again.\r\n\r\n{}",
            words
                .iter()
                .enumerate()
                .map(|(index, word)| format!("{}. {word}", index + 1))
                .collect::<Vec<_>>()
                .join("    ")
        ),
    );
}

struct SettingsApp {
    usb_dir: PathBuf,
    window: nwg::Window,
    title: nwg::Label,
    status: nwg::Label,
    sites_label: nwg::Label,
    sites: nwg::TextBox,
    shorts: nwg::CheckBox,
    channels_label: nwg::Label,
    channels: nwg::TextBox,
    save: nwg::Button,
    link: nwg::Button,
    uninstall: nwg::Button,
    words: nwg::Button,
}

impl SettingsApp {
    fn build(usb_dir: PathBuf) -> Result<Rc<Self>> {
        let mut app = Self {
            usb_dir,
            window: Default::default(),
            title: Default::default(),
            status: Default::default(),
            sites_label: Default::default(),
            sites: Default::default(),
            shorts: Default::default(),
            channels_label: Default::default(),
            channels: Default::default(),
            save: Default::default(),
            link: Default::default(),
            uninstall: Default::default(),
            words: Default::default(),
        };
        nwg::Window::builder()
            .size((640, 720))
            .position((260, 100))
            .title("Chainlink")
            .build(&mut app.window)?;
        nwg::Label::builder()
            .text("Chainlink")
            .position((20, 14))
            .size((590, 32))
            .parent(&app.window)
            .build(&mut app.title)?;
        nwg::Label::builder()
            .text("")
            .position((20, 48))
            .size((590, 24))
            .parent(&app.window)
            .build(&mut app.status)?;
        nwg::Label::builder()
            .text("Websites to block - one per line")
            .position((20, 82))
            .size((590, 22))
            .parent(&app.window)
            .build(&mut app.sites_label)?;
        nwg::TextBox::builder()
            .text("")
            .position((20, 106))
            .size((590, 210))
            .limit(200_000)
            .parent(&app.window)
            .build(&mut app.sites)?;
        nwg::CheckBox::builder()
            .text("Block YouTube Shorts")
            .position((20, 326))
            .size((250, 28))
            .parent(&app.window)
            .build(&mut app.shorts)?;
        nwg::Label::builder()
            .text("YouTube channels - @Name or a channel URL")
            .position((20, 362))
            .size((590, 22))
            .parent(&app.window)
            .build(&mut app.channels_label)?;
        nwg::TextBox::builder()
            .text("")
            .position((20, 386))
            .size((590, 205))
            .limit(200_000)
            .parent(&app.window)
            .build(&mut app.channels)?;
        nwg::Button::builder()
            .text("Save blocklist")
            .position((20, 610))
            .size((125, 34))
            .parent(&app.window)
            .build(&mut app.save)?;
        nwg::Button::builder()
            .text("Link this PC")
            .position((153, 610))
            .size((150, 34))
            .parent(&app.window)
            .build(&mut app.link)?;
        nwg::Button::builder()
            .text("Uninstall")
            .position((311, 610))
            .size((110, 34))
            .parent(&app.window)
            .build(&mut app.uninstall)?;
        nwg::Button::builder()
            .text("New recovery words")
            .position((429, 610))
            .size((181, 34))
            .parent(&app.window)
            .build(&mut app.words)?;
        let app = Rc::new(app);
        app.load()?;
        app.update_status();
        Ok(app)
    }

    fn source_blocklist(&self) -> PathBuf {
        self.usb_dir.join("blocklist.txt")
    }

    fn load(&self) -> Result<()> {
        let entries = read_blocklist(&self.source_blocklist())?;
        let mut sites = Vec::new();
        let mut channels = Vec::new();
        let mut shorts = false;
        for entry in entries {
            if entry.eq_ignore_ascii_case(SHORTS_ENTRY) {
                shorts = true;
            } else if [
                "youtube.com/@",
                "youtube.com/channel/",
                "youtube.com/c/",
                "youtube.com/user/",
            ]
            .iter()
            .any(|prefix| entry.starts_with(prefix))
            {
                channels.push(entry.trim_start_matches("youtube.com/").to_owned());
            } else {
                sites.push(entry);
            }
        }
        self.sites.set_text(&sites.join("\r\n"));
        self.channels.set_text(&channels.join("\r\n"));
        self.shorts.set_check_state(if shorts {
            nwg::CheckBoxState::Checked
        } else {
            nwg::CheckBoxState::Unchecked
        });
        Ok(())
    }

    fn save_blocklist(&self) -> Result<()> {
        let mut sites = Vec::new();
        for line in self
            .sites
            .text()
            .lines()
            .filter(|line| !line.trim().is_empty())
        {
            let entry = normalize_entry(line)?;
            if !sites.contains(&entry) {
                sites.push(entry);
            }
        }
        let mut channels = Vec::new();
        for line in self
            .channels
            .text()
            .lines()
            .filter(|line| !line.trim().is_empty())
        {
            let entry = normalize_channel(line)?;
            if !channels.contains(&entry) {
                channels.push(entry);
            }
        }
        let mut lines = vec![
            "# Chainlink blocklist - one entry per line.",
            "# Lines starting with # are ignored.",
            "",
            "# Websites",
        ]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
        lines.extend(sites);
        lines.extend(["".to_owned(), "# YouTube".to_owned()]);
        if self.shorts.check_state() == nwg::CheckBoxState::Checked {
            lines.push(SHORTS_ENTRY.to_owned());
        }
        lines.extend(channels);
        atomic_write(
            &self.source_blocklist(),
            format!("{}\n", lines.join("\n")).as_bytes(),
        )?;
        self.load()
    }

    fn update_status(&self) {
        let installed = windows::genuine_task() || windows::installed_exe().is_file();
        if !installed {
            self.status
                .set_text("This PC is not linked. Click Link this PC to start.");
            self.link.set_text("Link this PC");
            self.link.set_enabled(true);
            self.uninstall.set_enabled(false);
            self.words.set_enabled(false);
        } else if windows::usb_matches_pc(&self.usb_dir) {
            self.status
                .set_text("This PC is linked to this USB. Blocks are off while it is plugged in.");
            self.link.set_text("Repair / update this PC");
            self.link.set_enabled(true);
            self.uninstall.set_enabled(true);
            self.words.set_enabled(true);
        } else {
            self.status
                .set_text("This PC is linked to a different USB key.");
            self.link.set_text("Link this PC");
            self.link.set_enabled(false);
            self.uninstall.set_enabled(false);
            self.words.set_enabled(false);
        }
    }

    fn save_clicked(&self) {
        match self.save_blocklist() {
            Ok(()) => {
                nwg::modal_info_message(&self.window, "Chainlink", "Blocklist saved.");
            }
            Err(error) => show_error(&self.window, "Could not save the blocklist", &error),
        }
    }

    fn link_clicked(&self) {
        if let Err(error) = self.save_blocklist() {
            show_error(&self.window, "Could not save the blocklist", &error);
            return;
        }
        match windows::install(&self.usb_dir) {
            Ok(words) => {
                self.update_status();
                if let Some(words) = words {
                    show_words(&self.window, &words);
                }
                nwg::modal_info_message(
                    &self.window,
                    "Chainlink",
                    "This PC is linked. Unplug the USB and wait about 10 seconds to test it.",
                );
            }
            Err(error) => show_error(&self.window, "Linking failed", &error),
        }
    }

    fn uninstall_clicked(&self) {
        if !confirm(
            &self.window,
            "Remove Chainlink and restore prior browser policy?",
        ) {
            return;
        }
        match windows::uninstall() {
            Ok(()) => {
                self.update_status();
                nwg::modal_info_message(&self.window, "Chainlink", "Chainlink has been removed.");
            }
            Err(error) => show_error(&self.window, "Uninstall failed", &error),
        }
    }

    fn words_clicked(&self) {
        if !confirm(&self.window, "Replace the current recovery words?") {
            return;
        }
        match windows::replace_recovery_words() {
            Ok(words) => show_words(&self.window, &words),
            Err(error) => show_error(&self.window, "Could not replace recovery words", &error),
        }
    }
}

pub fn run_settings(usb_dir: PathBuf) -> Result<()> {
    nwg::init()?;
    nwg::Font::set_global_family("Segoe UI")?;
    let app = SettingsApp::build(usb_dir)?;
    let events = Rc::clone(&app);
    let handler = nwg::full_bind_event_handler(&app.window.handle, move |event, _, handle| {
        if event == nwg::Event::OnWindowClose && handle == events.window.handle {
            nwg::stop_thread_dispatch();
        } else if event == nwg::Event::OnButtonClick {
            if handle == events.save.handle {
                events.save_clicked();
            } else if handle == events.link.handle {
                events.link_clicked();
            } else if handle == events.uninstall.handle {
                events.uninstall_clicked();
            } else if handle == events.words.handle {
                events.words_clicked();
            }
        }
    });
    nwg::dispatch_thread_events();
    nwg::unbind_event_handler(&handler);
    Ok(())
}

struct EmergencyApp {
    window: nwg::Window,
    title: nwg::Label,
    hint: nwg::Label,
    inputs: [nwg::TextInput; 6],
    status: nwg::Label,
    uninstall: nwg::Button,
    cancel: nwg::Button,
}

impl EmergencyApp {
    fn build() -> Result<Rc<Self>> {
        let mut app = Self {
            window: Default::default(),
            title: Default::default(),
            hint: Default::default(),
            inputs: std::array::from_fn(|_| Default::default()),
            status: Default::default(),
            uninstall: Default::default(),
            cancel: Default::default(),
        };
        nwg::Window::builder()
            .size((510, 300))
            .position((320, 180))
            .title("Chainlink - emergency uninstall")
            .build(&mut app.window)?;
        nwg::Label::builder()
            .text("Emergency uninstall")
            .position((20, 16))
            .size((460, 28))
            .parent(&app.window)
            .build(&mut app.title)?;
        nwg::Label::builder().text("Ask your accountability partner for the six recovery words and enter them in order.").position((20, 48)).size((460, 36)).parent(&app.window).build(&mut app.hint)?;
        for (index, input) in app.inputs.iter_mut().enumerate() {
            nwg::TextInput::builder()
                .position((20 + (index % 2) as i32 * 240, 92 + (index / 2) as i32 * 38))
                .size((220, 30))
                .parent(&app.window)
                .build(input)?;
        }
        nwg::Label::builder()
            .text("")
            .position((20, 210))
            .size((460, 24))
            .parent(&app.window)
            .build(&mut app.status)?;
        nwg::Button::builder()
            .text("Uninstall Chainlink")
            .position((20, 240))
            .size((180, 34))
            .parent(&app.window)
            .build(&mut app.uninstall)?;
        nwg::Button::builder()
            .text("Cancel")
            .position((210, 240))
            .size((100, 34))
            .parent(&app.window)
            .build(&mut app.cancel)?;
        Ok(Rc::new(app))
    }

    fn attempt(&self) {
        let delay = windows::recovery_delay();
        if delay > 0 {
            self.status
                .set_text(&format!("Please wait {delay} seconds before trying again."));
            return;
        }
        let words = self
            .inputs
            .iter()
            .map(nwg::TextInput::text)
            .map(|word| word.trim().to_owned())
            .collect::<Vec<_>>();
        if words.iter().any(String::is_empty) {
            self.status.set_text("Please fill in all six words.");
            return;
        }
        if !windows::verify_recovery(&words) {
            let _ = windows::register_recovery_failure();
            self.status
                .set_text("Those words do not match. Check spelling and order.");
            return;
        }
        if !confirm(
            &self.window,
            "Recovery words accepted. Remove Chainlink from this PC?",
        ) {
            return;
        }
        windows::clear_recovery_failures();
        match windows::uninstall() {
            Ok(()) => {
                nwg::modal_info_message(&self.window, "Chainlink", "Chainlink has been removed.");
                nwg::stop_thread_dispatch();
            }
            Err(error) => show_error(&self.window, "Uninstall failed", &error),
        }
    }
}

pub fn run_emergency() -> Result<()> {
    if !windows::recovery_file().is_file() {
        anyhow::bail!(
            "this installation has no recovery words; repair it with the paired USB first"
        );
    }
    nwg::init()?;
    nwg::Font::set_global_family("Segoe UI")?;
    let app = EmergencyApp::build()?;
    let events = Rc::clone(&app);
    let handler = nwg::full_bind_event_handler(&app.window.handle, move |event, _, handle| {
        if event == nwg::Event::OnWindowClose && handle == events.window.handle
            || event == nwg::Event::OnButtonClick && handle == events.cancel.handle
        {
            nwg::stop_thread_dispatch();
        } else if event == nwg::Event::OnButtonClick && handle == events.uninstall.handle {
            events.attempt();
        }
    });
    nwg::dispatch_thread_events();
    nwg::unbind_event_handler(&handler);
    Ok(())
}
