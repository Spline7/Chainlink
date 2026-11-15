# Chainlink

Chainlink is a small, open-source website blocker for Windows 10 and 11 that uses a USB drive as a physical key, similar to the Brick app.

- **USB unplugged:** your blocklist is enforced in Chrome, Edge, Brave, and Firefox. Private/Incognito windows, guest mode, and new browser profiles are turned off so they can't be used to get around the blocks.
- **USB plugged in:** all blocks are lifted, and you can edit the blocklist.

It's meant to add friction, not to be unbreakable. If you lose the USB, your accountability partner's recovery words let you uninstall it. Someone with admin rights and technical know-how could still remove it by hand.

**Privacy:** Chainlink makes no network requests and has no telemetry, accounts, or cloud services. The Rust source and its locked dependency graph are included in this repository.

---

## What's on the USB

```
Chainlink.cmd            <- double-click this
build-usb.cmd            <- build the executable on Windows after cloning
Chainlink\
    chainlink.exe        settings UI and watchdog (created by build-usb.cmd)
    blocklist.txt        the sites you want blocked
    chainlink.key        your secret key (created on first link, hidden, never share it)
```

## Link a PC (one time per computer)

1. Plug in the Chainlink USB.
2. Open the USB in File Explorer and double-click **Chainlink.cmd**.
   - If Windows shows "Windows protected your PC", click **More info**, then **Run anyway**.
3. Click **Yes** on the admin prompt. The Chainlink window opens.
4. Fill in the sites and channels you want blocked (see below), then click **Link this PC**.

That's it. To link another computer, such as your main desktop, repeat these steps there with the same USB.

## Test it

1. With the USB **plugged in**, open Chrome or Edge and go to `mangadex.org`. It should load normally.
2. **Unplug** the USB and wait about 10 seconds.
3. Refresh the page. It should now say the site is blocked. Opening an Incognito/InPrivate window should also be unavailable.
4. **Plug the USB back in**, wait about 10 seconds, and refresh. The site loads again.

The browser will say "Managed by your organization" while Chainlink is installed. That's expected, because Chainlink uses the browser's built-in policy settings to block sites.

Firefox only picks up changes when it restarts.

## Edit the blocklist

Plug in the USB and double-click **Chainlink.cmd**. The window has:

- **Websites to block:** one per line, such as `mangadex.org`. Blocking a site also blocks every page and subdomain on it. You can paste full links, and Chainlink tidies them up.
- **Block YouTube Shorts:** a checkbox.
- **YouTube channels to block:** one per line. Type `@ChannelName`, or paste any link to the channel, such as `https://www.youtube.com/@ChannelName/videos`.

Click **Save blocklist**, then leave the USB plugged in for about 10 seconds so the PC copies the new list. If you close the window with unsaved changes, it asks whether to save.

Entries must be ordinary HTTP or HTTPS hostnames, with an optional port and path. `*.example.com` and `example.com/*` are accepted and mean the same as `example.com`. Chainlink rejects credentials, query strings, fragments, malformed URLs, overly long entries, and blocklists above 2,048 entries instead of passing ambiguous input to browser policy.

If `blocklist.txt` on the USB has a line Chainlink cannot use (for example after a typo in Notepad), your key still unlocks the PC. The PC keeps its last good list until the file is fixed, and the Chainlink window shows the bad lines so you can correct them. Firefox reads at most 1,000 patterns, and each entry takes two to six, so very long lists are only fully enforced in Chrome, Edge, and Brave.

The list is stored in `Chainlink\blocklist.txt` on the USB, so you can also edit it in Notepad.

**Limitation:** blocking a channel's page does not block that channel's videos when they show up in your YouTube recommendations, because video links (`youtube.com/watch?v=...`) don't include the channel name. Hiding those requires a browser extension, which is a possible future addition.

## Uninstall

1. Plug in the USB and double-click **Chainlink.cmd**.
2. Click **Uninstall from this PC**, then **Yes**.

This removes the background task, every browser block, and the program folder (`C:\ProgramData\Chainlink`). Your USB keeps working for any other PCs it's linked to.

Chainlink records the browser-policy values that existed before installation, and the exact entries it writes each time it locks. Unlock and uninstall remove only those entries, restore the earlier values, and preserve unrelated blocklist entries added later; they do not simply delete the browser's whole policy tree.

### Lost or broken USB: recovery words

The first time you link a PC, Chainlink shows **6 recovery words** for that PC. Give them to an accountability partner (a friend or family member), and don't keep a copy yourself. Each PC you link gets its own set of words.

If your USB is ever lost:

1. Ask your partner for the recovery words for that PC.
2. Open the Start menu and click **Chainlink Emergency Uninstall**, then click **Yes** on the admin prompt.
3. Type each word into its box, then click **Uninstall Chainlink**.

You can't get around this without asking your partner, which is the point. A wrong guess adds a short delay before you can try again.

If your partner loses the words, plug in your USB, open Chainlink, and click **New recovery words**. The old words stop working.

## How it works

- **Linking** creates a random secret (`chainlink.key`) on the USB. The PC stores only a SHA-256 hash of that secret combined with the USB's volume serial number, so copying the key file to a different drive doesn't work.
- A **scheduled task** named `Chainlink` runs `C:\ProgramData\Chainlink\chainlink.exe --watchdog` as SYSTEM. It starts at boot, retries failures, and starts again within a minute if it is stopped.
- Every **5 seconds** the watchdog checks the connected drives for a valid key:
  - **Not found:** it writes the blocklist into the browsers' policy settings in the registry (`URLBlocklist` for Chrome/Edge/Brave, `WebsiteFilter` for Firefox). It also turns off Incognito/InPrivate, guest mode, and adding profiles. About once a minute it checks whether those settings were changed and puts them back.
  - **Found:** it removes those settings and copies `blocklist.txt` from the USB if the file changed.
- Only SYSTEM and Administrators can read or modify `C:\ProgramData\Chainlink`. Chainlink creates that folder with its final owner and permissions in one step, and refuses to reuse a folder that another account created or owns, because the program in it runs as SYSTEM.
- The Start menu entry for emergency uninstall is a copy of the same program. It asks for administrator rights itself and removes itself once the uninstall is done.
- **Recovery words** are 6 words picked at random from a built-in list of 256. New records use salted PBKDF2-HMAC-SHA256 with 300,000 rounds. Existing PowerShell recovery records remain usable until you choose **New recovery words**.
- Without a valid key, errors fail closed: an invalid key file, unreadable state, or a failed watchdog cycle leaves the blocks on, and a missing or damaged installed blocklist blocks every site until the key is plugged in again. Errors are recorded in `C:\ProgramData\Chainlink\log.txt`.
- Install, repair, and uninstall hold a lock that the watchdog also needs, so the watchdog can never re-apply blocks half way through an uninstall. Uninstall removes the scheduled task first, then lifts the blocks, then deletes the files.

## Update or repair an installation

Run `Chainlink.cmd` from the paired USB and click **Repair / update this PC**. This refreshes the installed executable and scheduled task without replacing your recovery words or the pre-install browser-policy snapshot. The first update from the original release creates that snapshot while the paired USB has the old watchdog unlocked.

## Troubleshooting

- `C:\ProgramData\Chainlink\status.txt` shows the watchdog's last lock state.
- `C:\ProgramData\Chainlink\log.txt` records state changes and errors and rotates at about 200 KB.
- If linking reports that browser policies could not be saved, Chainlink stops the install rather than risk overwriting policies it cannot restore. A first-time link that fails removes what it created, so you can simply try again.
- If the saved policy snapshot is ever lost or damaged, unlock and uninstall still work: Chainlink removes the values it manages and leaves everything else alone.
- Firefox applies policy changes only after Firefox restarts.

## Development

Install the stable MSVC Rust toolchain, then build the USB executable on Windows:

```console
build-usb.cmd
```

Cross-platform core checks and linting are:

```console
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo fmt --all -- --check
```

The test suite covers URL/channel normalization, rejection cases, legacy recovery compatibility, atomic writes, and blocklist limits/deduplication. On Windows it also runs the lock, unlock, and tamper-detection code against a scratch registry key under `HKCU`, runs the watchdog loop and the install, repair, and uninstall flows against temporary folders with Task Scheduler replaced by a recorder, reads a policy snapshot written by the PowerShell release, and (in an elevated prompt) checks the program-folder permissions. The tests never touch real browser policy, the real Chainlink folder, or real scheduled tasks. See [SECURITY.md](SECURITY.md) for the threat model and responsible-reporting guidance.

## License

MIT. See [LICENSE](LICENSE).
