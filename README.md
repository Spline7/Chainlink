# Chainlink

Chainlink is a small, open-source website blocker for Windows 10 and 11 that uses a USB drive as a physical key, similar to the Brick app.

- **USB unplugged:** your blocklist is enforced in Chrome, Edge, Brave, and Firefox. Private/Incognito windows, guest mode, and new browser profiles are turned off so they can't be used to get around the blocks.
- **USB plugged in:** all blocks are lifted, and you can edit the blocklist.

It's meant to add friction, not to be unbreakable. If you lose the USB, your accountability partner's recovery words let you uninstall it. Someone with admin rights and technical know-how could still remove it by hand.

**Privacy:** Chainlink makes no network requests and has no telemetry, accounts, or cloud services. It is plain-text PowerShell that you can read in Notepad.

---

## What's on the USB

```
Chainlink.cmd            <- double-click this
Chainlink\
    Chainlink.ps1        the Chainlink window: edit blocklist / link / uninstall
    Chainlink.Common.psm1 shared validation and cryptographic helpers
    watchdog.ps1         background checker (copied to the PC when you link it)
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

Entries must be ordinary HTTP or HTTPS hostnames, with an optional path. Chainlink rejects credentials, query strings, fragments, malformed URLs, overly long entries, and blocklists above 2,048 entries instead of passing ambiguous input to browser policy.

The list is stored in `Chainlink\blocklist.txt` on the USB, so you can also edit it in Notepad.

**Limitation:** blocking a channel's page does not block that channel's videos when they show up in your YouTube recommendations, because video links (`youtube.com/watch?v=...`) don't include the channel name. Hiding those requires a browser extension, which is a possible future addition.

## Uninstall

1. Plug in the USB and double-click **Chainlink.cmd**.
2. Click **Uninstall from this PC**, then **Yes**.

This removes the background task, every browser block, and the program folder (`C:\ProgramData\Chainlink`). Your USB keeps working for any other PCs it's linked to.

Chainlink records the browser-policy values that existed before installation. Unlock and uninstall restore those values and preserve unrelated blocklist entries added later; they do not simply delete the browser's whole policy tree.

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
- A **scheduled task** named `Chainlink` runs `C:\ProgramData\Chainlink\watchdog.ps1` as SYSTEM. It starts at boot, and Task Scheduler restarts it within a minute if it's stopped.
- Every **5 seconds** the watchdog checks the connected drives for a valid key:
  - **Not found:** it writes the blocklist into the browsers' policy settings in the registry (`URLBlocklist` for Chrome/Edge/Brave, `WebsiteFilter` for Firefox). It also turns off Incognito/InPrivate, guest mode, and adding profiles. About once a minute it checks whether those settings were changed and puts them back.
  - **Found:** it removes those settings and copies `blocklist.txt` from the USB if the file changed.
- Only SYSTEM and Administrators can modify `C:\ProgramData\Chainlink`.
- **Recovery words** are 6 words picked at random from a built-in list of 256. The PC stores only a salted, slow hash of them (PBKDF2, 100,000 rounds), never the words themselves.
- New installations use 300,000 PBKDF2 rounds and a versioned recovery record. Existing 100,000-round records remain usable until you choose **New recovery words**.
- Invalid key files, unreadable state, and watchdog-cycle errors fail closed: Chainlink tries to apply the blocklist and records the error in `C:\ProgramData\Chainlink\log.txt`.

## Update or repair an installation

Run `Chainlink.cmd` from the paired USB and click **Repair / update this PC**. This refreshes the installed scripts and scheduled task without replacing your recovery words or the pre-install browser-policy snapshot. The first update from the original release creates that snapshot while the paired USB has the old watchdog unlocked.

## Troubleshooting

- `C:\ProgramData\Chainlink\status.txt` shows the watchdog's last lock state.
- `C:\ProgramData\Chainlink\log.txt` records state changes and errors and rotates at about 200 KB.
- If linking reports that browser policies could not be saved, Chainlink stops the install rather than risk overwriting policies it cannot restore.
- Firefox applies policy changes only after Firefox restarts.

## Development

The production scripts support Windows PowerShell 5.1 (the version included with Windows 10 and 11). Run the dependency-free checks from a PowerShell prompt:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\PowerShell.Tests.ps1
```

The tests parse every PowerShell file and exercise URL/channel normalization, rejection cases, hashing, constant-time comparison, atomic writes, and blocklist limits/deduplication. See [SECURITY.md](SECURITY.md) for the threat model and responsible-reporting guidance.

## License

MIT. See [LICENSE](LICENSE).
