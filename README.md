# Chainlink

Chainlink is a small, open-source website blocker for Windows 10 and 11 that uses a USB drive as a physical key, similar to the Brick app.

- **USB unplugged:** your blocklist is enforced in Chrome, Edge, Brave, and Firefox. Private/Incognito windows, guest mode, and new browser profiles are turned off so they can't be used to get around the blocks.
- **USB plugged in:** all blocks are lifted, and you can edit the blocklist.

It's meant to add friction, not to be unbreakable. Anyone with admin rights who knows what they're doing can remove it.

**Privacy:** Chainlink makes no network requests and has no telemetry, accounts, or cloud services. It is three plain-text scripts that you can read in Notepad.

---

## What's on the USB

```
Chainlink.cmd            <- double-click this
Chainlink\
    Chainlink.ps1        the Chainlink window: edit blocklist / link / uninstall
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

The list is stored in `Chainlink\blocklist.txt` on the USB, so you can also edit it in Notepad.

**Limitation:** blocking a channel's page does not block that channel's videos when they show up in your YouTube recommendations, because video links (`youtube.com/watch?v=...`) don't include the channel name. Hiding those requires a browser extension, which is a possible future addition.

## Uninstall

1. Plug in the USB and double-click **Chainlink.cmd**.
2. Click **Uninstall from this PC**, then **Yes**.

This removes the background task, every browser block, and the program folder (`C:\ProgramData\Chainlink`). Your USB keeps working for any other PCs it's linked to.

### Lost or broken USB

1. Download this project from GitHub (Code -> Download ZIP) and unzip it.
2. Open the Start menu, type **PowerShell**, right-click it, and choose **Run as administrator**.
3. Run (adjust the path to where you unzipped it):
   ```
   powershell -ExecutionPolicy Bypass -File "C:\Users\YOU\Downloads\Chainlink\Chainlink\Chainlink.ps1" -Emergency
   ```
4. Type `UNINSTALL` when asked.

## How it works

- **Linking** creates a random secret (`chainlink.key`) on the USB. The PC stores only a SHA-256 hash of that secret combined with the USB's volume serial number, so copying the key file to a different drive doesn't work.
- A **scheduled task** named `Chainlink` runs `C:\ProgramData\Chainlink\watchdog.ps1` as SYSTEM. It starts at boot, and Task Scheduler restarts it within a minute if it's stopped.
- Every **5 seconds** the watchdog checks the connected drives for a valid key:
  - **Not found:** it writes the blocklist into the browsers' policy settings in the registry (`URLBlocklist` for Chrome/Edge/Brave, `WebsiteFilter` for Firefox). It also turns off Incognito/InPrivate, guest mode, and adding profiles. About once a minute it checks whether those settings were changed and puts them back.
  - **Found:** it removes those settings and copies `blocklist.txt` from the USB if the file changed.
- Only SYSTEM and Administrators can modify `C:\ProgramData\Chainlink`.

## License

MIT. See [LICENSE](LICENSE).
