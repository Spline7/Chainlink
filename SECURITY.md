# Chainlink security model

## Goal

Chainlink is an accountability aid. With the paired USB absent, it should reliably apply the configured browser policies and make casual bypasses inconvenient. With the USB present, it should remove only the restrictions it owns. Uninstall should restore browser policy that existed before Chainlink was installed.

## Trust boundaries

- The executable/source on the paired USB and the person who controls that USB are trusted.
- `C:\ProgramData\Chainlink` is readable and writable only by SYSTEM and Administrators. It is created with that owner and ACL atomically; a pre-existing folder is reused only if it belongs to a genuine installation, is owned by SYSTEM or Administrators, and contains nothing owned by anyone else.
- The watchdog and scheduled task run as SYSTEM because machine-wide browser policy requires elevation.
- Browser policy, Task Scheduler, the Windows registry, volume serial numbers, and Windows cryptography are trusted operating-system services.
- Blocklist text is untrusted input and is validated before it reaches browser policy.

## Deliberate limitations

Chainlink is not protection against a local Administrator. An Administrator can disable the task, alter installed files or policy, attach a debugger, or uninstall software manually. A user can also use an unsupported browser, another machine, a VM, a proxy that changes URL handling, or boot another operating system. The USB volume serial is an anti-copying speed bump, not a hardware-backed identity.

The six recovery words contain 48 bits of random entropy. Their stored verifier uses PBKDF2 and failed attempts have a persisted, increasing delay, but an Administrator who copies or changes protected state remains outside the threat model.

## Defensive behavior

- A missing, malformed, or unreadable USB key never unlocks the machine.
- With no valid key present, errors fail closed. A missing or corrupt installed blocklist blocks every URL.
- With a valid key present, a bad `blocklist.txt` on the USB does not lock the machine. The watchdog keeps the last good list, copies the USB file before validating it so the bytes it checks are the bytes it installs, and reports the problem in `status.txt` and `log.txt`.
- Writes to mutable state go to a temporary file that then replaces the original in one step.
- Install refuses a program directory that is a file, junction, or symbolic link, that already holds files without a genuine Chainlink task, or that is owned by another account. A new directory is created with its owner and protected ACL in a single call, so there is no window in which another account can plant files that would later run as SYSTEM.
- A scheduled task named `Chainlink` is treated as Chainlink's only if it runs as SYSTEM and its action is exactly the installed watchdog. Uninstall also removes a same-named task whose action points into the Chainlink directory, so it never leaves a SYSTEM task aimed at a path it has just deleted.
- The watchdog holds an exclusive lock file inside the protected directory. Install, repair, and uninstall take the same lock before changing anything, which proves no watchdog is running and keeps a new one from starting. The lock cannot be held by a non-administrator, unlike a named kernel object.
- Uninstall removes the scheduled task before lifting the blocks, so the once-a-minute trigger cannot restart the watchdog and re-apply them. Before it releases the lock it writes a marker; a watchdog that was already starting checks for the marker once it holds the lock and exits. A failed first-time link deletes the program folder only after its task is confirmed gone.
- Uninstall and repair refuse to read state from, or run anything in, a program folder that a non-administrator could have written.
- A policy baseline is captured before Chainlink applies policy, and each lock records the entries it wrote. Unlock and uninstall remove exactly those entries and merge the baseline with unrelated entries rather than deleting complete policy trees. If the baseline is unreadable, Chainlink removes only the values it manages.
- Recovery verifiers are salted and compared without an early-exit byte comparison. Recovery words are never written to disk.
- The executable has no command-line modes beyond the watchdog and emergency uninstall, and the installed copy refuses to act as the settings window. Running as the watchdog it never shows a message box, which nobody could dismiss in the SYSTEM session.
- The per-USB key is excluded from version control.

## Reporting a vulnerability

Please report suspected vulnerabilities privately to the repository owner instead of opening a public issue with exploit details. Include the affected version or commit, Windows version, reproduction steps, impact, and any suggested mitigation. Do not include a real `chainlink.key`, recovery phrase, or other secret in a report.
