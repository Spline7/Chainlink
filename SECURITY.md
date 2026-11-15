# Chainlink security model

## Goal

Chainlink is an accountability aid. With the paired USB absent, it should reliably apply the configured browser policies and make casual bypasses inconvenient. With the USB present, it should remove only the restrictions it owns. Uninstall should restore browser policy that existed before Chainlink was installed.

## Trust boundaries

- The executable/source on the paired USB and the person who controls that USB are trusted.
- `C:\ProgramData\Chainlink` is writable only by SYSTEM and Administrators after installation.
- The watchdog and scheduled task run as SYSTEM because machine-wide browser policy requires elevation.
- Browser policy, Task Scheduler, the Windows registry, volume serial numbers, and Windows cryptography are trusted operating-system services.
- Blocklist text is untrusted input and is validated before it reaches browser policy.

## Deliberate limitations

Chainlink is not protection against a local Administrator. An Administrator can disable the task, alter installed files or policy, attach a debugger, or uninstall software manually. A user can also use an unsupported browser, another machine, a VM, a proxy that changes URL handling, or boot another operating system. The USB volume serial is an anti-copying speed bump, not a hardware-backed identity.

The six recovery words contain 48 bits of random entropy. Their stored verifier uses PBKDF2 and failed attempts have a persisted, increasing delay, but an Administrator who copies or changes protected state remains outside the threat model.

## Defensive behavior

- A missing, malformed, or unreadable USB key never unlocks the machine.
- The watchdog validates a blocklist before installing it and attempts to fail closed after errors.
- Writes to mutable state use a temporary file and rename where practical.
- Install refuses a program directory that is a file, junction, or symbolic link.
- A policy baseline is captured before Chainlink applies policy. Unlock and uninstall merge that baseline with unrelated entries rather than deleting complete policy trees.
- Recovery verifiers are salted and compared without an early-exit byte comparison. Recovery words are never written to disk.
- The per-USB key is excluded from version control.

## Reporting a vulnerability

Please report suspected vulnerabilities privately to the repository owner instead of opening a public issue with exploit details. Include the affected version or commit, Windows version, reproduction steps, impact, and any suggested mitigation. Do not include a real `chainlink.key`, recovery phrase, or other secret in a report.
