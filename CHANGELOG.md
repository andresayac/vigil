# Changelog

Each release's full notes are on the repository's Releases page.

## 2.6.0 — 2026-11-22

- Security release: nothing a standard user's program controls runs with administrator rights. Settings links,
  browser pages, per-user uninstallers and Run new task without "as administrator" run as the user through
  Explorer; local AI agents are not used while Vigil is elevated.
- Scan scripts go to PowerShell directly instead of through a temporary folder; PowerShell loads only Windows'
  modules; system folders come from Windows itself, not from environment variables.
- The portable vigil.exe needs no runtime DLL, loads system DLLs from System32 only, and warns before running as
  administrator from a folder other programs can change.
- The data folder is created with administrator-only permissions; one other programs could change is moved aside
  and a clean one started. Quarantine restore never follows links; the watch keeps administrator-only data in it.

## 2.5.0 — 2026-11-22

- The scan and the safety checks never open network paths: a startup entry, task or service pointing to
  `\\server\share\…`, a device path or a mapped network drive is judged without contacting that server.
- Every parser of data from the computer is tested against random and damaged input (policies, PE files, XML,
  registry values, reports, MCP messages, exports): no crash, hang or unbounded memory.
- Every page and dialog of the window is started in all five languages, light and dark, on each change, with
  its controls checked for screen-reader names. Text boxes that had only a placeholder now have a name.

## 2.4.0 — 2026-11-22

- Vulnerable drivers: every driver is checked offline against Microsoft's vulnerable driver blocklist that Windows
  keeps, hashed the way Windows does; the background watch alerts when a listed driver appears. The list is used
  only when its signature verifies offline up to Microsoft; otherwise it is reported and accuses no driver.
- Release links offered by the update check must be the exact release page of the new version.
- The Windows folder Vigil trusts comes from Windows itself, never from environment variables a user can change.
- A short welcome on first start (More → Welcome opens it again).
- An optional daily check for new versions, off by default; it only asks GitHub for this project's latest release
  and never downloads or installs anything.
- Translations reviewed in Spanish, French, Brazilian Portuguese and Chinese; placeholders are now checked.

## 2.3.0 — 2026-11-22

- Ctrl+K search: jump to any page or open a process, finding, alert, service, task, program, rule or extension.
- Battery and sleep page: battery health, what keeps the computer awake, what woke it, wake timers, power plan.
- Restore points page: list, create with a description, open System Restore and System Protection.
- Duplicate files in Storage: compared by content; copies go to the Recycle Bin, one copy always stays.
- Command bars fit any window width and language.
- Safer: the signature cache depends on file content and is kept only by the elevated copy; deletions check each
  file's real path and never delete permanently; the watch reports persistence that comes back after removal.

## 2.2.0 — 2026-11-22

- Windows Update page, read from what Windows recorded (never searched online).
- Startup impact (High / Medium / Low) on Startup apps, from Windows' own measurements.
- Explorer shell extensions in the scan.
- Safer: reports from folders any program can change open read-only; every confirmation is shown by the core;
  History undo asks first; single instance and elevation hand over cleanly; invisible and right-to-left characters
  are shown visibly.

## 2.1.0 — 2026-11-22

- Export findings as CSV or SARIF 2.1.0, from Findings or with `vigil export` and `vigil scan --format`.
- A signature cache makes repeat scans about twice as fast.
- BITS jobs that run a program are judged in the scan and watched.
- The background watch no longer reports an item that briefly disappears as new.

## 2.0.0 — 2026-11-22

- A native Windows interface: one process, about a third of the memory, faster start, nothing else to install.
- Accessibility: every control has a name for screen readers; charts and the treemap are readable.
- A new installer, always in Program Files, tested in CI by installing, upgrading and uninstalling.

## 1.9.0 — 2026-11-22

- Suspicious root certificates, AMSI providers and PowerShell logging, network tampering (DNS, DNS over HTTPS,
  proxy, WPAD, routes, tunnel adapters).
- Four new read-only AI tools: scan summary, related findings, a program's events, a file's history.
- Safer: secrets masked in every excerpt, local AI agents stopped as a whole process tree and given the same
  budget, a sturdier MCP server, wider anonymization.

## 1.8.0 — 2026-11-22

- Automatic daily or weekly scans (local rules only), notifying only what is new.
- Secrets left in the clear: only where they are and what kind, never their value.
- Per-user COM hijacking and remote access agents.

## 1.7.0 — 2026-11-22

- Hidden services and scheduled tasks, weak service permissions (real ACLs and unquoted paths).
- PowerShell profiles and Office persistence.
- Firewall rules and recent firewall changes in the scan.

## 1.6.0 — 2026-11-22

- Investigate with AI: the agent you chose looks into a finding with read-only tools.
- `vigil mcp`: an MCP server with read-only tools for AI clients.
- New detections: UAC bypasses, the sign-in screen backdoor, DLLs registered in Windows hooks, one-value tricks,
  defense evasion.
- The background watch follows drivers, registry hooks, the hosts file and key Windows events.
- A new icon.

## 1.5.0 — 2026-11-22

- Security posture page with a score and changes that only raise security.
- Accounts and sign-ins page: accounts, administrators, sessions, failed sign-ins and password guessing.
- Browser extensions page, with the browser policies adware uses.
- Background watch fixes: no alert flood at sign-in, a sturdier saved state, more changes noticed.

## 1.4.0 — 2026-11-22

- Protection page for Microsoft Defender: state, scans with progress, threat history, risky exclusions.
- Installed programs page: uninstall, and remove leftover entries with undo.
- Reliability page: blue screens, crashes, hangs, hardware and disk errors, failed updates.

## 1.3.0 — 2026-11-22

- Background watch from the tray, with alerts, notifications and start at sign-in.
- Scheduled tasks page and Firewall rules page, with undoable changes.

## 1.2.0 — 2026-11-21

- What changed since the last scan.
- Startup apps page.
- Processes: End task for whole apps, Store apps under their real process, processor affinity, Run new task.

## 1.1.0 — 2026-11-21

- Processes grouped like Task Manager, with a heat map and Grouped, Tree and List views.
- Services page with undoable changes.
- `vigil list`, `vigil ports` and `vigil services`.

## 1.0.0 — 2026-11-21

- Security scan of processes, services, drivers, tasks, startup entries, programs, extensions, network and event
  logs, judged by local rules, with an optional review by the AI agent you choose.
- Actions you confirm and can undo; live performance; maintenance; English, Spanish, French, Portuguese and Chinese.
