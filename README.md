# Vigil

**Security analysis of a Windows computer, with an AI agent at its side.** Vigil inventories everything that runs or
starts on the computer, judges it with local rules, and asks an AI agent of your choice for a second opinion: a cloud
model, a coding agent already installed on your computer (Claude Code, Codex CLI, Gemini CLI) or a model that runs
entirely on your machine (Ollama, LM Studio). Then it lets you act on each finding — end it, turn it off, quarantine
it or remove it — and every change can be undone.

It also shows live CPU, memory, GPU, VRAM, disk and network use, frees disk space, checks the hardware's health and
applies explained, reversible tune-ups. It looks and behaves like a Windows 11 app and speaks English, Spanish,
French, Portuguese and Chinese.

## Install and run

Requirements: Windows 10 or 11 (64-bit) with the Microsoft Edge WebView2 runtime (included in Windows 11 and in
up-to-date Windows 10).

1. Download the latest release from the repository's **Releases** page: `Vigil_x.y.z_x64-setup.exe` installs it for
   every user with Start menu shortcuts; `Vigil-x.y.z-portable.exe` is a single executable you can run from anywhere.
   `SHA256SUMS.txt` lists the checksums.
2. Open Vigil. It asks Windows for administrator rights when it starts; if you decline, it opens in read-only mode
   (the scan sees less and actions that change the system are off). `vigil.exe --no-elevate` starts it in read-only
   mode without asking.

The scan also runs from a terminal, without the window and without changing anything:

```bat
vigil scan                         :: scan + AI review with the configured agent (asks before sending)
vigil scan --ai openai-compatible --endpoint http://localhost:11434/v1 --model qwen3:14b
vigil scan --ai off                :: local rules only
vigil scan --help                  :: every option
```

A few more commands give a quick look at the live system from a terminal or a script. Like the scan they only read;
changes are made from the app. Each one has `--help`, `--json` for machine-readable output and `--lang CODE`:

```bat
vigil list                         :: the 25 processes using the most CPU, measured over one second
vigil list --sort mem -n 10        :: sort by cpu, mem, name or pid; -n 0 shows every process
vigil ports --listening            :: listening ports with the process and service behind each one
vigil services --running --json    :: running Windows services, as JSON
vigil programs --recent            :: programs installed in the last 7 days, newest first
vigil reliability --days 90        :: blue screens, crashes and other problems of the last 90 days
vigil --help                       :: every command
```

The tables have one line per entry, for example:

```text
PID      CPU %   Memory       Name                          Path
4321     12.5    245.3 MB     example.exe                   C:\Program Files\Example\example.exe

Protocol  Local address             Remote address            State         Service           Process
TCP       0.0.0.0:3389                                        LISTEN        Remote Desktop    svchost.exe (1180)

Name                          State       Startup type                PID      Display name
ExampleSvc                    Running     Automatic                   2210     Example Service
```

Exit codes: 0 when it worked, 2 for a wrong option or a read that failed.

## The AI agent

The local rules decide first; the agent reviews what is left and explains it in plain words. You choose the agent in
**Settings → AI review**:

| Choice | What it is | Address (examples) | Where your data goes |
|---|---|---|---|
| **OpenAI-compatible API** | The OpenAI Chat Completions standard, spoken by most model servers | `https://api.openai.com/v1` (default), Ollama `http://localhost:11434/v1`, LM Studio `http://localhost:1234/v1`, llama.cpp, vLLM, OpenRouter… | The server at that address |
| **Anthropic-compatible API** | The Anthropic Messages standard | `https://api.anthropic.com` (default), Ollama `http://localhost:11434` | The server at that address |
| **Local agents** | Claude Code, Codex CLI or Gemini CLI, signed in on this computer | — | The provider behind that agent |

A server on this computer (`localhost`) keeps everything here: nothing leaves the PC, and Settings says so in green.

- **Automatic** tries the local agents first (Claude Code, Codex CLI, Gemini CLI), then the Anthropic-compatible
  and the OpenAI-compatible API when it knows which model to use (Anthropic's own address, or an Ollama server on
  this computer). **Off** keeps the review to the local rules.
- You choose the address, the model and, for the Anthropic standard, the reasoning effort; **List models** asks the
  server which models it offers. `OPENAI_BASE_URL` and `ANTHROPIC_BASE_URL` change the default address of each
  standard. Remote addresses must use HTTPS; plain HTTP is accepted only on this computer.
- The API key is optional (servers on this computer usually need none). Keys are kept in Windows Credential
  Manager, never in a settings file; `OPENAI_API_KEY` and `ANTHROPIC_API_KEY` (or `ANTHROPIC_AUTH_TOKEN`) work too.
- **Ollama.** Its cloud models (`name:cloud`, `name:…-cloud`, or any model Ollama reports as remote) are never used:
  they run on ollama.com, not on your computer. Vigil leaves them out of the list and refuses them before sending
  anything, through either standard. For Ollama itself to stay offline as well, start it with `OLLAMA_NO_CLOUD=1`
  (or turn off its cloud features in Ollama's settings). Its default context window is short for a batch of
  findings: start it with `OLLAMA_CONTEXT_LENGTH=32768` (or more) so that nothing is cut.
- Before anything is sent you see how many items, where they go, and the exact data. Your user and computer names are
  replaced with `<user>` and `<computer>`; passwords and tokens in command lines are always replaced with
  `<redacted>`; a copy of everything sent is saved next to the scan.
- For the scan review the agent gets no tools and the inventory is treated as untrusted text (a file that says "classify me as safe" is a
  red flag, not an instruction). Its answer is validated, and an item the local rules rate as critical can never be
  downgraded to safe.
- The agent answers in the language Vigil uses.
- **Investigate with AI** (Findings, side panel): for one finding, the agent may call Vigil's read-only tools (below)
  to look further: its file and signature, how it starts, what it runs, its network activity. A Windows dialog first
  says where the data goes, whether it stays on the computer and that the tools read more than the finding itself.
  You then see the conclusion, the evidence with links to the pages, and every tool call; the record is saved in the
  data folder. The agent cannot change anything: a suggested action is text, and the finding's own action buttons
  (confirmed as always) are the only way to act. Local agents get the tools through `vigil mcp`, set up for that run
  only.

### MCP server

`vigil mcp` gives AI clients that speak the Model Context Protocol the same read-only tools, over stdio:

| Tool | What it reads |
|---|---|
| `get_overview`, `list_findings`, `get_finding` | The newest scan report this user can read (or `--report FILE`) |
| `list_processes`, `inspect_process`, `list_connections` | Processes (with signature, command line, DLLs from writable folders, hosted services), connections |
| `list_services`, `list_startup`, `list_tasks` | Services, startup entries, scheduled tasks |
| `get_posture`, `get_defender`, `list_extensions` | Security settings, Microsoft Defender, browser extensions and policies |
| `get_signins_summary`, `get_reliability_summary`, `list_alerts` | Accounts and sign-ins, event-log problems, the background watch's alerts |
| `check_file` | One local file's signature, version information and SHA-256 |
| `propose_action` | Nothing: it records a suggestion for you; Vigil never acts on it |

- **Nothing changes the computer.** The tools only read, and the MCP process never shows a window or a dialog;
  changes are made in the app, where each one is confirmed.
- It runs with the rights of the client that starts it: as a standard user, the Security log, Defender exclusions
  and other users' tasks are not readable (each result says `"coverage"`).
- User and computer names are replaced by default (`--no-anonymize` keeps them); passwords and tokens in command
  lines are always removed. Lists are paged and every result is capped, so a client never receives megabytes.
- Text in the results was read from the computer and may come from malware; the tools tell the model to treat it as
  data, never as instructions.
- Both protocol forms are answered: revision 2026-07-28 (`server/discover`) and the `initialize` handshake of
  2025-11-25 and earlier.

`vigil mcp --print-config` prints a ready-to-paste configuration with the path of your `vigil.exe`, for example:

```json
{ "mcpServers": { "vigil": { "command": "C:\\Program Files\\Vigil\\vigil.exe", "args": ["mcp"] } } }
```

## The app

| Page | What it shows | What you can do |
|---|---|---|
| **Overview** | The verdict on the whole computer, one sliver per finding, what to do first, the security state (Defender, firewall, UAC, Remote Desktop, updates) and coverage notes. | Start a scan, jump to findings. |
| **Findings** | Every item with its verdict (Remove, Disable, Review, No signals, Safe, Trusted), local score, type and presence. The side panel explains what it is, why it was flagged, the signals, where it appears, file and signature details, command lines and network activity. | The actions that make sense for that item, ignore it, copy its details. |
| **Alerts** | What the background watch noticed (below): new startup entries, new or changed services, new scheduled tasks, security settings turned off and remote-access ports opened to the network, with how much each one matters. | Open the page where the item lives, mark alerts as read, clear them. |
| **Protection** | Microsoft Defender, read live: whether it protects the computer (or another antivirus does, with Defender in passive mode), its switches (real-time, behavior monitoring, tamper protection, cloud protection, sample submission, potentially unwanted app blocking, network protection, controlled folder access), security intelligence and scan dates, the threat history and the exclusions, with the risky ones marked (a whole drive, a folder any program can write to, a program file type, a process excluded by name). | Quick or full scan in the background with its progress and Stop, the Microsoft Defender Offline scan, update security intelligence, turn a switch on (never off), remove an exclusion, remove the active threats, open Windows Security. |
| **Security posture** | The Windows settings that protect the computer as a whole, read live and explained, with a score ("N of M recommended settings are in place", weighted 1 to 3 by how much each matters; partly in place counts half; settings that do not apply or could not be read are left out): Secure Boot, TPM, Memory integrity, Credential Guard, LSA protection, the vulnerable driver blocklist, BitLocker per drive, User Account Control, Remote Desktop and Network Level Authentication, Remote Registry, SMBv1, the firewall profiles, SmartScreen, Windows PowerShell 2.0, AutoRun, the antivirus, its security intelligence and the last Windows update. | Raise a setting that is below the recommendation (see Actions), or open where Windows changes it (Windows Security, Settings, BitLocker, the Firewall rules and Protection pages). Nothing here lowers security. |
| **Firewall rules** | The domain, private and public profiles and every Windows Defender Firewall rule, read live, with the rules that deserve a look marked: open to any address on public networks for every program, opening a remote-access port (Remote Desktop, SSH, VNC, WinRM, Telnet), allowing a program in a folder any user can write to, or left over for a program that no longer exists. | Turn a rule on or off, delete it (its full definition is saved first; rules of the groups Windows defines can only be turned off), open the program's location or Windows Defender Firewall. |
| **Accounts and sign-ins** | Local accounts (enabled, last sign-in, password that may be empty or never expires, built-in Administrator and Guest), the members of Administrators and Remote Desktop Users, the sessions signed in now, and the sign-ins of the last 7 or 30 days from the event logs: successful and failed sign-ins per day, the addresses failures came from, sign-ins from other computers, accounts created, new administrators and a cleared security log. Password guessing and sign-ins from the internet are marked. The Security log needs administrator rights; the Remote Desktop logs do not. | Disable an account (enable it again from History or the page), remove a member from Administrators or Remote Desktop Users (History adds it back), sign out another person's disconnected or Remote Desktop session, open Other users or Local Users and Groups. |
| **Browser extensions** | Every extension of every profile of Chrome, Edge, Brave, Vivaldi, Opera, Opera GX and Firefox, read live (other accounts' profiles too when elevated), with where it came from (store, a program, a policy, developer mode), whether it is on and why the browser turned it off, and what its permissions allow in plain words. Marked: access to every site, history, cookies or site traffic, talking to a program on the computer, installed outside the store or by a policy, Manifest V2, and extensions the browser itself marked as harmful. The browser policies of the machine and the user (and Firefox's policies.json) are listed too, with those adware sets marked: forced extensions, search, home page, startup pages or new tab redirected, a proxy, Safe Browsing, SmartScreen or the developer tools turned off. | Open the browser's extensions page or the extension's folder (browsers put deleted extensions back, so they are removed in the browser); remove a policy that forces or redirects something (the value is saved first, so History can put it back; policies that keep protection on and Firefox's policies.json are never changed). |
| **Quarantine** | Files moved to quarantine. | Restore to the original location, delete permanently. |
| **History** | Every change made from the app, with what was saved to undo it. | Undo a step, or a whole "Remove completely". |
| **Performance** | Task Manager style: CPU (per core and clock), memory (in use, modified, standby, free, committed), each GPU (engines, VRAM), each disk and network adapter, with five minutes of history, a cursor shared by every chart, marks where Vigil changed something, and the processes using each resource most. | End a process, efficiency mode, priority, low disk and memory priority, trim its memory, show it in Processes. |
| **Processes** | Live process tree with CPU, memory, disk, GPU and VRAM, user and path; rows hold still while you point at them. Processes that match a finding carry its verdict colour. An inspector lists the modules (DLLs) a process loaded, flagging those from folders a standard user can write to, and the services it hosts. | End process or tree, suspend/resume, priority, quarantine its file, block its network access, verify its signature, open its location or properties. |
| **Network** | Live TCP/UDP endpoints with the service behind each port, highlighting internet addresses and remote-access ports open to the network. | End the owning process, block its network access. |
| **Services** | Every Windows service with its state, startup type, process ID, account and command line; for services that share a host (svchost), the DLL that really runs. Windows components and essential services carry a lock. | Start, stop, restart, change the startup type (undo it from History), open the file location or the Services console. |
| **Optimize** | Apps that start with Windows and services that start at boot, power plans, memory, Game Mode and GPU scheduling, GPU per app, hibernation file, drives. | Turn startup entries off, start services only when needed, switch or add power plans, free standby memory, choose the GPU for an app, turn hibernation off, TRIM or defragment a drive. |
| **Startup apps** | What starts at sign-in, read live: the Run and RunOnce keys of your account and of every user, and both Startup folders, with publisher, signature and status. Entries that run through rundll32, script hosts or PowerShell name the host that runs them. | Turn an entry on or off with the switch Windows uses (undo it from History), open its location. |
| **Scheduled tasks** | Every task in Task Scheduler, read live, with its triggers in plain words, last and next run, last result, account and rights, and the program each action starts. Tasks that run a file with full rights from a folder any user can change are marked, as are tasks whose program no longer exists. Tasks under `\Microsoft\` can be hidden. | Enable, disable, delete (the task definition is saved first, so History can recreate it), run now, open Task Scheduler. Windows tasks under `\Microsoft\` are shown but never changed. |
| **Installed programs** | Every program in Settings' list of installed apps, read live from the Uninstall keys (the machine's, 32-bit ones included, yours and those of other signed-in accounts), with publisher, version, install date, declared size and the signatures of its program and uninstaller. Marked: programs installed in the last 7 days, remote access and tunnelling tools, unsigned files, and leftover entries whose uninstaller and files are gone. | Uninstall with the program's own uninstaller, remove a leftover entry (its registry key is saved first, so History can bring it back), open the install folder or Settings' Installed apps. Microsoft's entries are never removed. |
| **Storage** | Every drive's free space, junk files by place and a space analyzer (treemap, biggest folders, largest files). | Clean the selected places, clean up the component store, send large files to the Recycle Bin. |
| **System** | Windows, processor, memory modules, graphics adapters and driver age, disks with health, temperature and wear, board, BIOS, page file, battery, and concrete findings such as memory running below its rated speed. | Copy a plain-text summary. |
| **Reliability** | What went wrong in the last 7, 30 or 90 days, read from the Windows event logs: blue screens (stop code and whether the memory dump is still there), unexpected shutdowns, program crashes grouped by program with the module they failed in, programs that stopped responding, service failures, hardware (WHEA) and disk errors, failed updates, installs and removals, and startup times. A daily timeline and short, plain hints say what the records point to (the graphics driver, memory, a disk, one module behind several crashes). | Copy an event's details, open Event Viewer or Reliability Monitor. Nothing is changed. |

### Background watch

Once a minute Vigil compares a small fingerprint of the computer with the last one: startup entries (Run keys,
including those set by policy, and Startup folders), services (new ones, a start type changed to automatic, a changed
program or svchost DLL), scheduled tasks (new ones outside `\Microsoft\`, and changed actions; under `\Microsoft\` only
a task that runs something outside the Windows folder), the security switches (Defender real-time protection, tamper
protection and the policy that turns Defender off, the three firewall profiles, UAC, Remote Desktop, WDigest password
caching, LSA protection), remote-access ports (SSH, Telnet, Remote Desktop, VNC, TeamViewer, WinRM) listening on every
network interface with the program that listens, kernel and file system drivers (a new one, or one moved outside the
Windows driver folders), the hosts file (names it newly redirects), and the registry places Windows reads to load or
run something: image hijacks (including the Ease of Access programs of the sign-in screen), Winlogon, AppInit and
AppCert DLLs, BootExecute, the LSA packages, per-user Settings and console handlers used to bypass UAC, the .NET
profiler variables, NetSh helpers, print monitors, time providers and Microsoft Defender exclusions (the non-policy
exclusions only as administrator). It also reads a few Windows logs from where the last check stopped, which catches
changes undone within the minute: a service installed, a log cleared, a new account or administrator and a scheduled
task created (the Security log only as administrator), Microsoft Defender detections and changes, and new permanent WMI
subscriptions. A change already reported from the fingerprint is not reported again from a log. Each difference becomes
an alert on the **Alerts** page and, if you want, a Windows notification, most important first. The fingerprint is saved, so changes
made while Vigil was closed are reported at the next start. A part that could not be read is skipped, never taken as
"everything was removed". The watch only reads; it tells you about a change, it does not block it.

In **Settings → Background watch** you choose what shows a notification, whether closing the window keeps Vigil
watching from its icon in the notification area, and whether Vigil starts in the tray when you sign in (an entry in
your account's startup apps, without administrator rights; you confirm it and History can undo it). From the tray icon
you can open Vigil, start a scan, pause notifications for an hour or pause the watch. Only one copy of Vigil watches
at a time.

### Actions

What is offered depends on how the item is present on the system:

- **Remove completely** (the main action for malware-like items): ends its processes, turns off every way it starts
  (services and drivers set to disabled, scheduled tasks disabled, startup entries switched off or deleted, WMI
  subscriptions removed) and moves its file to quarantine. Every step except ending processes can be undone.
- Processes: end. Services: stop, disable, delete (the registry key is exported first); from the Services page also
  start, restart and change the startup type. Drivers: disable.
- Scheduled tasks: disable, delete (the task definition is saved first); from the Scheduled tasks page also
  enable and run now.
- Startup entries: switch off with the same switch Task Manager uses, or delete (the value is saved first). Also
  debugger hooks (Image File Execution Options), Winlogon values, AppInit DLLs, logon scripts.
- Files: quarantine, block network access with Windows Firewall rules, scan with Microsoft Defender.
- Firewall rules: turn on or off, delete (the whole rule definition is saved first, so History can recreate it).
- Accounts: disable a local account (History enables it again), remove a member from Administrators or Remote
  Desktop Users (History adds it back), sign out another person's disconnected or Remote Desktop session (not
  undoable: unsaved work in it is lost).
- Microsoft Defender: quick or full scan (in the background; Stop asks Defender to end it), the Microsoft Defender
  Offline scan (restarts the computer at once), update security intelligence, turn real-time protection, cloud
  protection, sample submission or potentially unwanted app blocking on (History restores the previous value), remove
  an exclusion (History adds it back), remove the active threats. Nothing on the Protection page turns protection off.
- Programs: start their own uninstaller. Browser extensions: open the browser's extensions page.
- Browser policies: remove one that forces an extension, redirects search, the home page, the startup pages or the new
  tab, sets a proxy, or turns Safe Browsing, SmartScreen or the developer tools off (the value is saved first).
- Installed programs: remove a leftover entry whose uninstaller and files are gone (the Uninstall key is exported
  first, so History can import it back; entries published by Microsoft and products Windows Installer still knows
  are refused).
- Settings: turn the firewall on, turn real-time protection on, update Defender, remove Defender exclusions, turn
  Remote Desktop or the proxy off, disable the Guest account or other local accounts.
- Security posture: set User Account Control back to the Windows default, require Network Level Authentication for
  Remote Desktop (or turn it off), turn off SMBv1 and Windows PowerShell 2.0 (Windows features, with DISM), turn
  AutoRun off for every drive, turn on the vulnerable driver blocklist and LSA protection (Windows 11 2022 Update and
  later), disable the Remote Registry service. Each one only raises security, changes only what is below the
  recommendation, and History puts back the exact previous values. Memory integrity, BitLocker, SmartScreen and
  Secure Boot are only opened in Windows Security, Settings or the firmware, where Windows checks what they need.

Maintenance actions are honest about what they do: freeing standby memory or trimming working sets is temporary,
disk cleanup never touches cookies, history, passwords, documents or Downloads, large files go to the Recycle Bin
rather than straight to deletion, and nothing lowers security for speed (memory integrity, Defender and the firewall
are never "optimizations").

### Safety model

- **The scan never changes anything.** A change happens only when you confirm it in a Windows dialog shown by the
  Rust core (not by the web page); the confirmation lists every step and its target.
- **The page only asks.** The UI sends a small request; the core rebuilds the action from its own data (the loaded
  report, the live process list, what it measured), validates every value and refuses anything else.
- **Live state, not scan data.** Each action re-reads the current state first; a reused process ID is never ended.
- **Guards** refuse, whatever is asked: critical Windows processes, Vigil itself, essential Windows services,
  Microsoft-signed services in the Windows folder, scheduled tasks under `\Microsoft\`, files in the Windows folder or
  signed by Microsoft, registry values outside the known startup locations, the account running Vigil and the last
  enabled administrator account.
- **Undo.** Before changing something, the previous value, the exported registry key, the task XML or the file itself
  is saved. Quarantined files are stored masked so they cannot run, and are checked against their SHA-256 when
  restored. Before the first destructive action of a session the app offers a System Restore point.
- **No shell, no injection.** Tools are called by absolute path with argument lists; values that reach PowerShell
  travel in environment variables, never inside the script text.
- **Protected data folder.** When elevated, the journal, backups, quarantine and scans live in `%ProgramData%\Vigil`,
  readable only by Administrators and SYSTEM, so malware running as your user cannot tamper with what the elevated
  app later restores. In read-only mode it uses `%LOCALAPPDATA%\Vigil`.

## How findings are judged

1. **Inventory** (read-only): processes (with paths even for protected processes), services and drivers, scheduled
   tasks, startup entries, Winlogon, IFEO, AppInit/AppCert DLLs, LSA packages, Active Setup, WMI subscriptions,
   installed programs and Store apps, browser extensions, network endpoints, DNS cache, hosts file, proxy, UAC,
   Remote Desktop, Defender state and history, firewall, accounts, shares, and the event logs. Also the less
   common places that run or load something:
   - per-user handlers that auto-elevating Windows programs open (UAC bypasses);
   - the accessibility programs of the sign-in screen (a copy of `cmd.exe` in place of `sethc.exe`);
   - DLLs registered as print monitors and processors, time providers, netsh helpers, network providers,
     Winsock providers and KnownDLLs, and LSA packages set through OSConfig;
   - one-value tricks: screensaver, .NET profilers, Application Verifier DLLs, SetupExecute, RunOnceEx, service
     recovery programs, the crash debugger, the Safe mode shell, the Remote Desktop start program, administrators
     hidden from the sign-in screen, `%windir%` redefined for the user, and writable folders before System32 in
     PATH;
   - settings that blind the defences, only when set explicitly: Defender told to allow threats, cloud protection
     or block at first sight off, network exclusions, attack surface reduction rules off, the Defender or Event
     Log service stopped, event logs or their autologgers off, LSA protection or the vulnerable driver blocklist
     turned off.
2. **Grouping**: every reference is resolved to the file that really decides what runs (the DLL behind `rundll32`,
   the script behind `wscript`, the payload of an encoded PowerShell command...), so each file is judged once.
3. **Local rules**: digital signatures, locations, names that imitate Windows, command-line patterns (miners,
   downloads, encoded or hidden PowerShell, defence evasion, reverse shells...), privileges combined with
   user-writable paths, Defender detections and exclusions, optional VirusTotal hash lookups. Microsoft-signed
   components in their usual places with no signals are trusted automatically and never sent to the agent.
4. **AI review** (optional): the remaining items go to the agent you chose (above).

Scans are saved as `scan-YYYYMMDD-HHMMSS-report.json` (findings and verdicts), `-inventory.json` (raw data) and
`-sent-to-ai.json` (what was sent). **More → Export HTML report** writes a self-contained page. They contain a
detailed inventory of the computer: treat them as private.

## Languages

English, Español, Français, Português (Brasil) and 简体中文. Vigil follows the Windows display language unless you
choose one in **Settings → Appearance**; findings, actions, confirmations, reports and the agent's explanations use
it too.

## Limitations

- Bandwidth per process is not shown: Windows does not report it without a network driver.
- Disk temperature, wear and power-on hours need administrator rights, and not every drive reports them.
- Without administrator rights the security log, Defender exclusions and the command lines of system processes are
  not visible.
- It inspects what runs and starts; it does not scan every file on disk (use Defender's full scan for that).
- The background watch notices changes about a minute after they happen and cannot stop them. Without
  administrator rights it cannot read scheduled tasks, so it watches them only while Vigil runs elevated.
- Rootkits that hide from Windows itself can hide from Vigil too.

## Security notes

- The installer puts Vigil in Program Files, where only administrators can write. If you use the portable
  executable, keep it in a folder only administrators can write to.
- The window is a local web view with a strict content security policy: it loads nothing from the internet, and text
  from the inspected computer is always shown as text.

## Build from source

You need [Rust](https://rustup.rs/) (stable, 1.90 or later) and [Node.js](https://nodejs.org/) 22.

```bat
npm ci
npm run build              :: the UI, into ui/dist
cargo run -p vigil-app     :: the app, debug build (starts without asking for elevation)
npx tauri build            :: release executable and installer, in target/release
```

`npm run dev` serves the UI alone in a browser with fictitious data. Checks:

```bat
npm run check
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The tests never change the system beyond temporary files, a scratch registry key under `HKCU\Software\VigilTests`
that they delete, and child processes they start and end. See [AGENTS.md](AGENTS.md) for the rules of the code and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how it fits together.

## License

MIT. See [LICENSE](LICENSE).
