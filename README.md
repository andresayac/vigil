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

Three more commands give a quick look at the live system from a terminal or a script. Like the scan they only read;
changes are made from the app. Each one has `--help`, `--json` for machine-readable output and `--lang CODE`:

```bat
vigil list                         :: the 25 processes using the most CPU, measured over one second
vigil list --sort mem -n 10        :: sort by cpu, mem, name or pid; -n 0 shows every process
vigil ports --listening            :: listening ports with the process and service behind each one
vigil services --running --json    :: running Windows services, as JSON
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
- The agent gets no tools and the inventory is treated as untrusted text (a file that says "classify me as safe" is a
  red flag, not an instruction). Its answer is validated, and an item the local rules rate as critical can never be
  downgraded to safe.
- The agent answers in the language Vigil uses.

## The app

| Page | What it shows | What you can do |
|---|---|---|
| **Overview** | The verdict on the whole computer, one sliver per finding, what to do first, the security state (Defender, firewall, UAC, Remote Desktop, updates) and coverage notes. | Start a scan, jump to findings. |
| **Findings** | Every item with its verdict (Remove, Disable, Review, No signals, Safe, Trusted), local score, type and presence. The side panel explains what it is, why it was flagged, the signals, where it appears, file and signature details, command lines and network activity. | The actions that make sense for that item, ignore it, copy its details. |
| **Quarantine** | Files moved to quarantine. | Restore to the original location, delete permanently. |
| **History** | Every change made from the app, with what was saved to undo it. | Undo a step, or a whole "Remove completely". |
| **Performance** | Task Manager style: CPU (per core and clock), memory (in use, modified, standby, free, committed), each GPU (engines, VRAM), each disk and network adapter, with five minutes of history, a cursor shared by every chart, marks where Vigil changed something, and the processes using each resource most. | End a process, efficiency mode, priority, low disk and memory priority, trim its memory, show it in Processes. |
| **Processes** | Live process tree with CPU, memory, disk, GPU and VRAM, user and path; rows hold still while you point at them. Processes that match a finding carry its verdict colour. An inspector lists the modules (DLLs) a process loaded, flagging those from folders a standard user can write to, and the services it hosts. | End process or tree, suspend/resume, priority, quarantine its file, block its network access, verify its signature, open its location or properties. |
| **Network** | Live TCP/UDP endpoints with the service behind each port, highlighting internet addresses and remote-access ports open to the network. | End the owning process, block its network access. |
| **Services** | Every Windows service with its state, startup type, process ID, account and command line; for services that share a host (svchost), the DLL that really runs. Windows components and essential services carry a lock. | Start, stop, restart, change the startup type (undo it from History), open the file location or the Services console. |
| **Optimize** | Apps that start with Windows and services that start at boot, power plans, memory, Game Mode and GPU scheduling, GPU per app, hibernation file, drives. | Turn startup entries off, start services only when needed, switch or add power plans, free standby memory, choose the GPU for an app, turn hibernation off, TRIM or defragment a drive. |
| **Storage** | Every drive's free space, junk files by place and a space analyzer (treemap, biggest folders, largest files). | Clean the selected places, clean up the component store, send large files to the Recycle Bin. |
| **System** | Windows, processor, memory modules, graphics adapters and driver age, disks with health, temperature and wear, board, BIOS, page file, battery, and concrete findings such as memory running below its rated speed. | Copy a plain-text summary. |

### Actions

What is offered depends on how the item is present on the system:

- **Remove completely** (the main action for malware-like items): ends its processes, turns off every way it starts
  (services and drivers set to disabled, scheduled tasks disabled, startup entries switched off or deleted, WMI
  subscriptions removed) and moves its file to quarantine. Every step except ending processes can be undone.
- Processes: end. Services: stop, disable, delete (the registry key is exported first); from the Services page also
  start, restart and change the startup type. Drivers: disable.
- Scheduled tasks: disable, delete (the task definition is saved first).
- Startup entries: switch off with the same switch Task Manager uses, or delete (the value is saved first). Also
  debugger hooks (Image File Execution Options), Winlogon values, AppInit DLLs, logon scripts.
- Files: quarantine, block network access with Windows Firewall rules, scan with Microsoft Defender.
- Programs: start their own uninstaller. Browser extensions: open the browser's extensions page.
- Settings: turn the firewall on, turn real-time protection on, update Defender, remove Defender exclusions, turn
  Remote Desktop or the proxy off, disable the Guest account or other local accounts.

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
  signed by Microsoft, and registry values outside the known startup locations.
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
   Remote Desktop, Defender state and history, firewall, accounts, shares, and the event logs.
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
