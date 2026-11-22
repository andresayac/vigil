# Architecture

Vigil is a Rust workspace that builds one Windows executable, `vigil.exe`: a native window drawn with gpui-kit,
a tray icon with the background watch, and the command lines. The core does everything that touches the system;
the window displays data and asks for things.

## Why this stack

- **One self-contained executable** (no runtime to install): the window renders on the GPU through Direct3D, so
  it starts in about a quarter of a second, runs as a single process and stays near 100 MB.
- **Native Windows access** through Microsoft's `windows` crate: one kernel query per process sample, PDH counters,
  DXGI, the Credential Manager, task dialogs, the notification area.
- **Type safety where it matters most**: the action engine that deletes, disables and quarantines as administrator,
  and the window, which hands it typed requests only.
- **A Windows 11 look** (Mica, Fluent design, the native title bar) with accessibility from the framework: every
  control is a UI Automation element with its role, name and state (see [NATIVE-UI.md](NATIVE-UI.md)).

## Layout

```
Cargo.toml              workspace
crates/
  vigil-i18n/           translations of the core's texts (English source in the code, catalogs in locales/)
  vigil-sys/            live data: processes (NtQuerySystemInformation), PDH metrics, DXGI GPUs, connections,
                        elevation, the process inspector (modules, hosted services), Windows services, startup
                        entries, scheduled tasks (Task Scheduler COM), firewall rules (INetFwPolicy2),
                        installed programs (the Uninstall keys), reliability and sign-in events (the Event Log
                        API), local accounts, groups and sessions (NetApi32, Remote Desktop Services),
                        the security posture (registry, WMI, the TPM API)
  vigil-scan/           read-only scan: PowerShell collectors (embedded), rules, analysis, posture, reports,
                        the AI agent (the OpenAI- and Anthropic-compatible API standards, local CLI
                        agents), anonymization, VirusTotal, browser extensions and policies read live
                        for the Browser extensions page (`browsers.rs`)
  vigil-actions/        action engine: guards, journal, quarantine, undo, tool runner, tuning actions
  vigil-maint/          volumes, junk cleanup, space analyzer, Recycle Bin, hardware, tuning state, insights
  vigil-core/           the service layer: app state, planner, request validation, native confirmation,
                        the action path (`service::run_action`), the window's reads and scan flow (`api.rs`),
                        settings and secrets, the background watch, its notifications and automatic scans
                        (`autoscan.rs`), the AI investigation, the MCP tool registry and server
                        (`vigil mcp`), the read-only command lines (`vigil scan`, `list`, `ports`, `services`, `programs`, `reliability`)
  vigil-app/            vigil.exe: the window (src/shell.rs, src/pages, src/ui, src/theme.rs), the live
                        sampler, the tray and single-instance pieces (src/platform.rs), the dialogs, the
                        catalogs (locales/) and the demo data (data/demo.json)
installer/vigil.nsi     the per-machine installer (NSIS)
```

## Security model

- The window displays data and asks for things; it never decides. It sends a typed `Request`
  (`vigil-core/src/requests.rs`), which rebuilds the action from the core's own state (the loaded report, the live
  process list, the targets it measured) and validates every value. `vigil-app` does not even depend on the action
  engine; a test checks that no file other than `actions.rs` hands anything to the action path.
- Every change is confirmed in a **native** Windows task dialog shown by the core (`confirm.rs`), owned by the main
  window, so text from the inspected computer cannot trigger an action. Destructive actions default to "Cancel" and
  offer a restore point first.
- Only `vigil_actions::execute()` changes the system; it re-reads live state, applies the guards and journals what
  is needed to undo.
- Text that comes from the system (process names, paths, command lines, registry values) is drawn as plain text:
  nothing in the window interprets markup or follows links. URLs, consoles and tools the window may open are
  allowlisted in the core.
- The background watch (`vigil-core/src/watch.rs`) only reads. Once a minute it compares a fingerprint of startup
  entries, services, scheduled tasks, security switches and remote-access ports with the last one saved in
  `%LOCALAPPDATA%\Vigil\watch\watch.json`, and turns each difference into an alert; a named mutex lets one copy of
  Vigil watch at a time, and a second mutex keeps one window per session (a second start shows the first window).
  That folder is the user's, and an elevated Vigil writes there too, so `userdir.rs` opens it by handle
  (`NtCreateFile` relative to the parent, no reparse points) and replaces the file by a flushed temporary file and
  a rename; a lock file shared by both copies serializes every change. Starting in the tray at sign-in is itself an
  action (`vigil.autostart`): confirmed, journaled and undoable like any other change.
- The AI agent's answer is data: validated against a schema, never executed, and it can never lower the verdict of
  an item the local rules rate critical. API keys live in Windows Credential Manager; Settings only learns whether
  one is stored.
- **AI tools.** One registry of read-only tools (`vigil-core/src/mcp/registry.rs`, plus the context tools in
  `mcp/context.rs`: scan digest, related findings, a program's events, a file's history) serves two callers: `vigil mcp`
  (`mcp/server.rs`, MCP over stdio, newline-delimited JSON-RPC) and "Investigate with AI" (`investigate.rs`). The
  investigation loop (`vigil-scan/src/ai/agent.rs`) speaks tool calling in both API standards and gives the local
  agents the same tools by starting `vigil mcp` for that run (Claude Code `--mcp-config --strict-mcp-config`, Codex
  `-c mcp_servers.vigil.*`, Gemini CLI project settings plus a policy that allows only those tools). Trust
  boundaries: tool results are system data wrapped in a `{"tool", "data"}` envelope and capped per call and per
  investigation; the loop has limits on steps, calls, bytes and time, and can be cancelled; the final answer is
  validated (`investigate::validate`); the consent dialog is native; nothing a model returns can reach
  `vigil_actions::execute()`.
- Two API standards cover every model server: OpenAI Chat Completions (`vigil-scan/src/ai/openai.rs`) and Anthropic
  Messages (`ai/anthropic.rs`), each with any address the user sets. An address on this computer is "local": the
  data stays on the PC. When that server is Ollama (`/api/version`), `ai/ollama.rs` asks `/api/tags` which models
  really run here and refuses its cloud models, which would relay the inventory to ollama.com. Every network check
  goes through the `Probe` trait, so the tests use fakes and local servers only.

## The window

- `shell.rs` is the NavigationView (sections, the rights, More, Settings) and the content layer; each page is an
  entity in `src/pages` that reads through `data.rs` (the core, or `data/demo.json` with `--demo`) on the
  background executor and redraws when its data or the shared `Report` changes (`app.rs`: the loaded report, the
  scan in progress, the watch's state, navigation between pages).
- Live pages (Overview, Processes, Performance, Optimize, System) take their numbers from one sampler thread
  (`live.rs`) that runs only while such a page is open and the window is visible.
- Requests run on their own thread (`actions.rs`) so the confirmation's modal loop never blocks the window; scans,
  the space analysis and the AI investigation report progress through channels.

## Stored formats

The report (`-report.json`), the journal (`journal.jsonl`), quarantine records and backups have stable formats, so
History can undo what an earlier session recorded and reports open in any later version. Recorded reference data
next to each crate keeps them stable:

| What | Where | Checked |
|---|---|---|
| Analysis of two fictitious infected computers | `vigil-scan/tests/data` | items, ids, verdicts, levels, scores, flags, summary, HTML |
| Actions offered per finding (planner) | `vigil-core/tests/data` | the 61 actions of the 23 items |
| A journal, a quarantined file and a task backup | `vigil-actions/tests/data/formats` | read, undone, restored byte for byte |
| Insights and cleanup targets | `vigil-maint/tests/data` | texts and order |

## Languages

English is the source language everywhere. The window's texts live in `crates/vigil-app/locales/<code>.json`
(`en.json` is the source); the core translates its texts with `vigil_i18n::tr!` and
`crates/vigil-i18n/locales/<code>.json`. Tests fail when a catalog misses a string the code uses, and when a core
catalog keeps one no code uses.

## Commands

```bat
cargo run -p vigil-app                      :: the app (debug builds do not ask for UAC; add -- --elevate)
cargo run -p vigil-app -- --demo            :: every page with fictitious data
cargo run -p vigil-app -- scan --ai off     :: command-line scan, local rules only
cargo build --release -p vigil-app          :: target\release\vigil.exe (fxc.exe from the Windows SDK)
powershell -File installer\build-setup.ps1 -Out dist                 :: the setup (NSIS)
cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings
```
