# Architecture

Vigil is a Rust workspace with a Tauri 2 desktop app and a Svelte + TypeScript UI. The core does everything that
touches the system; the UI displays data and asks for things.

## Why this stack

- **One small executable** (about 16 MB; a 4 MB installer) with the UI embedded.
- **Native Windows access** through Microsoft's `windows` crate: one kernel query per process sample, PDH counters,
  DXGI, the Credential Manager, task dialogs.
- **Type safety where it matters most**: the action engine that deletes, disables and quarantines as administrator.
- **A Windows 11 look** (Mica, Fluent design, native title bar) without giving up a UI that can be previewed in a
  browser (see [NATIVE-UI.md](NATIVE-UI.md)).

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
  vigil-core/           the service layer every frontend shares: app state, planner, request validation,
                        native confirmation, the action path (`service::run_action`), settings and
                        secrets, the read-only command lines (`vigil scan`, `list`, `ports`, `services`)
  vigil-app/            Tauri app (binary: vigil.exe): commands (thin wrappers over vigil-core), live
                        sampler, the background watch (tray icon, notifications, alerts)
  vigil-gpui/           prototype of the native GPUI window (binary: vigil-gpui.exe), see GPUI-MIGRATION.md
ui/                     Svelte 5 + TypeScript, built by Vite into ui/dist and embedded in vigil.exe
package.json            UI toolchain (npm)
```

## Security model

- The web UI displays data and asks for things; it never decides. It sends small requests (`ActionRequest` in
  `ui/src/lib/types.ts`); `vigil-core/src/requests.rs` rebuilds the action from the core's own state (the loaded
  report, the live process list, the targets it measured) and validates every value.
- Every change is confirmed in a **native** Windows task dialog shown by the core (`confirm.rs`), not in the web
  page, so text that comes from the inspected computer cannot trigger an action even if it managed to inject markup.
  Destructive actions default to "Cancel" and offer a restore point first.
- Only `vigil_actions::execute()` changes the system; it re-reads live state, applies the guards and journals what
  is needed to undo.
- Strict CSP, no remote content, no `{@html}` in Svelte, capabilities limited to events and window control. URLs,
  consoles and tools the UI may open are allowlisted in the core.
- The background watch (`vigil-app/src/watch.rs`) only reads. Once a minute it compares a fingerprint of startup
  entries, services, scheduled tasks, security switches and remote-access ports with the last one saved in
  `%LOCALAPPDATA%\Vigil\watch\watch.json`, and turns each difference into an alert; a named mutex lets one copy of
  Vigil watch at a time. That folder is the user's, and an elevated Vigil writes there too, so `userdir.rs` opens it
  by handle (`NtCreateFile` relative to the parent, no reparse points) and replaces the file by a flushed temporary
  file and a rename; a lock file shared by both copies serializes every change. Starting in the tray at sign-in is
  itself an action (`vigil.autostart`): confirmed, journaled and undoable like any other change.
- The AI agent's answer is data: validated against a schema, never executed, and it can never lower the verdict of
  an item the local rules rate critical. API keys live in Windows Credential Manager.
- Two API standards cover every model server: OpenAI Chat Completions (`vigil-scan/src/ai/openai.rs`) and Anthropic
  Messages (`ai/anthropic.rs`), each with any address the user sets. An address on this computer is "local": the
  data stays on the PC. When that server is Ollama (`/api/version`), `ai/ollama.rs` asks `/api/tags` which models
  really run here and refuses its cloud models, which would relay the inventory to ollama.com. Every network check
  goes through the `Probe` trait, so the tests use fakes and local servers only.

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

English is the source language everywhere. The UI has typed catalogs in `ui/src/lib/i18n/`; the core translates
its texts with `vigil_i18n::tr!` and `crates/vigil-i18n/locales/<code>.json`. A test fails when a catalog misses a
string the code uses.

## Commands

```bat
npm ci                      :: UI toolchain
npm run dev                 :: UI on http://localhost:5173 (a browser preview uses fictitious data)
npm run build               :: UI into ui/dist (the app embeds it)
cargo run -p vigil-app      :: the app (debug builds do not ask for UAC; add -- --elevate)
cargo run -p vigil-app -- scan --ai off      :: command-line scan, local rules only
npx tauri build             :: release exe and NSIS installer in target/release
npm run check               :: type-check the UI
cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings
```
