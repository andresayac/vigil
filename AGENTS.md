# AGENTS.md

Guidance for AI coding agents (and humans) working on Vigil. Read it before changing code.

Vigil is a Windows desktop app that runs as administrator: a Rust workspace whose window is drawn natively with
gpui-kit. It analyses the computer's security with local rules and an AI agent the user chooses (cloud APIs, local
coding agents, local models), shows live performance, and changes the system only when the user confirms an
action. Because it runs elevated and can delete, disable and quarantine things, **safety rules here are not
optional**.

## Commands

```bat
cargo fmt --all --check                        :: formatting (rustfmt.toml: max_width 120)
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace                         :: all tests; none of them changes the machine
cargo run -p vigil-app                         :: the app (debug builds do not ask for elevation)
cargo run -p vigil-app -- --demo               :: every page with fictitious data; reads and changes nothing
cargo run -p vigil-app -- --elevate            :: the app, asking for administrator rights (UAC)
cargo run -p vigil-app -- scan --ai off        :: the command-line scan, local rules only
cargo build --release -p vigil-app             :: target\release\vigil.exe (needs fxc.exe from the Windows SDK)
powershell -File installer\build-setup.ps1 -Out dist   :: the setup from target\release\vigil.exe (NSIS)
powershell -File installer\test-installer.ps1 -ChecksOnly -Exe target\release\vigil.exe
                                               :: the installer test's checks that need no rights (CI runs all)
powershell -File installer\smoke-window.ps1 -Exe target\debug\vigil.exe [-Only processes,dialog-run] [-Out dir]
                                               :: every page and dialog in --demo: starts, no panic, no
                                               :: focusable control without a name (CI runs it on every push)
```

Run clippy and the tests before you finish any change. Never trigger a UAC prompt from automation: debug builds
start without elevation unless `--elevate` is passed, and release builds take `--no-elevate`.

## Layout

```
crates/
  vigil-i18n/     translations of the core's texts: `tr!` with English templates, catalogs in locales/
  vigil-sys/      Windows access for live data: processes (NtQuerySystemInformation), PDH metrics, DXGI GPUs,
                  connections, elevation, process inspector, services, startup entries, scheduled tasks,
                  firewall rules, installed programs, event logs (reliability, sign-ins, the watch's log
                  reader), local accounts, groups and sessions, security posture, Defender (WMI), registry
                  hooks, certificates, network configuration, BITS, service permissions, the vulnerable
                  driver blocklist, Windows Update, startup impact, power and battery, restore points
  vigil-scan/     the read-only scan: PowerShell collectors (embedded ps1), rules, analysis, posture, report
                  (JSON + HTML), export (CSV, SARIF), the signature cache, the AI agent (providers and the
                  tool-calling loop), anonymization, VirusTotal, the release check, and one module per
                  source (browsers, hooks, secrets, com, rmm, shellext, certs, amsi, netcfg, bits, vulndrv…)
  vigil-actions/  the action engine: every change to the system goes through execute() / undo(); guards,
                  journal, quarantine, tool runner
  vigil-maint/    maintenance data and primitives: volumes, cleanup targets, space analysis, duplicate
                  files, the Recycle Bin, hardware, tuning state, insights
  vigil-core/     the service layer: app state, planner (actions per finding), requests (request -> trusted
                  ActionSpec), native confirmation, the action path (service::run_action), the window's
                  reads (`api.rs`), settings, secrets, the background watch, its notifications and
                  automatic scans (`autoscan.rs`), the AI investigation, the MCP tool registry and
                  `vigil mcp`, export, duplicates, restore points, the update check (`version_check.rs`),
                  the display sanitizer for untrusted text (`display.rs`), the command lines
  vigil-app/      vigil.exe: the window (gpui-kit), the tray, the command-line entry points; pages in
                  src/pages, Fluent controls in src/ui, the Ctrl+K palette (`search.rs`, `palette.rs`), the
                  welcome (`welcome.rs`), catalogs in locales/, demo data in data/demo.json.
                  It never depends on vigil-actions: it only sends requests to service::run_action
installer/        vigil.nsi (the per-machine NSIS installer), build-setup.ps1, test-installer.ps1,
                  smoke-window.ps1 (every page and dialog of the window, in CI)
docs/             ARCHITECTURE.md (how it fits together), NATIVE-UI.md (the window and its Windows 11 look),
                  screenshots/ (demo screenshots used by the README)
CHANGELOG.md      what each release changed
```

Each crate has its tests next to the code (`#[cfg(test)]`) or in `tests/`; recorded reference data lives in
`tests/data/` and must keep matching (it pins report, journal and quarantine formats).

## Ground rules

1. **English in code, data keys, docs and commit messages. Every user-visible text is translatable.** The window
   uses the catalogs in `crates/vigil-app/locales/` (`en.json` is the source; dotted keys, `{name}` placeholders,
   plurals chosen by `count`); the core uses `vigil_i18n::tr!("English template {0}", value)` with catalogs in
   `crates/vigil-i18n/locales/`. Languages: en, es, fr, pt (Brazil), zh (Simplified). Add every new string to all
   of them; a test fails when one is missing. Never translate keys, enum values, op ids, paths or anything code
   compares.
2. **The scan is read-only.** `vigil-sys`, `vigil-scan` and `vigil-maint` never change the system.
   (`vigil-maint::storage` has the cleanup primitives, but they only run through the `storage.*` actions.)
3. **Every change goes through the action engine.** The window never runs anything: it sends a typed request
   (`vigil_core::requests::Request`). `vigil-core/src/requests.rs` rebuilds the `ActionSpec` from Rust's own
   state (the loaded report, the live process list, what it measured), validates every value, and `confirm.rs`
   shows a native Windows dialog. Only then `vigil_actions::execute()` runs the handler, journals it and keeps
   what is needed to undo it. That whole path is `vigil_core::service::run_action`; the window only hands it the
   request (`crates/vigil-app/src/actions.rs`, and a test checks no other file builds or runs an action). Never
   add code that changes the system directly, and never let the window choose an op, a path or a command line
   that Rust has not checked.
4. **Guards stay on.** Never act on critical Windows processes, essential services, `\Microsoft\` scheduled
   tasks, Microsoft-signed files, the Windows folder, Vigil itself or its data folder, the account running
   Vigil or the last enabled administrator (see `guards.rs`, process protection in `procs.rs`, the registry
   allowlist, `vigil-actions/src/accounts.rs`). Do not weaken a guard to make a feature work.
5. **No shell, no injection.** Run tools by absolute path (System32) with argument lists through the
   runner (`vigil_actions::runner`). Values for PowerShell travel as environment variables
   (`$env:PC_NAME`); never put a value inside script text. Child processes get no window.
6. **System data is untrusted.** Process names, paths, command lines and registry values may come from
   malware. The window draws them as plain text (never as markup or links); selectable text is plain text
   too. In the native dialogs text is plain (no hyperlinks). In AI prompts it is data, never instructions; the
   model's answer is validated and an item the local rules rate critical can never become "safe".
7. **The AI agent is the user's choice and the user's data.** Every provider goes through the same interface in
   `vigil-scan`: the two API standards (OpenAI- and Anthropic-compatible, any address) and the local CLI agents.
   Do not add a vendor-specific API: a server that speaks one of the standards already works. Nothing is sent
   before the consent dialog; the destination and whether data stays on the computer are always shown. Remote
   endpoints must be HTTPS (plain HTTP only for localhost). Ollama cloud models are never used, since they would
   send the data off the computer. API keys live in Windows Credential Manager (`vigil-core/src/secrets.rs`),
   never in settings, reports, logs or the window. Tests reach no real AI service: fake probes and local servers.
   **AI tools only read.** The tool registry (`vigil-core/src/mcp/registry.rs`), shared by `vigil mcp` and the
   in-app investigation, never changes the computer, never opens a dialog and never builds an `ActionSpec`. Results
   are capped, paged and anonymizable, and their text is data inside a JSON envelope, never instructions. A model
   may only suggest; actions go through `requests.rs` and the native confirmation like any other.
   **The update check is the only other network call**, and it is off by default (Settings > General):
   `vigil-scan/src/release.rs` asks GitHub's latest-release endpoint of this repository over HTTPS with a fixed
   User-Agent (the version only), validates the answer and never downloads or installs anything. Tests use a
   local server, never GitHub.
8. **Never follow links when deleting.** Skip reparse points (junctions, symlinks); open files without
   following links, check the final path is inside the expected root (see `vigil-maint::storage`).
9. **Honest wording.** Explanations say what really happens (for example: trimming memory is temporary).
   Nothing may lower security for speed (memory integrity, Defender, firewall, UAC are never
   "optimizations").
10. **No `unwrap`/`expect` in library code.** Errors become messages for the user. Every `unsafe` block is small
   and has a `// SAFETY:` comment.

## Adding an action

1. Write the handler in `vigil-actions` (`fn op_name(params, store) -> Result<Outcome>` and an undo function
   when it can be undone). Re-read the live state first, apply the guards, return an error message for the
   user, and put the undo data in `Outcome.undo`.
2. Register it in the engine's dispatch table (or with `vigil_actions::register` from `vigil-core` for ops that
   need other crates, like `storage.clean`). `no_admin` only for changes a standard user may make.
3. Add a readable name to `op_label()` (History page).
4. Build the `ActionSpec` where it is offered: `vigil-core/src/planner.rs` for findings, `requests.rs` for
   pages. Give it an accurate `explain`, `warning`, `destructive`, `reversible` and `admin`.
5. If a page offers it, add the request to `Request` in `vigil-core/src/requests.rs`; pages send it with
   `pages::common::send` (or `send_json` with the request's JSON shape).
6. Test it without touching the machine (below).

## Tests must not change the machine

- Use temporary folders. Never point a test at the real data folder.
- Registry: only the scratch key `HKCU\Software\VigilTests`, deleted afterwards.
- External tools: inject a fake runner that records the calls.
- Processes: start a child (for example `ping -n 30 127.0.0.1`), act on it, kill it in every path.
- Never run cleanup, Recycle Bin or quarantine code on real user data; build fake trees in temp folders.

## Privacy

- No real user names, computer names, SIDs, e-mail addresses, personal paths or scan output in code, tests,
  fixtures, docs, screenshots or commits. Use `jdoe`, `PC-VICTIM`, `DESKTOP-ABC123` and documentation IPs
  (`203.0.113.x`).
- Scan reports (`*-report.json`, `*-inventory.json`, `*-sent-to-ai.json`) are a detailed inventory of a real
  computer: they are git-ignored and must never be committed.

## UI conventions

- The look is Windows 11 Fluent (see `docs/NATIVE-UI.md`): Mica, the native title bar (it keeps snap layouts),
  Segoe UI Variable, the WinUI 3 tokens in `crates/vigil-app/src/theme.rs` (light and dark), Fluent controls in
  `src/ui` built on gpui-base primitives (focus, Tab, Enter/Space, accessibility role, name and state).
- Colour carries meaning: the six verdict colours are only for verdicts; `chart2` and the per-resource
  `chart_*` hues (CPU, memory, disk, network, GPU, as in Task Manager) only for live measurements;
  `ok` / `warn` / `bad` only for state; the accent only for interactive elements. Everything else is ink and
  greys.
- Never block the window: slow reads run on the background executor (`pages::common::read`), requests on their
  own thread (`actions.rs`); long jobs report progress through channels. Live data comes from one sampler thread
  that runs only while a live page is open and the window is visible (`live.rs`).
- Pages read through `crates/vigil-app/src/data.rs`: the core, or the fictitious data of `data/demo.json` with
  `--demo`. Every interactive element has an accessible role and name; charts and the treemap are named groups.
- Icons come from the Segoe Fluent Icons font; check a new glyph renders before using it.

## Checking the UI

`cargo run -p vigil-app -- --demo --page <key>` shows any page with fictitious data (`--item ID` selects a
finding, `--dialog settings|scan|run|search[=text]|welcome[=step]` opens a dialog, `--size WxH` sets the window
size, `--theme light|dark`, `--lang CODE`). Delete screenshots of the real app, which show real processes and
paths. Demo screenshots stay out of the repository too, except the few the README shows in `docs/screenshots/`:
demo data only, checked by eye, small optimized PNGs (a test checks every screenshot the README names exists).

## Performance

- Read processes with one `NtQuerySystemInformation` call per sample (`vigil-sys::process`), never one API call
  per process attribute. Metrics come from PDH counters.
- The process table is virtualized and keyed by `pid:createdMs`; do not rebuild it on every sample.
- The space analysis walks in parallel and merges small entries so memory stays bounded on huge trees.

## Things that must not change

- The quarantine mask key (`quarantine.rs`): files already in quarantine are masked with it.
- The data folder name (`%ProgramData%\Vigil`, `%LOCALAPPDATA%\Vigil`).
- Journal record fields and undo data: History must be able to undo actions recorded by earlier sessions.
- Report JSON keys (reports must keep opening), `settings.json` and `ignored.json` keys.
- The AppUserModelID `com.andresayac.vigil` and the installer's names (program folder, shortcut, uninstall
  entry): notifications and upgrades depend on them.
