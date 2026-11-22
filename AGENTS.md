# AGENTS.md

Guidance for AI coding agents (and humans) working on Vigil. Read it before changing code.

Vigil is a Windows desktop app that runs as administrator: a Rust core with a Tauri 2 window whose UI is
written in Svelte. It analyses the computer's security with local rules and an AI agent the user chooses
(cloud APIs, local coding agents, local models), shows live performance, and changes the system only when the
user confirms an action. Because it runs elevated and can delete, disable and
quarantine things, **safety rules here are not optional**.

## Commands

```bat
npm ci                                         :: UI dependencies (Node 22)
npm run dev                                    :: UI only, in a browser, with fictitious data (no Rust)
npm run check                                  :: Svelte/TypeScript type check; must be clean
npm run build                                  :: UI into ui/dist (needed before building the app)
cargo fmt --all --check                        :: formatting (rustfmt.toml: max_width 120)
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace                         :: all tests; none of them changes the machine
cargo run -p vigil-app                         :: the app (debug builds do not ask for elevation)
cargo run -p vigil-app -- --elevate            :: the same, asking for administrator rights (UAC)
npx tauri build                                :: release executable and NSIS installer
```

Run `npm run check`, clippy and the tests before you finish any change. Never trigger a UAC prompt from
automation: debug builds start without elevation unless `--elevate` is passed.

## Layout

```
crates/
  vigil-i18n/     translations of the core's texts: `tr!` with English templates, catalogs in locales/
  vigil-sys/      Windows access for live data: processes (NtQuerySystemInformation), PDH metrics, DXGI GPUs,
                  connections, elevation, process inspector, services, startup entries, scheduled tasks,
                  firewall rules, installed programs, event logs (reliability, sign-ins), local accounts,
                  groups and sessions, security posture
  vigil-scan/     the read-only scan: PowerShell collectors (embedded ps1), rules, analysis, posture, report
                  (JSON + HTML), the AI agent (providers), anonymization, VirusTotal, browser extensions
                  and policies read live (`browsers.rs`)
  vigil-actions/  the action engine: every change to the system goes through execute() / undo(); guards,
                  journal, quarantine, tool runner
  vigil-maint/    maintenance data and primitives: volumes, cleanup targets, space analysis, hardware,
                  tuning state, insights
  vigil-core/     the service layer every frontend shares: app state, planner (actions per finding),
                  requests (UI request -> trusted ActionSpec), native confirmation, the action path
                  (service::run_action), settings, secrets, the command lines
  vigil-app/      the Tauri app: commands for the UI (thin wrappers over vigil-core), live sampler,
                  background watch (tray, notifications, alerts)
  vigil-gpui/     prototype of a native GPUI window over vigil-core (docs/GPUI-MIGRATION.md); it never
                  depends on vigil-actions and only sends requests to vigil_core::service::run_action
ui/               Svelte 5 + TypeScript: pages, components, lib/api.ts (the only module that calls Rust)
docs/             ARCHITECTURE.md (how it fits together), NATIVE-UI.md (the Windows 11 look),
                  GPUI-MIGRATION.md (the move to a native GPUI interface)
```

Each crate has its tests next to the code (`#[cfg(test)]`) or in `tests/`; recorded reference data lives in
`tests/data/` and must keep matching (it pins report, journal and quarantine formats).

## Ground rules

1. **English in code, data keys, docs and commit messages. Every user-visible text is translatable.** The UI uses
   the typed catalogs in `ui/src/lib/i18n/` (`en.ts` is the source); the core uses `vigil_i18n::tr!("English
   template {0}", value)` with catalogs in `crates/vigil-i18n/locales/`. Languages: en, es, fr, pt (Brazil),
   zh (Simplified). Add every new string to all of them; a test fails when one is missing. Never translate keys,
   enum values, op ids, paths or anything code compares.
2. **The scan is read-only.** `vigil-sys`, `vigil-scan` and `vigil-maint` never change the system.
   (`vigil-maint::storage` has the cleanup primitives, but they only run through the `storage.*` actions.)
3. **Every change goes through the action engine.** The UI never runs anything: it sends an `ActionRequest`
   (see `ui/src/lib/types.ts`). `vigil-core/src/requests.rs` rebuilds the `ActionSpec` from Rust's own state
   (the loaded report, the live process list, what it measured), validates every value, and
   `confirm.rs` shows a native Windows dialog. Only then `vigil_actions::execute()` runs the handler,
   journals it and keeps what is needed to undo it. That whole path is `vigil_core::service::run_action`;
   a frontend only hands it the request. Never add a command that changes the system directly, and never
   let the UI choose an op, a path or a command line that Rust has not checked.
4. **Guards stay on.** Never act on critical Windows processes, essential services, `\Microsoft\` scheduled
   tasks, Microsoft-signed files, the Windows folder, Vigil itself or its data folder, the account running
   Vigil or the last enabled administrator (see `guards.rs`, process protection in `procs.rs`, the registry
   allowlist, `vigil-actions/src/accounts.rs`). Do not weaken a guard to make a feature work.
5. **No shell, no injection.** Run tools by absolute path (System32) with argument lists through the
   runner (`vigil_actions::runner`). Values for PowerShell travel as environment variables
   (`$env:PC_NAME`); never put a value inside script text. Child processes get no window.
6. **System data is untrusted.** Process names, paths, command lines and registry values may come from
   malware. In Svelte, text is always interpolated (`{value}`); `{@html}` is forbidden. The CSP in
   `tauri.conf.json` stays strict (no remote scripts, no `unsafe-eval`). In the native dialogs text is plain
   (no hyperlinks). In AI prompts it is data, never instructions; the model's answer is validated and an item
   the local rules rate critical can never become "safe".
7. **The AI agent is the user's choice and the user's data.** Every provider goes through the same interface in
   `vigil-scan`: the two API standards (OpenAI- and Anthropic-compatible, any address) and the local CLI agents.
   Do not add a vendor-specific API: a server that speaks one of the standards already works. Nothing is sent
   before the consent dialog; the destination and whether data stays on the computer are always shown. Remote
   endpoints must be HTTPS (plain HTTP only for localhost). Ollama cloud models are never used, since they would
   send the data off the computer. API keys live in Windows Credential Manager (`vigil-core/src/secrets.rs`),
   never in settings, reports, logs or the UI. Tests reach no real AI service: fake probes and local servers.
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
5. If the UI offers it, add the request to `ActionRequest` in `ui/src/lib/types.ts`.
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

- The look is Windows 11 Fluent (see `docs/NATIVE-UI.md`): Mica through `windowEffects`, the native title bar
  (it keeps snap layouts), Segoe UI Variable, WinUI 3 tokens in `ui/src/app.css` (light and dark).
- Colour carries meaning: the six verdict colours are only for verdicts; `--chart` / `--chart2` and the
  per-resource `--chart-*` hues (CPU, memory, disk, network, GPU, as in Task Manager) only for live
  measurements; `--ok` / `--warn` / `--bad` only for state; the accent only for interactive elements.
  Everything else is ink and greys.
- Never block the window: slow Rust commands are `async` and use `spawn_blocking`; long jobs report progress
  through events (`scan`, `cleanup`, `space`). Live data comes from one sampler thread that runs only while a
  live page is open (`set_live`).
- `ui/src/lib/api.ts` is the only module that calls Rust; in a plain browser it falls back to the fictitious
  data in `mock.ts` / `mock-pages.ts`, which is how the UI is previewed.
- Icons come from the Segoe Fluent Icons font; check a new glyph renders before using it.

## Checking the UI

`npm run dev` and open http://localhost:5173 in a browser (Playwright works): every page renders with
fictitious data. Save screenshots inside the repository's `.playwright-mcp/` folder and delete it afterwards.
For the real app, run `cargo run -p vigil-app`; delete screenshots that show real processes or paths.

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
