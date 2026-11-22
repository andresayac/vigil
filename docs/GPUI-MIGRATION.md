# Moving Vigil's interface to GPUI (gpui-kit)

This document records phase 1 of the move from Tauri 2 + Svelte 5 to a native Rust interface built with
[gpui-kit](https://gpui-kit.com) (Longbridge; one crate that bundles GPUI, `gpui-base` and `gpui-component`).
It covers what was verified, the prototype in `crates/vigil-gpui`, the measurements, the risks and the plan
for the remaining pages. The Tauri app keeps working side by side until the plan is done.

## 1. What was verified

| | |
|---|---|
| Crate | `gpui-kit = "=0.10.0"` (crates.io, Apache-2.0) |
| GPUI | `gpui-pre =0.3.12`: a published snapshot of the GPUI framework (Apache-2.0), pinned exactly by gpui-kit, with `gpui-pre-platform` / `gpui-pre-windows` 0.3.12, `gpui-base 0.10.0`, `gpui-component 0.10.0`, `gpui-kit-assets 0.10.0` |
| Toolchain | stable Rust 1.99, MSVC (`x86_64-pc-windows-msvc`); builds with the workspace's `rust-version = 1.90` settings and edition 2024 |
| Builds here | yes, debug and release, on Windows 11 (build 26300) |
| Build prerequisite | **release builds compile the HLSL shaders with `fxc.exe`** from the Windows 10/11 SDK (found through `PATH`, the SDK folders, or `GPUI_FXC_PATH`). Debug builds compile them at run time. The GitHub `windows-latest` image has the SDK. |
| Manifest | `gpui-pre` embeds its own application manifest (asInvoker, PerMonitorV2 DPI awareness, Common Controls 6, segment heap), so Vigil's task dialogs keep working; an icon or version resource must not add a second manifest |
| Licence | Apache-2.0 for gpui-kit, GPUI and their crates; compatible with Vigil's MIT licence (keep their notices in the installer's licence file) |

### Windows support

| Need | Finding |
|---|---|
| Backdrop | `WindowBackgroundAppearance::MicaBackdrop` / `MicaAltBackdrop` (DWMWA_SYSTEMBACKDROP_TYPE, Windows 11 22H2+, build 22621), `Blurred` (acrylic through SetWindowCompositionAttribute), `Transparent`, `Opaque`. The renderer draws through DirectComposition with premultiplied alpha, so translucent layers show the Mica material. Windows 10: opaque, as today. |
| Title bar | The native title bar (`TitlebarOptions { appears_transparent: false }`) keeps snap layouts, caption buttons, the system menu and their accessibility. A custom caption is also possible (`appears_transparent: true`): GPUI answers `WM_NCHITTEST` with `HTMAXBUTTON` for an element marked `WindowControlArea::Max`, so snap layouts survive a custom title bar too. The prototype keeps the native one, as the Tauri app does. |
| Dark title bar | GPUI sets `DWMWA_USE_IMMERSIVE_DARK_MODE` from the **Windows** theme. Vigil's own choice ("Dark" on a light Windows) needs one `DwmSetWindowAttribute` call (`vigil-gpui/src/win.rs`), repeated whenever Windows' theme changes. |
| DPI | Per-monitor v2 from the manifest; `WM_DPICHANGED` handled; layout in logical pixels. |
| Dark mode detection | `window.appearance()` and `observe_window_appearance` (UISettings foreground colour, `ImmersiveColorSet`). |
| IME | `WM_IME_STARTCOMPOSITION` / `WM_IME_COMPOSITION` handled; gpui-component inputs support composition (Chinese input). |
| Accessibility | AccessKit → UI Automation (`accesskit_windows`). Components declare roles, names and states; a custom `div` is invisible to screen readers until it gets `.role(...)` and `.aria_label(...)`. Checked with UI Automation on the prototype: the navigation items and command buttons appear as named buttons, the view switch as radio buttons, the search box as an edit, the process list as a table of data items. GPUI has no disabled state for a plain `div` yet. |
| Renderer | Direct3D 11 (feature level 10.1 with structured buffers) through DXGI; DirectWrite text. Text over translucent areas is grayscale anti-aliased (no ClearType there), as in every DirectComposition app. |
| Native dialogs | GPUI runs its own task dialogs on a separate thread with the main window as owner, so the UI thread keeps pumping messages. Vigil's confirmation does the same (see section 2). File dialogs: `cx.prompt_for_paths` / `prompt_for_new_path` (IFileDialog). Clipboard: `cx.write_to_clipboard`. |
| Not provided | Tray icon and toast notifications (Vigil already has its own toasts in `notify.rs`; the tray needs `Shell_NotifyIcon` code or a small crate), single-instance handling, the system accent colour (read it with `UISettings::GetColorValue(Accent)`). |

### Component coverage

| Vigil needs | gpui-kit 0.10 | Notes |
|---|---|---|
| Virtualized table, sortable and resizable columns | `table::DataTable` + `TableDelegate` (also `VirtualList`, `List`) | Used by the prototype. Its selection is by row index; live data needs selection by key (the prototype keeps it in the delegate and paints it in `render_tr`). |
| Tree rows | `tree`, or indentation and twisties in the table's first column | The prototype draws groups and the process tree in the table. |
| Sidebar / navigation | `sidebar` (gpui-component's own style) | The prototype draws the WinUI NavigationView itself (40 lines of `div`s) to match Task Manager. |
| Tabs, segmented control | `tab::TabBar`, `toggle_group` (base) | |
| Dialogs | `dialog`, `alert_dialog`, `sheet` (`window.open_dialog`) | Used for Settings in the prototype. Confirmations of changes stay native task dialogs. |
| Menus, context menus | `menu::PopupMenu`, `DropdownMenu`, `ContextMenu`; `TableDelegate::context_menu` | Needed for the Priority / File / More menus and the sidebar's More flyout. |
| Tooltips | `tooltip` | |
| Inputs, search | `input::Input` (prefix, clear button, IME), `NumberInput`, `select`, `combobox` | Search box used by the prototype. |
| Switches, checkboxes, radios, sliders | `switch`, `checkbox`, `radio`, `slider` | |
| Charts | `chart` (line, area, bar, pie, …) and `canvas` + `PathBuilder` | The prototype draws Task Manager's charts on a canvas (area + line + tinted grid). The treemap of Storage and the reliability timeline are canvas work too. |
| Scroll views | `scroll::Scrollable`, `overflow_y_scroll` | |
| Resizable split panel | `resizable` (`h_resizable` / `v_resizable`) | |
| Notifications / InfoBar | `notification`, `alert` | The prototype draws an InfoBar. |
| Progress, spinners, skeletons | `progress`, `spinner`, `skeleton` | |
| Selectable text | `text` (TextView), `selectable_text` (base) | Plain text is not selectable by default (paths, hashes, command lines must be). |

Nothing Vigil needs is missing outright; the gaps are look (gpui-component has its own web-like style, so Fluent
controls are restyled through `Theme` or drawn with `div`s) and key-based selection for live tables.

## 2. Architecture

```
crates/
  vigil-core/    NEW: the service layer every front end shares (no UI toolkit)
                 state (AppState: data folder, journal store, settings, loaded report, caches),
                 requests (typed Request -> trusted Plan), planner, confirm (native task dialog),
                 service::run_action (the only path to vigil_actions::execute), settings, secrets,
                 inspect (process details, scheduled tasks), firewall / programs / protection /
                 reliability views and request checks, the command lines
  vigil-app/     the Tauri app: Tauri commands are now thin wrappers over vigil-core
  vigil-gpui/    NEW: the native window (binary vigil-gpui.exe for now)
```

What moved, without behaviour changes: `requests`, `planner`, `confirm`, `settings`, `secrets`, `autostart`,
`storage_ops`, `cli`, `tools`, and the non-Tauri parts of `firewall`, `programs`, `protection` and
`reliability`. The body of the old `run_action` command (build the plan from fresh live state, prompt, restore
point, `execute_plan`, record on the finding, quarantine restore/delete, shell ops) is now
`vigil_core::service::run_action(&AppState, &Request, &dyn Ui)`. A front end implements three methods:

```rust
pub trait Ui {
    fn owner(&self) -> isize;              // the HWND that owns the dialog
    fn ask(&self, prompt: Prompt) -> Answer; // show confirm::ask, wait for the answer
    fn progress(&self, text: &str);
}
```

- Tauri: `run_action` runs the service in `spawn_blocking`; `ask` hops to the main thread with
  `run_on_main_thread` (as before) and progress becomes the `action` event.
- GPUI: the request runs on its own `vigil-action` thread; `ask` calls `confirm::ask` there with the main
  window as owner. Windows disables the owner while the modal loop runs (checked), and the UI thread keeps
  pumping, which is GPUI's own pattern for native dialogs. Progress lines reach the page through a channel.

The security model is unchanged: the window only builds a `Request::Process { op, pid, created_ms, … }`;
`requests.rs` rebuilds the `ActionSpec` from a fresh process list and validates it, `confirm.rs` shows the
native dialog, `vigil_actions::execute()` runs and journals it. `vigil-gpui` does not depend on
`vigil-actions`, and a test (`actions::tests::the_ui_never_builds_or_runs_actions`) fails if its sources name
`ActionSpec`, `execute(`, `execute_plan`, `vigil_actions` or `confirm::ask` outside the bridge.

What the move changes for security: the web view was a separate, sandboxed renderer process behind a strict
CSP; the native UI runs in the elevated process. It has no script or markup engine at all, so text from the
inspected computer can only ever be drawn as text, which removes the injection class the CSP guarded
against. The rule becomes: never pass system data to a component that interprets markup (gpui-component's
Markdown / TextView with markdown, links).

## 3. The prototype (`crates/vigil-gpui`)

`cargo run -p vigil-gpui -- --demo` (fictitious data) or `cargo run -p vigil-gpui` (this computer, never
elevated; a standard user sees less and the actions a standard user may run are offered).
Options: `--page KEY`, `--pid PID` (select a process, as "Show in Processes" does), `--theme system|light|dark`,
`--lang en|es|fr|pt|zh`.

- **Shell**: Mica backdrop (Windows 11 22H2+), the native title bar, the NavigationView with the hamburger,
  New scan, the three sections and all 18 pages in the web UI's order, the selection pill, the administrator /
  read-only status, More and Settings (a gpui-component dialog with theme and language). Pages not ported show
  a placeholder.
- **Theme**: the WinUI 3 light and dark tokens of `app.css` (`src/theme.rs`), projected onto gpui-component's
  theme; Segoe UI Variable Text / Display, Cascadia Mono, Segoe Fluent Icons with the web UI's code points.
  The title bar follows Vigil's theme.
- **Processes**, end to end: live once a second from `vigil-sys` (one sampler thread, idle while no live page is
  open); Grouped (Apps / Background / Windows processes, Task Manager's grouping ported from
  `process-groups.ts`), Tree and List views; a `DataTable` with sortable, resizable columns, two-line headers
  with the computer's totals, the heat map, finding marks from the last report, rows that hold their order
  while the pointer is over the list, search on every word; the detail panel; End task (Delete key too; a group
  ends every process of the app), Efficiency mode, Suspend / Resume, Open file location and Verify signature,
  all through `vigil_core::service::run_action` and the native confirmation.
- **Performance** (first slice): CPU and memory in Task Manager's layout, 60-second area charts drawn on a
  canvas with the resource hue, statistics in large figures.
- **i18n**: see below. **Tests**: 16 unit tests (grouping, sorting, holding the order, the filter, the tree,
  number formats in every language, plural rules, catalog completeness, the security boundary).

Checked by hand: the demo in light and dark, English and Spanish; real data (524 processes); End task on a
`ping` child started for the purpose, with Vigil's data folder redirected to a scratch folder: Delete → native
dialog owned by the window (owner disabled while open) → confirmed → the process ended → journal record
`process.terminate` written → result shown in the InfoBar.

### Strings in Rust

Decision: keep the web UI's catalog format, in JSON. `crates/vigil-gpui/locales/{en,es,fr,pt,zh}.json` use the
same dotted keys, `{name}` placeholders and plural objects (`{"one": …, "other": …}`) as `ui/src/lib/i18n/*.ts`,
so the 1,300 existing keys and their translations carry over mechanically. `t("key")`, `tf("key", &[("name",
value)])` and `tn("key", count, …)` look them up (CLDR cardinal rules for the five languages; French and
Brazilian Portuguese treat 0 as singular; missing entries fall back to English). Numbers, percentages and sizes
are formatted per language as `Intl` did (`1,234.5` / `12.345` / `1 234,5`, `12 %`). The language is
`vigil_i18n::language()`, so the interface and the core's texts always agree. Texts produced by the core
(findings, action labels, confirmations) keep using `vigil_i18n::tr!` with English templates.

Tests: every catalog has exactly the English keys, and every key the code uses exists. The prototype carries the
109 keys it uses plus 4 of its own. For the rest: convert all TS catalogs once with a small converter (a Node
script fits the current toolchain), then make the JSON the source and delete the TS catalogs with the Svelte UI.
A later step can generate a `Key` enum from `en.json` in a build script so a wrong key fails to compile, as
TypeScript does today.

## 4. Measurements

Both release builds from this branch (`npx tauri build --no-bundle` for `vigil.exe` 1.4.0, `cargo build --release
-p vigil-gpui`), same machine (8-core / 16-thread desktop CPU, Windows 11 build 26300, about 520 processes
running), never elevated (`--no-elevate` for the Tauri build), Vigil's data folder redirected to a scratch
folder for both (so no report is loaded and nothing of the user's data is read). Startup: median of five runs
after one warm-up. Memory: summed over the process tree 10 s after the page opened. CPU: process-tree CPU
time over the next 30 s. The Tauri app was taken to its Processes page through the WebView2 debugging port; the
native one was started on it with `--page processes`.

| | Tauri + Svelte (`vigil.exe`) | GPUI prototype (`vigil-gpui.exe`) |
|---|---|---|
| Release executable | 20.4 MB (19.4 MiB), plus the WebView2 runtime | 26.2 MB (25.0 MiB), nothing else |
| Processes at run time | 7 (Vigil + 6 WebView2) | 1 |
| Startup, window visible | 495 ms | 254 ms |
| Startup, content drawn | 510 ms | 290 ms |
| Idle on the start page: private memory / working set | 253.6 MB / 454.3 MB | 86.8 MB / 65.6 MB |
| Idle CPU | 3.7% of one core | 1.5% of one core |
| Processes page, live: private memory / working set | 338.6 MB / 531.8 MB | 108.6 MB / 86.8 MB |
| Processes page, live: CPU | 7.2% of one core (0.45% of the machine) | 2.8% of one core (0.18% of the machine) |
| Release build | 3 min 41 s (Vite + Rust, dependencies cached) | 7 min 15 s (fat LTO, dependencies cached) |

Notes:

- The native Processes page does less than the Svelte one (no program icons, menus or inspector tabs yet), so a
  complete port will cost somewhat more memory and CPU than measured here. The working-set sum of the Tauri tree
  counts pages shared between WebView2 processes more than once; private memory is the fairer comparison.
- The Tauri window is created hidden and shown once the page has loaded, so "visible" and "content" are close;
  GPUI shows the window and draws the first frame right after.
- Idle, GPUI keeps two threads waking every frame interval (about 0.7% of one core each); the process has 67
  threads, most of them GPUI's background executor pool, idle.
- Build cost: the first debug build of gpui-kit alone took 1 min 45 s (401 crates); the first release build of a
  window 3 min 43 s. With both front ends, `target/` holds about 18 GB (debug) and 3.5 GB (release).
- Size: GPUI, gpui-component, AccessKit and the image and SVG stack are statically linked. Dropping the `assets`
  feature (the bundled SVG icon set, if every icon comes from Segoe Fluent Icons) and size-oriented settings for the UI crates
  are the levers; the Tauri executable relies on the WebView2 runtime that Windows provides.

## 5. Risks

1. **Maturity and churn.** gpui-kit is 0.10 and GPUI is published as `gpui-pre` snapshots (pinned
   `=0.3.12`); APIs break between minor versions, and there is a second engine (`gpui-fast`). Mitigation: pin
   exact versions, upgrade on purpose with the screenshot and UI tests, keep Vigil's own thin layer (theme,
   icons, table helpers, the Ui bridge) so an upgrade touches few places.
2. **One vendor.** Longbridge maintains gpui-kit on top of GPUI snapshots from another upstream. If either stalls, Vigil carries the
   code. The Apache-2.0 licence allows vendoring.
3. **Accessibility.** WebView2 exposed the DOM to UI Automation for free. In GPUI only annotated elements exist
   for Narrator. Every custom control (navigation items, command bar buttons, segmented controls, tiles, charts)
   needs a role, a name and states; test with Narrator and a UI Automation inspector before release. Plain text is
   not selectable unless drawn with the selectable text component.
4. **Mica and Windows quirks.** Mica needs build 22621+ (Windows 10 and 21H2 get the solid fallback). GPUI resets
   the title bar to Windows' theme when Windows switches theme; Vigil re-applies its own. Text over translucent
   layers is grayscale. The renderer needs Direct3D 11 (WARP on GPU-less VMs). Release builds need `fxc.exe`.
5. **Look.** gpui-component has its own web-like style. A Fluent look means restyling through `Theme` and drawing some
   controls with `div`s (as the prototype does for the NavigationView, the command bar and the segmented
   control). Menus and flyouts are drawn by the app, as in the web UI (no system acrylic).
6. **Live tables.** The table selects by row index; with rows that move every second the selection must be kept
   by key (done in the prototype, with scrolling to a process chosen elsewhere). Keyboard navigation of the table
   follows its own index selection and needs the same treatment.
7. **WebView-only features.** There is no in-app HTML viewer to lose: reports are exported as HTML by
   `vigil-scan` and open in the browser, unchanged. What changes: `localStorage` choices (compact navigation,
   process view) move to a small UI state file; `color-mix` and the system `AccentColor` become Rust; the
   browser preview and Playwright checks are replaced (section 7).
8. **Process boundary.** The UI now runs inside the elevated process. A UI bug can crash Vigil (no separate
   renderer). Keep panics out of UI code (no `unwrap`), as in the core.
9. **Effort.** Every page is a rewrite (section 6); the Svelte UI is about 10,600 lines.

## 6. Plan, page by page

Estimates are focused days for one developer who knows the codebase, after phase 2's foundations.

| Area | Today (Svelte) | What it needs | Days |
|---|---|---|---|
| Shell | `App.svelte`, `Sidebar.svelte` | Done in the prototype; add More flyout, InfoBadges, the watch line, Restart as administrator, remembered compact state, notices | 2 |
| Overview | 251 + Tile, VerdictStrip, Readouts, WatchCard | cards, tiles, verdict strip | 3 |
| Findings | 196 + FindingDetail 212 | list and detail, actions per finding, ignore | 4 |
| Alerts | 181 | list, filters, mark read, watch settings | 2 |
| Protection | 422 | switches, scan progress events, exclusions, threats | 4 |
| Firewall rules | 375 | large table, filters, flags | 3 |
| Quarantine | 67 | table, restore / delete | 1 |
| History | 103 | grouped table, undo | 1.5 |
| Performance | 408 + LineChart, Sparkline, StackedBar, CoreGrid | Slice done; add disks, network, GPUs, 1/2/5 min ranges, shared cursor, pause, core grid, memory composition, "using the most" lists | 4 |
| Processes | 359 + ProcessTable 480 + dialogs | Core done; add Priority / File / More menus, context menu, inspector tabs (modules, services), program icons, affinity and Run new task dialogs, keyboard selection, a command bar that drops its labels when narrow (French overflows at 1,280 px) | 4 |
| Network | 109 | table | 1.5 |
| Services | 280 | table, filters, start / stop / start type | 2.5 |
| Optimize | 285 | readouts, stacked bar, tuning actions | 3 |
| Startup apps | 308 | table, signatures read in the background | 2.5 |
| Scheduled tasks | 471 | table with details, flags | 3.5 |
| Installed programs | 408 | table, signatures, uninstall | 3 |
| Storage | 271 + Treemap, UsageBar | treemap on a canvas, progress events, cleanup | 5 |
| System | 200 | hardware readouts | 2 |
| Reliability | 577 | timeline chart, grouped lists | 4 |
| Dialogs | Scan, Consent, Settings (377), Results, About | forms, selects, password fields for API keys, AI provider checks | 5 |
| Platform | tray, notifications, single copy, close to tray, `--tray`, file dialogs | Shell_NotifyIcon, the existing toasts, IFileDialog | 4 |
| Demo data | `mock*.ts` (about 1,100 lines) | port to `demo.rs` (or shared JSON fixtures) | 3 |
| Tests and screenshots | Playwright | gpui-kit UI tests, screenshot command | 2 |
| Strings | 1,300 keys | convert, test, generated keys | 1 |
| Packaging and CI | `tauri build`, NSIS | icon and version resource, NSIS script, signing, workflows | 2 |
| **Total** | | | **about 74 days**, plus 20% contingency |

Order: platform pieces and the Processes / Performance remainder first (they prove menus, dialogs and the tray),
then the table pages (Services, Startup, Tasks, Programs, Firewall, Network, Quarantine, History), then Findings
and Overview, then Storage and Reliability (custom canvas work), dialogs, and finally removing Tauri.

## 7. Replacing the browser preview and the Playwright checks

- `--demo` shows every page with fictitious data (jdoe, PC-VICTIM, Contoso, Fabrikam, Woodgrove, Tailspin)
  and reads nothing: no data folder, no counters, no process list, no actions. Phase 2 ports `mock.ts` and
  `mock-pages.ts` into it.
- `--page`, `--theme`, `--lang` and `--pid` open any page in any theme and language, so a screenshot needs no
  clicks. A capture script (PrintWindow with `PW_RENDERFULLCONTENT`, which includes Mica and DirectComposition
  content) saves the window without moving the mouse; a later step can add a `--screenshot FILE` option that
  renders the scene to an image.
- Behaviour: gpui-kit's UI integration tests (`test-support`: `#[gpui_kit::test]`, headless windows, real hit
  testing, key presses, `ElementSnapshot` with accessibility roles and states) replace the Playwright flows and
  run in `cargo test`.
- Screenshots of real data still show real processes: look, then delete them.

## 8. What changes in AGENTS.md and the workflows

When the native window replaces the Tauri one:

- Commands: drop `npm ci / run dev / check / build` and `npx tauri build`; add `cargo run -p vigil-gpui -- --demo`
  (preview), `cargo run -p vigil-gpui` (real data, never elevated in debug), `--elevate` as today, and the
  screenshot command.
- Layout: `vigil-core` (shared service layer), `vigil-gpui` (the window; renamed `vigil-app` once Tauri goes);
  remove `ui/`.
- Ground rule 3 names `vigil_core::service::run_action` as the only path, and the front-end crate must not depend
  on `vigil-actions` (tested).
- Ground rule 6: replace the Svelte / CSP wording with "system text is always drawn as plain text; never give it
  to a component that interprets markup or links".
- Strings: `crates/vigil-gpui/locales/*.json` instead of `ui/src/lib/i18n/*.ts`; the completeness tests.
- UI conventions: tokens in `vigil-gpui/src/theme.rs` (same colour meaning), icons in `icons.rs` (check that a
  glyph renders), every custom control gets an accessibility role and name, live data through the `Live` entity.
- Checking the UI: `--demo` plus the capture script instead of Vite and Playwright.
- CI: no Node; `cargo fmt`, `clippy -D warnings`, `cargo test --workspace` stay; add a release build of the
  window (the runner's Windows SDK provides `fxc.exe`).
- Release: build `vigil-gpui` in release as `vigil.exe` with Vigil's icon and version resource, package with
  NSIS directly (no WebView2 bootstrapper needed any more), keep `SHA256SUMS.txt` and the draft release.

## 9. Recommendation

**Go, for a phase 2 that brings a few pages to full parity before committing to the whole port.**

The prototype answers the open questions: gpui-kit builds and runs on Windows with MSVC; Mica, the native title
bar with snap layouts, Segoe UI Variable and Segoe Fluent Icons look as the Tauri app does in both themes; the
virtualized table handles 500+ live rows; the security model moves over unchanged through `vigil-core`; and the
native window starts in half the time with about a third of the memory and less than half the CPU, as one process
without WebView2. The costs are a rewrite of every page (about 74 days), a pre-1.0 dependency that must be pinned
and upgraded on purpose, accessibility work that the web view used to do for free, and a 6 MB larger executable.

Phase 2:

1. Foundations: a small Fluent control set in `vigil-gpui` (command bar button, menu flyout, segmented control,
   InfoBar, switch, checkbox, select, dialog skin), each with its accessibility role and name; the remembered UI
   state; all strings converted; `--demo` fed by the full mock data; gpui-kit UI tests; a screenshot command.
2. Platform: tray icon and close to tray, `--tray`, toast activation, single copy, Restart as administrator, file
   dialogs, window placement, the system accent colour.
3. Parity: finish Processes and Performance, then Services, Startup apps, Quarantine and History, which together
   exercise every pattern the remaining pages need (tables with live data, menus, dialogs, events, undo).
4. Check: a Narrator and UI Automation pass, the measurements again on the finished pages, and a
   go/no-go for the rest of the port and for retiring Tauri.
