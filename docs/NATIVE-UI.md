# A Windows-native look for Vigil

Goal: Vigil should look and behave like a Windows 11 app, such as Task Manager. That means a Mica backdrop,
a NavigationView with a hamburger, Segoe UI Variable, Fluent controls, and a Performance page with the
resource list on the left and the selected resource on the right.

## Options

| | (a) Tauri 2 + WebView2, Fluent styling | (b1) WinUI 3 / Windows App SDK | (b2) Win32 + XAML Islands | (b3) Slint, `fluent` style | (b4) egui / iced |
|---|---|---|---|---|---|
| Looks native | Very close: real Mica, real title bar and caption buttons, Fluent tokens and type ramp | Exact | Exact | Close (WinUI-like widgets, no Mica) | No (own look) |
| From Rust | Yes (current stack) | No supported XAML authoring in windows-rs; needs C# or C++/WinRT for the UI | Hosting is possible, but authoring XAML from Rust is unsupported and fragile | Yes | Yes |
| Rewrite cost | Restyle only (CSS + a few components) | Rewrite the whole UI in another language, plus an FFI layer to the Rust core | Same as WinUI, with more plumbing | Rewrite every page in `.slint` | Rewrite every page |
| What we keep | Svelte UI, browser preview with mock data, CSP, request-and-confirm security model, every page | Rust crates only | Rust crates only | Rust crates; lose the browser preview and the HTML report reuse | Rust crates; same losses |
| Risk | Low | High (two languages, Windows App SDK runtime, packaging) | High | Medium (charts, virtualized tree and treemap to rebuild) | Medium, and not native |
| Accessibility | WebView2 exposes the DOM to UI Automation | Best | Good | Partial | Weak |

The two paths where the UI is written in XAML (WinUI 3 and XAML Islands) have the same weakness. The UI layer
would become C# or C++, and the security boundary (the UI asks, Rust rebuilds the action and confirms it) would
have to be designed again as a cross-language API. Slint or egui would throw away a finished UI for a result
that looks no more native than (a).

**Recommendation: (a).** Keep Tauri and adopt Windows 11 Fluent design. This is what is implemented.

## What (a) does

- **Window.** `tauri.conf.json` sets `"transparent": true` and `"windowEffects": { "effects": ["mica"] }`. On
  Windows 11 the page marks itself `data-backdrop="mica"`, so the base and the navigation pane are transparent
  and the content layer is translucent, as in WinUI's NavigationView. On Windows 10 (no Mica) and in the browser
  preview, the page keeps solid Fluent backgrounds (`--canvas`). Windows 11 is detected through
  `navigator.userAgentData` (platform version 13 or later).
- **Title bar: native decorations, kept on purpose.** A custom title bar (`decorations: false`) loses the snap
  layouts flyout on the maximize button. It also loses native caption-button behaviour, the system menu and
  part of accessibility, unless Rust answers `WM_NCHITTEST` with `HTMAXBUTTON` itself. The native title bar,
  over Mica, already blends with the window. The page asks Tauri to switch the title bar and Mica to Vigil's
  theme with `setTheme` (permission `core:window:allow-set-theme`), so "Dark" in Settings gives a dark title bar
  even when Windows is light.
- **Tokens** (`ui/src/app.css`). WinUI 3 values for light and dark: layer, card and control fills, strokes with
  a darker bottom edge, subtle hover and pressed fills. Accent `#005FB8` (light) and `#60CDFF` (dark); the
  system `AccentColor` is used where the web view supports it. Radii are 4 (controls) and 8 (cards, flyouts,
  dialogs). Type ramp: Title 28, Subtitle 20, Body 14, Caption 12, in Segoe UI Variable. Focus is a 2 px
  outline, scroll bars are thin, and the Fluent dialog, flyout and InfoBar styles are used.
- **Colour still carries meaning.** Verdict colours (now Fluent's critical, caution and success hues) are used
  only for verdicts, and `--ok`, `--warn` and `--bad` only for state. Each resource has its own hue for live
  measurements: CPU blue, memory purple, disk green, network orange, GPU teal, as in Task Manager. The accent is
  used only for interactive elements.
- **NavigationView** (`Sidebar.svelte`):
  - a hamburger collapses the pane to a 56 px icon rail, and the choice is remembered in `localStorage`
    (guarded with try/catch);
  - the selected item has an accent pill;
  - section headers become dividers in the rail;
  - InfoBadges show counts;
  - the footer has the administrator status, "More" (a flyout with the ⋯ entries) and "Settings".
- **Performance** in Task Manager's layout:
  - Left, the resource list: a live thumbnail framed in the resource hue, and two lines (for example
    "20.6 GB/64.0 GB (32%)", "SSD (NVMe)", "S: 464 Kbps R: 5.8 Mbps").
  - Right, the selected resource: a 28 px title and the model on the right ("64.0 GB DDR5", the CPU model, the
    disk model), then the chart with labels around the plot ("% Utilization" and "100%" above, "60 seconds"
    and "0" below), a resource-tinted grid, the memory composition bar, the statistics in large figures, and
    the hardware facts (speed, slots used, sockets, cache, driver, capacity, health).
  - The 1/2/5 min ranges, the shared cursor, Pause / "Back to live" and the "using the most" list with its
    actions are unchanged.

## Limits

- Mica appears only on Windows 11 with transparency effects on; otherwise Windows draws the solid base
  colour, which matches the fallback.
- The in-app dialogs are HTML ContentDialogs. Confirmations of changes stay native Windows task dialogs
  shown by Rust (security model).
- Native look is not native widgets: menus and dialogs are drawn by the page. They follow Fluent metrics but
  not, for example, the acrylic of system menus.
