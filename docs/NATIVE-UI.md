# The window

Vigil should look and behave like a Windows 11 app, such as Task Manager: a Mica backdrop, a NavigationView with a
hamburger, Segoe UI Variable, Fluent controls, and a Performance page with the resource list on the left and the
selected resource on the right. The window is drawn natively with **gpui-kit** (pinned at `=0.10.0` with its
GPUI snapshot `gpui-pre =0.3.12`): a GPU-rendered, retained-mode UI in Rust, so the window, the core and the
action engine are one language and one process.

## Why gpui-kit

| | gpui-kit | WinUI 3 / XAML | Slint | egui / iced |
|---|---|---|---|---|
| From Rust | Yes | No supported XAML authoring from Rust; the UI would be C# or C++ | Yes | Yes |
| Windows 11 look | Mica, native title bar, Fluent tokens drawn by Vigil | Exact | WinUI-like widgets, no Mica | Own look |
| Large lists | Virtualized `DataTable` and lists | Yes | Partial | Immediate-mode redraws |
| Accessibility | Every element with a role becomes a UI Automation element (accesskit), with name, state and focus | Best | Partial | Weak |
| Keeps the security model | Yes: the window hands typed requests to `vigil-core` | Needs a cross-language API | Yes | Yes |

## What the window does

- **Window.** Mica on Windows 11 (`WindowBackgroundAppearance::MicaBackdrop`); the base and the navigation pane
  are transparent and the content layer is a translucent card with a rounded top-left corner, as WinUI's
  NavigationView draws it. On Windows 10 the window keeps solid Fluent backgrounds. One window per session: a
  second start shows the first one.
- **Title bar: native decorations, kept on purpose.** A custom title bar loses the snap layouts flyout on the
  maximize button, native caption-button behaviour, the system menu and part of accessibility. Over Mica the
  native title bar already blends with the window. Vigil paints it dark or light with
  `DWMWA_USE_IMMERSIVE_DARK_MODE`, so "Dark" in Settings gives a dark title bar even when Windows is light.
- **Tokens** (`crates/vigil-app/src/theme.rs`). WinUI 3 metrics and roles in the palette of Vigil's logo: deep
  teal `#035568`, emerald `#03C488` and mint `#7DFABD`, with teal-tinted neutrals for the layers, cards, controls
  and strokes. The accent is the deep teal on light and the emerald on dark; `brand` (emerald on light, mint on
  dark) marks the selected page and the logo only. Vigil does not take the Windows accent colour: the window looks
  the same on every computer and no accent can clash with the verdict colours. Over Mica the bases stay nearly
  opaque, so the wallpaper does not tint the palette. Radii are 4 (controls) and 8 (cards, flyouts, dialogs).
  Type ramp: Title 28, Subtitle 20, Body 14, Caption 12, in Segoe UI Variable; monospace text in Cascadia Mono;
  icons from Segoe Fluent Icons. The tokens are also projected onto gpui-component's theme, so its table, inputs,
  menus and scroll bars draw with the same values.
- **Layout.** Pages read like Windows Settings, not like a web page: a page title, then sections whose title sits
  above a group of rows in one card (`kit::section`, `kit::group`). A row that opens something is a whole-row
  button with a leading glyph, a title, a line under it and a chevron (`kit::NavRow`); links are WinUI
  HyperlinkButtons (accent text, a faint fill under the pointer, no underline) for secondary commands only.
  Notices (InfoBars) sit above the page and push it down; they never float over it.
- **Colour still carries meaning.** Verdict colours only for verdicts, and `ok`, `warn` and `bad` only for state.
  Each resource has its own hue for live measurements: CPU blue, memory purple, disk green, network orange, GPU
  teal, as in Task Manager. The accent is used only for interactive elements.
- **Controls** (`crates/vigil-app/src/ui`). Buttons (standard, accent, subtle, command bar, with icons, menus and
  tooltips), the toggle switch, the check box, the segmented control, the InfoBar, the search box, chips, links,
  badges and pills, read-outs, meters, a stacked bar chart and a virtualized grid keyed by row identity. They are
  built on gpui-base's primitives, so focus, Tab order, Enter/Space, the disabled state and the accessible role,
  name and state come from the framework.
- **NavigationView** (`shell.rs`): a hamburger collapses the pane to an icon rail; the selected item has an accent
  pill; the footer has the administrator status (with "Restart as administrator"), "More" (open a report, export
  HTML, restore point, Defender, Windows tools, About) and "Settings". The pane lists eight sections (`SECTIONS`),
  not pages: the content layer shows the section's title (Title, 28 px) with an **Ask** button that opens the
  Assistant about the current page, and, for a section with several pages, a TabView-like row of tabs with the
  brand pill under the selected one. Pages no longer draw their own title (`ui::page_title` keeps only its slot).
- **Performance** in Task Manager's layout: the resource list with live thumbnails framed in the resource hue,
  and the selected resource with its chart (labels around the plot, a resource-tinted grid), the memory
  composition bar, the statistics in large figures and the hardware facts; 1, 2 and 5 minute ranges, Pause, and
  the processes using the resource most.
- **Charts.** Live lines are painted on a canvas; the day charts (sign-ins, reliability) are stacked bars with a
  tooltip per day, and the space analysis is a squarified treemap you can drill into. Each chart is a named group
  for screen readers, and each bar or tile a named element.
- **Text.** Everything is drawn as plain text. Details that are useful to copy (paths, command lines, hashes,
  messages, AI conclusions) are selectable; Copy buttons put a whole description on the clipboard.

## Dialogs

In-window dialogs (New scan, the AI review consent, Settings, Run new task, Processor affinity) are gpui-component
dialogs on a solid flyout surface. Confirmations of changes stay native Windows task dialogs shown by the core,
owned by the window (security model).

## Previews

`vigil --demo --page <key>` opens any page with the fictitious data of `crates/vigil-app/data/demo.json` (jdoe,
PC-VICTIM, Contoso, documentation addresses); it reads nothing and changes nothing. `--item ID` selects a finding,
`--dialog settings|scan|run` opens a dialog, `--size WxH`, `--theme light|dark` and `--lang CODE` set the rest.

## Limits

- Mica appears only on Windows 11 with transparency effects on; otherwise Windows draws the solid base colour.
- Menus, flyouts and dialogs are drawn by the window: they follow Fluent metrics but not, for example, the acrylic
  of system menus.
- Release builds compile the window's shaders with `fxc.exe` from the Windows SDK.
