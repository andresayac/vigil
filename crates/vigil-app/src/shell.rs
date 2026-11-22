//! The window's content: a Windows 11 NavigationView (hamburger, sections, items with a selection
//! pill, footer with the rights, More and Settings) over the Mica base, and the content layer with a
//! rounded top-left corner. It also carries
//! out what the tray, a notification or a second copy asks ([`Command`]).

use std::path::PathBuf;
use std::sync::Arc;

use gpui_kit::component::menu::{DropdownMenu as _, PopupMenuItem};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    AnyView, App, AppContext, ClickEvent, Context, Entity, FontWeight, InteractiveElement, IntoElement, ParentElement,
    PathPromptOptions, Render, Role, StatefulInteractiveElement, Styled, Subscription, Window, div, px,
};
use vigil_core::requests::Request;
use vigil_core::state::AppState;
use vigil_core::watch::Watcher;

use crate::app::{Ctx, Report};
use crate::i18n::{t, tf};
use crate::icons;
use crate::live::Live;
use crate::pages::common::{self, Acting, Acts};
use crate::pages::history::HistoryPage;
use crate::pages::performance::PerformancePage;
use crate::pages::processes::ProcessesPage;
use crate::pages::quarantine::QuarantinePage;
use crate::pages::services::ServicesPage;
use crate::pages::startup::StartupPage;
use crate::palette::Palette;
use crate::platform::Command;
use crate::search::{self as find, Entry, Target};
use crate::theme::{self, Choice, FONT_BODY, Tokens, tokens};
use crate::ui::kit::J as _;
use crate::ui::{self, FButton, Kind, Severity};
use gpui_kit::base::Selectable as _;

/// (key, section) of every page, in the order of the navigation pane.
pub const PAGES: [(&str, &str); 24] = [
    ("overview", "nav.security"),
    ("findings", "nav.security"),
    ("alerts", "nav.security"),
    ("protection", "nav.security"),
    ("posture", "nav.security"),
    ("firewall", "nav.security"),
    ("accounts", "nav.security"),
    ("extensions", "nav.security"),
    ("quarantine", "nav.security"),
    ("history", "nav.security"),
    ("performance", "nav.live"),
    ("processes", "nav.live"),
    ("network", "nav.live"),
    ("services", "nav.live"),
    ("optimize", "nav.maintenance"),
    ("startup", "nav.maintenance"),
    ("tasks", "nav.maintenance"),
    ("programs", "nav.maintenance"),
    ("storage", "nav.maintenance"),
    ("restore", "nav.maintenance"),
    ("system", "nav.maintenance"),
    ("updates", "nav.maintenance"),
    ("power", "nav.maintenance"),
    ("reliability", "nav.maintenance"),
];

/// Element ids of the navigation items (GPUI ids are static strings or numbers).
const NAV_IDS: [&str; 24] = [
    "nav-overview",
    "nav-findings",
    "nav-alerts",
    "nav-protection",
    "nav-posture",
    "nav-firewall",
    "nav-accounts",
    "nav-extensions",
    "nav-quarantine",
    "nav-history",
    "nav-performance",
    "nav-processes",
    "nav-network",
    "nav-services",
    "nav-optimize",
    "nav-startup",
    "nav-tasks",
    "nav-programs",
    "nav-storage",
    "nav-restore",
    "nav-system",
    "nav-updates",
    "nav-power",
    "nav-reliability",
];

/// Pages that read live data (the sampler runs only while one is open).
fn is_live(page: &str) -> bool {
    matches!(page, "performance" | "processes" | "overview" | "optimize" | "system")
}

/// The page key for a name a notification or the command line gives (unknown: Alerts).
pub fn page_key(name: &str) -> &'static str {
    PAGES
        .iter()
        .map(|(key, _)| *key)
        .find(|key| *key == name)
        .unwrap_or("alerts")
}

/// How the window starts (from the command line).
pub struct Options {
    pub page: &'static str,
    /// `--pid`: the process the Processes page selects first.
    pub focus_pid: Option<u32>,
    /// `--item`: the finding the Findings page selects first.
    pub focus_item: Option<String>,
    /// `--dialog`: a dialog to open at start (settings, scan, run), for previews.
    pub dialog: Option<String>,
    pub demo: bool,
    pub choice: Choice,
    pub mica: bool,
    pub watcher: Option<Arc<Watcher>>,
}

pub struct Shell {
    page: &'static str,
    compact: bool,
    pub live: Entity<Live>,
    core: Option<Arc<AppState>>,
    demo: bool,
    elevated: bool,
    choice: Choice,
    mica: bool,
    watcher: Option<Arc<Watcher>>,
    pub report: Entity<Report>,
    content: Option<AnyView>,
    /// `--pid`: the process the Processes page selects first.
    focus_pid: Option<u32>,
    acting: Acting,
    /// An InfoBar over the content (an exported report, a refused restart).
    notice: Option<(Severity, String)>,
    /// The command palette (Ctrl+K) while it is open.
    palette: Option<Entity<Palette>>,
    _subscriptions: Vec<Subscription>,
}

impl Acts for Shell {
    fn acting(&mut self) -> &mut Acting {
        &mut self.acting
    }
    fn core(&self) -> Option<Arc<AppState>> {
        self.core.clone()
    }
    fn after(&mut self, _: &mut Window, _: &mut Context<Self>) {}
}

impl Shell {
    pub fn new(options: Options, core: Option<Arc<AppState>>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let Options {
            page,
            focus_pid,
            focus_item,
            dialog,
            demo,
            choice,
            mica,
            watcher,
        } = options;
        let live = Live::start(demo, cx);
        let report = cx.new(|cx| {
            let mut report = Report {
                focus: focus_item.map(crate::app::Focus::Item),
                ..Report::default()
            };
            if demo {
                report.set_analysis(Some(crate::data::demo("analysis")));
                report.loaded = true;
            } else {
                Report::reload(core.clone(), cx);
            }
            report
        });
        // Defender scans Vigil started report their progress (the Protection page shows it).
        if core.is_some() {
            let (tx, mut rx) = futures::channel::mpsc::unbounded::<serde_json::Value>();
            vigil_core::protection::start_monitor(move |event| {
                let _ = tx.unbounded_send(serde_json::to_value(event).unwrap_or_default());
            });
            let target = report.clone();
            cx.spawn(async move |_, cx| {
                use futures::StreamExt as _;
                while let Some(event) = rx.next().await {
                    target.update(cx, |r, cx| {
                        r.defender_scan = Some(event);
                        cx.notify();
                    });
                }
            })
            .detach();
        }
        // Windows changed its theme: GPUI has just painted the title bar in Windows' theme, so
        // apply Vigil's again (it may be a fixed light or dark), with Windows' accent colour.
        let subscriptions = vec![
            cx.observe_window_appearance(window, |this, window, cx| {
                this.apply_theme(window, cx);
            }),
            cx.observe(&report, |_, _, cx| cx.notify()),
            {
                // Ctrl+K anywhere in the window, and the palette's keys while it is open (its text
                // box would otherwise keep Up, Down and Enter), before any control sees them.
                let shell = cx.entity().downgrade();
                cx.intercept_keystrokes(move |event, window, cx| {
                    let keystroke = event.keystroke.clone();
                    let used = shell
                        .update(cx, |shell, cx| shell.palette_key(&keystroke, window, cx))
                        .unwrap_or(false);
                    if used {
                        cx.stop_propagation();
                    }
                })
            },
        ];
        let mut shell = Self {
            page,
            compact: false,
            live,
            core,
            demo,
            // The demo shows the administrator view (its actions still never run).
            elevated: demo || vigil_sys::elevation::is_elevated(),
            choice,
            mica,
            watcher,
            report,
            content: None,
            focus_pid,
            acting: Acting::default(),
            notice: None,
            palette: None,
            _subscriptions: subscriptions,
        };
        // The data folder could not be fully restricted to administrators: say so.
        shell.notice = shell
            .core
            .as_ref()
            .and_then(|c| c.warning.clone())
            .map(|w| (Severity::Warning, w));
        shell.apply_theme(window, cx);
        shell.open(page, window, cx);
        if let Some(dialog) = dialog {
            cx.defer_in(window, move |shell, window, cx| match dialog.as_str() {
                "settings" => shell.open_settings(window, cx),
                "scan" => shell.scan_dialog(window, cx),
                "run" => {
                    let ctx = shell.ctx(cx);
                    crate::dialogs::run_task(ctx, window, cx);
                }
                // `search` or `search=<text>`: the command palette, with that text typed.
                other if other == "search" || other.starts_with("search=") => {
                    shell.open_palette(window, cx);
                    if let (Some(text), Some(palette)) = (other.strip_prefix("search="), shell.palette.clone()) {
                        let text = text.to_string();
                        palette.update(cx, |palette, cx| palette.set_query(&text, window, cx));
                    }
                }
                _ => {}
            });
        }
        shell
    }

    fn apply_theme(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let dark = match self.choice {
            Choice::Dark => true,
            Choice::Light => false,
            Choice::System => matches!(
                window.appearance(),
                gpui_kit::WindowAppearance::Dark | gpui_kit::WindowAppearance::VibrantDark
            ),
        };
        let mut tokens = if dark {
            Tokens::dark(self.mica)
        } else {
            Tokens::light(self.mica)
        };
        // The demo keeps Fluent's default accent, so its screenshots look the same everywhere.
        if !self.demo
            && let Some(accent) = crate::platform::accent(dark)
        {
            tokens.set_accent(accent);
        }
        theme::apply(tokens, cx);
        crate::win::set_dark_title_bar(window, dark);
        window.refresh();
    }

    /// What a page needs from the app.
    pub fn ctx(&self, cx: &mut Context<Self>) -> Ctx {
        Ctx {
            core: self.core.clone(),
            elevated: self.elevated,
            watcher: self.watcher.clone(),
            report: self.report.clone(),
            live: self.live.clone(),
            shell: cx.entity().downgrade(),
        }
    }

    /// The New scan dialog (not while a scan runs).
    pub fn scan_dialog(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.report.read(cx).scanning {
            return;
        }
        let ctx = self.ctx(cx);
        crate::dialogs::scan(ctx, window, cx);
    }

    pub fn open(&mut self, page: &'static str, window: &mut Window, cx: &mut Context<Self>) {
        self.page = page;
        let ctx = self.ctx(cx);
        let live = self.live.clone();
        let core = self.core.clone();
        let elevated = self.elevated;
        self.content = match page {
            "processes" => {
                let pid = self.focus_pid.take();
                Some(
                    cx.new(|cx| {
                        let mut page = ProcessesPage::new(live, core, pid, elevated, window, cx);
                        page.ctx = Some(ctx);
                        page
                    })
                    .into(),
                )
            }
            "performance" => {
                let shell = cx.entity().downgrade();
                let on_show: crate::pages::performance::ShowProcess = std::rc::Rc::new(move |pid, window, cx| {
                    let _ = shell.update(cx, |shell, cx| {
                        shell.focus_pid = Some(pid);
                        shell.open("processes", window, cx);
                    });
                });
                Some(cx.new(|cx| PerformancePage::new(live, core, on_show, cx)).into())
            }
            "services" => Some(cx.new(|cx| ServicesPage::new(core, elevated, window, cx)).into()),
            "startup" => Some(cx.new(|cx| StartupPage::new(core, elevated, window, cx)).into()),
            "quarantine" => Some(cx.new(|cx| QuarantinePage::new(core, elevated, window, cx)).into()),
            "history" => Some(cx.new(|cx| HistoryPage::new(core, elevated, window, cx)).into()),
            "overview" => Some(cx.new(|cx| crate::pages::overview::OverviewPage::new(ctx, cx)).into()),
            "findings" => Some(
                cx.new(|cx| crate::pages::findings::FindingsPage::new(ctx, window, cx))
                    .into(),
            ),
            "accounts" => Some(cx.new(|cx| crate::pages::accounts::AccountsPage::new(ctx, cx)).into()),
            "firewall" => Some(
                cx.new(|cx| crate::pages::firewall::FirewallPage::new(ctx, window, cx))
                    .into(),
            ),
            "posture" => Some(cx.new(|cx| crate::pages::posture::PosturePage::new(ctx, cx)).into()),
            "protection" => Some(
                cx.new(|cx| crate::pages::protection::ProtectionPage::new(ctx, cx))
                    .into(),
            ),
            "alerts" => Some(cx.new(|cx| crate::pages::alerts::AlertsPage::new(ctx, cx)).into()),
            "extensions" => Some(
                cx.new(|cx| crate::pages::extensions::ExtensionsPage::new(ctx, window, cx))
                    .into(),
            ),
            "network" => Some(
                cx.new(|cx| crate::pages::network::NetworkPage::new(ctx, window, cx))
                    .into(),
            ),
            "tasks" => Some(cx.new(|cx| crate::pages::tasks::TasksPage::new(ctx, window, cx)).into()),
            "programs" => Some(
                cx.new(|cx| crate::pages::programs::ProgramsPage::new(ctx, window, cx))
                    .into(),
            ),
            "optimize" => Some(cx.new(|cx| crate::pages::optimize::OptimizePage::new(ctx, cx)).into()),
            "storage" => Some(cx.new(|cx| crate::pages::storage::StoragePage::new(ctx, cx)).into()),
            "restore" => Some(
                cx.new(|cx| crate::pages::restore::RestorePage::new(ctx, window, cx))
                    .into(),
            ),
            "system" => Some(cx.new(|cx| crate::pages::system::SystemPage::new(ctx, cx)).into()),
            "updates" => Some(cx.new(|cx| crate::pages::updates::UpdatesPage::new(ctx, cx)).into()),
            "power" => Some(cx.new(|cx| crate::pages::power::PowerPage::new(ctx, cx)).into()),
            "reliability" => Some(
                cx.new(|cx| crate::pages::reliability::ReliabilityPage::new(ctx, cx))
                    .into(),
            ),
            _ => None,
        };
        let active = is_live(page);
        self.live.update(cx, |live, cx| live.set_active(active, cx));
        cx.notify();
    }

    /// Carries out what the tray, a notification or a second copy asked.
    pub fn command(&mut self, command: Command, window: &mut Window, cx: &mut Context<Self>) {
        match command {
            Command::Open => self.show(window, cx),
            Command::OpenPage(page) => {
                self.show(window, cx);
                self.open(page_key(&page), window, cx);
            }
            Command::Scan => {
                self.show(window, cx);
                self.open("overview", window, cx);
                self.scan_dialog(window, cx);
            }
            Command::ToggleWatching => {
                if let Some(watcher) = &self.watcher
                    && watcher.set_watching(None)
                {
                    watcher.check_soon();
                }
                crate::platform::Tray::refresh();
            }
            Command::ToggleNotifications => {
                if let Some(watcher) = &self.watcher {
                    let paused = watcher.store.load().notifications_paused(vigil_core::watch::now_ms());
                    watcher.pause_notifications(!paused);
                }
                crate::platform::Tray::refresh();
            }
            Command::Quit => {
                crate::platform::remove_icon();
                // A running automatic scan stops at its next step.
                vigil_core::autoscan::cancel();
                cx.quit();
            }
            Command::Refresh => self.report.update(cx, |r, cx| {
                r.watch_tick += 1;
                cx.notify();
            }),
        }
    }

    /// Shows and focuses the window (it may be hidden in the tray); live pages sample again.
    fn show(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        crate::win::show(window);
        window.activate_window();
        self.live.update(cx, |live, cx| live.set_visible(true, cx));
    }

    /// The close button: hides the window and keeps watching in the tray when the settings say
    /// so (this copy owns the watch). Returns whether the window may close.
    pub fn should_close(&mut self, window: &mut Window, cx: &mut Context<Self>) -> bool {
        let Some(watcher) = self.watcher.clone() else {
            return true;
        };
        let settings = watcher.settings();
        if !watcher.owner() || !settings.close_to_tray {
            crate::platform::remove_icon();
            vigil_core::autoscan::cancel();
            return true;
        }
        crate::win::hide(window);
        self.live.update(cx, |live, cx| live.set_visible(false, cx));
        if !settings.tray_notice_shown {
            let _ = watcher.store.update(|file| file.settings.tray_notice_shown = true);
            let language = watcher.language();
            vigil_core::watch::in_language(&language, || {
                crate::platform::notify(
                    &vigil_i18n::tr!("Vigil keeps watching in the tray"),
                    &vigil_i18n::tr!(
                        "Open it or quit from its icon in the notification area. You can change this in Settings."
                    ),
                    "overview",
                );
            });
        }
        false
    }

    /// "Open report…": a saved `*-report.json` becomes the current report. Outside this copy's own
    /// scans folder it is opened to look at only (the core plans nothing from it), and every page
    /// reads the new report at once.
    fn open_report(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(core) = self.core.clone() else {
            self.notice = Some((Severity::Info, t("app.demoNoActions")));
            cx.notify();
            return;
        };
        let picked = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some(t("menu.openReport").into()),
        });
        cx.spawn_in(window, async move |this, cx| {
            let Ok(Ok(Some(paths))) = picked.await else { return };
            let Some(path) = paths.into_iter().next() else { return };
            let reader = Arc::clone(&core);
            let result = cx
                .background_spawn(async move { vigil_core::api::open_report(&reader, &path) })
                .await;
            let _ = this.update(cx, |shell, cx| {
                shell.notice = Some(match &result {
                    Ok(view) if view.as_ref().is_some_and(|v| v.get("viewOnly").is_some()) => {
                        (Severity::Warning, t("app.reportOpenedViewOnly"))
                    }
                    Ok(_) => (Severity::Success, t("app.reportOpened")),
                    Err(error) => (Severity::Error, error.clone()),
                });
                // The pages drop what they showed of the previous report (items, plans).
                if result.is_ok() {
                    let core = Some(Arc::clone(&core));
                    shell.report.update(cx, |_, cx| crate::app::Report::reload(core, cx));
                }
                cx.notify();
            });
        })
        .detach();
    }

    /// "Export HTML report…": the current report as a standalone HTML file.
    fn export_html(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let report = self.core.as_ref().map(|core| core.report_html());
        let (html, name) = match report {
            Some(Ok(found)) => found,
            Some(Err(error)) => {
                self.notice = Some((Severity::Error, error));
                cx.notify();
                return;
            }
            None => {
                self.notice = Some((Severity::Info, t("app.demoNoActions")));
                cx.notify();
                return;
            }
        };
        let documents = std::env::var_os("USERPROFILE")
            .map(|p| PathBuf::from(p).join("Documents"))
            .unwrap_or_default();
        let picked = cx.prompt_for_new_path(&documents, Some(&name));
        cx.spawn_in(window, async move |this, cx| {
            let Ok(Ok(Some(path))) = picked.await else { return };
            let shown = path.display().to_string();
            let result = std::fs::write(&path, html).map_err(|e| format!("Could not write the report: {e}"));
            let _ = this.update(cx, |shell, cx| {
                shell.notice = Some(match result {
                    Ok(()) => (Severity::Success, tf("menu.exported", &[("path", &shown)])),
                    Err(error) => (Severity::Error, error),
                });
                cx.notify();
            });
        })
        .detach();
    }

    /// Asks Windows for administrator rights (UAC); on success the elevated copy starts and this
    /// one quits. Declining keeps this copy as it is.
    fn restart_elevated(&mut self, cx: &mut Context<Self>) {
        // The elevated copy waits for this one (`--after`), so it never finds the window taken.
        let me = std::process::id().to_string();
        match vigil_sys::elevation::relaunch_elevated(&["--elevated", "--after", &me]) {
            Ok(true) => {
                crate::platform::release_window_mutex();
                crate::platform::remove_icon();
                // A running automatic scan stops at its next step.
                vigil_core::autoscan::cancel();
                cx.quit();
            }
            Ok(false) => {}
            Err(error) => {
                self.notice = Some((Severity::Error, error.to_string()));
                cx.notify();
            }
        }
    }

    fn tool(&mut self, op: &str, window: &mut Window, cx: &mut Context<Self>) {
        let request = Request::Tuning {
            op: op.into(),
            params: serde_json::json!({}),
        };
        common::send(self, request, window, cx);
    }

    fn shell_request(
        &mut self,
        op: &str,
        url: Option<&str>,
        name: Option<&str>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let request = Request::Shell {
            op: op.into(),
            path: None,
            url: url.map(str::to_string),
            name: name.map(str::to_string),
        };
        common::send(self, request, window, cx);
    }

    fn open_settings(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let ctx = self.ctx(cx);
        crate::settings_ui::open(ctx, window, cx);
    }

    /// Settings were saved: the theme and the language apply now (the page is drawn again in the
    /// language).
    pub fn apply_settings(&mut self, choice: Choice, window: &mut Window, cx: &mut Context<Self>) {
        self.choice = choice;
        self.apply_theme(window, cx);
        let page = self.page;
        self.open(page, window, cx);
    }

    /// What the palette can find now: the pages, the processes of the last live sample, the loaded
    /// report's findings, the watch's alerts, and what the pages read last (see `search.rs`).
    fn search_entries(&self, cx: &mut Context<Self>) -> (Vec<Entry>, Vec<find::Kind>) {
        let mut entries = Vec::new();
        for (key, _) in PAGES.iter() {
            let key: &'static str = key;
            let title = t(&format!("page.{key}"));
            let english = vigil_i18n::with_language("en", || t(&format!("page.{key}")));
            entries.push(Entry::new(
                find::Kind::Page,
                &title,
                "",
                &[&english, find::page_synonyms(key)],
                Target::Page(key),
            ));
        }
        for p in &self.live.read(cx).processes {
            let title = if p.description.is_empty() {
                &p.name
            } else {
                &p.description
            };
            entries.push(Entry::new(
                find::Kind::Process,
                title,
                &format!("{} PID {}", p.name, p.pid),
                &[&p.exe, &p.user],
                Target::Process(p.pid),
            ));
        }
        if let Some(analysis) = &self.report.read(cx).analysis {
            for item in analysis.a("items") {
                let detail = if item.has("path") {
                    item.s("path")
                } else {
                    item.s("subtitle")
                };
                entries.push(Entry::new(
                    find::Kind::Finding,
                    item.s("title"),
                    detail,
                    &[item.s("subtitle"), item.s("kind"), item.s("sha256")],
                    Target::Finding(item.s("id").to_string()),
                ));
            }
        }
        if let Some(alerts) = self.ctx(cx).watch_alerts().as_array() {
            for alert in alerts.iter().take(200) {
                entries.push(Entry::new(
                    find::Kind::Alert,
                    alert.s("title"),
                    alert.s("detail"),
                    &[alert.s("target")],
                    Target::Page("alerts"),
                ));
            }
        }
        let (mut remembered, missing) = find::remembered();
        entries.append(&mut remembered);
        (entries, missing)
    }

    /// Opens the command palette (Ctrl+K or the search button).
    fn open_palette(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.palette.is_some() {
            return;
        }
        let (entries, missing) = self.search_entries(cx);
        let shell = cx.entity().downgrade();
        let closing = shell.clone();
        let on_pick: crate::palette::OnPick = std::rc::Rc::new(move |target, window, cx| {
            let _ = shell.update(cx, |shell, cx| shell.pick(target, window, cx));
        });
        let on_close: crate::palette::OnClose = std::rc::Rc::new(move |_, cx| {
            let _ = closing.update(cx, |shell, cx| {
                shell.palette = None;
                cx.notify();
            });
        });
        self.palette = Some(cx.new(|cx| Palette::new(entries, missing, on_pick, on_close, window, cx)));
        cx.notify();
    }

    /// Ctrl+K opens (or closes) the palette; while it is open, Up, Down, Page Up, Page Down, Enter
    /// and Escape are its. True when the key was used.
    fn palette_key(&mut self, keystroke: &gpui_kit::Keystroke, window: &mut Window, cx: &mut Context<Self>) -> bool {
        let m = &keystroke.modifiers;
        if keystroke.key == "k" && m.control && !m.alt && !m.shift && !m.platform {
            if self.palette.take().is_some() {
                cx.notify();
            } else {
                self.open_palette(window, cx);
            }
            return true;
        }
        let Some(palette) = self.palette.clone() else {
            return false;
        };
        if m.control || m.alt || m.platform {
            return false;
        }
        match keystroke.key.as_str() {
            "escape" => {
                self.palette = None;
                cx.notify();
                true
            }
            "enter" => {
                let target = palette.read(cx).selected_target();
                if let Some(target) = target {
                    self.pick(target, window, cx);
                }
                true
            }
            key => palette.update(cx, |palette, cx| palette.key(key, cx)),
        }
    }

    /// Opens a palette result on its page. Nothing runs: it only shows the item.
    fn pick(&mut self, target: Target, window: &mut Window, cx: &mut Context<Self>) {
        self.palette = None;
        match target {
            Target::Page(page) => self.open(page, window, cx),
            Target::Process(pid) => {
                self.focus_pid = Some(pid);
                self.open("processes", window, cx);
            }
            Target::Finding(id) => {
                self.report
                    .update(cx, |r, _| r.focus = Some(crate::app::Focus::Item(id)));
                self.open("findings", window, cx);
            }
            Target::Seek { page, text } => {
                // The page's search box starts with the item's name (see `grid::seed`).
                find::set_seed(Some(text));
                self.open(page, window, cx);
                find::set_seed(None);
            }
        }
        cx.notify();
    }

    fn more_menu(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let compact = self.compact;
        let tk = *tokens(cx);
        let shell = cx.entity().downgrade();
        let mut button = FButton::new("nav-more", Kind::Subtle)
            .glyph(icons::MORE)
            .w_full()
            .justify_start()
            .gap(px(14.))
            .pl(px(14.))
            .text_color(tk.ink);
        if !compact {
            button = button.label(t("nav.more"));
        }
        button.dropdown_menu(move |menu, _, _| {
            let item = |label: String, run: fn(&mut Shell, &mut Window, &mut Context<Shell>)| {
                let shell = shell.clone();
                PopupMenuItem::new(label).on_click(move |_, window, cx| {
                    let _ = shell.update(cx, |shell, cx| run(shell, window, cx));
                })
            };
            menu.item(item(t("menu.openReport"), |s, w, cx| s.open_report(w, cx)))
                .item(item(t("menu.exportHtml"), |s, w, cx| s.export_html(w, cx)))
                .separator()
                .item(item(t("menu.restorePoint"), |s, w, cx| {
                    s.tool("system.restore_point", w, cx)
                }))
                .item(item(t("menu.defenderFullScan"), |s, w, cx| {
                    s.tool("defender.full_scan", w, cx)
                }))
                .item(item(t("menu.defenderUpdate"), |s, w, cx| {
                    s.tool("defender.update", w, cx)
                }))
                .separator()
                .item(item(t("menu.windowsSecurity"), |s, w, cx| {
                    s.shell_request("url", Some("windowsdefender://"), None, w, cx)
                }))
                .item(item(t("menu.taskScheduler"), |s, w, cx| {
                    s.shell_request("console", None, Some("taskschd.msc"), w, cx)
                }))
                .item(item(t("menu.services"), |s, w, cx| {
                    s.shell_request("console", None, Some("services.msc"), w, cx)
                }))
                .item(item(t("menu.eventViewer"), |s, w, cx| {
                    s.shell_request("console", None, Some("eventvwr.msc"), w, cx)
                }))
                .separator()
                .item(item(t("menu.about"), |_, w, cx| crate::dialogs::about(w, cx)))
        })
    }

    fn render_nav(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let compact = self.compact;
        // The scan in progress, and when the loaded report was made.
        let (scanning, last_scan) = {
            let report = self.report.read(cx);
            let last = match report.analysis.as_ref().map(|a| a.at("meta")) {
                Some(meta) => {
                    let key = if meta.b("is_admin") {
                        "nav.lastScan"
                    } else {
                        "nav.lastScanReadOnly"
                    };
                    tf(key, &[("when", &crate::pages::common::when(meta.s("started")))])
                }
                None => t("nav.noScanYet"),
            };
            (report.scanning, last)
        };
        let item = |id: &'static str, glyph: char, label: String, active: bool| {
            let mut button = FButton::new(id, Kind::Subtle)
                .glyph(glyph)
                .role(Role::Button)
                .selected(active)
                .relative()
                .flex_none()
                .w_full()
                .h(px(36.))
                .justify_start()
                .gap(px(14.))
                .pl(px(14.))
                .pr(px(12.))
                .text_color(tk.ink);
            if compact {
                button = button.accessible_name(label);
            } else {
                button = button.label(label);
            }
            button.when(active, |this| {
                this.child(
                    div()
                        .absolute()
                        .left(px(0.))
                        .top(px(10.))
                        .w(px(3.))
                        .h(px(16.))
                        .rounded(px(2.))
                        .bg(tk.accent),
                )
            })
        };

        let mut list = div()
            .id("nav-list")
            .role(Role::List)
            .aria_label(t("nav.navigation"))
            .flex()
            .flex_col()
            .gap(px(2.))
            .flex_1()
            .min_h_0()
            .overflow_y_scroll();
        let mut previous = "";
        for (index, (key, section)) in PAGES.iter().enumerate() {
            if *section != previous {
                previous = section;
                list = list.child(if compact {
                    div().h(px(1.)).mx(px(10.)).my(px(6.)).bg(tk.rule).flex_none()
                } else {
                    div()
                        .px(px(14.))
                        .pt(px(10.))
                        .pb(px(4.))
                        .text_size(px(12.))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(tk.ink2)
                        .flex_none()
                        .child(t(section))
                });
            }
            let key: &'static str = key;
            list = list.child(
                item(
                    NAV_IDS[index],
                    icons::page(key),
                    t(&format!("page.{key}")),
                    self.page == key,
                )
                .on_click(cx.listener(move |this, _: &ClickEvent, window, cx| this.open(key, window, cx))),
            );
        }

        let status = (!compact).then(|| {
            let (color, title, note) = if self.elevated {
                (tk.ok, t("nav.administrator"), t("nav.administratorNote"))
            } else {
                (tk.warn, t("nav.readOnly"), t("nav.readOnlyNote"))
            };
            let watch_line = self.watcher.as_ref().map(|w| {
                let status = w.status();
                let (text, dot) = if !status.owner {
                    (t("watch.otherWindow"), tk.ink3)
                } else if status.watching {
                    (t("app.watchOn"), tk.ok)
                } else {
                    (t("watch.paused"), tk.warn)
                };
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .text_size(px(12.))
                    .text_color(tk.ink2)
                    .child(div().w(px(8.)).h(px(8.)).rounded(px(4.)).bg(dot))
                    .child(text)
            });
            div()
                .flex()
                .flex_col()
                .gap(px(6.))
                .px(px(14.))
                .pt(px(8.))
                .pb(px(10.))
                .mb_1()
                .border_t_1()
                .border_color(tk.rule)
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .text_size(px(13.))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(color)
                        .child(icons::icon(icons::SHIELD, 14.0, color))
                        .child(title),
                )
                .child(div().text_size(px(12.)).text_color(tk.ink3).child(note))
                .when(!self.elevated && !self.demo, |this| {
                    this.child(
                        ui::button("restart-elevated", t("nav.restartElevated"))
                            .on_click(cx.listener(|this, _, _, cx| this.restart_elevated(cx))),
                    )
                })
                .children(watch_line)
                .when(self.demo, |this| {
                    this.child(div().text_size(px(12.)).text_color(tk.ink3).child(t("app.demo")))
                })
        });

        div()
            .flex()
            .flex_col()
            .flex_none()
            .w(px(if compact { 56. } else { 260. }))
            .h_full()
            .p_1()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(6.))
                    .h(px(44.))
                    .child(
                        ui::icon_button(
                            "hamburger",
                            icons::HAMBURGER,
                            t(if compact { "nav.expand" } else { "nav.collapse" }),
                        )
                        .w(px(40.))
                        .h(px(36.))
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.compact = !this.compact;
                            cx.notify();
                        })),
                    )
                    .when(!compact, |this| {
                        this.child(div().text_size(px(12.)).text_color(tk.ink2).child("Vigil"))
                            .child(div().flex_1())
                            .child(
                                ui::icon_button("nav-search", icons::SEARCH, t("palette.button"))
                                    .tip(t("palette.button"))
                                    .w(px(40.))
                                    .h(px(36.))
                                    .on_click(cx.listener(|this, _, window, cx| this.open_palette(window, cx))),
                            )
                    }),
            )
            .when(compact, |this| {
                this.child(
                    div().pb_1().child(
                        ui::icon_button("nav-search", icons::SEARCH, t("palette.button"))
                            .tip(t("palette.button"))
                            .w(px(40.))
                            .h(px(36.))
                            .on_click(cx.listener(|this, _, window, cx| this.open_palette(window, cx))),
                    ),
                )
            })
            .child(div().px_1().pb_2().flex().child({
                let label = t(if scanning { "nav.scanning" } else { "nav.newScan" });
                let mut scan = FButton::new("new-scan", Kind::Accent)
                    .glyph(icons::SCAN)
                    .disabled(scanning)
                    .flex_1()
                    .h(px(34.));
                if compact {
                    scan = scan.accessible_name(label).tip(last_scan.clone());
                } else {
                    scan = scan.label(label);
                }
                scan.on_click(cx.listener(|this, _, window, cx| {
                    this.open("overview", window, cx);
                    this.scan_dialog(window, cx);
                }))
            }))
            .when(!compact, |this| {
                this.child(
                    div()
                        .px_2()
                        .pb_2()
                        .text_size(px(12.))
                        .text_color(tk.ink3)
                        .child(last_scan.clone()),
                )
            })
            .child(list)
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(2.))
                    .pt(px(6.))
                    .children(status)
                    .child(self.more_menu(cx))
                    .child(
                        item("nav-settings", icons::SETTINGS, t("nav.settings"), false)
                            .on_click(cx.listener(|this, _, window, cx| this.open_settings(window, cx))),
                    ),
            )
    }
}

impl Render for Shell {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let body = match &self.content {
            Some(view) => view.clone().into_any_element(),
            None => div().into_any_element(),
        };
        let notice = self.notice.clone().map(|(severity, text)| {
            div()
                .absolute()
                .top(px(12.))
                .right(px(20.))
                .w(px(560.))
                .child(ui::info_bar(
                    "shell-notice",
                    severity,
                    text,
                    Some(Box::new({
                        let shell = cx.entity().downgrade();
                        move |_, cx: &mut App| {
                            let _ = shell.update(cx, |shell, cx| {
                                shell.notice = None;
                                cx.notify();
                            });
                        }
                    })),
                    &tk,
                ))
        });
        let acting = self
            .acting
            .bar("shell-result", &tk)
            .map(|bar| div().absolute().bottom(px(16.)).right(px(20.)).w(px(560.)).child(bar));
        let palette = self.palette.clone();
        div()
            .relative()
            .size_full()
            .flex()
            .bg(tk.canvas)
            .text_color(tk.ink)
            .font_family(FONT_BODY)
            .text_size(px(14.))
            .line_height(px(20.))
            .child(self.render_nav(cx))
            .child(
                div()
                    .relative()
                    .flex_1()
                    .min_w_0()
                    .h_full()
                    .bg(tk.layer)
                    .border_t_1()
                    .border_l_1()
                    .border_color(tk.layer_stroke)
                    .rounded_tl(px(8.))
                    .overflow_hidden()
                    .child(body)
                    .children(notice)
                    .children(acting),
            )
            .children(palette)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notifications_open_known_pages_only() {
        assert_eq!(page_key("startup"), "startup");
        assert_eq!(page_key("posture"), "posture");
        assert_eq!(page_key("<script>"), "alerts");
    }

    #[test]
    fn every_page_has_an_id_and_a_title() {
        for ((key, _), id) in PAGES.iter().zip(NAV_IDS) {
            assert_eq!(id, format!("nav-{key}"));
            assert!(!vigil_i18n::with_language("en", || t(&format!("page.{key}"))).is_empty());
        }
    }
}
