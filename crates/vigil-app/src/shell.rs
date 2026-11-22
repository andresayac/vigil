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

/// The sections of the navigation pane, in order, with their pages. A section with more than one
/// page shows them as tabs over the content; the first is the one a section opens with.
pub const SECTIONS: [(&str, &[&str]); 8] = [
    ("home", &["overview"]),
    ("assistant", &["assistant"]),
    (
        "security",
        &["findings", "protection", "posture", "firewall", "accounts"],
    ),
    ("live", &["processes", "performance", "network", "services"]),
    ("cleanup", &["storage", "optimize"]),
    ("apps", &["startup", "programs", "tasks", "extensions"]),
    ("system", &["system", "updates", "power", "reliability"]),
    ("activity", &["history", "alerts", "quarantine", "restore"]),
];

/// (key, section) of every page, in the order of the sections and their tabs.
pub const PAGES: [(&str, &str); 25] = [
    ("overview", "home"),
    ("assistant", "assistant"),
    ("findings", "security"),
    ("protection", "security"),
    ("posture", "security"),
    ("firewall", "security"),
    ("accounts", "security"),
    ("processes", "live"),
    ("performance", "live"),
    ("network", "live"),
    ("services", "live"),
    ("storage", "cleanup"),
    ("optimize", "cleanup"),
    ("startup", "apps"),
    ("programs", "apps"),
    ("tasks", "apps"),
    ("extensions", "apps"),
    ("system", "system"),
    ("updates", "system"),
    ("power", "system"),
    ("reliability", "system"),
    ("history", "activity"),
    ("alerts", "activity"),
    ("quarantine", "activity"),
    ("restore", "activity"),
];

/// Element ids of the navigation items, one per section (GPUI ids are static strings or numbers).
const NAV_IDS: [&str; 8] = [
    "nav-home",
    "nav-assistant",
    "nav-security",
    "nav-live",
    "nav-cleanup",
    "nav-apps",
    "nav-system",
    "nav-activity",
];

/// Element ids of the tabs, one per page, in the order of [`PAGES`].
const TAB_IDS: [&str; 25] = [
    "tab-overview",
    "tab-assistant",
    "tab-findings",
    "tab-protection",
    "tab-posture",
    "tab-firewall",
    "tab-accounts",
    "tab-processes",
    "tab-performance",
    "tab-network",
    "tab-services",
    "tab-storage",
    "tab-optimize",
    "tab-startup",
    "tab-programs",
    "tab-tasks",
    "tab-extensions",
    "tab-system",
    "tab-updates",
    "tab-power",
    "tab-reliability",
    "tab-history",
    "tab-alerts",
    "tab-quarantine",
    "tab-restore",
];

/// The section a page belongs to (unknown pages: Home).
pub fn section_of(page: &str) -> &'static str {
    PAGES
        .iter()
        .find(|(key, _)| *key == page)
        .map_or("home", |(_, section)| *section)
}

/// The pages of a section, in tab order.
pub fn pages_of(section: &str) -> &'static [&'static str] {
    SECTIONS
        .iter()
        .find(|(id, _)| *id == section)
        .map_or(&[], |(_, pages)| *pages)
}

/// Pages that read live data (the sampler runs only while one is open).
fn is_live(page: &str) -> bool {
    matches!(page, "performance" | "processes" | "overview" | "optimize" | "system")
}

/// Live pages that show the process list on every sample; the others get it now and then.
fn shows_processes(page: &str) -> bool {
    matches!(page, "performance" | "processes")
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
    /// The page each section showed last: a section opens on it again.
    last: std::collections::HashMap<&'static str, &'static str>,
    /// The page the Assistant was opened from (its first question is about that page).
    pub ask_from: Option<&'static str>,
    /// The Assistant, kept while the window lives so its conversation survives moving between pages.
    assistant: Option<Entity<crate::pages::assistant::AssistantPage>>,
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
    /// A newer Vigil the update check found (Settings > General), until dismissed.
    update: Option<vigil_core::version_check::Latest>,
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
            // Minimized (not presented): the live pages stop sampling until it is shown again.
            cx.observe_window_visibility(window, |this, visibility, _, cx| {
                let shown = visibility.is_visible();
                this.live.update(cx, |live, cx| live.set_minimized(!shown, cx));
            }),
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
        // The demo shows the administrator view (its actions still never run). An elevated copy
        // whose data folder could not be made private is read-only: the standard view.
        let elevated = demo
            || core
                .as_ref()
                .map_or_else(vigil_sys::elevation::is_elevated, |c| c.admin);
        let mut shell = Self {
            page,
            last: std::collections::HashMap::new(),
            ask_from: None,
            assistant: None,
            compact: false,
            live,
            core,
            demo,
            elevated,
            choice,
            mica,
            watcher,
            report,
            content: None,
            focus_pid,
            acting: Acting::default(),
            notice: None,
            palette: None,
            update: None,
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
        // A newer Vigil found by an earlier check (in this copy or the tray copy).
        if !shell.demo {
            shell.update = shell
                .watcher
                .as_ref()
                .and_then(|w| vigil_core::version_check::offer(&w.store.load().update));
        }
        // The first-run welcome, once (not when a dialog was asked for on the command line).
        let welcome_shown = shell.watcher.as_ref().is_none_or(|w| w.settings().welcome_shown);
        if dialog.is_none() && crate::welcome::show_at_start(shell.demo, welcome_shown) {
            cx.defer_in(window, |shell, window, cx| {
                let ctx = shell.ctx(cx);
                crate::welcome::open(ctx, window, cx);
            });
        }
        if let Some(dialog) = dialog {
            cx.defer_in(window, move |shell, window, cx| match dialog.as_str() {
                "settings" => shell.open_settings(window, cx),
                "scan" => shell.scan_dialog(window, cx),
                // `welcome` or `welcome=N`: the welcome, at step N (previews of each step).
                other if other == "welcome" || other.starts_with("welcome=") => {
                    let step = other
                        .strip_prefix("welcome=")
                        .and_then(|n| n.parse::<usize>().ok())
                        .map_or(0, |n| n.saturating_sub(1));
                    let ctx = shell.ctx(cx);
                    crate::welcome::open_at(ctx, step, window, cx);
                }
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
        // Vigil's own palette (its logo's), not the Windows accent: the window looks the same on every
        // computer, and a wallpaper or accent colour cannot clash with the verdict colours.
        let tokens = if dark {
            Tokens::dark(self.mica)
        } else {
            Tokens::light(self.mica)
        };
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
        self.last.insert(section_of(page), page);
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
            "assistant" => {
                let from = self.ask_from.take().unwrap_or("");
                let page = match self.assistant.clone() {
                    Some(page) => {
                        if !from.is_empty() {
                            page.update(cx, |page, cx| page.prefill(from, window, cx));
                        }
                        page
                    }
                    None => {
                        let page = cx.new(|cx| crate::pages::assistant::AssistantPage::new(ctx, from, window, cx));
                        self.assistant = Some(page.clone());
                        page
                    }
                };
                Some(page.into())
            }
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
        let processes = shows_processes(page);
        self.live.update(cx, |live, cx| live.set_active(active, processes, cx));
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
            let result = vigil_core::export::write_user_file(&path, html.as_bytes())
                .map_err(|e| format!("Could not write the report: {e}"));
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
    pub(crate) fn restart_elevated(&mut self, cx: &mut Context<Self>) {
        if self.demo {
            self.notice = Some((Severity::Info, t("app.demoNoActions")));
            cx.notify();
            return;
        }
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

    pub(crate) fn open_settings(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let ctx = self.ctx(cx);
        crate::settings_ui::open(ctx, window, cx);
    }

    /// Shows (or hides) the bar about a newer Vigil (after "Check now" in Settings).
    pub fn set_update(&mut self, latest: Option<vigil_core::version_check::Latest>, cx: &mut Context<Self>) {
        self.update = latest;
        cx.notify();
    }

    /// Opens a release page of Vigil in the browser (the core checks the address again).
    pub fn open_release(&mut self, url: &str, window: &mut Window, cx: &mut Context<Self>) {
        self.shell_request("url", Some(url), None, window, cx);
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
                .item(item(t("menu.welcome"), |s, w, cx| {
                    let ctx = s.ctx(cx);
                    crate::welcome::open(ctx, w, cx);
                }))
                .item(item(t("menu.about"), |_, w, cx| crate::dialogs::about(w, cx)))
        })
    }

    /// The count a section's navigation item shows: findings to act on (Security), unread alerts
    /// (Activity). `true`: it asks for attention.
    fn badge(&self, section: &str, cx: &mut Context<Self>) -> Option<(String, bool)> {
        match section {
            "security" => {
                let report = self.report.read(cx);
                let count = report
                    .visible()
                    .iter()
                    .filter(|i| matches!(i.s("verdict"), "remove" | "disable"))
                    .count();
                (count > 0).then(|| (count.to_string(), true))
            }
            "activity" => {
                let unread = match &self.watcher {
                    Some(w) => w.status().unread,
                    None if self.demo => self
                        .ctx(cx)
                        .watch_alerts()
                        .as_array()
                        .map_or(0, |a| a.iter().filter(|x| !x.b("read")).count()),
                    None => 0,
                };
                (unread > 0).then(|| (unread.to_string(), false))
            }
            _ => None,
        }
    }

    /// The section's title over the content, and its pages as tabs (when it has more than one).
    fn render_header(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let section = section_of(self.page);
        let title = t(&format!("section.{section}"));
        let pages = pages_of(section);
        let tabs = (pages.len() > 1).then(|| {
            let mut row = div()
                .id("section-tabs")
                .role(Role::TabList)
                .aria_label(title.clone())
                .flex()
                .flex_wrap()
                .gap(px(4.))
                .border_b_1()
                .border_color(tk.rule);
            for page in pages.iter().copied() {
                let index = PAGES.iter().position(|(key, _)| *key == page).unwrap_or(0);
                let selected = self.page == page;
                let label = t(&format!("page.{page}"));
                row = row.child(
                    gpui_kit::base::Button::new(TAB_IDS[index])
                        .role(Role::Tab)
                        .accessibility_label(label.clone())
                        .aria_selected(selected)
                        .relative()
                        .flex()
                        .items_center()
                        .h(px(36.))
                        .px(px(10.))
                        .rounded_t(px(4.))
                        .text_size(px(14.))
                        .when(selected, |this| {
                            this.text_color(tk.ink).font_weight(FontWeight::SEMIBOLD).child(
                                div()
                                    .absolute()
                                    .bottom(px(-1.))
                                    .left(px(10.))
                                    .right(px(10.))
                                    .h(px(3.))
                                    .rounded(px(2.))
                                    .bg(tk.brand),
                            )
                        })
                        .when(!selected, move |this| {
                            this.text_color(tk.ink2).hover(move |s| s.bg(tk.hover))
                        })
                        .on_click(cx.listener(move |this, _: &ClickEvent, window, cx| this.open(page, window, cx)))
                        .child(label),
                );
            }
            row
        });
        div()
            .flex_none()
            .flex()
            .flex_col()
            .gap(px(8.))
            .px(px(28.))
            .pt(px(18.))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(12.))
                    .child(
                        div()
                            .font_family(crate::theme::FONT_DISPLAY)
                            .text_size(px(28.))
                            .line_height(px(36.))
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(title),
                    )
                    .child(div().flex_1())
                    .when(section != "assistant", |this| {
                        this.child(
                            ui::FButton::new("ask-assistant", Kind::Standard)
                                .glyph(icons::section("assistant"))
                                .label(t("assistant.ask"))
                                .tip(t("assistant.askTip"))
                                .on_click(cx.listener(|this, _: &ClickEvent, window, cx| {
                                    let from = this.page;
                                    this.ask_from = Some(from);
                                    this.open("assistant", window, cx);
                                })),
                        )
                    }),
            )
            .children(tabs)
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
                        .bg(tk.brand),
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
        let current = section_of(self.page);
        for (index, (section, pages)) in SECTIONS.iter().enumerate() {
            // Activity (what changed, and what can be undone) sits apart from the sections.
            if *section == "activity" {
                list = list.child(div().h(px(1.)).mx(px(10.)).my(px(6.)).bg(tk.rule).flex_none());
            }
            let section: &'static str = section;
            let first: &'static str = pages[0];
            let mut entry = item(
                NAV_IDS[index],
                icons::section(section),
                t(&format!("section.{section}")),
                current == section,
            );
            if !compact && let Some((count, strong)) = self.badge(section, cx) {
                entry = entry.child(
                    div()
                        .ml_auto()
                        .flex_none()
                        .px(px(7.))
                        .rounded(px(9.))
                        .text_size(px(11.))
                        .line_height(px(18.))
                        .font_weight(FontWeight::SEMIBOLD)
                        .when(strong, |this| this.bg(tk.accent).text_color(tk.on_accent))
                        .when(!strong, |this| this.bg(tk.hover).text_color(tk.ink2))
                        .child(count),
                );
            }
            list = list.child(entry.on_click(cx.listener(move |this, _: &ClickEvent, window, cx| {
                let page = this.last.get(section).copied().unwrap_or(first);
                this.open(page, window, cx);
            })));
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
            // One compact line for the state (its explanation is the tooltip), so the page list keeps
            // its room on short windows.
            let shell = cx.entity().downgrade();
            let tip_note: gpui_kit::SharedString = note.into();
            div()
                .flex()
                .flex_col()
                .gap(px(4.))
                .px(px(14.))
                .pt(px(6.))
                .pb(px(6.))
                .border_t_1()
                .border_color(tk.rule)
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .child(
                            div()
                                .id("nav-state")
                                .flex()
                                .flex_none()
                                .items_center()
                                .gap_2()
                                .text_size(px(13.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(color)
                                .tooltip(move |window, cx| {
                                    gpui_kit::component::tooltip::Tooltip::new(tip_note.clone()).build(window, cx)
                                })
                                .child(icons::icon(icons::SHIELD, 14.0, color))
                                .child(title),
                        )
                        .child(div().flex_1())
                        .when(!self.elevated && !self.demo, |this| {
                            this.child(ui::kit::link(
                                "restart-elevated",
                                t("nav.restartShort"),
                                move |_, cx| {
                                    let _ = shell.update(cx, |this, cx| this.restart_elevated(cx));
                                },
                                &tk,
                            ))
                        }),
                )
                .children(watch_line)
                .when(self.demo, |this| {
                    let demo_note: gpui_kit::SharedString = t("app.demo").into();
                    this.child(
                        div()
                            .id("nav-demo")
                            .text_size(px(12.))
                            .text_color(tk.ink3)
                            .tooltip(move |window, cx| {
                                gpui_kit::component::tooltip::Tooltip::new(demo_note.clone()).build(window, cx)
                            })
                            .child(t("app.demoShort")),
                    )
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
                        this.child(gpui_kit::img(logo()).w(px(18.)).h(px(18.)).flex_none())
                            .child(
                                div()
                                    .text_size(px(14.))
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .text_color(tk.ink)
                                    .child("Vigil"),
                            )
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

/// Vigil's logo, decoded once (the window's own file, built into the program).
fn logo() -> std::sync::Arc<gpui_kit::Image> {
    static LOGO: std::sync::OnceLock<std::sync::Arc<gpui_kit::Image>> = std::sync::OnceLock::new();
    LOGO.get_or_init(|| {
        std::sync::Arc::new(gpui_kit::Image::from_bytes(
            gpui_kit::ImageFormat::Png,
            include_bytes!("../icons/icon.png").to_vec(),
        ))
    })
    .clone()
}

impl Render for Shell {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let body = match &self.content {
            Some(view) => view.clone().into_any_element(),
            None => div().into_any_element(),
        };
        // Notices sit above the page and push it down: they never cover what the page shows.
        let notice = self.notice.clone().map(|(severity, text)| {
            div().child(ui::info_bar(
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
        // A newer Vigil: its version, a link to the release page, and a close button.
        let update = self.update.clone().map(|latest| {
            let shell = cx.entity().downgrade();
            let open = {
                let shell = shell.clone();
                let url = latest.url.clone();
                Box::new(move |window: &mut Window, cx: &mut App| {
                    let _ = shell.update(cx, |shell, cx| shell.open_release(&url, window, cx));
                }) as ui::OnClose
            };
            div().child(ui::info_bar_with(
                "shell-update",
                Severity::Info,
                tf("update.available", &[("version", &latest.version)]),
                Some((t("update.openRelease").into(), open)),
                Some(Box::new(move |_, cx: &mut App| {
                    let _ = shell.update(cx, |shell, cx| {
                        shell.update = None;
                        cx.notify();
                    });
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
                    .flex()
                    .flex_col()
                    .when(notice.is_some() || update.is_some(), |this| {
                        this.child(
                            div()
                                .flex_none()
                                .flex()
                                .flex_col()
                                .gap_2()
                                .px(px(28.))
                                .pt(px(12.))
                                .children(notice)
                                .children(update),
                        )
                    })
                    .child(self.render_header(cx))
                    .child(div().flex_1().min_h_0().child(body))
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
        for ((key, _), id) in PAGES.iter().zip(TAB_IDS) {
            assert_eq!(id, format!("tab-{key}"));
            assert!(!vigil_i18n::with_language("en", || t(&format!("page.{key}"))).is_empty());
        }
        for ((section, _), id) in SECTIONS.iter().zip(NAV_IDS) {
            assert_eq!(id, format!("nav-{section}"));
            assert!(!vigil_i18n::with_language("en", || t(&format!("section.{section}"))).is_empty());
        }
    }

    #[test]
    fn every_page_is_in_one_section_in_order() {
        let flat: Vec<(&str, &str)> = SECTIONS
            .iter()
            .flat_map(|(section, pages)| pages.iter().map(move |page| (*page, *section)))
            .collect();
        assert_eq!(flat, PAGES.to_vec());
        assert_eq!(section_of("firewall"), "security");
        assert_eq!(pages_of("cleanup"), ["storage", "optimize"]);
    }
}
