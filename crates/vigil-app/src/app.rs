//! What the pages share: the loaded report (and the scan that makes it), the watch's state, the
//! rights, and a way to move to another page. Pages hold a [`Ctx`] and observe its [`Report`].

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt as _;
use futures::channel::mpsc;
use gpui_kit::{App, AppContext as _, Context, Entity, WeakEntity, Window};
use serde_json::{Value, json};
use vigil_core::state::AppState;
use vigil_core::watch::Watcher;

use crate::data::{self, Src};
use crate::i18n::tf;
use crate::shell::Shell;
use crate::ui::kit::J as _;

/// What the Findings page shows first (from Overview, Processes or Alerts).
#[derive(Debug, Clone)]
pub enum Focus {
    Item(String),
    Items(Vec<String>, String),
    Verdict(String),
}

/// The loaded report and the scan in progress.
#[derive(Default)]
pub struct Report {
    pub analysis: Option<Value>,
    /// Bumped each time `analysis` is replaced (see [`Report::set_analysis`]): pages keep what they
    /// derive from the report (sorted items) until it changes, instead of every frame.
    pub revision: u64,
    pub ignored: Vec<String>,
    pub loaded: bool,
    pub scanning: bool,
    /// The heading of the scan in progress (an i18n key).
    pub title: &'static str,
    pub log: Vec<String>,
    pub error: Option<String>,
    /// Bumped when the watch's state changes: pages that show it read it again.
    pub watch_tick: u64,
    /// What the Findings page should select when it opens.
    pub focus: Option<Focus>,
    /// The last progress event of a Defender scan Vigil started.
    pub defender_scan: Option<Value>,
}

impl Report {
    /// Replaces the loaded report.
    pub fn set_analysis(&mut self, analysis: Option<Value>) {
        self.analysis = analysis;
        self.revision = self.revision.wrapping_add(1);
    }

    pub fn is_ignored(&self, id: &str) -> bool {
        self.ignored.iter().any(|i| i == id)
    }

    /// The report's items that are not ignored.
    pub fn visible(&self) -> Vec<&Value> {
        self.analysis
            .as_ref()
            .map(|a| a.a("items").iter().filter(|i| !self.is_ignored(i.s("id"))).collect())
            .unwrap_or_default()
    }

    /// Reads the current report and the ignored findings again.
    pub fn reload(core: Option<Arc<AppState>>, cx: &mut Context<Self>) {
        let task = cx.background_spawn(async move {
            let analysis = data::fetch(core.as_ref(), Src::Report);
            let ignored = data::fetch(core.as_ref(), Src::Ignored);
            (analysis, ignored)
        });
        cx.spawn(async move |this, cx| {
            let (analysis, ignored) = task.await;
            let _ = this.update(cx, |report, cx| {
                match analysis {
                    Ok(Value::Null) => report.set_analysis(None),
                    Ok(value) => report.set_analysis(Some(value)),
                    Err(error) => report.error = Some(error),
                }
                if let Ok(Value::Array(ids)) = ignored {
                    report.ignored = ids.iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
                }
                report.loaded = true;
                cx.notify();
            });
        })
        .detach();
    }
}

/// What a page needs from the app.
#[derive(Clone)]
pub struct Ctx {
    pub core: Option<Arc<AppState>>,
    pub elevated: bool,
    pub watcher: Option<Arc<Watcher>>,
    pub report: Entity<Report>,
    pub live: Entity<crate::live::Live>,
    pub shell: WeakEntity<Shell>,
}

impl Ctx {
    pub fn demo(&self) -> bool {
        self.core.is_none()
    }

    /// Opens another page.
    pub fn go(&self, page: &str, window: &mut Window, cx: &mut App) {
        let page = crate::shell::page_key(page);
        let _ = self.shell.update(cx, |shell, cx| shell.open(page, window, cx));
    }

    /// Opens Findings on `focus`.
    pub fn find(&self, focus: Focus, window: &mut Window, cx: &mut App) {
        self.report.update(cx, |r, _| r.focus = Some(focus));
        self.go("findings", window, cx);
    }

    /// Opens the New scan dialog.
    pub fn scan_dialog(&self, window: &mut Window, cx: &mut App) {
        let _ = self.shell.update(cx, |shell, cx| shell.scan_dialog(window, cx));
    }

    /// The watch's state as the pages read it (camelCase), or the demo's.
    pub fn watch_status(&self) -> Option<Value> {
        match (&self.watcher, self.demo()) {
            (Some(w), _) => serde_json::to_value(w.status()).ok(),
            (None, true) => Some(data::demo("watchStatus")),
            (None, false) => None,
        }
    }

    /// Every alert kept, newest first.
    pub fn watch_alerts(&self) -> Value {
        match &self.watcher {
            Some(w) => serde_json::to_value(w.store.load().alerts).unwrap_or(json!([])),
            None if self.demo() => data::demo("watchAlerts"),
            None => json!([]),
        }
    }

    /// Changes the watch (Vigil's own file only), then lets the tray and the pages know.
    pub fn watch_change(
        &self,
        change: impl FnOnce(&Watcher) -> Result<(), String>,
        cx: &mut App,
    ) -> Result<(), String> {
        let Some(watcher) = &self.watcher else {
            return Ok(());
        };
        let result = change(watcher);
        crate::platform::Tray::refresh();
        self.report.update(cx, |r, cx| {
            r.watch_tick += 1;
            cx.notify();
        });
        result
    }

    /// Marks alerts read (`None`: all).
    pub fn mark_read(&self, ids: Option<Vec<u64>>, cx: &mut App) {
        let _ = self.watch_change(
            |w| {
                w.store.update(|file| {
                    for alert in &mut file.alerts {
                        if ids.as_ref().is_none_or(|ids| ids.contains(&alert.id)) {
                            alert.read = true;
                        }
                    }
                })
            },
            cx,
        );
    }

    pub fn set_watching(&self, on: bool, cx: &mut App) {
        let _ = self.watch_change(
            |w| {
                if w.set_watching(Some(on)) {
                    w.check_soon();
                }
                Ok(())
            },
            cx,
        );
    }

    pub fn pause_notifications(&self, pause: bool, cx: &mut App) {
        let _ = self.watch_change(
            |w| {
                w.pause_notifications(pause);
                Ok(())
            },
            cx,
        );
    }
}

/// Runs a scan: collects and rates, offers the AI review (the consent dialog), then finishes and
/// saves the report. The log lines arrive in the Report as they come.
pub fn start_scan(ctx: &Ctx, days: u32, virustotal: bool, use_ai: bool, window: &mut Window, cx: &mut App) {
    let report = ctx.report.clone();
    if report.read(cx).scanning {
        return;
    }
    report.update(cx, |r, cx| {
        r.scanning = true;
        r.error = None;
        r.log.clear();
        r.title = "scan.titleScanning";
        cx.notify();
    });
    let (tx, rx) = mpsc::unbounded::<String>();
    follow_log(&report, rx, cx);
    let core = ctx.core.clone();
    let task = cx.background_spawn(async move {
        let send = |line: &str| {
            let _ = tx.unbounded_send(line.to_string());
        };
        match core {
            Some(st) => vigil_core::api::scan_collect(&st, days, virustotal, &send)
                .and_then(|offer| serde_json::to_value(offer).map_err(|e| e.to_string())),
            None => {
                for line in [
                    "Collecting startup entries",
                    "Collecting services and scheduled tasks",
                    "Reading the event logs",
                    "Applying the local rules",
                ] {
                    send(line);
                    std::thread::sleep(Duration::from_millis(350));
                }
                Ok(data::demo("reviewOffer"))
            }
        }
    });
    let ctx = ctx.clone();
    window
        .spawn(cx, async move |cx| {
            let result = task.await;
            let _ = cx.update(|window, cx| match result {
                Err(error) => ctx.report.update(cx, |r, cx| {
                    r.error = Some(error);
                    r.scanning = false;
                    cx.notify();
                }),
                Ok(offer) => {
                    let ask = use_ai && offer.has("destination") && offer.n("pending") > 0.0;
                    if ask {
                        crate::dialogs::consent(ctx.clone(), offer, window, cx);
                    } else {
                        if use_ai && offer.has("problem") {
                            let line = tf("scan.aiUnavailable", &[("problem", offer.s("problem"))]);
                            ctx.report.update(cx, |r, _| r.log.push(line));
                        }
                        finish_scan(&ctx, false, use_ai, crate::win::hwnd(window), cx);
                    }
                }
            });
        })
        .detach();
}

/// Finishes the scan waiting for the AI decision (`review`: with the AI review). Before anything is
/// sent, the core confirms in its own native dialog, owned by `owner` (the main window).
pub fn finish_scan(ctx: &Ctx, review: bool, selected: bool, owner: isize, cx: &mut App) {
    let report = ctx.report.clone();
    report.update(cx, |r, cx| {
        r.title = if review {
            "scan.titleReviewing"
        } else {
            "scan.titleSaving"
        };
        cx.notify();
    });
    let (tx, rx) = mpsc::unbounded::<String>();
    follow_log(&report, rx, cx);
    let core = ctx.core.clone();
    let task = cx.background_spawn(async move {
        let send = |line: &str| {
            let _ = tx.unbounded_send(line.to_string());
        };
        match core {
            Some(st) => {
                let analysis = vigil_core::api::scan_finish(&st, review, selected, owner, &send);
                let ignored = vigil_core::api::ignored_list(&st);
                analysis.map(|a| (a, ignored))
            }
            None => {
                std::thread::sleep(Duration::from_millis(400));
                Ok((data::demo("analysis"), Vec::new()))
            }
        }
    });
    cx.spawn(async move |cx| {
        let result = task.await;
        report.update(cx, |r, cx| {
            match result {
                Ok((analysis, ignored)) => {
                    r.set_analysis(Some(analysis));
                    r.ignored = ignored;
                }
                Err(error) => r.error = Some(error),
            }
            r.scanning = false;
            r.loaded = true;
            cx.notify();
        });
    })
    .detach();
}

/// Appends the lines of `rx` to the scan log (the last 400 are kept).
fn follow_log(report: &Entity<Report>, mut rx: mpsc::UnboundedReceiver<String>, cx: &mut App) {
    let report = report.clone();
    cx.spawn(async move |cx| {
        while let Some(line) = rx.next().await {
            report.update(cx, |r, cx| {
                if r.log.len() >= 400 {
                    r.log.remove(0);
                }
                r.log.push(line);
                cx.notify();
            });
        }
    })
    .detach();
}
