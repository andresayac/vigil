//! How the background watch is shown: its state line, relative times, the alerts' look, and the
//! Watching section of Overview.

use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{AnyElement, App, ElementId, FontWeight, Hsla, IntoElement, ParentElement, Styled, Window, div, px};
use serde_json::Value;

use crate::app::Ctx;
use crate::format::{now_ms, num};
use crate::i18n::{t, tf, tn};
use crate::icons;
use crate::pages::common::when;
use crate::theme::Tokens;
use crate::ui::kit::{self, J as _};

/// "just now", "5 min ago", "3 h ago", "2 d ago".
pub fn since(ms: i64) -> String {
    if ms <= 0 {
        return String::new();
    }
    let seconds = ((now_ms() - ms) / 1000).max(0);
    if seconds < 45 {
        return t("watch.justNow");
    }
    let age = if seconds < 3600 {
        tf("time.minutesShort", &[("n", &num((seconds / 60).max(1) as f64, 0))])
    } else if seconds < 86_400 {
        tf("time.hoursShort", &[("n", &num((seconds / 3600) as f64, 0))])
    } else {
        tf("time.daysShort", &[("n", &num((seconds / 86_400) as f64, 0))])
    };
    tf("proc.startedAgo", &[("age", &age)])
}

/// A moment: the time if it is today, else the date and time.
pub fn clock(ms: i64) -> String {
    let iso = kit::local_iso(ms);
    let today = kit::local_iso(now_ms());
    if iso.get(..10) == today.get(..10) {
        iso.get(11..16).unwrap_or("").to_string()
    } else {
        when(&iso)
    }
}

/// The state line: another window watches, paused, last check, starting.
pub fn state_line(s: &Value) -> String {
    if !s.b("owner") {
        t("watch.otherWindow")
    } else if !s.b("watching") {
        t("watch.paused")
    } else if s.has("lastCheck") {
        tf("watch.checked", &[("when", &since(s.i("lastCheck")))])
    } else {
        t("watch.starting")
    }
}

/// The dot next to the state line.
pub fn state_color(s: &Value, tk: &Tokens) -> Hsla {
    match (s.b("owner"), s.b("watching")) {
        (true, true) => tk.ok,
        (true, false) => tk.warn,
        _ => tk.ink3,
    }
}

/// An alert's glyph and colour by severity.
pub fn severity_look(severity: &str, tk: &Tokens) -> (char, Hsla) {
    match severity {
        "critical" => (icons::ERROR, tk.bad),
        "warning" => (icons::WARNING, tk.warn),
        _ => (icons::INFO, tk.ink2),
    }
}

/// The page an alert opens, if it names one.
pub fn target_label(target: &str) -> Option<&'static str> {
    Some(match target {
        "startup" => "page.startup",
        "services" => "page.services",
        "tasks" => "page.tasks",
        "network" => "page.network",
        "protection" => "page.protection",
        "posture" => "page.posture",
        "firewall" => "page.firewall",
        "accounts" => "page.accounts",
        "findings" => "page.findings",
        _ => return None,
    })
}

pub fn kind_label(kind: &str) -> String {
    crate::i18n::t_or(&format!("watch.kind.{kind}"), kind)
}

/// The Watching section: the state in its header, then one group with the recent alerts, the
/// notes and the watch's switches.
pub fn watch_card(ctx: &Ctx, status: &Value, tk: &Tokens) -> impl IntoElement {
    let tk = *tk;
    let recent = status.a("recent").iter().take(4).cloned().collect::<Vec<_>>();
    let unread = status.i("unread");
    let owner = status.b("owner");
    let watching = status.b("watching");
    let head = kit::section_head(t("watch.title"), &tk)
        .child(div().flex_1())
        .child(kit::dot(Some(state_color(status, &tk))))
        .child(
            div()
                .font_weight(FontWeight::NORMAL)
                .text_size(px(12.))
                .text_color(tk.ink2)
                .child(state_line(status)),
        );
    let mut rows: Vec<AnyElement> = Vec::new();
    if status.has("notifyPausedUntil") {
        let c = ctx.clone();
        rows.push(kit::footer_row(vec![
            kit::faint(
                tf(
                    "watch.notificationsPausedUntil",
                    &[("time", &clock(status.i("notifyPausedUntil")))],
                ),
                &tk,
            )
            .into_any_element(),
            kit::link(
                "wc-resume",
                t("watch.resumeNotifications"),
                move |_, cx| c.pause_notifications(false, cx),
                &tk,
            )
            .into_any_element(),
        ]));
    }
    if recent.is_empty() {
        rows.push(kit::note_row(t("watch.nothingYet"), &tk));
    }
    for (i, alert) in recent.into_iter().enumerate() {
        let (g, color) = severity_look(alert.s("severity"), &tk);
        let unread = !alert.b("read");
        let c = ctx.clone();
        let id = alert.at("id").as_u64();
        let target = alert.s("target").to_string();
        let scan = alert.s("kind") == "scan";
        rows.push(
            kit::NavRow::new(
                ElementId::NamedInteger("wc-alert".into(), i as u64),
                alert.s("title").to_string(),
            )
            .lead(kit::lead_glyph(g, color))
            .trail(since(alert.i("time")), tk.ink3)
            .strong(unread)
            .build(
                move |window: &mut Window, cx: &mut App| {
                    if unread && let Some(id) = id {
                        c.mark_read(Some(vec![id]), cx);
                    }
                    if scan {
                        open_auto_report(&c, window, cx);
                        return;
                    }
                    let page = if target_label(&target).is_some() {
                        target.as_str()
                    } else {
                        "alerts"
                    };
                    c.go(page, window, cx);
                },
                &tk,
            ),
        );
    }
    if let Some(row) = auto_scan_row(ctx, status, "wc-auto-open", &tk) {
        rows.push(div().px(px(16.)).py(px(10.)).child(row).into_any_element());
    }
    if !status.b("tasksWatched") {
        rows.push(kit::note_row(t("watch.tasksNeedAdmin"), &tk));
    }
    let hidden = status.strs("logsHidden");
    if !hidden.is_empty() {
        rows.push(kit::note_row(
            tf("watch.logsNeedAdmin", &[("logs", &hidden.join(", "))]),
            &tk,
        ));
    }
    let see = if unread > 0 {
        tn("watch.seeAllUnread", unread as u64, &[])
    } else {
        t("watch.seeAll")
    };
    let all = ctx.clone();
    let toggle = ctx.clone();
    let mut footer =
        vec![kit::link("wc-all", see, move |window, cx| all.go("alerts", window, cx), &tk).into_any_element()];
    if owner {
        footer.push(
            kit::link(
                "wc-toggle",
                t(if watching { "watch.pause" } else { "watch.resume" }),
                move |_, cx| toggle.set_watching(!watching, cx),
                &tk,
            )
            .into_any_element(),
        );
    }
    rows.push(kit::footer_row(footer));
    kit::section(head, kit::group(rows, &tk))
}

/// One line about automatic scans (Overview card, Alerts page); "" when they are off and never ran.
pub fn auto_scan_line(status: &Value) -> String {
    let auto = status.at("autoScan");
    if !auto.is_object() {
        return String::new();
    }
    let state = auto.s("status");
    let mut line = if auto.b("running") || state == "running" {
        t("watch.auto.running")
    } else if let Some(reason) = state.strip_prefix("postponed:") {
        let key = match reason {
            "battery" | "fullscreen" | "busy" => format!("watch.auto.reason.{reason}"),
            _ => "watch.auto.reason.other".to_string(),
        };
        tf("watch.auto.waiting", &[("reason", &t(&key))])
    } else {
        let when = if auto.has("lastRun") {
            since(auto.i("lastRun"))
        } else {
            String::new()
        };
        match state {
            "failed" => tf("watch.auto.failed", &[("when", &when)]),
            "interrupted" => t("watch.auto.interrupted"),
            "done" if auto.n("found") > 0.0 => tn("watch.auto.found", auto.n("found") as u64, &[("when", &when)]),
            "done" => tf("watch.auto.clean", &[("when", &when)]),
            _ if auto.s("schedule") != "off" && auto.has("next") => {
                tf("watch.auto.next", &[("when", &clock(auto.i("next")))])
            }
            _ => String::new(),
        }
    };
    if !line.is_empty() && state == "done" && auto.b("partial") {
        line = format!("{line} {}", t("watch.auto.partial"));
    }
    line
}

/// Opens the report of the last automatic scan (checked by the core) and shows its findings. The
/// report is read and parsed off the UI thread; Findings shows it when it is ready.
pub fn open_auto_report(ctx: &Ctx, window: &mut Window, cx: &mut App) {
    if let (Some(core), Some(watcher)) = (ctx.core.clone(), ctx.watcher.clone()) {
        let report = ctx.report.clone();
        let task =
            gpui_kit::AppContext::background_spawn(
                cx,
                async move { vigil_core::api::open_auto_report(&core, &watcher) },
            );
        cx.spawn(async move |cx| {
            let result = task.await;
            report.update(cx, |r, cx| {
                match result {
                    Ok(Some(analysis)) => r.set_analysis(Some(analysis)),
                    Ok(None) => {}
                    Err(error) => r.error = Some(error),
                }
                cx.notify();
            });
        })
        .detach();
    }
    ctx.go("findings", window, cx);
}

/// The automatic-scan line with its Open report link, if there is something to say.
pub fn auto_scan_row(ctx: &Ctx, status: &Value, id: &'static str, tk: &Tokens) -> Option<gpui_kit::Div> {
    let line = auto_scan_line(status);
    if line.is_empty() {
        return None;
    }
    let c = ctx.clone();
    Some(
        div()
            .flex()
            .flex_col()
            .gap_1()
            .min_w_0()
            .child(kit::faint(line, tk))
            .when(status.at("autoScan").b("report"), |this| {
                this.child(kit::link(
                    id,
                    t("watch.auto.open"),
                    move |window, cx| open_auto_report(&c, window, cx),
                    tk,
                ))
            }),
    )
}
