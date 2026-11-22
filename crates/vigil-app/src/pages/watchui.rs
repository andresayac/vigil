//! How the background watch is shown: its state line, relative times, the alerts' look, and the
//! Watching card of Overview.

use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{App, ElementId, FontWeight, Hsla, IntoElement, ParentElement, Styled, Window, div, px};
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

/// The Watching card: the state, the recent alerts and the watch's switches.
pub fn watch_card(ctx: &Ctx, status: &Value, tk: &Tokens) -> impl IntoElement {
    let tk = *tk;
    let recent = status.a("recent").iter().take(4).cloned().collect::<Vec<_>>();
    let unread = status.i("unread");
    let owner = status.b("owner");
    let watching = status.b("watching");
    let mut card = kit::panel(&tk)
        .child(
            kit::row()
                .child(kit::h2(t("watch.title")))
                .child(div().flex_1())
                .child(kit::dot(Some(state_color(status, &tk))))
                .child(kit::muted(state_line(status), &tk)),
        )
        .when(status.has("notifyPausedUntil"), |this| {
            let c = ctx.clone();
            this.child(
                kit::row()
                    .child(kit::faint(
                        tf(
                            "watch.notificationsPausedUntil",
                            &[("time", &clock(status.i("notifyPausedUntil")))],
                        ),
                        &tk,
                    ))
                    .child(kit::link(
                        "wc-resume",
                        t("watch.resumeNotifications"),
                        move |_, cx| c.pause_notifications(false, cx),
                        &tk,
                    )),
            )
        });
    if recent.is_empty() {
        card = card.child(kit::muted(t("watch.nothingYet"), &tk));
    }
    for (i, alert) in recent.into_iter().enumerate() {
        let (g, color) = severity_look(alert.s("severity"), &tk);
        let unread = !alert.b("read");
        let c = ctx.clone();
        let id = alert.at("id").as_u64();
        let target = alert.s("target").to_string();
        let scan = alert.s("kind") == "scan";
        card = card.child(
            kit::list_row(
                ElementId::NamedInteger("wc-alert".into(), i as u64),
                alert.s("title").to_string(),
                false,
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
            )
            .child(kit::glyph(g, 14., color))
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .overflow_hidden()
                    .text_ellipsis()
                    .whitespace_nowrap()
                    .when(unread, |this| this.font_weight(FontWeight::SEMIBOLD))
                    .child(alert.s("title").to_string()),
            )
            .child(kit::faint(since(alert.i("time")), &tk)),
        );
    }
    if let Some(row) = auto_scan_row(ctx, status, "wc-auto-open", &tk) {
        card = card.child(row);
    }
    if !status.b("tasksWatched") {
        card = card.child(kit::faint(t("watch.tasksNeedAdmin"), &tk));
    }
    let hidden = status.strs("logsHidden");
    if !hidden.is_empty() {
        card = card.child(kit::faint(
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
    card.child(
        kit::row()
            .pt_1()
            .child(kit::link(
                "wc-all",
                see,
                move |window, cx| all.go("alerts", window, cx),
                &tk,
            ))
            .when(owner, |this| {
                this.child(kit::link(
                    "wc-toggle",
                    t(if watching { "watch.pause" } else { "watch.resume" }),
                    move |_, cx| toggle.set_watching(!watching, cx),
                    &tk,
                ))
            }),
    )
    .min_w(px(0.))
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

/// Opens the report of the last automatic scan (checked by the core) and shows its findings.
pub fn open_auto_report(ctx: &Ctx, window: &mut Window, cx: &mut App) {
    if let (Some(core), Some(watcher)) = (&ctx.core, &ctx.watcher) {
        match vigil_core::api::open_auto_report(core, watcher) {
            Ok(Some(analysis)) => ctx.report.update(cx, |r, cx| {
                r.analysis = Some(analysis);
                cx.notify();
            }),
            Ok(None) => {}
            Err(error) => ctx.report.update(cx, |r, cx| {
                r.error = Some(error);
                cx.notify();
            }),
        }
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
        kit::row()
            .gap_1()
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
