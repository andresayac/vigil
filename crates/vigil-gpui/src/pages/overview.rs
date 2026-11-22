//! Overview: live tiles (processor, memory, graphics, system drive), the scan in progress, the
//! report's verdict, what to do first, what changed since the last scan, the Watching card, the
//! security state and the scan's coverage notes.

use gpui_kit::base::Button as BaseButton;
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    AnyElement, Context, ElementId, FontWeight, Hsla, InteractiveElement as _, IntoElement, ParentElement, Render,
    Role, SharedString, StatefulInteractiveElement as _, Styled, Subscription, Window, div, px,
};
use serde_json::Value;

use crate::app::{Ctx, Focus};
use crate::data::{self, Src};
use crate::format::{pct, size};
use crate::i18n::{t, tf, tn};
use crate::pages::common::{self, when};
use crate::pages::labels::{VERDICT_ORDER, by_verdict, risk_color, risk_label, verdict_label};
use crate::pages::performance::{Line, chart};
use crate::pages::watchui;
use crate::theme::{RADIUS_CARD, Tokens, tokens};
use crate::ui;
use crate::ui::kit::{self, J as _, Readout};

pub struct OverviewPage {
    ctx: Ctx,
    drive: Option<Value>,
    _subscriptions: Vec<Subscription>,
}

impl OverviewPage {
    pub fn new(ctx: Ctx, cx: &mut Context<Self>) -> Self {
        let subscriptions = vec![
            cx.observe(&ctx.report, |_, _, cx| cx.notify()),
            cx.observe(&ctx.live, |_, _, cx| cx.notify()),
        ];
        let core = ctx.core.clone();
        common::read(
            cx,
            move || data::fetch(core.as_ref(), Src::Volumes).unwrap_or(Value::Null),
            |this: &mut Self, volumes, _| {
                let list = volumes.as_array().cloned().unwrap_or_default();
                this.drive = list
                    .iter()
                    .find(|v| v.s("mount").to_uppercase().starts_with("C:"))
                    .or(list.first())
                    .cloned();
            },
        );
        Self {
            ctx,
            drive: None,
            _subscriptions: subscriptions,
        }
    }
}

struct Tile {
    id: &'static str,
    title: String,
    value: String,
    detail: String,
    level: Option<Hsla>,
    series: Option<(Vec<f64>, Hsla)>,
    page: &'static str,
    focus: Option<String>,
}

fn tile(t: Tile, ctx: &Ctx, tk: &Tokens) -> AnyElement {
    let ctx = ctx.clone();
    let name: SharedString = format!("{} {}", t.title, t.value).into();
    let tk = *tk;
    BaseButton::new(t.id)
        .role(Role::Button)
        .accessibility_label(name)
        .flex()
        .flex_col()
        .items_start()
        .justify_start()
        .gap(px(2.))
        .h(px(112.))
        .p_3()
        .bg(tk.surface)
        .border_1()
        .border_color(tk.rule)
        .rounded(RADIUS_CARD)
        .hover(move |s| s.bg(tk.hover))
        .on_click(move |_, window, cx| {
            if let Some(focus) = &t.focus {
                crate::pages::performance::select(focus, cx);
            }
            ctx.go(t.page, window, cx);
        })
        .child(div().text_size(px(13.)).text_color(tk.ink2).child(t.title))
        .child(
            div()
                .text_size(px(22.))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(t.level.unwrap_or(tk.ink))
                .child(t.value),
        )
        .child(div().text_size(px(12.)).text_color(tk.ink3).child(t.detail))
        .when_some(t.series, |this, (values, hue)| {
            let values = values[values.len().saturating_sub(60)..].to_vec();
            this.child(div().w_full().flex_1().min_h(px(20.)).child(chart(
                vec![Line { values, dashed: false }],
                100.0,
                60,
                hue,
                tk,
                false,
            )))
        })
        .into_any_element()
}

/// The security state: what the scan read of Defender, the firewall, UAC and the system.
fn security_rows(posture: &Value, tk: &Tokens) -> Vec<Readout> {
    let mut entries: Vec<(String, Value)> = Vec::new();
    let Some(map) = posture.as_object() else {
        return Vec::new();
    };
    for key in ["system", "computer"] {
        if let Some(v) = map.get(key) {
            entries.push((key.to_string(), v.clone()));
        }
    }
    if let Some(defender) = map.get("defender").and_then(Value::as_object) {
        for key in [
            "realtime_protection",
            "tamper_protection",
            "signature_age_days",
            "last_quick_scan",
            "last_full_scan",
        ] {
            if let Some(v) = defender.get(key) {
                entries.push((key.to_string(), v.clone()));
            }
        }
    }
    for (key, v) in map {
        if !matches!(key.as_str(), "system" | "computer" | "defender") {
            entries.push((key.clone(), v.clone()));
        }
    }
    entries
        .into_iter()
        .take(24)
        .map(|(key, v)| {
            let name = crate::i18n::t_or(&format!("posture.{key}"), &kit::humanize(&key));
            let status = match key.as_str() {
                "realtime_protection" | "tamper_protection" | "is_administrator" => {
                    v.as_bool().map(|b| if b { tk.ok } else { tk.bad })
                }
                "firewall" => v.as_object().map(|o| {
                    if o.values().all(|x| x.as_bool() == Some(true)) {
                        tk.ok
                    } else {
                        tk.bad
                    }
                }),
                "uac" => Some(if v.as_str() == Some("enabled") { tk.ok } else { tk.bad }),
                "remote_desktop" => Some(if v.as_str() == Some("enabled") { tk.warn } else { tk.ok }),
                "last_full_scan" => Some(if matches!(v.as_str(), Some("never") | Some("")) {
                    tk.warn
                } else {
                    tk.ok
                }),
                "signature_age_days" => v.as_f64().map(|d| {
                    if d <= 7.0 {
                        tk.ok
                    } else if d <= 30.0 {
                        tk.warn
                    } else {
                        tk.bad
                    }
                }),
                _ => None,
            };
            Readout::new(name, fmt(&v)).status(status)
        })
        .collect()
}

/// A posture value as text: yes / no, lists, "key: value; ..." pairs.
pub fn fmt(v: &Value) -> String {
    match v {
        Value::Bool(b) => t(if *b { "common.yes" } else { "common.no" }),
        Value::Array(items) if items.is_empty() => t("common.none"),
        Value::Array(items) => items.iter().map(kit::text).collect::<Vec<_>>().join(", "),
        Value::Object(map) if map.is_empty() => t("common.none"),
        Value::Object(map) => map
            .iter()
            .map(|(k, v)| format!("{k}: {}", kit::text(v)))
            .collect::<Vec<_>>()
            .join("; "),
        other => kit::text(other),
    }
}

impl Render for OverviewPage {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let ctx = self.ctx.clone();
        let report = ctx.report.read(cx);
        let live = ctx.live.read(cx);
        let snap = live.snapshot.as_ref();
        let dash = "—".to_string();

        // Tiles.
        let mut tiles: Vec<AnyElement> = Vec::new();
        tiles.push(tile(
            Tile {
                id: "ov-cpu",
                title: t("res.cpu"),
                value: snap.map(|s| pct(f64::from(s.cpu), 0)).unwrap_or(dash.clone()),
                detail: snap
                    .map(|s| tn("overview.logical", s.per_core.len() as u64, &[]))
                    .unwrap_or_default(),
                level: None,
                series: Some((live.cpu.iter().map(|v| f64::from(*v)).collect(), tk.chart_cpu)),
                page: "performance",
                focus: Some("cpu".into()),
            },
            &ctx,
            &tk,
        ));
        tiles.push(tile(
            Tile {
                id: "ov-memory",
                title: t("res.memory"),
                value: snap
                    .filter(|s| s.memory.total > 0)
                    .map(|s| pct(s.memory.used as f64 / s.memory.total as f64 * 100.0, 0))
                    .unwrap_or(dash.clone()),
                detail: snap
                    .map(|s| tf("overview.available", &[("size", &size(s.memory.available as f64, 1))]))
                    .unwrap_or_default(),
                level: None,
                series: Some((live.memory.iter().map(|v| f64::from(*v)).collect(), tk.chart_memory)),
                page: "performance",
                focus: Some("memory".into()),
            },
            &ctx,
            &tk,
        ));
        if let Some(gpu) = snap.and_then(|s| s.gpus.iter().max_by_key(|g| g.dedicated_total)) {
            let key = format!("gpu:{}", gpu.luid);
            tiles.push(tile(
                Tile {
                    id: "ov-gpu",
                    title: t("res.gpu"),
                    value: pct(f64::from(gpu.utilization), 0),
                    detail: tf(
                        "overview.vram",
                        &[
                            ("used", &size(gpu.dedicated_used as f64, 1)),
                            ("total", &size(gpu.dedicated_total as f64, 0)),
                        ],
                    ),
                    level: None,
                    series: live
                        .series
                        .get(&key)
                        .map(|s| (s.iter().copied().collect(), tk.chart_gpu)),
                    page: "performance",
                    focus: Some(key),
                },
                &ctx,
                &tk,
            ));
        }
        if let Some(d) = &self.drive {
            let total = d.n("total");
            let free = d.n("free");
            let share = if total > 0.0 { free / total * 100.0 } else { 0.0 };
            tiles.push(tile(
                Tile {
                    id: "ov-drive",
                    title: tf("overview.drive", &[("drive", d.s("mount").trim_end_matches('\\'))]),
                    value: tf("overview.free", &[("size", &size(free, 0))]),
                    detail: tf(
                        "overview.freeShare",
                        &[("pct", &pct(share, 0)), ("total", &size(total, 1))],
                    ),
                    level: if share < 5.0 {
                        Some(tk.bad)
                    } else if share < 12.0 {
                        Some(tk.warn)
                    } else {
                        None
                    },
                    series: None,
                    page: "storage",
                    focus: None,
                },
                &ctx,
                &tk,
            ));
        }
        let wide = f32::from(window.viewport_size().width);
        let per_row = ((wide - 320.) / 240.).floor().clamp(1., 4.) as usize;
        let mut page =
            kit::page("overview").child(div().flex().flex_wrap().gap_3().children(tiles.into_iter().map(|t| {
                div()
                    .flex_basis(gpui_kit::relative(0.95 / per_row as f32))
                    .flex_grow(1.)
                    .child(t)
            })));

        if report.scanning {
            page = page.child(
                kit::panel(&tk)
                    .child(kit::h2(t(report.title)))
                    .child(kit::busy_bar("ov-busy", &tk))
                    .child(
                        div().id("ov-log").max_h(px(200.)).overflow_y_scroll().child(
                            kit::sel("ov-log-text", report.log.join("\n"))
                                .font_family(crate::theme::FONT_MONO)
                                .text_size(px(12.)),
                        ),
                    ),
            );
        }
        if let Some(error) = &report.error {
            page = page.child(kit::colored(error.clone(), tk.bad));
        }
        let analysis = report.analysis.clone();
        let watch = ctx.watch_status();
        let Some(a) = analysis else {
            if report.loaded && !report.scanning {
                let scan = ctx.clone();
                page = page
                    .child(kit::h1(t("overview.emptyTitle")))
                    .child(kit::muted(t("overview.emptyBody"), &tk))
                    .child(
                        div().child(
                            ui::accent_button("ov-first", t("overview.firstScan"))
                                .on_click(move |_, window, cx| scan.scan_dialog(window, cx)),
                        ),
                    )
                    .children(watch.map(|w| div().max_w(px(560.)).child(watchui::watch_card(&ctx, &w, &tk))));
            }
            return page;
        };
        let visible: Vec<Value> = report.visible().into_iter().cloned().collect();
        let summary = a.at("summary");
        let level = summary.s("risk_level");
        let headline = if summary.has("headline") {
            summary.s("headline").to_string()
        } else {
            let open: Vec<&Value> = visible.iter().filter(|i| !i.b("trusted")).collect();
            let critical = open.iter().filter(|i| i.s("level") == "critical").count();
            let suspicious = open.iter().filter(|i| i.s("level") == "suspicious").count();
            if critical > 0 {
                tn("overview.headlineCritical", critical as u64, &[])
            } else if suspicious > 0 {
                tn("overview.headlineSuspicious", suspicious as u64, &[])
            } else {
                t("overview.headlineClean")
            }
        };
        let meta = a.at("meta");
        let ai = a.at("ai");
        let mut parts = Vec::new();
        let started = when(meta.s("started"));
        if !started.is_empty() {
            parts.push(tf("overview.scanned", &[("when", &started)]));
        }
        parts.push(t(if meta.b("is_admin") {
            "overview.asAdmin"
        } else {
            "overview.notAdmin"
        }));
        if ai.has("with_verdict") {
            parts.push(tf("overview.aiBy", &[("model", ai.s("model"))]));
        } else if ai.has("reason") {
            parts.push(tf("overview.aiSkipped", &[("reason", ai.s("reason"))]));
        }
        page = page.child(
            div()
                .flex()
                .flex_col()
                .gap_1()
                .child(
                    div()
                        .text_size(px(13.))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(risk_color(level, &tk))
                        .child(risk_label(level)),
                )
                .child(kit::h1(headline))
                .when(summary.has("summary"), |this| {
                    this.child(kit::muted(summary.s("summary").to_string(), &tk))
                })
                .child(kit::faint(parts.join(" · "), &tk)),
        );

        // The verdict strip: one sliver per finding.
        let strip: Vec<&Value> = visible.iter().filter(|i| i.s("verdict") != "trusted").collect();
        if !strip.is_empty() {
            page = page.child(
                div()
                    .flex()
                    .h(px(46.))
                    .gap(px(1.))
                    .bg(tk.sunken)
                    .rounded(px(4.))
                    .overflow_hidden()
                    .children(strip.iter().enumerate().map(|(i, item)| {
                        let label = format!("{}: {}", verdict_label(item.s("verdict")), item.s("title"));
                        let tip = format!("{} · {}", verdict_label(item.s("verdict")), item.s("title"));
                        let id = item.s("id").to_string();
                        let c = ctx.clone();
                        div()
                            .id(ElementId::NamedInteger("ov-strip".into(), i as u64))
                            .role(Role::Button)
                            .aria_label(SharedString::from(label))
                            .flex_1()
                            .min_w(px(1.))
                            .h_full()
                            .bg(tk.verdict(item.s("verdict")))
                            .hover(|s| s.opacity(0.85))
                            .tooltip(move |window, cx| {
                                gpui_kit::component::tooltip::Tooltip::new(tip.clone()).build(window, cx)
                            })
                            .on_click(move |_, window, cx| c.find(Focus::Item(id.clone()), window, cx))
                    })),
            );
        }
        // Counts per verdict.
        let mut counts = kit::row().gap_4();
        for v in VERDICT_ORDER {
            let n = visible.iter().filter(|i| i.s("verdict") == v).count();
            if n == 0 {
                continue;
            }
            let c = ctx.clone();
            counts = counts.child(
                BaseButton::new(ElementId::Name(format!("ov-count-{v}").into()))
                    .role(Role::Button)
                    .accessibility_label(format!("{n} {}", verdict_label(v)))
                    .text_size(px(14.))
                    .text_color(tk.verdict(v))
                    .font_weight(FontWeight::SEMIBOLD)
                    .hover(|s| s.underline())
                    .on_click(move |_, window, cx| c.find(Focus::Verdict(v.to_string()), window, cx))
                    .child(format!("{n} {}", verdict_label(v))),
            );
        }
        page = page.child(counts);

        // What to do first.
        let items = a.a("items");
        let mut first = kit::panel(&tk).child(kit::h2(t("overview.first")));
        let priority = summary.a("priority_actions");
        let top: Vec<&Value> = visible
            .iter()
            .filter(|i| matches!(i.s("verdict"), "remove" | "disable" | "review") && !i.b("trusted"))
            .take(8)
            .collect();
        if !priority.is_empty() {
            for (i, action) in priority.iter().enumerate() {
                let ids: Vec<String> = action
                    .strs("ids")
                    .into_iter()
                    .filter(|id| items.iter().any(|it| it.s("id") == *id))
                    .map(str::to_string)
                    .collect();
                let title = action.s("title").to_string();
                let c = ctx.clone();
                first = first
                    .child(kit::h3(format!("{}. {}", i + 1, title)))
                    .child(kit::muted(action.s("detail").to_string(), &tk))
                    .when(!ids.is_empty(), |this| {
                        let n = ids.len() as u64;
                        this.child(kit::link(
                            ElementId::NamedInteger("ov-pa".into(), i as u64),
                            tn("overview.showItems", n, &[]),
                            move |window, cx| c.find(Focus::Items(ids.clone(), title.clone()), window, cx),
                            &tk,
                        ))
                    });
            }
        } else if !top.is_empty() {
            for (i, item) in top.iter().enumerate() {
                let id = item.s("id").to_string();
                let c = ctx.clone();
                let detail = if item.has("reason") {
                    item.s("reason")
                } else {
                    item.s("subtitle")
                };
                first = first
                    .child(kit::link(
                        ElementId::NamedInteger("ov-top".into(), i as u64),
                        format!("{} · {}", verdict_label(item.s("verdict")), item.s("title")),
                        move |window, cx| c.find(Focus::Item(id.clone()), window, cx),
                        &tk,
                    ))
                    .child(kit::faint(detail.to_string(), &tk));
            }
        } else {
            first = first.child(kit::muted(t("overview.nothing"), &tk));
        }
        let habits = summary.strs("good_practices");
        if !habits.is_empty() {
            first = first
                .child(kit::h3(t("overview.habits")))
                .children(habits.iter().map(|h| kit::body(format!("• {h}"))));
        }

        // The right column.
        let mut right = div().flex().flex_col().gap_3();
        if let Some(w) = &watch {
            right = right.child(watchui::watch_card(&ctx, w, &tk));
        }
        if let Some(changes) = a.get("changes").filter(|c| c.is_object()) {
            right = right.child(since_panel(&ctx, changes, items, &report.ignored, &tk));
        }
        let open_protection = ctx.clone();
        let open_posture = ctx.clone();
        right = right.child(
            kit::panel(&tk)
                .child(kit::h2(t("overview.security")))
                .child(kit::readouts("ov-sec", security_rows(a.at("posture"), &tk), 200., &tk))
                .child(
                    kit::row()
                        .child(kit::link(
                            "ov-protection",
                            t("overview.openProtection"),
                            move |window, cx| open_protection.go("protection", window, cx),
                            &tk,
                        ))
                        .child(kit::link(
                            "ov-posture",
                            t("overview.openPosture"),
                            move |window, cx| open_posture.go("posture", window, cx),
                            &tk,
                        )),
                ),
        );
        let notes = a.a("notes");
        if !notes.is_empty() {
            right = right.child(
                kit::panel(&tk).child(kit::h2(t("overview.coverage"))).children(
                    notes
                        .iter()
                        .take(12)
                        .map(|n| kit::muted(format!("{}: {}", kit::humanize(n.s("area")), n.s("message")), &tk)),
                ),
            );
        }
        page.child(kit::columns(0.6, first, right, window))
    }
}

/// What changed since the previous scan in the same folder.
fn since_panel(ctx: &Ctx, changes: &Value, items: &[Value], ignored: &[String], tk: &Tokens) -> impl IntoElement {
    let previous = changes.at("previous");
    let started = when(previous.s("started"));
    let title = if started.is_empty() {
        t("overview.sinceUndated")
    } else {
        tf("overview.since", &[("when", &started)])
    };
    let find = |id: &str| {
        items
            .iter()
            .find(|i| i.s("id") == id && !ignored.iter().any(|x| x == id))
    };
    let mut fresh: Vec<&Value> = changes.strs("new").into_iter().filter_map(find).collect();
    fresh.sort_by(|a, b| by_verdict(a, b));
    let mut altered: Vec<(&Value, Vec<String>)> = changes
        .a("changed")
        .iter()
        .filter_map(|c| find(c.s("id")).map(|i| (i, c.strs("what").into_iter().map(str::to_string).collect())))
        .collect();
    altered.sort_by(|a, b| by_verdict(a.0, b.0));
    let gone = changes.a("gone");
    let posture = changes.strs("posture");
    let mut tally = Vec::new();
    for (key, n) in [
        ("overview.sinceNew", changes.a("new").len()),
        ("overview.sinceGone", gone.len()),
        ("overview.sinceChanged", changes.a("changed").len()),
        ("overview.sinceSettings", posture.len()),
    ] {
        if n > 0 {
            tally.push(tn(key, n as u64, &[]));
        }
    }
    let mut panel = kit::panel(tk).child(kit::h2(title));
    if tally.is_empty() {
        return panel.child(kit::muted(t("overview.sinceNothing"), tk));
    }
    panel = panel.child(kit::muted(tally.join(" · "), tk));
    if !fresh.is_empty() {
        panel = panel.child(kit::h3(t("overview.sinceNewTitle")));
        for (i, item) in fresh.iter().take(5).enumerate() {
            let c = ctx.clone();
            let id = item.s("id").to_string();
            panel = panel.child(kit::link(
                ElementId::NamedInteger("ov-new".into(), i as u64),
                format!("{} · {}", verdict_label(item.s("verdict")), item.s("title")),
                move |window, cx| c.find(Focus::Item(id.clone()), window, cx),
                tk,
            ));
        }
        if fresh.len() > 1 {
            let c = ctx.clone();
            let ids: Vec<String> = fresh.iter().map(|i| i.s("id").to_string()).collect();
            panel = panel.child(kit::link(
                "ov-new-all",
                tn("overview.sinceShowNew", fresh.len() as u64, &[]),
                move |window, cx| c.find(Focus::Items(ids.clone(), t("findings.newSince")), window, cx),
                tk,
            ));
        }
    }
    if !altered.is_empty() {
        panel = panel.child(kit::h3(t("overview.sinceChangedTitle")));
        for (i, (item, what)) in altered.iter().take(4).enumerate() {
            let c = ctx.clone();
            let id = item.s("id").to_string();
            panel = panel
                .child(kit::link(
                    ElementId::NamedInteger("ov-chg".into(), i as u64),
                    item.s("title").to_string(),
                    move |window, cx| c.find(Focus::Item(id.clone()), window, cx),
                    tk,
                ))
                .child(kit::faint(what.join(" · "), tk));
        }
        if altered.len() > 4 {
            panel = panel.child(kit::faint(
                tn("overview.sinceMore", (altered.len() - 4) as u64, &[]),
                tk,
            ));
        }
    }
    if !posture.is_empty() {
        panel = panel
            .child(kit::h3(t("overview.sinceSettingsTitle")))
            .children(posture.iter().take(8).map(|p| kit::body(format!("• {p}"))));
    }
    if !gone.is_empty() {
        panel = panel.child(kit::h3(t("overview.sinceGoneTitle")));
        for g in gone.iter().take(4) {
            let mut line = g.s("title").to_string();
            if g.has("path") && g.s("path") != g.s("title") {
                line = format!("{line} · {}", g.s("path"));
            }
            panel = panel.child(kit::muted(line, tk));
        }
        if gone.len() > 4 {
            panel = panel.child(kit::faint(tn("overview.sinceMore", (gone.len() - 4) as u64, &[]), tk));
        }
    }
    panel
}
