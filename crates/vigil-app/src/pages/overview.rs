//! Overview: live tiles (processor, memory, graphics, system drive), the scan in progress, the
//! report's verdict with a bar of its findings by verdict, then sections of grouped rows: what to
//! do first, good habits, the Watching section, what changed since the last scan, the security
//! state and the scan's coverage notes.

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
use crate::icons;
use crate::pages::common::{self, when};
use crate::pages::labels::{VERDICT_ORDER, by_verdict, risk_color, risk_label, verdict_label};
use crate::pages::performance::{Line, chart};
use crate::pages::watchui;
use crate::theme::{FONT_DISPLAY, RADIUS_CARD, Tokens, tokens};
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
    /// A share of a whole, drawn as a meter at the bottom (the drive's used space).
    meter: Option<(f64, Hsla)>,
    page: &'static str,
    focus: Option<String>,
}

/// A live tile: its name, the figure, a detail line and, along the bottom, its recent history or
/// a meter. The whole tile opens its page.
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
        .h(px(128.))
        .pt(px(12.))
        .px(px(14.))
        .pb(px(12.))
        .bg(tk.surface)
        .border_1()
        .border_color(tk.rule)
        .rounded(RADIUS_CARD)
        .overflow_hidden()
        .hover(move |s| s.bg(tk.control_hover))
        .active(move |s| s.bg(tk.surface2))
        .on_click(move |_, window, cx| {
            if let Some(focus) = &t.focus {
                crate::pages::performance::select(focus, cx);
            }
            ctx.go(t.page, window, cx);
        })
        .child(div().text_size(px(12.)).text_color(tk.ink2).child(t.title))
        .child(
            div()
                .font_family(FONT_DISPLAY)
                .text_size(px(24.))
                .line_height(px(32.))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(t.level.unwrap_or(tk.ink))
                .child(t.value),
        )
        .child(
            div()
                .w_full()
                .text_size(px(12.))
                .text_color(tk.ink3)
                .whitespace_nowrap()
                .overflow_hidden()
                .text_ellipsis()
                .child(t.detail),
        )
        .when_some(t.series, |this, (values, hue)| {
            let values = values[values.len().saturating_sub(60)..].to_vec();
            this.child(div().w_full().flex_1().min_h(px(20.)).mt(px(6.)).child(chart(
                vec![Line { values, dashed: false }],
                100.0,
                60,
                hue,
                tk,
                false,
            )))
        })
        .when_some(t.meter, |this, (share, color)| {
            this.child(div().flex_1())
                .child(kit::meter(share, color, None, 6., &tk))
        })
        .into_any_element()
}

/// The glyph that stands for a verdict in a list (with its colour, never the colour alone).
fn verdict_glyph(verdict: &str) -> char {
    match verdict {
        "remove" => icons::ERROR,
        "disable" => icons::WARNING,
        "safe" | "trusted" => icons::SUCCESS,
        _ => icons::INFO,
    }
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

/// A posture word the scan writes in English ("enabled", "never"), in the window's language.
fn word(text: &str) -> String {
    match text {
        "enabled" => t("common.enabled"),
        "disabled" => t("common.disabled"),
        "never" => t("common.never"),
        other => other.to_string(),
    }
}

/// A posture value as text: yes / no, lists, "name: value · ..." pairs (names translated).
pub fn fmt(v: &Value) -> String {
    match v {
        Value::Bool(b) => t(if *b { "common.yes" } else { "common.no" }),
        Value::String(s) => word(s),
        Value::Array(items) if items.is_empty() => t("common.none"),
        Value::Array(items) => items.iter().map(kit::text).collect::<Vec<_>>().join(", "),
        Value::Object(map) if map.is_empty() => t("common.none"),
        Value::Object(map) => map
            .iter()
            .map(|(k, v)| {
                let name = crate::i18n::t_or(&format!("posture.part.{}", k.to_lowercase()), &kit::humanize(k));
                let value = match v {
                    Value::Bool(_) | Value::String(_) => fmt(v),
                    other => kit::text(other),
                };
                format!("{name}: {value}")
            })
            .collect::<Vec<_>>()
            .join(" · "),
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
                meter: None,
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
                meter: None,
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
                    meter: None,
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
            let level = if share < 5.0 {
                Some(tk.bad)
            } else if share < 12.0 {
                Some(tk.warn)
            } else {
                None
            };
            tiles.push(tile(
                Tile {
                    id: "ov-drive",
                    title: tf("overview.drive", &[("drive", d.s("mount").trim_end_matches('\\'))]),
                    value: tf("overview.free", &[("size", &size(free, 0))]),
                    detail: tf(
                        "overview.freeShare",
                        &[("pct", &pct(share, 0)), ("total", &size(total, 1))],
                    ),
                    level,
                    series: None,
                    meter: (total > 0.0).then(|| (1.0 - free / total, level.unwrap_or(tk.chart_disk))),
                    page: "storage",
                    focus: None,
                },
                &ctx,
                &tk,
            ));
        }
        let wide = f32::from(window.viewport_size().width);
        let per_row = ((wide - 320.) / 240.).floor().clamp(1., 4.) as usize;
        let mut page = kit::page("overview").child(ui::page_title(t("page.overview"))).child(
            div().flex().flex_wrap().gap_3().children(tiles.into_iter().map(|t| {
                div()
                    .flex_basis(gpui_kit::relative(0.95 / per_row as f32))
                    .flex_grow(1.)
                    .child(t)
            })),
        );

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
            page = page.child(ui::info_bar("ov-error", ui::Severity::Error, error.clone(), None, &tk));
        }
        let analysis = report.analysis.clone();
        let watch = ctx.watch_status();
        let Some(a) = analysis else {
            if report.loaded && !report.scanning {
                let scan = ctx.clone();
                page = page
                    .child(
                        kit::panel(&tk)
                            .p(px(20.))
                            .gap_3()
                            .child(kit::h2(t("overview.emptyTitle")))
                            .child(kit::muted(t("overview.emptyBody"), &tk))
                            .child(
                                div().flex().child(
                                    ui::accent_button("ov-first", t("overview.firstScan"))
                                        .glyph(icons::SCAN)
                                        .on_click(move |_, window, cx| scan.scan_dialog(window, cx)),
                                ),
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

        // The verdict: a shield in the risk's colour, the headline, what the scan was.
        let brand = crate::theme::hero();
        let mut hero = div()
            .flex()
            .flex_col()
            .gap_4()
            .p(px(24.))
            .bg(brand.fill)
            .text_color(brand.ink)
            .rounded(RADIUS_CARD)
            .child(
                div()
                    .flex()
                    .items_start()
                    .gap_4()
                    .child(
                        div()
                            .w(px(48.))
                            .h(px(48.))
                            .flex_none()
                            .flex()
                            .items_center()
                            .justify_center()
                            .rounded(px(12.))
                            .bg(brand.hover)
                            .child(icons::icon(icons::SHIELD_PLAIN, 24.0, brand.mint)),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .flex()
                            .flex_col()
                            .gap(px(2.))
                            .child(
                                div()
                                    .text_size(px(12.))
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .text_color(brand.mint)
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child(kit::dot(Some(risk_color(level, &tk))))
                                    .child(risk_label(level)),
                            )
                            .child(
                                div()
                                    .font_family(FONT_DISPLAY)
                                    .text_size(px(20.))
                                    .line_height(px(28.))
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .child(kit::plain(headline)),
                            )
                            .when(summary.has("summary"), |this| {
                                this.child(kit::body(summary.s("summary").to_string()).text_color(brand.ink2))
                            })
                            .child(
                                div()
                                    .pt_1()
                                    .text_size(px(12.))
                                    .text_color(brand.ink2)
                                    .child(parts.join(" · ")),
                            ),
                    ),
            );
        // The two things to do from here: look at what matters, or scan again.
        let review_verdict = ["remove", "disable", "review"]
            .into_iter()
            .find(|v| visible.iter().any(|i| i.s("verdict") == *v && !i.b("trusted")));
        let review = ctx.clone();
        let again = ctx.clone();
        hero = hero.child(
            div()
                .flex()
                .flex_wrap()
                .gap_2()
                .when_some(review_verdict, |this, verdict| {
                    this.child(
                        ui::FButton::new("ov-review", ui::Kind::Standard)
                            .label(t("overview.reviewNow"))
                            .glyph(icons::CHEVRON_RIGHT)
                            .bg(brand.mint)
                            .text_color(brand.on_mint)
                            .border_0()
                            .font_weight(FontWeight::SEMIBOLD)
                            .on_click(move |_, window, cx| {
                                review.find(Focus::Verdict(verdict.to_string()), window, cx)
                            }),
                    )
                })
                .child(
                    ui::FButton::new("ov-again", ui::Kind::Standard)
                        .label(t("overview.scanAgain"))
                        .glyph(icons::REFRESH)
                        .bg(brand.hover)
                        .text_color(brand.ink)
                        .border_color(brand.ink2)
                        .disabled(report.scanning)
                        .on_click(move |_, window, cx| again.scan_dialog(window, cx)),
                ),
        );

        // One bar for the open findings, a segment per verdict, and its legend.
        let counts: Vec<(&'static str, usize)> = VERDICT_ORDER
            .iter()
            .map(|v| (*v, visible.iter().filter(|i| i.s("verdict") == *v).count()))
            .filter(|(_, n)| *n > 0)
            .collect();
        let open: Vec<(&'static str, usize)> = counts.iter().copied().filter(|(v, _)| *v != "trusted").collect();
        if !open.is_empty() {
            hero = hero.child(
                div()
                    .flex()
                    .w_full()
                    .h(px(8.))
                    .gap(px(2.))
                    .children(open.iter().map(|(v, n)| {
                        let v = *v;
                        let label = format!("{n} {}", verdict_label(v));
                        let tip = label.clone();
                        let c = ctx.clone();
                        div()
                            .id(ElementId::Name(format!("ov-bar-{v}").into()))
                            .role(Role::Button)
                            .aria_label(SharedString::from(label))
                            .h_full()
                            .flex_basis(gpui_kit::relative(0.))
                            .flex_grow(*n as f32)
                            .min_w(px(6.))
                            .rounded(px(2.))
                            .bg(tk.verdict(v))
                            .hover(|s| s.opacity(0.8))
                            .tooltip(move |window, cx| {
                                gpui_kit::component::tooltip::Tooltip::new(tip.clone()).build(window, cx)
                            })
                            .on_click(move |_, window, cx| c.find(Focus::Verdict(v.to_string()), window, cx))
                    })),
            );
        }
        if !counts.is_empty() {
            hero = hero.child(
                div()
                    .flex()
                    .flex_wrap()
                    .items_center()
                    .gap_2()
                    .ml(px(-8.))
                    .children(counts.iter().map(|(v, n)| {
                        let v = *v;
                        let c = ctx.clone();
                        BaseButton::new(ElementId::Name(format!("ov-count-{v}").into()))
                            .role(Role::Button)
                            .accessibility_label(format!("{n} {}", verdict_label(v)))
                            .flex()
                            .items_center()
                            .gap_2()
                            .px(px(8.))
                            .py(px(3.))
                            .rounded(px(4.))
                            .text_size(px(13.))
                            .hover(move |s| s.bg(brand.hover))
                            .on_click(move |_, window, cx| c.find(Focus::Verdict(v.to_string()), window, cx))
                            .child(kit::dot(Some(tk.verdict(v))))
                            .child(div().font_weight(FontWeight::SEMIBOLD).child(n.to_string()))
                            .child(div().text_color(brand.ink2).child(verdict_label(v)))
                    })),
            );
        }
        page = page.child(hero);

        // What to do first.
        let items = a.a("items");
        let mut first: Vec<AnyElement> = Vec::new();
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
                let detail = action.s("detail").to_string();
                if ids.is_empty() {
                    first.push(kit::info_row(
                        Some(kit::lead_number(i + 1, &tk)),
                        title,
                        Some(detail),
                        &tk,
                    ));
                    continue;
                }
                let n = ids.len() as u64;
                let c = ctx.clone();
                let name = title.clone();
                first.push(
                    kit::NavRow::new(ElementId::NamedInteger("ov-pa".into(), i as u64), title)
                        .subtitle(detail)
                        .lead(kit::lead_number(i + 1, &tk))
                        .trail(tn("overview.showItems", n, &[]), tk.ink3)
                        .build(
                            move |window, cx| c.find(Focus::Items(ids.clone(), name.clone()), window, cx),
                            &tk,
                        ),
                );
            }
        } else if !top.is_empty() {
            for (i, item) in top.iter().enumerate() {
                let id = item.s("id").to_string();
                let c = ctx.clone();
                let v = item.s("verdict");
                let detail = if item.has("reason") {
                    item.s("reason")
                } else {
                    item.s("subtitle")
                };
                first.push(
                    kit::NavRow::new(
                        ElementId::NamedInteger("ov-top".into(), i as u64),
                        item.s("title").to_string(),
                    )
                    .subtitle(detail.to_string())
                    .lead(kit::lead_glyph(verdict_glyph(v), tk.verdict(v)))
                    .trail(verdict_label(v), tk.verdict(v))
                    .build(move |window, cx| c.find(Focus::Item(id.clone()), window, cx), &tk),
                );
            }
        } else {
            first.push(kit::info_row(
                Some(kit::lead_glyph(icons::SUCCESS, tk.ok)),
                t("overview.nothing"),
                None,
                &tk,
            ));
        }
        let mut left = div().flex().flex_col().gap(px(20.)).min_w_0().child(kit::section(
            kit::section_head(t("overview.first"), &tk),
            kit::group(first, &tk),
        ));
        let habits = summary.strs("good_practices");
        if !habits.is_empty() {
            left = left.child(kit::section(
                kit::section_head(t("overview.habits"), &tk),
                kit::group(
                    habits
                        .iter()
                        .map(|h| kit::info_row(Some(kit::lead_glyph(icons::CHECK, tk.ink3)), h.to_string(), None, &tk))
                        .collect(),
                    &tk,
                ),
            ));
        }

        // The right column: the quick actions first.
        let quick: Vec<AnyElement> = [
            (
                "storage",
                "overview.quickStorage",
                "overview.quickStorageNote",
                icons::section("cleanup"),
            ),
            (
                "startup",
                "overview.quickStartup",
                "overview.quickStartupNote",
                icons::page("startup"),
            ),
            (
                "protection",
                "overview.quickDefender",
                "overview.quickDefenderNote",
                icons::page("protection"),
            ),
            (
                "restore",
                "overview.quickRestore",
                "overview.quickRestoreNote",
                icons::page("restore"),
            ),
            (
                "assistant",
                "overview.quickAsk",
                "overview.quickAskNote",
                icons::section("assistant"),
            ),
        ]
        .into_iter()
        .enumerate()
        .map(|(i, (target, title, note, glyph))| {
            let c = ctx.clone();
            kit::NavRow::new(ElementId::NamedInteger("ov-quick".into(), i as u64), t(title))
                .subtitle(t(note))
                .lead(kit::lead_glyph(glyph, tk.accent))
                .build(move |window, cx| c.go(target, window, cx), &tk)
        })
        .collect();
        let mut right = div().flex().flex_col().gap(px(20.)).min_w_0().child(kit::section(
            kit::section_head(t("overview.quick"), &tk),
            kit::group(quick, &tk),
        ));
        if let Some(w) = &watch {
            right = right.child(watchui::watch_card(&ctx, w, &tk));
        }
        if let Some(changes) = a.get("changes").filter(|c| c.is_object()) {
            right = right.child(since_panel(&ctx, changes, items, &report.ignored, &tk));
        }
        let open_protection = ctx.clone();
        let open_posture = ctx.clone();
        right = right.child(kit::section(
            kit::section_head(t("overview.security"), &tk),
            kit::group(
                vec![
                    div()
                        .px(px(16.))
                        .py(px(4.))
                        .child(kit::readouts("ov-sec", security_rows(a.at("posture"), &tk), 180., &tk))
                        .into_any_element(),
                    kit::footer_row(vec![
                        kit::link(
                            "ov-protection",
                            t("overview.openProtection"),
                            move |window, cx| open_protection.go("protection", window, cx),
                            &tk,
                        )
                        .into_any_element(),
                        kit::link(
                            "ov-posture",
                            t("overview.openPosture"),
                            move |window, cx| open_posture.go("posture", window, cx),
                            &tk,
                        )
                        .into_any_element(),
                    ]),
                ],
                &tk,
            ),
        ));
        let notes = a.a("notes");
        if !notes.is_empty() {
            right = right.child(kit::section(
                kit::section_head(t("overview.coverage"), &tk),
                kit::group(
                    notes
                        .iter()
                        .take(12)
                        .map(|n| kit::note_row(format!("{}: {}", kit::humanize(n.s("area")), n.s("message")), &tk))
                        .collect(),
                    &tk,
                ),
            ));
        }
        page.child(kit::columns(0.58, left, right, window))
    }
}

/// What changed since the previous scan in the same folder: a section with the tally in its
/// header and the new, changed and vanished items in one group.
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
    let head = kit::section_head(title, tk);
    let mut rows: Vec<AnyElement> = Vec::new();
    if tally.is_empty() {
        rows.push(kit::note_row(t("overview.sinceNothing"), tk));
        return kit::section(head, kit::group(rows, tk));
    }
    rows.push(kit::note_row(tally.join(" · "), tk));
    for (i, item) in fresh.iter().take(5).enumerate() {
        let c = ctx.clone();
        let id = item.s("id").to_string();
        let v = item.s("verdict");
        rows.push(
            kit::NavRow::new(
                ElementId::NamedInteger("ov-new".into(), i as u64),
                item.s("title").to_string(),
            )
            .lead(kit::lead_glyph(verdict_glyph(v), tk.verdict(v)))
            .trail(t("overview.sinceNewTitle"), tk.ink3)
            .build(move |window, cx| c.find(Focus::Item(id.clone()), window, cx), tk),
        );
    }
    for (i, (item, what)) in altered.iter().take(4).enumerate() {
        let c = ctx.clone();
        let id = item.s("id").to_string();
        let v = item.s("verdict");
        rows.push(
            kit::NavRow::new(
                ElementId::NamedInteger("ov-chg".into(), i as u64),
                item.s("title").to_string(),
            )
            .subtitle(what.join(" · "))
            .lead(kit::lead_glyph(verdict_glyph(v), tk.verdict(v)))
            .trail(t("overview.sinceChangedTitle"), tk.ink3)
            .build(move |window, cx| c.find(Focus::Item(id.clone()), window, cx), tk),
        );
    }
    if altered.len() > 4 {
        rows.push(kit::note_row(
            tn("overview.sinceMore", (altered.len() - 4) as u64, &[]),
            tk,
        ));
    }
    if !posture.is_empty() {
        rows.push(kit::info_row(
            Some(kit::lead_glyph(icons::SETTINGS, tk.ink2)),
            t("overview.sinceSettingsTitle"),
            Some(posture.iter().take(8).copied().collect::<Vec<_>>().join(" · ")),
            tk,
        ));
    }
    if !gone.is_empty() {
        let names: Vec<String> = gone.iter().take(4).map(|g| g.s("title").to_string()).collect();
        let mut line = names.join(" · ");
        if gone.len() > 4 {
            line = format!("{line} · {}", tn("overview.sinceMore", (gone.len() - 4) as u64, &[]));
        }
        rows.push(kit::info_row(
            Some(kit::lead_glyph(icons::DELETE, tk.ink3)),
            t("overview.sinceGoneTitle"),
            Some(line),
            tk,
        ));
    }
    if fresh.len() > 1 {
        let c = ctx.clone();
        let ids: Vec<String> = fresh.iter().map(|i| i.s("id").to_string()).collect();
        rows.push(kit::footer_row(vec![
            kit::link(
                "ov-new-all",
                tn("overview.sinceShowNew", fresh.len() as u64, &[]),
                move |window, cx| c.find(Focus::Items(ids.clone(), t("findings.newSince")), window, cx),
                tk,
            )
            .into_any_element(),
        ]));
    }
    kit::section(head, kit::group(rows, tk))
}
