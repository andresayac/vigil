//! Reliability: blue screens, unexpected shutdowns, crashes, hangs, failing services, hardware
//! and disk errors, failed updates and installs from the event logs, a chart of problems per day,
//! hints, the selected event's details and boot times.

use std::collections::{BTreeSet, HashMap};
use std::rc::Rc;
use std::sync::Arc;

use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    ClipboardItem, Context, Div, ElementId, FontWeight, Hsla, Image, InteractiveElement as _, IntoElement,
    ParentElement, Render, StatefulInteractiveElement as _, Styled, Window, div, px,
};
use serde_json::{Value, json};
use vigil_core::state::AppState;

use crate::app::Ctx;
use crate::data::{self, Src};
use crate::format::num;
use crate::i18n::{t, t_or, tf, tn};
use crate::icons;
use crate::pages::common::{self, Acting, Acts, day_short, when};
use crate::theme::{FONT_MONO, Tokens, tokens};
use crate::ui;
use crate::ui::kit::{self, BarColumn, J as _};

const ORDER: [&str; 9] = [
    "bluescreen",
    "shutdown",
    "app_crash",
    "app_hang",
    "service",
    "hardware",
    "disk",
    "update",
    "install",
];
const STACK: [&str; 8] = [
    "bluescreen",
    "shutdown",
    "hardware",
    "app_crash",
    "app_hang",
    "service",
    "disk",
    "update",
];

fn cat_key(cat: &str) -> String {
    let key = match cat {
        "app_crash" => "appCrash",
        "app_hang" => "appHang",
        other => other,
    };
    t_or(&format!("rel.cat.{key}"), cat)
}

fn tone(cat: &str, tk: &Tokens) -> Hsla {
    match cat {
        "bluescreen" | "shutdown" | "hardware" => tk.bad,
        "install" => tk.ink3,
        _ => tk.warn,
    }
}

fn kind_text(e: &Value) -> String {
    if e.s("category") == "update" {
        return t("rel.kind.updateFailed");
    }
    let kind = e.s("kind");
    let key = match kind {
        "kernel_power" => "kernelPower",
        "power_loss" => "powerLoss",
        "power_button" => "powerButton",
        "start_failed" => "startFailed",
        "start_timeout" => "startTimeout",
        "stopped_with_error" => "stoppedWithError",
        "bad_block" => "badBlock",
        "controller_error" => "controllerError",
        "paging_error" => "pagingError",
        "needs_repair" => "needsRepair",
        "install_failed" => "installFailed",
        "remove_failed" => "removeFailed",
        other => other,
    };
    t_or(&format!("rel.kind.{key}"), kind)
}

fn subject(e: &Value) -> String {
    let s = e.s("subject");
    if e.s("category") == "disk" {
        let lower = s.to_lowercase();
        if let Some(pos) = lower.find("harddisk") {
            let digits: String = lower[pos + 8..].chars().take_while(|c| c.is_ascii_digit()).collect();
            if !digits.is_empty() {
                return tf("rel.disk", &[("n", &digits)]);
            }
        }
    }
    s.to_string()
}

fn headline(e: &Value) -> String {
    let kind = kind_text(e);
    let subject = subject(e);
    if subject.is_empty() {
        return kind;
    }
    if matches!(e.s("category"), "bluescreen" | "shutdown" | "hardware") {
        format!("{kind}: {subject}")
    } else {
        format!("{subject}: {kind}")
    }
}

fn severity(e: &Value, tk: &Tokens) -> (char, Hsla) {
    match e.s("severity") {
        "critical" | "error" => (icons::ERROR, tk.bad),
        "warning" => (icons::WARNING, tk.warn),
        _ => (icons::INFO, tk.ink2),
    }
}

fn seconds(ms: f64) -> String {
    tf("rel.seconds", &[("n", &num(ms / 1000.0, 1))])
}

pub struct ReliabilityPage {
    ctx: Ctx,
    days: u32,
    data: Option<Value>,
    loading: bool,
    error: Option<String>,
    day: Option<String>,
    hint: Option<(Vec<String>, String)>,
    category: Option<&'static str>,
    selected: Option<String>,
    open: BTreeSet<String>,
    all: BTreeSet<&'static str>,
    copied: bool,
    icons: HashMap<String, Arc<Image>>,
    acting: Acting,
}

impl Acts for ReliabilityPage {
    fn acting(&mut self) -> &mut Acting {
        &mut self.acting
    }
    fn core(&self) -> Option<Arc<AppState>> {
        self.ctx.core.clone()
    }
    fn after(&mut self, _: &mut Window, _: &mut Context<Self>) {}
}

impl ReliabilityPage {
    pub fn new(ctx: Ctx, cx: &mut Context<Self>) -> Self {
        let mut page = Self {
            ctx,
            days: 30,
            data: None,
            loading: false,
            error: None,
            day: None,
            hint: None,
            category: None,
            selected: None,
            open: BTreeSet::new(),
            all: BTreeSet::new(),
            copied: false,
            icons: HashMap::new(),
            acting: Acting::default(),
        };
        page.load(cx);
        page
    }

    fn load(&mut self, cx: &mut Context<Self>) {
        self.loading = true;
        let core = self.ctx.core.clone();
        let days = self.days;
        common::read(
            cx,
            move || {
                let data = data::fetch(core.as_ref(), Src::Reliability(days));
                let paths: Vec<String> = data
                    .as_ref()
                    .ok()
                    .map(|d| {
                        d.a("events")
                            .iter()
                            .filter(|e| {
                                matches!(e.s("category"), "app_crash" | "app_hang")
                                    && e.s("path").to_lowercase().ends_with(".exe")
                            })
                            .map(|e| e.s("path").to_string())
                            .collect::<BTreeSet<_>>()
                            .into_iter()
                            .collect()
                    })
                    .unwrap_or_default();
                let icons = data::fetch(core.as_ref(), Src::Icons(paths))
                    .ok()
                    .and_then(|v| v.as_object().cloned())
                    .map(|o| {
                        o.iter()
                            .filter_map(|(k, v)| kit::image(v.as_str()?).map(|i| (k.to_lowercase(), i)))
                            .collect()
                    })
                    .unwrap_or_default();
                (data, icons)
            },
            |this: &mut Self, (result, icons), _| {
                this.loading = false;
                this.icons = icons;
                match result {
                    Ok(v) => {
                        if let Some(sel) = &this.selected
                            && !v.a("events").iter().any(|e| e.s("id") == sel)
                        {
                            this.selected = None;
                        }
                        this.data = Some(v);
                        this.error = None;
                    }
                    Err(e) => this.error = Some(e),
                }
            },
        );
    }

    fn scoped(&self) -> Vec<Value> {
        self.data
            .as_ref()
            .map(|d| {
                d.a("events")
                    .iter()
                    .filter(|e| {
                        self.day
                            .as_ref()
                            .is_none_or(|day| e.s("time").get(..10) == Some(day.as_str()))
                    })
                    .filter(|e| {
                        self.hint
                            .as_ref()
                            .is_none_or(|(ids, _)| ids.iter().any(|id| id == e.s("id")))
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    fn chart(&self, cx: &mut Context<Self>, tk: &Tokens) -> Div {
        let events = self.data.as_ref().map(|d| d.a("events").to_vec()).unwrap_or_default();
        let days = kit::last_days(
            self.data
                .as_ref()
                .map(|d| d.n("days") as usize)
                .filter(|d| *d > 0)
                .unwrap_or(self.days as usize),
        );
        let mut per_day: HashMap<String, HashMap<String, f64>> = HashMap::new();
        for e in &events {
            if let Some(day) = e.s("time").get(..10) {
                *per_day
                    .entry(day.to_string())
                    .or_default()
                    .entry(e.s("category").to_string())
                    .or_default() += 1.0;
            }
        }
        let problems = events.iter().filter(|e| e.s("category") != "install").count();
        let max = days
            .iter()
            .map(|d| {
                per_day
                    .get(d)
                    .map(|c| STACK.iter().map(|k| c.get(*k).copied().unwrap_or(0.0)).sum::<f64>())
                    .unwrap_or(0.0)
            })
            .fold(0.0, f64::max);
        let top = kit::chart_top(max);
        let labels = kit::day_labels(days.len(), |i| day_short(&days[i]), &t("rel.today"));
        let columns: Vec<BarColumn> = days
            .iter()
            .zip(labels)
            .map(|(day, label)| {
                let counts = per_day.get(day).cloned().unwrap_or_default();
                let count = |k: &str| counts.get(k).copied().unwrap_or(0.0);
                let total: f64 = STACK.iter().map(|k| count(k)).sum();
                let installs = count("install");
                let mut tip: Vec<String> = STACK
                    .iter()
                    .filter(|k| count(k) > 0.0)
                    .map(|k| format!("{}: {}", cat_key(k), num(count(k), 0)))
                    .collect();
                if total == 0.0 {
                    tip.push(t("rel.noProblemsDay"));
                }
                if installs > 0.0 {
                    tip.push(tn("rel.installsDay", installs as u64, &[]));
                }
                BarColumn {
                    key: day.clone(),
                    name: when(day),
                    segments: STACK.iter().map(|k| (count(k), tone(k, tk))).collect(),
                    tip,
                    mark: installs > 0.0,
                    label,
                }
            })
            .collect();
        let weak = cx.entity().downgrade();
        let pick: kit::OnPick = Rc::new(move |key: String, _, cx| {
            let _ = weak.update(cx, |this, cx| {
                this.day = if this.day.as_deref() == Some(key.as_str()) {
                    None
                } else {
                    Some(key)
                };
                this.hint = None;
                cx.notify();
            });
        });
        kit::panel(tk)
            .child(
                kit::row()
                    .child(kit::h2(t("rel.chartTitle")))
                    .child(kit::faint(tn("rel.problems", problems as u64, &[]), tk))
                    .child(div().flex_1())
                    .child(div().w(px(10.)).h(px(10.)).bg(tk.bad))
                    .child(kit::faint(t("rel.legendSerious"), tk))
                    .child(div().w(px(10.)).h(px(10.)).bg(tk.warn))
                    .child(kit::faint(t("rel.legendProblems"), tk))
                    .child(div().w(px(6.)).h(px(6.)).rounded(px(3.)).bg(tk.ink3))
                    .child(kit::faint(cat_key("install"), tk)),
            )
            .child(kit::bar_chart(
                "rel-chart",
                columns,
                top,
                140.,
                self.day.clone(),
                Some(pick),
                tk,
            ))
    }

    fn sections(&self, cx: &mut Context<Self>, tk: &Tokens) -> Div {
        let scoped = self.scoped();
        let mut out = div().flex().flex_col().gap_3();
        let mut any = false;
        for cat in ORDER {
            if self.category.is_some_and(|c| c != cat) {
                continue;
            }
            let events: Vec<&Value> = scoped.iter().filter(|e| e.s("category") == cat).collect();
            if events.is_empty() {
                continue;
            }
            any = true;
            let show_all = self.all.contains(cat);
            let mut panel = kit::panel(tk).child(
                kit::row()
                    .child(kit::h2(cat_key(cat)))
                    .child(kit::faint(events.len().to_string(), tk)),
            );
            let rows_count;
            if matches!(cat, "app_crash" | "app_hang") {
                // Grouped by program.
                let mut groups: Vec<(String, Vec<&Value>)> = Vec::new();
                for e in &events {
                    let key = e.s("subject").to_lowercase();
                    match groups.iter_mut().find(|(k, _)| *k == key) {
                        Some((_, list)) => list.push(e),
                        None => groups.push((key, vec![e])),
                    }
                }
                groups.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(b.1[0].s("time").cmp(a.1[0].s("time"))));
                rows_count = groups.len();
                for (gi, (key, list)) in groups.iter().enumerate().take(if show_all { usize::MAX } else { 8 }) {
                    let first = list[0];
                    let mut modules: HashMap<&str, usize> = HashMap::new();
                    for e in list {
                        if e.has("module") {
                            *modules.entry(e.s("module")).or_default() += 1;
                        }
                    }
                    let top_module = modules
                        .iter()
                        .max_by_key(|(_, n)| **n)
                        .map(|(m, n)| (m.to_string(), *n));
                    let open_key = format!("{cat}:{key}");
                    let open = self.open.contains(&open_key);
                    let weak = cx.entity().downgrade();
                    let toggle = open_key.clone();
                    let count_text = tn(
                        if cat == "app_crash" { "rel.crashes" } else { "rel.hangs" },
                        list.len() as u64,
                        &[],
                    );
                    let icon = self.icons.get(&first.s("path").to_lowercase()).cloned();
                    panel = panel.child(
                        kit::list_row(
                            ElementId::Name(format!("rel-g-{cat}-{gi}").into()),
                            first.s("subject").to_string(),
                            false,
                            move |_, cx| {
                                let _ = weak.update(cx, |this, cx| {
                                    if !this.open.remove(&toggle) {
                                        this.open.insert(toggle.clone());
                                    }
                                    cx.notify();
                                });
                            },
                            tk,
                        )
                        .child(kit::glyph(
                            if open {
                                icons::CHEVRON_DOWN
                            } else {
                                icons::CHEVRON_RIGHT
                            },
                            10.,
                            tk.ink2,
                        ))
                        .child(match icon {
                            Some(image) => div().w(px(16.)).h(px(16.)).child(gpui_kit::img(image).size_full()),
                            None => kit::glyph('\u{E7C4}', 16., tk.ink2),
                        })
                        .child(
                            div()
                                .font_weight(FontWeight::SEMIBOLD)
                                .min_w(px(120.))
                                .child(kit::plain(first.s("subject").to_string())),
                        )
                        .child(kit::body(count_text))
                        .child(kit::faint(tf("rel.last", &[("when", &when(first.s("time")))]), tk))
                        .when_some(top_module, |this, (module, n)| {
                            this.child(kit::faint(
                                tf("rel.inModule", &[("module", &module), ("count", &n.to_string())]),
                                tk,
                            ))
                        }),
                    );
                    if open {
                        for (ei, e) in list.iter().enumerate() {
                            panel = panel.child(
                                self.event_row(e, &format!("rel-ge-{cat}-{gi}-{ei}"), true, cx, tk)
                                    .pl(px(38.)),
                            );
                        }
                    }
                }
            } else {
                rows_count = events.len();
                for (ei, e) in events.iter().enumerate().take(if show_all { usize::MAX } else { 8 }) {
                    panel = panel.child(self.event_row(e, &format!("rel-e-{cat}-{ei}"), false, cx, tk));
                }
            }
            if rows_count > 8 {
                let weak = cx.entity().downgrade();
                let label = if show_all {
                    t("rel.showFewer")
                } else {
                    tn("rel.showAll", rows_count as u64, &[])
                };
                panel = panel.child(kit::link(
                    ElementId::Name(format!("rel-all-{cat}").into()),
                    label,
                    move |_, cx| {
                        let _ = weak.update(cx, |this, cx| {
                            if !this.all.remove(cat) {
                                this.all.insert(cat);
                            }
                            cx.notify();
                        });
                    },
                    tk,
                ));
            }
            out = out.child(panel);
        }
        if !any {
            out = out.child(kit::faint(
                t(if self.loading { "common.reading" } else { "rel.noneHere" }),
                tk,
            ));
        }
        out
    }

    fn event_row(&self, e: &Value, id: &str, sub: bool, cx: &mut Context<Self>, tk: &Tokens) -> gpui_kit::base::Button {
        let (g, c) = severity(e, tk);
        let event_id = e.s("id").to_string();
        let weak = cx.entity().downgrade();
        let detail = if e.s("category") == "bluescreen" {
            e.s("code").to_string()
        } else if sub {
            [e.s("codeName"), e.s("code"), e.s("parameters")]
                .into_iter()
                .find(|s| !s.is_empty())
                .unwrap_or("")
                .to_string()
        } else if e.has("code") {
            if e.has("codeName") {
                e.s("codeName").to_string()
            } else {
                format!("{} {}", t("rel.field.errorCode"), e.s("code"))
            }
        } else {
            e.s("version").to_string()
        };
        let text = if sub {
            let mut base = if e.has("module") {
                e.s("module").to_string()
            } else {
                kind_text(e)
            };
            if e.has("version") {
                base = format!("{base} · {}", e.s("version"));
            }
            base
        } else {
            headline(e)
        };
        kit::list_row(
            ElementId::Name(id.to_string().into()),
            headline(e),
            self.selected.as_deref() == Some(event_id.as_str()),
            move |_, cx| {
                let _ = weak.update(cx, |this, cx| {
                    this.selected = Some(event_id.clone());
                    cx.notify();
                });
            },
            tk,
        )
        .child(kit::glyph(g, 14., c))
        .child(div().w(px(150.)).flex_none().child(when(e.s("time"))))
        .child(
            div()
                .flex_1()
                .min_w_0()
                .overflow_hidden()
                .text_ellipsis()
                .whitespace_nowrap()
                .child(text),
        )
        .child(
            kit::faint(detail, tk)
                .font_family(FONT_MONO)
                .max_w(px(200.))
                .overflow_hidden()
                .text_ellipsis()
                .whitespace_nowrap(),
        )
    }

    fn detail(&self, cx: &mut Context<Self>, tk: &Tokens) -> Div {
        let event = self.selected.as_ref().and_then(|id| {
            self.data
                .as_ref()?
                .a("events")
                .iter()
                .find(|e| e.s("id") == id)
                .cloned()
        });
        let Some(e) = event else {
            return kit::panel(tk).child(kit::faint(t("rel.select"), tk));
        };
        let cat = e.s("category");
        let (g, c) = severity(&e, tk);
        let mut rows: Vec<(String, String, bool)> = vec![(t("rel.field.when"), when(e.s("time")), false)];
        if e.has("subject") {
            let label = match cat {
                "bluescreen" => "rel.field.stopCode",
                "shutdown" => "rel.field.subject",
                "app_crash" | "app_hang" => "rel.field.program",
                "service" => "rel.field.service",
                "hardware" => "rel.field.component",
                "disk" => "rel.field.device",
                "update" => "rel.field.update",
                _ => "rel.field.product",
            };
            rows.push((t(label), subject(&e), false));
        }
        if e.has("version") {
            rows.push((t("rel.field.version"), e.s("version").to_string(), false));
        }
        if e.has("module") {
            rows.push((
                t("rel.field.module"),
                format!("{} ({})", e.s("module"), e.s("moduleVersion")),
                false,
            ));
        }
        if e.has("code") {
            let label = match cat {
                "bluescreen" => "rel.field.stopCode",
                "app_crash" => "rel.field.exception",
                _ => "rel.field.errorCode",
            };
            let value = if cat == "bluescreen" || !e.has("codeName") {
                e.s("code").to_string()
            } else {
                format!("{} ({})", e.s("code"), e.s("codeName"))
            };
            rows.push((t(label), value, true));
        }
        if e.has("parameters") {
            let label = match cat {
                "app_crash" => "rel.field.offset",
                "app_hang" => "rel.field.hangType",
                "service" => "rel.field.timeout",
                _ => "rel.field.parameters",
            };
            rows.push((t(label), e.s("parameters").to_string(), cat != "app_hang"));
        }
        if e.has("path") {
            rows.push((
                t(if cat == "bluescreen" {
                    "rel.field.dump"
                } else {
                    "rel.field.programFile"
                }),
                e.s("path").to_string(),
                true,
            ));
        }
        if cat == "bluescreen"
            && let Some(kept) = e.at("pathExists").as_bool()
        {
            rows.push((
                String::new(),
                t(if kept { "rel.dumpKept" } else { "rel.dumpGone" }),
                false,
            ));
        }
        if e.has("publisher") {
            rows.push((t("rel.field.publisher"), e.s("publisher").to_string(), false));
        }
        if e.n("count") > 0.0 {
            rows.push((t("rel.field.serviceCount"), num(e.n("count"), 0), false));
        }
        rows.push((
            t("rel.field.source"),
            tf(
                "rel.sourceValue",
                &[("provider", e.s("provider")), ("id", &kit::text(e.at("eventId")))],
            ),
            false,
        ));
        rows.push((
            t("rel.field.log"),
            tf(
                "rel.logValue",
                &[("log", e.s("log")), ("record", &kit::text(e.at("recordId")))],
            ),
            false,
        ));
        let copy_text = {
            let mut lines = vec![headline(&e)];
            lines.extend(
                rows.iter()
                    .filter(|(l, _, _)| !l.is_empty())
                    .map(|(l, v, _)| format!("{l}: {v}")),
            );
            lines.push(String::new());
            lines.push(e.s("message").to_string());
            lines.join("\n")
        };
        let mut pane = kit::panel(tk)
            .child(kit::row().child(kit::glyph(g, 18., c)).child(kit::h3(headline(&e))))
            .child(kit::faint(cat_key(cat), tk));
        for (i, (label, value, mono)) in rows.into_iter().enumerate() {
            pane = pane.child(kit::kv_text(
                ElementId::NamedInteger("rel-f".into(), i as u64),
                label,
                value,
                mono,
                120.,
                tk,
            ));
        }
        if e.has("message") {
            pane = pane.child(
                div()
                    .id("rel-message")
                    .max_h(px(220.))
                    .overflow_y_scroll()
                    .p_2()
                    .rounded(px(4.))
                    .bg(tk.sunken)
                    .text_size(px(12.))
                    .child(kit::sel("rel-message-text", e.s("message").to_string())),
            );
        }
        pane.child(
            kit::row()
                .child(
                    ui::button("rel-copy", t(if self.copied { "common.copied" } else { "rel.copy" }))
                        .glyph('\u{E8C8}')
                        .on_click(cx.listener(move |this, _, _, cx| {
                            cx.write_to_clipboard(ClipboardItem::new_string(copy_text.clone()));
                            this.copied = true;
                            cx.notify();
                            cx.spawn(async move |this, cx| {
                                cx.background_executor()
                                    .timer(std::time::Duration::from_millis(1500))
                                    .await;
                                let _ = this.update(cx, |this, cx| {
                                    this.copied = false;
                                    cx.notify();
                                });
                            })
                            .detach();
                        })),
                )
                .child(
                    ui::button("rel-viewer", t("menu.eventViewer")).on_click(cx.listener(|this, _, window, cx| {
                        common::send_json(
                            this,
                            json!({"kind": "shell", "op": "console", "name": "eventvwr.msc"}),
                            window,
                            cx,
                        )
                    })),
                ),
        )
    }

    fn boots(&self, tk: &Tokens) -> Div {
        let d = self.data.clone().unwrap_or(Value::Null);
        let boots = d.a("boots");
        let mut panel = kit::panel(tk).child(kit::h2(t("rel.bootTitle")));
        if boots.is_empty() {
            let hidden = d
                .strs("unreadLogs")
                .contains(&"Microsoft-Windows-Diagnostics-Performance/Operational");
            return panel.child(kit::faint(
                t(if hidden && !self.ctx.elevated {
                    "rel.bootNeedsAdmin"
                } else {
                    "rel.bootNone"
                }),
                tk,
            ));
        }
        let average = boots.iter().map(|b| b.n("bootMs")).sum::<f64>() / boots.len() as f64;
        let slowest = boots
            .iter()
            .max_by(|a, b| a.n("bootMs").total_cmp(&b.n("bootMs")))
            .cloned()
            .unwrap_or(Value::Null);
        panel = panel
            .child(kit::kv(
                t("rel.bootLast"),
                div().child(seconds(boots[0].n("bootMs"))),
                160.,
                tk,
            ))
            .child(kit::kv(
                tn("rel.bootAverage", boots.len() as u64, &[]),
                div().child(seconds(average)),
                160.,
                tk,
            ))
            .child(kit::kv(
                t("rel.bootSlowest"),
                kit::row()
                    .child(seconds(slowest.n("bootMs")))
                    .child(kit::faint(when(slowest.s("time")), tk)),
                160.,
                tk,
            ))
            .child(kit::faint(t("rel.bootNote"), tk));
        panel
    }
}

impl Render for ReliabilityPage {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let weak = cx.entity().downgrade();
        let periods: Vec<(u32, String)> = [7u32, 30, 90]
            .iter()
            .map(|d| (*d, tn("common.days", u64::from(*d), &[])))
            .collect();
        let mut head = kit::row()
            .child(ui::page_title(t("page.reliability")))
            .child(ui::segmented(
                "rel-period",
                t("rel.period"),
                periods,
                self.days,
                move |d, _, cx| {
                    let _ = weak.update(cx, |this, cx| {
                        if this.days != d {
                            this.days = d;
                            this.day = None;
                            this.hint = None;
                            this.load(cx);
                        }
                    });
                },
                &tk,
            ));
        if self.loading {
            head = head.child(kit::faint(t("common.reading"), &tk));
        }
        head = head
            .child(div().flex_1())
            .child(
                ui::command("rel-monitor", '\u{E9D2}', t("rel.monitor")).on_click(cx.listener(
                    |this, _, window, cx| {
                        common::send_json(
                            this,
                            json!({"kind": "shell", "op": "tool", "name": "reliability"}),
                            window,
                            cx,
                        )
                    },
                )),
            )
            .child(
                ui::command("rel-events", '\u{E8A7}', t("menu.eventViewer")).on_click(cx.listener(
                    |this, _, window, cx| {
                        common::send_json(
                            this,
                            json!({"kind": "shell", "op": "console", "name": "eventvwr.msc"}),
                            window,
                            cx,
                        )
                    },
                )),
            )
            .child(ui::separator(&tk))
            .child(
                ui::command("rel-refresh", icons::REFRESH, t("common.refresh"))
                    .disabled(self.loading)
                    .on_click(cx.listener(|this, _, _, cx| this.load(cx))),
            );
        let mut page = kit::page("reliability")
            .child(head)
            .child(kit::faint(t("rel.note"), &tk))
            .children(self.acting.bar("rel-result", &tk));
        if let Some(e) = &self.error {
            page = page.child(kit::colored(e.clone(), tk.warn));
        }
        let Some(d) = self.data.clone() else {
            return page.child(kit::faint(t("common.reading"), &tk));
        };
        page = page.child(self.chart(cx, &tk));
        let hints = d.a("hints");
        let problems = d.a("events").iter().filter(|e| e.s("category") != "install").count();
        if !hints.is_empty() {
            let mut panel = kit::panel(&tk).child(kit::h2(t("rel.hintsTitle")));
            for (i, h) in hints.iter().enumerate() {
                let (g, c) = if h.s("severity") == "warn" {
                    (icons::WARNING, tk.warn)
                } else {
                    (icons::INFO, tk.ink2)
                };
                let ids: Vec<String> = h.strs("events").into_iter().map(str::to_string).collect();
                let title = h.s("title").to_string();
                let weak = cx.entity().downgrade();
                panel = panel.child(
                    div()
                        .flex()
                        .gap_2()
                        .items_start()
                        .child(div().pt(px(2.)).child(kit::glyph(g, 16., c)))
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .child(kit::body(title.clone()).font_weight(FontWeight::SEMIBOLD))
                                .child(
                                    kit::sel(
                                        ElementId::NamedInteger("rel-hint".into(), i as u64),
                                        h.s("text").to_string(),
                                    )
                                    .text_size(px(13.)),
                                )
                                .when(!ids.is_empty(), |this| {
                                    this.child(kit::link(
                                        ElementId::NamedInteger("rel-hint-ev".into(), i as u64),
                                        t("rel.showEvents"),
                                        move |_, cx| {
                                            let _ = weak.update(cx, |this, cx| {
                                                this.selected = ids.first().cloned();
                                                this.hint = Some((ids.clone(), title.clone()));
                                                this.category = None;
                                                this.day = None;
                                                cx.notify();
                                            });
                                        },
                                        &tk,
                                    ))
                                }),
                        ),
                );
            }
            page = page.child(panel);
        } else if problems == 0 {
            page = page.child(
                kit::panel(&tk)
                    .flex_row()
                    .gap_2()
                    .child(kit::glyph(icons::CHECK, 16., tk.ok))
                    .child(kit::body(tf("rel.allClear", &[("days", &self.days.to_string())]))),
            );
        }
        // Filters.
        let scoped = self.scoped();
        let weak = cx.entity().downgrade();
        let mut chips = kit::row().child(kit::chip(
            "rel-all",
            t("rel.all"),
            Some(scoped.len()),
            self.category.is_none(),
            false,
            move |_, cx| {
                let _ = weak.update(cx, |this, cx| {
                    this.category = None;
                    cx.notify();
                });
            },
            &tk,
        ));
        for cat in ORDER {
            let n = scoped.iter().filter(|e| e.s("category") == cat).count();
            let weak = cx.entity().downgrade();
            chips = chips.child(kit::chip(
                ElementId::Name(format!("rel-cat-{cat}").into()),
                cat_key(cat),
                Some(n),
                self.category == Some(cat),
                n == 0,
                move |_, cx| {
                    let _ = weak.update(cx, |this, cx| {
                        this.category = Some(cat);
                        cx.notify();
                    });
                },
                &tk,
            ));
        }
        page = page.child(chips);
        if self.day.is_some() || self.hint.is_some() {
            let text = match (&self.day, &self.hint) {
                (Some(day), _) => tf("rel.showingDay", &[("date", &when(day))]),
                (None, Some((_, title))) => tf("rel.showingHint", &[("title", title)]),
                _ => String::new(),
            };
            let weak = cx.entity().downgrade();
            page = page.child(kit::row().child(kit::faint(text, &tk)).child(kit::link(
                "rel-clear",
                t("rel.clearFilter"),
                move |_, cx| {
                    let _ = weak.update(cx, |this, cx| {
                        this.day = None;
                        this.hint = None;
                        cx.notify();
                    });
                },
                &tk,
            )));
        }
        let sections = self.sections(cx, &tk);
        let side = div()
            .flex()
            .flex_col()
            .gap_3()
            .child(self.detail(cx, &tk))
            .child(self.boots(&tk));
        let wide = f32::from(window.viewport_size().width) >= 1100.;
        page = if wide {
            page.child(
                div()
                    .flex()
                    .gap_3()
                    .items_start()
                    .child(sections.flex_1().min_w_0())
                    .child(side.w(px(360.)).flex_none()),
            )
        } else {
            page.child(sections).child(side)
        };
        let mut footer = tn(
            "rel.footer",
            d.a("events").len() as u64,
            &[("when", &common::when_ms(d.i("readMs")))],
        );
        if d.b("truncated") {
            footer = format!("{footer} · {}", t("rel.truncated"));
        }
        let unread: Vec<&str> = d.strs("unreadLogs");
        if !unread.is_empty() {
            footer = format!("{footer} · {}", tf("rel.unread", &[("logs", &unread.join(", "))]));
        }
        page.child(kit::faint(footer, &tk))
    }
}
