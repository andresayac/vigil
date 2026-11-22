//! Battery and sleep: the battery's health and charge, what keeps the computer awake now, the
//! sleeps and wakes of the last week with what woke it, what may wake it (scheduled tasks, devices,
//! wake timers), and the active power plan's sleep settings. Read only: the page opens Settings and
//! Optimize, and changes nothing itself.

use std::sync::Arc;

use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    Context, Div, ElementId, FontWeight, Hsla, IntoElement, ParentElement, Render, Styled, Window, div, px,
};
use serde_json::{Value, json};
use vigil_core::state::AppState;

use crate::app::Ctx;
use crate::data::{self, Src};
use crate::format::num;
use crate::i18n::{t, tf, tn};
use crate::icons;
use crate::pages::common::{self, Acting, Acts, when, when_ms};
use crate::theme::{Tokens, tokens};
use crate::ui;
use crate::ui::kit::{self, J as _, Readout};

/// Events shown before "Show all".
const FIRST_EVENTS: usize = 20;
/// Battery glyph (Segoe Fluent Icons "Battery10").
const BATTERY: char = '\u{E83F}';
/// Moon glyph, for sleep.
const SLEEP: char = '\u{E708}';

pub struct PowerPage {
    ctx: Ctx,
    data: Option<Value>,
    loading: bool,
    error: Option<String>,
    all_events: bool,
    acting: Acting,
}

impl Acts for PowerPage {
    fn acting(&mut self) -> &mut Acting {
        &mut self.acting
    }
    fn core(&self) -> Option<Arc<AppState>> {
        self.ctx.core.clone()
    }
    fn after(&mut self, _: &mut Window, _: &mut Context<Self>) {}
}

/// A timeout in seconds as text ("Never" for 0; "—" when unknown).
fn duration(seconds: Option<u64>) -> String {
    match seconds {
        None => "—".to_string(),
        Some(0) => t("battery.never"),
        Some(s) if s < 3600 => tn("battery.minutes", s.div_ceil(60), &[]),
        Some(s) if s % 3600 == 0 => tn("battery.hours", s / 3600, &[]),
        Some(s) => format!(
            "{} {}",
            tn("battery.hours", s / 3600, &[]),
            tn("battery.minutes", (s % 3600).div_ceil(60), &[])
        ),
    }
}

/// "Plugged in: … · On battery: …" for a setting with both values (only one shown on a computer
/// without a battery).
fn ac_dc(ac: String, dc: String, battery: bool) -> String {
    if battery {
        tf("battery.acdc", &[("ac", &ac), ("dc", &dc)])
    } else {
        ac
    }
}

fn seconds(v: &Value, key: &str) -> Option<u64> {
    v.at(key).as_u64()
}

fn lid_text(action: Option<u64>) -> String {
    match action {
        Some(0) => t("battery.lid.nothing"),
        Some(1) => t("battery.lid.sleep"),
        Some(2) => t("battery.lid.hibernate"),
        Some(3) => t("battery.lid.shutdown"),
        _ => "—".to_string(),
    }
}

fn timers_text(value: Option<u64>) -> String {
    match value {
        Some(0) => t("battery.timersOff"),
        Some(1) => t("battery.timersOn"),
        Some(2) => t("battery.timersImportant"),
        _ => "—".to_string(),
    }
}

fn kind_text(kind: &str) -> String {
    match kind {
        "display" => t("battery.kind.display"),
        "system" => t("battery.kind.system"),
        "awaymode" => t("battery.kind.awaymode"),
        "execution" => t("battery.kind.execution"),
        "perfboost" => t("battery.kind.perfboost"),
        "activelockscreen" => t("battery.kind.lockscreen"),
        other => other.to_string(),
    }
}

fn source_text(source: &str) -> String {
    match source {
        "process" => t("battery.source.process"),
        "service" => t("battery.source.service"),
        "driver" => t("battery.source.driver"),
        _ => t("battery.source.other"),
    }
}

fn event_text(e: &Value) -> String {
    match e.s("kind") {
        "sleep" => t("battery.event.sleep"),
        "hibernate" => t("battery.event.hibernate"),
        "resume" => t("battery.event.resume"),
        "standby_enter" => t("battery.event.standbyEnter"),
        "standby_exit" => t("battery.event.standbyExit"),
        _ => {
            let source = if e.has("source") {
                e.s("source").to_string()
            } else {
                t("battery.unknownSource")
            };
            tf("battery.event.wake", &[("source", &source)])
        }
    }
}

fn state_text(state: &str) -> String {
    match state {
        "charging" => t("battery.state.charging"),
        "discharging" => t("battery.state.discharging"),
        "plugged_in" => t("battery.state.pluggedIn"),
        _ => t("battery.state.unknown"),
    }
}

/// The title and text of a hint (the core gives its code and figures).
fn hint_text(h: &Value) -> (String, String) {
    let count = h.i("count").max(0) as u64;
    let n = count.to_string();
    match h.s("code") {
        "battery_replace" => (
            t("battery.hint.replaceTitle"),
            tf("battery.hint.replaceText", &[("n", &n)]),
        ),
        "battery_worn" => (t("battery.hint.wornTitle"), tf("battery.hint.wornText", &[("n", &n)])),
        "kept_awake" => (
            t("battery.hint.awakeTitle"),
            tn("battery.hint.awakeText", count, &[("name", h.s("subject"))]),
        ),
        "timer_wakes" => (
            t("battery.hint.timerTitle"),
            tn("battery.hint.timerText", count, &[("name", h.s("subject"))]),
        ),
        "frequent_wakes" => (
            t("battery.hint.frequentTitle"),
            tn("battery.hint.frequentText", count, &[]),
        ),
        "wake_tasks" => (t("battery.hint.tasksTitle"), tn("battery.hint.tasksText", count, &[])),
        other => (other.to_string(), String::new()),
    }
}

impl PowerPage {
    pub fn new(ctx: Ctx, cx: &mut Context<Self>) -> Self {
        let mut page = Self {
            ctx,
            data: None,
            loading: false,
            error: None,
            all_events: false,
            acting: Acting::default(),
        };
        page.load(cx);
        page
    }

    fn load(&mut self, cx: &mut Context<Self>) {
        self.loading = true;
        let core = self.ctx.core.clone();
        common::read(
            cx,
            move || data::fetch(core.as_ref(), Src::Power),
            |this: &mut Self, result, _| {
                this.loading = false;
                match result {
                    Ok(v) => {
                        this.data = Some(v);
                        this.error = None;
                    }
                    Err(e) => this.error = Some(e),
                }
            },
        );
    }

    fn open(&mut self, url: &str, window: &mut Window, cx: &mut Context<Self>) {
        common::send_json(self, json!({"kind": "shell", "op": "url", "url": url}), window, cx);
    }

    /// The headline: the battery's charge, or that there is none.
    fn status(&self, d: &Value, tk: &Tokens) -> Div {
        let plugged = match d.at("onAc").as_bool() {
            Some(true) => t("battery.onAc"),
            Some(false) => t("battery.onBattery"),
            None => String::new(),
        };
        let (glyph, color, title, line) = if d.b("hasBattery") {
            let percent = d.at("batteryPercent").as_u64();
            let title = match percent {
                Some(p) => tf("battery.statusBattery", &[("percent", &p.to_string())]),
                None => t("battery.statusBatteryUnknown"),
            };
            let low = percent.is_some_and(|p| p <= 15) && d.at("onAc").as_bool() == Some(false);
            (BATTERY, if low { tk.warn } else { tk.ok }, title, plugged)
        } else {
            (SLEEP, tk.ink2, t("battery.noBattery"), t("battery.noBatteryText"))
        };
        kit::panel(tk)
            .flex_row()
            .items_center()
            .gap_3()
            .child(kit::glyph(glyph, 28., color))
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .child(kit::h2(title))
                    .when(!line.is_empty(), |this| this.child(kit::faint(line, tk))),
            )
    }

    fn hints(&self, d: &Value, tk: &Tokens) -> Option<Div> {
        let hints = d.a("hints");
        if hints.is_empty() {
            return None;
        }
        let mut panel = kit::panel(tk).child(kit::h2(t("battery.hintsTitle")));
        for (i, h) in hints.iter().enumerate() {
            let (glyph, color) = if h.s("severity") == "warn" {
                (icons::WARNING, tk.warn)
            } else {
                (icons::INFO, tk.ink2)
            };
            let (title, text) = hint_text(h);
            panel = panel.child(
                div()
                    .flex()
                    .gap_2()
                    .items_start()
                    .child(div().pt(px(2.)).child(kit::glyph(glyph, 16., color)))
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .child(kit::body(title).font_weight(FontWeight::SEMIBOLD))
                            .child(
                                kit::sel(ElementId::NamedInteger("pw-hint".into(), i as u64), text).text_size(px(13.)),
                            ),
                    ),
            );
        }
        Some(panel)
    }

    fn battery(&self, b: &Value, index: usize, tk: &Tokens) -> Div {
        let mut rows = Vec::new();
        // "Contoso · 5K9" — but not "Contoso · Contoso 5K9" when the name already starts with it.
        let (maker, model) = (b.s("manufacturer"), b.s("name"));
        let name = if maker.is_empty() || model.to_lowercase().starts_with(&maker.to_lowercase()) {
            model.to_string()
        } else if model.is_empty() {
            maker.to_string()
        } else {
            format!("{maker} · {model}")
        };
        if !name.is_empty() {
            rows.push(Readout::new(t("battery.batteryName"), name));
        }
        let relative = b.b("relative");
        if let Some(health) = b.at("healthPercent").as_u64().filter(|_| !relative) {
            let color = if health < 60 {
                tk.bad
            } else if health < 80 {
                tk.warn
            } else {
                tk.ok
            };
            rows.push(
                Readout::new(
                    t("battery.health"),
                    tf("battery.healthValue", &[("percent", &health.to_string())]),
                )
                .status(Some(color)),
            );
        }
        let mwh = |key: &str| -> Option<String> {
            b.at(key)
                .as_u64()
                .map(|v| tf("battery.mwh", &[("n", &num(v as f64, 0))]))
        };
        if !relative {
            if let Some(design) = mwh("designMwh") {
                rows.push(Readout::new(t("battery.design"), design));
            }
            if let Some(full) = mwh("fullMwh") {
                rows.push(Readout::new(t("battery.full"), full));
            }
        }
        if let Some(cycles) = b.at("cycleCount").as_u64() {
            rows.push(Readout::new(t("battery.cycles"), num(cycles as f64, 0)));
        }
        if b.has("chemistry") {
            rows.push(Readout::new(t("battery.chemistry"), b.s("chemistry")));
        }
        let mut charge = state_text(b.s("state"));
        if let Some(p) = b.at("chargePercent").as_u64() {
            charge = format!("{p}% · {charge}");
        }
        rows.push(Readout::new(t("battery.charge"), charge).status(b.b("critical").then_some(tk.bad)));
        if let Some(rate) = b.at("rateMw").as_i64().filter(|r| *r != 0) {
            rows.push(Readout::new(
                t("battery.rate"),
                tf("battery.watts", &[("n", &num(rate.abs() as f64 / 1000., 1))]),
            ));
        }
        if let Some(mv) = b.at("voltageMv").as_u64() {
            rows.push(Readout::new(
                t("battery.voltage"),
                tf("battery.volts", &[("n", &num(mv as f64 / 1000., 2))]),
            ));
        }
        if let Some(left) = b
            .at("estimatedSeconds")
            .as_u64()
            .filter(|_| b.s("state") == "discharging")
        {
            rows.push(Readout::new(t("battery.timeLeft"), duration(Some(left))));
        }
        let id: &'static str = match index {
            0 => "pw-battery-0",
            1 => "pw-battery-1",
            _ => "pw-battery-n",
        };
        kit::panel(tk)
            .child(kit::h2(t("battery.batteryTitle")))
            .child(kit::readouts(id, rows, 170., tk))
            .when(relative, |this| this.child(kit::faint(t("battery.relativeNote"), tk)))
    }

    fn awake(&self, d: &Value, tk: &Tokens) -> Div {
        let mut panel = kit::panel(tk).child(kit::h2(t("battery.awakeTitle")));
        if !d.b("requestsRead") {
            let note = if d.strs("notes").contains(&"requests_need_admin") {
                t("battery.awakeNeedsAdmin")
            } else {
                t("battery.awakeUnreadable")
            };
            return panel.child(kit::faint(note, tk));
        }
        let requests = d.a("requests");
        if requests.is_empty() {
            return panel.child(kit::muted(t("battery.awakeNone"), tk));
        }
        for (i, r) in requests.iter().enumerate() {
            let mut line = format!("{} · {}", kind_text(r.s("kind")), source_text(r.s("source")));
            if r.has("reason") {
                line = format!("{line} · {}", r.s("reason"));
            }
            panel = panel.child(
                div()
                    .py(px(3.))
                    .child(kit::sel(
                        ElementId::NamedInteger("pw-req".into(), i as u64),
                        r.s("name").to_string(),
                    ))
                    .child(kit::faint(line, tk)),
            );
        }
        panel
    }

    fn plan(&self, d: &Value, tk: &Tokens) -> Div {
        let p = d.at("plan");
        let battery = d.b("hasBattery");
        let pair = |ac: &str, dc: &str| ac_dc(duration(seconds(p, ac)), duration(seconds(p, dc)), battery);
        let mut rows = Vec::new();
        if p.has("name") {
            rows.push(Readout::new(t("battery.planName"), p.s("name")));
        }
        rows.push(Readout::new(t("battery.sleepAfter"), pair("sleepAc", "sleepDc")));
        rows.push(Readout::new(
            t("battery.hibernateAfter"),
            pair("hibernateAc", "hibernateDc"),
        ));
        rows.push(Readout::new(t("battery.displayAfter"), pair("displayAc", "displayDc")));
        if d.b("lidPresent") {
            rows.push(Readout::new(
                t("battery.lid"),
                ac_dc(lid_text(seconds(p, "lidAc")), lid_text(seconds(p, "lidDc")), battery),
            ));
        }
        rows.push(Readout::new(
            t("battery.hibernation"),
            if d.b("hibernateAvailable") {
                t("battery.available")
            } else {
                t("battery.notAvailable")
            },
        ));
        rows.push(Readout::new(
            t("battery.modernStandby"),
            if d.b("modernStandby") {
                t("battery.modernYes")
            } else {
                t("battery.modernNo")
            },
        ));
        let go = self.ctx.clone();
        kit::panel(tk)
            .child(kit::h2(t("battery.planTitle")))
            .child(kit::readouts("pw-plan", rows, 170., tk))
            .child(kit::link(
                "pw-optimize",
                t("battery.seePlans"),
                move |window, cx| go.go("optimize", window, cx),
                tk,
            ))
    }

    /// Sleeps and wakes of the last week: a day strip, what woke it, and the events.
    fn history(&self, d: &Value, cx: &mut Context<Self>, tk: &Tokens) -> Div {
        let mut panel = kit::panel(tk).child(kit::h2(t("battery.eventsTitle")));
        if d.strs("notes").contains(&"events_unreadable") {
            return panel.child(kit::faint(t("battery.eventsUnreadable"), tk));
        }
        let events = d.a("events");
        if events.is_empty() {
            return panel.child(kit::muted(t("battery.eventsNone"), tk));
        }
        panel = panel.child(kit::faint(
            tf(
                "battery.eventsSummary",
                &[
                    ("sleeps", &d.i("sleeps").to_string()),
                    ("wakes", &d.i("wakes").to_string()),
                ],
            ),
            tk,
        ));
        // One bar per day: its height follows the busiest day.
        let days = d.a("days");
        let busiest = days
            .iter()
            .map(|day| day.i("sleeps").max(day.i("wakes")))
            .max()
            .unwrap_or(1)
            .max(1) as f32;
        let mut strip = div().flex().gap_2().items_end().h(px(74.)).py(px(4.));
        for day in days {
            let height = |n: i64| px(4. + 40. * n as f32 / busiest);
            let label = day.s("date").get(5..).unwrap_or_default().to_string();
            strip = strip.child(
                div()
                    .flex()
                    .flex_col()
                    .items_center()
                    .gap(px(2.))
                    .child(
                        div()
                            .flex()
                            .gap(px(2.))
                            .items_end()
                            .child(div().w(px(8.)).h(height(day.i("sleeps"))).bg(tk.ink3).rounded(px(2.)))
                            .child(div().w(px(8.)).h(height(day.i("wakes"))).bg(tk.accent).rounded(px(2.))),
                    )
                    .child(div().text_size(px(11.)).text_color(tk.ink3).child(label)),
            );
        }
        panel = panel.child(strip).child(
            div()
                .flex()
                .gap_3()
                .text_size(px(12.))
                .text_color(tk.ink3)
                .child(legend(tk.ink3, t("battery.legendSleep")))
                .child(legend(tk.accent, t("battery.legendWake"))),
        );
        let sources = d.a("wakeSources");
        if !sources.is_empty() {
            panel = panel.child(kit::body(t("battery.wakeSourcesTitle")).font_weight(FontWeight::SEMIBOLD));
            for (i, s) in sources.iter().enumerate().take(10) {
                let name = if s.has("source") {
                    s.s("source").to_string()
                } else {
                    t("battery.unknownSource")
                };
                let kind = match s.s("sourceKind") {
                    "timer" => t("battery.sourceTimer"),
                    "device" => t("battery.sourceDevice"),
                    _ => String::new(),
                };
                let mut line = tn(
                    "battery.wakeSourceLine",
                    s.i("count").max(0) as u64,
                    &[("when", &when_ms(s.i("lastMs")))],
                );
                if !kind.is_empty() {
                    line = format!("{kind} · {line}");
                }
                panel = panel.child(
                    div()
                        .py(px(2.))
                        .child(kit::sel(ElementId::NamedInteger("pw-src".into(), i as u64), name))
                        .child(kit::faint(line, tk)),
                );
            }
        }
        panel = panel.child(kit::body(t("battery.eventsListTitle")).font_weight(FontWeight::SEMIBOLD));
        let shown = if self.all_events {
            events.len()
        } else {
            FIRST_EVENTS.min(events.len())
        };
        for (i, e) in events.iter().take(shown).enumerate() {
            let mut what = event_text(e);
            if let Some(minutes) = e.at("sleptMinutes").as_u64() {
                what = format!(
                    "{what} · {}",
                    tf("battery.sleptFor", &[("duration", &duration(Some(minutes * 60)))])
                );
            }
            let color: Hsla = match e.s("kind") {
                "wake" => tk.accent,
                _ => tk.ink2,
            };
            panel = panel.child(
                div()
                    .flex()
                    .gap_3()
                    .items_start()
                    .text_size(px(13.))
                    .py(px(2.))
                    .child(
                        div()
                            .w(px(130.))
                            .flex_none()
                            .text_color(tk.ink3)
                            .child(when(e.s("time"))),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .text_color(color)
                            .child(kit::sel(ElementId::NamedInteger("pw-ev".into(), i as u64), what)),
                    ),
            );
        }
        if events.len() > FIRST_EVENTS {
            let label = if self.all_events {
                t("battery.showFewer")
            } else {
                tn("battery.showAll", events.len() as u64, &[])
            };
            let weak = cx.entity().downgrade();
            panel = panel.child(kit::link(
                "pw-all",
                label,
                move |_, cx| {
                    let _ = weak.update(cx, |this, cx| {
                        this.all_events = !this.all_events;
                        cx.notify();
                    });
                },
                tk,
            ));
        }
        panel
    }

    /// What may wake the computer: wake timers, scheduled tasks and devices.
    fn wakers(&self, d: &Value, tk: &Tokens) -> Div {
        let p = d.at("plan");
        let battery = d.b("hasBattery");
        let mut panel = kit::panel(tk)
            .child(kit::h2(t("battery.wakeTitle")))
            .child(kit::readouts(
                "pw-timers",
                vec![Readout::new(
                    t("battery.wakeTimers"),
                    ac_dc(
                        timers_text(seconds(p, "wakeTimersAc")),
                        timers_text(seconds(p, "wakeTimersDc")),
                        battery,
                    ),
                )],
                170.,
                tk,
            ));
        panel = panel.child(kit::body(t("battery.wakeTasksTitle")).font_weight(FontWeight::SEMIBOLD));
        let tasks = d.a("wakeTasks");
        if d.strs("notes").contains(&"tasks_unreadable") {
            panel = panel.child(kit::faint(t("battery.wakeTasksUnreadable"), tk));
        } else if tasks.is_empty() {
            panel = panel.child(kit::muted(t("battery.wakeTasksNone"), tk));
        }
        for (i, task) in tasks.iter().enumerate() {
            let mut line = Vec::new();
            if task.b("microsoft") {
                line.push(t("battery.windowsTask"));
            }
            if !task.b("enabled") {
                line.push(t("battery.taskDisabled"));
            } else if task.has("nextRun") {
                line.push(tf("battery.nextRun", &[("when", &when(task.s("nextRun")))]));
            }
            if task.has("program") {
                line.push(task.s("program").to_string());
            }
            panel = panel.child(
                div()
                    .py(px(2.))
                    .child(kit::sel(
                        ElementId::NamedInteger("pw-task".into(), i as u64),
                        task.s("path").to_string(),
                    ))
                    .when(!line.is_empty(), |this| this.child(kit::faint(line.join(" · "), tk))),
            );
        }
        panel = panel.child(kit::body(t("battery.wakeDevicesTitle")).font_weight(FontWeight::SEMIBOLD));
        let devices = d.a("wakeDevices");
        if !d.b("wakeDevicesRead") {
            panel = panel.child(kit::faint(t("battery.wakeDevicesUnreadable"), tk));
        } else if devices.is_empty() {
            panel = panel.child(kit::muted(t("battery.wakeDevicesNone"), tk));
        }
        for (i, device) in devices.iter().enumerate() {
            panel = panel.child(kit::sel(
                ElementId::NamedInteger("pw-dev".into(), i as u64),
                device.as_str().unwrap_or_default().to_string(),
            ));
        }
        panel.child(kit::faint(t("battery.wakeNote"), tk))
    }
}

/// A coloured square and its label.
fn legend(color: Hsla, label: String) -> Div {
    div()
        .flex()
        .items_center()
        .gap(px(4.))
        .child(div().w(px(8.)).h(px(8.)).bg(color).rounded(px(2.)))
        .child(label)
}

impl Render for PowerPage {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let mut head = kit::row().child(ui::page_title(t("page.power")));
        if self.loading {
            head = head.child(kit::faint(t("common.reading"), &tk));
        }
        let go = self.ctx.clone();
        head = head
            .child(div().flex_1())
            .child(
                ui::command("pw-settings", icons::SETTINGS, t("battery.openSettings"))
                    .on_click(cx.listener(|this, _, window, cx| this.open("ms-settings:powersleep", window, cx))),
            )
            .child(
                ui::command("pw-plans", '\u{EC4A}', t("battery.openPlans"))
                    .on_click(move |_, window, cx| go.go("optimize", window, cx)),
            )
            .child(ui::separator(&tk))
            .child(
                ui::command("pw-refresh", icons::REFRESH, t("common.refresh"))
                    .disabled(self.loading)
                    .on_click(cx.listener(|this, _, _, cx| this.load(cx))),
            );
        let mut page = kit::page("power")
            .child(head)
            .child(kit::faint(t("battery.note"), &tk))
            .children(self.acting.bar("pw-result", &tk));
        if let Some(e) = &self.error {
            page = page.child(kit::colored(e.clone(), tk.warn));
        }
        let Some(d) = self.data.clone() else {
            return page.child(kit::faint(t("common.reading"), &tk));
        };
        page = page.child(self.status(&d, &tk));
        if let Some(hints) = self.hints(&d, &tk) {
            page = page.child(hints);
        }
        let mut left = div().flex().flex_col().gap_3();
        for (i, b) in d.a("batteries").iter().enumerate() {
            left = left.child(self.battery(b, i, &tk));
        }
        left = left.child(self.awake(&d, &tk)).child(self.plan(&d, &tk));
        let right = div()
            .flex()
            .flex_col()
            .gap_3()
            .child(self.history(&d, cx, &tk))
            .child(self.wakers(&d, &tk));
        let wide = f32::from(window.viewport_size().width) >= 1100.;
        page = if wide {
            page.child(
                div()
                    .flex()
                    .gap_3()
                    .items_start()
                    .child(left.w(px(460.)).flex_none())
                    .child(right.flex_1().min_w_0()),
            )
        } else {
            page.child(left).child(right)
        };
        page.child(kit::faint(
            tf("battery.footer", &[("when", &when_ms(d.i("readMs")))]),
            &tk,
        ))
        .when(!self.ctx.elevated, |this| {
            this.child(kit::faint(t("battery.standardUser"), &tk))
        })
    }
}
