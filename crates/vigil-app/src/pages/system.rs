//! System: Windows, processor, memory, graphics, storage, board and battery, with what deserves
//! a look (insights) and a line from Reliability. Copy puts the whole description on the
//! clipboard.

use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    ClipboardItem, Context, Div, IntoElement, ParentElement, Render, Styled, Subscription, Window, div, px,
};
use serde_json::Value;

use crate::app::Ctx;
use crate::data::{self, Src};
use crate::format::{num, size};
use crate::i18n::{t, tf, tn};
use crate::pages::common::{self, when};
use crate::pages::dates;
use crate::pages::labels::state_color;
use crate::theme::{Tokens, tokens};
use crate::ui;
use crate::ui::kit::{self, J as _, Readout};

pub struct SystemPage {
    ctx: Ctx,
    hardware: Option<Value>,
    insights: Vec<Value>,
    adapters: Vec<Value>,
    reliability: Option<Value>,
    loading: bool,
    error: Option<String>,
    copied: bool,
    _subscriptions: Vec<Subscription>,
}

fn day(iso: &str) -> String {
    if iso.len() < 10 { "—".into() } else { when(&iso[..10]) }
}

impl SystemPage {
    pub fn new(ctx: Ctx, cx: &mut Context<Self>) -> Self {
        let subscriptions = vec![cx.observe(&ctx.live, |_, _, cx| cx.notify())];
        let mut page = Self {
            ctx,
            hardware: None,
            insights: Vec::new(),
            adapters: Vec::new(),
            reliability: None,
            loading: false,
            error: None,
            copied: false,
            _subscriptions: subscriptions,
        };
        page.load(false, cx);
        page
    }

    fn load(&mut self, force: bool, cx: &mut Context<Self>) {
        self.loading = true;
        let core = self.ctx.core.clone();
        common::read(
            cx,
            move || {
                let hw = data::fetch(core.as_ref(), Src::Hardware(force));
                let insights = data::fetch(core.as_ref(), Src::Insights).ok();
                let adapters = data::fetch(core.as_ref(), Src::Adapters).ok();
                let rel = data::fetch(core.as_ref(), Src::Reliability(30)).ok();
                (hw, insights, adapters, rel)
            },
            |this: &mut Self, (hw, insights, adapters, rel), _| {
                this.loading = false;
                match hw {
                    Ok(v) => {
                        this.hardware = Some(v);
                        this.error = None;
                    }
                    Err(e) => this.error = Some(e),
                }
                this.insights = insights.and_then(|v| v.as_array().cloned()).unwrap_or_default();
                this.adapters = adapters
                    .and_then(|v| v.as_array().cloned())
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|a| !a.b("software"))
                    .collect();
                this.reliability = rel;
            },
        );
    }

    fn cards(&self, uptime: f64, tk: &Tokens) -> Vec<(String, Vec<Readout>, Option<String>)> {
        let Some(hw) = &self.hardware else { return Vec::new() };
        let mut cards = Vec::new();
        let os = hw.at("os");
        let mut rows = vec![
            Readout::new(t("system.edition"), os.s("caption")),
            Readout::new(
                t("system.version"),
                tf(
                    "system.versionValue",
                    &[
                        ("version", os.s("version")),
                        ("build", if os.has("build") { os.s("build") } else { "?" }),
                    ],
                ),
            ),
            Readout::new(t("system.architecture"), os.s("arch")),
            Readout::new(t("system.installed"), day(os.s("installed"))),
        ];
        if uptime > 0.0 {
            let days = uptime / 86_400.0;
            let value = if days >= 1.0 {
                tf("system.days", &[("n", &num(days, 1))])
            } else {
                tf("time.hoursShort", &[("n", &num(uptime / 3600.0, 1))])
            };
            rows.push(Readout::new(t("system.runningFor"), value).status((days >= 14.0).then_some(tk.warn)));
        }
        let pc = hw.at("computer");
        let computer = format!("{} {}", pc.s("manufacturer"), pc.s("model")).trim().to_string();
        rows.push(Readout::new(
            t("system.computer"),
            if computer.is_empty() { "—".into() } else { computer },
        ));
        cards.push((t("system.windows"), rows, None));

        let cpu = hw.at("cpu");
        let speed = if cpu.n("maxMhz") > 0.0 {
            tf("unit.ghz", &[("n", &num(cpu.n("maxMhz") / 1000.0, 2))])
        } else {
            "—".into()
        };
        let virt = cpu.b("virtualization");
        cards.push((
            t("system.processor"),
            vec![
                Readout::new(t("system.model"), cpu.s("name")),
                Readout::new(
                    t("system.coresThreads"),
                    format!("{} / {}", cpu.i("cores"), cpu.i("logical")),
                ),
                Readout::new(t("perf.baseSpeed"), speed),
                Readout::new(
                    t("system.cache"),
                    format!(
                        "L2 {} · L3 {}",
                        size(cpu.n("l2Kb") * 1024.0, 0),
                        size(cpu.n("l3Kb") * 1024.0, 0)
                    ),
                ),
                Readout::new(t("system.socket"), cpu.s("socket")),
                Readout::new(
                    t("perf.virtualization"),
                    t(if virt { "system.virtOn" } else { "system.virtOff" }),
                )
                .status(virt.then_some(tk.ok)),
            ],
            None,
        ));

        let memory = hw.at("memory");
        let modules = memory.a("modules");
        let installed: f64 = modules.iter().map(|m| m.n("capacity")).sum();
        let mut rows = vec![
            Readout::new(t("system.installedMemory"), size(installed, 0)),
            Readout::new(
                t("perf.slotsUsed"),
                tf(
                    "perf.slotsValue",
                    &[
                        ("used", &modules.len().to_string()),
                        ("total", &kit::text(memory.at("slots"))),
                    ],
                ),
            ),
            Readout::new(t("system.maxSupported"), size(memory.n("maxCapacity"), 0)),
        ];
        for m in modules {
            let name = if m.has("bank") {
                m.s("bank").to_string()
            } else if m.has("slot") {
                m.s("slot").to_string()
            } else {
                t("system.module")
            };
            let running = if m.n("configuredSpeed") > 0.0 {
                m.n("configuredSpeed")
            } else {
                m.n("speed")
            };
            let value = format!(
                "{} {} · {} · {} {}",
                size(m.n("capacity"), 0),
                m.s("type"),
                tf("unit.mts", &[("n", &num(running, 0))]),
                m.s("manufacturer"),
                m.s("partNumber")
            );
            let slow = m.n("configuredSpeed") > 0.0 && m.n("configuredSpeed") < m.n("speed") * 0.95;
            rows.push(
                Readout::new(name, value)
                    .tip(tf(
                        "system.moduleTip",
                        &[
                            ("rated", &kit::text(m.at("speed"))),
                            ("running", &kit::text(m.at("configuredSpeed"))),
                        ],
                    ))
                    .status(slow.then_some(tk.warn)),
            );
        }
        cards.push((t("res.memory"), rows, None));

        let mut rows = Vec::new();
        for gpu in hw.a("gpus") {
            let adapter = self
                .adapters
                .iter()
                .find(|a| a.s("name") == gpu.s("name") && a.n("dedicatedTotal") > 0.0);
            let value = match adapter {
                Some(a) => tf("system.dedicated", &[("size", &size(a.n("dedicatedTotal"), 0))]),
                None => t("system.basicAdapter"),
            };
            rows.push(Readout::new(
                if gpu.has("name") {
                    gpu.s("name").to_string()
                } else {
                    t("system.adapter")
                },
                value,
            ));
            let old = gpu.s("driverDate").len() >= 10
                && kit::last_days(366)
                    .first()
                    .is_some_and(|limit| gpu.s("driverDate")[..10] < limit[..])
                && matches!(gpu.s("vendorId").to_uppercase().as_str(), "10DE" | "1002" | "8086");
            rows.push(
                Readout::new(
                    format!("  {}", t("system.driver")),
                    format!("{} ({})", gpu.s("driverVersion"), day(gpu.s("driverDate"))),
                )
                .status(old.then_some(tk.warn)),
            );
            if gpu.has("width") {
                rows.push(Readout::new(
                    format!("  {}", t("system.display")),
                    tf(
                        "system.displayValue",
                        &[
                            ("w", &kit::text(gpu.at("width"))),
                            ("h", &kit::text(gpu.at("height"))),
                            ("hz", &kit::text(gpu.at("refreshRate"))),
                        ],
                    ),
                ));
            }
        }
        if rows.is_empty() {
            rows.push(Readout::new(t("system.adapters"), t("system.noneReported")));
        }
        cards.push((t("system.graphics"), rows, None));

        let mut rows = Vec::new();
        for disk in hw.a("disks") {
            let letters: Vec<String> = disk
                .strs("letters")
                .iter()
                .map(|l| {
                    if l.ends_with(':') {
                        l.to_string()
                    } else {
                        format!("{l}:")
                    }
                })
                .collect();
            let mut value = format!(
                "{} · {} {} · {}",
                disk.s("name"),
                disk.s("media"),
                disk.s("bus"),
                size(disk.n("size"), 0)
            );
            if !letters.is_empty() {
                value = format!("{value} · {}", letters.join(", "));
            }
            let health = disk.s("health");
            let status = if health.eq_ignore_ascii_case("healthy") {
                Some(tk.ok)
            } else if health.is_empty() {
                None
            } else {
                Some(tk.bad)
            };
            rows.push(
                Readout::new(tf("res.disk", &[("n", &kit::text(disk.at("number")))]), value)
                    .status(status)
                    .tip(tf(
                        "system.healthTip",
                        &[("health", if health.is_empty() { "—" } else { health })],
                    )),
            );
            let mut parts = Vec::new();
            if disk.has("temperature") {
                parts.push(format!("{} °C", kit::text(disk.at("temperature"))));
            }
            if !disk.at("wear").is_null() {
                parts.push(tf(
                    "system.worn",
                    &[("pct", &format!("{}%", kit::text(disk.at("wear"))))],
                ));
            }
            if disk.has("powerOnHours") {
                parts.push(tf("system.poweredOn", &[("hours", &num(disk.n("powerOnHours"), 0))]));
            }
            if !parts.is_empty() {
                let warn = disk.n("temperature") >= 60.0 || disk.n("wear") >= 80.0;
                rows.push(
                    Readout::new(format!("  {}", t("perf.health")), parts.join(" · ")).status(warn.then_some(tk.warn)),
                );
            }
        }
        if let Some(on) = hw.at("trim").at("ntfs").as_bool() {
            rows.push(
                Readout::new("TRIM", t(if on { "common.on" } else { "common.off" })).status(Some(if on {
                    tk.ok
                } else {
                    tk.bad
                })),
            );
        }
        if hw.a("disks").is_empty() {
            rows.push(Readout::new(t("system.disks"), t("system.noneReported")));
        }
        cards.push((
            t("page.storage"),
            rows,
            (!self.ctx.elevated).then(|| t("system.healthNeedsAdmin")),
        ));

        let board = hw.at("board");
        let bios = hw.at("bios");
        let mut rows = vec![
            Readout::new(
                t("system.motherboard"),
                format!("{} {}", board.s("manufacturer"), board.s("product")),
            ),
            Readout::new("BIOS", format!("{} {}", bios.s("manufacturer"), bios.s("version"))),
            Readout::new(t("system.biosDate"), day(bios.s("date"))),
        ];
        for p in hw.a("pagefiles") {
            rows.push(Readout::new(
                t("system.pageFile"),
                tf(
                    "system.pageFileValue",
                    &[
                        ("path", p.s("path")),
                        ("size", &kit::text(p.at("allocatedMb"))),
                        ("peak", &kit::text(p.at("peakMb"))),
                    ],
                ),
            ));
        }
        cards.push((t("system.board"), rows, None));

        let battery = hw.at("battery");
        if battery.is_object() {
            let health = if battery.n("designedCapacity") > 0.0 {
                format!(
                    "{}%",
                    (battery.n("fullCapacity") / battery.n("designedCapacity") * 100.0).round()
                )
            } else {
                "—".into()
            };
            cards.push((
                t("system.battery"),
                vec![
                    Readout::new(t("system.charge"), format!("{}%", kit::text(battery.at("charge")))),
                    Readout::new(t("perf.health"), health),
                    Readout::new(t("system.cycles"), kit::text(battery.at("cycles"))),
                ],
                None,
            ));
        }
        cards
    }

    fn copy(&mut self, uptime: f64, cx: &mut Context<Self>) {
        let tk = *tokens(cx);
        let mut lines = Vec::new();
        for (title, rows, _) in self.cards(uptime, &tk) {
            lines.push(title);
            for r in rows {
                lines.push(format!("  {}: {}", r.name.trim(), r.value));
            }
            lines.push(String::new());
        }
        for i in &self.insights {
            lines.push(
                format!("[{}] {} {}", i.s("level"), i.s("text"), i.s("fix"))
                    .trim()
                    .to_string(),
            );
        }
        cx.write_to_clipboard(ClipboardItem::new_string(lines.join("\n")));
        self.copied = true;
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
    }

    fn reliability_line(&self, tk: &Tokens) -> Div {
        let rel = self.reliability.clone().unwrap_or(Value::Null);
        let counts = rel.at("counts");
        let days = kit::text(rel.at("days"));
        let days = if days.is_empty() { "30".to_string() } else { days };
        let mut parts = Vec::new();
        for (key, text) in [
            ("bluescreen", "system.relBluescreens"),
            ("shutdown", "system.relShutdowns"),
            ("app_crash", "system.relCrashes"),
        ] {
            let n = counts.n(key) as u64;
            if n > 0 {
                parts.push(tn(text, n, &[]));
            }
        }
        let line = if parts.is_empty() {
            tf("system.reliabilityQuiet", &[("days", &days)])
        } else {
            tf(
                "system.reliabilityLine",
                &[("days", &days), ("list", &dates::list(&parts))],
            )
        };
        let go = self.ctx.clone();
        kit::panel(tk)
            .flex_row()
            .items_center()
            .gap_3()
            .child(kit::glyph('\u{E95E}', 18., tk.ink2))
            .child(kit::body(line).flex_1())
            .child(kit::link(
                "sy-rel",
                t("system.seeReliability"),
                move |window, cx| go.go("reliability", window, cx),
                tk,
            ))
    }
}

impl Render for SystemPage {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let uptime = self
            .ctx
            .live
            .read(cx)
            .snapshot
            .as_ref()
            .map(|s| s.uptime_s)
            .unwrap_or(0.0);
        let mut head = kit::row().child(ui::page_title(t("page.system"))).child(div().flex_1());
        if self.loading {
            head = head.child(kit::faint(t("system.reading"), &tk));
        } else if let Some(e) = &self.error {
            head = head.child(kit::faint(e.clone(), &tk));
        }
        head = head
            .child(
                ui::button("sy-copy", t(if self.copied { "common.copied" } else { "system.copy" }))
                    .disabled(self.hardware.is_none())
                    .on_click(cx.listener(move |this, _, _, cx| this.copy(uptime, cx))),
            )
            .child(
                ui::button("sy-again", t("system.readAgain"))
                    .disabled(self.loading)
                    .on_click(cx.listener(|this, _, _, cx| this.load(true, cx))),
            );
        let mut page = kit::page("system").child(head);
        if !self.insights.is_empty() {
            let problems = self
                .insights
                .iter()
                .filter(|i| matches!(i.s("level"), "warn" | "bad"))
                .count();
            let title = if problems > 0 {
                tn("system.problems", problems as u64, &[])
            } else {
                t("system.allFine")
            };
            let mut panel = kit::panel(&tk).child(kit::h2(title));
            for i in &self.insights {
                let level = i.s("level");
                let mark = match level {
                    "ok" => "✓",
                    "warn" => "!",
                    "bad" => "✕",
                    _ => "i",
                };
                let color = state_color(level, &tk).unwrap_or(tk.ink3);
                let quiet = matches!(level, "ok" | "info");
                panel = panel.child(
                    div()
                        .flex()
                        .gap_2()
                        .text_size(px(13.))
                        .child(
                            div()
                                .w(px(16.))
                                .text_color(color)
                                .font_weight(gpui_kit::FontWeight::SEMIBOLD)
                                .child(mark),
                        )
                        .child(
                            div()
                                .w(px(80.))
                                .flex_none()
                                .text_color(tk.ink3)
                                .child(kit::plain(i.s("area").to_string())),
                        )
                        .child(
                            div()
                                .flex_1()
                                .when(quiet, |this| this.text_color(tk.ink2))
                                .child(format!("{}  {}", i.s("text"), i.s("fix")).trim().to_string()),
                        ),
                );
            }
            page = page.child(panel);
        }
        page = page.child(self.reliability_line(&tk));
        let cards = self.cards(uptime, &tk);
        let wide = f32::from(window.viewport_size().width) >= 1100.;
        let mut left = div().flex_1().min_w_0().flex().flex_col().gap_3();
        let mut right = div().flex_1().min_w_0().flex().flex_col().gap_3();
        for (i, (title, rows, note)) in cards.into_iter().enumerate() {
            let id: &'static str = ["sy-c0", "sy-c1", "sy-c2", "sy-c3", "sy-c4", "sy-c5", "sy-c6", "sy-c7"][i.min(7)];
            let card = kit::panel(&tk)
                .child(kit::h2(title))
                .child(kit::readouts(id, rows, 170., &tk))
                .children(note.map(|n| kit::faint(n, &tk)));
            if !wide || i % 2 == 0 {
                left = left.child(card);
            } else {
                right = right.child(card);
            }
        }
        page.child(if wide {
            div().flex().gap_3().items_start().child(left).child(right)
        } else {
            left
        })
    }
}
