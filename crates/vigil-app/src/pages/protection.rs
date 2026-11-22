//! Protection: Microsoft Defender's state in one line, its scans (with the progress of a scan
//! Vigil started and Stop), exclusions, settings and threats. Every change is a Defender request
//! checked against a fresh read and confirmed natively.

use std::sync::Arc;
use std::time::Duration;

use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    Context, Div, ElementId, Hsla, IntoElement, ParentElement, Render, Styled, Subscription, Window, div, px,
};
use serde_json::{Value, json};
use vigil_core::state::AppState;

use crate::app::Ctx;
use crate::data::{self, Src};
use crate::format::now_ms;
use crate::i18n::{t, tf, tn};
use crate::icons;
use crate::pages::common::{self, Acting, Acts};
use crate::theme::{Tokens, tokens};
use crate::ui;
use crate::ui::kit::{self, J as _};

const SWITCHES: [(&str, &str, &str, bool, Fix); 8] = [
    (
        "realtime",
        "protection.swRealtime",
        "protection.swRealtimeAbout",
        true,
        Fix::TurnOn,
    ),
    (
        "behavior",
        "protection.swBehavior",
        "protection.swBehaviorAbout",
        true,
        Fix::Security,
    ),
    (
        "tamper",
        "protection.swTamper",
        "protection.swTamperAbout",
        true,
        Fix::Security,
    ),
    (
        "cloud",
        "protection.swCloud",
        "protection.swCloudAbout",
        true,
        Fix::TurnOn,
    ),
    (
        "samples",
        "protection.swSamples",
        "protection.swSamplesAbout",
        false,
        Fix::TurnOn,
    ),
    ("pua", "protection.swPua", "protection.swPuaAbout", false, Fix::TurnOn),
    (
        "network",
        "protection.swNetwork",
        "protection.swNetworkAbout",
        false,
        Fix::None,
    ),
    ("cfa", "protection.swCfa", "protection.swCfaAbout", false, Fix::Security),
];

#[derive(Clone, Copy, PartialEq)]
enum Fix {
    TurnOn,
    Security,
    None,
}

pub struct ProtectionPage {
    ctx: Ctx,
    defender: Option<Value>,
    loading: bool,
    error: Option<String>,
    selected: Option<String>,
    acting: Acting,
    _subscriptions: Vec<Subscription>,
}

impl Acts for ProtectionPage {
    fn acting(&mut self) -> &mut Acting {
        &mut self.acting
    }
    fn core(&self) -> Option<Arc<AppState>> {
        self.ctx.core.clone()
    }
    fn after(&mut self, _: &mut Window, cx: &mut Context<Self>) {
        self.load(cx);
    }
}

fn duration(seconds: f64) -> String {
    let s = seconds.max(0.0) as u64;
    let (h, m, sec) = (s / 3600, (s % 3600) / 60, s % 60);
    if h > 0 {
        tf(
            "protection.durHours",
            &[("h", &h.to_string()), ("m", &format!("{m:02}"))],
        )
    } else if m > 0 {
        tf(
            "protection.durMinutes",
            &[("m", &m.to_string()), ("s", &format!("{sec:02}"))],
        )
    } else {
        tf("protection.durSeconds", &[("s", &sec.to_string())])
    }
}

fn at(ms: i64) -> String {
    if ms > 0 {
        common::when(&kit::local_iso(ms))
    } else {
        t("protection.never")
    }
}

impl ProtectionPage {
    pub fn new(ctx: Ctx, cx: &mut Context<Self>) -> Self {
        let subscriptions = vec![cx.observe(&ctx.report, |this, report, cx| {
            // A scan Vigil started ended with its result: read Defender again.
            if let Some(event) = &report.read(cx).defender_scan
                && !event.b("running")
                && !event.at("found").is_null()
                && this.defender.as_ref().is_some_and(|d| d.at("scan").b("running"))
            {
                this.load(cx);
            }
            cx.notify();
        })];
        // A clock for the elapsed time of a running scan.
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor().timer(Duration::from_secs(1)).await;
                if this.update(cx, |_, cx| cx.notify()).is_err() {
                    break;
                }
            }
        })
        .detach();
        let mut page = Self {
            ctx,
            defender: None,
            loading: false,
            error: None,
            selected: None,
            acting: Acting::default(),
            _subscriptions: subscriptions,
        };
        page.load(cx);
        page
    }

    fn load(&mut self, cx: &mut Context<Self>) {
        self.loading = true;
        let core = self.ctx.core.clone();
        common::read(
            cx,
            move || data::fetch(core.as_ref(), Src::Protection),
            |this: &mut Self, result, _| {
                this.loading = false;
                match result {
                    Ok(v) => {
                        this.defender = Some(v);
                        this.error = None;
                    }
                    Err(e) => this.error = Some(e),
                }
            },
        );
    }

    fn run(&mut self, request: Value, window: &mut Window, cx: &mut Context<Self>) {
        common::send_json(self, request, window, cx);
    }

    fn security(&mut self, url: &str, window: &mut Window, cx: &mut Context<Self>) {
        self.run(json!({"kind": "shell", "op": "url", "url": url}), window, cx);
    }

    fn status(&self, tk: &Tokens) -> (Hsla, String, String) {
        let Some(d) = &self.defender else {
            return (tk.warn, t("common.reading"), String::new());
        };
        let other: Vec<&str> = d
            .a("otherAntivirus")
            .iter()
            .filter(|a| a.b("enabled"))
            .map(|a| a.s("name"))
            .collect();
        let names = other.join(", ");
        let switch = |key: &str| {
            d.a("switches")
                .iter()
                .find(|s| s.s("key") == key)
                .map(|s| s.s("state").to_string())
                .unwrap_or_else(|| "unknown".into())
        };
        let active = d.a("threats").iter().filter(|x| x.b("active")).count();
        let flagged = d.a("exclusions").iter().filter(|x| !x.a("flags").is_empty()).count();
        let other_detail = || {
            tf(
                "protection.statusOtherDetail",
                &[("names", if names.is_empty() { "—" } else { &names })],
            )
        };
        if !d.b("available") {
            return if other.is_empty() {
                (
                    tk.bad,
                    t("protection.statusUnavailable"),
                    t("protection.statusUnavailableDetail"),
                )
            } else {
                (tk.ok, t("protection.statusOther"), other_detail())
            };
        }
        if active > 0 {
            return (
                tk.bad,
                tn("protection.statusThreats", active as u64, &[]),
                t("protection.statusThreatsDetail"),
            );
        }
        if d.s("mode") == "passive" || (!d.b("antivirusEnabled") && !other.is_empty()) {
            return (
                if other.is_empty() { tk.warn } else { tk.ok },
                t("protection.statusOther"),
                other_detail(),
            );
        }
        if !d.b("serviceEnabled") || !d.b("antivirusEnabled") {
            return (tk.bad, t("protection.statusOff"), t("protection.statusOffDetail"));
        }
        if switch("realtime") == "off" {
            return (
                tk.bad,
                t("protection.statusRealtimeOff"),
                t("protection.statusRealtimeOffDetail"),
            );
        }
        if d.b("signatureOutOfDate") || d.n("signatureAgeDays") > 7.0 {
            return (
                tk.warn,
                t("protection.statusOutdated"),
                t("protection.statusOutdatedDetail"),
            );
        }
        if d.b("fullScanRequired") {
            return (
                tk.warn,
                t("protection.statusFullScan"),
                t("protection.fullScanRequired"),
            );
        }
        if ["tamper", "cloud", "behavior"].iter().any(|k| switch(k) == "off") || flagged > 0 {
            return (tk.warn, t("protection.statusLook"), t("protection.statusLookDetail"));
        }
        (tk.ok, t("protection.statusOk"), t("protection.statusOkDetail"))
    }

    /// The scan Vigil started: the live event, or the state read with Defender.
    fn scan(&self, cx: &gpui_kit::App) -> Option<Value> {
        let read = self
            .defender
            .as_ref()
            .map(|d| d.at("scan").clone())
            .filter(|s| s.is_object());
        let progress = self.ctx.report.read(cx).defender_scan.clone();
        match (progress, read) {
            (Some(p), Some(r)) if p.n("id") >= r.n("id") => Some(p),
            (Some(p), None) => Some(p),
            (_, Some(mut r)) => {
                let end = if r.b("running") { now_ms() } else { r.i("finishedMs") };
                let elapsed = ((end - r.i("startedMs")) as f64 / 1000.0).round().max(0.0);
                r["elapsedSecs"] = json!(elapsed);
                r["found"] = Value::Null;
                Some(r)
            }
            (None, None) => None,
        }
    }

    fn scans_card(&self, cx: &mut Context<Self>, tk: &Tokens) -> Div {
        let d = self.defender.clone().unwrap_or(Value::Null);
        let scan = self.scan(cx);
        let running = scan.as_ref().is_some_and(|s| s.b("running"));
        let external = if running {
            None
        } else {
            d.at("runningScan").as_object().map(|_| d.at("runningScan").clone())
        };
        let busy = self.acting.busy;
        let elevated = self.ctx.elevated;
        let can_scan = d.b("available") && d.b("serviceEnabled") && !running && !busy;
        let mut card = kit::panel(tk).child(kit::h2(t("protection.scans")));
        let label = |kind: &str| {
            t(if kind == "quick" {
                "protection.quickRunning"
            } else {
                "protection.fullRunning"
            })
        };
        let stop = |cx: &mut Context<Self>| {
            ui::button("pr-stop", t("protection.stop"))
                .glyph(icons::STOP)
                .disabled(busy)
                .on_click(cx.listener(|this, _, window, cx| {
                    this.run(json!({"kind": "defender", "op": "cancel-scan"}), window, cx)
                }))
        };
        if let Some(s) = scan.as_ref().filter(|s| s.b("running")) {
            let elapsed = if s.n("elapsedSecs") > 0.0 {
                s.n("elapsedSecs")
            } else {
                (now_ms() - s.i("startedMs")) as f64 / 1000.0
            };
            card = card
                .child(
                    kit::row()
                        .child(kit::body(label(s.s("kind"))))
                        .child(kit::faint(
                            tf("protection.elapsed", &[("time", &duration(elapsed))]),
                            tk,
                        ))
                        .child(div().flex_1())
                        .child(stop(cx)),
                )
                .child(kit::busy_bar("pr-busy", tk));
        } else if let Some(e) = external {
            card = card
                .child(
                    kit::row()
                        .child(kit::body(label(e.s("kind"))))
                        .child(div().flex_1())
                        .child(stop(cx)),
                )
                .child(kit::faint(
                    tf("protection.externalRunning", &[("time", &at(e.i("startMs")))]),
                    tk,
                ));
        } else if let Some(s) = scan.as_ref() {
            let time = duration(s.n("elapsedSecs"));
            let (color, text) = if s.b("cancelled") {
                (tk.warn, tf("protection.resultCancelled", &[("time", &time)]))
            } else if s.n("found") > 0.0 {
                (
                    tk.bad,
                    tn("protection.resultFound", s.n("found") as u64, &[("time", &time)]),
                )
            } else if s.at("code").as_i64() == Some(0) {
                (tk.ok, tf("protection.resultClean", &[("time", &time)]))
            } else if s.at("code").as_i64() == Some(2) {
                (tk.warn, tf("protection.resultAttention", &[("time", &time)]))
            } else {
                let code = s
                    .at("code")
                    .as_i64()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "?".into());
                (tk.warn, tf("protection.resultFailed", &[("code", &code)]))
            };
            card = card.child(kit::colored(text, color));
        }
        card = card
            .child(kit::kv_text(
                "pr-quick",
                t("protection.lastQuick"),
                at(d.at("quickScan").i("endMs")),
                false,
                170.,
                tk,
            ))
            .child(kit::kv_text(
                "pr-full",
                t("protection.lastFull"),
                at(d.at("fullScan").i("endMs")),
                false,
                170.,
                tk,
            ));
        if d.b("fullScanRequired") {
            card = card.child(kit::colored(t("protection.fullScanRequired"), tk.warn));
        }
        card = card
            .child(
                kit::row()
                    .child(
                        ui::accent_button("pr-quickscan", t("protection.quickScan"))
                            .glyph(icons::START)
                            .disabled(!can_scan)
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.run(json!({"kind": "defender", "op": "quick-scan"}), window, cx)
                            })),
                    )
                    .child(
                        ui::button("pr-fullscan", t("protection.fullScan"))
                            .disabled(!can_scan)
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.run(json!({"kind": "defender", "op": "full-scan"}), window, cx)
                            })),
                    )
                    .child(
                        ui::button("pr-offline", t("protection.offlineScan"))
                            .disabled(!can_scan || !elevated)
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.run(json!({"kind": "defender", "op": "offline-scan"}), window, cx)
                            })),
                    ),
            )
            .child(kit::faint(t("protection.offlineNote"), tk));
        let other = d.a("otherAntivirus");
        if !other.is_empty() {
            card = card.child(kit::h3(t("protection.otherAv")));
            for a in other {
                let mut row = kit::row().child(kit::body(a.s("name").to_string()));
                row = row.child(if a.b("enabled") {
                    kit::colored(t("common.on"), tk.ok)
                } else {
                    kit::body(t("common.off"))
                });
                if !a.b("upToDate") {
                    row = row.child(kit::colored(t("protection.avOutdated"), tk.warn));
                }
                card = card.child(row);
            }
        }
        card
    }

    fn exclusions_card(&self, cx: &mut Context<Self>, tk: &Tokens) -> Div {
        let d = self.defender.clone().unwrap_or(Value::Null);
        let busy = self.acting.busy;
        let elevated = self.ctx.elevated;
        let mut card = kit::panel(tk)
            .child(kit::h2(t("protection.exclusions")))
            .child(kit::faint(t("protection.exclusionsNote"), tk));
        if d.b("exclusionsHidden") {
            return card.child(kit::body(t("protection.exclusionsHidden")));
        }
        let list = d.a("exclusions");
        if self.defender.is_some() && list.is_empty() {
            return card.child(kit::muted(t("protection.noExclusions"), tk));
        }
        for (i, x) in list.iter().enumerate() {
            let kind = match x.s("kind") {
                "path" => t("protection.kindPath"),
                "process" => t("protection.kindProcess"),
                _ => t("protection.kindExtension"),
            };
            let mut flags = div().flex().flex_col();
            for f in x.strs("flags") {
                let key = match f {
                    "drive" => "protection.flagDrive",
                    "writable" => "protection.flagWritable",
                    "executable" => "protection.flagExecutable",
                    _ => "protection.flagAnyFolder",
                };
                flags = flags.child(
                    div()
                        .flex()
                        .gap_1()
                        .items_start()
                        .child(kit::glyph(icons::WARNING, 12., tk.warn).pt(px(2.)))
                        .child(kit::colored(t(key), tk.warn).text_size(px(12.)).flex_1().min_w_0()),
                );
            }
            let request =
                json!({"kind": "defender", "op": "remove-exclusion", "list": x.s("kind"), "value": x.s("value")});
            card = card.child(
                div()
                    .flex()
                    .gap_2()
                    .items_start()
                    .py_1()
                    .border_t_1()
                    .border_color(tk.rule)
                    .child(div().w(px(110.)).flex_none().child(kit::faint(kind, tk)))
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .child(
                                kit::sel(
                                    ElementId::NamedInteger("pr-ex".into(), i as u64),
                                    x.s("value").to_string(),
                                )
                                .font_family(crate::theme::FONT_MONO)
                                .text_size(px(12.)),
                            )
                            .child(flags),
                    )
                    .child(
                        ui::button(
                            ElementId::NamedInteger("pr-ex-rm".into(), i as u64),
                            t("protection.remove"),
                        )
                        .disabled(!elevated || busy)
                        .on_click(cx.listener(move |this, _, window, cx| this.run(request.clone(), window, cx))),
                    ),
            );
        }
        card
    }

    fn settings_card(&self, cx: &mut Context<Self>, tk: &Tokens) -> Div {
        let d = self.defender.clone().unwrap_or(Value::Null);
        let passive = d.s("mode") == "passive";
        let busy = self.acting.busy;
        let elevated = self.ctx.elevated;
        let mut card = kit::panel(tk).child(kit::h2(t("protection.settings")));
        for (key, name, about, essential, fix) in SWITCHES {
            let state = d
                .a("switches")
                .iter()
                .find(|s| s.s("key") == key)
                .map(|s| s.s("state").to_string())
                .unwrap_or_else(|| "unknown".into());
            let (text, color) = match state.as_str() {
                "on" => (t("common.on"), Some(tk.ok)),
                "off" => (t("common.off"), essential.then_some(tk.warn)),
                "audit" => (t("protection.audit"), essential.then_some(tk.warn)),
                _ => (t("common.unknown"), None),
            };
            let about = if key == "realtime" && passive {
                t("protection.passiveRealtime")
            } else {
                t(about)
            };
            let mut action = div().w(px(150.)).flex_none().flex().justify_end();
            if matches!(state.as_str(), "off" | "audit") {
                match fix {
                    Fix::TurnOn if !(key == "realtime" && passive) => {
                        let request = json!({"kind": "defender", "op": "turn-on", "setting": key});
                        action = action.child(
                            ui::button(ElementId::Name(format!("pr-on-{key}").into()), t("protection.turnOn"))
                                .disabled(!elevated || busy || !d.b("available"))
                                .on_click(
                                    cx.listener(move |this, _, window, cx| this.run(request.clone(), window, cx)),
                                ),
                        );
                    }
                    Fix::Security => {
                        action = action.child(
                            ui::button(
                                ElementId::Name(format!("pr-sec-{key}").into()),
                                t("protection.openSecurity"),
                            )
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.security("windowsdefender://threatsettings", window, cx)
                            })),
                        );
                    }
                    _ => {}
                }
            }
            card = card.child(
                div()
                    .flex()
                    .gap_2()
                    .items_center()
                    .py_1()
                    .border_t_1()
                    .border_color(tk.rule)
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .child(kit::body(t(name)))
                            .child(kit::faint(about, tk)),
                    )
                    .child(
                        div()
                            .w(px(90.))
                            .flex_none()
                            .text_size(px(13.))
                            .when_some(color, |this, c| this.text_color(c))
                            .child(text),
                    )
                    .child(action),
            );
        }
        if !elevated {
            card = card.child(kit::faint(t("protection.adminNote"), tk));
        }
        card
    }

    fn threats_card(&self, cx: &mut Context<Self>, tk: &Tokens) -> Div {
        let d = self.defender.clone().unwrap_or(Value::Null);
        let threats = d.a("threats");
        let active = threats.iter().filter(|x| x.b("active")).count();
        let busy = self.acting.busy;
        let mut card = kit::panel(tk).child(
            kit::row()
                .child(kit::h2(t("protection.threats")))
                .child(div().flex_1())
                .child(
                    ui::command("pr-remove-threats", icons::DELETE, t("protection.removeThreats"))
                        .disabled(active == 0 || !self.ctx.elevated || busy)
                        .on_click(cx.listener(|this, _, window, cx| {
                            this.run(json!({"kind": "defender", "op": "remove-threats"}), window, cx)
                        })),
                )
                .child(ui::command("pr-history", '\u{E8A7}', t("protection.history")).on_click(
                    cx.listener(|this, _, window, cx| this.security("windowsdefender://history", window, cx)),
                )),
        );
        if threats.is_empty() {
            let key = if self.loading && self.defender.is_none() {
                "common.reading"
            } else {
                "protection.noThreats"
            };
            return card.child(kit::faint(t(key), tk));
        }
        let header = div()
            .flex()
            .gap_2()
            .px_2()
            .text_size(px(12.))
            .text_color(tk.ink3)
            .child(div().flex_1().child(t("protection.colThreat")))
            .child(div().w(px(130.)).child(t("protection.colCategory")))
            .child(div().w(px(90.)).child(t("protection.colSeverity")))
            .child(div().w(px(130.)).child(t("protection.colStatus")))
            .child(div().w(px(160.)).child(t("protection.colDetected")));
        card = card.child(header);
        for (i, x) in threats.iter().enumerate() {
            let id = x.s("id").to_string();
            let selected = self.selected.as_deref() == Some(id.as_str());
            let is_active = x.b("active");
            let cat = x.s("category");
            let category = t(&format!(
                "protection.cat{}",
                capital(if cat.is_empty() { "other" } else { cat })
            ));
            let severity = match x.s("severity") {
                "low" | "moderate" | "high" | "severe" => t(&format!("protection.sev{}", capital(x.s("severity")))),
                _ => t("common.unknown"),
            };
            let status = if is_active {
                t("protection.stActive")
            } else {
                crate::i18n::t_or(
                    &format!("protection.st{}", capital(x.s("status"))),
                    &t("protection.stResolved"),
                )
            };
            let weak = cx.entity().downgrade();
            let key = id.clone();
            let bad = is_active.then_some(tk.bad);
            card = card.child(
                kit::list_row(
                    ElementId::NamedInteger("pr-threat".into(), i as u64),
                    x.s("name").to_string(),
                    selected,
                    move |_, cx| {
                        let _ = weak.update(cx, |this, cx| {
                            this.selected = if this.selected.as_deref() == Some(key.as_str()) {
                                None
                            } else {
                                Some(key.clone())
                            };
                            cx.notify();
                        });
                    },
                    tk,
                )
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .flex()
                        .gap_1()
                        .items_center()
                        .child(if is_active {
                            kit::glyph(icons::WARNING, 14., tk.bad)
                        } else {
                            div().w(px(14.))
                        })
                        .child(
                            div()
                                .overflow_hidden()
                                .text_ellipsis()
                                .whitespace_nowrap()
                                .child(kit::plain(x.s("name").to_string())),
                        ),
                )
                .child(div().w(px(130.)).child(category))
                .child(
                    div()
                        .w(px(90.))
                        .when_some(bad, |this, c| this.text_color(c))
                        .child(severity),
                )
                .child(
                    div()
                        .w(px(130.))
                        .when_some(bad, |this, c| this.text_color(c))
                        .child(status),
                )
                .child(div().w(px(160.)).child(at(x.i("detectedMs")))),
            );
            if selected {
                let mut detail = div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .p_3()
                    .ml_4()
                    .rounded(px(6.))
                    .bg(tk.sunken);
                if is_active {
                    detail = detail.child(kit::colored(t("protection.activeNote"), tk.bad));
                }
                if x.b("executed") {
                    detail = detail.child(kit::colored(t("protection.executed"), tk.warn));
                }
                let resources = x.strs("resources");
                let resources = if resources.is_empty() {
                    "—".to_string()
                } else {
                    resources.join("\n")
                };
                detail = detail.child(kit::kv_text(
                    "pr-res",
                    t("protection.resources"),
                    resources,
                    true,
                    130.,
                    tk,
                ));
                if x.has("process") {
                    detail = detail.child(kit::kv_text(
                        "pr-proc",
                        t("protection.process"),
                        x.s("process").to_string(),
                        true,
                        130.,
                        tk,
                    ));
                }
                detail = detail.child(kit::kv_text(
                    "pr-det",
                    t("protection.colDetected"),
                    format!(
                        "{} · {}",
                        at(x.i("detectedMs")),
                        tn("protection.detections", x.n("detections") as u64, &[])
                    ),
                    false,
                    130.,
                    tk,
                ));
                card = card.child(detail);
            }
        }
        card
    }
}

fn capital(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

impl Render for ProtectionPage {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let (color, title, detail) = self.status(&tk);
        let ok = color == tk.ok;
        let d = self.defender.clone().unwrap_or(Value::Null);
        let mut status = kit::panel(&tk).flex_row().gap_4().items_center().child(kit::glyph(
            if ok { '\u{F760}' } else { '\u{E730}' },
            44.,
            if self.defender.is_some() { color } else { tk.ink3 },
        ));
        let mut text = div().flex().flex_col().gap_1().flex_1().min_w_0().child(kit::h2(title));
        if !detail.is_empty() {
            text = text.child(kit::muted(detail, &tk));
        }
        if d.b("available") {
            let or_dash = |k: &str| if d.has(k) { d.s(k).to_string() } else { "—".into() };
            text = text.child(
                kit::sel(
                    "pr-versions",
                    tf(
                        "protection.versions",
                        &[
                            ("sig", &or_dash("signatureVersion")),
                            ("when", &at(d.i("signatureUpdatedMs"))),
                            ("engine", &or_dash("engineVersion")),
                            ("platform", &or_dash("platformVersion")),
                        ],
                    ),
                )
                .text_size(px(12.))
                .text_color(tk.ink3),
            );
        } else if d.has("problem") {
            text = text.child(kit::faint(d.s("problem").to_string(), &tk));
        }
        if let Some(e) = &self.error {
            text = text.child(kit::colored(e.clone(), tk.bad));
        }
        status = status.child(text);
        let left = div()
            .flex()
            .flex_col()
            .gap_3()
            .child(self.scans_card(cx, &tk))
            .child(self.exclusions_card(cx, &tk));
        let right = self.settings_card(cx, &tk);
        kit::page("protection")
            .child(
                kit::row().child(ui::page_title(t("page.protection"))).child(
                    ui::CommandBar::new("pr-bar")
                        .cmd(
                            ui::cmd("pr-update", '\u{E896}', t("protection.update"))
                                .disabled(!d.b("available") || !self.ctx.elevated || self.acting.busy)
                                .on_click(cx.listener(|this, _, window, cx| {
                                    this.run(json!({"kind": "defender", "op": "update"}), window, cx)
                                })),
                        )
                        .cmd(ui::cmd("pr-open", '\u{E8A7}', t("protection.openSecurity")).on_click(
                            cx.listener(|this, _, window, cx| this.security("windowsdefender://threat", window, cx)),
                        ))
                        .separator()
                        .cmd(
                            ui::cmd("pr-refresh", icons::REFRESH, t("common.refresh"))
                                .disabled(self.loading)
                                .on_click(cx.listener(|this, _, _, cx| this.load(cx))),
                        ),
                ),
            )
            .child(kit::muted(t("protection.lead"), &tk))
            .children(self.acting.bar("pr-result", &tk))
            .child(status)
            .child(kit::columns(0.45, left, right, window))
            .child(self.threats_card(cx, &tk))
    }
}
