//! Windows Update: what Windows Update recorded on this computer, read only and locally (Vigil
//! never searches, downloads, installs or restarts): the state, hints, the policies that change
//! how updates arrive, failures grouped by update, and the install history.

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

/// History rows shown before "Show all".
const FIRST_ROWS: usize = 25;
const DAY_MS: i64 = 86_400_000;

pub struct UpdatesPage {
    ctx: Ctx,
    data: Option<Value>,
    loading: bool,
    error: Option<String>,
    all_history: bool,
    acting: Acting,
}

impl Acts for UpdatesPage {
    fn acting(&mut self) -> &mut Acting {
        &mut self.acting
    }
    fn core(&self) -> Option<Arc<AppState>> {
        self.ctx.core.clone()
    }
    fn after(&mut self, _: &mut Window, _: &mut Context<Self>) {}
}

/// "3 days ago" / "today" for a moment in Unix ms.
fn ago(ms: i64, now: i64) -> String {
    let days = (now - ms).max(0) / DAY_MS;
    if days == 0 {
        t("updates.today")
    } else {
        tn("updates.daysAgo", days as u64, &[])
    }
}

fn result_text(result: &str) -> String {
    match result {
        "succeeded" => t("updates.resultSucceeded"),
        "succeeded_with_errors" => t("updates.resultPartly"),
        "failed" => t("updates.resultFailed"),
        "aborted" => t("updates.resultAborted"),
        "in_progress" => t("updates.resultInProgress"),
        _ => t("updates.resultUnknown"),
    }
}

fn result_color(result: &str, tk: &Tokens) -> Hsla {
    match result {
        "succeeded" => tk.ok,
        "failed" | "aborted" => tk.bad,
        "succeeded_with_errors" => tk.warn,
        _ => tk.ink3,
    }
}

/// The title and text of a hint (the core gives its code and figures).
fn hint_text(h: &Value) -> (String, String) {
    let count = h.i("count").max(0) as u64;
    let n = count.to_string();
    match h.s("code") {
        "failing_repeatedly" => (
            tf("updates.hint.failingTitle", &[("title", h.s("subject"))]),
            tn(
                "updates.hint.failingText",
                count,
                &[
                    ("n", &n),
                    ("code", if h.s("detail").is_empty() { "—" } else { h.s("detail") }),
                ],
            ),
        ),
        "store_retry" => (
            t("updates.hint.storeTitle"),
            tn("updates.hint.storeText", count, &[("apps", h.s("subject"))]),
        ),
        "updates_disabled" => (t("updates.hint.disabledTitle"), t("updates.hint.disabledText")),
        "service_disabled" => (t("updates.hint.serviceTitle"), t("updates.hint.serviceText")),
        "paused" => (
            t("updates.hint.pausedTitle"),
            tn(
                "updates.hint.pausedText",
                count,
                &[("n", &n), ("until", &when(h.s("detail")))],
            ),
        ),
        "restart_pending" => (
            t("updates.hint.restartTitle"),
            tn("updates.hint.restartText", count, &[("n", &n)]),
        ),
        "no_recent_install" => (
            t("updates.hint.staleTitle"),
            tn("updates.hint.staleText", count, &[("n", &n)]),
        ),
        "managed" => (
            t("updates.hint.managedTitle"),
            tf("updates.hint.managedText", &[("server", h.s("subject"))]),
        ),
        "deferred" => (
            t("updates.hint.deferredTitle"),
            tn("updates.hint.deferredText", count, &[("n", &n)]),
        ),
        other => (other.to_string(), String::new()),
    }
}

impl UpdatesPage {
    pub fn new(ctx: Ctx, cx: &mut Context<Self>) -> Self {
        let mut page = Self {
            ctx,
            data: None,
            loading: false,
            error: None,
            all_history: false,
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
            move || data::fetch(core.as_ref(), Src::Updates),
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

    /// The headline: the one thing that matters most now.
    fn status(&self, d: &Value, tk: &Tokens) -> Div {
        let now = d.i("readMs");
        let (glyph, color, title) = if d.b("disabled") {
            (icons::ERROR, tk.bad, t("updates.statusOff"))
        } else if d.b("paused") {
            (
                icons::PAUSE,
                tk.warn,
                tf("updates.statusPaused", &[("until", &when_ms(d.i("pauseUntilMs")))]),
            )
        } else if d.strs("rebootReasons").iter().any(|r| *r != "file_rename") {
            (icons::WARNING, tk.warn, t("updates.statusRestart"))
        } else if d.has("lastInstallMs") {
            let days = (now - d.i("lastInstallMs")).max(0) / DAY_MS;
            let color = if days <= 35 { tk.ok } else { tk.warn };
            (
                if days <= 35 { icons::CHECK } else { icons::WARNING },
                color,
                tf("updates.statusLast", &[("ago", &ago(d.i("lastInstallMs"), now))]),
            )
        } else {
            (icons::INFO, tk.ink2, t("updates.statusUnknown"))
        };
        let version = [d.s("product"), d.s("displayVersion")]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        let build = match d.at("ubr").as_i64() {
            Some(ubr) if d.has("build") => format!("{}.{ubr}", d.s("build")),
            _ => d.s("build").to_string(),
        };
        kit::panel(tk)
            .flex_row()
            .items_center()
            .gap_3()
            .child(kit::glyph(glyph, 28., color))
            .child(div().flex_1().min_w_0().child(kit::h2(title)).child(kit::faint(
                tf("updates.windowsLine", &[("version", &version), ("build", &build)]),
                tk,
            )))
    }

    fn state(&self, d: &Value, tk: &Tokens) -> Div {
        let now = d.i("readMs");
        let mut rows = Vec::new();
        let installed = if d.has("lastInstallMs") {
            let mut text = format!("{} ({})", when_ms(d.i("lastInstallMs")), ago(d.i("lastInstallMs"), now));
            if d.has("lastInstallTitle") {
                text = format!("{text} · {}", d.s("lastInstallTitle"));
            }
            text
        } else {
            t("updates.notRecorded")
        };
        rows.push(Readout::new(t("updates.lastInstall"), installed));
        rows.push(Readout::new(
            t("updates.lastSearch"),
            if d.has("lastSearchMs") {
                format!("{} ({})", when_ms(d.i("lastSearchMs")), ago(d.i("lastSearchMs"), now))
            } else {
                t("updates.notRecorded")
            },
        ));
        let reasons: Vec<String> = d
            .strs("rebootReasons")
            .into_iter()
            .map(|r| match r {
                "windows_update" => t("updates.rebootWu"),
                "servicing" => t("updates.rebootServicing"),
                _ => t("updates.rebootRename"),
            })
            .collect();
        let restart = if reasons.is_empty() {
            t("updates.no")
        } else if d.has("rebootSinceMs") {
            tf(
                "updates.rebootSince",
                &[("since", &when_ms(d.i("rebootSinceMs"))), ("why", &reasons.join(", "))],
            )
        } else {
            reasons.join(", ")
        };
        let important = d.strs("rebootReasons").iter().any(|r| *r != "file_rename");
        rows.push(Readout::new(t("updates.restart"), restart).status(important.then_some(tk.warn)));
        rows.push(
            Readout::new(
                t("updates.pause"),
                if d.b("paused") {
                    tf("updates.pausedUntil", &[("until", &when_ms(d.i("pauseUntilMs")))])
                } else {
                    t("updates.no")
                },
            )
            .status(d.b("paused").then_some(tk.warn)),
        );
        if let (Some(start), Some(end)) = (d.at("activeHoursStart").as_i64(), d.at("activeHoursEnd").as_i64()) {
            let mut text = format!("{start:02}:00 – {end:02}:00");
            if d.b("activeHoursAutomatic") {
                text = format!("{text} · {}", t("updates.activeAuto"));
            }
            rows.push(Readout::new(t("updates.activeHours"), text));
        }
        let service = match d.s("serviceStart") {
            "auto" | "delayed" => t("updates.serviceAuto"),
            "demand" => t("updates.serviceDemand"),
            "disabled" => t("updates.serviceDisabled"),
            _ => "—".to_string(),
        };
        let running = match d.at("serviceRunning").as_bool() {
            Some(true) => format!(" · {}", t("updates.serviceRunning")),
            Some(false) => format!(" · {}", t("updates.serviceStopped")),
            None => String::new(),
        };
        rows.push(
            Readout::new(t("updates.service"), format!("{service}{running}"))
                .status((d.s("serviceStart") == "disabled").then_some(tk.bad)),
        );
        if d.has("servicingStack") {
            rows.push(Readout::new(t("updates.servicingStack"), d.s("servicingStack")));
        }
        let defender = if d.has("defenderUpdatedMs") {
            let age = (now - d.i("defenderUpdatedMs")).max(0) / DAY_MS;
            (
                tf(
                    "updates.defenderValue",
                    &[
                        ("version", d.s("defenderVersion")),
                        ("when", &when_ms(d.i("defenderUpdatedMs"))),
                    ],
                ),
                Some(if age <= 3 { tk.ok } else { tk.warn }),
            )
        } else {
            (t("updates.notRecorded"), None)
        };
        let go = self.ctx.clone();
        kit::panel(tk)
            .child(kit::h2(t("updates.stateTitle")))
            .child(kit::readouts("up-state", rows, 190., tk))
            .child(
                kit::row()
                    .child(kit::readouts(
                        "up-defender",
                        vec![Readout::new(t("updates.defender"), defender.0).status(defender.1)],
                        190.,
                        tk,
                    ))
                    .child(div().flex_1())
                    .child(kit::link(
                        "up-protection",
                        t("updates.seeProtection"),
                        move |window, cx| go.go("protection", window, cx),
                        tk,
                    )),
            )
    }

    fn policies(&self, d: &Value, tk: &Tokens) -> Option<Div> {
        let p = d.at("policy");
        if !p.b("set") {
            return None;
        }
        let mut rows = Vec::new();
        if p.has("wsusServer") {
            rows.push(Readout::new(t("updates.policyServer"), p.s("wsusServer")));
        }
        if p.b("noAutoUpdate") {
            rows.push(Readout::new(t("updates.policyAuto"), t("updates.policyAutoOff")).status(Some(tk.bad)));
        } else if let Some(option) = p.at("auOptions").as_i64() {
            let text = match option {
                2 => t("updates.auNotify"),
                3 => t("updates.auDownload"),
                4 => t("updates.auScheduled"),
                5 => t("updates.auAdmin"),
                _ => option.to_string(),
            };
            rows.push(Readout::new(t("updates.policyAuto"), text));
        }
        if p.b("disableAccess") {
            rows.push(Readout::new(t("updates.policyAccess"), t("updates.policyAccessOff")).status(Some(tk.warn)));
        }
        if p.b("blockInternet") {
            rows.push(Readout::new(
                t("updates.policyInternet"),
                t("updates.policyInternetOff"),
            ));
        }
        for (key, label) in [
            ("deferFeatureDays", "updates.policyDeferFeature"),
            ("deferQualityDays", "updates.policyDeferQuality"),
        ] {
            if let Some(days) = p.at(key).as_u64()
                && days > 0
            {
                rows.push(Readout::new(t(label), tn("common.days", days, &[])));
            }
        }
        if p.has("targetVersion") {
            rows.push(Readout::new(t("updates.policyTarget"), p.s("targetVersion")));
        }
        Some(
            kit::panel(tk)
                .child(kit::h2(t("updates.policyTitle")))
                .child(kit::faint(t("updates.policyNote"), tk))
                .child(kit::readouts("up-policy", rows, 190., tk)),
        )
    }

    fn failures(&self, d: &Value, tk: &Tokens) -> Option<Div> {
        let groups = d.a("failures");
        if groups.is_empty() {
            return None;
        }
        let mut panel = kit::panel(tk)
            .child(kit::h2(t("updates.failuresTitle")))
            .child(kit::faint(t("updates.failuresNote"), tk));
        for (i, g) in groups.iter().enumerate().take(12) {
            let fixed = g.b("fixedLater");
            // A Store app that could not update for now is no failure to worry about.
            let retry = g.b("storeRetry");
            let (glyph, color) = if fixed {
                (icons::CHECK, tk.ink3)
            } else if retry {
                (icons::INFO, tk.ink3)
            } else {
                (icons::ERROR, tk.bad)
            };
            let mut line = tn(
                "updates.failureLine",
                g.i("count").max(0) as u64,
                &[("n", &g.i("count").to_string()), ("when", &when_ms(g.i("lastMs")))],
            );
            if g.has("code") {
                line = format!("{line} · {}", g.s("code"));
            }
            if fixed {
                line = format!("{line} · {}", t("updates.fixedLater"));
            } else if retry {
                line = format!("{line} · {}", t("updates.storeRetry"));
            }
            panel = panel.child(
                div()
                    .flex()
                    .gap_2()
                    .items_start()
                    .child(div().pt(px(2.)).child(kit::glyph(glyph, 14., color)))
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .child(kit::sel(
                                ElementId::NamedInteger("up-fail".into(), i as u64),
                                g.s("title").to_string(),
                            ))
                            .child(kit::faint(line, tk)),
                    ),
            );
        }
        Some(panel)
    }

    fn history(&self, d: &Value, cx: &mut Context<Self>, tk: &Tokens) -> Div {
        let entries = d.a("history");
        let mut panel = kit::panel(tk).child(kit::h2(t("updates.historyTitle")));
        match d.s("historySource") {
            "events" => panel = panel.child(kit::faint(t("updates.fromEvents"), tk)),
            "none" => return panel.child(kit::faint(t("updates.historyUnreadable"), tk)),
            _ => {}
        }
        if entries.is_empty() {
            return panel.child(kit::faint(t("updates.historyEmpty"), tk));
        }
        let shown = if self.all_history {
            entries.len()
        } else {
            FIRST_ROWS.min(entries.len())
        };
        for (i, e) in entries.iter().take(shown).enumerate() {
            let result = e.s("result");
            let mut what = result_text(result);
            if e.s("operation") == "uninstall" {
                what = format!("{} · {what}", t("updates.removal"));
            }
            if e.has("code") {
                what = format!("{what} · {}", e.s("code"));
            }
            panel = panel.child(
                div()
                    .flex()
                    .gap_3()
                    .items_start()
                    .text_size(px(13.))
                    .py(px(3.))
                    .child(
                        div()
                            .w(px(130.))
                            .flex_none()
                            .text_color(tk.ink3)
                            .child(when_ms(e.i("timeMs"))),
                    )
                    .child(div().flex_1().min_w_0().child(kit::sel(
                        ElementId::NamedInteger("up-hist".into(), i as u64),
                        e.s("title").to_string(),
                    )))
                    .child(
                        div()
                            .w(px(190.))
                            .flex_none()
                            .text_color(if e.b("storeRetry") {
                                tk.ink3
                            } else {
                                result_color(result, tk)
                            })
                            .child(what),
                    ),
            );
        }
        if entries.len() > FIRST_ROWS {
            let label = if self.all_history {
                t("updates.showFewer")
            } else {
                tn("updates.showAll", entries.len() as u64, &[])
            };
            let weak = cx.entity().downgrade();
            panel = panel.child(kit::link(
                "up-all",
                label,
                move |_, cx| {
                    let _ = weak.update(cx, |this, cx| {
                        this.all_history = !this.all_history;
                        cx.notify();
                    });
                },
                tk,
            ));
        }
        panel
    }

    fn hints(&self, d: &Value, tk: &Tokens) -> Option<Div> {
        let hints = d.a("hints");
        if hints.is_empty() {
            return None;
        }
        let mut panel = kit::panel(tk).child(kit::h2(t("updates.hintsTitle")));
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
                                kit::sel(ElementId::NamedInteger("up-hint".into(), i as u64), text).text_size(px(13.)),
                            ),
                    ),
            );
        }
        Some(panel)
    }
}

impl Render for UpdatesPage {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let mut head = kit::row().child(ui::page_title(t("page.updates")));
        if self.loading {
            head = head.child(kit::faint(t("common.reading"), &tk));
        }
        head = head.child(
            ui::CommandBar::new("up-bar")
                .cmd(
                    ui::cmd("up-settings", icons::SETTINGS, t("updates.openSettings")).on_click(
                        cx.listener(|this, _, window, cx| this.open("ms-settings:windowsupdate", window, cx)),
                    ),
                )
                .cmd(ui::cmd("up-history", '\u{E81C}', t("updates.openHistory")).on_click(
                    cx.listener(|this, _, window, cx| this.open("ms-settings:windowsupdate-history", window, cx)),
                ))
                .separator()
                .cmd(
                    ui::cmd("up-refresh", icons::REFRESH, t("common.refresh"))
                        .disabled(self.loading)
                        .on_click(cx.listener(|this, _, _, cx| this.load(cx))),
                ),
        );
        let mut page = kit::page("updates")
            .child(head)
            .child(kit::faint(t("updates.note"), &tk))
            .children(self.acting.bar("up-result", &tk));
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
        let left = div()
            .flex()
            .flex_col()
            .gap_3()
            .child(self.state(&d, &tk))
            .children(self.policies(&d, &tk))
            .children(self.failures(&d, &tk));
        let history = self.history(&d, cx, &tk);
        let wide = f32::from(window.viewport_size().width) >= 1100.;
        page = if wide {
            page.child(
                div()
                    .flex()
                    .gap_3()
                    .items_start()
                    .child(left.w(px(520.)).flex_none())
                    .child(history.flex_1().min_w_0()),
            )
        } else {
            page.child(left).child(history)
        };
        let count = d.a("history").len() as u64;
        page.child(kit::faint(
            tn(
                "updates.footer",
                count,
                &[("n", &num(count as f64, 0)), ("when", &when_ms(d.i("readMs")))],
            ),
            &tk,
        ))
        .when(!self.ctx.elevated, |this| {
            this.child(kit::faint(t("updates.standardUser"), &tk))
        })
    }
}
