//! The window's dialogs: New scan, the AI review consent, Run new task and Processor affinity.
//! Changes still go through the action service (its native confirmation comes after these).

use std::cell::Cell;
use std::collections::BTreeSet;
use std::rc::Rc;

use gpui_kit::component::WindowExt as _;
use gpui_kit::component::input::{Input, InputState};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    AppContext as _, Context, Entity, FontWeight, InteractiveElement as _, IntoElement, ParentElement, Render,
    StatefulInteractiveElement as _, Styled, Window, div, px,
};
use serde_json::{Value, json};
use vigil_core::requests::Request;

use crate::app::{self, Ctx};
use crate::data::{self, Src};
use crate::i18n::{t, tf, tn};
use crate::icons;
use crate::pages::common::{self, Acting, Acts};
use crate::theme::{FONT_MONO, tokens};
use crate::ui;
use crate::ui::kit::{self, J as _};

/// The name of a provider: "Automatic", "Off" or its own name.
pub fn provider_name(provider: Option<&Value>, id: &str) -> String {
    let kind = provider.map(|p| p.s("kind")).unwrap_or("");
    if kind == "auto" || id == "auto" {
        t("ai.automatic")
    } else if id == "off" {
        t("ai.off")
    } else {
        provider
            .map(|p| p.s("name").to_string())
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| id.to_string())
    }
}

// ---------------------------------------------------------------- New scan

pub struct ScanDialog {
    ctx: Ctx,
    settings: Value,
    days: u32,
    virustotal: bool,
    use_ai: bool,
    status: Option<Value>,
    providers: Vec<Value>,
}

impl ScanDialog {
    fn new(ctx: Ctx, cx: &mut Context<Self>) -> Self {
        let core = ctx.core.clone();
        common::read(
            cx,
            move || {
                let settings = data::fetch(core.as_ref(), Src::Settings).unwrap_or(Value::Null);
                let status = data::fetch(core.as_ref(), Src::AiStatus).ok();
                let providers = data::fetch(core.as_ref(), Src::AiProviders).unwrap_or(json!([]));
                (settings, status, providers)
            },
            |this: &mut Self, (settings, status, providers), _| {
                this.days = settings.n("days").max(1.0) as u32;
                this.virustotal = settings.b("virustotal");
                this.use_ai = settings.at("ai").s("provider") != "off";
                this.settings = settings;
                this.status = status;
                this.providers = providers.as_array().cloned().unwrap_or_default();
            },
        );
        Self {
            ctx,
            settings: Value::Null,
            days: 30,
            virustotal: false,
            use_ai: true,
            status: None,
            providers: Vec::new(),
        }
    }
}

impl Render for ScanDialog {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let configured = self.settings.at("ai").s("provider").to_string();
        let off = configured == "off";
        let status_id = self
            .status
            .as_ref()
            .map(|s| s.s("provider").to_string())
            .unwrap_or(configured.clone());
        let provider = self.providers.iter().find(|p| p.s("id") == status_id);
        let name = provider_name(provider, &status_id);
        let hint = if off {
            t("scan.aiOffHint")
        } else {
            match &self.status {
                None => t("scan.checkingAi"),
                Some(s) if s.has("destination") => {
                    let key = if s.b("local") { "scan.usesLocal" } else { "scan.uses" };
                    tf(key, &[("destination", s.s("destination"))])
                }
                Some(s) => tf("scan.aiNotAvailable", &[("problem", s.s("problem"))]),
            }
        };
        let local = self.status.as_ref().is_some_and(|s| s.b("local"));
        let weak = cx.entity().downgrade();
        let days_options: Vec<(u32, String)> = [7u32, 14, 30, 60, 90]
            .iter()
            .map(|d| (*d, tn("common.days", u64::from(*d), &[])))
            .collect();
        let pick = weak.clone();
        let ai = weak.clone();
        let vt = weak.clone();
        let no_key = self.virustotal && !self.settings.at("secrets").b("virustotal");
        div()
            .flex()
            .flex_col()
            .gap_3()
            .child(kit::muted(t("scan.intro"), &tk))
            .child(ui::check_box(
                "scan-ai",
                self.use_ai && !off,
                off,
                tf("scan.useAi", &[("provider", &name)]),
                move |on, _, cx| {
                    let _ = ai.update(cx, |d, cx| {
                        d.use_ai = on;
                        cx.notify();
                    });
                },
                &tk,
            ))
            .child(kit::faint(hint, &tk).pl(px(28.)))
            .child(kit::row().child(kit::body(t("scan.eventLogs"))).child(ui::segmented(
                "scan-days",
                t("scan.eventLogs"),
                days_options,
                self.days,
                move |d, _, cx| {
                    let _ = pick.update(cx, |this, cx| {
                        this.days = d;
                        cx.notify();
                    });
                },
                &tk,
            )))
            .child(ui::check_box(
                "scan-vt",
                self.virustotal,
                false,
                t("scan.virustotal"),
                move |on, _, cx| {
                    let _ = vt.update(cx, |d, cx| {
                        d.virustotal = on;
                        cx.notify();
                    });
                },
                &tk,
            ))
            .when(no_key, |this| {
                this.child(kit::colored(t("scan.virustotalNoKey"), tk.warn).pl(px(28.)))
            })
            .child(kit::faint(
                t(if local { "scan.localNote" } else { "scan.consentNote" }),
                &tk,
            ))
            .child(
                div()
                    .flex()
                    .justify_end()
                    .gap_2()
                    .pt_2()
                    .child(
                        ui::button("scan-cancel", t("common.cancel"))
                            .min_w(px(120.))
                            .on_click(|_, window, cx| window.close_dialog(cx)),
                    )
                    .child(
                        ui::accent_button("scan-start", t("scan.start"))
                            .min_w(px(120.))
                            .on_click(move |_, window, cx| {
                                let Some(this) = weak.upgrade() else { return };
                                let (ctx, days, vt, ai) = {
                                    let d = this.read(cx);
                                    (
                                        d.ctx.clone(),
                                        d.days,
                                        d.virustotal,
                                        d.use_ai && d.settings.at("ai").s("provider") != "off",
                                    )
                                };
                                window.close_dialog(cx);
                                ctx.go("overview", window, cx);
                                app::start_scan(&ctx, days, vt, ai, window, cx);
                            }),
                    ),
            )
    }
}

/// Opens the New scan dialog.
pub fn scan(ctx: Ctx, window: &mut Window, cx: &mut gpui_kit::App) {
    let view = cx.new(|cx| ScanDialog::new(ctx, cx));
    window.open_dialog(cx, move |dialog, _, cx| {
        let dialog = dialog.bg(crate::theme::tokens(cx).flyout);
        dialog.title(t("scan.title")).w(px(560.)).child(view.clone())
    });
}

// ---------------------------------------------------------------- AI review consent

pub struct Consent {
    offer: Value,
    show: bool,
}

impl Render for Consent {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let local = self.offer.b("local");
        let preview = self.offer.a("preview");
        let weak = cx.entity().downgrade();
        let toggle_label = if self.show {
            tn("consent.hideData", preview.len() as u64, &[])
        } else {
            tn("consent.showData", preview.len() as u64, &[])
        };
        let redacted = if self.offer.b("redact") {
            t("consent.redacted")
        } else {
            t("consent.notRedacted")
        };
        div()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .flex()
                    .gap_3()
                    .items_center()
                    .p_3()
                    .rounded(px(6.))
                    .border_1()
                    .border_color(if local { tk.ok.opacity(0.5) } else { tk.rule })
                    .bg(if local { tk.ok.opacity(0.08) } else { tk.surface })
                    .child(kit::glyph(
                        if local { icons::SHIELD } else { '\u{E774}' },
                        20.,
                        if local { tk.ok } else { tk.ink2 },
                    ))
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .child(
                                kit::sel("consent-dest", self.offer.s("destination").to_string())
                                    .font_weight(FontWeight::SEMIBOLD),
                            )
                            .child(kit::faint(
                                t(if local { "consent.staysLocal" } else { "consent.leaves" }),
                                &tk,
                            )),
                    ),
            )
            .child(kit::body(tn("consent.items", self.offer.n("pending") as u64, &[])))
            .child(kit::muted(format!("{redacted} {}", t("consent.copySaved")), &tk))
            .child(kit::link(
                "consent-toggle",
                toggle_label,
                move |_, cx| {
                    let _ = weak.update(cx, |c, cx| {
                        c.show = !c.show;
                        cx.notify();
                    });
                },
                &tk,
            ))
            .when(self.show, |this| {
                let text = serde_json::to_string_pretty(&Value::Array(preview.to_vec())).unwrap_or_default();
                this.child(
                    div()
                        .id("consent-data")
                        .max_h(px(340.))
                        .overflow_y_scroll()
                        .p_2()
                        .rounded(px(4.))
                        .bg(tk.sunken)
                        .border_1()
                        .border_color(tk.rule)
                        .font_family(FONT_MONO)
                        .text_size(px(11.))
                        .child(kit::sel("consent-json", text)),
                )
            })
    }
}

/// Asks whether the scan's items go to the AI for review, then finishes the scan.
pub fn consent(ctx: Ctx, offer: Value, window: &mut Window, cx: &mut gpui_kit::App) {
    let local = offer.b("local");
    let view = cx.new(|_| Consent { offer, show: false });
    let answered = Rc::new(Cell::new(false));
    window.open_dialog(cx, move |dialog, _, cx| {
        let dialog = dialog.bg(crate::theme::tokens(cx).flyout);
        let answer = |id: &'static str, send: bool, accent: bool| {
            let ctx = ctx.clone();
            let answered = Rc::clone(&answered);
            let label = if send {
                t(if local { "consent.review" } else { "consent.send" })
            } else {
                t("consent.skip")
            };
            let button = if accent {
                ui::accent_button(id, label)
            } else {
                ui::button(id, label)
            };
            button.min_w(px(120.)).on_click(move |_, window, cx| {
                answered.set(true);
                window.close_dialog(cx);
                app::finish_scan(&ctx, send, true, crate::win::hwnd(window), cx);
            })
        };
        let on_close = {
            let ctx = ctx.clone();
            let answered = Rc::clone(&answered);
            move |_: &gpui_kit::ClickEvent, window: &mut Window, cx: &mut gpui_kit::App| {
                if !answered.replace(true) {
                    app::finish_scan(&ctx, false, true, crate::win::hwnd(window), cx);
                }
            }
        };
        dialog
            .title(t(if local { "consent.titleLocal" } else { "consent.title" }))
            .w(px(720.))
            .overlay_closable(false)
            .on_close(on_close)
            .child(view.clone())
            .footer(
                div()
                    .flex()
                    .justify_end()
                    .gap_2()
                    .child(answer("consent-skip", false, false))
                    .child(answer("consent-send", true, true)),
            )
    });
}

// ---------------------------------------------------------------- Run new task

pub struct RunTask {
    ctx: Ctx,
    path: Entity<InputState>,
    args: Entity<InputState>,
    admin: bool,
    acting: Acting,
}

impl Acts for RunTask {
    fn acting(&mut self) -> &mut Acting {
        &mut self.acting
    }
    fn core(&self) -> Option<std::sync::Arc<vigil_core::state::AppState>> {
        self.ctx.core.clone()
    }
    fn after(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        window.close_dialog(cx);
    }
}

impl RunTask {
    fn start(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let path = self.path.read(cx).value().trim().to_string();
        if path.is_empty() {
            return;
        }
        let args = self.args.read(cx).value().to_string();
        let request = Request::Run {
            path,
            args,
            admin: self.admin || self.ctx.elevated,
        };
        common::send(self, request, window, cx);
    }

    fn browse(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let picked = cx.prompt_for_paths(gpui_kit::PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some(t("run.browse").into()),
        });
        let input = self.path.clone();
        cx.spawn_in(window, async move |_, cx| {
            let Ok(Ok(Some(paths))) = picked.await else { return };
            let Some(path) = paths.into_iter().next() else { return };
            let _ = cx.update(|window, cx| {
                input.update(cx, |state, cx| state.set_value(path.display().to_string(), window, cx));
            });
        })
        .detach();
    }
}

impl Render for RunTask {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let elevated = self.ctx.elevated;
        let empty = self.path.read(cx).value().trim().is_empty();
        let weak = cx.entity().downgrade();
        let admin = weak.clone();
        div()
            .flex()
            .flex_col()
            .gap_3()
            .child(kit::muted(t("run.intro"), &tk))
            .child(kit::body(t("run.program")).font_weight(FontWeight::SEMIBOLD))
            .child(
                div()
                    .flex()
                    .gap_2()
                    .child(div().flex_1().font_family(FONT_MONO).child(Input::new(&self.path)))
                    .child(
                        ui::button("run-browse", t("run.browse"))
                            .disabled(self.ctx.demo())
                            .on_click(cx.listener(|this, _, window, cx| this.browse(window, cx))),
                    ),
            )
            .child(kit::body(t("run.arguments")).font_weight(FontWeight::SEMIBOLD))
            .child(div().font_family(FONT_MONO).child(Input::new(&self.args)))
            .child(kit::faint(t("run.argumentsHint"), &tk))
            .child(ui::check_box(
                "run-admin",
                self.admin || elevated,
                elevated,
                t("run.admin"),
                move |on, _, cx| {
                    let _ = admin.update(cx, |d, cx| {
                        d.admin = on;
                        cx.notify();
                    });
                },
                &tk,
            ))
            .when(elevated, |this| {
                this.child(kit::faint(t("run.adminElevated"), &tk).pl(px(28.)))
            })
            .children(self.acting.bar("run-result", &tk))
            .child(
                div()
                    .flex()
                    .justify_end()
                    .gap_2()
                    .child(
                        ui::button("run-cancel", t("common.cancel"))
                            .min_w(px(120.))
                            .on_click(|_, window, cx| window.close_dialog(cx)),
                    )
                    .child(
                        ui::accent_button("run-start", t("run.start"))
                            .min_w(px(120.))
                            .disabled(empty || self.acting.busy)
                            .on_click(cx.listener(|this, _, window, cx| this.start(window, cx))),
                    ),
            )
    }
}

/// Opens Run new task (from Processes).
pub fn run_task(ctx: Ctx, window: &mut Window, cx: &mut gpui_kit::App) {
    let path = cx.new(|cx| InputState::new(window, cx).placeholder("notepad"));
    let args = cx.new(|cx| InputState::new(window, cx));
    let admin = ctx.elevated;
    let view = cx.new(|_| RunTask {
        ctx,
        path,
        args,
        admin,
        acting: Acting::default(),
    });
    window.open_dialog(cx, move |dialog, _, cx| {
        let dialog = dialog.bg(crate::theme::tokens(cx).flyout);
        dialog.title(t("run.title")).w(px(520.)).child(view.clone())
    });
}

// ---------------------------------------------------------------- Processor affinity

pub struct AffinityDialog {
    ctx: Ctx,
    pid: u32,
    created_ms: i64,
    name: String,
    processors: Vec<Value>,
    checked: BTreeSet<i64>,
    loading: bool,
    error: Option<String>,
    acting: Acting,
}

impl Acts for AffinityDialog {
    fn acting(&mut self) -> &mut Acting {
        &mut self.acting
    }
    fn core(&self) -> Option<std::sync::Arc<vigil_core::state::AppState>> {
        self.ctx.core.clone()
    }
    fn after(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        window.close_dialog(cx);
    }
}

impl AffinityDialog {
    fn new(ctx: Ctx, pid: u32, created_ms: i64, name: String, cx: &mut Context<Self>) -> Self {
        let core = ctx.core.clone();
        common::read(
            cx,
            move || data::fetch(core.as_ref(), Src::Affinity(pid, created_ms)),
            |this: &mut Self, result, _| {
                this.loading = false;
                match result {
                    Ok(view) => {
                        this.processors = view.a("processors").to_vec();
                        this.checked = view.a("allowed").iter().filter_map(Value::as_i64).collect();
                    }
                    Err(error) => this.error = Some(error),
                }
            },
        );
        Self {
            ctx,
            pid,
            created_ms,
            name,
            processors: Vec::new(),
            checked: BTreeSet::new(),
            loading: true,
            error: None,
            acting: Acting::default(),
        }
    }

    fn set_all(&mut self, test: impl Fn(&Value) -> bool) {
        self.checked = self
            .processors
            .iter()
            .filter(|p| test(p))
            .map(|p| p.i("index"))
            .collect();
    }

    fn apply(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let cores: Vec<i64> = self.checked.iter().copied().collect();
        let request =
            json!({"kind": "process", "op": "affinity", "pid": self.pid, "createdMs": self.created_ms, "cores": cores});
        common::send_json(self, request, window, cx);
    }
}

impl Render for AffinityDialog {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let classes: BTreeSet<i64> = self.processors.iter().map(|p| p.i("efficiencyClass")).collect();
        let hybrid = classes.len() > 1;
        let top = classes.iter().max().copied().unwrap_or(0);
        // One entry per physical core, in the order first seen.
        let mut cores: Vec<(String, Vec<&Value>)> = Vec::new();
        for p in &self.processors {
            let key = format!("{}:{}", p.i("group"), p.i("core"));
            match cores.iter_mut().find(|(k, _)| *k == key) {
                Some((_, members)) => members.push(p),
                None => cores.push((key, vec![p])),
            }
        }
        let count = self.checked.len();
        let total = self.processors.len();
        let busy = self.acting.busy;
        let mut body = div()
            .flex()
            .flex_col()
            .gap_3()
            .child(kit::muted(tf("affinity.intro", &[("name", &self.name)]), &tk));
        if self.loading {
            body = body.child(kit::faint(t("affinity.reading"), &tk));
        } else if let Some(error) = &self.error {
            body = body.child(kit::colored(error.clone(), tk.bad));
        } else {
            body = body
                .child(
                    kit::row()
                        .child(
                            ui::button("aff-all", t("affinity.all")).on_click(cx.listener(|this, _, _, cx| {
                                this.set_all(|_| true);
                                cx.notify();
                            })),
                        )
                        .child(
                            ui::button("aff-none", t("affinity.none")).on_click(cx.listener(|this, _, _, cx| {
                                this.set_all(|_| false);
                                cx.notify();
                            })),
                        )
                        .when(hybrid, |this| {
                            this.child(ui::button("aff-perf", t("affinity.performance")).on_click(cx.listener(
                                move |this, _, _, cx| {
                                    this.set_all(|p| p.i("efficiencyClass") == top);
                                    cx.notify();
                                },
                            )))
                        })
                        .child(div().flex_1())
                        .child(kit::faint(
                            tf(
                                "affinity.selected",
                                &[("count", &count.to_string()), ("total", &total.to_string())],
                            ),
                            &tk,
                        )),
                )
                .child(
                    div()
                        .id("aff-cores")
                        .max_h(px(340.))
                        .overflow_y_scroll()
                        .flex()
                        .flex_wrap()
                        .gap_2()
                        .children(cores.iter().enumerate().map(|(n, (_, members))| {
                            let p_core = members.first().is_some_and(|p| p.i("efficiencyClass") == top);
                            div()
                                .w(px(250.))
                                .flex()
                                .flex_col()
                                .gap_1()
                                .p_2()
                                .rounded(px(6.))
                                .border_1()
                                .border_color(tk.rule)
                                .child(
                                    kit::row()
                                        .child(kit::body(tf("affinity.core", &[("n", &(n + 1).to_string())])))
                                        .when(hybrid, |this| {
                                            this.child(if p_core {
                                                kit::faint(t("affinity.pcore"), &tk)
                                                    .font_weight(FontWeight::SEMIBOLD)
                                                    .text_color(tk.ink2)
                                            } else {
                                                kit::faint(t("affinity.ecore"), &tk)
                                            })
                                        }),
                                )
                                .child(kit::row().children(members.iter().map(|p| {
                                    let index = p.i("index");
                                    let on = self.checked.contains(&index);
                                    let weak = cx.entity().downgrade();
                                    ui::check_box(
                                        gpui_kit::ElementId::NamedInteger("aff-cpu".into(), index as u64),
                                        on,
                                        false,
                                        tf("affinity.cpu", &[("n", &index.to_string())]),
                                        move |value, _, cx| {
                                            let _ = weak.update(cx, |this, cx| {
                                                if value {
                                                    this.checked.insert(index);
                                                } else {
                                                    this.checked.remove(&index);
                                                }
                                                cx.notify();
                                            });
                                        },
                                        &tk,
                                    )
                                })))
                        })),
                )
                .child(kit::faint(t("affinity.hint"), &tk));
        }
        body.children(self.acting.bar("aff-result", &tk)).child(
            div()
                .flex()
                .justify_end()
                .gap_2()
                .child(
                    ui::button("aff-cancel", t("common.cancel"))
                        .min_w(px(120.))
                        .on_click(|_, window, cx| window.close_dialog(cx)),
                )
                .child(
                    ui::accent_button("aff-apply", t("affinity.apply"))
                        .min_w(px(120.))
                        .disabled(count == 0 || self.loading || busy)
                        .on_click(cx.listener(|this, _, window, cx| this.apply(window, cx))),
                ),
        )
    }
}

/// Opens Processor affinity for a process.
pub fn affinity(ctx: Ctx, pid: u32, created_ms: i64, name: String, window: &mut Window, cx: &mut gpui_kit::App) {
    let view = cx.new(|cx| AffinityDialog::new(ctx, pid, created_ms, name, cx));
    window.open_dialog(cx, move |dialog, _, cx| {
        let dialog = dialog.bg(crate::theme::tokens(cx).flyout);
        dialog.title(t("affinity.title")).w(px(620.)).child(view.clone())
    });
}

// ---------------------------------------------------------------- About

/// About Vigil: the version, what it does and its licence.
pub fn about(window: &mut Window, cx: &mut gpui_kit::App) {
    window.open_dialog(cx, move |dialog, _, cx| {
        let tk = *tokens(cx);
        dialog
            .bg(tk.flyout)
            .title(t("about.title"))
            .w(px(480.))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(kit::body(format!("Vigil {}", env!("CARGO_PKG_VERSION"))).font_weight(FontWeight::SEMIBOLD))
                    .child(kit::body(t("about.body")))
                    .child(kit::muted(
                        format!("{} · github.com/andresayac/vigil", t("about.licence")),
                        &tk,
                    )),
            )
            .footer(
                div().flex().justify_end().child(
                    ui::accent_button("about-close", t("common.close"))
                        .min_w(px(120.))
                        .on_click(|_, window, cx| window.close_dialog(cx)),
                ),
            )
    });
}
