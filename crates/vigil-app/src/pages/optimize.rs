//! Optimize: what starts with Windows, background tasks and services from the last scan, power
//! plans, memory, gaming, hibernation, drives and Windows' own tools. Every change is a tuning,
//! role or shell request through the action service; nothing here lowers security.

use std::sync::Arc;

use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    Context, Div, ElementId, FontWeight, InteractiveElement as _, IntoElement, ParentElement, Render,
    StatefulInteractiveElement as _, Styled, Subscription, Window, div, px,
};
use serde_json::{Value, json};
use vigil_core::state::AppState;

use crate::app::{Ctx, Report};
use crate::data::{self, Src};
use crate::format::{pct, size};
use crate::i18n::{t, tf, tn};
use crate::pages::common::{self, Acting, Acts};
use crate::pages::labels::verdict_label;
use crate::theme::{Tokens, tokens};
use crate::ui;
use crate::ui::kit::{self, J as _, Readout};

pub struct OptimizePage {
    ctx: Ctx,
    tuning: Option<Value>,
    hardware: Option<Value>,
    startup: Option<Vec<Value>>,
    plan: String,
    task: Option<(String, usize)>,
    service: Option<(String, usize)>,
    gpu_exe: Option<String>,
    acting: Acting,
    _subscriptions: Vec<Subscription>,
}

impl Acts for OptimizePage {
    fn acting(&mut self) -> &mut Acting {
        &mut self.acting
    }
    fn core(&self) -> Option<Arc<AppState>> {
        self.ctx.core.clone()
    }
    fn after(&mut self, _: &mut Window, cx: &mut Context<Self>) {
        self.reload(cx);
        let core = self.ctx.core.clone();
        self.ctx.report.update(cx, |_, cx| Report::reload(core, cx));
    }
}

impl OptimizePage {
    pub fn new(ctx: Ctx, cx: &mut Context<Self>) -> Self {
        let subscriptions = vec![
            cx.observe(&ctx.report, |_, _, cx| cx.notify()),
            cx.observe(&ctx.live, |_, _, cx| cx.notify()),
        ];
        let mut page = Self {
            ctx,
            tuning: None,
            hardware: None,
            startup: None,
            plan: String::new(),
            task: None,
            service: None,
            gpu_exe: None,
            acting: Acting::default(),
            _subscriptions: subscriptions,
        };
        page.reload(cx);
        let core = page.ctx.core.clone();
        common::read(
            cx,
            move || {
                let hw = data::fetch(core.as_ref(), Src::Hardware(false)).ok();
                let startup = data::fetch(core.as_ref(), Src::Startup)
                    .ok()
                    .and_then(|v| v.as_array().cloned())
                    .unwrap_or_default();
                (hw, startup)
            },
            |this: &mut Self, (hw, startup), _| {
                this.hardware = hw;
                this.startup = Some(startup);
            },
        );
        page
    }

    fn reload(&mut self, cx: &mut Context<Self>) {
        let core = self.ctx.core.clone();
        common::read(
            cx,
            move || data::fetch(core.as_ref(), Src::Tuning).ok(),
            |this: &mut Self, tuning, _| {
                if let Some(t) = &tuning {
                    this.plan = t
                        .a("powerPlans")
                        .iter()
                        .find(|p| p.b("active"))
                        .map(|p| p.s("guid").to_string())
                        .unwrap_or_default();
                }
                this.tuning = tuning;
            },
        );
    }

    fn tune(&mut self, op: &str, params: Value, window: &mut Window, cx: &mut Context<Self>) {
        common::send_json(self, json!({"kind": "tuning", "op": op, "params": params}), window, cx);
    }

    fn startup_card(&self, cx: &mut Context<Self>, tk: &Tokens) -> Div {
        let mut card = kit::panel(tk).child(kit::h2(t("optimize.startup")));
        match &self.startup {
            None => card = card.child(kit::muted(t("common.reading"), tk)),
            Some(list) => {
                let mut on: Vec<&Value> = list.iter().filter(|e| e.b("canToggle") && e.b("enabled")).collect();
                on.sort_by_key(|e| {
                    if e.has("description") {
                        e.s("description").to_lowercase()
                    } else {
                        e.s("name").to_lowercase()
                    }
                });
                let off = list.iter().filter(|e| e.b("canToggle") && !e.b("enabled")).count();
                let mut text = tn("optimize.startupLive", on.len() as u64, &[]);
                if off > 0 {
                    text = format!("{text} {}", tn("optimize.startupOff", off as u64, &[]));
                }
                card = card.child(kit::muted(format!("{text} {}", t("optimize.startupTip")), tk));
                if !on.is_empty() {
                    let rows = on
                        .iter()
                        .take(6)
                        .map(|e| {
                            let name = if e.has("description") {
                                e.s("description")
                            } else {
                                e.s("name")
                            };
                            let value = if e.has("host") {
                                tf("startup.viaHost", &[("host", kit::base_name(e.s("executable")))])
                            } else if e.has("publisher") {
                                e.s("publisher").to_string()
                            } else {
                                "—".into()
                            };
                            Readout::new(name, value).tip(e.s("command"))
                        })
                        .collect();
                    card = card.child(kit::readouts("op-startup", rows, 220., tk));
                }
                if on.len() > 6 {
                    card = card.child(kit::faint(tn("optimize.startupMore", (on.len() - 6) as u64, &[]), tk));
                }
            }
        }
        let go = self.ctx.clone();
        card = card.child(
            div().flex().child(
                ui::accent_button("op-open-startup", t("optimize.openStartup"))
                    .on_click(move |_, window, cx| go.go("startup", window, cx)),
            ),
        );
        card = card.child(kit::h3(t("optimize.tasks")));
        let report = self.ctx.report.read(cx);
        let Some(analysis) = report.analysis.clone() else {
            let scan = self.ctx.clone();
            return card.child(kit::muted(t("optimize.tasksNoScan"), tk)).child(
                div().flex().child(
                    ui::button("op-scan", t("optimize.runScan"))
                        .on_click(move |_, window, cx| scan.scan_dialog(window, cx)),
                ),
            );
        };
        let rows = role_rows(&analysis, "task");
        card = card.child(kit::muted(tn("optimize.tasksCount", rows.len() as u64, &[]), tk));
        if !rows.is_empty() {
            let mut list = div()
                .id("op-task-list")
                .max_h(px(260.))
                .overflow_y_scroll()
                .flex()
                .flex_col();
            for (n, (item, index, role)) in rows.iter().enumerate() {
                let key = (item.s("id").to_string(), *index);
                let selected = self.task.as_ref() == Some(&key);
                let verdict = item.s("verdict");
                let colored = matches!(verdict, "remove" | "disable" | "review");
                let weak = cx.entity().downgrade();
                list = list.child(
                    kit::list_row(
                        ElementId::NamedInteger("op-task".into(), n as u64),
                        item.s("title").to_string(),
                        selected,
                        move |_, cx| {
                            let _ = weak.update(cx, |this, cx| {
                                this.task = Some(key.clone());
                                cx.notify();
                            });
                        },
                        tk,
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .overflow_hidden()
                            .text_ellipsis()
                            .whitespace_nowrap()
                            .child(kit::plain(item.s("title").to_string())),
                    )
                    .child(
                        kit::faint(role.s("label").to_string(), tk)
                            .max_w(px(200.))
                            .overflow_hidden()
                            .text_ellipsis()
                            .whitespace_nowrap(),
                    )
                    .child(
                        kit::colored(
                            verdict_label(verdict),
                            if colored { tk.verdict(verdict) } else { tk.ink3 },
                        )
                        .text_size(px(12.)),
                    ),
                );
            }
            card = card.child(list);
            let task = self.task.clone();
            card = card.child(
                div().flex().child(
                    ui::button("op-task-off", t("optimize.turnOff"))
                        .disabled(task.is_none() || !self.ctx.elevated || self.acting.busy)
                        .on_click(cx.listener(move |this, _, window, cx| {
                            if let Some((id, role)) = &task {
                                common::send_json(
                                    this,
                                    json!({"kind": "role", "op": "task.disable", "itemId": id, "role": role}),
                                    window,
                                    cx,
                                );
                            }
                        })),
                ),
            );
        }
        card
    }

    fn services_card(&self, cx: &mut Context<Self>, tk: &Tokens) -> Div {
        let mut card = kit::panel(tk).child(kit::h2(t("optimize.services")));
        let Some(analysis) = self.ctx.report.read(cx).analysis.clone() else {
            return card.child(kit::muted(t("optimize.runScanServices"), tk));
        };
        let rows: Vec<(&Value, usize, &Value)> = role_rows(&analysis, "service")
            .into_iter()
            .filter(|(_, _, r)| r.at("detail").has("name"))
            .collect();
        card = card.child(kit::muted(tn("optimize.servicesCount", rows.len() as u64, &[]), tk));
        let mut list = div()
            .id("op-svc-list")
            .max_h(px(260.))
            .overflow_y_scroll()
            .flex()
            .flex_col();
        for (n, (item, index, role)) in rows.iter().enumerate() {
            let key = (item.s("id").to_string(), *index);
            let selected = self.service.as_ref() == Some(&key);
            let weak = cx.entity().downgrade();
            list = list.child(
                kit::list_row(
                    ElementId::NamedInteger("op-svc".into(), n as u64),
                    role.at("detail").s("name").to_string(),
                    selected,
                    move |_, cx| {
                        let _ = weak.update(cx, |this, cx| {
                            this.service = Some(key.clone());
                            cx.notify();
                        });
                    },
                    tk,
                )
                .child(div().flex_1().child(role.at("detail").s("name").to_string()))
                .child(kit::faint(item.s("title").to_string(), tk))
                .child(kit::faint(verdict_label(item.s("verdict")), tk)),
            );
        }
        let service = self.service.clone();
        card.child(list).child(
            div().flex().child(
                ui::button("op-svc-manual", t("optimize.manual"))
                    .disabled(service.is_none() || !self.ctx.elevated || self.acting.busy)
                    .on_click(cx.listener(move |this, _, window, cx| {
                        if let Some((id, role)) = &service {
                            common::send_json(
                                this,
                                json!({"kind": "role", "op": "service.manual", "itemId": id, "role": role}),
                                window,
                                cx,
                            );
                        }
                    })),
            ),
        )
    }

    fn power_card(&self, cx: &mut Context<Self>, tk: &Tokens) -> Div {
        let mut card = kit::panel(tk).child(kit::h2(t("optimize.power")));
        let plans = self
            .tuning
            .as_ref()
            .map(|t| t.a("powerPlans").to_vec())
            .unwrap_or_default();
        let active = plans.iter().find(|p| p.b("active")).cloned();
        if plans.is_empty() {
            card = card
                .child(kit::muted(t("optimize.noPlans"), tk))
                .child(div().flex().child(
                    ui::button("op-power-open", t("optimize.openPower")).on_click(cx.listener(
                        |this, _, window, cx| {
                            common::send_json(
                                this,
                                json!({"kind": "shell", "op": "url", "url": "ms-settings:powersleep"}),
                                window,
                                cx,
                            )
                        },
                    )),
                ));
        }
        let mut group = ui::radio_group("op-plans", t("optimize.power"));
        for (i, p) in plans.iter().enumerate() {
            let guid = p.s("guid").to_string();
            let weak = cx.entity().downgrade();
            let note = match guid.to_lowercase().as_str() {
                "381b4222-f694-41f0-9685-ff5bb260df2e" => Some("optimize.planBalanced"),
                "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" => Some("optimize.planHigh"),
                "a1841308-3541-4fab-bc81-f71556f20b4a" => Some("optimize.planSaver"),
                _ if p.s("name").to_lowercase().contains("ultimate") => Some("optimize.planUltimate"),
                _ => None,
            };
            group = group
                .child(ui::radio(
                    ElementId::NamedInteger("op-plan".into(), i as u64),
                    self.plan == guid,
                    false,
                    p.s("name").to_string(),
                    move |_, cx| {
                        let _ = weak.update(cx, |this, cx| {
                            this.plan = guid.clone();
                            cx.notify();
                        });
                    },
                    tk,
                ))
                .children(note.map(|n| kit::faint(t(n), tk).pl(px(28.)).pb(px(4.))));
        }
        if !plans.is_empty() {
            card = card.child(group);
        }
        let chosen = plans.iter().find(|p| p.s("guid") == self.plan).cloned();
        let active_guid = active.as_ref().map(|p| p.s("guid").to_string()).unwrap_or_default();
        let has_ultimate =
            self.tuning.is_none() || plans.iter().any(|p| p.s("name").to_lowercase().contains("ultimate"));
        let battery = self.hardware.as_ref().is_some_and(|h| h.has("battery"));
        let params = json!({
            "guid": self.plan,
            "name": chosen.as_ref().map(|p| p.s("name")).unwrap_or(""),
            "previous_name": active.as_ref().map(|p| p.s("name")).unwrap_or(""),
        });
        card.child(
            kit::row()
                .child(
                    ui::button("op-use-plan", t("optimize.usePlan"))
                        .disabled(self.plan.is_empty() || self.plan == active_guid || self.acting.busy)
                        .on_click(
                            cx.listener(move |this, _, window, cx| this.tune("power.plan", params.clone(), window, cx)),
                        ),
                )
                .when(!has_ultimate && !battery, |this| {
                    this.child(
                        ui::button("op-ultimate", t("optimize.addUltimate"))
                            .disabled(!self.ctx.elevated || self.acting.busy)
                            .on_click(
                                cx.listener(|this, _, window, cx| this.tune("power.ultimate", json!({}), window, cx)),
                            ),
                    )
                }),
        )
    }

    fn memory_card(&self, cx: &mut Context<Self>, tk: &Tokens) -> Div {
        let mut card = kit::panel(tk).child(kit::h2(t("res.memory")));
        let live = self.ctx.live.read(cx);
        match live.snapshot.as_ref().map(|s| s.memory.clone()) {
            Some(m) if m.total > 0 => {
                let hue = tk.chart_memory;
                let parts = vec![
                    (t("perf.inUse"), m.used.saturating_sub(m.modified) as f64, hue),
                    (t("perf.modified"), m.modified as f64, hue.opacity(0.6)),
                    (t("perf.standby"), m.standby as f64, hue.opacity(0.25)),
                    (t("perf.free"), m.free as f64, tk.sunken),
                ];
                let commit = if m.commit_limit > 0 {
                    m.commit as f64 / m.commit_limit as f64 * 100.0
                } else {
                    0.0
                };
                let state = if commit >= 90.0 {
                    t("optimize.memoryTight")
                } else if commit < 70.0 {
                    t("optimize.memoryPlenty")
                } else {
                    t("optimize.memoryModerate")
                };
                card = card
                    .child(kit::stacked_bar(&parts, m.total as f64, 36., tk))
                    .child(kit::row().gap_3().children(parts.iter().map(|(name, value, color)| {
                        kit::row()
                            .gap_1()
                            .child(div().w(px(10.)).h(px(10.)).bg(*color).border_1().border_color(tk.rule))
                            .child(kit::faint(name.clone(), tk))
                            .child(kit::body(size(*value, 1)).font_weight(FontWeight::SEMIBOLD))
                    })))
                    .child(kit::muted(
                        format!(
                            "{} {state}",
                            tf(
                                "optimize.memoryState",
                                &[
                                    ("available", &size(m.available as f64, 1)),
                                    ("total", &size(m.total as f64, 1)),
                                    ("commit", &size(m.commit as f64, 1)),
                                    ("limit", &size(m.commit_limit as f64, 1)),
                                    ("pct", &pct(commit, 0)),
                                ],
                            )
                        ),
                        tk,
                    ));
            }
            _ => card = card.child(kit::muted(t("optimize.readingMemory"), tk)),
        }
        let disabled = !self.ctx.elevated || self.acting.busy;
        card.child(kit::faint(t("optimize.standbyNote"), tk)).child(
            kit::row()
                .child(ui::button("op-purge", t("optimize.purge")).disabled(disabled).on_click(
                    cx.listener(|this, _, window, cx| this.tune("memory.purge_standby", json!({}), window, cx)),
                ))
                .child(
                    ui::button("op-trim", t("optimize.trimAll"))
                        .disabled(disabled)
                        .on_click(
                            cx.listener(|this, _, window, cx| this.tune("memory.trim_all", json!({}), window, cx)),
                        ),
                ),
        )
    }

    fn gaming_card(&self, cx: &mut Context<Self>, tk: &Tokens) -> Div {
        let tuning = self.tuning.clone().unwrap_or(Value::Null);
        let game = tuning.b("gameMode");
        let hags = tuning.at("hags").as_bool();
        let rows = vec![
            Readout::new(t("optimize.gameMode"), t(if game { "common.on" } else { "common.off" }))
                .status(game.then_some(tk.ok))
                .tip(t("optimize.gameModeTip")),
            Readout::new(
                t("optimize.hags"),
                match hags {
                    Some(true) => t("common.on"),
                    Some(false) => t("common.off"),
                    None => t("optimize.notSet"),
                },
            )
            .status((hags == Some(true)).then_some(tk.ok)),
        ];
        let busy = self.acting.busy;
        let mut card = kit::panel(tk)
            .child(kit::h2(t("optimize.gaming")))
            .child(kit::readouts("op-gaming", rows, 220., tk))
            .child(
                kit::row()
                    .child(
                        ui::button(
                            "op-game",
                            t(if game {
                                "optimize.gameModeOff"
                            } else {
                                "optimize.gameModeOn"
                            }),
                        )
                        .disabled(busy)
                        .on_click(cx.listener(move |this, _, window, cx| {
                            this.tune("gaming.game_mode", json!({"on": !game}), window, cx)
                        })),
                    )
                    .child(
                        ui::button(
                            "op-hags",
                            t(if hags == Some(true) {
                                "optimize.hagsOff"
                            } else {
                                "optimize.hagsOn"
                            }),
                        )
                        .disabled(!self.ctx.elevated || busy)
                        .on_click(cx.listener(move |this, _, window, cx| {
                            this.tune("gaming.hags", json!({"on": hags != Some(true)}), window, cx)
                        })),
                    ),
            )
            .child(kit::h3(t("optimize.gpuPerApp")))
            .child(kit::faint(t("optimize.gpuPerAppNote"), tk));
        let prefs = tuning.a("gpuPreferences");
        if !prefs.is_empty() {
            let rows = prefs
                .iter()
                .take(12)
                .map(|p| {
                    let value = match p.i("preference") {
                        0 => t("optimize.gpuAuto"),
                        1 => t("optimize.gpuSaving"),
                        2 => t("optimize.gpuHigh"),
                        n => n.to_string(),
                    };
                    Readout::new(kit::base_name(p.s("exe")), value).tip(p.s("exe"))
                })
                .collect();
            card = card.child(kit::readouts("op-gpu", rows, 220., tk));
        }
        card = card.child(
            div().flex().child(
                ui::button("op-choose", t("optimize.chooseApp"))
                    .disabled(self.ctx.demo())
                    .on_click(cx.listener(|this, _, window, cx| this.choose_exe(window, cx))),
            ),
        );
        if let Some(exe) = self.gpu_exe.clone() {
            let mut row = kit::row();
            for (pref, key) in [
                (0, "optimize.gpuAuto"),
                (1, "optimize.gpuSaving"),
                (2, "optimize.gpuHigh"),
            ] {
                let exe = exe.clone();
                row = row.child(
                    ui::button(ElementId::NamedInteger("op-pref".into(), pref), t(key))
                        .disabled(busy)
                        .on_click(cx.listener(move |this, _, window, cx| {
                            this.tune("gpu.preference", json!({"exe": exe, "preference": pref}), window, cx);
                            this.gpu_exe = None;
                        })),
                );
            }
            card = card
                .child(row)
                .child(kit::faint(tf("optimize.forApp", &[("app", kit::base_name(&exe))]), tk));
        }
        card
    }

    fn choose_exe(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let picked = cx.prompt_for_paths(gpui_kit::PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some(t("optimize.chooseApp").into()),
        });
        cx.spawn_in(window, async move |this, cx| {
            let Ok(Ok(Some(paths))) = picked.await else { return };
            let Some(path) = paths.into_iter().next() else { return };
            let text = path.display().to_string();
            if !text.to_lowercase().ends_with(".exe") {
                return;
            }
            let _ = this.update(cx, |this, cx| {
                this.gpu_exe = Some(text);
                cx.notify();
            });
        })
        .detach();
    }

    fn other_cards(&self, cx: &mut Context<Self>, tk: &Tokens) -> Vec<Div> {
        let busy = self.acting.busy;
        let elevated = self.ctx.elevated;
        let mut hib = kit::panel(tk).child(kit::h2(t("optimize.hibernation")));
        if let Some(tuning) = &self.tuning {
            let h = tuning.at("hibernation");
            if h.b("enabled") {
                let file = size(h.n("fileSize"), 1);
                hib = hib
                    .child(kit::muted(tf("optimize.hibernationOn", &[("size", &file)]), tk))
                    .child(
                        div().flex().child(
                            ui::button("op-hib-off", tf("optimize.hibernationOff", &[("size", &file)]))
                                .disabled(!elevated || busy)
                                .on_click(cx.listener(|this, _, window, cx| {
                                    this.tune("power.hibernate", json!({"on": false}), window, cx)
                                })),
                        ),
                    );
            } else {
                hib = hib.child(kit::muted(t("optimize.hibernationIsOff"), tk)).child(
                    div().flex().child(
                        ui::button("op-hib-on", t("optimize.hibernationTurnOn"))
                            .disabled(!elevated || busy)
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.tune("power.hibernate", json!({"on": true}), window, cx)
                            })),
                    ),
                );
            }
        }
        let mut drives: Vec<(String, String)> = Vec::new();
        if let Some(hw) = &self.hardware {
            for disk in hw.a("disks") {
                let media = disk.s("media").to_uppercase();
                if media != "SSD" && media != "HDD" {
                    continue;
                }
                for letter in disk.strs("letters") {
                    drives.push((letter.trim_end_matches(':').to_string(), media.clone()));
                }
            }
        }
        drives.sort();
        let mut drive_card = kit::panel(tk)
            .child(kit::h2(t("optimize.drives")))
            .child(kit::faint(t("optimize.drivesNote"), tk));
        if drives.is_empty() {
            drive_card = drive_card.child(kit::muted(
                t(if self.hardware.is_some() {
                    "optimize.noDrives"
                } else {
                    "optimize.readingDrives"
                }),
                tk,
            ));
        }
        for (letter, media) in drives {
            let action = if media == "SSD" {
                t("optimize.trim")
            } else {
                t("optimize.defrag")
            };
            let params = json!({"drive": letter, "media": media});
            drive_card = drive_card.child(
                kit::row()
                    .child(kit::muted(format!("{letter}: {media}"), tk))
                    .child(div().flex_1())
                    .child(
                        ui::button(
                            ElementId::Name(format!("op-drive-{letter}").into()),
                            format!("{letter}: {action}"),
                        )
                        .disabled(!elevated || busy)
                        .on_click(cx.listener(move |this, _, window, cx| {
                            this.tune("disk.optimize", params.clone(), window, cx)
                        })),
                    ),
            );
        }
        let mut tools = kit::panel(tk)
            .child(kit::h2(t("optimize.tools")))
            .child(kit::faint(t("optimize.toolsNote"), tk));
        let mut row = kit::row();
        for (key, name) in [
            ("optimize.toolPerformance", "SystemPropertiesPerformance.exe"),
            ("optimize.toolResmon", "resmon.exe"),
            ("optimize.toolDefrag", "dfrgui.exe"),
            ("optimize.toolMsinfo", "msinfo32.exe"),
        ] {
            row = row.child(
                ui::button(ElementId::Name(format!("op-tool-{name}").into()), t(key)).on_click(cx.listener(
                    move |this, _, window, cx| {
                        common::send_json(this, json!({"kind": "shell", "op": "tool", "name": name}), window, cx)
                    },
                )),
            );
        }
        tools = tools.child(row);
        vec![hib, drive_card, tools]
    }
}

/// The active, persistent roles of a kind outside the Windows folder: (item, role index, role).
fn role_rows<'a>(analysis: &'a Value, kind: &str) -> Vec<(&'a Value, usize, &'a Value)> {
    let mut rows = Vec::new();
    for item in analysis.a("items") {
        if item.s("path").to_lowercase().starts_with("c:\\windows") {
            continue;
        }
        for (i, role) in item.a("roles").iter().enumerate() {
            if role.s("kind") == kind && role.b("active") && role.b("persistent") {
                rows.push((item, i, role));
            }
        }
    }
    rows
}

impl Render for OptimizePage {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let mut cards = vec![
            self.startup_card(cx, &tk),
            self.services_card(cx, &tk),
            self.power_card(cx, &tk),
            self.memory_card(cx, &tk),
            self.gaming_card(cx, &tk),
        ];
        cards.extend(self.other_cards(cx, &tk));
        let wide = f32::from(window.viewport_size().width) >= 1100.;
        let mut grid = div().flex().gap_3().items_start();
        if wide {
            let mut left = div().flex_1().min_w_0().flex().flex_col().gap_3();
            let mut right = div().flex_1().min_w_0().flex().flex_col().gap_3();
            for (i, card) in cards.into_iter().enumerate() {
                if i % 2 == 0 {
                    left = left.child(card);
                } else {
                    right = right.child(card);
                }
            }
            grid = grid.child(left).child(right);
        } else {
            grid = grid.flex_col().children(cards);
        }
        kit::page("optimize")
            .child(ui::page_title(t("page.optimize")))
            .child(kit::muted(t("optimize.lead"), &tk))
            .children(self.acting.bar("op-result", &tk))
            .child(grid)
    }
}
