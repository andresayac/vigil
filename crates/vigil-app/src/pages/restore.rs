//! Restore points: the System Restore points of this computer, which drives System Protection
//! covers and how much space it uses, a restore point made on request (with a description), and
//! System Restore and System Protection opened from here. Restore points are never deleted from
//! here: that would only make the computer harder to recover.

use std::sync::Arc;

use gpui_kit::component::input::{Input, InputState};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    AppContext as _, Context, Div, ElementId, Entity, IntoElement, ParentElement, Render, Styled, Window, div, px,
};
use serde_json::{Value, json};
use vigil_core::state::AppState;

use crate::app::Ctx;
use crate::data::{self, Src};
use crate::format::{num, size};
use crate::i18n::{t, tf, tn};
use crate::icons;
use crate::pages::common::{self, Acting, Acts, when_ms};
use crate::theme::{Tokens, tokens};
use crate::ui;
use crate::ui::kit::{self, J as _, Readout};

/// The longest description (the core checks it again).
const MAX_DESCRIPTION: usize = vigil_core::restore::MAX_DESCRIPTION;

pub struct RestorePage {
    ctx: Ctx,
    data: Option<Value>,
    loading: bool,
    error: Option<String>,
    description: Entity<InputState>,
    acting: Acting,
}

impl Acts for RestorePage {
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

/// The name of a restore point's kind.
fn kind_text(kind: &str) -> String {
    match kind {
        "install" => t("restore.kindInstall"),
        "uninstall" => t("restore.kindUninstall"),
        "driver" => t("restore.kindDriver"),
        "settings" => t("restore.kindSettings"),
        "checkpoint" => t("restore.kindCheckpoint"),
        "restore" => t("restore.kindRestore"),
        "cancelled" => t("restore.kindCancelled"),
        "backup" => t("restore.kindBackup"),
        _ => t("restore.kindOther"),
    }
}

impl RestorePage {
    pub fn new(ctx: Ctx, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let description = cx.new(|cx| InputState::new(window, cx).placeholder(t("restore.descriptionHint")));
        let mut page = Self {
            ctx,
            data: None,
            loading: false,
            error: None,
            description,
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
            move || data::fetch(core.as_ref(), Src::Restore),
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

    fn tool(&mut self, name: &str, window: &mut Window, cx: &mut Context<Self>) {
        common::send_json(self, json!({"kind": "shell", "op": "tool", "name": name}), window, cx);
    }

    fn create(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let typed = self.description.read(cx).value().trim().to_string();
        common::send_json(
            self,
            json!({"kind": "tuning", "op": "system.restore_point", "params": {"description": typed}}),
            window,
            cx,
        );
    }

    /// What System Restore does, and the warning when a policy turns it off.
    fn status(&self, d: &Value, tk: &Tokens) -> Div {
        let drives = d.a("drives");
        let known = drives.iter().any(|x| x.at("protected").is_boolean());
        let on = drives.iter().any(|x| x.b("protected"));
        let (glyph, color, title) = if d.b("offByPolicy") {
            (icons::ERROR, tk.bad, t("restore.statusPolicy"))
        } else if !known {
            (icons::INFO, tk.ink2, t("restore.statusUnknown"))
        } else if on {
            (icons::CHECK, tk.ok, t("restore.statusOn"))
        } else {
            (icons::WARNING, tk.warn, t("restore.statusOff"))
        };
        let mut text = if d.b("offByPolicy") {
            t("restore.policyText")
        } else if known && !on {
            t("restore.offText")
        } else {
            t("restore.what")
        };
        if d.b("configLocked") {
            text = format!("{text} {}", t("restore.configLocked"));
        }
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
                    .child(kit::muted(text, tk)),
            )
    }

    fn create_panel(&self, d: &Value, cx: &mut Context<Self>, tk: &Tokens) -> Div {
        let minutes = d.i("frequencyMinutes").max(0) as u64;
        let frequency = if minutes == 0 {
            t("restore.frequencyNone")
        } else if minutes.is_multiple_of(60) {
            tn("restore.frequencyHours", minutes / 60, &[])
        } else {
            tn("restore.frequencyMinutes", minutes, &[])
        };
        let too_long = self.description.read(cx).value().chars().count() > MAX_DESCRIPTION;
        let disabled = !self.ctx.elevated || self.acting.busy || d.b("offByPolicy") || too_long;
        kit::panel(tk)
            .child(kit::h2(t("restore.createTitle")))
            .child(kit::muted(t("restore.createNote"), tk))
            .child(
                kit::row()
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .child(Input::new(&self.description).aria_label(t("restore.createTitle"))),
                    )
                    .child(
                        ui::accent_button("rp-create", t("restore.create"))
                            .disabled(disabled)
                            .on_click(cx.listener(|this, _, window, cx| this.create(window, cx))),
                    ),
            )
            .when(too_long, |this| {
                this.child(kit::colored(
                    tf("restore.tooLong", &[("max", &MAX_DESCRIPTION.to_string())]),
                    tk.warn,
                ))
            })
            .child(kit::faint(tf("restore.frequency", &[("frequency", &frequency)]), tk))
            .when(!self.ctx.elevated, |this| {
                this.child(kit::faint(t("restore.needsAdminCreate"), tk))
            })
    }

    fn drives(&self, d: &Value, tk: &Tokens) -> Div {
        let mut rows = Vec::new();
        for x in d.a("drives") {
            let name = if x.s("label").is_empty() {
                x.s("drive").to_string()
            } else {
                format!("{} ({})", x.s("drive"), x.s("label"))
            };
            let (state, color) = match x.at("protected").as_bool() {
                Some(true) => (t("restore.protectionOn"), Some(tk.ok)),
                Some(false) => (t("restore.protectionOff"), Some(tk.ink3)),
                None => (t("restore.protectionUnknown"), None),
            };
            let usage = if x.at("used").is_u64() {
                let limit = if x.b("unlimited") {
                    t("restore.noLimit")
                } else if x.at("max").is_u64() {
                    size(x.n("max"), 1)
                } else {
                    "—".to_string()
                };
                tf("restore.usage", &[("used", &size(x.n("used"), 1)), ("max", &limit)])
            } else {
                String::new()
            };
            let value = if usage.is_empty() {
                state
            } else {
                format!("{state} · {usage}")
            };
            rows.push(Readout::new(name, value).status(color));
        }
        let mut panel = kit::panel(tk).child(kit::h2(t("restore.drivesTitle")));
        if rows.is_empty() {
            panel = panel.child(kit::faint(t("restore.noDrives"), tk));
        } else {
            panel = panel.child(kit::readouts("rp-drives", rows, 170., tk));
        }
        if !d.b("storageReadable") {
            panel = panel.child(kit::faint(t("restore.storageNeedsAdmin"), tk));
        }
        panel.child(kit::faint(t("restore.protectionHint"), tk))
    }

    fn points(&self, d: &Value, tk: &Tokens) -> Div {
        let points = d.a("points");
        let mut panel = kit::panel(tk).child(kit::h2(t("restore.pointsTitle")));
        if !d.b("pointsReadable") {
            return panel.child(kit::faint(t("restore.pointsNeedAdmin"), tk));
        }
        if points.is_empty() {
            return panel.child(kit::faint(t("restore.pointsNone"), tk));
        }
        for (i, p) in points.iter().enumerate() {
            panel = panel.child(
                div()
                    .flex()
                    .gap_3()
                    .items_center()
                    .text_size(px(13.))
                    .py(px(3.))
                    .child(
                        div()
                            .w(px(140.))
                            .flex_none()
                            .text_color(tk.ink3)
                            .child(if p.i("createdMs") > 0 {
                                when_ms(p.i("createdMs"))
                            } else {
                                "—".to_string()
                            }),
                    )
                    .child(div().flex_1().min_w_0().child(kit::sel(
                        ElementId::NamedInteger("rp-point".into(), i as u64),
                        p.s("description").to_string(),
                    )))
                    .when(p.b("vigil"), |this| {
                        this.child(kit::badge(t("restore.byVigil"), Some(tk.accent), tk))
                    })
                    .child(
                        div()
                            .w(px(170.))
                            .flex_none()
                            .text_color(tk.ink2)
                            .child(kind_text(p.s("kind"))),
                    ),
            );
        }
        panel.child(kit::faint(t("restore.neverDeleted"), tk))
    }
}

impl Render for RestorePage {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let mut head = kit::row().child(ui::page_title(t("page.restore")));
        if self.loading {
            head = head.child(kit::faint(t("common.reading"), &tk));
        }
        head = head.child(
            ui::CommandBar::new("rp-bar")
                .cmd(
                    ui::cmd("rp-rstrui", icons::page("restore"), t("restore.openRestore"))
                        .on_click(cx.listener(|this, _, window, cx| this.tool("rstrui.exe", window, cx))),
                )
                .cmd(
                    ui::cmd("rp-protection", icons::SETTINGS, t("restore.openProtection")).on_click(
                        cx.listener(|this, _, window, cx| this.tool("SystemPropertiesProtection.exe", window, cx)),
                    ),
                )
                .separator()
                .cmd(
                    ui::cmd("rp-refresh", icons::REFRESH, t("common.refresh"))
                        .disabled(self.loading)
                        .on_click(cx.listener(|this, _, _, cx| this.load(cx))),
                ),
        );
        let mut page = kit::page("restore")
            .child(head)
            .child(kit::faint(t("restore.note"), &tk))
            .children(self.acting.bar("rp-result", &tk));
        if let Some(e) = &self.error {
            page = page.child(kit::colored(e.clone(), tk.warn));
        }
        let Some(d) = self.data.clone() else {
            return page.child(kit::faint(t("common.reading"), &tk));
        };
        page = page.child(self.status(&d, &tk));
        let left = div()
            .flex()
            .flex_col()
            .gap_3()
            .child(self.create_panel(&d, cx, &tk))
            .child(self.drives(&d, &tk));
        let points = self.points(&d, &tk);
        let wide = f32::from(window.viewport_size().width) >= 1100.;
        page = if wide {
            page.child(
                div()
                    .flex()
                    .gap_3()
                    .items_start()
                    .child(left.w(px(480.)).flex_none())
                    .child(points.flex_1().min_w_0()),
            )
        } else {
            page.child(left).child(points)
        };
        let count = d.a("points").len() as u64;
        page.when(d.b("pointsReadable"), |this| {
            this.child(kit::faint(
                tn("restore.footer", count, &[("n", &num(count as f64, 0))]),
                &tk,
            ))
        })
    }
}
