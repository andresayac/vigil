//! Alerts: what the background watch noticed (startup entries, services, tasks, security
//! changes, ports, hooks, drivers, hosts, events), its state and switches, filters by kind, mark
//! read and clear (Vigil's own file only).

use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    Context, ElementId, FontWeight, InteractiveElement as _, IntoElement, ParentElement, Render, SharedString,
    StatefulInteractiveElement as _, Styled, Subscription, Window, div, px,
};
use serde_json::Value;

use crate::app::Ctx;
use crate::i18n::t;
use crate::i18n::tf;
use crate::icons;
use crate::pages::watchui::{clock, kind_label, severity_look, since, state_color, state_line, target_label};
use crate::theme::tokens;
use crate::ui;
use crate::ui::kit::{self, J as _};

const KINDS: [&str; 9] = [
    "startup", "service", "task", "security", "port", "hook", "driver", "hosts", "event",
];

pub struct AlertsPage {
    ctx: Ctx,
    alerts: Vec<Value>,
    kind: Option<&'static str>,
    confirm_clear: bool,
    _subscriptions: Vec<Subscription>,
}

impl AlertsPage {
    pub fn new(ctx: Ctx, cx: &mut Context<Self>) -> Self {
        let subscriptions = vec![cx.observe(&ctx.report, |this, _, cx| this.load(cx))];
        let mut page = Self {
            ctx,
            alerts: Vec::new(),
            kind: None,
            confirm_clear: false,
            _subscriptions: subscriptions,
        };
        page.load(cx);
        page
    }

    fn load(&mut self, cx: &mut Context<Self>) {
        self.alerts = self.ctx.watch_alerts().as_array().cloned().unwrap_or_default();
        self.alerts.truncate(200);
        cx.notify();
    }

    fn clear(&mut self, cx: &mut Context<Self>) {
        let _ = self
            .ctx
            .watch_change(|w| w.store.update(|file| file.alerts.clear()), cx);
        self.confirm_clear = false;
        self.load(cx);
    }
}

impl Render for AlertsPage {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let status = self.ctx.watch_status();
        let mut page = kit::page("alerts")
            .child(ui::page_title(t("page.alerts")))
            .child(kit::muted(t("alerts.note"), &tk));
        if let Some(s) = &status {
            let watching = s.b("watching");
            let c = self.ctx.clone();
            let n = self.ctx.clone();
            let mut row = kit::row()
                .child(kit::dot(Some(state_color(s, &tk))))
                .child(kit::body(state_line(s)).font_weight(FontWeight::SEMIBOLD));
            if s.b("owner") {
                row = row.child(
                    ui::button("al-watch", t(if watching { "watch.pause" } else { "watch.resume" }))
                        .glyph(if watching { icons::PAUSE } else { icons::START })
                        .on_click(move |_, _, cx| c.set_watching(!watching, cx)),
                );
            }
            if s.has("notifyPausedUntil") {
                row = row
                    .child(kit::faint(
                        tf(
                            "watch.notificationsPausedUntil",
                            &[("time", &clock(s.i("notifyPausedUntil")))],
                        ),
                        &tk,
                    ))
                    .child(
                        ui::button("al-notify", t("watch.resumeNotifications"))
                            .on_click(move |_, _, cx| n.pause_notifications(false, cx)),
                    );
            } else {
                row = row.child(
                    ui::button("al-notify", t("watch.pauseNotifications"))
                        .glyph('\u{E7ED}')
                        .on_click(move |_, _, cx| n.pause_notifications(true, cx)),
                );
            }
            if !s.b("tasksWatched") {
                row = row.child(kit::faint(t("watch.tasksNeedAdmin"), &tk));
            }
            page = page.child(row);
            if s.has("error") {
                page = page.child(kit::colored(s.s("error").to_string(), tk.warn).text_size(px(12.)));
            }
        }

        // Kind tabs and tools.
        let mut tabs = kit::row();
        let weak = cx.entity().downgrade();
        tabs = tabs.child(kit::chip(
            "al-all",
            t("alerts.all"),
            Some(self.alerts.len()),
            self.kind.is_none(),
            false,
            move |_, cx| {
                let _ = weak.update(cx, |this, cx| {
                    this.kind = None;
                    cx.notify();
                });
            },
            &tk,
        ));
        for k in KINDS {
            let n = self.alerts.iter().filter(|a| a.s("kind") == k).count();
            if n == 0 {
                continue;
            }
            let weak = cx.entity().downgrade();
            tabs = tabs.child(kit::chip(
                ElementId::Name(format!("al-kind-{k}").into()),
                kind_label(k),
                Some(n),
                self.kind == Some(k),
                false,
                move |_, cx| {
                    let _ = weak.update(cx, |this, cx| {
                        this.kind = Some(k);
                        cx.notify();
                    });
                },
                &tk,
            ));
        }
        let any_unread = self.alerts.iter().any(|a| !a.b("read"));
        let mark = self.ctx.clone();
        tabs = tabs.child(div().flex_1()).child(
            ui::command("al-read", icons::CHECK, t("alerts.markAllRead"))
                .disabled(!any_unread)
                .on_click(move |_, _, cx| mark.mark_read(None, cx)),
        );
        if self.confirm_clear {
            tabs = tabs
                .child(kit::faint(t("alerts.clearConfirm"), &tk))
                .child(
                    ui::button("al-clear-yes", t("alerts.clear"))
                        .danger(true)
                        .on_click(cx.listener(|this, _, _, cx| this.clear(cx))),
                )
                .child(
                    ui::button("al-clear-no", t("common.cancel")).on_click(cx.listener(|this, _, _, cx| {
                        this.confirm_clear = false;
                        cx.notify();
                    })),
                );
        } else {
            tabs = tabs.child(
                ui::command("al-clear", icons::DELETE, t("alerts.clear"))
                    .disabled(self.alerts.is_empty())
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.confirm_clear = true;
                        cx.notify();
                    })),
            );
        }
        page = page.child(tabs);

        let shown: Vec<&Value> = self
            .alerts
            .iter()
            .filter(|a| self.kind.is_none_or(|k| a.s("kind") == k))
            .collect();
        let mut list = kit::panel(&tk).gap_0().p_0();
        if shown.is_empty() {
            list = list.child(div().p_6().flex().justify_center().child(kit::faint(
                t(if self.alerts.is_empty() {
                    "alerts.empty"
                } else {
                    "alerts.noneOfKind"
                }),
                &tk,
            )));
        }
        for (i, a) in shown.into_iter().enumerate() {
            let (g, color) = severity_look(a.s("severity"), &tk);
            let unread = !a.b("read");
            let severity_name = t(&format!("alerts.severity.{}", a.s("severity")));
            let when_tip = clock(a.i("time"));
            let mut meta = kit::row()
                .gap_1()
                .text_size(px(12.))
                .text_color(tk.ink3)
                .child(
                    div()
                        .id(ElementId::NamedInteger("al-time".into(), i as u64))
                        .tooltip(move |window, cx| {
                            gpui_kit::component::tooltip::Tooltip::new(when_tip.clone()).build(window, cx)
                        })
                        .child(since(a.i("time"))),
                )
                .child(format!("· {}", kind_label(a.s("kind"))));
            if unread {
                meta = meta.child(
                    div()
                        .text_color(tk.accent)
                        .font_weight(FontWeight::SEMIBOLD)
                        .child(format!("· {}", t("alerts.unread"))),
                );
            }
            let target = a.s("target").to_string();
            let id = a.at("id").as_u64();
            let label = target_label(&target);
            let action: Option<String> = match label {
                Some(l) => Some(tf("alerts.open", &[("page", &t(l))])),
                None if unread => Some(t("alerts.markRead")),
                None => None,
            };
            let c = self.ctx.clone();
            list = list.child(
                div()
                    .flex()
                    .gap_3()
                    .items_start()
                    .px_4()
                    .py_3()
                    .border_b_1()
                    .border_color(tk.rule)
                    .child(
                        div()
                            .id(ElementId::NamedInteger("al-sev".into(), i as u64))
                            .pt(px(2.))
                            .tooltip(move |window, cx| {
                                gpui_kit::component::tooltip::Tooltip::new(severity_name.clone()).build(window, cx)
                            })
                            .child(kit::glyph(g, 16., color)),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .flex()
                            .flex_col()
                            .gap(px(2.))
                            .child(
                                kit::sel(
                                    ElementId::NamedInteger("al-title".into(), i as u64),
                                    a.s("title").to_string(),
                                )
                                .text_size(px(14.))
                                .when(unread, |this| this.font_weight(FontWeight::SEMIBOLD)),
                            )
                            .when(a.has("detail"), |this| {
                                this.child(
                                    kit::sel(
                                        ElementId::NamedInteger("al-detail".into(), i as u64),
                                        a.s("detail").to_string(),
                                    )
                                    .text_size(px(12.))
                                    .text_color(tk.ink2),
                                )
                            })
                            .child(meta),
                    )
                    .when_some(action, |this, action| {
                        this.child(kit::link(
                            ElementId::NamedInteger("al-open".into(), i as u64),
                            SharedString::from(action),
                            move |window, cx| {
                                if unread && let Some(id) = id {
                                    c.mark_read(Some(vec![id]), cx);
                                }
                                if label.is_some() {
                                    c.go(&target, window, cx);
                                }
                            },
                            &tk,
                        ))
                    }),
            );
        }
        page.child(list)
    }
}
