//! The Services page: every Win32 service with its
//! state, startup type, process, account and binary; Start, Stop, Restart and the startup type
//! through the action service. Essential Windows services are marked and never offered.

use std::sync::Arc;

use gpui_kit::component::input::{InputEvent, InputState};
use gpui_kit::component::menu::{DropdownMenu as _, PopupMenuItem};
use gpui_kit::component::table::TableState;
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    AppContext as _, Context, Entity, FocusHandle, InteractiveElement as _, IntoElement, ParentElement, Render, Styled,
    Subscription, Window, div, px,
};
use vigil_core::requests::Request;
use vigil_core::state::AppState;
use vigil_sys::services::Service;

use crate::i18n::{t, tf};
use crate::icons;
use crate::pages::common::{self, Acting, Acts};
use crate::theme::{Tokens, tokens};
use crate::ui::grid::{self, Grid, GridCell, GridCol, GridRow};
use crate::ui::{self, FButton, Kind};

/// A service as the page shows it: what Windows reports, and whether Vigil refuses to change it.
#[derive(Clone)]
pub struct Row {
    pub service: Service,
    pub protected: bool,
}

/// The four startup types the page can set, in the order services.msc lists them.
const START_TYPES: [(&str, &str); 4] = [
    ("auto", "services.auto"),
    ("delayed-auto", "services.delayedAuto"),
    ("demand", "services.demand"),
    ("disabled", "services.disabled"),
];

fn state_label(state: &str) -> String {
    match state {
        "running" => t("services.running"),
        "start_pending" => t("services.starting"),
        "stop_pending" => t("services.stopping"),
        "continue_pending" | "pause_pending" => t("services.changing"),
        "paused" => t("services.paused"),
        "stopped" => t("services.stopped"),
        other => other.to_string(),
    }
}

fn state_rank(state: &str) -> f64 {
    match state {
        "running" => 0.0,
        "stopped" => 3.0,
        "paused" => 2.0,
        _ => 1.0,
    }
}

fn start_label(value: &str) -> String {
    match START_TYPES.iter().find(|(v, _)| *v == value) {
        Some((_, key)) => t(key),
        None if value.is_empty() => "—".into(),
        None if value == "boot" || value == "system" => t("services.boot"),
        None => value.to_string(),
    }
}

fn start_rank(value: &str) -> usize {
    START_TYPES
        .iter()
        .position(|(v, _)| *v == value)
        .unwrap_or(START_TYPES.len())
}

pub struct ServicesPage {
    rows: Vec<Row>,
    table: Entity<TableState<Grid>>,
    search: Entity<InputState>,
    running_only: bool,
    loading: bool,
    error: Option<String>,
    core: Option<Arc<AppState>>,
    elevated: bool,
    acting: Acting,
    focus: FocusHandle,
    _subscriptions: Vec<Subscription>,
}

impl Acts for ServicesPage {
    fn acting(&mut self) -> &mut Acting {
        &mut self.acting
    }
    fn core(&self) -> Option<Arc<AppState>> {
        self.core.clone()
    }
    fn after(&mut self, _: &mut Window, cx: &mut Context<Self>) {
        self.load(cx);
    }
}

impl ServicesPage {
    pub fn new(core: Option<Arc<AppState>>, elevated: bool, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let cols = vec![
            GridCol::new("displayName", t("services.displayName"), 300.),
            GridCol::new("name", t("services.name"), 170.),
            GridCol::new("state", t("services.status"), 110.),
            GridCol::new("startType", t("services.startupType"), 150.),
            GridCol::new("pid", t("services.pid"), 70.).numeric(),
            GridCol::new("account", t("services.account"), 170.),
            GridCol::new("path", t("services.path"), 380.),
        ];
        let table = cx.new(|cx| {
            TableState::new(Grid::new(t("services.empty"), cols), window, cx)
                .row_selectable(false)
                .col_movable(false)
        });
        let search = cx.new(|cx| InputState::new(window, cx).placeholder(t("services.filter")));
        let subscriptions = vec![
            cx.observe(&table, |_, _, cx| cx.notify()),
            cx.subscribe(&search, |this, input, event: &InputEvent, cx| {
                if matches!(event, InputEvent::Change) {
                    let text = input.read(cx).value().to_string();
                    this.table.update(cx, |table, cx| {
                        table.delegate_mut().set_filter(&text);
                        table.refresh(cx);
                        cx.notify();
                    });
                }
            }),
        ];
        let mut page = Self {
            rows: Vec::new(),
            table,
            search,
            running_only: false,
            loading: false,
            error: None,
            core,
            elevated,
            acting: Acting::default(),
            focus: cx.focus_handle(),
            _subscriptions: subscriptions,
        };
        window.focus(&page.focus, cx);
        page.load(cx);
        page
    }

    fn load(&mut self, cx: &mut Context<Self>) {
        if self.core.is_none() {
            self.rows = crate::demo_pages::services();
            self.fill(cx);
            return;
        }
        self.loading = true;
        common::read(
            cx,
            || {
                vigil_sys::services::list().map(|list| {
                    list.into_iter()
                        .map(|service| Row {
                            protected: vigil_core::requests::protected_service(&service),
                            service,
                        })
                        .collect::<Vec<_>>()
                })
            },
            |page, result, cx| {
                page.loading = false;
                match result {
                    Ok(rows) => {
                        page.rows = rows;
                        page.error = None;
                    }
                    Err(error) => page.error = Some(error.to_string()),
                }
                page.fill(cx);
            },
        );
    }

    fn fill(&mut self, cx: &mut Context<Self>) {
        let tk = *tokens(cx);
        let rows: Vec<GridRow> = self
            .rows
            .iter()
            .filter(|r| !self.running_only || r.service.state == "running")
            .map(|r| {
                let s = &r.service;
                let color = match s.state.as_str() {
                    "running" => tk.ok,
                    "stopped" => tk.ink3,
                    _ => tk.warn,
                };
                let mut name = GridCell::text(&s.display_name);
                if r.protected {
                    name = name.glyph(icons::LOCK, tk.ink3);
                }
                let cells = vec![
                    name,
                    GridCell::text(&s.name),
                    GridCell::text(state_label(&s.state))
                        .ranked(state_rank(&s.state))
                        .color(color),
                    GridCell::text(start_label(&s.start_type)).ranked(start_rank(&s.start_type) as f64),
                    GridCell::num(
                        if s.pid > 0 { s.pid.to_string() } else { String::new() },
                        f64::from(s.pid),
                    ),
                    GridCell::text(&s.account),
                    GridCell::text(&s.path).mono(),
                ];
                let search = format!(
                    "{} {} {} {} {} {} {}",
                    s.display_name, s.name, s.description, s.pid, s.path, s.account, s.group
                );
                GridRow::new(s.name.clone(), cells, search)
            })
            .collect();
        self.table.update(cx, |table, cx| {
            table.delegate_mut().set_rows(rows);
            table.refresh(cx);
            cx.notify();
        });
    }

    fn current(&self, cx: &gpui_kit::App) -> Option<Row> {
        let key = self.table.read(cx).delegate().selected.clone()?;
        self.rows.iter().find(|r| r.service.name == key).cloned()
    }

    fn run(&mut self, op: &str, start_type: Option<&str>, window: &mut Window, cx: &mut Context<Self>) {
        let Some(row) = self.current(cx) else { return };
        let request = Request::Service {
            op: op.to_string(),
            name: row.service.name.clone(),
            start_type: start_type.map(str::to_string),
        };
        common::send(self, request, window, cx);
    }

    fn details(&self, row: &Row, tk: &Tokens) -> gpui_kit::Div {
        let s = &row.service;
        let host = if s.service_type == "share" {
            if s.group.is_empty() {
                t("services.sharedHost")
            } else {
                tf("services.sharedHostGroup", &[("group", &s.group)])
            }
        } else {
            t("services.ownProcess")
        };
        let runs = if s.pid > 0 {
            format!("{host} · PID {}", s.pid)
        } else {
            host
        };
        let note = if row.protected {
            t("services.protectedNote")
        } else if !self.elevated {
            t("services.adminNote")
        } else if s.start_type == "disabled" && s.state == "stopped" {
            t("services.disabledNote")
        } else {
            String::new()
        };
        ui::card(tk)
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .pb_1()
                    .child(
                        div()
                            .font_weight(gpui_kit::FontWeight::SEMIBOLD)
                            .child(s.display_name.clone()),
                    )
                    .child(
                        div()
                            .text_size(px(12.))
                            .text_color(tk.ink3)
                            .child(state_label(&s.state)),
                    )
                    .when(row.protected, |this| {
                        this.child(
                            div()
                                .flex()
                                .gap_1()
                                .text_size(px(12.))
                                .text_color(tk.ink3)
                                .child(icons::icon(icons::LOCK, 12.0, tk.ink3))
                                .child(t("services.protected")),
                        )
                    }),
            )
            .child(
                div()
                    .text_size(px(13.))
                    .text_color(tk.ink2)
                    .child(if s.description.is_empty() {
                        t("services.noDescription")
                    } else {
                        s.description.clone()
                    }),
            )
            .child(ui::fact(t("services.name"), s.name.clone(), true, tk))
            .child(ui::fact(
                t("services.startupType"),
                start_label(&s.start_type),
                false,
                tk,
            ))
            .child(ui::fact(t("services.runsIn"), runs, false, tk))
            .child(ui::fact(t("services.account"), s.account.clone(), false, tk))
            .child(ui::fact(t("services.path"), s.path.clone(), true, tk))
            .when(!s.dll.is_empty(), |this| {
                this.child(ui::fact(t("services.dll"), s.dll.clone(), true, tk))
            })
            .when(!note.is_empty(), |this| {
                this.child(div().pt_1().text_size(px(12.)).text_color(tk.ink3).child(note))
            })
    }
}

impl Render for ServicesPage {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let current = self.current(cx);
        let busy = self.acting.busy;
        let locked = current.as_ref().is_none_or(|r| r.protected) || !self.elevated || busy;
        let state = current.as_ref().map(|r| r.service.state.clone()).unwrap_or_default();
        let start = current
            .as_ref()
            .map(|r| r.service.start_type.clone())
            .unwrap_or_default();
        let can_start = !locked && state == "stopped" && start != "disabled";
        let can_stop = !locked && state == "running";
        let can_restart = can_stop && start != "disabled";
        let can_set_type = !locked && start_rank(&start) < START_TYPES.len();
        let executable = current
            .as_ref()
            .map(|r| r.service.executable.clone())
            .unwrap_or_default();
        let running = self.rows.iter().filter(|r| r.service.state == "running").count();
        let shown = self.table.read(cx).delegate().row_count();
        let weak = cx.entity().downgrade();
        let current_type = start.clone();

        let type_menu = FButton::new("svc-type", Kind::Standard)
            .label(t("services.startupType"))
            .chevron()
            .disabled(!can_set_type)
            .dropdown_menu(move |menu, _, _| {
                let mut menu = menu;
                for (value, key) in START_TYPES {
                    let weak = weak.clone();
                    let on = current_type == value;
                    menu = menu.item(PopupMenuItem::new(t(key)).checked(on).disabled(on).on_click(
                        move |_, window, cx| {
                            let _ = weak.update(cx, |page, cx| page.run("start_type", Some(value), window, cx));
                        },
                    ));
                }
                menu
            });

        let root = div()
            .track_focus(&self.focus)
            .size_full()
            .flex()
            .flex_col()
            .gap_2()
            .px(px(20.))
            .pt(px(12.))
            .pb(px(12.));
        common::list_keys(root, |p: &ServicesPage| p.table.clone(), cx)
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(ui::page_title(t("page.services")))
                    .child(div().flex_1())
                    .child(div().w(px(320.)).child(ui::search_box(&self.search, &tk)))
                    .child(ui::check_box(
                        "svc-running",
                        self.running_only,
                        false,
                        t("services.runningOnly"),
                        {
                            let weak = cx.entity().downgrade();
                            move |value, _, cx| {
                                let _ = weak.update(cx, |page, cx| {
                                    page.running_only = value;
                                    page.fill(cx);
                                });
                            }
                        },
                        &tk,
                    ))
                    .child(
                        ui::button(
                            "svc-refresh",
                            if self.loading {
                                t("common.reading")
                            } else {
                                t("common.refresh")
                            },
                        )
                        .disabled(self.loading)
                        .on_click(cx.listener(|this, _, _, cx| this.load(cx))),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_1()
                    .child(
                        ui::command("svc-start", icons::START, t("services.start"))
                            .disabled(!can_start)
                            .on_click(cx.listener(|this, _, window, cx| this.run("start", None, window, cx))),
                    )
                    .child(
                        ui::command("svc-stop", icons::STOP, t("services.stop"))
                            .danger(can_stop)
                            .disabled(!can_stop)
                            .on_click(cx.listener(|this, _, window, cx| this.run("stop", None, window, cx))),
                    )
                    .child(
                        ui::command("svc-restart", icons::REFRESH, t("services.restart"))
                            .disabled(!can_restart)
                            .on_click(cx.listener(|this, _, window, cx| this.run("restart", None, window, cx))),
                    )
                    .child(type_menu)
                    .child(ui::separator(&tk))
                    .child(
                        ui::command("svc-location", icons::FOLDER, t("proc.location"))
                            .disabled(executable.is_empty())
                            .on_click(cx.listener(move |this, _, window, cx| {
                                let request = Request::Shell {
                                    op: "location".into(),
                                    path: Some(executable.clone()),
                                    url: None,
                                    name: None,
                                };
                                common::send(this, request, window, cx);
                            })),
                    )
                    .child(
                        ui::command("svc-console", icons::SETTINGS, t("services.openConsole")).on_click(cx.listener(
                            |this, _, window, cx| {
                                let request = Request::Shell {
                                    op: "console".into(),
                                    path: None,
                                    url: None,
                                    name: Some("services.msc".into()),
                                };
                                common::send(this, request, window, cx);
                            },
                        )),
                    ),
            )
            .children(self.acting.bar("svc-result", &tk))
            .child(grid::frame(&tk).child(grid::table(&self.table, t("page.services"))))
            .child(match &current {
                Some(row) => self.details(row, &tk),
                None => ui::card(&tk).child(div().text_size(px(13.)).text_color(tk.ink3).child(t("services.pick"))),
            })
            .child(
                div()
                    .text_size(px(12.))
                    .text_color(tk.ink3)
                    .child(self.error.clone().unwrap_or_else(|| {
                        tf(
                            "services.summary",
                            &[
                                ("shown", &crate::format::num(shown as f64, 0)),
                                ("total", &crate::format::num(self.rows.len() as f64, 0)),
                                ("running", &crate::format::num(running as f64, 0)),
                            ],
                        )
                    })),
            )
    }
}
