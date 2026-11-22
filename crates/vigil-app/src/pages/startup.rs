//! The Startup apps page: what Windows starts at
//! sign-in, from the Run keys, the Startup folders and policies, with each program's publisher,
//! state, signature (checked in the background) and location; Enable, Disable and (for policy
//! entries) Delete go through the action service.

use std::collections::HashMap;
use std::sync::Arc;

use gpui_kit::component::input::{InputEvent, InputState};
use gpui_kit::component::table::TableState;
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    AppContext as _, Context, Entity, FocusHandle, InteractiveElement as _, IntoElement, ParentElement, Render, Styled,
    Subscription, Window, div, px,
};
use vigil_core::inspect::StartupSignature;
use vigil_core::requests::Request;
use vigil_core::state::AppState;
use vigil_sys::startup::StartupEntry;

use crate::i18n::{t, tf};
use crate::icons;
use crate::pages::common::{self, Acting, Acts};
use crate::theme::{Tokens, tokens};
use crate::ui;
use crate::ui::grid::{self, Grid, GridCell, GridCol, GridRow};

fn base_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

fn display_name(e: &StartupEntry) -> String {
    if e.description.is_empty() {
        e.name.clone()
    } else {
        e.description.clone()
    }
}

fn publisher(e: &StartupEntry) -> String {
    if e.host {
        tf("startup.viaHost", &[("host", base_name(&e.executable))])
    } else {
        e.publisher.clone()
    }
}

fn status(e: &StartupEntry) -> (String, f64) {
    if e.kind == "policy" {
        (t("startup.byPolicy"), 2.0)
    } else if !e.can_toggle {
        (t("startup.runsOnce"), 2.0)
    } else if e.enabled {
        (t("startup.enabled"), 0.0)
    } else {
        (t("startup.disabled"), 1.0)
    }
}

fn location(e: &StartupEntry) -> String {
    let user = e.scope == "user";
    let key = match e.kind.as_str() {
        "folder" if user => "startup.locFolderUser",
        "folder" => "startup.locFolderMachine",
        "run_once" if user => "startup.locOnceUser",
        "run_once" => "startup.locOnceMachine",
        "policy" if user => "startup.locPolicyUser",
        "policy" => "startup.locPolicyMachine",
        _ if user => "startup.locRunUser",
        _ if e.location.to_ascii_lowercase().contains("wow6432node") => "startup.locRun32",
        _ => "startup.locRunMachine",
    };
    t(key)
}

/// The signature column: text, colour (only when something is wrong) and sort rank.
fn signature(
    e: &StartupEntry,
    found: Option<&StartupSignature>,
    checking: bool,
    tk: &Tokens,
) -> (String, gpui_kit::Hsla, f64) {
    if e.executable.is_empty() {
        return (t("startup.sigUnknown"), tk.ink3, 5.0);
    }
    if !e.exists {
        return (t("startup.fileMissing"), tk.warn, 3.0);
    }
    if e.host {
        return (t("startup.sigHost"), tk.ink3, 4.0);
    }
    let Some(found) = found else {
        let text = if checking {
            t("startup.sigChecking")
        } else {
            t("startup.sigUnknown")
        };
        return (text, tk.ink3, 5.0);
    };
    match found.status.as_str() {
        "broken" => (t("startup.sigBroken"), tk.bad, 0.0),
        "untrusted" => (t("startup.sigUntrusted"), tk.bad, 1.0),
        "unsigned" => (t("startup.sigUnsigned"), tk.warn, 2.0),
        "missing" => (t("startup.fileMissing"), tk.warn, 3.0),
        "valid" => (t("startup.sigValid"), tk.ink, 6.0),
        _ => (t("startup.sigUnknown"), tk.ink3, 5.0),
    }
}

pub struct StartupPage {
    rows: Vec<StartupEntry>,
    signatures: HashMap<String, StartupSignature>,
    checking: bool,
    /// Program icons by lower-case path (`None`: the file has none).
    icons: HashMap<String, Option<Arc<gpui_kit::Image>>>,
    table: Entity<TableState<Grid>>,
    search: Entity<InputState>,
    loading: bool,
    error: Option<String>,
    core: Option<Arc<AppState>>,
    elevated: bool,
    acting: Acting,
    focus: FocusHandle,
    _subscriptions: Vec<Subscription>,
}

impl Acts for StartupPage {
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

impl StartupPage {
    pub fn new(core: Option<Arc<AppState>>, elevated: bool, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let cols = vec![
            GridCol::new("name", t("startup.colName"), 300.),
            GridCol::new("publisher", t("startup.colPublisher"), 220.),
            GridCol::new("status", t("startup.colStatus"), 130.),
            GridCol::new("signature", t("startup.colSignature"), 150.),
            GridCol::new("location", t("startup.colLocation"), 260.),
        ];
        let table = cx.new(|cx| {
            TableState::new(Grid::new(t("startup.empty"), cols), window, cx)
                .row_selectable(false)
                .col_movable(false)
        });
        let search = cx.new(|cx| InputState::new(window, cx).placeholder(t("startup.search")));
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
            signatures: HashMap::new(),
            checking: false,
            icons: HashMap::new(),
            table,
            search,
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
            let (rows, signatures) = crate::demo_pages::startup();
            self.rows = rows;
            self.signatures = signatures;
            self.fill(cx);
            return;
        }
        self.loading = true;
        common::read(cx, vigil_sys::startup::list, |page, rows, cx| {
            page.loading = false;
            page.rows = rows;
            page.fill(cx);
            page.check(cx);
            page.read_icons(cx);
        });
    }

    /// The programs' icons, read once each in the background.
    fn read_icons(&mut self, cx: &mut Context<Self>) {
        let paths: Vec<String> = self
            .rows
            .iter()
            .filter(|r| r.exists && !r.host && !r.executable.is_empty())
            .map(|r| r.executable.clone())
            .filter(|p| !self.icons.contains_key(&p.to_lowercase()))
            .collect();
        if paths.is_empty() {
            return;
        }
        common::read(
            cx,
            move || {
                paths
                    .into_iter()
                    .take(256)
                    .map(|path| {
                        let image = vigil_sys::apps::icon_data_url(&path)
                            .and_then(|url| crate::format::data_url_bytes(&url))
                            .map(|bytes| Arc::new(gpui_kit::Image::from_bytes(gpui_kit::ImageFormat::Png, bytes)));
                        (path.to_lowercase(), image)
                    })
                    .collect::<Vec<_>>()
            },
            |page, found, cx| {
                page.icons.extend(found);
                page.fill(cx);
            },
        );
    }

    /// Each signature check runs PowerShell, so they are read after the list and never hold it up.
    fn check(&mut self, cx: &mut Context<Self>) {
        let mut paths: Vec<String> = self
            .rows
            .iter()
            .filter(|r| r.exists && !r.host && !r.executable.is_empty())
            .map(|r| r.executable.clone())
            .filter(|p| !self.signatures.contains_key(p))
            .collect();
        paths.sort();
        paths.dedup();
        if paths.is_empty() {
            return;
        }
        self.checking = true;
        common::read(
            cx,
            move || vigil_core::inspect::startup_signatures(paths),
            |page, found, cx| {
                page.checking = false;
                page.signatures.extend(found);
                page.fill(cx);
            },
        );
    }

    fn fill(&mut self, cx: &mut Context<Self>) {
        let tk = *tokens(cx);
        let rows: Vec<GridRow> = self
            .rows
            .iter()
            .map(|e| {
                let (state, rank) = status(e);
                let (sig, color, sig_rank) = signature(e, self.signatures.get(&e.executable), self.checking, &tk);
                let image = self.icons.get(&e.executable.to_lowercase()).cloned().flatten();
                let mut name = GridCell::text(display_name(e));
                name = if image.is_some() {
                    name.image(image)
                } else {
                    name.glyph(icons::APP, tk.ink3)
                };
                if e.own {
                    name.text = format!("{} · {}", name.text, t("startup.own"));
                }
                let cells = vec![
                    name,
                    GridCell::text(publisher(e)),
                    GridCell::text(state).ranked(rank),
                    GridCell::text(sig).ranked(sig_rank).color(color),
                    GridCell::text(location(e)),
                ];
                let search = format!(
                    "{} {} {} {} {}",
                    e.name, e.description, e.publisher, e.command, e.location
                );
                let mut row = GridRow::new(e.id.clone(), cells, search);
                row.dim = e.can_toggle && !e.enabled;
                row
            })
            .collect();
        self.table.update(cx, |table, cx| {
            table.delegate_mut().set_rows(rows);
            table.refresh(cx);
            cx.notify();
        });
    }

    fn current(&self, cx: &gpui_kit::App) -> Option<StartupEntry> {
        let key = self.table.read(cx).delegate().selected.clone()?;
        self.rows.iter().find(|r| r.id == key).cloned()
    }

    fn toggle(&mut self, op: &str, window: &mut Window, cx: &mut Context<Self>) {
        let Some(entry) = self.current(cx) else { return };
        let request = Request::Startup {
            op: op.to_string(),
            id: entry.id,
        };
        common::send(self, request, window, cx);
    }

    fn shell(&mut self, op: &str, path: String, window: &mut Window, cx: &mut Context<Self>) {
        let request = Request::Shell {
            op: op.into(),
            path: Some(path),
            url: None,
            name: None,
        };
        common::send(self, request, window, cx);
    }

    fn details(&self, e: &StartupEntry, tk: &Tokens) -> gpui_kit::Div {
        let (state, _) = status(e);
        let note = if e.kind == "policy" {
            if self.elevated {
                t("startup.policyNote")
            } else {
                t("startup.policyAdminNote")
            }
        } else if !e.can_toggle {
            t("startup.onceNote")
        } else if e.scope == "machine" && !self.elevated {
            t("startup.adminNote")
        } else if !e.exists {
            t("startup.missingNote")
        } else if e.host {
            t("startup.hostNote")
        } else {
            String::new()
        };
        let place = if e.kind == "folder" {
            e.file.clone()
        } else {
            format!(r"{}\{}", e.location, e.value)
        };
        let signer = self
            .signatures
            .get(&e.executable)
            .filter(|s| !s.signer.is_empty())
            .map(|s| tf("startup.signedBy", &[("signer", &s.signer)]));
        ui::card(tk)
            .child(
                div()
                    .flex()
                    .items_baseline()
                    .gap_3()
                    .pb_1()
                    .child(div().font_weight(gpui_kit::FontWeight::SEMIBOLD).child(display_name(e)))
                    .child(
                        div()
                            .text_size(px(12.))
                            .text_color(tk.ink3)
                            .child(format!("{state} · {}", location(e))),
                    ),
            )
            .child(ui::fact(
                t("startup.command"),
                if e.command.is_empty() {
                    "—".into()
                } else {
                    e.command.clone()
                },
                true,
                tk,
            ))
            .child(ui::fact(
                t("startup.program"),
                if e.executable.is_empty() {
                    "—".into()
                } else {
                    e.executable.clone()
                },
                true,
                tk,
            ))
            .child(ui::fact(t("startup.where"), place, true, tk))
            .child(ui::fact(
                t("startup.scope"),
                if e.scope == "user" {
                    t("startup.scopeUser")
                } else {
                    t("startup.scopeMachine")
                },
                false,
                tk,
            ))
            .when_some(signer, |this, signer| {
                this.child(ui::fact(t("startup.colSignature"), signer, false, tk))
            })
            .when(!note.is_empty(), |this| {
                this.child(div().pt_1().text_size(px(12.)).text_color(tk.ink3).child(note))
            })
    }
}

impl Render for StartupPage {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let current = self.current(cx);
        let busy = self.acting.busy;
        let switchable = current
            .as_ref()
            .is_some_and(|e| e.can_toggle && (e.scope == "user" || self.elevated))
            && !busy;
        let can_enable = switchable && current.as_ref().is_some_and(|e| !e.enabled);
        let can_disable = switchable && current.as_ref().is_some_and(|e| e.enabled);
        let policy = current.as_ref().is_some_and(|e| e.kind == "policy");
        let can_delete = policy && self.elevated && !busy;
        let target = current
            .as_ref()
            .map(|e| {
                if e.host || !e.exists {
                    e.file.clone()
                } else {
                    e.executable.clone()
                }
            })
            .unwrap_or_default();
        let enabled = self.rows.iter().filter(|e| e.can_toggle && e.enabled).count();
        let shown = self.table.read(cx).delegate().row_count();
        let (location_target, properties_target) = (target.clone(), target.clone());

        let root = div()
            .track_focus(&self.focus)
            .size_full()
            .flex()
            .flex_col()
            .gap_2()
            .px(px(20.))
            .pt(px(10.))
            .pb(px(12.));
        common::list_keys(root, |p: &StartupPage| p.table.clone(), cx)
            .child(
                div()
                    .flex()
                    .justify_center()
                    .child(div().w(px(640.)).max_w_full().child(ui::search_box(&self.search, &tk))),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_1()
                    .min_h(px(40.))
                    .child(ui::page_title(t("page.startup")))
                    .child(div().flex_1())
                    .child(
                        ui::command("st-enable", icons::CHECK, t("startup.enable"))
                            .disabled(!can_enable)
                            .on_click(cx.listener(|this, _, window, cx| this.toggle("enable", window, cx))),
                    )
                    .child(
                        ui::command("st-disable", icons::END_TASK, t("startup.disable"))
                            .disabled(!can_disable)
                            .on_click(cx.listener(|this, _, window, cx| this.toggle("disable", window, cx))),
                    )
                    .when(policy, |this| {
                        this.child(
                            ui::command("st-delete", icons::DELETE, t("startup.delete"))
                                .danger(can_delete)
                                .disabled(!can_delete)
                                .on_click(cx.listener(|this, _, window, cx| this.toggle("delete", window, cx))),
                        )
                    })
                    .child(ui::separator(&tk))
                    .child(
                        ui::command("st-location", icons::FOLDER, t("proc.location"))
                            .disabled(target.is_empty())
                            .on_click(cx.listener(move |this, _, window, cx| {
                                this.shell("location", location_target.clone(), window, cx)
                            })),
                    )
                    .child(
                        ui::command("st-properties", icons::PROPERTIES, t("proc.properties"))
                            .disabled(target.is_empty())
                            .on_click(cx.listener(move |this, _, window, cx| {
                                this.shell("properties", properties_target.clone(), window, cx)
                            })),
                    )
                    .child(ui::separator(&tk))
                    .child(
                        ui::command("st-refresh", icons::REFRESH, t("common.refresh"))
                            .disabled(self.loading)
                            .on_click(cx.listener(|this, _, _, cx| this.load(cx))),
                    ),
            )
            .child(div().text_size(px(12.)).text_color(tk.ink3).child(t("startup.note")))
            .children(self.acting.bar("st-result", &tk))
            .child(grid::frame(&tk).child(grid::table(&self.table, t("page.startup"))))
            .when_some(current.as_ref(), |this, e| this.child(self.details(e, &tk)))
            .child(
                div()
                    .text_size(px(12.))
                    .text_color(tk.ink3)
                    .child(self.error.clone().unwrap_or_else(|| {
                        let mut line = tf(
                            "startup.summary",
                            &[
                                ("shown", &crate::format::num(shown as f64, 0)),
                                ("total", &crate::format::num(self.rows.len() as f64, 0)),
                                ("enabled", &crate::format::num(enabled as f64, 0)),
                            ],
                        );
                        if self.checking {
                            line.push_str(&format!(" · {}", t("startup.checking")));
                        }
                        line
                    })),
            )
    }
}
