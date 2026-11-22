//! Installed programs: everything with an Uninstall entry, with recent installs, remote-access
//! tools, leftover entries and unsigned files marked, and the selected program's details.
//! Uninstall, remove a leftover entry and open its folder go through the action service.

use std::collections::HashMap;
use std::sync::Arc;

use gpui_kit::component::input::InputState;
use gpui_kit::component::table::TableState;
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    Context, Div, ElementId, Entity, FocusHandle, Hsla, Image, InteractiveElement as _, IntoElement, ParentElement,
    Render, StatefulInteractiveElement as _, Styled, Subscription, Window, div, px,
};
use serde_json::{Value, json};
use vigil_core::state::AppState;

use crate::app::Ctx;
use crate::data::{self, Src};
use crate::format::size;
use crate::i18n::{t, tf, tn};
use crate::icons;
use crate::pages::common::{self, Acting, Acts, when};
use crate::theme::{Tokens, tokens};
use crate::ui;
use crate::ui::grid::{self, Grid, GridCell, GridCol, GridRow};
use crate::ui::kit::{self, J as _};

const RECENT_DAYS: i64 = 7;

const CHIPS: [(&str, &str); 5] = [
    ("all", "programs.chipAll"),
    ("recent", "programs.chipRecent"),
    ("remote", "programs.chipRemote"),
    ("leftover", "programs.chipLeftover"),
    ("unsigned", "programs.chipUnsigned"),
];

fn files_of(p: &Value) -> Vec<String> {
    let mut files = Vec::new();
    if p.has("executable") {
        files.push(p.s("executable").to_string());
    }
    if p.b("uninstallerExists") && !p.b("uninstallerHost") {
        let u = p.s("uninstaller").to_string();
        if !u.is_empty() && !files.iter().any(|f| f.eq_ignore_ascii_case(&u)) {
            files.push(u);
        }
    }
    files
}

fn days_since(date: &str) -> Option<i64> {
    let today = kit::last_days(1).pop()?;
    let day = |s: &str| -> Option<i64> {
        let mut p = s.get(..10)?.split('-');
        let (y, m, d) = (
            p.next()?.parse::<i64>().ok()?,
            p.next()?.parse::<i64>().ok()?,
            p.next()?.parse::<i64>().ok()?,
        );
        // Days from a civil date (inverse of `kit::civil`).
        let y = if m <= 2 { y - 1 } else { y };
        let era = y.div_euclid(400);
        let yoe = y - era * 400;
        let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        Some(era * 146_097 + doe - 719_468)
    };
    Some(day(&today)? - day(date)?)
}

fn recent(p: &Value) -> bool {
    days_since(p.s("installed")).is_some_and(|d| (0..=RECENT_DAYS).contains(&d))
}

fn scope_text(p: &Value) -> String {
    if p.has("sid") {
        return if p.has("account") {
            p.s("account").to_string()
        } else {
            p.s("sid").to_string()
        };
    }
    t(match p.s("scope") {
        "user" => "programs.scopeUser",
        "machine32" => "programs.scopeMachine32",
        _ => "programs.scopeMachine",
    })
}

pub struct ProgramsPage {
    ctx: Ctx,
    rows: Vec<Value>,
    signatures: HashMap<String, Value>,
    icons: HashMap<String, Arc<Image>>,
    chip: &'static str,
    loading: bool,
    checking: bool,
    error: Option<String>,
    table: Entity<TableState<Grid>>,
    search: Entity<InputState>,
    acting: Acting,
    focus: FocusHandle,
    _subscriptions: Vec<Subscription>,
}

impl Acts for ProgramsPage {
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

impl ProgramsPage {
    pub fn new(ctx: Ctx, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let cols = vec![
            GridCol::new("name", t("programs.colName"), 300.),
            GridCol::new("publisher", t("programs.colPublisher"), 200.),
            GridCol::new("version", t("programs.colVersion"), 120.),
            GridCol::new("installed", t("programs.colInstalled"), 120.),
            GridCol::new("size", t("programs.colSize"), 90.).numeric(),
            GridCol::new("scope", t("programs.colScope"), 150.),
        ];
        let table = grid::new_state(t("programs.empty"), cols, window, cx);
        let (search, searching) = grid::search(&table, t("programs.search"), window, cx);
        let subscriptions = vec![searching, cx.observe(&table, |_, _, cx| cx.notify())];
        let mut page = Self {
            ctx,
            rows: Vec::new(),
            signatures: HashMap::new(),
            icons: HashMap::new(),
            chip: "all",
            loading: false,
            checking: false,
            error: None,
            table,
            search,
            acting: Acting::default(),
            focus: cx.focus_handle(),
            _subscriptions: subscriptions,
        };
        window.focus(&page.focus, cx);
        page.load(cx);
        page
    }

    fn load(&mut self, cx: &mut Context<Self>) {
        self.loading = true;
        let core = self.ctx.core.clone();
        common::read(
            cx,
            move || {
                let rows = data::fetch(core.as_ref(), Src::Programs);
                let paths: Vec<String> = rows
                    .as_ref()
                    .ok()
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter(|p| p.has("icon"))
                            .map(|p| p.s("icon").to_string())
                            .collect()
                    })
                    .unwrap_or_default();
                let icons: HashMap<String, Arc<Image>> = data::fetch(core.as_ref(), Src::Icons(paths))
                    .ok()
                    .and_then(|v| v.as_object().cloned())
                    .map(|o| {
                        o.iter()
                            .filter_map(|(k, v)| kit::image(v.as_str()?).map(|i| (k.to_lowercase(), i)))
                            .collect()
                    })
                    .unwrap_or_default();
                (rows, icons)
            },
            |this: &mut Self, (result, icons), cx| {
                this.loading = false;
                this.icons = icons;
                match result {
                    Ok(v) => {
                        this.rows = v.as_array().cloned().unwrap_or_default();
                        this.error = None;
                    }
                    Err(e) => this.error = Some(e),
                }
                this.fill(cx);
                this.check(cx);
            },
        );
    }

    /// Checks the files' signatures in batches, without holding the list.
    fn check(&mut self, cx: &mut Context<Self>) {
        let mut paths: Vec<String> = self
            .rows
            .iter()
            .flat_map(files_of)
            .filter(|f| !self.signatures.contains_key(f))
            .collect();
        paths.sort();
        paths.dedup();
        if paths.is_empty() {
            return;
        }
        self.checking = true;
        let core = self.ctx.core.clone();
        common::read(
            cx,
            move || {
                let mut found = HashMap::new();
                for batch in paths.chunks(48) {
                    if let Ok(Value::Object(map)) = data::fetch(core.as_ref(), Src::ProgramSignatures(batch.to_vec())) {
                        found.extend(map);
                    }
                }
                found
            },
            |this: &mut Self, found, cx| {
                this.checking = false;
                this.signatures.extend(found);
                this.fill(cx);
            },
        );
    }

    fn unsigned(&self, p: &Value) -> Vec<String> {
        files_of(p)
            .into_iter()
            .filter(|f| {
                self.signatures
                    .get(f)
                    .is_some_and(|s| matches!(s.s("status"), "unsigned" | "broken" | "untrusted"))
            })
            .collect()
    }

    /// The marks of a program: (text, deserves a look).
    fn marks(&self, p: &Value) -> Vec<(String, bool)> {
        let mut marks = Vec::new();
        if p.b("remote") {
            marks.push((t("programs.flagRemote"), true));
        }
        if p.b("leftover") {
            marks.push((t("programs.flagLeftover"), true));
        }
        for f in self.unsigned(p) {
            marks.push((tf("programs.flagUnsigned", &[("file", kit::base_name(&f))]), true));
        }
        if recent(p) {
            marks.push((tn("programs.flagRecent", RECENT_DAYS as u64, &[]), false));
        }
        marks
    }

    fn chip_test(&self, chip: &str, p: &Value) -> bool {
        match chip {
            "recent" => recent(p),
            "remote" => p.b("remote"),
            "leftover" => p.b("leftover"),
            "unsigned" => !self.unsigned(p).is_empty(),
            _ => true,
        }
    }

    fn fill(&mut self, cx: &mut Context<Self>) {
        let tk = *tokens(cx);
        let mut list: Vec<&Value> = self.rows.iter().filter(|p| self.chip_test(self.chip, p)).collect();
        list.sort_by_key(|p| p.s("name").to_lowercase());
        let rows = list
            .into_iter()
            .map(|p| {
                let marks = self.marks(p);
                let mut name = GridCell::text(p.s("name")).image(self.icons.get(&p.s("icon").to_lowercase()).cloned());
                if marks.iter().any(|(_, w)| *w) {
                    name = name.glyph(icons::WARNING, tk.warn);
                } else if !marks.is_empty() {
                    name = name.glyph(icons::INFO, tk.ink3);
                } else if name.image.is_none() {
                    name = name.glyph('\u{E71D}', tk.ink2);
                }
                let mut installed = GridCell::text(if p.has("installed") {
                    when(p.s("installed"))
                } else {
                    String::new()
                });
                installed.sort = grid::SortKey::Text(p.s("installed").to_string());
                let bytes = p.n("size");
                let cells = vec![
                    name,
                    GridCell::text(p.s("publisher")),
                    GridCell::text(p.s("version")),
                    installed,
                    GridCell::num(if bytes > 0.0 { size(bytes, 1) } else { String::new() }, bytes),
                    GridCell::text(scope_text(p)),
                ];
                let search = format!(
                    "{} {} {} {} {} {}",
                    p.s("name"),
                    p.s("publisher"),
                    p.s("version"),
                    p.s("location"),
                    p.s("uninstaller"),
                    p.s("keyName")
                );
                let mut row = GridRow::new(p.s("id").to_string(), cells, search);
                row.dim = p.b("leftover");
                row
            })
            .collect();
        grid::fill(&self.table, rows, cx);
    }

    fn current(&self, cx: &gpui_kit::App) -> Option<Value> {
        let key = grid::selected(&self.table, cx)?;
        self.rows.iter().find(|p| p.s("id") == key).cloned()
    }

    fn signature(&self, path: &str, tk: &Tokens) -> (String, Hsla) {
        match self.signatures.get(path) {
            None => (
                t(if self.checking {
                    "startup.sigChecking"
                } else {
                    "startup.sigUnknown"
                }),
                tk.ink3,
            ),
            Some(s) => {
                let (key, color) = match s.s("status") {
                    "broken" => ("startup.sigBroken", tk.bad),
                    "untrusted" => ("startup.sigUntrusted", tk.bad),
                    "unsigned" => ("startup.sigUnsigned", tk.warn),
                    "missing" => ("startup.fileMissing", tk.warn),
                    "valid" => ("startup.sigValid", tk.ink),
                    _ => ("startup.sigUnknown", tk.ink3),
                };
                let mut text = t(key);
                if s.has("signer") {
                    text = format!("{text} · {}", s.s("signer"));
                }
                (text, color)
            }
        }
    }

    fn detail(&self, p: &Value, tk: &Tokens) -> Div {
        let sub: Vec<&str> = [p.s("publisher"), p.s("version")]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect();
        let mut pane = kit::panel(tk)
            .child(kit::h3(p.s("name").to_string()))
            .child(kit::faint(sub.join(" · "), tk));
        for (text, warn) in self.marks(p) {
            let (g, c) = if warn {
                (icons::WARNING, tk.warn)
            } else {
                (icons::INFO, tk.ink2)
            };
            pane = pane.child(kit::row().child(kit::glyph(g, 14., c)).child(kit::body(text)));
        }
        let mut rows: Vec<(String, String, Option<Hsla>, bool)> = Vec::new();
        let installed = if !p.has("installed") {
            "—".to_string()
        } else if p.b("installedEstimated") {
            tf("programs.estimated", &[("date", &when(p.s("installed")))])
        } else {
            when(p.s("installed"))
        };
        rows.push((t("programs.colInstalled"), installed, None, false));
        rows.push((
            t("programs.colSize"),
            if p.n("size") > 0.0 {
                size(p.n("size"), 1)
            } else {
                t("programs.notDeclared")
            },
            None,
            false,
        ));
        let location = if !p.has("location") {
            t("programs.notDeclared")
        } else if !p.b("locationExists") {
            tf("programs.locationMissing", &[("path", p.s("location"))])
        } else if p.b("locationEmpty") {
            tf("programs.locationEmpty", &[("path", p.s("location"))])
        } else {
            p.s("location").to_string()
        };
        rows.push((t("programs.location"), location, None, false));
        rows.push((
            t("programs.uninstallCommand"),
            if p.has("uninstall") {
                p.s("uninstall").to_string()
            } else {
                "—".into()
            },
            None,
            true,
        ));
        if p.has("quietUninstall") {
            rows.push((
                t("programs.quietCommand"),
                p.s("quietUninstall").to_string(),
                None,
                true,
            ));
        }
        if p.has("executable") {
            rows.push((t("programs.executable"), p.s("executable").to_string(), None, true));
            let (text, color) = self.signature(p.s("executable"), tk);
            rows.push((t("programs.signature"), text, Some(color), false));
        }
        if p.has("uninstaller") && !p.b("uninstallerHost") {
            let value = if p.b("uninstallerExists") {
                p.s("uninstaller").to_string()
            } else {
                tf("programs.locationMissing", &[("path", p.s("uninstaller"))])
            };
            rows.push((t("programs.uninstaller"), value, None, true));
            if p.b("uninstallerExists") && !p.s("uninstaller").eq_ignore_ascii_case(p.s("executable")) {
                let (text, color) = self.signature(p.s("uninstaller"), tk);
                rows.push((t("programs.signature"), text, Some(color), false));
            }
        }
        if p.b("msi") {
            let code = p.s("productCode");
            let (value, warn) = if code.is_empty() {
                ("—".to_string(), false)
            } else if p.b("msiKnown") {
                (tf("programs.msiKnown", &[("code", code)]), false)
            } else {
                (tf("programs.msiUnknown", &[("code", code)]), true)
            };
            rows.push((t("programs.msiLabel"), value, warn.then_some(tk.warn), false));
        }
        rows.push((t("programs.colScope"), scope_text(p), None, false));
        rows.push((t("programs.registry"), p.s("id").to_string(), None, true));
        for (i, (label, value, color, mono)) in rows.into_iter().enumerate() {
            let text = kit::sel(ElementId::NamedInteger("pg-f".into(), i as u64), value)
                .when(mono, |this| {
                    this.font_family(crate::theme::FONT_MONO).text_size(px(12.))
                })
                .when_some(color, |this, c| this.text_color(c));
            pane = pane.child(kit::kv(label, text, 150., tk));
        }
        if p.has("sid") {
            let account = if p.has("account") { p.s("account") } else { p.s("sid") };
            pane = pane.child(kit::faint(tf("programs.otherNote", &[("account", account)]), tk));
        } else if p.s("scope") != "user" && !self.ctx.elevated {
            pane = pane.child(kit::faint(t("programs.adminNote"), tk));
        }
        if p.b("leftover") {
            pane = pane.child(kit::faint(
                t(if p.b("microsoft") {
                    "programs.microsoftNote"
                } else {
                    "programs.leftoverNote"
                }),
                tk,
            ));
        }
        if p.b("noRemove") {
            pane = pane.child(kit::faint(t("programs.noRemoveNote"), tk));
        }
        if !p.has("uninstall") {
            pane = pane.child(kit::faint(t("programs.noUninstallerNote"), tk));
        }
        pane
    }

    fn run(&mut self, op: &str, window: &mut Window, cx: &mut Context<Self>) {
        let Some(p) = self.current(cx) else { return };
        common::send_json(self, json!({"kind": "program", "op": op, "id": p.s("id")}), window, cx);
    }
}

impl Render for ProgramsPage {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let current = self.current(cx);
        let mine = current
            .as_ref()
            .is_some_and(|p| !p.has("sid") && (p.s("scope") == "user" || self.ctx.elevated))
            && !self.acting.busy;
        let can_uninstall = current.as_ref().is_some_and(|p| {
            mine && p.has("uninstall")
                && !p.b("noRemove")
                && if p.b("msi") {
                    !(p.has("productCode") && !p.b("msiKnown"))
                } else {
                    p.b("uninstallerExists")
                }
        });
        let can_remove_entry = current
            .as_ref()
            .is_some_and(|p| mine && p.b("leftover") && !p.b("microsoft") && !(p.b("msi") && p.b("msiKnown")));
        let can_folder = current
            .as_ref()
            .is_some_and(|p| p.has("location") && p.b("locationExists"));
        let mut chips = kit::row();
        for (key, label) in CHIPS {
            let n = self.rows.iter().filter(|p| self.chip_test(key, p)).count();
            if key != "all" && n == 0 {
                continue;
            }
            let weak = cx.entity().downgrade();
            chips = chips.child(kit::chip(
                ElementId::Name(format!("pg-chip-{key}").into()),
                t(label),
                Some(n),
                self.chip == key,
                false,
                move |_, cx| {
                    let _ = weak.update(cx, |this, cx| {
                        this.chip = key;
                        this.fill(cx);
                    });
                },
                &tk,
            ));
        }
        let shown_size: f64 = self
            .rows
            .iter()
            .filter(|p| self.chip_test(self.chip, p))
            .map(|p| p.n("size"))
            .sum();
        let mut footer = match &self.error {
            Some(e) => e.clone(),
            None => tf(
                "programs.summary",
                &[
                    ("shown", &self.table.read(cx).delegate().row_count().to_string()),
                    ("total", &self.rows.len().to_string()),
                    ("size", &size(shown_size, 1)),
                ],
            ),
        };
        if self.checking {
            footer = format!("{footer} · {}", t("startup.checking"));
        }
        let root = div()
            .track_focus(&self.focus)
            .size_full()
            .flex()
            .flex_col()
            .gap_2()
            .px(px(20.))
            .pt(px(12.))
            .pb(px(12.));
        common::list_keys(root, |p: &ProgramsPage| p.table.clone(), cx)
            .child(
                div()
                    .flex()
                    .justify_center()
                    .child(div().w_full().max_w(px(640.)).child(ui::search_box(&self.search, &tk))),
            )
            .child(
                kit::row().child(ui::page_title(t("page.programs"))).child(
                    ui::CommandBar::new("pg-bar")
                        .cmd(
                            ui::cmd("pg-uninstall", icons::DELETE, t("programs.uninstall"))
                                .disabled(!can_uninstall)
                                .on_click(cx.listener(|this, _, window, cx| this.run("uninstall", window, cx))),
                        )
                        .cmd(
                            ui::cmd("pg-entry", '\u{E75C}', t("programs.removeEntry"))
                                .disabled(!can_remove_entry)
                                .on_click(cx.listener(|this, _, window, cx| this.run("remove_entry", window, cx))),
                        )
                        .separator()
                        .cmd(
                            ui::cmd("pg-folder", icons::FOLDER, t("programs.openFolder"))
                                .disabled(!can_folder)
                                .on_click(cx.listener(|this, _, window, cx| this.run("folder", window, cx))),
                        )
                        .cmd(
                            ui::cmd("pg-settings", icons::SETTINGS, t("programs.openSettings")).on_click(cx.listener(
                                |this, _, window, cx| {
                                    common::send_json(
                                        this,
                                        json!({"kind": "shell", "op": "url", "url": "ms-settings:appsfeatures"}),
                                        window,
                                        cx,
                                    )
                                },
                            )),
                        )
                        .separator()
                        .cmd(
                            ui::cmd("pg-refresh", icons::REFRESH, t("common.refresh"))
                                .disabled(self.loading)
                                .on_click(cx.listener(|this, _, _, cx| this.load(cx))),
                        ),
                ),
            )
            .child(kit::faint(t("programs.note"), &tk))
            .children(self.acting.bar("pg-result", &tk))
            .child(chips)
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .flex()
                    .gap_3()
                    .child(grid::frame(&tk).child(grid::table(&self.table, t("page.programs"))))
                    .when_some(current, |this, p| {
                        this.child(
                            div()
                                .id("pg-pane")
                                .w(px(400.))
                                .flex_none()
                                .overflow_y_scroll()
                                .child(self.detail(&p, &tk)),
                        )
                    }),
            )
            .child(kit::faint(footer, &tk))
    }
}
