//! Findings: every item of the report with filters by verdict, novelty and kind, a search, and the
//! selected finding's details: its actions (planned and checked by the core, confirmed natively),
//! ignore, copy, what is known about its file, roles, signals and commands, and the AI
//! investigation (consent, progress, result).

use std::collections::BTreeMap;
use std::sync::Arc;

use futures::StreamExt as _;
use futures::channel::mpsc;
use gpui_kit::component::input::InputState;
use gpui_kit::component::menu::{DropdownMenu as _, PopupMenuItem};
use gpui_kit::component::table::TableState;
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    AnyElement, AppContext as _, ClipboardItem, Context, Div, ElementId, Entity, FocusHandle, FontWeight,
    InteractiveElement as _, IntoElement, ParentElement, Render, StatefulInteractiveElement as _, Styled, Subscription,
    Window, div, px,
};
use serde_json::{Value, json};
use vigil_core::export::Format;
use vigil_core::state::AppState;

use crate::app::{Ctx, Focus, Report};
use crate::data::{self, Src};
use crate::i18n::{t, tf, tn};
use crate::icons;
use crate::pages::common::{self, Acting, Acts, when};
use crate::pages::labels::{KINDS, VERDICT_ORDER, kind_label, verdict_label, verdict_rank};
use crate::theme::{FONT_MONO, tokens};
use crate::ui::grid::{self, Grid, GridCell, GridCol, GridRow};
use crate::ui::kit::{self, J as _};
use crate::ui::{self, FButton, Kind};

#[derive(Default)]
struct Investigation {
    running: bool,
    read: Vec<String>,
    result: Option<Value>,
    message: Option<String>,
    show_calls: bool,
}

pub struct FindingsPage {
    ctx: Ctx,
    table: Entity<TableState<Grid>>,
    search: Entity<InputState>,
    verdicts: BTreeMap<&'static str, bool>,
    kind: String,
    show_ignored: bool,
    only_new: bool,
    ids: Option<(Vec<String>, String)>,
    /// The finding the details show, and its planned actions.
    current: Option<String>,
    plans: Vec<Value>,
    /// The report's items, copied once per report revision (not every frame).
    items: (u64, std::sync::Arc<Vec<Value>>),
    copied: bool,
    investigation: Investigation,
    acting: Acting,
    /// The Export menu's "replace names" choice.
    export_anonymize: bool,
    /// The last export: how it went and, when it was saved, the file.
    export_note: Option<(ui::Severity, String, Option<String>)>,
    focus: FocusHandle,
    _subscriptions: Vec<Subscription>,
}

impl Acts for FindingsPage {
    fn acting(&mut self) -> &mut Acting {
        &mut self.acting
    }
    fn core(&self) -> Option<Arc<AppState>> {
        self.ctx.core.clone()
    }
    fn after(&mut self, _: &mut Window, cx: &mut Context<Self>) {
        let core = self.ctx.core.clone();
        self.ctx.report.update(cx, |_, cx| Report::reload(core, cx));
    }
}

fn presence(item: &Value) -> String {
    let roles = item.a("roles");
    let running = roles.iter().any(|r| r.s("kind") == "process");
    let autostart = roles.iter().any(|r| r.b("persistent") && r.b("active"));
    match (running, autostart) {
        (true, true) => t("findings.runningAutostart"),
        (true, false) => t("findings.running"),
        (false, true) => t("findings.autostart"),
        _ => String::new(),
    }
}

impl FindingsPage {
    pub fn new(ctx: Ctx, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let cols = vec![
            GridCol::new("verdict", t("findings.verdict"), 150.),
            GridCol::new("score", t("findings.score"), 80.).numeric(),
            GridCol::new("name", t("findings.name"), 300.),
            GridCol::new("type", t("findings.type"), 110.),
            GridCol::new("presence", t("findings.presence"), 150.),
        ];
        let empty = if ctx.report.read(cx).analysis.is_some() {
            t("findings.select")
        } else {
            t("findings.runScan")
        };
        let table = grid::new_state(empty, cols, window, cx);
        let (search, searching) = grid::search(&table, t("findings.search"), window, cx);
        let verdicts = VERDICT_ORDER.iter().map(|v| (*v, *v != "trusted")).collect();
        let subscriptions = vec![
            searching,
            cx.observe(&table, |this, _, cx| this.selection_changed(cx)),
            cx.observe(&ctx.report, |this, _, cx| {
                this.fill(cx);
                this.load_plans(cx);
            }),
        ];
        let mut page = Self {
            ctx,
            table,
            search,
            verdicts,
            kind: String::new(),
            show_ignored: false,
            only_new: false,
            ids: None,
            current: None,
            plans: Vec::new(),
            items: (u64::MAX, std::sync::Arc::new(Vec::new())),
            copied: false,
            investigation: Investigation::default(),
            acting: Acting::default(),
            export_anonymize: false,
            export_note: None,
            focus: cx.focus_handle(),
            _subscriptions: subscriptions,
        };
        let focus = page.ctx.report.update(cx, |r, _| r.focus.take());
        let mut first = None;
        match focus {
            Some(Focus::Items(ids, caption)) => {
                first = ids.first().cloned();
                page.ids = Some((ids, caption));
            }
            Some(Focus::Item(id)) => {
                if let Some(v) = page.item(&id, cx).map(|i| i.s("verdict").to_string())
                    && let Some(key) = VERDICT_ORDER.iter().find(|k| **k == v)
                {
                    page.verdicts.insert(key, true);
                }
                first = Some(id);
            }
            Some(Focus::Verdict(v)) => {
                for (key, on) in page.verdicts.iter_mut() {
                    *on = *key == v;
                }
            }
            None => {}
        }
        window.focus(&page.focus, cx);
        page.fill(cx);
        if first.is_some() {
            grid::select(&page.table, first, cx);
            page.selection_changed(cx);
        }
        page
    }

    /// "Export": the loaded report's findings (or the page) as a file the user names. The report
    /// is read-only here; only the chosen file is written.
    fn export(&mut self, format: Format, window: &mut Window, cx: &mut Context<Self>) {
        // The demo changes nothing on the computer, not even a file the person names.
        if self.ctx.demo() {
            self.export_note = Some((ui::Severity::Info, t("app.demoNoActions"), None));
            cx.notify();
            return;
        }
        let Some(report) = self.ctx.report.read(cx).analysis.clone() else {
            self.export_note = Some((ui::Severity::Info, t("findings.runScan"), None));
            cx.notify();
            return;
        };
        let options = vigil_core::export::Options {
            anonymize: self.export_anonymize,
            include_trusted: false,
        };
        let name = vigil_core::export::suggested_name(&report, format);
        let documents = std::env::var_os("USERPROFILE")
            .map(|p| std::path::PathBuf::from(p).join("Documents"))
            .unwrap_or_default();
        let picked = cx.prompt_for_new_path(&documents, Some(&name));
        cx.spawn_in(window, async move |this, cx| {
            let Ok(Ok(Some(path))) = picked.await else { return };
            let shown = path.display().to_string();
            let written = cx
                .background_spawn(async move {
                    let bytes = vigil_core::export::render_report(&report, format, options);
                    vigil_core::export::write_user_file(&path, &bytes)
                })
                .await;
            let _ = this.update(cx, |page, cx| {
                page.export_note = Some(match written {
                    Ok(()) => {
                        let key = if options.anonymize {
                            "findings.exportedAnonymized"
                        } else {
                            "findings.exported"
                        };
                        (ui::Severity::Success, tf(key, &[("path", &shown)]), Some(shown))
                    }
                    Err(error) => (
                        ui::Severity::Error,
                        tf("findings.exportFailed", &[("error", &error.to_string())]),
                        None,
                    ),
                });
                cx.notify();
            });
        })
        .detach();
    }

    /// The Export menu button.
    fn export_menu(&self, has_report: bool, cx: &mut Context<Self>) -> impl IntoElement {
        let weak = cx.entity().downgrade();
        let anonymize = self.export_anonymize;
        FButton::new("fi-export", Kind::Standard)
            .glyph(icons::EXPORT)
            .label(t("findings.export"))
            .chevron()
            .disabled(!has_report)
            .dropdown_menu(move |menu, _, _| {
                let pick = |label: String, format: Format| {
                    let weak = weak.clone();
                    PopupMenuItem::new(label).on_click(move |_, window, cx| {
                        let _ = weak.update(cx, |this, cx| this.export(format, window, cx));
                    })
                };
                let toggle = {
                    let weak = weak.clone();
                    PopupMenuItem::new(t("findings.exportAnonymize"))
                        .checked(anonymize)
                        .on_click(move |_, _, cx| {
                            let _ = weak.update(cx, |this, cx| {
                                this.export_anonymize = !this.export_anonymize;
                                cx.notify();
                            });
                        })
                };
                menu.item(pick(t("findings.exportCsv"), Format::Csv))
                    .item(pick(t("findings.exportSarif"), Format::Sarif))
                    .item(pick(t("findings.exportHtml"), Format::Html))
                    .separator()
                    .item(toggle)
            })
    }

    /// The result of the last export, with "Open folder" when a file was saved.
    fn export_bar(&self, cx: &mut Context<Self>) -> Option<Div> {
        let tk = *tokens(cx);
        let (severity, message, path) = self.export_note.clone()?;
        let weak = cx.entity().downgrade();
        let close: ui::OnClose = Box::new(move |_, cx| {
            let _ = weak.update(cx, |this, cx| {
                this.export_note = None;
                cx.notify();
            });
        });
        let mut row =
            kit::row().child(
                div()
                    .flex_1()
                    .child(ui::info_bar("fi-export-note", severity, message, Some(close), &tk)),
            );
        if let Some(path) = path.filter(|_| self.ctx.core.is_some()) {
            let weak = cx.entity().downgrade();
            row = row.child(
                FButton::new("fi-export-folder", Kind::Standard)
                    .glyph(icons::FOLDER)
                    .label(t("findings.exportOpenFolder"))
                    .on_click(move |_, window, cx| {
                        let path = path.clone();
                        let _ = weak.update(cx, |this, cx| {
                            let request = vigil_core::requests::Request::Shell {
                                op: "location".into(),
                                path: Some(path),
                                url: None,
                                name: None,
                            };
                            common::send(this, request, window, cx);
                        });
                    }),
            );
        }
        Some(row)
    }

    fn item(&self, id: &str, cx: &gpui_kit::App) -> Option<Value> {
        let report = self.ctx.report.read(cx);
        report
            .analysis
            .as_ref()
            .and_then(|a| a.a("items").iter().find(|i| i.s("id") == id).cloned())
    }

    fn new_ids(&self, cx: &gpui_kit::App) -> Vec<String> {
        let report = self.ctx.report.read(cx);
        report
            .analysis
            .as_ref()
            .map(|a| a.at("changes").strs("new").into_iter().map(str::to_string).collect())
            .unwrap_or_default()
    }

    fn fill(&mut self, cx: &mut Context<Self>) {
        let report = self.ctx.report.read(cx);
        let Some(analysis) = report.analysis.clone() else {
            grid::fill(&self.table, Vec::new(), cx);
            return;
        };
        let ignored = report.ignored.clone();
        let tk = *tokens(cx);
        let changes = analysis.at("changes");
        let new_ids = changes.strs("new");
        let changed: Vec<&str> = changes.a("changed").iter().map(|c| c.s("id")).collect();
        let mut items: Vec<&Value> = analysis
            .a("items")
            .iter()
            .filter(|i| {
                let id = i.s("id");
                if let Some((ids, _)) = &self.ids {
                    return ids.iter().any(|x| x == id);
                }
                let shown = if self.only_new {
                    new_ids.contains(&id)
                } else {
                    self.verdicts.get(i.s("verdict")).copied().unwrap_or(true)
                };
                shown
                    && (self.kind.is_empty() || i.s("kind") == self.kind)
                    && (self.show_ignored || !ignored.iter().any(|x| x == id))
            })
            .collect();
        items.sort_by(|a, b| crate::pages::labels::by_verdict(a, b));
        let rows = items
            .into_iter()
            .map(|i| {
                let id = i.s("id");
                let verdict = i.s("verdict");
                let mut label = verdict_label(verdict);
                // The AI review can set a verdict the local score alone wouldn't ("Remove" at 0):
                // the list says where the verdict came from.
                if i.s("verdict_source") == "ai" {
                    label = format!("{label} · {}", t("findings.byAi"));
                }
                if i.a("actions_taken").iter().any(|a| a.b("ok")) {
                    label = format!("{label} · {}", t("findings.handled"));
                }
                if ignored.iter().any(|x| x == id) {
                    label = format!("{label} · {}", t("findings.ignored"));
                }
                let mut name = i.s("title").to_string();
                if new_ids.contains(&id) {
                    name = format!("{name}  [{}]", t("findings.badgeNew"));
                } else if changed.contains(&id) {
                    name = format!("{name}  [{}]", t("findings.badgeChanged"));
                }
                let score = i.n("score");
                let score_color = if score >= 70.0 {
                    tk.verdict_remove
                } else if score >= 40.0 {
                    tk.verdict_disable
                } else if score >= 15.0 {
                    tk.verdict_review
                } else {
                    tk.verdict_no_signals
                };
                let roles: Vec<&str> = i.a("roles").iter().map(|r| r.s("label")).collect();
                let search = format!(
                    "{} {} {} {} {} {} {} {id}",
                    i.s("title"),
                    i.s("subtitle"),
                    i.s("path"),
                    i.s("what"),
                    i.s("reason"),
                    i.strs("commands").join(" "),
                    roles.join(" ")
                );
                let cells = vec![
                    GridCell::text(label)
                        .ranked(verdict_rank(verdict) as f64 * 1000.0 - score)
                        .color(tk.verdict(verdict))
                        .glyph('\u{E91F}', tk.verdict(verdict)),
                    GridCell::num(crate::format::num(score, 0), score).color(score_color),
                    GridCell::text(name),
                    GridCell::text(kind_label(i.s("kind"))),
                    GridCell::text(presence(i)),
                ];
                let mut row = GridRow::new(id.to_string(), cells, search);
                row.cells[0].strong = true;
                row
            })
            .collect();
        grid::fill(&self.table, rows, cx);
    }

    fn selection_changed(&mut self, cx: &mut Context<Self>) {
        let selected = grid::selected(&self.table, cx);
        if selected != self.current {
            self.current = selected;
            self.plans.clear();
            self.copied = false;
            self.investigation = Investigation::default();
            self.acting = Acting::default();
            self.load_plans(cx);
        }
        cx.notify();
    }

    fn load_plans(&mut self, cx: &mut Context<Self>) {
        let Some(id) = self.current.clone() else { return };
        let core = self.ctx.core.clone();
        let asked = id.clone();
        common::read(
            cx,
            move || data::fetch(core.as_ref(), Src::Plans(asked)),
            move |this: &mut Self, plans, _| {
                if this.current.as_deref() == Some(id.as_str()) {
                    this.plans = plans.ok().and_then(|p| p.as_array().cloned()).unwrap_or_default();
                }
            },
        );
    }

    /// Asks for action `index` of the selected finding, naming the op and target the page shows:
    /// the core refuses it if the report changed meanwhile.
    fn act(&mut self, index: usize, window: &mut Window, cx: &mut Context<Self>) {
        let Some(id) = self.current.clone() else { return };
        let Some(spec) = self.plans.get(index) else { return };
        let (op, target) = (spec.s("op").to_string(), spec.s("target").to_string());
        common::send_json(
            self,
            json!({"kind": "finding", "itemId": id, "index": index, "op": op, "target": target}),
            window,
            cx,
        );
    }

    fn toggle_ignored(&mut self, cx: &mut Context<Self>) {
        let Some(id) = self.current.clone() else { return };
        let value = !self.ctx.report.read(cx).is_ignored(&id);
        let result = match &self.ctx.core {
            Some(core) => vigil_core::api::ignored_set(core, &id, value),
            None => {
                let mut ids = self.ctx.report.read(cx).ignored.clone();
                ids.retain(|x| *x != id);
                if value {
                    ids.push(id);
                }
                Ok(ids)
            }
        };
        match result {
            Ok(ids) => self.ctx.report.update(cx, |r, cx| {
                r.ignored = ids;
                cx.notify();
            }),
            Err(error) => {
                self.acting.outcome = Some(crate::actions::Outcome::Failed(error));
                cx.notify();
            }
        }
    }

    fn copy(&mut self, item: &Value, cx: &mut Context<Self>) {
        let mut lines = vec![
            format!("{} [{}]", item.s("title"), verdict_label(item.s("verdict"))),
            item.s("subtitle").to_string(),
        ];
        for (key, field) in [
            ("detail.what", "what"),
            ("detail.why", "reason"),
            ("detail.recommendation", "action"),
            ("detail.path", "path"),
        ] {
            if item.has(field) {
                lines.push(format!("{}: {}", t(key), item.s(field)));
            }
        }
        if item.has("sha256") {
            lines.push(format!("SHA-256: {}", item.s("sha256")));
        }
        let signals: Vec<&str> = item
            .a("flags")
            .iter()
            .filter(|f| f.n("weight") > 0.0)
            .map(|f| f.s("text"))
            .collect();
        if !signals.is_empty() {
            lines.push(format!("{}: {}", t("detail.signals"), signals.join("; ")));
        }
        for role in item.a("roles") {
            lines.push(format!("- {}", role.s("label")));
        }
        for command in item.strs("commands") {
            lines.push(format!("> {command}"));
        }
        lines.retain(|l| !l.is_empty());
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

    fn investigate(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(id) = self.current.clone() else { return };
        self.investigation = Investigation {
            running: true,
            ..Investigation::default()
        };
        cx.notify();
        let (tx, mut rx) = mpsc::unbounded::<String>();
        let done = match self.ctx.core.clone() {
            Some(core) => crate::actions::investigate(core, id.clone(), crate::win::hwnd(window), tx),
            None => {
                let (done_tx, done_rx) = futures::channel::oneshot::channel();
                std::thread::spawn(move || {
                    for line in ["read_item (2.1 KB)", "file_info (840 B)", "startup_entries (3.4 KB)"] {
                        let _ = tx.unbounded_send(line.to_string());
                        std::thread::sleep(std::time::Duration::from_millis(500));
                    }
                    let _ = done_tx.send(Ok(Some(data::demo("investigation"))));
                });
                done_rx
            }
        };
        cx.spawn(async move |this, cx| {
            let follow = this.clone();
            let mut cx2 = cx.clone();
            let progress = async move {
                while let Some(line) = rx.next().await {
                    let _ = follow.update(&mut cx2, |page, cx| {
                        let inv = &mut page.investigation;
                        if inv.running {
                            if inv.read.len() >= 8 {
                                inv.read.remove(0);
                            }
                            inv.read.push(line);
                            cx.notify();
                        }
                    });
                }
            };
            let (result, ()) = futures::join!(done, progress);
            let _ = this.update(cx, |page, cx| {
                if page.current.as_deref() != Some(id.as_str()) {
                    return;
                }
                let inv = &mut page.investigation;
                inv.running = false;
                match result {
                    Ok(Ok(Some(view))) => inv.result = Some(view),
                    Ok(Ok(None)) => inv.message = Some(t("investigate.notStarted")),
                    Ok(Err(error)) => inv.message = Some(tf("investigate.error", &[("error", &error)])),
                    Err(_) => inv.message = Some(t("investigate.notStarted")),
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn detail(&self, item: &Value, cx: &mut Context<Self>) -> Div {
        let tk = *tokens(cx);
        let ignored = self.ctx.report.read(cx).is_ignored(item.s("id"));
        let changes = self
            .ctx
            .report
            .read(cx)
            .analysis
            .as_ref()
            .map(|a| a.at("changes").clone())
            .unwrap_or(Value::Null);
        let id = item.s("id");
        let since: Option<(bool, Vec<String>)> = if changes.strs("new").contains(&id) {
            Some((true, Vec::new()))
        } else {
            changes
                .a("changed")
                .iter()
                .find(|c| c.s("id") == id)
                .map(|c| (false, c.strs("what").into_iter().map(str::to_string).collect()))
        };
        let verdict = item.s("verdict");
        let mut pane = div()
            .flex()
            .flex_col()
            .gap_2()
            .child(kit::h2(item.s("title").to_string()));
        if item.has("subtitle") && item.s("subtitle") != item.s("title") {
            pane = pane.child(kit::muted(item.s("subtitle").to_string(), &tk));
        }
        let source = match item.s("verdict_source") {
            "ai" => t("detail.sourceAi"),
            "heuristic" | "" => t("detail.sourceRules"),
            "automatic" => t("detail.sourceAuto"),
            other => other.to_string(),
        };
        let mut pills = kit::row()
            .child(kit::pill(verdict_label(verdict), tk.verdict(verdict), true, &tk))
            .child(kit::pill(kind_label(item.s("kind")), tk.ink2, false, &tk))
            .child(kit::pill(source, tk.ink3, false, &tk));
        if item.has("confidence") {
            let key = match item.s("confidence") {
                "high" => "detail.confidenceHigh",
                "low" => "detail.confidenceLow",
                _ => "detail.confidenceMedium",
            };
            pills = pills.child(kit::pill(t(key), tk.ink3, false, &tk));
        }
        if item.has("score") {
            pills = pills.child(kit::pill(
                tf("detail.score", &[("score", &kit::text(item.at("score")))]),
                tk.ink3,
                false,
                &tk,
            ));
        }
        pane = pane.child(pills);
        if item.s("verdict_source") == "ai" && item.has("score") {
            let score = item.n("score");
            let shown = crate::format::num(score, 0);
            let key = if score < 15.0 {
                "detail.aiOverrideLittle"
            } else {
                "detail.aiOverride"
            };
            pane = pane.child(kit::muted(
                tf(key, &[("verdict", &verdict_label(verdict)), ("score", &shown)]),
                &tk,
            ));
        }
        if item.has("what") {
            pane = pane.child(kit::sel("fd-what", item.s("what").to_string()).text_size(px(13.)));
        }
        for (key, field, sid) in [
            ("detail.why", "reason", "fd-why"),
            ("detail.recommendation", "action", "fd-action"),
        ] {
            if item.has(field) {
                pane = pane
                    .child(kit::h4(t(key), &tk))
                    .child(kit::sel(sid, item.s(field).to_string()).text_size(px(13.)));
            }
        }
        if let Some((is_new, what)) = since {
            pane = pane.child(kit::h4(t("detail.since"), &tk));
            if is_new {
                pane = pane.child(kit::muted(t("detail.sinceNew"), &tk));
            }
            pane = pane.children(what.into_iter().map(|w| kit::body(format!("• {w}"))));
        }

        // Actions.
        let busy = self.acting.busy;
        let elevated = self.ctx.elevated;
        if !self.plans.is_empty() || !item.b("trusted") {
            pane = pane.child(kit::h4(t("detail.actions"), &tk));
            if !elevated && self.plans.iter().any(|s| s.b("admin")) {
                pane = pane.child(kit::faint(t("detail.needsAdmin"), &tk));
            }
            for (index, spec) in self.plans.iter().enumerate() {
                if spec.a("steps").is_empty() {
                    continue;
                }
                let disabled = busy || (spec.b("admin") && !elevated);
                pane = pane
                    .child(
                        div().flex().child(
                            ui::accent_button(
                                ElementId::NamedInteger("fd-plan".into(), index as u64),
                                spec.s("label").to_string(),
                            )
                            .disabled(disabled)
                            .tip(spec.s("explain").to_string())
                            .on_click(cx.listener(move |this, _, window, cx| this.act(index, window, cx))),
                        ),
                    )
                    .child(kit::faint(spec.s("explain").to_string(), &tk));
            }
            for (group, caption) in [
                ("contain", "detail.groupContain"),
                ("disable", "detail.groupDisable"),
                ("remove", "detail.groupRemove"),
                ("fix", "detail.groupFix"),
                ("inspect", "detail.groupInspect"),
            ] {
                let members: Vec<(usize, &Value)> = self
                    .plans
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| s.s("group") == group && s.a("steps").is_empty())
                    .collect();
                if members.is_empty() && group != "inspect" {
                    continue;
                }
                let mut buttons = kit::row().flex_1();
                for (index, spec) in members {
                    let mut tip = spec.s("explain").to_string();
                    if !spec.b("reversible") {
                        tip = format!("{tip}  {}", t("detail.cannotUndo"));
                    }
                    buttons = buttons.child(
                        ui::button(
                            ElementId::NamedInteger("fd-act".into(), index as u64),
                            spec.s("label").to_string(),
                        )
                        .danger(spec.b("destructive"))
                        .disabled(busy || (spec.b("admin") && !elevated))
                        .tip(tip)
                        .on_click(cx.listener(move |this, _, window, cx| this.act(index, window, cx))),
                    );
                }
                if group == "inspect" {
                    let copy_item = item.clone();
                    buttons = buttons
                        .child(
                            ui::button(
                                "fd-ignore",
                                t(if ignored { "detail.unignore" } else { "detail.ignore" }),
                            )
                            .on_click(cx.listener(|this, _, _, cx| this.toggle_ignored(cx))),
                        )
                        .child(
                            ui::button("fd-copy", t(if self.copied { "common.copied" } else { "detail.copy" }))
                                .on_click(cx.listener(move |this, _, _, cx| this.copy(&copy_item, cx))),
                        );
                }
                pane = pane.child(
                    div()
                        .flex()
                        .gap_2()
                        .items_start()
                        .child(
                            div()
                                .w(px(84.))
                                .flex_none()
                                .pt(px(6.))
                                .text_size(px(12.))
                                .text_color(tk.ink3)
                                .child(t(caption)),
                        )
                        .child(buttons),
                );
            }
            pane = pane.children(self.acting.bar("fd-result", &tk));
        }
        let taken = item.a("actions_taken");
        if !taken.is_empty() {
            pane = pane.child(kit::h4(t("detail.alreadyDone"), &tk));
            for a in taken.iter().rev().take(12).collect::<Vec<_>>().into_iter().rev() {
                let state = t(if a.b("ok") { "detail.done" } else { "detail.failed" });
                pane = pane.child(kit::muted(
                    format!("{state} · {} · {}", a.s("label"), when(a.s("time"))),
                    &tk,
                ));
                if a.has("message") {
                    pane = pane.child(kit::faint(a.s("message").to_string(), &tk));
                }
            }
        }
        let mut flags: Vec<&Value> = item.a("flags").iter().filter(|f| f.n("weight") > 0.0).collect();
        flags.sort_by(|a, b| b.n("weight").total_cmp(&a.n("weight")));
        if !flags.is_empty() {
            pane = pane
                .child(kit::h4(t("detail.signals"), &tk))
                .children(flags.iter().map(|f| {
                    div()
                        .flex()
                        .gap_2()
                        .text_size(px(13.))
                        .child(
                            div()
                                .w(px(36.))
                                .flex_none()
                                .flex()
                                .justify_end()
                                .text_color(tk.ink3)
                                .child(format!("+{}", kit::text(f.at("weight")))),
                        )
                        .child(div().flex_1().child(kit::plain(f.s("text").to_string())))
                }));
        }
        let roles = item.a("roles");
        if !roles.is_empty() {
            pane = pane
                .child(kit::h4(t("detail.where"), &tk))
                .children(roles.iter().take(24).map(|r| kit::body(format!("• {}", r.s("label")))));
        }
        let file = item.at("file");
        if item.has("path") || file.is_object() {
            pane = pane.child(kit::h4(t("detail.file"), &tk));
            if item.has("path") {
                pane = pane.child(kit::code("fd-path", item.s("path").to_string(), &tk));
            }
            let mut facts: Vec<(String, String)> = Vec::new();
            if file.is_object() {
                facts.push((t("detail.signature"), signature(file)));
                for (key, field) in [
                    ("detail.publisher", "company"),
                    ("detail.description", "description"),
                    ("detail.product", "product"),
                    ("detail.version", "version"),
                    ("detail.originalName", "original"),
                ] {
                    facts.push((t(key), file.s(field).to_string()));
                }
                if file.has("size") {
                    facts.push((
                        t("detail.size"),
                        tf("unit.bytes", &[("n", &crate::format::num(file.n("size"), 0))]),
                    ));
                }
                facts.push((t("detail.created"), file.s("created").to_string()));
                facts.push((t("detail.modified"), file.s("modified").to_string()));
            }
            facts.push(("SHA-256".into(), item.s("sha256").to_string()));
            facts.push(("VirusTotal".into(), item.at("vt").s("summary").to_string()));
            for (i, (label, value)) in facts.into_iter().filter(|(_, v)| !v.is_empty()).enumerate() {
                pane = pane.child(kit::kv_text(
                    ElementId::NamedInteger("fd-fact".into(), i as u64),
                    label,
                    value,
                    false,
                    130.,
                    &tk,
                ));
            }
        }
        let commands = item.strs("commands");
        if !commands.is_empty() {
            pane = pane.child(kit::h4(tn("detail.commandLines", commands.len() as u64, &[]), &tk));
            for (i, c) in commands.iter().enumerate() {
                pane = pane.child(kit::code(
                    ElementId::NamedInteger("fd-cmd".into(), i as u64),
                    c.to_string(),
                    &tk,
                ));
            }
        }
        for (i, d) in item.a("decoded").iter().enumerate() {
            pane = pane.child(kit::h4(t("detail.decoded"), &tk)).child(kit::code(
                ElementId::NamedInteger("fd-dec".into(), i as u64),
                kit::text(d),
                &tk,
            ));
        }
        let network = item.at("network");
        if network.as_object().is_some_and(|o| !o.is_empty()) {
            pane = pane.child(kit::h4(t("detail.network"), &tk));
            let mut connected = network.strs("remote").join(", ");
            let more = network.n("remote_total") as usize;
            if more > network.a("remote").len() {
                connected = format!(
                    "{connected} {}",
                    tn("detail.more", (more - network.a("remote").len()) as u64, &[])
                );
            }
            for (i, (key, value)) in [
                ("detail.listening", network.strs("listen").join(", ")),
                ("detail.reachable", network.strs("exposed").join(", ")),
                ("detail.connected", connected.trim().to_string()),
            ]
            .into_iter()
            .filter(|(_, v)| !v.is_empty())
            .enumerate()
            {
                pane = pane.child(kit::kv_text(
                    ElementId::NamedInteger("fd-net".into(), i as u64),
                    t(key),
                    value,
                    true,
                    130.,
                    &tk,
                ));
            }
        }
        let members = item.a("members");
        if !members.is_empty() {
            pane = pane
                .child(kit::h4(tn("detail.components", members.len() as u64, &[]), &tk))
                .children(members.iter().take(60).map(|m| {
                    div()
                        .flex()
                        .flex_col()
                        .child(kit::body(m.s("name").to_string()).font_weight(FontWeight::SEMIBOLD))
                        .child(kit::faint(m.s("path").to_string(), &tk))
                }));
        }
        let facts: Vec<(String, String)> = item
            .at("facts")
            .as_object()
            .map(|o| {
                o.iter()
                    .filter(|(k, v)| {
                        !matches!(k.as_str(), "topic" | "uninstall" | "registry_key" | "folder") && kit::truthy(v)
                    })
                    .take(24)
                    .map(|(k, v)| (kit::humanize(k), show(v)))
                    .collect()
            })
            .unwrap_or_default();
        if !facts.is_empty() {
            pane = pane.child(kit::h4(t("detail.details"), &tk));
            for (i, (k, v)) in facts.into_iter().enumerate() {
                pane = pane.child(kit::kv_text(
                    ElementId::NamedInteger("fd-x".into(), i as u64),
                    k,
                    v,
                    false,
                    130.,
                    &tk,
                ));
            }
        }
        let steps: Vec<&Value> = item
            .a("remediation")
            .iter()
            .filter(|s| s.has("note") || s.has("command"))
            .take(10)
            .collect();
        if !steps.is_empty() {
            pane = pane.child(kit::h4(t("detail.manual"), &tk));
            for (i, s) in steps.into_iter().enumerate() {
                pane = pane.child(kit::body(s.s("title").to_string()));
                if s.has("command") {
                    pane = pane.child(kit::code(
                        ElementId::NamedInteger("fd-rm".into(), i as u64),
                        s.s("command").to_string(),
                        &tk,
                    ));
                }
                if s.has("note") {
                    pane = pane.child(kit::faint(s.s("note").to_string(), &tk));
                }
            }
        }
        pane
    }

    fn investigation(&self, cx: &mut Context<Self>) -> Div {
        let tk = *tokens(cx);
        let inv = &self.investigation;
        let mut pane = div()
            .flex()
            .flex_col()
            .gap_2()
            .pt_3()
            .mt_2()
            .border_t_1()
            .border_color(tk.rule);
        if inv.running {
            pane = pane
                .child(
                    kit::row()
                        .child(kit::body(t("investigate.running")))
                        .child(div().flex_1())
                        .child(
                            ui::button("inv-stop", t("investigate.stop"))
                                .glyph(icons::CANCEL)
                                .on_click(|_, _, _| vigil_core::investigate::cancel()),
                        ),
                )
                .child(kit::busy_bar("inv-busy", &tk))
                .children(
                    inv.read.iter().map(|line| {
                        kit::faint(tf("investigate.reading", &[("tool", line)]), &tk).font_family(FONT_MONO)
                    }),
                );
            return pane;
        }
        let Some(result) = &inv.result else {
            return pane
                .child(
                    div().flex().child(
                        ui::accent_button("inv-start", t("investigate.button"))
                            .glyph(icons::SEARCH)
                            .on_click(cx.listener(|this, _, window, cx| this.investigate(window, cx))),
                    ),
                )
                .child(kit::faint(t("investigate.note"), &tk))
                .children(inv.message.clone().map(|m| kit::muted(m, &tk)));
        };
        let verdict = result.s("verdict");
        let conf = t(&format!("investigate.conf.{}", result.s("confidence")));
        pane = pane
            .child(kit::h3(t("investigate.title")))
            .child(
                kit::row()
                    .child(
                        div()
                            .pl_2()
                            .border_l_4()
                            .border_color(tk.verdict(verdict))
                            .text_color(tk.verdict(verdict))
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(verdict_label(verdict)),
                    )
                    .child(kit::faint(tf("investigate.confidence", &[("level", &conf)]), &tk)),
            )
            .when(result.has("guardNote"), |this| {
                this.child(kit::colored(result.s("guardNote").to_string(), tk.warn))
            })
            .child(kit::sel("inv-conclusion", result.s("conclusion").to_string()).text_size(px(13.)));
        let evidence = result.a("evidence");
        if !evidence.is_empty() {
            pane = pane.child(kit::h4(t("investigate.evidence"), &tk));
            for (i, e) in evidence.iter().enumerate() {
                pane = pane.child(kit::body(format!("• {}", e.s("text"))));
                if e.has("page") {
                    let page = e.s("page").to_string();
                    let ctx = self.ctx.clone();
                    pane = pane.child(kit::link(
                        ElementId::NamedInteger("inv-ev".into(), i as u64),
                        tf("investigate.open", &[("page", &t(&format!("page.{page}")))]),
                        move |window, cx| ctx.go(&page, window, cx),
                        &tk,
                    ));
                }
            }
        }
        if result.has("suggestedAction") {
            pane = pane
                .child(kit::h4(t("investigate.suggested"), &tk))
                .child(kit::body(result.s("suggestedAction").to_string()))
                .child(kit::faint(t("investigate.suggestedNote"), &tk));
        }
        let questions = result.strs("openQuestions");
        if !questions.is_empty() {
            pane = pane
                .child(kit::h4(t("investigate.questions"), &tk))
                .children(questions.iter().map(|q| kit::body(format!("• {q}"))));
        }
        pane = pane.child(kit::faint(
            tf("investigate.destination", &[("destination", result.s("destination"))]),
            &tk,
        ));
        if result.b("local") {
            pane = pane.child(kit::faint(t("investigate.local"), &tk));
        }
        if result.b("anonymized") {
            pane = pane.child(kit::faint(t("investigate.anonymized"), &tk));
        }
        if result.has("limit") {
            pane = pane.child(kit::faint(
                tf("investigate.limit", &[("limit", &kit::text(result.at("limit")))]),
                &tk,
            ));
        }
        let calls = result.a("calls");
        let open = inv.show_calls;
        pane = pane.child(
            ui::button("inv-calls", tn("investigate.calls", calls.len() as u64, &[]))
                .glyph(if open {
                    icons::CHEVRON_DOWN
                } else {
                    icons::CHEVRON_RIGHT
                })
                .on_click(cx.listener(|this, _, _, cx| {
                    this.investigation.show_calls = !this.investigation.show_calls;
                    cx.notify();
                })),
        );
        if open {
            for c in calls {
                let bytes = c.n("bytes");
                let size = if bytes >= 1024.0 {
                    format!("{:.1} KB", bytes / 1024.0)
                } else {
                    format!("{bytes} B")
                };
                let mut meta = format!("{size} · {} ms", kit::text(c.at("ms")));
                if !c.b("ok") {
                    meta = format!("{meta} · {}", t("investigate.failedCall"));
                }
                pane = pane.child(
                    div()
                        .flex()
                        .gap_2()
                        .text_size(px(12.))
                        .child(kit::mono(c.s("name").to_string()).when(!c.b("ok"), |this| this.text_color(tk.warn)))
                        .child(
                            kit::mono(c.at("input").to_string())
                                .flex_1()
                                .min_w_0()
                                .overflow_hidden()
                                .text_ellipsis()
                                .whitespace_nowrap()
                                .text_color(tk.ink3),
                        )
                        .child(kit::faint(meta, &tk)),
                );
            }
        }
        pane.child(
            div().flex().child(
                ui::button("inv-again", t("investigate.button"))
                    .glyph(icons::REFRESH)
                    .on_click(cx.listener(|this, _, window, cx| this.investigate(window, cx))),
            ),
        )
    }
}

/// A file's signature in words.
fn signature(file: &Value) -> String {
    if file.at("exists").as_bool() == Some(false) {
        return t("detail.sigMissing");
    }
    let status = file.s("sig_status");
    let key = match status {
        "Valid" => "detail.sigValid",
        "NotSigned" => "detail.sigNotSigned",
        "HashMismatch" => "detail.sigBroken",
        "NotTrusted" => "detail.sigUntrusted",
        "UnknownError" => "detail.sigUnknown",
        "" => return String::new(),
        other => return other.to_string(),
    };
    let mut text = t(key);
    if !matches!(status, "NotSigned" | "HashMismatch") && file.has("signer") {
        text = format!("{text} · {}", file.s("signer"));
    }
    text
}

/// A fact's value as text, cut to 600 characters.
fn show(v: &Value) -> String {
    let text = match v {
        Value::Array(items) => items
            .iter()
            .take(20)
            .map(|i| match i.as_object() {
                Some(o) => o
                    .iter()
                    .map(|(k, v)| format!("{k}: {}", kit::text(v)))
                    .collect::<Vec<_>>()
                    .join(", "),
                None => kit::text(i),
            })
            .collect::<Vec<_>>()
            .join(", "),
        Value::Object(o) => o
            .iter()
            .take(12)
            .map(|(k, v)| format!("{k}: {}", kit::text(v)))
            .collect::<Vec<_>>()
            .join("; "),
        other => kit::text(other),
    };
    text.chars().take(600).collect()
}

impl Render for FindingsPage {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let report = self.ctx.report.read(cx);
        let has_report = report.analysis.is_some();
        // A report the tray copy saved where any program can change it: shown to read only.
        let view_only = report.analysis.as_ref().is_some_and(|a| a.b("viewOnly"));
        if self.items.0 != report.revision {
            let items = report
                .analysis
                .as_ref()
                .map(|a| a.a("items").to_vec())
                .unwrap_or_default();
            self.items = (report.revision, std::sync::Arc::new(items));
        }
        let all = std::sync::Arc::clone(&self.items.1);
        let ignored = report.ignored.clone();
        let counted: Vec<&Value> = all
            .iter()
            .filter(|i| self.show_ignored || !ignored.iter().any(|x| x == i.s("id")))
            .collect();
        let new_ids = self.new_ids(cx);
        let new_count = all.iter().filter(|i| new_ids.iter().any(|x| x == i.s("id"))).count();
        let shown = self.table.read(cx).delegate().row_count();

        let mut chips = kit::row();
        for v in VERDICT_ORDER {
            let n = counted.iter().filter(|i| i.s("verdict") == v).count();
            let on = self.verdicts.get(v).copied().unwrap_or(false) && self.ids.is_none() && !self.only_new;
            let weak = cx.entity().downgrade();
            chips = chips.child(kit::chip(
                ElementId::Name(format!("fi-chip-{v}").into()),
                verdict_label(v),
                Some(n),
                on,
                false,
                move |_, cx| {
                    let _ = weak.update(cx, |this, cx| {
                        this.ids = None;
                        this.only_new = false;
                        if let Some(state) = this.verdicts.get_mut(v) {
                            *state = !*state;
                        }
                        this.fill(cx);
                    });
                },
                &tk,
            ));
        }
        if !new_ids.is_empty() {
            let weak = cx.entity().downgrade();
            chips = chips.child(kit::chip(
                "fi-chip-new",
                t("findings.newSince"),
                Some(new_count),
                self.only_new && self.ids.is_none(),
                false,
                move |_, cx| {
                    let _ = weak.update(cx, |this, cx| {
                        this.ids = None;
                        this.only_new = !this.only_new;
                        this.fill(cx);
                    });
                },
                &tk,
            ));
        }
        chips = chips.child(div().flex_1());
        if let Some((_, caption)) = &self.ids {
            let weak = cx.entity().downgrade();
            chips = chips.child(kit::faint(caption.clone(), &tk)).child(kit::link(
                "fi-all",
                t("findings.showAll"),
                move |_, cx| {
                    let _ = weak.update(cx, |this, cx| {
                        this.ids = None;
                        this.fill(cx);
                    });
                },
                &tk,
            ));
        }
        let kind_name = if self.kind.is_empty() {
            t("findings.allTypes")
        } else {
            kind_label(&self.kind)
        };
        let weak = cx.entity().downgrade();
        let current_kind = self.kind.clone();
        chips = chips
            .child(
                FButton::new("fi-kind", Kind::Standard)
                    .label(kind_name)
                    .accessible_name(t("findings.type"))
                    .chevron()
                    .dropdown_menu(move |menu, _, _| {
                        let mut menu = menu;
                        for k in std::iter::once("").chain(KINDS) {
                            let weak = weak.clone();
                            let label = if k.is_empty() {
                                t("findings.allTypes")
                            } else {
                                kind_label(k)
                            };
                            menu = menu.item(PopupMenuItem::new(label).checked(current_kind == k).on_click(
                                move |_, _, cx| {
                                    let _ = weak.update(cx, |this, cx| {
                                        this.kind = k.to_string();
                                        this.fill(cx);
                                    });
                                },
                            ));
                        }
                        menu
                    }),
            )
            .child(ui::check_box(
                "fi-ignored",
                self.show_ignored,
                false,
                t("findings.showIgnored"),
                {
                    let weak = cx.entity().downgrade();
                    move |on, _, cx| {
                        let _ = weak.update(cx, |this, cx| {
                            this.show_ignored = on;
                            this.fill(cx);
                        });
                    }
                },
                &tk,
            ));

        let current = self
            .current
            .as_ref()
            .and_then(|id| all.iter().find(|i| i.s("id") == id).cloned());
        let side: AnyElement = match current {
            Some(item) => div()
                .id("fi-detail")
                .size_full()
                .overflow_y_scroll()
                .p_4()
                .child(self.detail(&item, cx))
                .child(self.investigation(cx))
                .into_any_element(),
            None => div()
                .p_4()
                .child(kit::muted(
                    t(if has_report {
                        "findings.select"
                    } else {
                        "findings.runScan"
                    }),
                    &tk,
                ))
                .into_any_element(),
        };
        let wide = f32::from(window.viewport_size().width) >= 1100.;
        let body = div()
            .flex_1()
            .min_h_0()
            .flex()
            .gap_3()
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(grid::frame(&tk).child(grid::table(&self.table, t("page.findings"))))
                    .child(kit::faint(
                        tf(
                            "findings.shown",
                            &[("shown", &shown.to_string()), ("total", &all.len().to_string())],
                        ),
                        &tk,
                    )),
            )
            .child(
                div()
                    .w(px(if wide { 460. } else { 380. }))
                    .flex_none()
                    .min_h_0()
                    .bg(tk.surface)
                    .border_1()
                    .border_color(tk.rule)
                    .rounded(crate::theme::RADIUS_CARD)
                    .child(side),
            );
        let root = div()
            .track_focus(&self.focus)
            .size_full()
            .flex()
            .flex_col()
            .gap_2()
            .px(px(20.))
            .pt(px(12.))
            .pb(px(12.));
        common::list_keys(root, |p: &FindingsPage| p.table.clone(), cx)
            .child(
                kit::row()
                    .child(ui::page_title(t("page.findings")))
                    .child(div().flex_1())
                    .child(self.export_menu(has_report, cx))
                    .child(div().w(px(320.)).child(ui::search_box(&self.search, &tk))),
            )
            .when_some(self.export_bar(cx), |this, bar| this.child(bar))
            .when(view_only, |this| {
                this.child(ui::info_bar(
                    "fi-view-only",
                    ui::Severity::Warning,
                    t("findings.viewOnly"),
                    None,
                    &tk,
                ))
            })
            .child(chips)
            .child(body)
    }
}
