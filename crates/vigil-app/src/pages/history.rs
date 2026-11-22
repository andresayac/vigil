//! The History page: every change Vigil made, newest
//! first, with what it saved to undo it. The steps of one "Remove completely" are grouped under a
//! heading; Undo and Undo the whole removal go through the action service.

use std::sync::Arc;

use gpui_kit::component::table::TableState;
use gpui_kit::{
    AppContext as _, Context, Entity, FocusHandle, InteractiveElement as _, IntoElement, ParentElement, Render, Styled,
    Subscription, Window, div, px,
};
use serde_json::Value;
use vigil_core::requests::Request;
use vigil_core::state::AppState;

use crate::i18n::{t, tf};
use crate::icons;
use crate::pages::common::{self, Acting, Acts, when};
use crate::theme::tokens;
use crate::ui;
use crate::ui::grid::{self, Grid, GridCell, GridCol, GridRow};

/// One journal record as History shows it (`vigil_core::service::record_json`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Entry {
    pub id: String,
    pub batch: Option<String>,
    pub time: String,
    pub op_label: String,
    pub target: String,
    pub item: String,
    pub ok: bool,
    pub message: String,
    pub undone: bool,
    pub can_undo: bool,
}

impl Entry {
    pub fn from_json(value: &Value) -> Self {
        let text = |key: &str| value.get(key).and_then(Value::as_str).unwrap_or("").to_string();
        let flag = |key: &str| value.get(key).and_then(Value::as_bool).unwrap_or(false);
        Self {
            id: text("id"),
            batch: value.get("batch").and_then(Value::as_str).map(str::to_string),
            time: text("time"),
            op_label: text("op_label"),
            target: text("target"),
            item: text("item"),
            ok: flag("ok"),
            message: text("message"),
            undone: flag("undone"),
            can_undo: flag("can_undo"),
        }
    }
}

/// Newest first, the steps of a batch together under one heading.
fn rows(entries: &[Entry], tk: &crate::theme::Tokens) -> Vec<GridRow> {
    let mut out: Vec<GridRow> = Vec::new();
    let mut seen_batches: Vec<String> = Vec::new();
    for entry in entries {
        if let Some(batch) = &entry.batch {
            if seen_batches.contains(batch) {
                continue;
            }
            seen_batches.push(batch.clone());
            let mut heading = GridRow::new(
                format!("batch:{batch}"),
                vec![
                    GridCell::text(when(&entry.time)),
                    GridCell::text(tf("history.removal", &[("item", &entry.item)])),
                    GridCell::text(""),
                    GridCell::text(""),
                    GridCell::text(""),
                ],
                "",
            );
            heading.heading = true;
            out.push(heading);
            for step in entries.iter().filter(|e| e.batch.as_deref() == Some(batch.as_str())) {
                let mut row = row(step, tk);
                row.child = true;
                out.push(row);
            }
        } else {
            out.push(row(entry, tk));
        }
    }
    out
}

fn row(e: &Entry, tk: &crate::theme::Tokens) -> GridRow {
    let result = if e.ok {
        GridCell::text(&e.message)
    } else {
        GridCell::text(format!("{} {}", t("history.failed"), e.message)).color(tk.bad)
    };
    let undo = if e.undone {
        t("history.undone")
    } else if e.can_undo {
        t("history.available")
    } else {
        "—".into()
    };
    let cells = vec![
        GridCell::text(when(&e.time)),
        GridCell::text(&e.op_label),
        GridCell::text(&e.target),
        result,
        GridCell::text(undo),
    ];
    let search = format!("{} {} {} {}", e.op_label, e.target, e.message, e.item);
    GridRow::new(e.id.clone(), cells, search)
}

pub struct HistoryPage {
    entries: Vec<Entry>,
    table: Entity<TableState<Grid>>,
    core: Option<Arc<AppState>>,
    elevated: bool,
    acting: Acting,
    focus: FocusHandle,
    _subscriptions: Vec<Subscription>,
}

impl Acts for HistoryPage {
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

impl HistoryPage {
    pub fn new(core: Option<Arc<AppState>>, elevated: bool, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let cols = vec![
            GridCol::new("when", t("history.when"), 150.),
            GridCol::new("action", t("history.action"), 220.),
            GridCol::new("target", t("history.target"), 300.),
            GridCol::new("result", t("history.result"), 340.),
            GridCol::new("undo", t("history.undoColumn"), 110.),
        ];
        let table = cx.new(|cx| {
            TableState::new(Grid::new(t("history.empty"), cols), window, cx)
                .row_selectable(false)
                .col_movable(false)
                .sortable(false)
        });
        let subscriptions = vec![cx.observe(&table, |_, _, cx| cx.notify())];
        let mut page = Self {
            entries: Vec::new(),
            table,
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
        match self.core.clone() {
            None => {
                self.entries = crate::demo_pages::history();
                self.fill(cx);
            }
            Some(core) => common::read(
                cx,
                move || {
                    let mut records: Vec<Entry> = core
                        .store
                        .records()
                        .iter()
                        .map(|r| Entry::from_json(&vigil_core::service::record_json(r)))
                        .collect();
                    records.reverse();
                    records
                },
                |page, entries, cx| {
                    page.entries = entries;
                    page.fill(cx);
                },
            ),
        }
    }

    fn fill(&mut self, cx: &mut Context<Self>) {
        let tk = *tokens(cx);
        let rows = rows(&self.entries, &tk);
        self.table.update(cx, |table, cx| {
            table.delegate_mut().set_rows(rows);
            table.refresh(cx);
            cx.notify();
        });
    }

    fn current(&self, cx: &gpui_kit::App) -> Option<Entry> {
        let id = self.table.read(cx).delegate().selected.clone()?;
        self.entries.iter().find(|e| e.id == id).cloned()
    }

    fn undo(&mut self, all: bool, window: &mut Window, cx: &mut Context<Self>) {
        let Some(entry) = self.current(cx) else { return };
        let request = match (&entry.batch, all) {
            (Some(batch), true) => Request::Journal {
                op: "undo_batch".into(),
                id: batch.clone(),
            },
            _ => Request::Journal {
                op: "undo".into(),
                id: entry.id,
            },
        };
        common::send(self, request, window, cx);
    }
}

impl Render for HistoryPage {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let current = self.current(cx);
        let busy = self.acting.busy;
        let can_undo = current.as_ref().is_some_and(|e| e.can_undo) && !busy && self.elevated;
        let batch = current.as_ref().and_then(|e| e.batch.clone());
        let batch_undoable = batch
            .as_ref()
            .is_some_and(|b| self.entries.iter().any(|e| e.batch.as_ref() == Some(b) && e.can_undo))
            && !busy
            && self.elevated;
        let root = div()
            .track_focus(&self.focus)
            .size_full()
            .flex()
            .flex_col()
            .gap_2()
            .px(px(20.))
            .pt(px(12.))
            .pb(px(12.));
        common::list_keys(root, |p: &HistoryPage| p.table.clone(), cx)
            .child(ui::page_title(t("page.history")))
            .child(div().text_size(px(13.)).text_color(tk.ink2).child(t("history.note")))
            .child(
                div()
                    .flex()
                    .gap_2()
                    .child(
                        ui::button("h-undo", t("history.undo"))
                            .glyph(icons::UNDO)
                            .disabled(!can_undo)
                            .on_click(cx.listener(|this, _, window, cx| this.undo(false, window, cx))),
                    )
                    .child(
                        ui::button("h-undo-all", t("history.undoAll"))
                            .disabled(!batch_undoable)
                            .on_click(cx.listener(|this, _, window, cx| this.undo(true, window, cx))),
                    ),
            )
            .children(self.acting.bar("h-result", &tk))
            .child(grid::frame(&tk).child(grid::table(&self.table, t("page.history"))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batches_are_grouped_under_one_heading() {
        let tk = crate::theme::Tokens::light(false);
        let entries = crate::demo_pages::history();
        let rows = vigil_i18n::with_language("en", || rows(&entries, &tk));
        let headings: Vec<&GridRow> = rows.iter().filter(|r| r.heading).collect();
        assert_eq!(headings.len(), 1);
        let first_child = rows.iter().position(|r| r.child).unwrap_or(0);
        assert!(rows[first_child - 1].heading, "the steps follow their heading");
        assert_eq!(rows.iter().filter(|r| !r.heading).count(), entries.len());
    }
}
