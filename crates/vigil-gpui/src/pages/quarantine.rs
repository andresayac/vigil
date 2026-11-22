//! The Quarantine page (a port of `ui/src/pages/Quarantine.svelte`): the files Vigil moved into
//! quarantine, with Restore and Delete permanently through the action service (both confirmed
//! natively, as every change).

use std::sync::Arc;

use gpui_kit::component::table::TableState;
use gpui_kit::{
    AppContext as _, Context, Entity, FocusHandle, InteractiveElement as _, IntoElement, ParentElement, Render, Styled,
    Subscription, Window, div, px,
};
use vigil_core::requests::Request;
use vigil_core::state::{AppState, QuarantineEntry};

use crate::format::size;
use crate::i18n::{t, tn};
use crate::icons;
use crate::pages::common::{self, Acting, Acts, when};
use crate::theme::tokens;
use crate::ui;
use crate::ui::grid::{self, Grid, GridCell, GridCol, GridRow};

pub struct QuarantinePage {
    entries: Vec<QuarantineEntry>,
    table: Entity<TableState<Grid>>,
    core: Option<Arc<AppState>>,
    elevated: bool,
    acting: Acting,
    focus: FocusHandle,
    _subscriptions: Vec<Subscription>,
}

impl Acts for QuarantinePage {
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

impl QuarantinePage {
    pub fn new(core: Option<Arc<AppState>>, elevated: bool, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let cols = vec![
            GridCol::new("file", t("quarantine.file"), 180.),
            GridCol::new("original", t("quarantine.original"), 340.),
            GridCol::new("when", t("quarantine.when"), 150.),
            GridCol::new("size", t("quarantine.size"), 90.).numeric(),
            GridCol::new("sha256", "SHA-256".into(), 220.),
            GridCol::new("reason", t("quarantine.reason"), 220.),
        ];
        let table = cx.new(|cx| {
            TableState::new(Grid::new(t("quarantine.empty"), cols), window, cx)
                .row_selectable(false)
                .col_movable(false)
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
                self.entries = crate::demo_pages::quarantine();
                self.fill(cx);
            }
            Some(core) => common::read(
                cx,
                move || core.store.quarantined(),
                |page, entries, cx| {
                    page.entries = entries;
                    page.fill(cx);
                },
            ),
        }
    }

    fn fill(&mut self, cx: &mut Context<Self>) {
        let rows: Vec<GridRow> = self
            .entries
            .iter()
            .map(|e| {
                let cells = vec![
                    GridCell::text(&e.name),
                    GridCell::text(&e.original_path),
                    GridCell::text(when(&e.quarantined_at)).ranked(0.0),
                    GridCell::num(size(e.size as f64, 1), e.size as f64),
                    GridCell::text(&e.sha256).mono(),
                    GridCell::text(&e.reason),
                ];
                let search = format!("{} {} {} {}", e.name, e.original_path, e.sha256, e.reason);
                GridRow::new(e.id.clone(), cells, search)
            })
            .collect();
        self.table.update(cx, |table, cx| {
            table.delegate_mut().set_rows(rows);
            table.refresh(cx);
            cx.notify();
        });
    }

    fn run(&mut self, op: &str, window: &mut Window, cx: &mut Context<Self>) {
        let Some(id) = self.table.read(cx).delegate().selected.clone() else {
            return;
        };
        let request = Request::Journal { op: op.into(), id };
        common::send(self, request, window, cx);
    }
}

impl Render for QuarantinePage {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let selected = self.table.read(cx).delegate().selected_row().is_some();
        let can = selected && self.elevated && !self.acting.busy;
        let scheduled = self
            .table
            .read(cx)
            .delegate()
            .selected
            .as_ref()
            .and_then(|id| self.entries.iter().find(|e| &e.id == id))
            .is_some_and(|e| e.state.as_deref() == Some("scheduled"));
        let root = div()
            .track_focus(&self.focus)
            .size_full()
            .flex()
            .flex_col()
            .gap_2()
            .px(px(20.))
            .pt(px(12.))
            .pb(px(12.));
        common::list_keys(root, |p: &QuarantinePage| p.table.clone(), cx)
            .child(ui::page_title(t("page.quarantine")))
            .child(div().text_size(px(13.)).text_color(tk.ink2).child(t("quarantine.note")))
            .child(
                div()
                    .flex()
                    .gap_2()
                    .child(
                        ui::button("q-restore", t("quarantine.restore"))
                            .glyph(icons::UNDO)
                            .disabled(!can)
                            .on_click(cx.listener(|this, _, window, cx| this.run("restore", window, cx))),
                    )
                    .child(
                        ui::button("q-delete", t("quarantine.delete"))
                            .glyph(icons::DELETE)
                            .danger(can)
                            .disabled(!can)
                            .on_click(cx.listener(|this, _, window, cx| this.run("delete", window, cx))),
                    ),
            )
            .children(self.acting.bar("q-result", &tk))
            .children(scheduled.then(|| {
                ui::info_bar("q-scheduled", ui::Severity::Info, t("quarantine.scheduled"), None, &tk).into_any_element()
            }))
            .child(grid::frame(&tk).child(grid::table(&self.table, t("page.quarantine"))))
            .child(div().text_size(px(12.)).text_color(tk.ink3).child(tn(
                "quarantine.count",
                self.entries.len() as u64,
                &[],
            )))
    }
}
