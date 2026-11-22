//! A table of rows kept by identity: the data of the Services, Startup apps, Quarantine and
//! History pages. It is gpui-component's virtualized `DataTable` with Vigil's own selection, which
//! follows the row's key (a service name, a record id) when rows are read again or re-sorted, and
//! keyboard navigation that moves that selection (Up, Down, Home, End, Page Up, Page Down).

use std::cmp::Ordering;
use std::ops::Range;
use std::sync::Arc;

use gpui_kit::component::table::{Column, ColumnSort, TableDelegate, TableState};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    App, ClickEvent, Context, Div, FontWeight, Hsla, Image, InteractiveElement, IntoElement, KeyBinding, ObjectFit,
    ParentElement, SharedString, Stateful, StatefulInteractiveElement, Styled, StyledImage, Window, div, img, px,
};

use crate::theme::{FONT_DISPLAY, FONT_MONO, tokens};

pub const KEY_CONTEXT: &str = "VigilList";

gpui_kit::actions!(
    vigil_list,
    [
        SelectPrevious,
        SelectNext,
        SelectFirst,
        SelectLast,
        PagePrevious,
        PageNext
    ]
);

/// The list keys, inside a page's list and inside the table when it has focus.
pub fn bind_keys(cx: &mut App) {
    for context in [KEY_CONTEXT, "VigilList > DataTable"] {
        cx.bind_keys([
            KeyBinding::new("up", SelectPrevious, Some(context)),
            KeyBinding::new("down", SelectNext, Some(context)),
            KeyBinding::new("home", SelectFirst, Some(context)),
            KeyBinding::new("end", SelectLast, Some(context)),
            KeyBinding::new("pageup", PagePrevious, Some(context)),
            KeyBinding::new("pagedown", PageNext, Some(context)),
        ]);
    }
}

/// Rows a Page Up / Page Down moves.
pub const PAGE: isize = 12;

/// How a column sorts.
#[derive(Debug, Clone, PartialEq)]
pub enum SortKey {
    Text(String),
    Num(f64),
}

impl SortKey {
    fn compare(&self, other: &SortKey) -> Ordering {
        match (self, other) {
            (SortKey::Num(a), SortKey::Num(b)) => a.total_cmp(b),
            (SortKey::Text(a), SortKey::Text(b)) => a.cmp(b),
            (SortKey::Num(_), SortKey::Text(_)) => Ordering::Less,
            (SortKey::Text(_), SortKey::Num(_)) => Ordering::Greater,
        }
    }
}

#[derive(Clone)]
pub struct GridCol {
    pub key: &'static str,
    pub title: String,
    pub width: f32,
    pub numeric: bool,
}

impl GridCol {
    pub fn new(key: &'static str, title: String, width: f32) -> Self {
        Self {
            key,
            title,
            width,
            numeric: false,
        }
    }

    pub fn numeric(mut self) -> Self {
        self.numeric = true;
        self
    }
}

#[derive(Clone)]
pub struct GridCell {
    pub text: String,
    pub sort: SortKey,
    /// A state colour (running, unsigned…); `None` is plain ink.
    pub color: Option<Hsla>,
    pub mono: bool,
    /// A glyph before the text (Segoe Fluent Icons) and its colour.
    pub glyph: Option<(char, Hsla)>,
    /// A program icon before the text.
    pub image: Option<Arc<Image>>,
    pub strong: bool,
}

impl GridCell {
    /// A text cell. Names and paths come from the computer: hidden or direction-changing
    /// characters and line breaks are shown as markers (`vigil_core::display::shown_line`).
    pub fn text(text: impl Into<String>) -> Self {
        let text = text.into();
        let text = if vigil_core::display::is_plain(&text) && !text.contains(['\n', '\r', '\t']) {
            text
        } else {
            vigil_core::display::shown_line(&text)
        };
        Self {
            sort: SortKey::Text(text.to_lowercase()),
            text,
            color: None,
            mono: false,
            glyph: None,
            image: None,
            strong: false,
        }
    }

    /// A number shown as `text` and sorted by `value`.
    pub fn num(text: impl Into<String>, value: f64) -> Self {
        Self {
            sort: SortKey::Num(value),
            ..Self::text(text)
        }
    }

    /// Sorts by `rank` (a state's order) whatever the text.
    pub fn ranked(mut self, rank: f64) -> Self {
        self.sort = SortKey::Num(rank);
        self
    }

    pub fn color(mut self, color: Hsla) -> Self {
        self.color = Some(color);
        self
    }

    pub fn mono(mut self) -> Self {
        self.mono = true;
        self
    }

    pub fn glyph(mut self, glyph: char, color: Hsla) -> Self {
        self.glyph = Some((glyph, color));
        self
    }

    pub fn image(mut self, image: Option<Arc<Image>>) -> Self {
        self.image = image;
        self
    }
}

#[derive(Clone)]
pub struct GridRow {
    pub key: String,
    pub cells: Vec<GridCell>,
    /// Words the search looks in (lower case).
    pub search: String,
    /// A heading (a batch of History): drawn in bold, never selected, kept with the rows after it.
    pub heading: bool,
    /// Indented under a heading.
    pub child: bool,
    /// Drawn in grey (a disabled startup app).
    pub dim: bool,
}

impl GridRow {
    pub fn new(key: impl Into<String>, cells: Vec<GridCell>, search: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            cells,
            search: search.into().to_lowercase(),
            heading: false,
            child: false,
            dim: false,
        }
    }
}

/// The table's data. Rows keep the order they were given when no column is sorted; groups (a
/// heading and its children) stay together.
pub struct Grid {
    cols: Vec<GridCol>,
    rows: Vec<GridRow>,
    /// Visible rows, in order (indexes into `rows`).
    order: Vec<usize>,
    sort: Option<(usize, bool)>,
    filter: Vec<String>,
    pub selected: Option<String>,
    name: SharedString,
}

impl Grid {
    pub fn new(name: impl Into<SharedString>, cols: Vec<GridCol>) -> Self {
        Self {
            cols,
            rows: Vec::new(),
            order: Vec::new(),
            sort: None,
            filter: Vec::new(),
            selected: None,
            name: name.into(),
        }
    }

    pub fn set_rows(&mut self, rows: Vec<GridRow>) {
        self.rows = rows;
        self.rebuild();
    }

    /// Replaces the columns (a column that cannot be read is left out); the rows must match them.
    /// Returns whether they changed, so the caller refreshes the table.
    pub fn set_cols(&mut self, cols: Vec<GridCol>) -> bool {
        let same = cols.len() == self.cols.len() && cols.iter().zip(&self.cols).all(|(a, b)| a.key == b.key);
        if same {
            return false;
        }
        self.cols = cols;
        self.sort = None;
        true
    }

    /// What the grid says when it has no rows.
    pub fn set_empty(&mut self, text: impl Into<SharedString>) {
        self.name = text.into();
    }

    pub fn set_filter(&mut self, text: &str) {
        self.filter = text.split_whitespace().map(str::to_lowercase).collect();
        self.rebuild();
    }

    pub fn row_count(&self) -> usize {
        self.order.len()
    }

    /// The selected row, when it is still in the data.
    pub fn selected_row(&self) -> Option<&GridRow> {
        let key = self.selected.as_deref()?;
        self.rows.iter().find(|r| r.key == key)
    }

    fn matches(&self, row: &GridRow) -> bool {
        self.filter.iter().all(|w| row.search.contains(w.as_str()))
    }

    fn rebuild(&mut self) {
        // Groups: a heading and the children after it travel together.
        let mut groups: Vec<Vec<usize>> = Vec::new();
        for (i, row) in self.rows.iter().enumerate() {
            if row.child && !groups.is_empty() {
                if let Some(last) = groups.last_mut() {
                    last.push(i);
                }
            } else {
                groups.push(vec![i]);
            }
        }
        let mut kept: Vec<Vec<usize>> = groups
            .into_iter()
            .filter_map(|group| {
                let shown: Vec<usize> = group
                    .iter()
                    .copied()
                    .filter(|&i| self.rows[i].heading || self.matches(&self.rows[i]))
                    .collect();
                shown.iter().any(|&i| !self.rows[i].heading).then_some(shown)
            })
            .collect();
        if let Some((col, descending)) = self.sort {
            let key = |group: &Vec<usize>| -> Option<SortKey> {
                let first = group.iter().find(|&&i| !self.rows[i].heading).copied()?;
                self.rows[first].cells.get(col).map(|c| c.sort.clone())
            };
            kept.sort_by(|a, b| {
                let order = match (key(a), key(b)) {
                    (Some(x), Some(y)) => x.compare(&y),
                    _ => Ordering::Equal,
                };
                if descending { order.reverse() } else { order }
            });
        }
        self.order = kept.into_iter().flatten().collect();
    }

    /// Moves the selection by `delta` rows (`isize::MIN` / `MAX`: first / last), skipping headings.
    /// Returns the visible index to scroll to.
    pub fn step(&mut self, delta: isize) -> Option<usize> {
        let selectable: Vec<usize> = (0..self.order.len())
            .filter(|&ix| !self.rows[self.order[ix]].heading)
            .collect();
        if selectable.is_empty() {
            return None;
        }
        let current = self
            .selected
            .as_deref()
            .and_then(|key| selectable.iter().position(|&ix| self.rows[self.order[ix]].key == key));
        let next = match (current, delta) {
            (_, isize::MIN) => 0,
            (_, isize::MAX) => selectable.len() - 1,
            (None, d) if d < 0 => selectable.len() - 1,
            (None, _) => 0,
            (Some(at), d) => (at as isize + d).clamp(0, selectable.len() as isize - 1) as usize,
        };
        let ix = selectable[next];
        self.selected = Some(self.rows[self.order[ix]].key.clone());
        Some(ix)
    }

    fn cell(&self, row_ix: usize, col_ix: usize) -> Option<&GridCell> {
        self.rows.get(*self.order.get(row_ix)?)?.cells.get(col_ix)
    }
}

impl TableDelegate for Grid {
    fn columns_count(&self, _cx: &App) -> usize {
        self.cols.len()
    }

    fn rows_count(&self, _cx: &App) -> usize {
        self.order.len()
    }

    fn column(&self, col_ix: usize, _cx: &App) -> Column {
        let col = &self.cols[col_ix];
        let column = Column::new(col.key, col.title.clone())
            .width(px(col.width))
            .min_width(px(48.))
            .p_0()
            .movable(false)
            .sort(ColumnSort::Default);
        if col.numeric { column.text_right() } else { column }
    }

    fn perform_sort(&mut self, col_ix: usize, sort: ColumnSort, _: &mut Window, _: &mut Context<TableState<Self>>) {
        self.sort = match sort {
            ColumnSort::Ascending => Some((col_ix, false)),
            ColumnSort::Descending => Some((col_ix, true)),
            ColumnSort::Default => None,
        };
        self.rebuild();
    }

    fn render_th(&mut self, col_ix: usize, _: &mut Window, cx: &mut Context<TableState<Self>>) -> impl IntoElement {
        let tk = *tokens(cx);
        let sorted = self.sort.is_some_and(|(c, _)| c == col_ix);
        div()
            .w_full()
            .px_2()
            .text_size(px(12.))
            .text_color(if sorted { tk.ink } else { tk.ink2 })
            .overflow_hidden()
            .text_ellipsis()
            .child(self.cols[col_ix].title.clone())
    }

    fn render_tr(&mut self, row_ix: usize, _: &mut Window, cx: &mut Context<TableState<Self>>) -> Stateful<Div> {
        let tk = *tokens(cx);
        let row = self.order.get(row_ix).and_then(|&i| self.rows.get(i));
        let selected = row.is_some_and(|r| self.selected.as_deref() == Some(r.key.as_str()));
        let heading = row.is_some_and(|r| r.heading);
        div()
            .id(("grid-row", row_ix))
            .when(selected, |this| this.bg(tk.table_select))
            .when(!heading, |this| {
                this.on_click(cx.listener(move |table: &mut TableState<Grid>, _: &ClickEvent, _, cx| {
                    let grid = table.delegate_mut();
                    if let Some(key) = grid
                        .order
                        .get(row_ix)
                        .and_then(|&i| grid.rows.get(i))
                        .map(|r| r.key.clone())
                    {
                        grid.selected = Some(key);
                        cx.notify();
                    }
                }))
            })
    }

    fn render_td(
        &mut self,
        row_ix: usize,
        col_ix: usize,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        let tk = *tokens(cx);
        let Some(row) = self.order.get(row_ix).and_then(|&i| self.rows.get(i)) else {
            return div().into_any_element();
        };
        let (heading, child, dim) = (row.heading, row.child, row.dim);
        let Some(cell) = self.cell(row_ix, col_ix) else {
            return div().into_any_element();
        };
        let numeric = self.cols[col_ix].numeric;
        let color = cell.color.unwrap_or(if dim { tk.ink3 } else { tk.ink });
        div()
            .size_full()
            .flex()
            .items_center()
            .gap_2()
            .px_2()
            .when(col_ix == 0 && child, |this| this.pl(px(28.)))
            .text_size(px(13.))
            .text_color(color)
            .overflow_hidden()
            .when(numeric, |this| this.justify_end().font_family(FONT_DISPLAY))
            .when(cell.mono, |this| this.font_family(FONT_MONO).text_size(px(12.)))
            .when(heading || cell.strong, |this| this.font_weight(FontWeight::SEMIBOLD))
            .when_some(cell.image.clone(), |this, image| {
                this.child(
                    img(image)
                        .w(px(16.))
                        .h(px(16.))
                        .flex_none()
                        .object_fit(ObjectFit::Contain),
                )
            })
            .when_some(cell.glyph, |this, (glyph, color)| {
                this.child(crate::icons::icon(glyph, 12.0, color))
            })
            .child(
                div()
                    .overflow_hidden()
                    .text_ellipsis()
                    .whitespace_nowrap()
                    .child(cell.text.clone()),
            )
            .into_any_element()
    }

    fn cell_label(&self, row_ix: usize, col_ix: usize, _: &App) -> Option<SharedString> {
        self.cell(row_ix, col_ix).map(|c| c.text.clone().into())
    }

    fn visible_rows_changed(&mut self, _: Range<usize>, _: &mut Window, _: &mut Context<TableState<Self>>) {}

    fn render_empty(&mut self, _: &mut Window, cx: &mut Context<TableState<Self>>) -> impl IntoElement {
        let tk = *tokens(cx);
        div()
            .size_full()
            .flex()
            .items_center()
            .justify_center()
            .text_color(tk.ink3)
            .child(self.name.clone())
    }
}

/// The table element for a grid, with Vigil's row height and no stripes.
pub fn table(state: &gpui_kit::Entity<TableState<Grid>>, name: impl Into<SharedString>) -> impl IntoElement {
    use gpui_kit::component::Sizable as _;
    gpui_kit::component::table::DataTable::new(state)
        .with_size(gpui_kit::component::Size::Size(px(28.)))
        .bordered(false)
        .stripe(false)
        // Scrollbars stay visible: columns past the right edge must show they are there (a
        // scrollbar that only appears while scrolling hides them).
        .scrollbar_mode(gpui_kit::component::scroll::ScrollbarMode::Always)
        .accessibility_label(name)
}

/// The rounded card around a table.
pub fn frame(tk: &crate::theme::Tokens) -> Div {
    div()
        .flex_1()
        .min_h_0()
        .rounded(crate::theme::RADIUS_CARD)
        .border_1()
        .border_color(tk.rule)
        .bg(tk.surface)
        .overflow_hidden()
}

/// A new grid's state: no index selection (rows are selected by key), columns fixed in place.
pub fn new_state<V: 'static>(
    empty: String,
    cols: Vec<GridCol>,
    window: &mut Window,
    cx: &mut Context<V>,
) -> gpui_kit::Entity<TableState<Grid>> {
    use gpui_kit::AppContext as _;
    cx.new(|cx| {
        TableState::new(Grid::new(empty, cols), window, cx)
            .row_selectable(false)
            .col_movable(false)
    })
}

/// Replaces a grid's rows (the selection stays while its key is there).
pub fn fill(table: &gpui_kit::Entity<TableState<Grid>>, rows: Vec<GridRow>, cx: &mut App) {
    table.update(cx, |table, cx| {
        table.delegate_mut().set_rows(rows);
        table.refresh(cx);
        cx.notify();
    });
}

/// The key of the selected row.
pub fn selected(table: &gpui_kit::Entity<TableState<Grid>>, cx: &App) -> Option<String> {
    table.read(cx).delegate().selected_row().map(|r| r.key.clone())
}

/// Selects the row with `key` and scrolls it into view.
pub fn select(table: &gpui_kit::Entity<TableState<Grid>>, key: Option<String>, cx: &mut App) {
    table.update(cx, |table, cx| {
        let some = key.is_some();
        table.delegate_mut().selected = key;
        if some && let Some(ix) = table.delegate_mut().step(0) {
            table.scroll_to_row(ix, cx);
        }
        cx.notify();
    });
}

/// A search box state that filters `table` as the person types.
pub fn search<V: 'static>(
    table: &gpui_kit::Entity<TableState<Grid>>,
    placeholder: String,
    window: &mut Window,
    cx: &mut Context<V>,
) -> (
    gpui_kit::Entity<gpui_kit::component::input::InputState>,
    gpui_kit::Subscription,
) {
    use gpui_kit::AppContext as _;
    use gpui_kit::component::input::{InputEvent, InputState};
    let input = cx.new(|cx| InputState::new(window, cx).placeholder(placeholder));
    let table = table.clone();
    seed(&input, &table, window, cx);
    let subscription = cx.subscribe(&input, move |_, input, event: &InputEvent, cx| {
        if matches!(event, InputEvent::Change) {
            let text = input.read(cx).value().to_string();
            table.update(cx, |table, cx| {
                table.delegate_mut().set_filter(&text);
                table.refresh(cx);
                cx.notify();
            });
        }
    });
    (input, subscription)
}

/// Starts a page's search box with the text the global search (Ctrl+K) opened it with, and filters
/// the table by it, so the item picked there shows. Nothing happens when the page opened otherwise.
pub fn seed<V: 'static>(
    input: &gpui_kit::Entity<gpui_kit::component::input::InputState>,
    table: &gpui_kit::Entity<TableState<Grid>>,
    window: &mut Window,
    cx: &mut Context<V>,
) {
    let Some(text) = crate::search::take_seed() else {
        return;
    };
    input.update(cx, |state, cx| state.set_value(text.clone(), window, cx));
    table.update(cx, |table, cx| {
        table.delegate_mut().set_filter(&text);
        table.refresh(cx);
        cx.notify();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grid() -> Grid {
        let mut grid = Grid::new("empty", vec![GridCol::new("name", "Name".into(), 100.)]);
        grid.set_rows(vec![
            GridRow::new("b", vec![GridCell::text("Bravo")], "bravo"),
            GridRow::new("a", vec![GridCell::text("Alpha")], "alpha"),
            GridRow::new("c", vec![GridCell::text("Charlie")], "charlie"),
        ]);
        grid
    }

    #[test]
    fn the_selection_follows_the_key() {
        let mut grid = grid();
        assert_eq!(grid.step(1), Some(0));
        assert_eq!(grid.selected.as_deref(), Some("b"));
        grid.sort = Some((0, false));
        grid.rebuild();
        // Re-sorted: "b" is now second; Down goes to "c".
        assert_eq!(grid.step(1), Some(2));
        assert_eq!(grid.selected.as_deref(), Some("c"));
        assert_eq!(grid.step(isize::MIN), Some(0));
        assert_eq!(grid.selected.as_deref(), Some("a"));
    }

    #[test]
    fn headings_stay_with_their_rows_and_are_skipped() {
        let mut grid = Grid::new("empty", vec![GridCol::new("name", "Name".into(), 100.)]);
        let mut heading = GridRow::new("h", vec![GridCell::text("Batch")], "");
        heading.heading = true;
        let mut child = GridRow::new("x", vec![GridCell::text("Step")], "step");
        child.child = true;
        grid.set_rows(vec![
            heading,
            child,
            GridRow::new("y", vec![GridCell::text("Other")], "other"),
        ]);
        assert_eq!(grid.row_count(), 3);
        assert_eq!(grid.step(1), Some(1));
        grid.set_filter("other");
        assert_eq!(grid.row_count(), 1, "a heading without matching rows is hidden");
    }
}
