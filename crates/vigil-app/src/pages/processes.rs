//! The Processes page:
//! Task Manager's grouped view (Apps, Background processes, Windows processes), the process tree
//! and a flat list, live once a second, in a virtualized table (gpui-component's `DataTable`) with
//! sortable, resizable columns and the heat map. Ending a process goes through the action service.
//!
//! Process names, paths, command lines and users come from the inspected computer and may come
//! from malware: GPUI draws them as plain text, never as markup.

use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::sync::Arc;

use gpui_kit::component::input::{InputEvent, InputState};
use gpui_kit::component::menu::{PopupMenu, PopupMenuItem};
use gpui_kit::component::table::{Column, ColumnSort, DataTable, TableDelegate, TableState};
use gpui_kit::component::{Sizable, Size};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    AnyElement, App, AppContext, ClickEvent, Context, Div, Entity, FocusHandle, FontWeight, Image, ImageFormat,
    InteractiveElement, IntoElement, KeyBinding, ObjectFit, ParentElement, Render, SharedString, Stateful,
    StatefulInteractiveElement, Styled, StyledImage, Subscription, WeakEntity, Window, div, img, px,
};
use vigil_core::inspect::ProcessDetails;
use vigil_core::requests::{ProcessRef, Request};
use vigil_core::state::AppState;
use vigil_sys::metrics::GpuUse;
use vigil_sys::process::{ProcessRow, ProcessStatus};

use crate::format::{age, now_ms, num, pct, size};
use crate::groups::{self, SECTIONS, Section};
use crate::i18n::{t, tf, tn};
use crate::icons;
use crate::live::Live;
use crate::pages::common::{self, Acting, Acts};
use crate::theme::{FONT_DISPLAY, FONT_MONO, RADIUS, RADIUS_CARD, Tokens, tokens};
use crate::ui::{self, grid};

const MB: f64 = 1_048_576.0;
/// 100 MB/s reads as a busy disk.
const DISK_SCALE: f64 = 100.0 * MB;
const ROW_HEIGHT: f32 = 28.0;
const KEY_CONTEXT: &str = "VigilProcesses";

gpui_kit::actions!(vigil, [EndTask]);

/// The page's keys: Delete ends the selected task (Task Manager's shortcut).
pub fn bind_keys(cx: &mut App) {
    cx.bind_keys([KeyBinding::new("delete", EndTask, Some(KEY_CONTEXT))]);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Grouped,
    Tree,
    List,
}

/// Whole-computer use in percent, shown above the column labels.
#[derive(Debug, Clone, Copy, Default)]
struct Totals {
    cpu: f64,
    memory: f64,
    disk: f64,
    gpu: f64,
    vram: f64,
}

#[derive(Debug, Clone, Copy, Default)]
struct Values {
    cpu: f64,
    mem: f64,
    io: f64,
    gpu: f64,
    vram: f64,
    suspended: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Twisty {
    None,
    Open,
    Closed,
}

#[derive(Debug, Clone)]
enum Item {
    Section(String),
    Row {
        key: String,
        depth: usize,
        label: String,
        /// Index into the rows of the last sample.
        row: usize,
        /// Processes this line stands for (more than one for a group).
        members: Vec<usize>,
        twisty: Twisty,
        values: Values,
    },
}

impl Item {
    fn key(&self) -> &str {
        match self {
            Item::Section(label) => label,
            Item::Row { key, .. } => key,
        }
    }
}

/// A column: its key, title, width and how its cells read.
struct Col {
    key: &'static str,
    title: &'static str,
    width: f32,
    numeric: bool,
}

const COLS: [Col; 11] = [
    Col {
        key: "name",
        title: "table.name",
        width: 300.0,
        numeric: false,
    },
    Col {
        key: "status",
        title: "table.status",
        width: 92.0,
        numeric: false,
    },
    Col {
        key: "pid",
        title: "table.pid",
        width: 68.0,
        numeric: true,
    },
    Col {
        key: "cpu",
        title: "table.cpu",
        width: 76.0,
        numeric: true,
    },
    Col {
        key: "mem",
        title: "table.memory",
        width: 100.0,
        numeric: true,
    },
    Col {
        key: "io",
        title: "table.disk",
        width: 88.0,
        numeric: true,
    },
    Col {
        key: "gpu",
        title: "table.gpu",
        width: 64.0,
        numeric: true,
    },
    Col {
        key: "vram",
        title: "table.vram",
        width: 96.0,
        numeric: true,
    },
    Col {
        key: "user",
        title: "table.user",
        width: 128.0,
        numeric: false,
    },
    Col {
        key: "started",
        title: "table.started",
        width: 76.0,
        numeric: true,
    },
    Col {
        key: "path",
        title: "table.path",
        width: 340.0,
        numeric: false,
    },
];

/// The table's data: the last sample, the view, the sort and the selection (by process key, so
/// it follows the process when rows move).
pub struct ProcTable {
    rows: Vec<ProcessRow>,
    gpu: HashMap<u32, GpuUse>,
    items: Vec<Item>,
    view: View,
    filter: String,
    sort: Option<(usize, bool)>,
    group_open: HashMap<String, bool>,
    tree_closed: HashSet<String>,
    selected: Option<String>,
    /// The pointer is over the rows: existing rows keep their order, values stay live.
    hold: bool,
    ranks: Option<HashMap<String, usize>>,
    totals: Option<Totals>,
    memory_total: f64,
    vram_total: f64,
    /// Findings of the last scan whose file runs now: lower-case exe -> verdict.
    marks: HashMap<String, String>,
    now: i64,
    /// Program icons by lower-case path (`None`: the file has none).
    icons: HashMap<String, Option<Arc<Image>>>,
    /// The page, for the rows' context menu.
    page: Option<WeakEntity<ProcessesPage>>,
}

impl ProcTable {
    fn new(marks: HashMap<String, String>) -> Self {
        Self {
            rows: Vec::new(),
            gpu: HashMap::new(),
            items: Vec::new(),
            view: View::Grouped,
            filter: String::new(),
            sort: None,
            group_open: HashMap::new(),
            tree_closed: HashSet::new(),
            selected: None,
            hold: false,
            ranks: None,
            totals: None,
            memory_total: 0.0,
            vram_total: 0.0,
            marks,
            now: now_ms(),
            icons: HashMap::new(),
            page: None,
        }
    }

    /// Moves the selection by `delta` lines (`isize::MIN` / `MAX`: first / last), skipping the
    /// section headings; the selection stays on the same process when rows move. Returns the
    /// line to scroll to.
    fn step(&mut self, delta: isize) -> Option<usize> {
        let lines: Vec<usize> = (0..self.items.len())
            .filter(|&ix| matches!(self.items[ix], Item::Row { .. }))
            .collect();
        if lines.is_empty() {
            return None;
        }
        let current = self
            .selected
            .as_deref()
            .and_then(|key| lines.iter().position(|&ix| self.items[ix].key() == key));
        let next = match (current, delta) {
            (_, isize::MIN) => 0,
            (_, isize::MAX) => lines.len() - 1,
            (None, d) if d < 0 => lines.len() - 1,
            (None, _) => 0,
            (Some(at), d) => (at as isize + d).clamp(0, lines.len() as isize - 1) as usize,
        };
        let ix = lines[next];
        self.selected = Some(self.items[ix].key().to_string());
        Some(ix)
    }

    fn values(&self, members: &[usize]) -> Values {
        let mut v = Values {
            suspended: !members.is_empty(),
            ..Default::default()
        };
        for &m in members {
            let row = &self.rows[m];
            let gpu = self.gpu.get(&row.pid);
            v.cpu += f64::from(row.cpu);
            v.mem += row.private_bytes as f64;
            v.io += row.io_bps;
            v.gpu += gpu.map_or(0.0, |g| f64::from(g.utilization));
            v.vram += gpu.map_or(0.0, |g| g.dedicated as f64);
            v.suspended &= row.status == ProcessStatus::Suspended;
        }
        v.gpu = v.gpu.min(100.0);
        v
    }

    /// The value a column sorts by.
    fn sort_value(&self, item: &Item, col: usize) -> SortValue {
        let Item::Row { row, values, label, .. } = item else {
            return SortValue::Num(0.0);
        };
        let r = &self.rows[*row];
        match COLS[col].key {
            "name" => SortValue::Text(label.to_lowercase()),
            "status" => SortValue::Num(if values.suspended { 1.0 } else { 0.0 }),
            "pid" => SortValue::Num(f64::from(r.pid)),
            "cpu" => SortValue::Num(values.cpu),
            "mem" => SortValue::Num(values.mem),
            "io" => SortValue::Num(values.io),
            "gpu" => SortValue::Num(values.gpu),
            "vram" => SortValue::Num(values.vram),
            "user" => SortValue::Text(r.user.to_lowercase()),
            "started" => SortValue::Num(-(r.created_ms as f64)),
            _ => SortValue::Text(r.exe.to_lowercase()),
        }
    }

    fn compare(&self, a: &Item, b: &Item) -> std::cmp::Ordering {
        if self.hold
            && let Some(ranks) = &self.ranks
        {
            match (ranks.get(a.key()), ranks.get(b.key())) {
                (Some(x), Some(y)) => return x.cmp(y),
                (Some(_), None) => return std::cmp::Ordering::Less,
                (None, Some(_)) => return std::cmp::Ordering::Greater,
                (None, None) => {}
            }
        }
        let (col, descending) = self.sort.unwrap_or((0, false));
        let order = self
            .sort_value(a, col)
            .cmp_with(&self.sort_value(b, col))
            .then_with(|| self.pid_of(a).cmp(&self.pid_of(b)));
        if descending { order.reverse() } else { order }
    }

    fn pid_of(&self, item: &Item) -> u32 {
        match item {
            Item::Row { row, .. } => self.rows[*row].pid,
            Item::Section(_) => 0,
        }
    }

    fn matches(&self, row: &ProcessRow, words: &[String]) -> bool {
        if words.is_empty() {
            return true;
        }
        let text = format!("{} {} {} {} {}", row.name, row.description, row.pid, row.user, row.exe).to_lowercase();
        words.iter().all(|w| text.contains(w.as_str()))
    }

    fn single(&self, index: usize, depth: usize, label: String, twisty: Twisty) -> Item {
        Item::Row {
            key: groups::key(&self.rows[index]),
            depth,
            label,
            row: index,
            members: vec![index],
            twisty,
            values: self.values(&[index]),
        }
    }

    /// Rebuilds the visible lines from the last sample, the view, the filter and the sort.
    fn rebuild(&mut self) {
        let words: Vec<String> = self.filter.split_whitespace().map(str::to_lowercase).collect();
        let mut out: Vec<Item> = Vec::new();
        match self.view {
            View::List => {
                let mut items: Vec<Item> = (0..self.rows.len())
                    .filter(|&i| self.matches(&self.rows[i], &words))
                    .map(|i| self.single(i, 0, self.rows[i].name.clone(), Twisty::None))
                    .collect();
                items.sort_by(|a, b| self.compare(a, b));
                out = items;
            }
            View::Grouped => {
                let entries = groups::group(&self.rows);
                for section in SECTIONS {
                    let mut lines: Vec<(Item, Vec<Item>)> = Vec::new();
                    for entry in entries.iter().filter(|e| e.section == section) {
                        let shown: Vec<usize> = entry
                            .members
                            .iter()
                            .copied()
                            .filter(|&m| self.matches(&self.rows[m], &words))
                            .collect();
                        if shown.is_empty() {
                            continue;
                        }
                        let group = entry.members.len() > 1;
                        let open = group && self.group_open.get(&entry.key).copied().unwrap_or(!words.is_empty());
                        let label = if group {
                            tf(
                                "table.withCount",
                                &[("name", &entry.label), ("count", &num(entry.members.len() as f64, 0))],
                            )
                        } else {
                            entry.label.clone()
                        };
                        let item = Item::Row {
                            key: entry.key.clone(),
                            depth: 0,
                            label,
                            row: entry.main,
                            members: entry.members.clone(),
                            twisty: match (group, open) {
                                (false, _) => Twisty::None,
                                (true, true) => Twisty::Open,
                                (true, false) => Twisty::Closed,
                            },
                            values: self.values(&entry.members),
                        };
                        let mut members: Vec<Item> = if open {
                            shown
                                .iter()
                                .map(|&m| self.single(m, 1, groups::display_name(&self.rows[m]), Twisty::None))
                                .collect()
                        } else {
                            Vec::new()
                        };
                        members.sort_by(|a, b| self.compare(a, b));
                        lines.push((item, members));
                    }
                    if lines.is_empty() {
                        continue;
                    }
                    let name = t(match section {
                        Section::Apps => "proc.groupApps",
                        Section::Background => "proc.groupBackground",
                        Section::Windows => "proc.groupWindows",
                    });
                    out.push(Item::Section(tf(
                        "table.withCount",
                        &[("name", &name), ("count", &num(lines.len() as f64, 0))],
                    )));
                    lines.sort_by(|a, b| self.compare(&a.0, &b.0));
                    for (item, members) in lines {
                        out.push(item);
                        out.extend(members);
                    }
                }
            }
            View::Tree => {
                let by_pid: HashMap<u32, usize> = self.rows.iter().enumerate().map(|(i, r)| (r.pid, i)).collect();
                let mut kids: HashMap<usize, Vec<usize>> = HashMap::new();
                let mut roots: Vec<usize> = Vec::new();
                for (i, r) in self.rows.iter().enumerate() {
                    match by_pid.get(&r.ppid) {
                        Some(&p) if self.rows[p].pid != r.pid && self.rows[p].created_ms <= r.created_ms => {
                            kids.entry(p).or_default().push(i);
                        }
                        _ => roots.push(i),
                    }
                }
                let mut visible: HashMap<usize, bool> = HashMap::new();
                fn check(
                    table: &ProcTable,
                    i: usize,
                    depth: usize,
                    kids: &HashMap<usize, Vec<usize>>,
                    words: &[String],
                    visible: &mut HashMap<usize, bool>,
                ) -> bool {
                    if let Some(&known) = visible.get(&i) {
                        return known;
                    }
                    if depth > 64 {
                        return false;
                    }
                    let mut show = table.matches(&table.rows[i], words);
                    for &child in kids.get(&i).map(Vec::as_slice).unwrap_or(&[]) {
                        show = check(table, child, depth + 1, kids, words, visible) || show;
                    }
                    visible.insert(i, show);
                    show
                }
                for &r in &roots {
                    check(self, r, 0, &kids, &words, &mut visible);
                }
                // Depth-first, each level sorted, at most 64 levels deep.
                let mut ordered: Vec<Item> = Vec::new();
                fn walk(
                    table: &ProcTable,
                    list: &[usize],
                    depth: usize,
                    kids: &HashMap<usize, Vec<usize>>,
                    visible: &HashMap<usize, bool>,
                    words: &[String],
                    out: &mut Vec<Item>,
                ) {
                    if depth > 64 {
                        return;
                    }
                    let mut items: Vec<(Item, Vec<usize>, bool)> = list
                        .iter()
                        .copied()
                        .filter(|i| visible.get(i).copied().unwrap_or(false))
                        .map(|i| {
                            let shown: Vec<usize> = kids
                                .get(&i)
                                .map(Vec::as_slice)
                                .unwrap_or(&[])
                                .iter()
                                .copied()
                                .filter(|c| visible.get(c).copied().unwrap_or(false))
                                .collect();
                            let key = groups::key(&table.rows[i]);
                            let open = !table.tree_closed.contains(&key) || !words.is_empty();
                            let twisty = match (shown.is_empty(), open) {
                                (true, _) => Twisty::None,
                                (false, true) => Twisty::Open,
                                (false, false) => Twisty::Closed,
                            };
                            (table.single(i, depth, table.rows[i].name.clone(), twisty), shown, open)
                        })
                        .collect();
                    items.sort_by(|a, b| table.compare(&a.0, &b.0));
                    for (item, shown, open) in items {
                        out.push(item);
                        if !shown.is_empty() && open {
                            walk(table, &shown, depth + 1, kids, visible, words, out);
                        }
                    }
                }
                walk(self, &roots, 0, &kids, &visible, &words, &mut ordered);
                out = ordered;
            }
        }
        if !self.hold {
            self.ranks = Some(
                out.iter()
                    .enumerate()
                    .map(|(i, item)| (item.key().to_string(), i))
                    .collect(),
            );
        }
        self.items = out;
    }

    fn selected_item(&self) -> Option<&Item> {
        let key = self.selected.as_deref()?;
        self.items.iter().find(|item| item.key() == key)
    }

    fn toggle(&mut self, key: &str, twisty: Twisty) {
        match self.view {
            View::Grouped => {
                self.group_open.insert(key.to_string(), twisty == Twisty::Closed);
            }
            View::Tree => {
                if twisty == Twisty::Open {
                    self.tree_closed.insert(key.to_string());
                } else {
                    self.tree_closed.remove(key);
                }
            }
            View::List => {}
        }
        self.ranks = None;
        self.rebuild();
    }

    fn heat(share: f64) -> usize {
        if share >= 0.4 {
            4
        } else if share >= 0.15 {
            3
        } else if share >= 0.05 {
            2
        } else if share >= 0.01 {
            1
        } else {
            0
        }
    }

    /// The share of the computer a column's value stands for (None: not a resource column).
    fn share(&self, col: usize, v: &Values) -> Option<f64> {
        Some(match COLS[col].key {
            "cpu" => v.cpu / 100.0,
            "mem" if self.memory_total > 0.0 => v.mem / self.memory_total,
            "mem" => 0.0,
            "io" => v.io / DISK_SCALE,
            "gpu" => v.gpu / 100.0,
            "vram" if self.vram_total > 0.0 => v.vram / self.vram_total,
            "vram" => 0.0,
            _ => return None,
        })
    }

    fn total(&self, col: usize) -> Option<f64> {
        let totals = self.totals?;
        Some(match COLS[col].key {
            "cpu" => totals.cpu,
            "mem" => totals.memory,
            "io" => totals.disk,
            "gpu" => totals.gpu,
            "vram" => totals.vram,
            _ => return None,
        })
    }

    fn cell_text(&self, item: &Item, col: usize) -> String {
        let Item::Row {
            row,
            values: v,
            members,
            ..
        } = item
        else {
            return String::new();
        };
        let r = &self.rows[*row];
        let zero = |unit: &str| format!("{} {}", num(0.0, 0), t(unit));
        match COLS[col].key {
            "status" if v.suspended => t("table.suspended"),
            "status" => String::new(),
            "pid" if members.len() > 1 => String::new(),
            "pid" => r.pid.to_string(),
            "cpu" if v.cpu >= 0.05 => pct(v.cpu, 1),
            "cpu" => pct(0.0, 0),
            "mem" => format!("{} {}", num(v.mem / MB, 1), t("unit.MB")),
            "io" if v.io / MB >= 0.05 => format!("{} {}", num(v.io / MB, 1), t("unit.MBps")),
            "io" => zero("unit.MBps"),
            "gpu" => pct(v.gpu, 0),
            "vram" if v.vram > 0.0 => format!("{} {}", num(v.vram / MB, 1), t("unit.MB")),
            "vram" => zero("unit.MB"),
            "user" => r.user.rsplit('\\').next().unwrap_or("").to_string(),
            "started" => age(r.created_ms, self.now),
            "path" => r.exe.clone(),
            _ => String::new(),
        }
    }
}

enum SortValue {
    Num(f64),
    Text(String),
}

impl SortValue {
    fn cmp_with(&self, other: &SortValue) -> std::cmp::Ordering {
        match (self, other) {
            (SortValue::Num(a), SortValue::Num(b)) => a.total_cmp(b),
            (SortValue::Text(a), SortValue::Text(b)) => a.cmp(b),
            (SortValue::Num(_), SortValue::Text(_)) => std::cmp::Ordering::Less,
            (SortValue::Text(_), SortValue::Num(_)) => std::cmp::Ordering::Greater,
        }
    }
}

impl TableDelegate for ProcTable {
    fn columns_count(&self, _cx: &App) -> usize {
        COLS.len()
    }

    fn rows_count(&self, _cx: &App) -> usize {
        self.items.len()
    }

    fn column(&self, col_ix: usize, _cx: &App) -> Column {
        let col = &COLS[col_ix];
        let column = Column::new(col.key, t(col.title))
            .width(px(col.width))
            .min_width(px(if col_ix == 0 { 200.0 } else { 48.0 }))
            .p_0()
            .movable(false)
            .sort(ColumnSort::Default);
        if col.numeric { column.text_right() } else { column }
    }

    fn perform_sort(
        &mut self,
        col_ix: usize,
        sort: ColumnSort,
        _window: &mut Window,
        _cx: &mut Context<TableState<Self>>,
    ) {
        self.sort = match sort {
            ColumnSort::Ascending => Some((col_ix, false)),
            ColumnSort::Descending => Some((col_ix, true)),
            ColumnSort::Default => None,
        };
        self.ranks = None;
        let held = self.hold;
        self.hold = false;
        self.rebuild();
        self.hold = held;
    }

    /// Two lines over a resource column, as in Task Manager: the computer's total, then the name.
    fn render_th(
        &mut self,
        col_ix: usize,
        _window: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        let tk = *tokens(cx);
        let col = &COLS[col_ix];
        let sorted = self.sort.is_some_and(|(c, _)| c == col_ix);
        div()
            .w_full()
            .px_2()
            .flex()
            .flex_col()
            .justify_end()
            .when(col.numeric, |this| this.items_end())
            .when_some(self.total(col_ix), |this, total| {
                this.child(
                    div()
                        .text_size(px(15.))
                        .font_family(FONT_DISPLAY)
                        .text_color(tk.ink)
                        .child(pct(total, 0)),
                )
            })
            .child(
                div()
                    .text_size(px(12.))
                    .text_color(if sorted { tk.ink } else { tk.ink2 })
                    .overflow_hidden()
                    .text_ellipsis()
                    .child(t(col.title)),
            )
    }

    fn render_tr(&mut self, row_ix: usize, _window: &mut Window, cx: &mut Context<TableState<Self>>) -> Stateful<Div> {
        let tk = *tokens(cx);
        let selected = self
            .items
            .get(row_ix)
            .is_some_and(|item| self.selected.as_deref() == Some(item.key()));
        let section = matches!(self.items.get(row_ix), Some(Item::Section(_)));
        div()
            .id(("proc-row", row_ix))
            .when(selected, |this| this.bg(tk.table_select))
            .when(section, |this| this.bg(tk.surface.opacity(0.)))
            .on_click(
                cx.listener(move |table: &mut TableState<ProcTable>, _: &ClickEvent, _, cx| {
                    let delegate = table.delegate_mut();
                    if let Some(Item::Row { key, .. }) = delegate.items.get(row_ix) {
                        delegate.selected = Some(key.clone());
                        cx.notify();
                    }
                }),
            )
    }

    fn render_td(
        &mut self,
        row_ix: usize,
        col_ix: usize,
        _window: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        let tk = *tokens(cx);
        let Some(item) = self.items.get(row_ix).cloned() else {
            return div().into_any_element();
        };
        match &item {
            Item::Section(label) => {
                if col_ix != 0 {
                    return div().into_any_element();
                }
                div()
                    .size_full()
                    .flex()
                    .items_center()
                    .px_2()
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_size(px(13.))
                    .text_color(tk.ink)
                    .child(label.clone())
                    .into_any_element()
            }
            Item::Row {
                key,
                depth,
                label,
                row,
                twisty,
                values,
                ..
            } => {
                let numeric = COLS[col_ix].numeric;
                let cell = div()
                    .size_full()
                    .flex()
                    .items_center()
                    .px_2()
                    .text_size(px(13.))
                    .text_color(tk.ink)
                    .overflow_hidden()
                    .when(numeric, |this| this.justify_end().font_family(FONT_DISPLAY));
                if col_ix == 0 {
                    let mark = self
                        .marks
                        .get(&self.rows[*row].exe.to_lowercase())
                        .map(|verdict| tk.verdict(verdict));
                    let key = key.clone();
                    let twisty = *twisty;
                    let chevron = match twisty {
                        Twisty::Open => Some(icons::CHEVRON_DOWN),
                        Twisty::Closed => Some(icons::CHEVRON_RIGHT),
                        Twisty::None => None,
                    };
                    return cell
                        .gap_1()
                        .pl(px(8.0 + 18.0 * *depth as f32))
                        .child(
                            div()
                                .id(("twisty", row_ix))
                                .w(px(16.))
                                .h(px(16.))
                                .flex()
                                .items_center()
                                .justify_center()
                                .rounded(RADIUS)
                                .when_some(chevron, |this, glyph| {
                                    this.hover(|s| s.bg(tk.hover))
                                        .child(icons::icon(glyph, 10.0, tk.ink2))
                                        .on_click(cx.listener(
                                            move |table: &mut TableState<ProcTable>, _: &ClickEvent, _, cx| {
                                                cx.stop_propagation();
                                                table.delegate_mut().toggle(&key, twisty);
                                                table.refresh(cx);
                                                cx.notify();
                                            },
                                        ))
                                }),
                        )
                        .child(
                            match self.icons.get(&self.rows[*row].exe.to_lowercase()).cloned().flatten() {
                                Some(image) => img(image)
                                    .w(px(16.))
                                    .h(px(16.))
                                    .flex_none()
                                    .object_fit(ObjectFit::Contain)
                                    .into_any_element(),
                                None => icons::icon(icons::APP, 14.0, tk.ink3).into_any_element(),
                            },
                        )
                        .when_some(mark, |this, color| {
                            this.child(div().w(px(8.)).h(px(8.)).rounded(px(4.)).bg(color))
                        })
                        .child(
                            div()
                                .overflow_hidden()
                                .text_ellipsis()
                                .child(crate::ui::kit::plain(label.clone())),
                        )
                        .into_any_element();
                }
                let text = self.cell_text(&item, col_ix);
                let heat = self.share(col_ix, values).map(Self::heat);
                cell.when_some(heat, |this, level| {
                    this.bg(tk.heat[level]).border_l_1().border_color(tk.heat_rule)
                })
                .when(COLS[col_ix].key == "path", |this| this.text_color(tk.ink2))
                .child(
                    div()
                        .overflow_hidden()
                        .text_ellipsis()
                        .child(crate::ui::kit::plain(text)),
                )
                .into_any_element()
            }
        }
    }

    /// Right-click: the row becomes the selection and gets Task Manager's menu.
    fn context_menu(
        &mut self,
        row_ix: usize,
        menu: PopupMenu,
        _window: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> PopupMenu {
        let Some(Item::Row { key, row, .. }) = self.items.get(row_ix) else {
            return menu;
        };
        self.selected = Some(key.clone());
        let row = self.rows[*row].clone();
        let Some(page) = self.page.clone() else {
            return menu;
        };
        let (elevated, busy) = page
            .upgrade()
            .map(|p| {
                let p = p.read(cx);
                (p.elevated, p.acting.busy)
            })
            .unwrap_or((false, true));
        let mut menu = menu;
        for item in ProcessesPage::menu_items(page, "context", Some(&row), elevated, busy) {
            menu = menu.item(item);
        }
        menu
    }

    fn cell_label(&self, row_ix: usize, col_ix: usize, _cx: &App) -> Option<SharedString> {
        let item = self.items.get(row_ix)?;
        Some(match item {
            Item::Section(label) if col_ix == 0 => label.clone().into(),
            Item::Section(_) => return None,
            Item::Row { label, .. } if col_ix == 0 => crate::ui::kit::plain(label.clone()),
            Item::Row { .. } => crate::ui::kit::plain(self.cell_text(item, col_ix)),
        })
    }

    fn visible_rows_changed(
        &mut self,
        _range: Range<usize>,
        _window: &mut Window,
        _cx: &mut Context<TableState<Self>>,
    ) {
    }
}

/// The inspector's tabs under the list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Details,
    Modules,
    Services,
}

/// CPU priority classes, lowest first, with their names.
const PRIORITIES: [(&str, &str); 5] = [
    ("idle", "priority.idle"),
    ("below_normal", "priority.below_normal"),
    ("normal", "priority.normal"),
    ("above_normal", "priority.above_normal"),
    ("high", "priority.high"),
];

/// The Processes page.
pub struct ProcessesPage {
    live: Entity<Live>,
    /// The app, for the dialogs this page opens (Run new task, Processor affinity).
    pub ctx: Option<crate::app::Ctx>,
    table: Entity<TableState<ProcTable>>,
    search: Entity<InputState>,
    core: Option<Arc<AppState>>,
    elevated: bool,
    acting: Acting,
    seen: u64,
    /// A process chosen elsewhere (`--pid`, "Show in Processes"): selected once the list has it.
    pending_pid: Option<u32>,
    tab: Tab,
    /// Modules and hosted services of the selected process, read when its tab opens: (key, details).
    details: Option<(String, Arc<ProcessDetails>)>,
    details_loading: bool,
    /// Program icons asked for (lower-case path); the table holds the decoded ones.
    icons_asked: HashSet<String>,
    focus: FocusHandle,
    _subscriptions: Vec<Subscription>,
}

impl Acts for ProcessesPage {
    fn acting(&mut self) -> &mut Acting {
        &mut self.acting
    }
    fn core(&self) -> Option<Arc<AppState>> {
        self.core.clone()
    }
    fn after(&mut self, _: &mut Window, _: &mut Context<Self>) {
        // The next sample (within a second) shows the change.
    }
}

impl ProcessesPage {
    pub fn new(
        live: Entity<Live>,
        core: Option<Arc<AppState>>,
        focus_pid: Option<u32>,
        elevated: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let marks = core.as_ref().map(|c| finding_marks(c)).unwrap_or_default();
        let page = cx.entity().downgrade();
        let table = cx.new(|cx| {
            let mut delegate = ProcTable::new(marks);
            delegate.page = Some(page);
            TableState::new(delegate, window, cx)
                .row_selectable(false)
                .col_movable(false)
                .sortable(true)
        });
        let search = cx.new(|cx| InputState::new(window, cx).placeholder(t("proc.search")));
        let subscriptions = vec![
            cx.observe(&live, |this, _, cx| this.on_sample(cx)),
            cx.observe(&table, |this, _, cx| {
                this.selection_changed(cx);
                cx.notify();
            }),
            cx.subscribe(&search, |this, input, event: &InputEvent, cx| {
                if matches!(event, InputEvent::Change) {
                    let filter = input.read(cx).value().to_string();
                    this.table.update(cx, |table, cx| {
                        let delegate = table.delegate_mut();
                        delegate.filter = filter;
                        delegate.ranks = None;
                        delegate.rebuild();
                        table.refresh(cx);
                        cx.notify();
                    });
                }
            }),
        ];
        let mut page = Self {
            ctx: None,
            live,
            table,
            search,
            core,
            elevated,
            acting: Acting::default(),
            seen: 0,
            pending_pid: focus_pid,
            tab: Tab::Details,
            details: None,
            details_loading: false,
            icons_asked: HashSet::new(),
            focus: cx.focus_handle(),
            _subscriptions: subscriptions,
        };
        // Keyboard first: Delete ends the selected task, the arrows move the selection.
        window.focus(&page.focus, cx);
        page.on_sample(cx);
        page
    }

    fn on_sample(&mut self, cx: &mut Context<Self>) {
        let live = self.live.read(cx);
        if live.generation == self.seen {
            return;
        }
        self.seen = live.generation;
        let rows = live.processes.clone();
        let (totals, memory_total, vram_total, gpu) = match &live.snapshot {
            Some(snap) => {
                let vram_total: f64 = snap.gpus.iter().map(|g| g.dedicated_total as f64).sum();
                let vram_used: f64 = snap.gpus.iter().map(|g| g.dedicated_used as f64).sum();
                let totals = Totals {
                    cpu: f64::from(snap.cpu),
                    memory: if snap.memory.total > 0 {
                        snap.memory.used as f64 / snap.memory.total as f64 * 100.0
                    } else {
                        0.0
                    },
                    disk: snap.disks.iter().map(|d| f64::from(d.active)).fold(0.0, f64::max),
                    gpu: snap.gpus.iter().map(|g| f64::from(g.utilization)).fold(0.0, f64::max),
                    vram: if vram_total > 0.0 {
                        vram_used / vram_total * 100.0
                    } else {
                        0.0
                    },
                };
                let gpu: HashMap<u32, GpuUse> = snap.gpu_by_pid.iter().map(|g| (g.pid, g.clone())).collect();
                (Some(totals), snap.memory.total as f64, vram_total, gpu)
            }
            None => (None, 0.0, 0.0, HashMap::new()),
        };
        let new_paths: Vec<String> = rows
            .iter()
            .filter(|r| !r.exe.is_empty())
            .map(|r| r.exe.clone())
            .filter(|p| !self.icons_asked.contains(&p.to_lowercase()))
            .collect();
        let pending = self.pending_pid;
        let mut found = false;
        self.table.update(cx, |table, cx| {
            let delegate = table.delegate_mut();
            if let Some(row) = pending.and_then(|pid| rows.iter().find(|r| r.pid == pid)) {
                // A single process, even when it belongs to a group: show it in the list view.
                delegate.selected = Some(groups::key(row));
                delegate.view = View::List;
                found = true;
            }
            delegate.rows = rows;
            delegate.gpu = gpu;
            delegate.totals = totals;
            delegate.memory_total = memory_total;
            delegate.vram_total = vram_total;
            delegate.now = now_ms();
            delegate.rebuild();
            let reveal = found
                .then(|| {
                    let key = delegate.selected.as_deref()?;
                    delegate.items.iter().position(|item| item.key() == key)
                })
                .flatten();
            table.refresh(cx);
            if let Some(index) = reveal {
                table.scroll_to_row(index, cx);
            }
            cx.notify();
        });
        if found {
            self.pending_pid = None;
        }
        self.read_icons(new_paths, cx);
        cx.notify();
    }

    /// Reads the icons of programs not seen yet, in the background (each is read once).
    fn read_icons(&mut self, mut paths: Vec<String>, cx: &mut Context<Self>) {
        paths.sort_by_key(|p| p.to_lowercase());
        paths.dedup_by_key(|p| p.to_lowercase());
        if paths.is_empty() {
            return;
        }
        for path in &paths {
            self.icons_asked.insert(path.to_lowercase());
        }
        let demo = self.core.is_none();
        common::read(
            cx,
            move || {
                paths
                    .into_iter()
                    .take(512)
                    .map(|path| {
                        let image = if demo {
                            None
                        } else {
                            vigil_sys::apps::icon_data_url(&path)
                                .and_then(|url| crate::format::data_url_bytes(&url))
                                .map(|bytes| Arc::new(Image::from_bytes(ImageFormat::Png, bytes)))
                        };
                        (path.to_lowercase(), image)
                    })
                    .collect::<Vec<_>>()
            },
            |page, found, cx| {
                page.table.update(cx, |table, cx| {
                    table.delegate_mut().icons.extend(found);
                    cx.notify();
                });
            },
        );
    }

    /// The selection moved: the inspector's modules and services belong to another process now.
    fn selection_changed(&mut self, cx: &mut Context<Self>) {
        let key = self.table.read(cx).delegate().selected.clone();
        if self.tab != Tab::Details && key.is_some() && self.details.as_ref().map(|(k, _)| k) != key.as_ref() {
            self.read_details(cx);
        }
    }

    fn set_tab(&mut self, tab: Tab, cx: &mut Context<Self>) {
        self.tab = tab;
        if tab != Tab::Details {
            self.read_details(cx);
        }
        cx.notify();
    }

    fn read_details(&mut self, cx: &mut Context<Self>) {
        let Some((row, _, _)) = self.picked(cx) else { return };
        let key = groups::key(&row);
        if self.details.as_ref().is_some_and(|(k, _)| *k == key) || self.details_loading {
            return;
        }
        self.details_loading = true;
        let demo = self.core.is_none();
        let pid = row.pid;
        common::read(
            cx,
            move || {
                if demo {
                    crate::demo::process_details(pid)
                } else {
                    vigil_core::inspect::process_details(pid)
                }
            },
            move |page, details, cx| {
                page.details_loading = false;
                page.details = Some((key, Arc::new(details)));
                page.selection_changed(cx);
            },
        );
    }

    fn set_view(&mut self, view: View, cx: &mut Context<Self>) {
        self.table.update(cx, |table, cx| {
            let delegate = table.delegate_mut();
            delegate.view = view;
            delegate.ranks = None;
            delegate.rebuild();
            table.refresh(cx);
            cx.notify();
        });
    }

    fn step(&mut self, delta: isize, cx: &mut Context<Self>) {
        self.table.update(cx, |table, cx| {
            if let Some(ix) = table.delegate_mut().step(delta) {
                table.scroll_to_row(ix, cx);
            }
            cx.notify();
        });
    }

    /// The selected line: its process, the processes it stands for and its label.
    fn picked(&self, cx: &App) -> Option<(ProcessRow, Vec<ProcessRef>, String)> {
        let table = self.table.read(cx).delegate();
        let Item::Row {
            row, members, label, ..
        } = table.selected_item()?
        else {
            return None;
        };
        let refs = members
            .iter()
            .map(|&m| ProcessRef {
                pid: table.rows[m].pid,
                created_ms: table.rows[m].created_ms,
            })
            .collect();
        Some((table.rows[*row].clone(), refs, label.clone()))
    }

    /// The finding of the last scan for the selected program, if any: (id, verdict).
    fn finding(&self, row: &ProcessRow, cx: &App) -> Option<String> {
        self.table
            .read(cx)
            .delegate()
            .marks
            .get(&row.exe.to_lowercase())
            .cloned()
    }

    /// Sends a process request through the action service (checked, confirmed natively, journaled).
    pub(crate) fn act(&mut self, op: &str, priority: Option<&str>, window: &mut Window, cx: &mut Context<Self>) {
        if op == "run_task" {
            if let Some(ctx) = self.ctx.clone() {
                crate::dialogs::run_task(ctx, window, cx);
            }
            return;
        }
        let Some((row, members, _)) = self.picked(cx) else {
            return;
        };
        if op == "affinity" {
            if let Some(ctx) = self.ctx.clone() {
                let name = format!("{} (PID {})", row.name, row.pid);
                crate::dialogs::affinity(ctx, row.pid, row.created_ms, name, window, cx);
            }
            return;
        }
        let group = members.len() > 1 && matches!(op, "terminate" | "terminate_tree");
        let request = match op {
            "location" | "properties" | "verify" => Request::Shell {
                op: op.into(),
                path: Some(row.exe.clone()),
                url: None,
                name: None,
            },
            _ => Request::Process {
                op: op.to_string(),
                pid: row.pid,
                created_ms: row.created_ms,
                priority: priority.map(str::to_string),
                pids: if group { members } else { Vec::new() },
                cores: Vec::new(),
            },
        };
        common::send(self, request, window, cx);
    }

    /// The menus of the command bar and of a row's context menu, built from the same items.
    fn menu_items(
        page: WeakEntity<ProcessesPage>,
        menu: &'static str,
        row: Option<&ProcessRow>,
        elevated: bool,
        busy: bool,
    ) -> Vec<PopupMenuItem> {
        let can = row.is_some() && !busy;
        let can_end = row.is_some_and(|r| r.pid > 4) && !busy;
        let has_file = row.is_some_and(|r| !r.exe.is_empty());
        let suspended = row.is_some_and(|r| r.status == ProcessStatus::Suspended);
        let item = |label: String, op: &'static str, priority: Option<&'static str>, enabled: bool| {
            let page = page.clone();
            PopupMenuItem::new(label)
                .disabled(!enabled)
                .on_click(move |_, window, cx| {
                    let _ = page.update(cx, |page, cx| page.act(op, priority, window, cx));
                })
        };
        match menu {
            "priority" => {
                let mut items: Vec<PopupMenuItem> = PRIORITIES
                    .iter()
                    .map(|(value, key)| {
                        item(
                            tf("proc.cpuPriority", &[("level", &t(key))]),
                            "priority",
                            Some(value),
                            can,
                        )
                    })
                    .collect();
                items.push(PopupMenuItem::separator());
                items.push(item(t("proc.background"), "background", None, can));
                items.push(PopupMenuItem::separator());
                items.push(item(t("proc.affinity"), "affinity", None, can));
                items
            }
            "file" => vec![
                item(t("proc.location"), "location", None, has_file),
                item(t("proc.properties"), "properties", None, has_file),
                item(t("proc.verify"), "verify", None, has_file),
                PopupMenuItem::separator(),
                item(t("proc.block"), "block", None, has_file && elevated && !busy),
                item(t("proc.quarantine"), "quarantine", None, has_file && elevated && !busy),
            ],
            "more" => vec![
                item(t("proc.endTree"), "terminate_tree", None, can_end),
                if suspended {
                    item(t("proc.resume"), "resume", None, can)
                } else {
                    item(t("proc.suspend"), "suspend", None, can_end)
                },
                item(t("proc.trim"), "trim", None, can),
            ],
            // The row's context menu: Task Manager's order.
            _ => {
                let mut items = vec![
                    item(t("proc.endTask"), "terminate", None, can_end),
                    item(t("proc.endTree"), "terminate_tree", None, can_end),
                    item(t("proc.efficiency"), "efficiency", None, can),
                    if suspended {
                        item(t("proc.resume"), "resume", None, can)
                    } else {
                        item(t("proc.suspend"), "suspend", None, can_end)
                    },
                    PopupMenuItem::separator(),
                ];
                items.extend(Self::menu_items(page.clone(), "file", row, elevated, busy));
                items
            }
        }
    }

    fn render_commandbar(&self, window: &Window, cx: &mut Context<Self>) -> ui::CommandBar {
        let tk = *tokens(cx);
        let picked = self.picked(cx).map(|(row, _, _)| row);
        let busy = self.acting.busy;
        let has_row = picked.is_some();
        let can_end = picked.as_ref().is_some_and(|r| r.pid > 4) && !busy;
        let view = self.table.read(cx).delegate().view;
        let elevated = self.elevated;
        let menu = |id: &'static str, glyph: char, label: String, which: &'static str, enabled: bool| {
            let page = cx.entity().downgrade();
            let row = picked.clone();
            ui::cmd(id, glyph, label).disabled(!enabled).menu(move |menu, _, _| {
                let mut menu = menu;
                for item in Self::menu_items(page.clone(), which, row.as_ref(), elevated, busy) {
                    menu = menu.item(item);
                }
                menu
            })
        };
        let weak = cx.entity().downgrade();
        let views = [t("proc.viewGrouped"), t("proc.viewTree"), t("proc.viewList")];
        let views_width = ui::bar::segmented_width(window, &views.iter().map(String::as_str).collect::<Vec<_>>());
        let [grouped, tree, list] = views;
        ui::CommandBar::new("proc-bar")
            .cmd(
                ui::cmd("run-task", '\u{E7C4}', t("proc.runTask"))
                    .disabled(busy)
                    .on_click(cx.listener(|this, _, window, cx| this.act("run_task", None, window, cx))),
            )
            .cmd(
                ui::cmd("end-task", icons::END_TASK, t("proc.endTask"))
                    .keep()
                    .disabled(!can_end)
                    .on_click(cx.listener(|this, _, window, cx| this.act("terminate", None, window, cx))),
            )
            .cmd(
                ui::cmd("efficiency", icons::EFFICIENCY, t("proc.efficiency"))
                    .disabled(!has_row || busy)
                    .on_click(cx.listener(|this, _, window, cx| this.act("efficiency", None, window, cx))),
            )
            .cmd(menu(
                "priority",
                icons::PRIORITY,
                t("proc.priority"),
                "priority",
                has_row && !busy,
            ))
            .cmd(menu(
                "file",
                icons::FILE,
                t("proc.file"),
                "file",
                picked.as_ref().is_some_and(|r| !r.exe.is_empty()),
            ))
            .cmd(menu("more", icons::MORE, t("proc.more"), "more", has_row))
            .separator()
            .fixed(
                ui::segmented(
                    "proc-view",
                    t("proc.view"),
                    vec![(View::Grouped, grouped), (View::Tree, tree), (View::List, list)],
                    view,
                    move |value, _, cx| {
                        let _ = weak.update(cx, |page, cx| page.set_view(value, cx));
                    },
                    &tk,
                ),
                views_width,
            )
    }

    fn render_inspector(&self, row: &ProcessRow, count: usize, label: &str, cx: &mut Context<Self>) -> Div {
        let tk = *tokens(cx);
        let dash = |text: &str| {
            if text.is_empty() {
                "—".to_string()
            } else {
                text.to_string()
            }
        };
        let state = if row.status == ProcessStatus::Suspended {
            t("proc.stateSuspended")
        } else {
            t("proc.stateRunning")
        };
        let mut head = String::new();
        if count > 1 {
            head.push_str(&tn("proc.count", count as u64, &[]));
            head.push_str(" · ");
        }
        head.push_str(&tf(
            "proc.ids",
            &[("pid", &row.pid.to_string()), ("ppid", &row.ppid.to_string())],
        ));
        head.push_str(" · ");
        head.push_str(&state);
        let key = groups::key(row);
        let shown = self
            .details
            .as_ref()
            .filter(|(k, _)| *k == key)
            .map(|(_, d)| Arc::clone(d));
        let writable = shown
            .as_ref()
            .map_or(0, |d| d.modules.iter().filter(|m| m.user_writable).count());
        let finding = self.finding(row, cx);
        let weak = cx.entity().downgrade();
        let mut modules_label = t("proc.tabModules");
        if writable > 0 {
            modules_label = format!("{modules_label} ({writable})");
        }
        let tabs = ui::segmented(
            "proc-tab",
            t("proc.tabDetails"),
            vec![
                (Tab::Details, t("proc.tabDetails")),
                (Tab::Modules, modules_label),
                (Tab::Services, t("proc.tabServices")),
            ],
            self.tab,
            move |tab, _, cx| {
                let _ = weak.update(cx, |page, cx| page.set_tab(tab, cx));
            },
            &tk,
        );
        let body: AnyElement = match (self.tab, shown) {
            (Tab::Details, _) => div()
                .flex()
                .flex_col()
                .gap_1()
                .child(ui::fact(t("proc.path"), dash(&row.exe), true, &tk))
                .child(ui::fact(t("proc.commandLine"), dash(&row.cmdline), true, &tk))
                .child(ui::fact(t("proc.user"), dash(&row.user), false, &tk))
                .child(ui::fact(
                    t("proc.started"),
                    tf("proc.startedAgo", &[("age", &age(row.created_ms, now_ms()))]),
                    false,
                    &tk,
                ))
                .child(ui::fact(
                    t("proc.memory"),
                    tf(
                        "proc.memoryValue",
                        &[
                            ("private", &size(row.private_bytes as f64, 1)),
                            ("working", &size(row.working_set as f64, 1)),
                        ],
                    ),
                    false,
                    &tk,
                ))
                .child(ui::fact(
                    t("proc.threadsHandles"),
                    format!(
                        "{} · {}",
                        num(f64::from(row.threads), 0),
                        num(f64::from(row.handles), 0)
                    ),
                    false,
                    &tk,
                ))
                .into_any_element(),
            (Tab::Modules, None) => faint(
                if self.details_loading {
                    t("proc.readingModules")
                } else {
                    String::new()
                },
                &tk,
            ),
            (Tab::Modules, Some(details)) => match &details.modules_error {
                Some(error) => faint(format!("{error} {}", t("proc.modulesDenied")), &tk),
                None => {
                    let mut modules: Vec<_> = details.modules.iter().collect();
                    modules.sort_by_key(|m| !m.user_writable);
                    let mut line = tn("proc.modulesLoaded", modules.len() as u64, &[]);
                    if writable > 0 {
                        line.push_str(" · ");
                        line.push_str(&tn("proc.modulesWritable", writable as u64, &[]));
                    }
                    div()
                        .flex()
                        .flex_col()
                        .gap_1()
                        .child(faint(line, &tk))
                        .child(
                            div()
                                .id("modules")
                                .max_h(px(168.))
                                .overflow_y_scroll()
                                .border_1()
                                .border_color(tk.rule)
                                .rounded(RADIUS)
                                .children(modules.into_iter().take(400).map(|m| {
                                    div()
                                        .flex()
                                        .gap_3()
                                        .px_2()
                                        .h(px(24.))
                                        .items_center()
                                        .text_size(px(13.))
                                        .when(m.user_writable, |this| {
                                            this.text_color(tk.warn).font_weight(FontWeight::SEMIBOLD)
                                        })
                                        .child(
                                            div()
                                                .w(px(200.))
                                                .flex_none()
                                                .overflow_hidden()
                                                .text_ellipsis()
                                                .child(crate::ui::kit::plain(m.name.clone())),
                                        )
                                        .child(
                                            div()
                                                .flex_1()
                                                .min_w_0()
                                                .overflow_hidden()
                                                .text_ellipsis()
                                                .font_family(FONT_MONO)
                                                .text_size(px(12.))
                                                .child(m.path.clone()),
                                        )
                                        .child(div().w(px(80.)).flex_none().text_right().child(size(m.size as f64, 0)))
                                })),
                        )
                        .into_any_element()
                }
            },
            (Tab::Services, None) => faint(
                if self.details_loading {
                    t("proc.readingServices")
                } else {
                    String::new()
                },
                &tk,
            ),
            (Tab::Services, Some(details)) if details.services.is_empty() => faint(t("proc.noServices"), &tk),
            (Tab::Services, Some(details)) => div()
                .id("hosted")
                .max_h(px(168.))
                .overflow_y_scroll()
                .border_1()
                .border_color(tk.rule)
                .rounded(RADIUS)
                .children(details.services.iter().map(|s| {
                    div()
                        .flex()
                        .gap_3()
                        .px_2()
                        .h(px(24.))
                        .items_center()
                        .text_size(px(13.))
                        .child(
                            div()
                                .w(px(220.))
                                .flex_none()
                                .font_family(FONT_MONO)
                                .text_size(px(12.))
                                .child(s.name.clone()),
                        )
                        .child(
                            div()
                                .flex_1()
                                .overflow_hidden()
                                .text_ellipsis()
                                .child(crate::ui::kit::plain(s.display_name.clone())),
                        )
                }))
                .into_any_element(),
        };
        ui::card(&tk)
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .pb_1()
                    .child(div().font_weight(FontWeight::SEMIBOLD).child(label.to_string()))
                    .child(div().text_size(px(12.)).text_color(tk.ink3).child(head))
                    .when_some(finding, |this, verdict| {
                        this.child(
                            div()
                                .flex()
                                .items_center()
                                .gap_2()
                                .text_size(px(12.))
                                .child(div().w(px(8.)).h(px(8.)).rounded(px(4.)).bg(tk.verdict(&verdict)))
                                .child(t("proc.showFinding")),
                        )
                    })
                    .child(div().flex_1())
                    .child(tabs),
            )
            .child(body)
    }
}

fn faint(text: String, tk: &Tokens) -> AnyElement {
    div()
        .text_size(px(12.))
        .text_color(tk.ink3)
        .child(text)
        .into_any_element()
}

/// Findings of the last scan to mark in the list: lower-case exe path -> verdict.
fn finding_marks(core: &AppState) -> HashMap<String, String> {
    let inner = core.lock();
    let items = inner
        .analysis_json
        .as_ref()
        .and_then(|a| a.get("items"))
        .and_then(serde_json::Value::as_array);
    items
        .into_iter()
        .flatten()
        .filter_map(|item| {
            let text = |key: &str| item.get(key).and_then(serde_json::Value::as_str).unwrap_or("");
            let verdict = text("verdict");
            let path = text("path");
            (!path.is_empty() && matches!(verdict, "remove" | "disable" | "review"))
                .then(|| (path.to_lowercase(), verdict.to_string()))
        })
        .collect()
}

impl Render for ProcessesPage {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let picked = self.picked(cx);
        let live = self.live.read(cx);
        let count = live.processes.len();
        let suspended_count = live
            .processes
            .iter()
            .filter(|r| r.status == ProcessStatus::Suspended)
            .count();
        let usage = live.snapshot.as_ref().map(|snap| {
            tf(
                "proc.usage",
                &[
                    ("cpu", &pct(f64::from(snap.cpu), 0)),
                    (
                        "memory",
                        &pct(snap.memory.used as f64 / (snap.memory.total.max(1)) as f64 * 100.0, 0),
                    ),
                    ("total", &size(snap.memory.total as f64, 0)),
                ],
            )
        });
        let error = live.error.clone();
        let held = self.table.read(cx).delegate().hold;
        let mut footer = vec![tn("proc.count", count as u64, &[])];
        if suspended_count > 0 {
            footer.push(tn("proc.suspendedCount", suspended_count as u64, &[]));
        }
        if held {
            footer.push(t("proc.held"));
        }
        footer.extend(usage);
        let table = self.table.clone();

        div()
            .key_context(KEY_CONTEXT)
            .track_focus(&self.focus)
            .on_action(cx.listener(|this, _: &EndTask, window, cx| {
                if !this.acting.busy {
                    this.act("terminate", None, window, cx);
                }
            }))
            .on_action(cx.listener(|this, _: &grid::SelectPrevious, _, cx| this.step(-1, cx)))
            .on_action(cx.listener(|this, _: &grid::SelectNext, _, cx| this.step(1, cx)))
            .on_action(cx.listener(|this, _: &grid::SelectFirst, _, cx| this.step(isize::MIN, cx)))
            .on_action(cx.listener(|this, _: &grid::SelectLast, _, cx| this.step(isize::MAX, cx)))
            .on_action(cx.listener(|this, _: &grid::PagePrevious, _, cx| this.step(-grid::PAGE, cx)))
            .on_action(cx.listener(|this, _: &grid::PageNext, _, cx| this.step(grid::PAGE, cx)))
            .size_full()
            .flex()
            .flex_col()
            .gap_2()
            .px(px(20.))
            .pt(px(10.))
            .pb(px(12.))
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
                    .gap_2()
                    .min_h(px(40.))
                    .child(ui::page_title(t("page.processes")))
                    .child(self.render_commandbar(window, cx)),
            )
            .children(self.acting.bar("proc-result", &tk))
            .when_some(error, |this, error| {
                this.child(div().text_size(px(12.)).text_color(tk.warn).child(error))
            })
            .child(
                div()
                    .id("proc-rows")
                    .flex_1()
                    .min_h_0()
                    .rounded(RADIUS_CARD)
                    .border_1()
                    .border_color(tk.rule)
                    .bg(tk.surface)
                    .overflow_hidden()
                    .on_hover(cx.listener(move |this, hovered: &bool, _, cx| {
                        let hovered = *hovered;
                        this.table.update(cx, |table, cx| {
                            let delegate = table.delegate_mut();
                            delegate.hold = hovered;
                            if !hovered {
                                delegate.rebuild();
                            }
                            cx.notify();
                        });
                    }))
                    .child(
                        DataTable::new(&table)
                            .with_size(Size::Size(px(ROW_HEIGHT)))
                            .header_row_height(px(52.))
                            .bordered(false)
                            .stripe(false)
                            .accessibility_label(t("page.processes")),
                    ),
            )
            .when_some(picked, |this, (row, members, label)| {
                this.child(self.render_inspector(&row, members.len(), &label, cx))
            })
            .child(
                div()
                    .pl_1()
                    .text_size(px(12.))
                    .text_color(tk.ink3)
                    .child(footer.join(" · ")),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table_with(rows: Vec<ProcessRow>, view: View) -> ProcTable {
        let mut table = ProcTable::new(HashMap::new());
        table.rows = rows;
        table.view = view;
        table.rebuild();
        table
    }

    fn row(pid: u32, ppid: u32, name: &str, exe: &str, window: bool, cpu: f32) -> ProcessRow {
        let mut r = crate::demo::processes(0, 0)[0].clone();
        r.pid = pid;
        r.ppid = ppid;
        r.name = name.into();
        r.exe = exe.into();
        r.window = window;
        r.cpu = cpu;
        r.created_ms = i64::from(pid);
        r.description = String::new();
        r
    }

    #[test]
    fn grouped_view_has_sections_and_groups() {
        let rows = crate::demo::processes(0, 10_000_000);
        let table = table_with(rows, View::Grouped);
        let sections: Vec<&Item> = table.items.iter().filter(|i| matches!(i, Item::Section(_))).collect();
        assert_eq!(sections.len(), 3);
        assert!(matches!(table.items.first(), Some(Item::Section(_))));
    }

    #[test]
    fn sorting_by_cpu_puts_the_busiest_first() {
        let rows = vec![
            row(10, 0, "a.exe", r"C:\Program Files\Contoso\a.exe", false, 1.0),
            row(11, 0, "b.exe", r"C:\Program Files\Contoso\b.exe", false, 9.0),
            row(12, 0, "c.exe", r"C:\Program Files\Contoso\c.exe", false, 4.0),
        ];
        let mut table = table_with(rows, View::List);
        table.sort = Some((3, true));
        table.rebuild();
        let pids: Vec<u32> = table.items.iter().map(|i| table.pid_of(i)).collect();
        assert_eq!(pids, [11, 12, 10]);
    }

    #[test]
    fn the_order_holds_while_pointed_at() {
        let rows = vec![
            row(10, 0, "a.exe", r"C:\Program Files\Contoso\a.exe", false, 1.0),
            row(11, 0, "b.exe", r"C:\Program Files\Contoso\b.exe", false, 9.0),
        ];
        let mut table = table_with(rows, View::List);
        table.sort = Some((3, true));
        table.rebuild();
        table.hold = true;
        table.rows[0].cpu = 50.0;
        table.rebuild();
        let pids: Vec<u32> = table.items.iter().map(|i| table.pid_of(i)).collect();
        assert_eq!(pids, [11, 10], "rows keep their place while the pointer is over them");
        table.hold = false;
        table.rebuild();
        let pids: Vec<u32> = table.items.iter().map(|i| table.pid_of(i)).collect();
        assert_eq!(pids, [10, 11]);
    }

    #[test]
    fn the_filter_matches_every_word() {
        let rows = crate::demo::processes(0, 10_000_000);
        let mut table = table_with(rows, View::List);
        table.filter = "contoso mail".into();
        table.rebuild();
        assert!(!table.items.is_empty());
        assert!(
            table
                .items
                .iter()
                .all(|i| matches!(i, Item::Row { label, .. } if label == "ContosoMail.exe"))
        );
    }

    #[test]
    fn the_tree_nests_children_under_parents() {
        let rows = vec![
            row(10, 0, "parent.exe", r"C:\Program Files\Contoso\parent.exe", false, 0.0),
            row(11, 10, "child.exe", r"C:\Program Files\Contoso\child.exe", false, 0.0),
        ];
        let table = table_with(rows, View::Tree);
        let depths: Vec<usize> = table
            .items
            .iter()
            .filter_map(|i| match i {
                Item::Row { depth, .. } => Some(*depth),
                Item::Section(_) => None,
            })
            .collect();
        assert_eq!(depths, [0, 1]);
    }
}
