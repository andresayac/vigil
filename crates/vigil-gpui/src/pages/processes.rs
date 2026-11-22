//! The Processes page, ported from `ui/src/pages/Processes.svelte` and `ProcessTable.svelte`:
//! Task Manager's grouped view (Apps, Background processes, Windows processes), the process tree
//! and a flat list, live once a second, in a virtualized table (gpui-component's `DataTable`) with
//! sortable, resizable columns and the heat map. Ending a process goes through the action service.
//!
//! Process names, paths, command lines and users come from the inspected computer and may come
//! from malware: GPUI draws them as plain text, never as markup.

use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::sync::Arc;

use futures::StreamExt as _;
use futures::channel::mpsc;
use gpui_kit::component::input::{Input, InputEvent, InputState};
use gpui_kit::component::table::{Column, ColumnSort, DataTable, TableDelegate, TableState};
use gpui_kit::component::{Sizable, Size};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    App, AppContext, ClickEvent, Context, Div, Entity, FocusHandle, FontWeight, InteractiveElement, IntoElement,
    KeyBinding, ParentElement, Render, SharedString, Stateful, StatefulInteractiveElement, Styled, Subscription,
    Window, div, px,
};
use vigil_core::requests::{ProcessRef, Request};
use vigil_core::state::AppState;
use vigil_sys::metrics::GpuUse;
use vigil_sys::process::{ProcessRow, ProcessStatus};

use crate::actions::{self, Outcome};
use crate::format::{age, now_ms, num, pct, size};
use crate::groups::{self, SECTIONS, Section};
use crate::i18n::{t, tf, tn};
use crate::icons;
use crate::live::Live;
use crate::theme::{FONT_DISPLAY, FONT_MONO, RADIUS, RADIUS_CARD, Tokens, tokens};

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
        }
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
                        .when_some(mark, |this, color| {
                            this.child(div().w(px(8.)).h(px(8.)).rounded(px(4.)).bg(color))
                        })
                        .child(div().overflow_hidden().text_ellipsis().child(label.clone()))
                        .into_any_element();
                }
                let text = self.cell_text(&item, col_ix);
                let heat = self.share(col_ix, values).map(Self::heat);
                cell.when_some(heat, |this, level| {
                    this.bg(tk.heat[level]).border_l_1().border_color(tk.heat_rule)
                })
                .when(COLS[col_ix].key == "path", |this| this.text_color(tk.ink2))
                .child(div().overflow_hidden().text_ellipsis().child(text))
                .into_any_element()
            }
        }
    }

    fn cell_label(&self, row_ix: usize, col_ix: usize, _cx: &App) -> Option<SharedString> {
        let item = self.items.get(row_ix)?;
        Some(match item {
            Item::Section(label) if col_ix == 0 => label.clone().into(),
            Item::Section(_) => return None,
            Item::Row { label, .. } if col_ix == 0 => label.clone().into(),
            Item::Row { .. } => self.cell_text(item, col_ix).into(),
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

/// The Processes page.
pub struct ProcessesPage {
    live: Entity<Live>,
    table: Entity<TableState<ProcTable>>,
    search: Entity<InputState>,
    core: Option<Arc<AppState>>,
    busy: bool,
    outcome: Option<Outcome>,
    progress: Option<String>,
    seen: u64,
    /// A process chosen elsewhere (`--pid`, "Show in Processes"): selected once the list has it.
    pending_pid: Option<u32>,
    focus: FocusHandle,
    _subscriptions: Vec<Subscription>,
}

impl ProcessesPage {
    pub fn new(
        live: Entity<Live>,
        core: Option<Arc<AppState>>,
        focus_pid: Option<u32>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let marks = core.as_ref().map(|c| finding_marks(c)).unwrap_or_default();
        let table = cx.new(|cx| {
            TableState::new(ProcTable::new(marks), window, cx)
                .row_selectable(false)
                .col_movable(false)
                .sortable(true)
        });
        let search = cx.new(|cx| InputState::new(window, cx).placeholder(t("proc.search")));
        let subscriptions = vec![
            cx.observe(&live, |this, _, cx| this.on_sample(cx)),
            cx.observe(&table, |_, _, cx| cx.notify()),
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
            live,
            table,
            search,
            core,
            busy: false,
            outcome: None,
            progress: None,
            seen: 0,
            pending_pid: focus_pid,
            focus: cx.focus_handle(),
            _subscriptions: subscriptions,
        };
        // Keyboard first: Delete ends the selected task, as in Task Manager.
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
            table.refresh(cx);
            cx.notify();
        });
        if found {
            self.pending_pid = None;
        }
        cx.notify();
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

    /// Sends a process request through the action service (checked, confirmed natively, journaled).
    fn act(&mut self, op: &str, window: &mut Window, cx: &mut Context<Self>) {
        let Some((row, members, _)) = self.picked(cx) else {
            return;
        };
        let Some(core) = self.core.clone() else {
            self.outcome = Some(Outcome::Failed(t("gpui.demoNoActions")));
            cx.notify();
            return;
        };
        let group = members.len() > 1 && matches!(op, "terminate" | "terminate_tree");
        let request = Request::Process {
            op: op.to_string(),
            pid: row.pid,
            created_ms: row.created_ms,
            priority: None,
            pids: if group { members } else { Vec::new() },
            cores: Vec::new(),
        };
        let (progress_tx, mut progress_rx) = mpsc::unbounded::<String>();
        let done = actions::run(core, request, crate::win::hwnd(window), progress_tx);
        self.busy = true;
        self.outcome = None;
        cx.notify();
        cx.spawn(async move |this, cx| {
            let follow = this.clone();
            let mut cx2 = cx.clone();
            let progress = async move {
                while let Some(line) = progress_rx.next().await {
                    let _ = follow.update(&mut cx2, |page, cx| {
                        page.progress = Some(line);
                        cx.notify();
                    });
                }
            };
            let (outcome, ()) = futures::join!(done, progress);
            let _ = this.update(cx, |page, cx| {
                page.busy = false;
                page.progress = None;
                page.outcome = Some(outcome.unwrap_or(Outcome::Cancelled));
                cx.notify();
            });
        })
        .detach();
    }

    fn render_commandbar(&self, has_row: bool, can_end: bool, suspended: bool, cx: &mut Context<Self>) -> Div {
        let tk = *tokens(cx);
        let view = self.table.read(cx).delegate().view;
        let busy = self.busy;
        let command = |id: &'static str, glyph: char, label: String, enabled: bool| {
            div()
                .id(id)
                .flex()
                .items_center()
                .gap_2()
                .h(px(32.))
                .px_3()
                .rounded(RADIUS)
                .text_color(if enabled { tk.ink } else { tk.ink_disabled })
                .when(enabled, |this| {
                    this.hover(|s| s.bg(tk.hover)).active(|s| s.bg(tk.pressed))
                })
                .child(icons::icon(glyph, 16.0, if enabled { tk.ink } else { tk.ink_disabled }))
                .child(label)
        };
        let segment = |id: &'static str, label: String, on: bool| {
            div()
                .id(id)
                .px(px(10.))
                .h(px(26.))
                .flex()
                .items_center()
                .rounded(px(3.))
                .text_size(px(13.))
                .border_1()
                .border_color(if on { tk.control_stroke } else { tk.surface.opacity(0.) })
                .when(on, |this| {
                    this.bg(tk.surface).text_color(tk.ink).font_weight(FontWeight::SEMIBOLD)
                })
                .when(!on, |this| this.text_color(tk.ink2).hover(|s| s.bg(tk.hover)))
                .child(label)
        };
        div()
            .flex()
            .items_center()
            .gap_1()
            .child(
                command("end-task", icons::END_TASK, t("proc.endTask"), can_end && !busy).when(
                    can_end && !busy,
                    |this| {
                        this.on_click(cx.listener(|this, _: &ClickEvent, window, cx| this.act("terminate", window, cx)))
                    },
                ),
            )
            .child(
                command("efficiency", icons::EFFICIENCY, t("proc.efficiency"), has_row && !busy).when(
                    has_row && !busy,
                    |this| {
                        this.on_click(
                            cx.listener(|this, _: &ClickEvent, window, cx| this.act("efficiency", window, cx)),
                        )
                    },
                ),
            )
            .child(if suspended {
                command("resume", icons::RESUME, t("proc.resume"), has_row && !busy).when(has_row && !busy, |this| {
                    this.on_click(cx.listener(|this, _: &ClickEvent, window, cx| this.act("resume", window, cx)))
                })
            } else {
                command("suspend", icons::SUSPEND, t("proc.suspend"), can_end && !busy).when(can_end && !busy, |this| {
                    this.on_click(cx.listener(|this, _: &ClickEvent, window, cx| this.act("suspend", window, cx)))
                })
            })
            .child(
                command("location", icons::FOLDER, t("proc.location"), has_row).when(has_row, |this| {
                    this.on_click(cx.listener(|this, _: &ClickEvent, window, cx| this.act("location", window, cx)))
                }),
            )
            .child(
                command("verify", icons::VERIFY, t("proc.verify"), has_row && !busy).when(has_row && !busy, |this| {
                    this.on_click(cx.listener(|this, _: &ClickEvent, window, cx| this.act("verify", window, cx)))
                }),
            )
            .child(div().w(px(1.)).h(px(20.)).mx(px(6.)).bg(tk.rule_strong))
            .child(
                div()
                    .flex()
                    .gap(px(2.))
                    .p(px(2.))
                    .rounded(RADIUS)
                    .bg(tk.control)
                    .border_1()
                    .border_color(tk.control_stroke)
                    .child(
                        segment("view-grouped", t("proc.viewGrouped"), view == View::Grouped)
                            .on_click(cx.listener(|this, _: &ClickEvent, _, cx| this.set_view(View::Grouped, cx))),
                    )
                    .child(
                        segment("view-tree", t("proc.viewTree"), view == View::Tree)
                            .on_click(cx.listener(|this, _: &ClickEvent, _, cx| this.set_view(View::Tree, cx))),
                    )
                    .child(
                        segment("view-list", t("proc.viewList"), view == View::List)
                            .on_click(cx.listener(|this, _: &ClickEvent, _, cx| this.set_view(View::List, cx))),
                    ),
            )
    }

    fn render_details(&self, row: &ProcessRow, count: usize, label: &str, tk: &Tokens) -> Div {
        let line = |name: String, value: String, mono: bool| {
            div()
                .flex()
                .gap_3()
                .text_size(px(13.))
                .child(div().w(px(130.)).flex_none().text_color(tk.ink3).child(name))
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .overflow_hidden()
                        .text_ellipsis()
                        .when(mono, |this| this.font_family(FONT_MONO).text_size(px(12.)))
                        .child(value),
                )
        };
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
        div()
            .flex_none()
            .flex()
            .flex_col()
            .gap_1()
            .p_4()
            .bg(tk.surface)
            .border_1()
            .border_color(tk.rule)
            .rounded(RADIUS_CARD)
            .child(
                div()
                    .flex()
                    .items_baseline()
                    .gap_3()
                    .pb_1()
                    .child(div().font_weight(FontWeight::SEMIBOLD).child(label.to_string()))
                    .child(div().text_size(px(12.)).text_color(tk.ink3).child(head)),
            )
            .child(line(t("proc.path"), dash(&row.exe), true))
            .child(line(t("proc.commandLine"), dash(&row.cmdline), true))
            .child(line(t("proc.user"), dash(&row.user), false))
            .child(line(
                t("proc.started"),
                tf("proc.startedAgo", &[("age", &age(row.created_ms, now_ms()))]),
                false,
            ))
            .child(line(
                t("proc.memory"),
                tf(
                    "proc.memoryValue",
                    &[
                        ("private", &size(row.private_bytes as f64, 1)),
                        ("working", &size(row.working_set as f64, 1)),
                    ],
                ),
                false,
            ))
            .child(line(
                t("proc.threadsHandles"),
                format!(
                    "{} · {}",
                    num(f64::from(row.threads), 0),
                    num(f64::from(row.handles), 0)
                ),
                false,
            ))
    }
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
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let picked = self.picked(cx);
        let has_row = picked.is_some();
        let can_end = picked.as_ref().is_some_and(|(row, _, _)| row.pid > 4);
        let suspended = picked
            .as_ref()
            .is_some_and(|(row, _, _)| row.status == ProcessStatus::Suspended);
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
        let outcome = match (&self.progress, &self.outcome) {
            (Some(line), _) => Some((line.clone(), tk.ink2)),
            (None, Some(Outcome::Done(lines))) if !lines.is_empty() => Some((lines.join("\n"), tk.ink)),
            (None, Some(Outcome::Failed(error))) => Some((error.clone(), tk.bad)),
            _ => None,
        };
        let table = self.table.clone();

        div()
            .key_context(KEY_CONTEXT)
            .track_focus(&self.focus)
            .on_action(cx.listener(|this, _: &EndTask, window, cx| {
                if !this.busy {
                    this.act("terminate", window, cx);
                }
            }))
            .size_full()
            .flex()
            .flex_col()
            .gap_2()
            .px(px(20.))
            .pt(px(10.))
            .pb(px(12.))
            .child(
                div().flex().justify_center().child(
                    div().w(px(640.)).max_w_full().child(
                        Input::new(&self.search)
                            .prefix(icons::icon(icons::SEARCH, 14.0, tk.ink2))
                            .cleanable(true),
                    ),
                ),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .min_h(px(40.))
                    .child(
                        div()
                            .pl_1()
                            .font_family(FONT_DISPLAY)
                            .text_size(px(20.))
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(t("page.processes")),
                    )
                    .child(div().flex_1())
                    .child(self.render_commandbar(has_row, can_end, suspended, cx)),
            )
            .when_some(outcome, |this, (text, color)| {
                this.child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .px_3()
                        .py_2()
                        .rounded(RADIUS)
                        .bg(tk.flyout)
                        .border_1()
                        .border_color(tk.rule)
                        .child(icons::icon(icons::INFO, 16.0, tk.accent))
                        .child(div().text_color(color).text_size(px(13.)).child(text)),
                )
            })
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
                this.child(self.render_details(&row, members.len(), &label, &tk))
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
