//! The command palette (Ctrl+K): a search box over the window that jumps to a page or opens a
//! process, service, startup app, task, program, firewall rule, extension, finding or alert on its
//! page. It only navigates: no action runs from it (see `search.rs` for what it searches).

use std::rc::Rc;

use gpui_kit::component::input::{InputEvent, InputState};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    App, AppContext as _, Context, ElementId, Entity, FontWeight, InteractiveElement as _, IntoElement, MouseButton,
    ParentElement, Render, Role, ScrollHandle, SharedString, StatefulInteractiveElement as _, Styled, Subscription,
    Window, div, px, relative,
};

use crate::i18n::{t, tf, tn};
use crate::icons;
use crate::search::{self, Entry, Group, Kind, Target};
use crate::theme::{RADIUS_CARD, tokens};
use crate::ui::{self, kit};

/// What opening a result does (the shell carries it out).
pub type OnPick = Rc<dyn Fn(Target, &mut Window, &mut App)>;
/// Closing the palette.
pub type OnClose = Rc<dyn Fn(&mut Window, &mut App)>;

/// Results shown per group, and in all.
const PER_GROUP: usize = 6;
const LIMIT: usize = 40;

pub struct Palette {
    input: Entity<InputState>,
    entries: Vec<Entry>,
    /// The remembered kinds no page has read yet.
    missing: Vec<Kind>,
    query: String,
    groups: Vec<Group>,
    rows: Vec<usize>,
    selected: usize,
    scroll: ScrollHandle,
    on_pick: OnPick,
    on_close: OnClose,
    _subscriptions: Vec<Subscription>,
}

impl Palette {
    pub fn new(
        entries: Vec<Entry>,
        missing: Vec<Kind>,
        on_pick: OnPick,
        on_close: OnClose,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let input = cx.new(|cx| InputState::new(window, cx).placeholder(t("palette.placeholder")));
        let subscriptions =
            vec![cx.subscribe_in(
                &input,
                window,
                |this, input, event: &InputEvent, window, cx| match event {
                    InputEvent::Change => {
                        this.query = input.read(cx).value().to_string();
                        this.refresh(cx);
                    }
                    InputEvent::PressEnter { .. } => this.open(this.selected, window, cx),
                    _ => {}
                },
            )];
        input.update(cx, |state, cx| state.focus(window, cx));
        let mut palette = Self {
            input,
            entries,
            missing,
            query: String::new(),
            groups: Vec::new(),
            rows: Vec::new(),
            selected: 0,
            scroll: ScrollHandle::new(),
            on_pick,
            on_close,
            _subscriptions: subscriptions,
        };
        palette.refresh(cx);
        palette
    }

    fn refresh(&mut self, cx: &mut Context<Self>) {
        // Nothing typed: every page, as a list to jump to.
        let per_group = if self.query.trim().is_empty() { LIMIT } else { PER_GROUP };
        self.groups = search::search(&self.entries, &self.query, per_group, LIMIT);
        self.rows = search::rows(&self.groups);
        self.selected = 0;
        self.scroll.scroll_to_item(0);
        cx.notify();
    }

    /// A key the shell intercepted while the palette is open (it moves the selection); true when
    /// the palette used it. Enter and Escape are the shell's: it closes the palette itself.
    pub fn key(&mut self, key: &str, cx: &mut Context<Self>) -> bool {
        let delta = match key {
            "up" => -1,
            "down" => 1,
            "pageup" => -(PER_GROUP as isize),
            "pagedown" => PER_GROUP as isize,
            _ => return false,
        };
        self.selected = search::step(self.selected, self.rows.len(), delta);
        self.scroll.scroll_to_item(self.child_index(self.selected));
        cx.notify();
        true
    }

    /// Types `text` in the search box (the `--dialog search=<text>` preview).
    pub fn set_query(&mut self, text: &str, window: &mut Window, cx: &mut Context<Self>) {
        self.input
            .update(cx, |state, cx| state.set_value(text.to_string(), window, cx));
        self.query = text.to_string();
        self.refresh(cx);
    }

    /// What opening the selected result does.
    pub fn selected_target(&self) -> Option<Target> {
        self.rows
            .get(self.selected)
            .map(|&index| self.entries[index].target.clone())
    }

    /// The child of the result list that shows row `row` (each group starts with its heading).
    fn child_index(&self, row: usize) -> usize {
        let mut seen = 0;
        for (g, group) in self.groups.iter().enumerate() {
            if row < seen + group.hits.len() {
                return seen + g + 1 + (row - seen);
            }
            seen += group.hits.len();
        }
        0
    }

    fn open(&mut self, row: usize, window: &mut Window, cx: &mut Context<Self>) {
        let Some(&index) = self.rows.get(row) else {
            return;
        };
        let target = self.entries[index].target.clone();
        (self.on_close)(window, cx);
        (self.on_pick)(target, window, cx);
    }

    fn group_name(kind: Kind) -> String {
        match kind {
            Kind::Page => t("palette.pages"),
            other => t(&format!("page.{}", other.page())),
        }
    }
}

impl Render for Palette {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let close = Rc::clone(&self.on_close);
        let weak = cx.entity().downgrade();

        let mut list = div()
            .id("palette-results")
            .role(Role::List)
            .aria_label(t("palette.title"))
            .track_scroll(&self.scroll)
            .flex()
            .flex_col()
            .gap(px(2.))
            .px_2()
            .pb_2()
            .max_h(px(420.))
            .overflow_y_scroll();
        let mut row = 0;
        for group in &self.groups {
            let more = group.total.saturating_sub(group.hits.len());
            list = list.child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .px_2()
                    .pt_2()
                    .pb_1()
                    .text_size(px(12.))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(tk.ink2)
                    .child(Self::group_name(group.kind))
                    .when(more > 0, |this| {
                        this.child(div().font_weight(FontWeight::NORMAL).text_color(tk.ink3).child(tn(
                            "palette.more",
                            more as u64,
                            &[],
                        )))
                    }),
            );
            for &index in &group.hits {
                let entry = &self.entries[index];
                let selected = row == self.selected;
                let glyph = match &entry.target {
                    Target::Page(key) => icons::page(key),
                    _ => icons::page(entry.kind.page()),
                };
                let this_row = row;
                let pick = weak.clone();
                list = list.child(
                    kit::list_row(
                        ElementId::NamedInteger("palette-row".into(), row as u64),
                        format!("{} {}", entry.title, entry.detail),
                        selected,
                        move |window, cx| {
                            let _ = pick.update(cx, |palette, cx| palette.open(this_row, window, cx));
                        },
                        &tk,
                    )
                    .child(icons::icon(glyph, 16.0, tk.ink2))
                    .child(
                        div()
                            .flex_none()
                            .max_w(relative(0.55))
                            .overflow_hidden()
                            .text_ellipsis()
                            .whitespace_nowrap()
                            .child(kit::plain(entry.title.clone())),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .overflow_hidden()
                            .text_ellipsis()
                            .whitespace_nowrap()
                            .text_size(px(12.))
                            .text_color(tk.ink3)
                            .child(kit::plain(entry.detail.clone())),
                    ),
                );
                row += 1;
            }
        }

        let count = self.rows.len();
        let status: SharedString = if count == 0 && !self.query.trim().is_empty() {
            tf("palette.none", &[("query", self.query.trim())]).into()
        } else {
            tn("palette.results", count as u64, &[]).into()
        };
        let missing = (!self.missing.is_empty() && !self.query.trim().is_empty()).then(|| {
            let pages = self
                .missing
                .iter()
                .map(|k| t(&format!("page.{}", k.page())))
                .collect::<Vec<_>>()
                .join(", ");
            tf("palette.notLoaded", &[("pages", &pages)])
        });

        // The backdrop: a click outside the box closes it.
        div()
            .id("palette-backdrop")
            .absolute()
            .top_0()
            .left_0()
            .size_full()
            .bg(gpui_kit::black().opacity(0.3))
            .flex()
            .justify_center()
            .items_start()
            .pt(px(56.))
            .on_mouse_down(MouseButton::Left, move |_, window, cx| close(window, cx))
            .child(
                div()
                    .id("palette")
                    .role(Role::Dialog)
                    .aria_label(t("palette.title"))
                    .w(px(640.))
                    .max_w(relative(0.9))
                    .flex()
                    .flex_col()
                    .bg(tk.flyout)
                    .border_1()
                    .border_color(tk.rule_strong)
                    .rounded(RADIUS_CARD)
                    .shadow_lg()
                    .overflow_hidden()
                    .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
                    .child(
                        div()
                            .p_3()
                            .child(ui::search_box(&self.input, &tk).aria_label(t("palette.title"))),
                    )
                    .child(list)
                    .children(missing.map(|text| div().px_4().pb_2().child(kit::faint(text, &tk))))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_3()
                            .px_4()
                            .py_2()
                            .border_t_1()
                            .border_color(tk.rule)
                            .text_size(px(12.))
                            .text_color(tk.ink3)
                            // Announced as it changes: how many results the query found.
                            .child(
                                div()
                                    .id("palette-count")
                                    .role(Role::Status)
                                    .aria_label(status.clone())
                                    .child(status),
                            )
                            .child(div().flex_1())
                            .child(t("palette.hint")),
                    ),
            )
    }
}
