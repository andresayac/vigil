//! A command bar that fits its width, as WinUI's CommandBar does. It measures the room it is given
//! each frame; when its commands do not fit, their labels collapse to icons (the label stays the
//! tooltip and what a screen reader says), starting from the end of the bar, and when even the icons
//! do not fit, the last commands move into a "More commands" menu. Separators, the segmented
//! controls and other fixed parts always stay.
//!
//! Pages build it like a row of command buttons:
//!
//! ```ignore
//! CommandBar::new("st-bar")
//!     .cmd(ui::cmd("st-enable", icons::CHECK, t("startup.enable")).disabled(!can).on_click(...))
//!     .separator()
//!     .cmd(ui::cmd("st-more", icons::MORE, t("proc.more")).menu(|menu, window, cx| ...))
//! ```

use std::rc::Rc;

use gpui_kit::component::menu::{DropdownMenu as _, PopupMenu, PopupMenuItem};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    AnyElement, App, ClickEvent, Context, ElementId, InteractiveElement as _, IntoElement, ParentElement, RenderOnce,
    SharedString, Styled, TextRun, Window, canvas, div, font, px,
};

use crate::i18n::t;
use crate::icons;
use crate::ui::{FButton, Kind, icon_button};

/// What clicking a command does.
pub type ClickFn = Rc<dyn Fn(&ClickEvent, &mut Window, &mut App)>;
/// The items of a command's menu.
pub type MenuFn = Rc<dyn Fn(PopupMenu, &mut Window, &mut Context<PopupMenu>) -> PopupMenu>;

/// The space between two parts of the bar.
pub const GAP: f32 = 4.0;
/// A separator with its margins.
pub const SEPARATOR: f32 = 13.0;
/// The "More commands" button.
pub const MORE: f32 = 32.0;
/// The size of a command's label.
const LABEL_SIZE: f32 = 14.0;

/// How a command is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Its icon and its label.
    Full,
    /// Its icon only (the label is the tooltip and the accessible name).
    Icon,
    /// In the "More commands" menu.
    Overflow,
}

/// The widths of one command, each with the gap before it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Measure {
    pub full: f32,
    pub icon: f32,
    /// Never moves into the overflow menu (the page's main command).
    pub keep: bool,
}

/// The width of a command button with its label (`label` wide), as `FButton` draws it.
pub fn full_width(label: f32, glyph: bool, chevron: bool) -> f32 {
    24.0 + if glyph { 16.0 + 8.0 } else { 0.0 } + label + if chevron { 8.0 + 10.0 } else { 0.0 }
}

/// The width of a command button showing only its icon.
pub fn icon_width(chevron: bool) -> f32 {
    16.0 + 16.0 + if chevron { 8.0 + 10.0 } else { 0.0 }
}

/// How each command is shown in `available` pixels, `fixed` being taken by the parts that always
/// stay (separators, segmented controls, their gaps). Labels collapse from the last command to the
/// first; then commands move into the overflow menu, from the last to the first, skipping the kept
/// ones. When nothing more can go, what is left may still not fit (the bar then clips).
pub fn plan(commands: &[Measure], fixed: f32, available: f32) -> Vec<Mode> {
    let mut modes = vec![Mode::Full; commands.len()];
    let mut total = fixed + commands.iter().map(|c| c.full).sum::<f32>();
    if total <= available {
        return modes;
    }
    for i in (0..commands.len()).rev() {
        modes[i] = Mode::Icon;
        total -= commands[i].full - commands[i].icon;
        if total <= available {
            return modes;
        }
    }
    let mut overflowing = false;
    for i in (0..commands.len()).rev() {
        if commands[i].keep {
            continue;
        }
        modes[i] = Mode::Overflow;
        total -= commands[i].icon;
        if !overflowing {
            overflowing = true;
            total += MORE + GAP;
        }
        if total <= available {
            break;
        }
    }
    modes
}

/// Which separators stay: one between two shown parts, none at the ends, never two in a row.
/// `shown[i]` is `None` for a separator and whether the part is shown otherwise.
pub fn separators(shown: &[Option<bool>]) -> Vec<bool> {
    let mut keep = vec![false; shown.len()];
    let mut seen_before = false;
    let mut pending: Option<usize> = None;
    for (i, part) in shown.iter().enumerate() {
        match part {
            None => {
                if seen_before && pending.is_none() {
                    pending = Some(i);
                }
            }
            Some(true) => {
                if let Some(p) = pending.take() {
                    keep[p] = true;
                }
                seen_before = true;
            }
            Some(false) => {}
        }
    }
    keep
}

enum Action {
    Click(ClickFn),
    Menu(MenuFn),
}

/// One command of a bar.
pub struct Cmd {
    id: ElementId,
    glyph: char,
    label: SharedString,
    disabled: bool,
    danger: bool,
    keep: bool,
    action: Option<Action>,
}

/// A command: an icon and a label.
pub fn cmd(id: impl Into<ElementId>, glyph: char, label: impl Into<SharedString>) -> Cmd {
    Cmd {
        id: id.into(),
        glyph,
        label: label.into(),
        disabled: false,
        danger: false,
        keep: false,
        action: None,
    }
}

impl Cmd {
    pub fn disabled(mut self, disabled: bool) -> Self {
        self.disabled = disabled;
        self
    }

    /// Red text: the command deletes or ends something.
    pub fn danger(mut self, danger: bool) -> Self {
        self.danger = danger;
        self
    }

    /// Stays in the bar (as an icon at least) however narrow the window is.
    pub fn keep(mut self) -> Self {
        self.keep = true;
        self
    }

    pub fn on_click(mut self, handler: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static) -> Self {
        self.action = Some(Action::Click(Rc::new(handler)));
        self
    }

    /// The command opens a menu (a chevron after it).
    pub fn menu(
        mut self,
        items: impl Fn(PopupMenu, &mut Window, &mut Context<PopupMenu>) -> PopupMenu + 'static,
    ) -> Self {
        self.action = Some(Action::Menu(Rc::new(items)));
        self
    }

    fn chevron(&self) -> bool {
        matches!(self.action, Some(Action::Menu(_)))
    }

    /// The button, with or without its label.
    fn button(self, labelled: bool) -> AnyElement {
        let mut button = FButton::new(self.id, Kind::Command)
            .glyph(self.glyph)
            .danger(self.danger)
            .disabled(self.disabled);
        button = if labelled {
            button.label(self.label.clone())
        } else {
            button.accessible_name(self.label.clone()).tip(self.label.clone())
        };
        match self.action {
            Some(Action::Click(handler)) => button
                .on_click(move |event, window, cx| handler(event, window, cx))
                .into_any_element(),
            Some(Action::Menu(items)) => button
                .chevron()
                .dropdown_menu(move |menu, window, cx| items(menu, window, cx))
                .into_any_element(),
            None => button.into_any_element(),
        }
    }
}

enum Part {
    Command(Cmd),
    Separator,
    Fixed(AnyElement, f32),
}

/// A row of commands that fits its width (see the module).
#[derive(IntoElement)]
pub struct CommandBar {
    id: &'static str,
    parts: Vec<Part>,
    start: bool,
}

impl CommandBar {
    pub fn new(id: &'static str) -> Self {
        Self {
            id,
            parts: Vec::new(),
            start: false,
        }
    }

    /// A bar on its own row of the page (in a column): the commands start at the left and the bar
    /// takes the row's width. By default the bar sits in a row after the page title and its
    /// commands end at the right.
    pub fn start(mut self) -> Self {
        self.start = true;
        self
    }

    pub fn cmd(mut self, cmd: Cmd) -> Self {
        self.parts.push(Part::Command(cmd));
        self
    }

    pub fn separator(mut self) -> Self {
        self.parts.push(Part::Separator);
        self
    }

    /// A part that always stays (a segmented control), `width` pixels wide.
    pub fn fixed(mut self, element: impl IntoElement, width: f32) -> Self {
        self.parts.push(Part::Fixed(element.into_any_element(), width));
        self
    }
}

/// How wide `text` is drawn in the body font at `size`.
pub fn text_width(window: &Window, text: &str, size: f32) -> f32 {
    if text.is_empty() {
        return 0.0;
    }
    let run = TextRun {
        len: text.len(),
        font: font(crate::theme::FONT_BODY),
        color: gpui_kit::black(),
        background_color: None,
        underline: None,
        strikethrough: None,
    };
    let shaped = window
        .text_system()
        .shape_line(SharedString::from(text.to_string()), px(size), &[run], None);
    f32::from(shaped.width)
}

/// The width of a segmented control (`ui::segmented`) with these labels.
pub fn segmented_width(window: &Window, labels: &[&str]) -> f32 {
    // Padding 2 and a border on each side; each option: 10 px each side, a border, and room for
    // the selected option's semibold text; 2 px between options.
    let options: f32 = labels.iter().map(|l| text_width(window, l, 13.0) * 1.06 + 22.0).sum();
    6.0 + options + 2.0 * labels.len().saturating_sub(1) as f32
}

impl RenderOnce for CommandBar {
    fn render(self, window: &mut Window, cx: &mut App) -> impl IntoElement {
        // The room the bar had at the last frame (none yet: everything is drawn in full).
        let room = window.use_keyed_state(ElementId::Name(format!("{}-room", self.id).into()), cx, |_, _| {
            f32::INFINITY
        });
        let available = *room.read(cx);

        let mut measures = Vec::new();
        let mut fixed = 0.0;
        for part in &self.parts {
            match part {
                Part::Command(c) => {
                    let chevron = c.chevron();
                    let label = text_width(window, &c.label, LABEL_SIZE);
                    measures.push(Measure {
                        full: full_width(label, true, chevron) + GAP,
                        icon: icon_width(chevron) + GAP,
                        keep: c.keep,
                    });
                }
                Part::Separator => fixed += SEPARATOR + GAP,
                Part::Fixed(_, width) => fixed += width + GAP,
            }
        }
        let modes = plan(&measures, fixed, available);

        // Separators next to commands that moved into the menu go too.
        let mut index = 0;
        let shown: Vec<Option<bool>> = self
            .parts
            .iter()
            .map(|part| match part {
                Part::Command(_) => {
                    let mode = modes[index];
                    index += 1;
                    Some(mode != Mode::Overflow)
                }
                Part::Separator => None,
                Part::Fixed(..) => Some(true),
            })
            .collect();
        let keep_separator = separators(&shown);

        let tk = *crate::theme::tokens(cx);
        let mut row = div().flex().flex_none().items_center().gap(px(GAP));
        let mut overflow: Vec<Option<Cmd>> = Vec::new();
        let mut index = 0;
        for (i, part) in self.parts.into_iter().enumerate() {
            match part {
                Part::Command(c) => {
                    let mode = modes[index];
                    index += 1;
                    match mode {
                        Mode::Full => row = row.child(c.button(true)),
                        Mode::Icon => row = row.child(c.button(false)),
                        Mode::Overflow => overflow.push(Some(c)),
                    }
                }
                Part::Separator => {
                    if keep_separator[i] {
                        row = row.child(super::separator(&tk));
                    } else if overflow.last().is_some_and(Option::is_some) {
                        // A group boundary inside the overflow menu.
                        overflow.push(None);
                    }
                }
                Part::Fixed(element, _) => row = row.child(element),
            }
        }
        while overflow.last().is_some_and(Option::is_none) {
            overflow.pop();
        }
        if !overflow.is_empty() {
            row = row.child(more_button(self.id, overflow));
        }

        let measured = room.clone();
        div()
            .id(self.id)
            .relative()
            .flex()
            .items_center()
            // On its own row (in a column) it takes the row's width; next to a title (in a row) it
            // takes what the title leaves, without pushing the title or wrapping under it.
            .when(self.start, |this| this.justify_start().w_full().flex_none())
            .when(!self.start, |this| this.justify_end().flex_basis(px(0.)).flex_grow(1.))
            .min_w_0()
            .overflow_hidden()
            .child(
                canvas(
                    move |bounds, _, cx| {
                        let width = f32::from(bounds.size.width);
                        measured.update(cx, |room, cx| {
                            if (*room - width).abs() > 0.5 {
                                *room = width;
                                cx.notify();
                            }
                        });
                    },
                    |_, _, _, _| {},
                )
                .absolute()
                .top_0()
                .left_0()
                .size_full(),
            )
            .child(row)
    }
}

/// The "More commands" button and its menu: the commands that did not fit, with their labels.
fn more_button(id: &'static str, commands: Vec<Option<Cmd>>) -> impl IntoElement {
    let commands: Rc<Vec<Option<Cmd>>> = Rc::new(commands);
    icon_button(
        ElementId::Name(format!("{id}-more").into()),
        icons::MORE,
        t("common.moreCommands"),
    )
    .tip(t("common.moreCommands"))
    .dropdown_menu(move |mut menu, window, cx| {
        for entry in commands.iter() {
            let Some(c) = entry else {
                menu = menu.separator();
                continue;
            };
            menu = match &c.action {
                Some(Action::Click(handler)) => {
                    let handler = Rc::clone(handler);
                    menu.item(
                        PopupMenuItem::new(c.label.clone())
                            .disabled(c.disabled)
                            .on_click(move |event, window, cx| handler(event, window, cx)),
                    )
                }
                Some(Action::Menu(items)) if !c.disabled => {
                    let items = Rc::clone(items);
                    menu.submenu(c.label.clone(), window, cx, move |m, window, cx| items(m, window, cx))
                }
                _ => menu.item(PopupMenuItem::new(c.label.clone()).disabled(true)),
            };
        }
        menu
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(full: f32, icon: f32) -> Measure {
        Measure {
            full,
            icon,
            keep: false,
        }
    }

    #[test]
    fn everything_fits_in_full() {
        let modes = plan(&[m(100.0, 36.0), m(120.0, 36.0)], 20.0, 400.0);
        assert_eq!(modes, vec![Mode::Full, Mode::Full]);
    }

    #[test]
    fn labels_collapse_from_the_end_first() {
        // 100 + 120 + 20 = 240 > 200: the last label goes (120 → 36: 156 fits).
        let modes = plan(&[m(100.0, 36.0), m(120.0, 36.0)], 20.0, 200.0);
        assert_eq!(modes, vec![Mode::Full, Mode::Icon]);
        // Even tighter: both become icons (36 + 36 + 20 = 92).
        let modes = plan(&[m(100.0, 36.0), m(120.0, 36.0)], 20.0, 100.0);
        assert_eq!(modes, vec![Mode::Icon, Mode::Icon]);
    }

    #[test]
    fn then_the_last_commands_move_into_the_menu_but_kept_ones_stay() {
        let mut first = m(100.0, 36.0);
        first.keep = true;
        let commands = [first, m(100.0, 36.0), m(100.0, 36.0)];
        // All icons: 108 + 20 = 128 > 90. Overflow the last (−36 + 36 more button) = 128, then the
        // middle one: 92, then nothing left that may go (the first is kept).
        let modes = plan(&commands, 20.0, 90.0);
        assert_eq!(modes, vec![Mode::Icon, Mode::Overflow, Mode::Overflow]);
        let modes = plan(&commands, 20.0, 95.0);
        assert_eq!(modes, vec![Mode::Icon, Mode::Overflow, Mode::Overflow]);
        // As icons they fit at 128: nothing goes into the menu.
        let modes = plan(&commands, 20.0, 130.0);
        assert_eq!(modes, vec![Mode::Icon, Mode::Icon, Mode::Icon]);
        // Menu commands (50 px as icons): moving the last one out (−50 + 36) is enough at 160.
        let menus = [m(120.0, 50.0), m(120.0, 50.0), m(120.0, 50.0)];
        let modes = plan(&menus, 20.0, 160.0);
        assert_eq!(modes, vec![Mode::Icon, Mode::Icon, Mode::Overflow]);
    }

    #[test]
    fn an_unmeasured_bar_is_drawn_in_full() {
        let modes = plan(&[m(100.0, 36.0)], 0.0, f32::INFINITY);
        assert_eq!(modes, vec![Mode::Full]);
    }

    #[test]
    fn separators_only_between_shown_parts() {
        // cmd | cmd(hidden) | sep | cmd
        assert_eq!(
            separators(&[Some(true), None, Some(false), None, Some(true)]),
            vec![false, true, false, false, false]
        );
        // A separator at the start or the end goes.
        assert_eq!(separators(&[None, Some(true), None]), vec![false, false, false]);
        // Two in a row become one.
        assert_eq!(
            separators(&[Some(true), None, None, Some(true)]),
            vec![false, true, false, false]
        );
        // Everything after it went into the menu: the separator goes.
        assert_eq!(
            separators(&[Some(true), None, Some(false), Some(false)]),
            vec![false, false, false, false]
        );
    }

    #[test]
    fn widths_follow_the_button_layout() {
        assert_eq!(icon_width(false), 32.0);
        assert_eq!(icon_width(true), 50.0);
        assert_eq!(full_width(50.0, true, false), 98.0);
        assert_eq!(full_width(50.0, true, true), 116.0);
        assert_eq!(full_width(50.0, false, false), 74.0);
    }
}
