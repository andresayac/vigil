//! Vigil's Fluent control set, drawn over gpui-base's unstyled primitives so that focus, Tab
//! traversal, Enter/Space activation, the disabled state and the accessibility role and name come
//! from the framework, and the look from Vigil's WinUI tokens (`theme.rs`).
//!
//! - [`FButton`]: standard, accent, subtle, danger and command-bar buttons, with an icon, a menu
//!   chevron and a flyout menu (`dropdown_menu`).
//! - [`toggle_switch`], [`check_box`], [`segmented`]: the WinUI toggle switch, check box and
//!   segmented control.
//! - [`info_bar`]: the InfoBar (informational, success, warning, error), announced as a status.
//! - [`search_box`]: the text box with a search glyph and a clear button.
//! - [`grid`]: a table of rows kept by identity, with keyboard navigation.
//!
//! Text handed to these controls is drawn as plain text: nothing interprets markup.

pub mod bar;
pub mod grid;
pub mod kit;

pub use bar::{CommandBar, cmd};

use std::rc::Rc;

use gpui_kit::base::{Button as BaseButton, Checkbox, Selectable, StyledExt as _, Switch};
use gpui_kit::component::input::{Input, InputState};
use gpui_kit::component::menu::DropdownMenu;
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    AnyElement, App, ClickEvent, ElementId, Entity, FontWeight, InteractiveElement, Interactivity, IntoElement,
    ParentElement, RenderOnce, Role, SharedString, StatefulInteractiveElement, StyleRefinement, Styled, Toggled,
    Window, div, px,
};

use crate::icons;
use crate::theme::{RADIUS, Tokens, tokens};

/// The look of a button.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Control fill with a stroke and a darker bottom edge.
    Standard,
    /// The accent fill: the one main action of a view.
    Accent,
    /// No fill until hovered (toolbars, icon buttons).
    Subtle,
    /// Command bar: an icon and a label, no fill until hovered.
    Command,
}

type Handler = Rc<dyn Fn(&ClickEvent, &mut Window, &mut App)>;

/// A Fluent button. Built on gpui-base's `Button`: focusable, Tab-traversable, activated with
/// Enter and Space, exposed as a button with its label, and inert (and announced so) when disabled.
#[derive(IntoElement)]
pub struct FButton {
    base: BaseButton,
    kind: Kind,
    label: Option<SharedString>,
    glyph: Option<char>,
    chevron: bool,
    danger: bool,
    disabled: bool,
    selected: bool,
    role: Option<Role>,
    tip: Option<SharedString>,
    on_click: Option<Handler>,
    style: StyleRefinement,
    /// Drawn after the label (a selection pill, a badge).
    children: Vec<AnyElement>,
}

impl FButton {
    pub fn new(id: impl Into<ElementId>, kind: Kind) -> Self {
        Self {
            base: BaseButton::new(id),
            kind,
            label: None,
            glyph: None,
            chevron: false,
            danger: false,
            disabled: false,
            selected: false,
            role: None,
            tip: None,
            on_click: None,
            style: StyleRefinement::default(),
            children: Vec::new(),
        }
    }

    /// The name a screen reader says for a button that shows no text (a collapsed navigation item).
    pub fn accessible_name(mut self, name: impl Into<SharedString>) -> Self {
        self.base = self.base.accessibility_label(name.into());
        self
    }

    /// A tooltip (plain text).
    pub fn tip(mut self, tip: impl Into<SharedString>) -> Self {
        let tip = tip.into();
        self.tip = (!tip.is_empty()).then_some(tip);
        self
    }

    pub fn label(mut self, label: impl Into<SharedString>) -> Self {
        self.label = Some(label.into());
        self
    }

    pub fn glyph(mut self, glyph: char) -> Self {
        self.glyph = Some(glyph);
        self
    }

    /// A chevron after the label: the button opens a menu.
    pub fn chevron(mut self) -> Self {
        self.chevron = true;
        self
    }

    /// Red text: the action deletes or ends something.
    pub fn danger(mut self, danger: bool) -> Self {
        self.danger = danger;
        self
    }

    pub fn disabled(mut self, disabled: bool) -> Self {
        self.disabled = disabled;
        self
    }

    /// Overrides the accessibility role (a navigation item stays a button; a segment is a radio).
    pub fn role(mut self, role: Role) -> Self {
        self.role = Some(role);
        self
    }

    pub fn on_click(mut self, handler: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static) -> Self {
        self.on_click = Some(Rc::new(handler));
        self
    }
}

/// A standard button with a label.
pub fn button(id: impl Into<ElementId>, label: impl Into<SharedString>) -> FButton {
    FButton::new(id, Kind::Standard).label(label)
}

/// The accent button of a view.
pub fn accent_button(id: impl Into<ElementId>, label: impl Into<SharedString>) -> FButton {
    FButton::new(id, Kind::Accent).label(label)
}

/// A command bar button: icon and label.
pub fn command(id: impl Into<ElementId>, glyph: char, label: impl Into<SharedString>) -> FButton {
    FButton::new(id, Kind::Command).glyph(glyph).label(label)
}

/// An icon-only button; `name` is what a screen reader says.
pub fn icon_button(id: impl Into<ElementId>, glyph: char, name: impl Into<SharedString>) -> FButton {
    let name = name.into();
    let mut button = FButton::new(id, Kind::Subtle).glyph(glyph);
    button.base = button.base.accessibility_label(name);
    button
}

impl Styled for FButton {
    fn style(&mut self) -> &mut StyleRefinement {
        &mut self.style
    }
}

impl InteractiveElement for FButton {
    fn interactivity(&mut self) -> &mut Interactivity {
        self.base.interactivity()
    }
}

impl ParentElement for FButton {
    fn extend(&mut self, elements: impl IntoIterator<Item = AnyElement>) {
        self.children.extend(elements);
    }
}

impl Selectable for FButton {
    fn selected(mut self, selected: bool) -> Self {
        self.selected = selected;
        self
    }

    fn is_selected(&self) -> bool {
        self.selected
    }
}

impl DropdownMenu for FButton {}

impl RenderOnce for FButton {
    fn render(self, _window: &mut Window, cx: &mut App) -> impl IntoElement {
        let tk = *tokens(cx);
        let disabled = self.disabled;
        let ink = if disabled {
            tk.ink_disabled
        } else if self.danger {
            tk.bad
        } else {
            tk.ink
        };
        let (fill, fg, stroke, hover, pressed) = match self.kind {
            Kind::Standard => (
                tk.control,
                ink,
                Some(tk.control_stroke),
                tk.control_hover,
                tk.control.opacity(0.9),
            ),
            Kind::Accent if disabled => (tk.rule_strong, tk.ink_disabled, None, tk.rule_strong, tk.rule_strong),
            Kind::Accent => (tk.accent, tk.on_accent, None, tk.accent_hover, tk.accent_pressed),
            Kind::Subtle | Kind::Command => (tk.surface.opacity(0.), ink, None, tk.hover, tk.pressed),
        };
        let label = self.label.clone();
        let mut base = self
            .base
            .disabled(disabled)
            .selected(self.selected)
            .flex()
            .items_center()
            .gap_2()
            .h(px(32.))
            .px(px(if label.is_some() { 12. } else { 8. }))
            .rounded(RADIUS)
            .text_size(px(14.))
            .text_color(fg)
            .bg(if self.selected { hover } else { fill })
            .when_some(stroke, |this, stroke| this.border_1().border_color(stroke))
            .when(self.kind == Kind::Accent, |this| this.font_weight(FontWeight::SEMIBOLD))
            .hover(move |s| s.bg(hover))
            .active(move |s| s.bg(pressed));
        if let Some(role) = self.role {
            base = base.role(role);
        }
        if let Some(label) = &label {
            base = base.accessibility_label(label.clone());
        }
        if let Some(tip) = self.tip {
            base = base
                .tooltip(move |window, cx| gpui_kit::component::tooltip::Tooltip::new(tip.clone()).build(window, cx));
        }
        if let Some(handler) = self.on_click {
            base = base.on_click(move |event, window, cx| handler(event, window, cx));
        }
        let glyph_color = if self.kind == Kind::Accent { fg } else { ink };
        base.when_some(self.glyph, |this, glyph| {
            this.child(icons::icon(glyph, 16.0, glyph_color))
        })
        .when_some(label, |this, label| this.child(div().whitespace_nowrap().child(label)))
        .when(self.chevron, |this| {
            this.child(icons::icon(icons::CHEVRON_DOWN, 10.0, ink))
        })
        .children(self.children)
        .refine_style(&self.style)
    }
}

/// The WinUI toggle switch: a 40 × 20 track and its thumb, with "On" / "Off" (or `label`) next to
/// it. Exposed as a switch with its state and name.
pub fn toggle_switch(
    id: impl Into<ElementId>,
    checked: bool,
    disabled: bool,
    label: impl Into<SharedString>,
    on_change: impl Fn(bool, &mut Window, &mut App) + 'static,
    tk: &Tokens,
) -> impl IntoElement {
    let label = label.into();
    let (track, border, thumb) = match (checked, disabled) {
        (_, true) => (tk.surface.opacity(0.), tk.ink_disabled, tk.ink_disabled),
        (true, false) => (tk.accent, tk.accent, tk.on_accent),
        (false, false) => (tk.surface.opacity(0.), tk.ink2, tk.ink2),
    };
    Switch::new(id)
        .checked(checked)
        .disabled(disabled)
        .accessibility_label(label.clone())
        .on_change(move |value, _, window, cx| on_change(value, window, cx))
        .flex()
        .items_center()
        .gap_3()
        .child(
            div()
                .w(px(40.))
                .h(px(20.))
                .flex_none()
                .rounded(px(10.))
                .border_1()
                .border_color(border)
                .bg(track)
                .flex()
                .items_center()
                .px(px(3.))
                .when(checked, |this| this.justify_end())
                .child(div().w(px(12.)).h(px(12.)).rounded(px(6.)).bg(thumb)),
        )
        .child(
            div()
                .text_color(if disabled { tk.ink_disabled } else { tk.ink })
                .child(label),
        )
}

/// The WinUI check box with its label.
pub fn check_box(
    id: impl Into<ElementId>,
    checked: bool,
    disabled: bool,
    label: impl Into<SharedString>,
    on_change: impl Fn(bool, &mut Window, &mut App) + 'static,
    tk: &Tokens,
) -> impl IntoElement {
    let label = label.into();
    let (fill, stroke) = match (checked, disabled) {
        (_, true) => (tk.surface.opacity(0.), tk.ink_disabled),
        (true, false) => (tk.accent, tk.accent),
        (false, false) => (tk.control, tk.ink2),
    };
    Checkbox::new(id)
        .checked(checked)
        .disabled(disabled)
        .accessibility_label(label.clone())
        .on_change(move |state, _, window, cx| on_change(state == gpui_kit::base::CheckboxState::Checked, window, cx))
        .flex()
        .items_center()
        .gap_2()
        .child(
            div()
                .w(px(20.))
                .h(px(20.))
                .flex_none()
                .rounded(RADIUS)
                .border_1()
                .border_color(stroke)
                .bg(fill)
                .flex()
                .items_center()
                .justify_center()
                .when(checked, |this| {
                    this.child(icons::icon(icons::CHECK, 12.0, tk.on_accent))
                }),
        )
        .child(
            div()
                .text_color(if disabled { tk.ink_disabled } else { tk.ink })
                .child(label),
        )
}

/// A group of radio buttons (screen readers announce it with its name).
pub fn radio_group(id: &'static str, name: impl Into<SharedString>) -> gpui_kit::Stateful<gpui_kit::Div> {
    div()
        .id(id)
        .role(Role::RadioGroup)
        .aria_label(name.into())
        .flex()
        .flex_col()
        .gap(px(2.))
}

/// The WinUI radio button: a circle (filled with the accent and a dot when chosen) and its label.
pub fn radio(
    id: impl Into<ElementId>,
    selected: bool,
    disabled: bool,
    label: impl Into<SharedString>,
    on_pick: impl Fn(&mut Window, &mut App) + 'static,
    tk: &Tokens,
) -> impl IntoElement {
    let label = label.into();
    let tk = *tk;
    let (fill, stroke) = match (selected, disabled) {
        (true, true) => (tk.ink_disabled, tk.ink_disabled),
        (false, true) => (tk.surface.opacity(0.), tk.ink_disabled),
        (true, false) => (tk.accent, tk.accent),
        (false, false) => (tk.control, tk.ink2),
    };
    BaseButton::new(id)
        .role(Role::RadioButton)
        .accessibility_label(label.clone())
        .aria_toggled(if selected { Toggled::True } else { Toggled::False })
        .disabled(disabled)
        .flex()
        .items_center()
        .gap_2()
        .min_h(px(28.))
        .on_click(move |_, window, cx| on_pick(window, cx))
        .child(
            div()
                .w(px(20.))
                .h(px(20.))
                .flex_none()
                .rounded_full()
                .border_1()
                .border_color(stroke)
                .bg(fill)
                .flex()
                .items_center()
                .justify_center()
                .when(selected, |this| {
                    this.child(div().w(px(8.)).h(px(8.)).rounded_full().bg(tk.on_accent))
                }),
        )
        .child(
            div()
                .text_color(if disabled { tk.ink_disabled } else { tk.ink })
                .child(label),
        )
}

/// A segmented control: one option out of a few, each a radio button.
pub fn segmented<T: Copy + PartialEq + 'static>(
    id: &'static str,
    name: impl Into<SharedString>,
    options: Vec<(T, String)>,
    current: T,
    on_pick: impl Fn(T, &mut Window, &mut App) + 'static,
    tk: &Tokens,
) -> impl IntoElement {
    let on_pick = Rc::new(on_pick);
    let tk = *tk;
    div()
        .id(id)
        .role(Role::RadioGroup)
        .aria_label(name.into())
        .flex()
        .gap(px(2.))
        .p(px(2.))
        .rounded(RADIUS)
        .bg(tk.control)
        .border_1()
        .border_color(tk.control_stroke)
        .children(options.into_iter().enumerate().map(move |(index, (value, label))| {
            let on = value == current;
            let pick = Rc::clone(&on_pick);
            BaseButton::new(ElementId::NamedInteger(id.into(), index as u64))
                .role(Role::RadioButton)
                .accessibility_label(label.clone())
                .aria_toggled(if on { Toggled::True } else { Toggled::False })
                .px(px(10.))
                .h(px(26.))
                .rounded(px(3.))
                .text_size(px(13.))
                .border_1()
                .border_color(if on { tk.control_stroke } else { tk.surface.opacity(0.) })
                .when(on, |this| {
                    this.bg(tk.surface).text_color(tk.ink).font_weight(FontWeight::SEMIBOLD)
                })
                .when(!on, |this| this.text_color(tk.ink2).hover(move |s| s.bg(tk.hover)))
                .on_click(move |_, window, cx| pick(value, window, cx))
                .child(label)
        }))
}

/// What closing an InfoBar does.
pub type OnClose = Box<dyn Fn(&mut Window, &mut App)>;

/// How an InfoBar reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Success,
    Warning,
    Error,
}

/// The WinUI InfoBar: an icon in the severity's colour, the message, and an optional close button.
pub fn info_bar(
    id: impl Into<ElementId>,
    severity: Severity,
    message: impl Into<SharedString>,
    on_close: Option<OnClose>,
    tk: &Tokens,
) -> impl IntoElement {
    info_bar_with(id, severity, message, None, on_close, tk)
}

/// An InfoBar with one action button after the message (WinUI's InfoBar action).
pub fn info_bar_with(
    id: impl Into<ElementId>,
    severity: Severity,
    message: impl Into<SharedString>,
    action: Option<(SharedString, OnClose)>,
    on_close: Option<OnClose>,
    tk: &Tokens,
) -> impl IntoElement {
    let (glyph, color) = match severity {
        Severity::Info => (icons::INFO, tk.accent),
        Severity::Success => (icons::SUCCESS, tk.ok),
        Severity::Warning => (icons::WARNING, tk.warn),
        Severity::Error => (icons::ERROR, tk.bad),
    };
    let message = message.into();
    let id = id.into();
    div()
        .id(id.clone())
        .role(Role::Status)
        .aria_label(message.clone())
        .flex()
        .items_center()
        .gap_3()
        .px_3()
        .py_2()
        .rounded(RADIUS)
        .bg(tk.flyout)
        .border_1()
        .border_color(tk.rule)
        .child(icons::icon(glyph, 16.0, color))
        .child(div().flex_1().text_size(px(13.)).child(message))
        .when_some(action, |this, (label, run)| {
            this.child(
                button(
                    ElementId::NamedChild(std::sync::Arc::new(id.clone()), "action".into()),
                    label,
                )
                .on_click(move |_, window, cx| run(window, cx)),
            )
        })
        .when_some(on_close, |this, close| {
            this.child(
                icon_button(
                    ElementId::NamedChild(std::sync::Arc::new(id), "close".into()),
                    icons::CANCEL,
                    crate::i18n::t("common.dismiss"),
                )
                .on_click(move |_, window, cx| close(window, cx)),
            )
        })
}

/// The search text box: a search glyph, the placeholder of `state`, and a clear button.
pub fn search_box(state: &Entity<InputState>, tk: &Tokens) -> Input {
    Input::new(state)
        .prefix(icons::icon(icons::SEARCH, 14.0, tk.ink2))
        .cleanable(true)
}

/// A page title (Subtitle in the WinUI type ramp).
pub fn page_title(text: impl Into<SharedString>) -> impl IntoElement {
    // Never squeezed or wrapped by a command bar next to it: the bar collapses instead.
    div()
        .flex_none()
        .whitespace_nowrap()
        .pl_1()
        .font_family(crate::theme::FONT_DISPLAY)
        .text_size(px(20.))
        .line_height(px(28.))
        .font_weight(FontWeight::SEMIBOLD)
        .child(text.into())
}

/// A vertical rule between command bar groups.
pub fn separator(tk: &Tokens) -> AnyElement {
    div()
        .w(px(1.))
        .h(px(20.))
        .mx(px(6.))
        .bg(tk.rule_strong)
        .into_any_element()
}

/// The card that holds a selected item's details.
pub fn card(tk: &Tokens) -> gpui_kit::Div {
    div()
        .flex_none()
        .flex()
        .flex_col()
        .gap_1()
        .p_4()
        .bg(tk.surface)
        .border_1()
        .border_color(tk.rule)
        .rounded(crate::theme::RADIUS_CARD)
}

/// One "name: value" line of a details card.
pub fn fact(
    name: impl Into<SharedString>,
    value: impl Into<SharedString>,
    mono: bool,
    tk: &Tokens,
) -> impl IntoElement {
    div()
        .flex()
        .gap_3()
        .text_size(px(13.))
        .child(div().w(px(150.)).flex_none().text_color(tk.ink3).child(name.into()))
        .child(
            div()
                .flex_1()
                .min_w_0()
                .overflow_hidden()
                .text_ellipsis()
                .when(mono, |this| {
                    this.font_family(crate::theme::FONT_MONO).text_size(px(12.))
                })
                .child(value.into()),
        )
}
