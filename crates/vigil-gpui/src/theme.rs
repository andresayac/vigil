//! Windows 11 Fluent tokens (WinUI 3 theme resources), ported from `ui/src/app.css`.
//!
//! Colour carries meaning, as in the web UI: verdict colours only for verdicts, the `chart_*`
//! resource hues only for live measurements, `ok` / `warn` / `bad` only for state, `heat` only for
//! the process table's heat map, the accent only for interactive elements. Everything else is ink
//! and greys.

use gpui_kit::component::{Theme, ThemeMode};
use gpui_kit::{App, Global, Hsla, Pixels, SharedString, px, rgb, rgba};

/// Body text: Segoe UI Variable (Text optical size), with fallbacks for Windows 10 and Chinese.
pub const FONT_BODY: &str = "Segoe UI Variable Text";
/// Titles and large figures.
pub const FONT_DISPLAY: &str = "Segoe UI Variable Display";
pub const FONT_MONO: &str = "Cascadia Mono";
/// Icons: the Windows 11 icon font (Segoe MDL2 Assets on Windows 10 has the same code points).
pub const FONT_ICONS: &str = "Segoe Fluent Icons";

pub const RADIUS: Pixels = px(4.);
pub const RADIUS_CARD: Pixels = px(8.);

/// The theme the user chose in Settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    System,
    Light,
    Dark,
}

impl Choice {
    pub fn parse(text: &str) -> Self {
        match text {
            "light" => Self::Light,
            "dark" => Self::Dark,
            _ => Self::System,
        }
    }
}

/// The whole WinUI token set of `app.css`; the pages not ported yet use the rest (disk, network
/// and GPU hues, the input fill, the bottom stroke of controls).
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct Tokens {
    pub dark: bool,
    /// The window draws Mica: the base is transparent and the content layer translucent.
    pub mica: bool,
    pub canvas: Hsla,
    pub layer: Hsla,
    pub layer_stroke: Hsla,
    pub surface: Hsla,
    pub surface2: Hsla,
    pub flyout: Hsla,
    pub ink: Hsla,
    pub ink2: Hsla,
    pub ink3: Hsla,
    pub ink_disabled: Hsla,
    pub rule: Hsla,
    pub rule_strong: Hsla,
    pub hover: Hsla,
    pub pressed: Hsla,
    pub control: Hsla,
    pub control_hover: Hsla,
    pub control_stroke: Hsla,
    pub control_stroke_bottom: Hsla,
    pub input_bg: Hsla,
    pub accent: Hsla,
    pub accent_hover: Hsla,
    pub accent_pressed: Hsla,
    pub on_accent: Hsla,
    pub table_select: Hsla,
    pub ok: Hsla,
    pub warn: Hsla,
    pub bad: Hsla,
    pub chart_cpu: Hsla,
    pub chart_memory: Hsla,
    pub chart_disk: Hsla,
    pub chart_net: Hsla,
    pub chart_gpu: Hsla,
    pub heat: [Hsla; 5],
    pub heat_rule: Hsla,
    pub verdict_remove: Hsla,
    pub verdict_disable: Hsla,
    pub verdict_review: Hsla,
}

impl Global for Tokens {}

fn hex(value: u32) -> Hsla {
    rgb(value).into()
}

fn hexa(value: u32) -> Hsla {
    rgba(value).into()
}

impl Tokens {
    pub fn light(mica: bool) -> Self {
        let accent = hex(0x005fb8);
        Self {
            dark: false,
            mica,
            canvas: if mica { hexa(0x00000000) } else { hex(0xeef2f6) },
            layer: if mica { hexa(0xffffffb8) } else { hex(0xfbfbfb) },
            layer_stroke: hexa(0x0000000f),
            surface: hex(0xffffff),
            surface2: hex(0xfafafa),
            flyout: hex(0xfcfcfc),
            ink: hex(0x1b1b1b),
            ink2: hex(0x5d5d5d),
            ink3: hex(0x8b8b8b),
            ink_disabled: hex(0xa8a8a8),
            rule: hex(0xe5e5e5),
            rule_strong: hex(0xd1d1d1),
            hover: hexa(0x0000000a),
            pressed: hexa(0x00000006),
            control: hex(0xfbfbfb),
            control_hover: hex(0xf6f6f6),
            control_stroke: hex(0xe5e5e5),
            control_stroke_bottom: hex(0xcccccc),
            input_bg: hex(0xffffff),
            accent,
            accent_hover: hex(0x1a6fc1),
            accent_pressed: hex(0x3381ca),
            on_accent: hex(0xffffff),
            table_select: accent.opacity(0.12),
            ok: hex(0x0f7b0f),
            warn: hex(0x9d5d00),
            bad: hex(0xc42b1c),
            chart_cpu: hex(0x0f6cbd),
            chart_memory: hex(0x8a3fb8),
            chart_disk: hex(0x3d8b0f),
            chart_net: hex(0xb35c00),
            chart_gpu: hex(0x0e7a8a),
            heat: [
                hex(0xf8eefb),
                hex(0xf2ddf8),
                hex(0xecd0f4),
                hex(0xe5c2f0),
                hex(0xd9a9ea),
            ],
            heat_rule: hexa(0xffffffcc),
            verdict_remove: hex(0xc42b1c),
            verdict_disable: hex(0x9d5d00),
            verdict_review: hex(0x6b3fd1),
        }
    }

    pub fn dark(mica: bool) -> Self {
        let accent = hex(0x60cdff);
        Self {
            dark: true,
            mica,
            canvas: if mica { hexa(0x00000000) } else { hex(0x202020) },
            layer: if mica { hexa(0x3a3a3a4d) } else { hex(0x272727) },
            layer_stroke: hexa(0x0000001a),
            surface: hex(0x2b2b2b),
            surface2: hex(0x2e2e2e),
            flyout: hex(0x2c2c2c),
            ink: hex(0xffffff),
            ink2: hex(0xc8c8c8),
            ink3: hex(0x9d9d9d),
            ink_disabled: hex(0x717171),
            rule: hex(0x363636),
            rule_strong: hex(0x454545),
            hover: hexa(0xffffff0f),
            pressed: hexa(0xffffff0b),
            control: hex(0x2d2d2d),
            control_hover: hex(0x323232),
            control_stroke: hex(0x353535),
            control_stroke_bottom: hex(0x3f3f3f),
            input_bg: hex(0x1f1f1f),
            accent,
            accent_hover: hex(0x5abce9),
            accent_pressed: hex(0x52aad2),
            on_accent: hex(0x000000),
            table_select: accent.opacity(0.16),
            ok: hex(0x6ccb5f),
            warn: hex(0xf6c343),
            bad: hex(0xff99a4),
            chart_cpu: hex(0x4aa3ff),
            chart_memory: hex(0xc38cf2),
            chart_disk: hex(0x7cc35a),
            chart_net: hex(0xf0a34a),
            chart_gpu: hex(0x4cc9d6),
            heat: [
                hex(0x2b2433),
                hex(0x382a45),
                hex(0x44305a),
                hex(0x523671),
                hex(0x653d8c),
            ],
            heat_rule: hexa(0x00000059),
            verdict_remove: hex(0xff99a4),
            verdict_disable: hex(0xf6c343),
            verdict_review: hex(0xc4a7ff),
        }
    }

    /// The verdict colour of a finding ("remove", "disable", "review").
    pub fn verdict(&self, verdict: &str) -> Hsla {
        match verdict {
            "remove" => self.verdict_remove,
            "disable" => self.verdict_disable,
            _ => self.verdict_review,
        }
    }
}

/// Shorthand for the tokens of the current theme.
pub fn tokens(cx: &App) -> &Tokens {
    cx.global::<Tokens>()
}

/// Installs the tokens and projects them onto gpui-component's theme, so its controls (table,
/// input, scroll bars, menus) draw with the same Fluent values.
pub fn apply(tokens: Tokens, cx: &mut App) {
    let mode = if tokens.dark { ThemeMode::Dark } else { ThemeMode::Light };
    Theme::change(mode, None, cx);
    Theme::update(cx, |theme| {
        theme.font_family = SharedString::new_static(FONT_BODY);
        theme.font_size = px(14.);
        theme.mono_font_family = SharedString::new_static(FONT_MONO);
        theme.mono_font_size = px(12.);
        theme.radius = RADIUS;
        theme.radius_lg = RADIUS_CARD;
        theme.shadow = false;
        theme.background = tokens.canvas;
        theme.foreground = tokens.ink;
        theme.muted_foreground = tokens.ink2;
        theme.border = tokens.rule;
        theme.input = tokens.control_stroke;
        theme.ring = tokens.ink;
        theme.accent = tokens.hover;
        theme.accent_foreground = tokens.ink;
        theme.primary = tokens.accent;
        theme.primary_hover = tokens.accent_hover;
        theme.primary_active = tokens.accent_pressed;
        theme.primary_foreground = tokens.on_accent;
        theme.popover = tokens.flyout;
        theme.popover_foreground = tokens.ink;
        theme.selection = tokens.accent.opacity(0.35);
        theme.caret = tokens.ink;
        theme.table = tokens.surface.opacity(0.);
        theme.table_head = tokens.surface.opacity(0.);
        theme.table_head_foreground = tokens.ink2;
        theme.table_even = tokens.surface2;
        theme.table_hover = tokens.hover;
        theme.table_active = tokens.table_select;
        theme.table_active_border = tokens.accent;
        theme.table_row_border = tokens.rule.opacity(0.);
        theme.list_hover = tokens.hover;
        theme.list_active = tokens.table_select;
        theme.scrollbar = tokens.surface.opacity(0.);
        theme.scrollbar_thumb = tokens.ink3.opacity(0.6);
        theme.scrollbar_thumb_hover = tokens.ink2;
        theme.danger = tokens.bad;
        theme.warning = tokens.warn;
        theme.success = tokens.ok;
    });
    cx.set_global(tokens);
}
