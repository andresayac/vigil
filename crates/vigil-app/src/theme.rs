//! Vigil's tokens: the WinUI 3 metrics and roles, in the palette of Vigil's logo (deep teal
//! `#035568`, emerald `#03C488`, mint `#7DFABD`), light and dark.
//!
//! Colour carries meaning: verdict colours only for verdicts, the `chart_*`
//! resource hues only for live measurements, `ok` / `warn` / `bad` only for state, `heat` only for
//! the process table's heat map, the accent only for interactive elements, `brand` only for brand
//! marks. Everything else is ink and teal-tinted greys.

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

/// The WinUI token set, light and dark.
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
    /// The logo's green, for brand marks only: the selected page's indicator, the logo.
    pub brand: Hsla,
    /// A faint wash of the brand green (the selected page's fill).
    pub brand_soft: Hsla,
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
    pub verdict_no_signals: Hsla,
    pub verdict_safe: Hsla,
    pub verdict_trusted: Hsla,
    /// Text on a chart or verdict colour.
    pub on_chart: Hsla,
    pub chart2: Hsla,
    pub sunken: Hsla,
}

impl Global for Tokens {}

fn hex(value: u32) -> Hsla {
    rgb(value).into()
}

fn hexa(value: u32) -> Hsla {
    rgba(value).into()
}

impl Tokens {
    /// Light: neutrals tinted with the logo's teal, the deep teal (`#035568`) as the accent and the
    /// emerald (`#03C488`) for the brand marks (the selected page, the logo).
    pub fn light(mica: bool) -> Self {
        let accent = hex(0x035568);
        Self {
            dark: false,
            mica,
            // Over Mica the bases stay nearly opaque: the wallpaper's tint must not recolour the palette.
            canvas: if mica { hexa(0xe9efeee6) } else { hex(0xe9efee) },
            layer: if mica { hexa(0xf5f8f7f5) } else { hex(0xf5f8f7) },
            layer_stroke: hexa(0x0a2a300f),
            surface: hex(0xffffff),
            surface2: hex(0xf9fbfb),
            flyout: hex(0xfcfdfd),
            ink: hex(0x0e2226),
            ink2: hex(0x4a5e62),
            ink3: hex(0x74878a),
            ink_disabled: hex(0xa6b3b4),
            rule: hex(0xe1e8e7),
            rule_strong: hex(0xcad5d4),
            hover: hexa(0x0a2a300a),
            pressed: hexa(0x0a2a3006),
            control: hex(0xfbfcfc),
            control_hover: hex(0xf3f7f6),
            control_stroke: hex(0xdbe3e2),
            control_stroke_bottom: hex(0xc4cfce),
            input_bg: hex(0xffffff),
            accent,
            accent_hover: hex(0x0d6679),
            accent_pressed: hex(0x1b7689),
            on_accent: hex(0xffffff),
            brand: hex(0x03c488),
            brand_soft: hex(0x03c488).opacity(0.14),
            table_select: accent.opacity(0.10),
            ok: hex(0x0f7b0f),
            warn: hex(0x9d5d00),
            bad: hex(0xc42b1c),
            chart_cpu: hex(0x0f6cbd),
            chart_memory: hex(0x8a3fb8),
            chart_disk: hex(0x3d8b0f),
            chart_net: hex(0xb35c00),
            chart_gpu: hex(0x0e7a8a),
            heat: [
                hex(0xeef7f4),
                hex(0xdcf1ea),
                hex(0xc9eadf),
                hex(0xb3e1d2),
                hex(0x93d4c0),
            ],
            heat_rule: hexa(0xffffffcc),
            verdict_remove: hex(0xc42b1c),
            verdict_disable: hex(0x9d5d00),
            verdict_review: hex(0x6b3fd1),
            verdict_no_signals: hex(0x6b7b7d),
            verdict_safe: hex(0x0f7b0f),
            verdict_trusted: hex(0x9aa7a8),
            on_chart: hex(0xffffff),
            chart2: hex(0x0e7a8a),
            sunken: hex(0xf0f4f3),
        }
    }

    /// Dark: deep neutrals tinted with the logo's teal, the emerald (`#03C488`) as the accent.
    pub fn dark(mica: bool) -> Self {
        let accent = hex(0x03c488);
        Self {
            dark: true,
            mica,
            canvas: if mica { hexa(0x0c1416e6) } else { hex(0x0c1416) },
            layer: if mica { hexa(0x111b1ef5) } else { hex(0x111b1e) },
            layer_stroke: hexa(0xffffff0d),
            surface: hex(0x162327),
            surface2: hex(0x19272b),
            flyout: hex(0x1b292d),
            ink: hex(0xe8f1ef),
            ink2: hex(0xadc0bd),
            ink3: hex(0x7e9390),
            ink_disabled: hex(0x50625f),
            rule: hex(0x213236),
            rule_strong: hex(0x2c3f43),
            hover: hexa(0xffffff0d),
            pressed: hexa(0xffffff08),
            control: hex(0x1a292d),
            control_hover: hex(0x203135),
            control_stroke: hex(0x2a3c40),
            control_stroke_bottom: hex(0x33484c),
            input_bg: hex(0x0e171a),
            accent,
            accent_hover: hex(0x1fd39b),
            accent_pressed: hex(0x02a874),
            on_accent: hex(0x03262d),
            brand: hex(0x7dfabd),
            brand_soft: hex(0x03c488).opacity(0.16),
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
                hex(0x15282b),
                hex(0x173338),
                hex(0x1a4047),
                hex(0x1d4e57),
                hex(0x215f6a),
            ],
            heat_rule: hexa(0x00000059),
            verdict_remove: hex(0xff99a4),
            verdict_disable: hex(0xf6c343),
            verdict_review: hex(0xc4a7ff),
            verdict_no_signals: hex(0x9aaaa8),
            verdict_safe: hex(0x6ccb5f),
            verdict_trusted: hex(0x627673),
            on_chart: hex(0x000000),
            chart2: hex(0x4cc9d6),
            sunken: hex(0x0b1315),
        }
    }

    /// The verdict colour of a finding ("remove", "disable", "review").
    pub fn verdict(&self, verdict: &str) -> Hsla {
        match verdict {
            "remove" => self.verdict_remove,
            "disable" => self.verdict_disable,
            "review" => self.verdict_review,
            "no_signals" => self.verdict_no_signals,
            "safe" => self.verdict_safe,
            "trusted" => self.verdict_trusted,
            _ => self.ink3,
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
