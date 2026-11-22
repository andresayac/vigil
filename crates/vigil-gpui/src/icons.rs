//! Segoe Fluent Icons glyphs (the code points the web UI uses) and the element that draws one.

use gpui_kit::{Div, Hsla, ParentElement, Styled, div, px};

use crate::theme::FONT_ICONS;

pub const HAMBURGER: char = '\u{E700}';
pub const SEARCH: char = '\u{E721}';
pub const SCAN: char = '\u{E721}';
pub const SHIELD: char = '\u{E7EF}';
pub const MORE: char = '\u{E712}';
pub const SETTINGS: char = '\u{E713}';
pub const END_TASK: char = '\u{E733}';
pub const EFFICIENCY: char = '\u{EC0A}';
pub const CHEVRON_RIGHT: char = '\u{E76C}';
pub const CHEVRON_DOWN: char = '\u{E70D}';
pub const INFO: char = '\u{E946}';
pub const FOLDER: char = '\u{E838}';
pub const VERIFY: char = '\u{E8D7}';
pub const SUSPEND: char = '\u{E769}';
pub const RESUME: char = '\u{E768}';

/// The glyph of each page in the navigation pane, by page key.
pub fn page(key: &str) -> char {
    match key {
        "overview" => '\u{E80F}',
        "findings" => '\u{EA18}',
        "alerts" => '\u{EA8F}',
        "protection" => '\u{F760}',
        "posture" => '\u{E9D5}',
        "firewall" => '\u{E83D}',
        "accounts" => '\u{E77B}',
        "extensions" => '\u{EA86}',
        "quarantine" => '\u{E7B8}',
        "history" => '\u{E81C}',
        "performance" => '\u{E9D9}',
        "processes" => '\u{E7C4}',
        "network" => '\u{E774}',
        "services" => '\u{EA86}',
        "optimize" => '\u{EC4A}',
        "startup" => '\u{E7E8}',
        "tasks" => '\u{E787}',
        "programs" => '\u{E71D}',
        "storage" => '\u{EDA2}',
        "system" => '\u{E950}',
        "reliability" => '\u{E95E}',
        _ => '\u{E8A5}',
    }
}

/// One icon glyph, `size` pixels, in `color`.
pub fn icon(glyph: char, size: f32, color: Hsla) -> Div {
    div()
        .flex_none()
        .font_family(FONT_ICONS)
        .text_size(px(size))
        .line_height(px(size))
        .text_color(color)
        .child(glyph.to_string())
}
