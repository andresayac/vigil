//! Segoe Fluent Icons glyphs and the element that draws one.

use gpui_kit::{Div, Hsla, ParentElement, Styled, div, px};

use crate::theme::FONT_ICONS;

pub const HAMBURGER: char = '\u{E700}';
pub const SEARCH: char = '\u{E721}';
pub const SCAN: char = '\u{E721}';
pub const SHIELD: char = '\u{E7EF}';
/// A plain shield (the verdict of a scan).
pub const SHIELD_PLAIN: char = '\u{EA18}';
pub const MORE: char = '\u{E712}';
pub const SETTINGS: char = '\u{E713}';
pub const END_TASK: char = '\u{E733}';
pub const EFFICIENCY: char = '\u{EC0A}';
pub const CHEVRON_RIGHT: char = '\u{E76C}';
pub const CHEVRON_DOWN: char = '\u{E70D}';
pub const ARROW_UP: char = '\u{E74A}';
pub const ARROW_DOWN: char = '\u{E74B}';
pub const SORT: char = '\u{E8CB}';
pub const INFO: char = '\u{E946}';
pub const FOLDER: char = '\u{E838}';
/// Save (exporting findings to a file).
pub const EXPORT: char = '\u{E74E}';
pub const CHECK: char = '\u{E73E}';
pub const SUCCESS: char = '\u{E930}';
pub const WARNING: char = '\u{E7BA}';
pub const ERROR: char = '\u{EA39}';
pub const CANCEL: char = '\u{E711}';
pub const START: char = '\u{E768}';
pub const STOP: char = '\u{E71A}';
pub const REFRESH: char = '\u{E72C}';
pub const LOCK: char = '\u{E72E}';
pub const DELETE: char = '\u{E74D}';
pub const PROPERTIES: char = '\u{E946}';
pub const PRIORITY: char = '\u{E8CB}';
pub const FILE: char = '\u{E8A5}';
pub const UNDO: char = '\u{E7A7}';
pub const PAUSE: char = '\u{E769}';
pub const APP: char = '\u{ECAA}';

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
        "restore" => '\u{E777}',
        "system" => '\u{E950}',
        "updates" => '\u{E895}',
        "power" => '\u{E83F}',
        "reliability" => '\u{E95E}',
        "assistant" => '\u{E8F2}',
        _ => '\u{E8A5}',
    }
}

/// The glyph of a section of the navigation pane.
pub fn section(key: &str) -> char {
    match key {
        "home" => '\u{E80F}',
        "assistant" => '\u{E8F2}',
        "security" => '\u{EA18}',
        "live" => '\u{E9D9}',
        "cleanup" => '\u{EA99}',
        "apps" => '\u{ECAA}',
        "system" => '\u{E7F4}',
        "activity" => '\u{E81C}',
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
