//! Names and colours of verdicts, kinds, risk levels and states.

use gpui_kit::Hsla;
use serde_json::Value;

use crate::i18n::t_or;
use crate::theme::Tokens;
use crate::ui::kit::J as _;

pub const VERDICT_ORDER: [&str; 6] = ["remove", "disable", "review", "no_signals", "safe", "trusted"];
pub const KINDS: [&str; 7] = [
    "executable",
    "command",
    "group",
    "program",
    "extension",
    "event",
    "config",
];

pub fn verdict_label(v: &str) -> String {
    t_or(&format!("verdict.{v}"), v)
}

pub fn verdict_rank(v: &str) -> usize {
    VERDICT_ORDER
        .iter()
        .position(|o| *o == v)
        .unwrap_or(VERDICT_ORDER.len())
}

pub fn kind_label(k: &str) -> String {
    t_or(&format!("kind.{k}"), k)
}

pub fn risk_label(level: &str) -> String {
    match level {
        "low" | "moderate" | "high" | "critical" => t_or(&format!("risk.{level}"), level),
        _ => t_or("risk.local", level),
    }
}

pub fn risk_color(level: &str, tk: &Tokens) -> Hsla {
    match level {
        "low" => tk.verdict_safe,
        "moderate" => tk.verdict_disable,
        "high" | "critical" => tk.verdict_remove,
        _ => tk.ink2,
    }
}

/// "ok" / "warn" / "bad" as a colour (`None`: no state).
pub fn state_color(state: &str, tk: &Tokens) -> Option<Hsla> {
    match state {
        "ok" => Some(tk.ok),
        "warn" => Some(tk.warn),
        "bad" => Some(tk.bad),
        _ => None,
    }
}

/// Sorts findings by verdict, then score (highest first).
pub fn by_verdict(a: &Value, b: &Value) -> std::cmp::Ordering {
    verdict_rank(a.s("verdict"))
        .cmp(&verdict_rank(b.s("verdict")))
        .then(b.n("score").total_cmp(&a.n("score")))
}
