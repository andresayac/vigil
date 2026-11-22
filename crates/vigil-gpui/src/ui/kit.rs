//! The building blocks of the report and maintenance pages: headings, muted and faint text,
//! selectable text, panels, chips, links, badges, read-outs, label/value grids, list rows, meters,
//! an indeterminate progress bar and a stacked bar chart. Everything draws plain text.

use std::rc::Rc;
use std::time::Duration;

use gpui_kit::base::{Button as BaseButton, SelectableText};
use gpui_kit::component::tooltip::Tooltip;
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    Animation, AnimationExt as _, AnyElement, App, Div, ElementId, FontWeight, Hsla, InteractiveElement as _,
    IntoElement, ParentElement, Role, SharedString, Stateful, StatefulInteractiveElement as _, Styled, Toggled, Window,
    div, px, relative,
};
use serde_json::Value;

use crate::icons;
use crate::theme::{FONT_MONO, RADIUS, RADIUS_CARD, Tokens};

static NULL: Value = Value::Null;

/// Reading fields of the JSON the core and the demo give (camelCase, as the report keeps them).
pub trait J {
    fn at(&self, key: &str) -> &Value;
    fn s(&self, key: &str) -> &str {
        self.at(key).as_str().unwrap_or("")
    }
    fn n(&self, key: &str) -> f64 {
        self.at(key).as_f64().unwrap_or(0.0)
    }
    fn i(&self, key: &str) -> i64 {
        let v = self.at(key);
        v.as_i64().or_else(|| v.as_f64().map(|f| f as i64)).unwrap_or(0)
    }
    fn b(&self, key: &str) -> bool {
        self.at(key).as_bool().unwrap_or(false)
    }
    fn a(&self, key: &str) -> &[Value] {
        self.at(key).as_array().map(Vec::as_slice).unwrap_or(&[])
    }
    /// The field is present and not null, false, 0 or empty.
    fn has(&self, key: &str) -> bool {
        truthy(self.at(key))
    }
    /// The strings of an array field.
    fn strs(&self, key: &str) -> Vec<&str> {
        self.a(key).iter().filter_map(Value::as_str).collect()
    }
}

impl J for Value {
    fn at(&self, key: &str) -> &Value {
        self.get(key).unwrap_or(&NULL)
    }
}

/// JavaScript's truthiness, which the page conditions follow.
pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

/// A value as text (numbers without a needless ".0").
pub fn text(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        other => other.to_string(),
    }
}

/// Every word of `query` (lowercase, split on spaces) is in `haystack`.
pub fn matches(query: &str, haystack: &str) -> bool {
    let hay = haystack.to_lowercase();
    query.to_lowercase().split_whitespace().all(|word| hay.contains(word))
}

/// The file name of a Windows path.
pub fn base_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// "some_key" as "Some key".
pub fn humanize(key: &str) -> String {
    let spaced = key.replace('_', " ");
    let mut chars = spaced.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// The smallest of 1, 2, 5, 10 × 10ⁿ that is at least `v`.
pub fn nice_ceiling(v: f64) -> f64 {
    if v <= 0.0 {
        return 1.0;
    }
    let base = 10f64.powf(v.log10().floor());
    [1.0, 2.0, 5.0, 10.0]
        .into_iter()
        .map(|m| m * base)
        .find(|c| *c >= v)
        .unwrap_or(10.0 * base)
}

/// The top of a chart's scale: a nice ceiling, even so the middle line has a whole number.
pub fn chart_top(max: f64) -> f64 {
    let c = nice_ceiling(max.max(1.0));
    if c as i64 % 2 == 1 { (c + 1.0).max(2.0) } else { c }
}

pub fn h1(text: impl Into<SharedString>) -> Div {
    div()
        .font_family(crate::theme::FONT_DISPLAY)
        .text_size(px(24.))
        .font_weight(FontWeight::SEMIBOLD)
        .child(text.into())
}

pub fn h2(text: impl Into<SharedString>) -> Div {
    div()
        .text_size(px(16.))
        .font_weight(FontWeight::SEMIBOLD)
        .child(text.into())
}

pub fn h3(text: impl Into<SharedString>) -> Div {
    div()
        .text_size(px(14.))
        .font_weight(FontWeight::SEMIBOLD)
        .child(text.into())
}

/// A small heading inside a detail pane.
pub fn h4(text: impl Into<SharedString>, tk: &Tokens) -> Div {
    div()
        .pt_2()
        .text_size(px(13.))
        .font_weight(FontWeight::SEMIBOLD)
        .text_color(tk.ink2)
        .child(text.into())
}

pub fn body(text: impl Into<SharedString>) -> Div {
    div().text_size(px(13.)).child(text.into())
}

pub fn muted(text: impl Into<SharedString>, tk: &Tokens) -> Div {
    div().text_size(px(13.)).text_color(tk.ink2).child(text.into())
}

pub fn faint(text: impl Into<SharedString>, tk: &Tokens) -> Div {
    div().text_size(px(12.)).text_color(tk.ink3).child(text.into())
}

pub fn colored(text: impl Into<SharedString>, color: Hsla) -> Div {
    div().text_size(px(13.)).text_color(color).child(text.into())
}

pub fn mono(text: impl Into<SharedString>) -> Div {
    div().font_family(FONT_MONO).text_size(px(12.)).child(text.into())
}

/// Text the mouse can select and copy (Ctrl+C), drawn as plain text.
pub fn sel(id: impl Into<ElementId>, text: impl Into<SharedString>) -> Div {
    div().min_w_0().child(SelectableText::new(id, text))
}

/// Monospace selectable text on a sunken background (a path, a command line).
pub fn code(id: impl Into<ElementId>, text: impl Into<SharedString>, tk: &Tokens) -> Div {
    div()
        .font_family(FONT_MONO)
        .text_size(px(12.))
        .px_2()
        .py_1()
        .rounded(RADIUS)
        .bg(tk.sunken)
        .border_1()
        .border_color(tk.rule)
        .child(SelectableText::new(id, text))
}

/// A panel of the page (a card with room inside).
pub fn panel(tk: &Tokens) -> Div {
    div()
        .flex()
        .flex_col()
        .gap_2()
        .p_4()
        .min_w_0()
        .bg(tk.surface)
        .border_1()
        .border_color(tk.rule)
        .rounded(RADIUS_CARD)
}

/// The scrolling column of a page.
pub fn page(id: &'static str) -> Stateful<Div> {
    div()
        .id(id)
        .size_full()
        .overflow_y_scroll()
        .flex()
        .flex_col()
        .gap_3()
        .px(px(20.))
        .pt(px(12.))
        .pb(px(20.))
}

/// Two columns sharing the width (`left` share of it), stacked when the window is narrow.
pub fn columns(left: f32, a: impl IntoElement, b: impl IntoElement, window: &Window) -> Div {
    let wide = f32::from(window.viewport_size().width) >= 1100.;
    if wide {
        div()
            .flex()
            .gap_3()
            .items_start()
            .child(div().flex_basis(relative(left)).flex_grow(1.).min_w_0().child(a))
            .child(div().flex_basis(relative(1. - left)).flex_grow(1.).min_w_0().child(b))
    } else {
        div().flex().flex_col().gap_3().child(a).child(b)
    }
}

/// A row of controls that wraps.
pub fn row() -> Div {
    div().flex().flex_wrap().items_center().gap_2()
}

/// A dot in a state colour (`None`: transparent).
pub fn dot(color: Option<Hsla>) -> Div {
    div()
        .w(px(8.))
        .h(px(8.))
        .flex_none()
        .rounded(px(4.))
        .when_some(color, |this, c| this.bg(c))
}

/// A filter chip: its label and a count, on or off.
pub fn chip(
    id: impl Into<ElementId>,
    label: impl Into<SharedString>,
    count: Option<usize>,
    on: bool,
    disabled: bool,
    on_click: impl Fn(&mut Window, &mut App) + 'static,
    tk: &Tokens,
) -> AnyElement {
    let label = label.into();
    let tk = *tk;
    let name: SharedString = match count {
        Some(n) => format!("{label} {n}").into(),
        None => label.clone(),
    };
    BaseButton::new(id)
        .role(Role::Button)
        .aria_toggled(if on { Toggled::True } else { Toggled::False })
        .accessibility_label(name)
        .disabled(disabled)
        .flex()
        .items_center()
        .gap_1()
        .h(px(28.))
        .px(px(10.))
        .rounded(px(14.))
        .text_size(px(13.))
        .border_1()
        .border_color(if on { tk.accent } else { tk.control_stroke })
        .bg(if on { tk.table_select } else { tk.control })
        .text_color(if disabled { tk.ink_disabled } else { tk.ink })
        .when(!disabled, |this| this.hover(move |s| s.bg(tk.control_hover)))
        .on_click(move |_, window, cx| on_click(window, cx))
        .child(label)
        .when_some(count, |this, n| {
            this.child(div().text_color(tk.ink3).child(n.to_string()))
        })
        .into_any_element()
}

/// A text link (accent colour) that runs `on_click`.
pub fn link(
    id: impl Into<ElementId>,
    label: impl Into<SharedString>,
    on_click: impl Fn(&mut Window, &mut App) + 'static,
    tk: &Tokens,
) -> Div {
    let label = label.into();
    let accent = tk.accent;
    div().flex().flex_none().child(
        BaseButton::new(id)
            .role(Role::Link)
            .accessibility_label(label.clone())
            .text_size(px(13.))
            .text_color(accent)
            .hover(|s| s.underline())
            .on_click(move |_, window, cx| on_click(window, cx))
            .child(label),
    )
}

/// A small label in a border (a badge in a list row).
pub fn badge(text: impl Into<SharedString>, color: Option<Hsla>, tk: &Tokens) -> Div {
    let color = color.unwrap_or(tk.ink2);
    div()
        .flex_none()
        .px(px(6.))
        .rounded(px(3.))
        .border_1()
        .border_color(color.opacity(0.5))
        .text_size(px(12.))
        .text_color(color)
        .child(text.into())
}

/// A pill: solid (the colour behind on-chart text) or tinted.
pub fn pill(text: impl Into<SharedString>, color: Hsla, solid: bool, tk: &Tokens) -> Div {
    let base = div()
        .flex_none()
        .px(px(8.))
        .py(px(1.))
        .rounded(px(10.))
        .text_size(px(12.))
        .font_weight(FontWeight::SEMIBOLD)
        .child(text.into());
    if solid {
        base.bg(color).text_color(tk.on_chart)
    } else {
        base.bg(color.opacity(0.12))
            .border_1()
            .border_color(color.opacity(0.35))
            .text_color(color)
    }
}

/// One read-out line: a state dot, a name and a value (with a tooltip).
pub struct Readout {
    pub status: Option<Hsla>,
    pub name: String,
    pub value: String,
    pub tip: Option<String>,
}

impl Readout {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            status: None,
            name: name.into(),
            value: value.into(),
            tip: None,
        }
    }
    pub fn status(mut self, status: Option<Hsla>) -> Self {
        self.status = status;
        self
    }
    pub fn tip(mut self, tip: impl Into<String>) -> Self {
        let tip = tip.into();
        self.tip = (!tip.is_empty()).then_some(tip);
        self
    }
}

/// Read-outs: a column of state dots, names and selectable values.
pub fn readouts(id: &'static str, rows: Vec<Readout>, name_width: f32, tk: &Tokens) -> Div {
    let tk = *tk;
    div()
        .flex()
        .flex_col()
        .gap(px(2.))
        .children(rows.into_iter().enumerate().map(move |(i, r)| {
            let tip = r.tip.clone().unwrap_or_else(|| r.value.clone());
            div()
                .id(ElementId::NamedInteger(id.into(), i as u64))
                .flex()
                .items_center()
                .gap_2()
                .min_h(px(24.))
                .text_size(px(13.))
                .tooltip(move |window, cx| Tooltip::new(tip.clone()).build(window, cx))
                .child(dot(r.status))
                .child(
                    div()
                        .w(px(name_width))
                        .flex_none()
                        .text_size(px(12.))
                        .text_color(tk.ink3)
                        .child(r.name),
                )
                .child(sel(ElementId::NamedInteger(format!("{id}-v").into(), i as u64), r.value).flex_1())
        }))
}

/// A label/value grid line (the value an element).
pub fn kv(label: impl Into<SharedString>, value: impl IntoElement, width: f32, tk: &Tokens) -> Div {
    div()
        .flex()
        .gap_3()
        .text_size(px(13.))
        .child(div().w(px(width)).flex_none().text_color(tk.ink3).child(label.into()))
        .child(div().flex_1().min_w_0().child(value))
}

/// A label/value line whose value is selectable text.
pub fn kv_text(
    id: impl Into<ElementId>,
    label: impl Into<SharedString>,
    value: impl Into<SharedString>,
    mono_font: bool,
    width: f32,
    tk: &Tokens,
) -> Div {
    let value = sel(id, value).when(mono_font, |this| this.font_family(FONT_MONO).text_size(px(12.)));
    kv(label, value, width, tk)
}

/// A selectable row of a list (a button with its own content), keyboard reachable.
pub fn list_row(
    id: impl Into<ElementId>,
    name: impl Into<SharedString>,
    selected: bool,
    on_click: impl Fn(&mut Window, &mut App) + 'static,
    tk: &Tokens,
) -> BaseButton {
    let tk = *tk;
    BaseButton::new(id)
        .role(Role::ListItem)
        .accessibility_label(name.into())
        .aria_selected(selected)
        .w_full()
        .flex()
        .items_center()
        .justify_start()
        .gap_2()
        .min_h(px(30.))
        .px_2()
        .rounded(RADIUS)
        .text_size(px(13.))
        .when(selected, |this| this.bg(tk.table_select))
        .when(!selected, |this| this.hover(move |s| s.bg(tk.hover)))
        .on_click(move |_, window, cx| on_click(window, cx))
}

/// A horizontal meter: `fraction` of the track filled with `color`.
pub fn meter(fraction: f64, color: Hsla, width: Option<f32>, height: f32, tk: &Tokens) -> Div {
    let f = fraction.clamp(0.0, 1.0) as f32;
    div()
        .when_some(width, |this, w| this.w(px(w)).flex_none())
        .when(width.is_none(), |this| this.w_full())
        .h(px(height))
        .rounded(px(height / 2.))
        .bg(tk.sunken)
        .border_1()
        .border_color(tk.rule)
        .overflow_hidden()
        .child(div().h_full().w(relative(f.max(0.02))).bg(color))
}

/// A usage bar: the chart colour, warning and bad colours near full.
pub fn usage_bar(fraction: f64, tk: &Tokens) -> Div {
    let color = if fraction >= 0.95 {
        tk.bad
    } else if fraction >= 0.85 {
        tk.warn
    } else {
        tk.chart_cpu
    };
    meter(fraction, color, None, 10., tk)
}

/// Segments of one bar, each a share of `total`, with a legend.
pub fn stacked_bar(parts: &[(String, f64, Hsla)], total: f64, height: f32, tk: &Tokens) -> Div {
    let total = if total > 0.0 { total } else { 1.0 };
    div()
        .w_full()
        .h(px(height))
        .flex()
        .rounded(RADIUS)
        .overflow_hidden()
        .bg(tk.sunken)
        .border_1()
        .border_color(tk.rule)
        .children(parts.iter().map(|(_, value, color)| {
            div()
                .h_full()
                .w(relative((value / total).clamp(0.0, 1.0) as f32))
                .bg(*color)
        }))
}

/// A bar that slides while something runs for an unknown time.
pub fn busy_bar(id: &'static str, tk: &Tokens) -> impl IntoElement {
    let chart = tk.chart_cpu;
    div()
        .w_full()
        .h(px(4.))
        .rounded(px(2.))
        .bg(tk.sunken)
        .overflow_hidden()
        .relative()
        .child(
            div()
                .absolute()
                .top_0()
                .h_full()
                .w(relative(0.4))
                .bg(chart)
                .with_animation(
                    id,
                    Animation::new(Duration::from_millis(1400)).repeat(),
                    |this, delta| this.left(relative(delta * 1.4 - 0.4)),
                ),
        )
}

/// A glyph in a colour, as text inline.
pub fn glyph(g: char, size: f32, color: Hsla) -> Div {
    icons::icon(g, size, color)
}

/// What clicking a chart column does (its key).
pub type OnPick = Rc<dyn Fn(String, &mut Window, &mut App)>;

/// One column of a bar chart: its segments from the bottom, a mark under it, its labels.
pub struct BarColumn {
    pub key: String,
    /// What a screen reader says, and the tooltip's title.
    pub name: String,
    pub segments: Vec<(f64, Hsla)>,
    /// Lines of the tooltip under its title.
    pub tip: Vec<String>,
    /// A dot under the bar (installs on the Reliability chart).
    pub mark: bool,
    pub label: String,
}

/// A stacked bar chart: one column per day, a 0 / half / top scale, a tooltip per column,
/// clicking a column picks it (`picked` dims the others).
pub fn bar_chart(
    id: &'static str,
    columns: Vec<BarColumn>,
    top: f64,
    height: f32,
    picked: Option<String>,
    on_pick: Option<OnPick>,
    tk: &Tokens,
) -> Div {
    let tk = *tk;
    let top = if top > 0.0 { top } else { 1.0 };
    let fmt = |v: f64| crate::format::num(v, 0);
    let scale = div()
        .w(px(32.))
        .flex_none()
        .h(px(height))
        .flex()
        .flex_col()
        .justify_between()
        .items_end()
        .pr_1()
        .text_size(px(11.))
        .text_color(tk.ink3)
        .child(fmt(top))
        .child(fmt(top / 2.0))
        .child("0");
    let n = columns.len().max(1);
    let any_mark = columns.iter().any(|c| c.mark);
    let mut bars = div()
        .flex_1()
        .h(px(height))
        .relative()
        .flex()
        .items_end()
        .border_b_1()
        .border_color(tk.rule_strong)
        .child(div().absolute().top_0().left_0().right_0().h(px(1.)).bg(tk.rule))
        .child(
            div()
                .absolute()
                .top(relative(0.5))
                .left_0()
                .right_0()
                .h(px(1.))
                .bg(tk.rule),
        );
    let mut marks = div().flex_1().flex().h(px(12.));
    let mut labels = div().flex_1().flex().text_size(px(11.)).text_color(tk.ink3);
    for (i, col) in columns.into_iter().enumerate() {
        let on = picked.as_deref() == Some(col.key.as_str());
        let dim = picked.is_some() && !on;
        let title = col.name.clone();
        let tip_lines = col.tip.clone();
        let pick = on_pick.clone();
        let key = col.key.clone();
        let stack = div()
            .w(relative(0.8))
            .max_w(px(18.))
            .h_full()
            .flex()
            .flex_col_reverse()
            .gap(px(1.))
            .children(col.segments.iter().filter(|(v, _)| *v > 0.0).map(|(v, color)| {
                div()
                    .w_full()
                    .h(relative((*v / top).clamp(0.0, 1.0) as f32))
                    .min_h(px(2.))
                    .rounded(px(1.))
                    .bg(*color)
            }));
        bars = bars.child(
            div()
                .id(ElementId::NamedInteger(id.into(), i as u64))
                .role(Role::Button)
                .aria_label(SharedString::from(format!("{}: {}", col.name, col.tip.join(", "))))
                .flex_1()
                .h_full()
                .flex()
                .justify_center()
                .items_end()
                .px(px(1.))
                .when(on, |this| this.bg(tk.table_select))
                .when(dim, |this| this.opacity(0.35))
                .hover(move |s| s.bg(tk.hover))
                .tooltip(move |window, cx| {
                    let title = title.clone();
                    let lines = tip_lines.clone();
                    Tooltip::element(move |_, _| {
                        div()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(div().font_weight(FontWeight::SEMIBOLD).child(title.clone()))
                            .children(lines.iter().map(|l| div().child(l.clone())))
                    })
                    .build(window, cx)
                })
                .when_some(pick, |this, pick| {
                    this.on_click(move |_, window, cx| pick(key.clone(), window, cx))
                })
                .child(stack),
        );
        marks = marks.child(
            div()
                .flex_1()
                .flex()
                .justify_center()
                .items_center()
                .when(col.mark, |this| {
                    this.child(div().w(px(6.)).h(px(6.)).rounded(px(3.)).bg(tk.ink3))
                }),
        );
        labels = labels.child(
            div()
                .flex_1()
                .min_w_0()
                .overflow_hidden()
                .whitespace_nowrap()
                .flex()
                .justify_center()
                .when(i + 1 == n, |this| this.justify_end())
                .child(col.label),
        );
    }
    div()
        .flex()
        .flex_col()
        .child(div().flex().child(scale).child(bars))
        .when(any_mark, |this| {
            this.child(div().flex().child(div().w(px(32.)).flex_none()).child(marks))
        })
        .child(div().flex().child(div().w(px(32.)).flex_none()).child(labels))
}

/// An image from a `data:` URL (PNG, JPEG, GIF, WebP, BMP or ICO), drawn as an image only.
pub fn image(url: &str) -> Option<std::sync::Arc<gpui_kit::Image>> {
    use gpui_kit::ImageFormat;
    let mime = url.strip_prefix("data:")?.split(';').next()?;
    let format = match mime {
        "image/png" => ImageFormat::Png,
        "image/jpeg" => ImageFormat::Jpeg,
        "image/gif" => ImageFormat::Gif,
        "image/webp" => ImageFormat::Webp,
        "image/bmp" => ImageFormat::Bmp,
        "image/x-icon" | "image/vnd.microsoft.icon" => ImageFormat::Ico,
        _ => return None,
    };
    let bytes = crate::format::data_url_bytes(url)?;
    Some(std::sync::Arc::new(gpui_kit::Image::from_bytes(format, bytes)))
}

/// The labels under a day chart: today at the end, a short date every few columns.
pub fn day_labels(count: usize, short: impl Fn(usize) -> String, today: &str) -> Vec<String> {
    let every = count.div_ceil(6).max(1);
    (0..count)
        .map(|i| {
            if i + 1 == count {
                today.to_string()
            } else if (count - 1 - i).is_multiple_of(every) && (i as f64) < count as f64 - every as f64 / 2.0 {
                short(i)
            } else {
                String::new()
            }
        })
        .collect()
}

/// The last `days` local calendar days, oldest first, as "YYYY-MM-DD".
pub fn last_days(days: usize) -> Vec<String> {
    let now = crate::format::now_ms();
    let offset = local_offset_ms();
    let today = (now + offset).div_euclid(86_400_000);
    (0..days as i64).rev().map(|back| civil(today - back)).collect()
}

/// The local time zone's offset from UTC now, in milliseconds.
pub fn local_offset_ms() -> i64 {
    use windows::Win32::System::Time::{GetTimeZoneInformation, TIME_ZONE_INFORMATION};
    const TIME_ZONE_ID_DAYLIGHT: u32 = 2;
    let mut info = TIME_ZONE_INFORMATION::default();
    // SAFETY: `info` is a valid, writable TIME_ZONE_INFORMATION for the call.
    let id = unsafe { GetTimeZoneInformation(&mut info) };
    let mut bias = info.Bias;
    if id == TIME_ZONE_ID_DAYLIGHT {
        bias += info.DaylightBias;
    } else {
        bias += info.StandardBias;
    }
    -(bias as i64) * 60_000
}

/// The date of a day number since 1970-01-01 (proleptic Gregorian).
pub fn civil(days: i64) -> String {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

/// A local ISO time ("2026-01-01T10:05:00") of a moment in milliseconds.
pub fn local_iso(ms: i64) -> String {
    if ms <= 0 {
        return String::new();
    }
    let local = ms + local_offset_ms();
    let day = local.div_euclid(86_400_000);
    let rest = local.rem_euclid(86_400_000) / 1000;
    format!(
        "{}T{:02}:{:02}:{:02}",
        civil(day),
        rest / 3600,
        (rest % 3600) / 60,
        rest % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_and_scales() {
        assert_eq!(civil(0), "1970-01-01");
        assert_eq!(civil(20_454), "2026-01-01");
        assert_eq!(nice_ceiling(3.0), 5.0);
        assert_eq!(nice_ceiling(0.0), 1.0);
        assert_eq!(nice_ceiling(11.0), 20.0);
        assert_eq!(chart_top(1.0), 2.0);
        assert_eq!(chart_top(4.0), 6.0);
        assert_eq!(chart_top(12.0), 20.0);
        assert_eq!(day_labels(3, |i| i.to_string(), "T"), vec!["0", "1", "T"]);
        assert!(matches("foo BAR", "the bar of foo"));
        assert_eq!(humanize("signature_age_days"), "Signature age days");
    }
}
