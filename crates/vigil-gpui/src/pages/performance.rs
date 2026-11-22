//! The Performance page in Task Manager's layout (a first slice of `ui/src/pages/Performance.svelte`):
//! the resource list on the left with live thumbnails, the selected resource on the right with its
//! 60-second chart and the statistics in large figures. CPU and memory for now; the charts are
//! drawn on a GPUI canvas (filled area and line, a grid tinted with the resource hue).

use std::collections::VecDeque;

use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    Bounds, ClickEvent, Context, Div, Entity, FontWeight, Hsla, InteractiveElement, IntoElement, ParentElement,
    PathBuilder, Pixels, Render, StatefulInteractiveElement, Styled, Subscription, Window, canvas, div, point, px,
};

use crate::format::{num, pct, size};
use crate::i18n::{t, tf, tn};
use crate::live::{HISTORY, Live};
use crate::theme::{FONT_DISPLAY, RADIUS, RADIUS_CARD, Tokens, tokens};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Resource {
    Cpu,
    Memory,
}

pub struct PerformancePage {
    live: Entity<Live>,
    selected: Resource,
    _subscription: Subscription,
}

impl PerformancePage {
    pub fn new(live: Entity<Live>, cx: &mut Context<Self>) -> Self {
        let subscription = cx.observe(&live, |_, _, cx| cx.notify());
        Self {
            live,
            selected: Resource::Cpu,
            _subscription: subscription,
        }
    }
}

/// A filled area under a line, values 0-100, newest on the right, the full width standing for
/// `HISTORY` seconds (Task Manager's chart).
fn chart(values: Vec<f32>, hue: Hsla, tk: Tokens, grid: bool) -> impl IntoElement {
    canvas(
        |_, _, _| {},
        move |bounds: Bounds<Pixels>, _, window, _| {
            let w = f32::from(bounds.size.width);
            let h = f32::from(bounds.size.height);
            let x0 = f32::from(bounds.origin.x);
            let y0 = f32::from(bounds.origin.y);
            if grid {
                let rule = hue.opacity(if tk.dark { 0.22 } else { 0.16 });
                for i in 1..10 {
                    let y = y0 + h * i as f32 / 10.0;
                    window.paint_quad(gpui_kit::fill(
                        Bounds::new(point(px(x0), px(y)), gpui_kit::size(px(w), px(1.))),
                        rule,
                    ));
                }
                for i in 1..20 {
                    let x = x0 + w * i as f32 / 20.0;
                    window.paint_quad(gpui_kit::fill(
                        Bounds::new(point(px(x), px(y0)), gpui_kit::size(px(1.), px(h))),
                        rule,
                    ));
                }
            }
            if values.len() < 2 {
                return;
            }
            let step = w / (HISTORY - 1) as f32;
            let start = x0 + w - step * (values.len() - 1) as f32;
            let at = |i: usize, v: f32| {
                point(
                    px(start + step * i as f32),
                    px(y0 + h - h * v.clamp(0.0, 100.0) / 100.0),
                )
            };
            let mut area = PathBuilder::fill();
            area.move_to(point(px(start), px(y0 + h)));
            for (i, v) in values.iter().enumerate() {
                area.line_to(at(i, *v));
            }
            area.line_to(point(px(x0 + w), px(y0 + h)));
            area.close();
            if let Ok(path) = area.build() {
                window.paint_path(path, hue.opacity(if tk.dark { 0.28 } else { 0.14 }));
            }
            let mut line = PathBuilder::stroke(px(1.5));
            for (i, v) in values.iter().enumerate() {
                if i == 0 {
                    line.move_to(at(i, *v));
                } else {
                    line.line_to(at(i, *v));
                }
            }
            if let Ok(path) = line.build() {
                window.paint_path(path, hue);
            }
        },
    )
    .size_full()
}

fn series(values: &VecDeque<f32>) -> Vec<f32> {
    values.iter().copied().collect()
}

fn stat(name: String, value: String, tk: &Tokens) -> Div {
    div()
        .flex()
        .flex_col()
        .min_w(px(120.))
        .child(div().text_size(px(12.)).text_color(tk.ink2).child(name))
        .child(
            div()
                .font_family(FONT_DISPLAY)
                .text_size(px(20.))
                .line_height(px(28.))
                .child(value),
        )
}

fn uptime(seconds: f64) -> String {
    let s = seconds.max(0.0) as u64;
    let (days, hours, minutes) = (s / 86_400, (s % 86_400) / 3_600, (s % 3_600) / 60);
    let hm = format!("{hours}:{minutes:02}");
    if days > 0 {
        tf("time.uptimeDays", &[("days", &days.to_string()), ("hm", &hm)])
    } else {
        hm
    }
}

impl Render for PerformancePage {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let live = self.live.read(cx);
        let snap = live.snapshot.clone();
        let cpu = series(&live.cpu);
        let memory = series(&live.memory);

        let tile = |id: &'static str,
                    resource: Resource,
                    title: String,
                    line: String,
                    values: Vec<f32>,
                    hue: Hsla,
                    cx: &mut Context<Self>| {
            let selected = self.selected == resource;
            div()
                .id(id)
                .flex()
                .items_center()
                .gap_3()
                .p_2()
                .rounded(RADIUS)
                .when(selected, |this| this.bg(tk.hover))
                .hover(|s| s.bg(tk.hover))
                .child(
                    div()
                        .w(px(70.))
                        .h(px(44.))
                        .flex_none()
                        .border_1()
                        .border_color(hue)
                        .bg(tk.surface)
                        .child(chart(values, hue, tk, false)),
                )
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .min_w_0()
                        .child(div().font_weight(FontWeight::SEMIBOLD).child(title))
                        .child(div().text_size(px(12.)).text_color(tk.ink2).child(line)),
                )
                .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                    this.selected = resource;
                    cx.notify();
                }))
        };

        let (cpu_line, memory_line) = match &snap {
            Some(s) => {
                let used = s.memory.used as f64 / s.memory.total.max(1) as f64 * 100.0;
                (
                    format!(
                        "{} {}",
                        pct(f64::from(s.cpu), 0),
                        tf("unit.ghz", &[("n", &num(f64::from(s.freq_mhz) / 1000.0, 2))])
                    ),
                    format!(
                        "{}/{} ({})",
                        size(s.memory.used as f64, 1),
                        size(s.memory.total as f64, 1),
                        pct(used, 0)
                    ),
                )
            }
            None => (t("perf.readingCounters"), String::new()),
        };

        let (title, hue, values, caption, stats) = match (self.selected, &snap) {
            (Resource::Cpu, Some(s)) => (
                t("res.cpu"),
                tk.chart_cpu,
                cpu.clone(),
                t("perf.utilizationPct"),
                vec![
                    (t("perf.utilization"), pct(f64::from(s.cpu), 0)),
                    (
                        t("perf.speed"),
                        tf("unit.ghz", &[("n", &num(f64::from(s.freq_mhz) / 1000.0, 2))]),
                    ),
                    (t("perf.processes"), num(f64::from(s.processes), 0)),
                    (t("perf.threads"), num(f64::from(s.threads), 0)),
                    (t("perf.handles"), num(f64::from(s.handles), 0)),
                    (t("perf.uptime"), uptime(s.uptime_s)),
                ],
            ),
            (Resource::Memory, Some(s)) => (
                t("res.memory"),
                tk.chart_memory,
                memory.clone(),
                t("perf.memoryUsage"),
                vec![
                    (
                        t("perf.inUseCompressed"),
                        format!(
                            "{} ({})",
                            size(s.memory.used as f64, 1),
                            size(s.memory.compressed as f64, 1)
                        ),
                    ),
                    (t("perf.available"), size(s.memory.available as f64, 1)),
                    (
                        t("perf.committed"),
                        format!(
                            "{}/{}",
                            size(s.memory.commit as f64, 1),
                            size(s.memory.commit_limit as f64, 1)
                        ),
                    ),
                    (t("perf.cached"), size((s.memory.standby + s.memory.modified) as f64, 1)),
                    (t("perf.pagedPool"), size(s.memory.paged_pool as f64, 1)),
                    (t("perf.nonPagedPool"), size(s.memory.nonpaged_pool as f64, 1)),
                ],
            ),
            (resource, None) => (
                t(if resource == Resource::Cpu {
                    "res.cpu"
                } else {
                    "res.memory"
                }),
                tk.chart_cpu,
                Vec::new(),
                t("perf.readingCounters"),
                Vec::new(),
            ),
        };
        let subtitle = match (self.selected, &snap) {
            (Resource::Memory, Some(s)) => size(s.memory.total as f64, 1),
            _ => String::new(),
        };

        div()
            .size_full()
            .flex()
            .gap_4()
            .px(px(20.))
            .py(px(16.))
            .child(
                div()
                    .w(px(260.))
                    .flex_none()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(
                        div()
                            .pb_2()
                            .font_family(FONT_DISPLAY)
                            .text_size(px(20.))
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(t("page.performance")),
                    )
                    .child(tile(
                        "tile-cpu",
                        Resource::Cpu,
                        t("res.cpu"),
                        cpu_line,
                        cpu,
                        tk.chart_cpu,
                        cx,
                    ))
                    .child(tile(
                        "tile-memory",
                        Resource::Memory,
                        t("res.memory"),
                        memory_line,
                        memory,
                        tk.chart_memory,
                        cx,
                    )),
            )
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .p_4()
                    .bg(tk.surface)
                    .border_1()
                    .border_color(tk.rule)
                    .rounded(RADIUS_CARD)
                    .child(
                        div()
                            .flex()
                            .items_baseline()
                            .child(
                                div()
                                    .flex_1()
                                    .font_family(FONT_DISPLAY)
                                    .text_size(px(28.))
                                    .line_height(px(36.))
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .child(title),
                            )
                            .child(div().text_size(px(16.)).text_color(tk.ink2).child(subtitle)),
                    )
                    .child(
                        div()
                            .flex()
                            .text_size(px(12.))
                            .text_color(tk.ink2)
                            .child(div().flex_1().child(caption))
                            .child(pct(100.0, 0)),
                    )
                    .child(
                        div()
                            .h(px(280.))
                            .border_1()
                            .border_color(hue)
                            .child(chart(values, hue, tk, true)),
                    )
                    .child(
                        div()
                            .flex()
                            .text_size(px(12.))
                            .text_color(tk.ink2)
                            .child(div().flex_1().child(tn("chart.seconds", HISTORY as u64, &[])))
                            .child("0"),
                    )
                    .child(
                        div()
                            .pt_3()
                            .flex()
                            .flex_wrap()
                            .gap_x_6()
                            .gap_y_3()
                            .children(stats.into_iter().map(|(name, value)| stat(name, value, &tk))),
                    ),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uptime_reads_like_task_manager() {
        assert_eq!(vigil_i18n::with_language("en", || uptime(3_660.0)), "1:01");
        assert_eq!(vigil_i18n::with_language("en", || uptime(93_784.0)), "1 d 2:03");
    }
}
