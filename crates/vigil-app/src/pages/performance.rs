//! The Performance page in Task Manager's layout:
//! the resource list on the left (CPU, memory, every disk, the two busiest network adapters,
//! every GPU) with live thumbnails, and the selected resource on the right: its chart over 1, 2
//! or 5 minutes (Pause keeps a moment), a second chart where Task Manager has one (transfer rate,
//! dedicated GPU memory), the logical processors, the memory composition, the statistics, the
//! hardware facts and the processes using the resource most. Charts are drawn on a GPUI canvas.

use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    AnyElement, App, Bounds, Context, Div, Entity, FontWeight, Hsla, InteractiveElement, IntoElement, ParentElement,
    PathBuilder, Pixels, Render, Role, StatefulInteractiveElement, Styled, Subscription, Window, canvas, div, point,
    px,
};
use vigil_core::state::AppState;
use vigil_maint::hardware::Hardware;
use vigil_sys::metrics::Snapshot;
use vigil_sys::process::ProcessRow;

use crate::format::{num, pct, size};
use crate::i18n::{t, tf, tn};
use crate::live::Live;
use crate::pages::common;
use crate::theme::{FONT_DISPLAY, RADIUS, RADIUS_CARD, Tokens, tokens};
use crate::ui;

/// What the page asks the shell to do: show a process on the Processes page.
pub type ShowProcess = Rc<dyn Fn(u32, &mut Window, &mut App)>;

/// The time ranges, in seconds.
const RANGES: [usize; 3] = [60, 120, 300];

/// A line of a chart: values oldest first, drawn dashed when `dashed`.
pub(crate) struct Line {
    pub values: Vec<f64>,
    pub dashed: bool,
}

/// Bytes per second as bits per second ("464 Kbps").
fn bits(bytes_per_second: f64) -> String {
    let mut value = bytes_per_second * 8.0;
    let units = ["unit.bps", "unit.Kbps", "unit.Mbps", "unit.Gbps"];
    for (i, unit) in units.iter().enumerate() {
        if value < 1000.0 || i == units.len() - 1 {
            let shown = if value >= 100.0 || i == 0 {
                num(value.round(), 0)
            } else {
                num(value, 1)
            };
            return format!("{shown} {}", t(unit));
        }
        value /= 1000.0;
    }
    String::new()
}

/// Bytes per second ("5.8 MB/s").
fn rate(bytes_per_second: f64) -> String {
    let mut value = bytes_per_second;
    let units = ["unit.Bps", "unit.KBps", "unit.MBps", "unit.GBps"];
    for (i, unit) in units.iter().enumerate() {
        if value < 1024.0 || i == units.len() - 1 {
            let shown = if value >= 100.0 || i == 0 {
                num(value.round(), 0)
            } else {
                num(value, 1)
            };
            return format!("{shown} {}", t(unit));
        }
        value /= 1024.0;
    }
    String::new()
}

fn ghz(mhz: f32) -> String {
    if mhz <= 0.0 {
        return "—".into();
    }
    tf("unit.ghz", &[("n", &num(f64::from(mhz) / 1000.0, 2))])
}

/// 1, 2, 5 × 10^n just above `value`: the top of a throughput chart.
fn nice_ceiling(value: f64) -> f64 {
    if value <= 0.0 {
        return 1.0;
    }
    let exponent = value.log10().floor();
    for step in [1.0, 2.0, 5.0, 10.0] {
        let top = step * 10f64.powf(exponent);
        if top >= value {
            return top;
        }
    }
    10f64.powf(exponent + 1.0)
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

/// The last `range` values of a history.
fn window(values: &[f64], range: usize) -> Vec<f64> {
    values[values.len().saturating_sub(range)..].to_vec()
}

/// A chart: filled area under the first line, the lines, a grid tinted with the resource hue.
/// Values run 0..`max`; the full width stands for `range` seconds, newest on the right.
pub(crate) fn chart(lines: Vec<Line>, max: f64, range: usize, hue: Hsla, tk: Tokens, grid: bool) -> impl IntoElement {
    canvas(
        |_, _, _| {},
        move |bounds: Bounds<Pixels>, _, window, _| {
            let w = f32::from(bounds.size.width);
            let h = f32::from(bounds.size.height);
            let x0 = f32::from(bounds.origin.x);
            let y0 = f32::from(bounds.origin.y);
            if grid {
                let rule = hue.opacity(if tk.dark { 0.18 } else { 0.12 });
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
            let max = if max > 0.0 { max } else { 1.0 };
            let step = w / (range.max(2) - 1) as f32;
            for (index, line) in lines.iter().enumerate() {
                let values = &line.values;
                if values.len() < 2 {
                    continue;
                }
                let start = x0 + w - step * (values.len() - 1) as f32;
                let at = |i: usize, v: f64| {
                    let share = (v / max).clamp(0.0, 1.0) as f32;
                    point(px(start + step * i as f32), px(y0 + h - h * share))
                };
                if index == 0 {
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
                }
                let mut path = PathBuilder::stroke(px(1.5));
                let mut pen_down = false;
                for (i, v) in values.iter().enumerate() {
                    // A dashed line: four samples drawn, two left out.
                    let draw = !line.dashed || i % 6 < 4;
                    if draw && pen_down {
                        path.line_to(at(i, *v));
                    } else {
                        path.move_to(at(i, *v));
                    }
                    pen_down = draw;
                }
                if let Ok(path) = path.build() {
                    window.paint_path(path, hue);
                }
            }
        },
    )
    .size_full()
}

/// An entry of the resource list.
struct Resource {
    key: String,
    title: String,
    line1: String,
    line2: String,
    hue: Hsla,
    values: Vec<f64>,
    max: f64,
}

/// What the page draws: the live data, or the moment Pause kept.
#[derive(Clone)]
struct Frozen {
    snapshot: Option<Snapshot>,
    cpu: Vec<f64>,
    memory: Vec<f64>,
    series: HashMap<String, Vec<f64>>,
    processes: Vec<ProcessRow>,
}

thread_local! {
    static FIRST: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// The resource the next Performance page selects first (from an Overview tile).
pub fn select(key: &str, _cx: &mut App) {
    FIRST.with(|f| *f.borrow_mut() = Some(key.to_string()));
}

pub struct PerformancePage {
    live: Entity<Live>,
    selected: String,
    range: usize,
    paused: Option<Frozen>,
    hardware: Option<Arc<Hardware>>,
    cpu_name: String,
    on_show: ShowProcess,
    _subscription: Subscription,
}

impl PerformancePage {
    pub fn new(live: Entity<Live>, core: Option<Arc<AppState>>, on_show: ShowProcess, cx: &mut Context<Self>) -> Self {
        let subscription = cx.observe(&live, |this, _, cx| {
            if this.paused.is_none() {
                cx.notify();
            }
        });
        let mut page = Self {
            live,
            selected: FIRST.with(|f| f.borrow_mut().take()).unwrap_or_else(|| "cpu".into()),
            range: RANGES[0],
            paused: None,
            hardware: None,
            cpu_name: String::new(),
            on_show,
            _subscription: subscription,
        };
        // Hardware facts (models, slots, disk health) are read once; it takes a few seconds.
        match core {
            Some(core) => common::read(
                cx,
                move || (core.hardware(false).ok(), vigil_sys::metrics::cpu_name()),
                |page, (hardware, name), _| {
                    page.hardware = hardware.map(Arc::new);
                    page.cpu_name = name;
                },
            ),
            None => page.cpu_name = "Contoso C9 7950 16-Core Processor".into(),
        }
        page
    }

    fn frozen(&self, cx: &App) -> Frozen {
        if let Some(frozen) = &self.paused {
            return frozen.clone();
        }
        let live = self.live.read(cx);
        Frozen {
            snapshot: live.snapshot.clone(),
            cpu: live.cpu.iter().map(|v| f64::from(*v)).collect(),
            memory: live.memory.iter().map(|v| f64::from(*v)).collect(),
            series: live
                .series
                .iter()
                .map(|(k, v)| (k.clone(), v.iter().copied().collect()))
                .collect(),
            processes: live.processes.clone(),
        }
    }

    fn resources(&self, data: &Frozen, tk: &Tokens) -> Vec<Resource> {
        let Some(snap) = &data.snapshot else {
            return Vec::new();
        };
        let hist = |key: &str| data.series.get(key).cloned().unwrap_or_default();
        let mut out = vec![Resource {
            key: "cpu".into(),
            title: t("res.cpu"),
            line1: format!("{} {}", pct(f64::from(snap.cpu), 0), ghz(snap.freq_mhz)),
            line2: String::new(),
            hue: tk.chart_cpu,
            values: data.cpu.clone(),
            max: 100.0,
        }];
        let m = &snap.memory;
        let used = if m.total > 0 {
            m.used as f64 / m.total as f64 * 100.0
        } else {
            0.0
        };
        out.push(Resource {
            key: "memory".into(),
            title: t("res.memory"),
            line1: format!(
                "{}/{} ({})",
                size(m.used as f64, 1),
                size(m.total as f64, 1),
                pct(used, 0)
            ),
            line2: String::new(),
            hue: tk.chart_memory,
            values: data.memory.clone(),
            max: 100.0,
        });
        for disk in &snap.disks {
            let key = format!("disk:{}", disk.key);
            out.push(Resource {
                title: self.disk_title(&disk.key),
                line1: self.disk_media(&disk.key),
                line2: pct(f64::from(disk.active), 0),
                hue: tk.chart_disk,
                values: hist(&key),
                max: 100.0,
                key,
            });
        }
        // Virtual switches (Hyper-V, WSL, VPNs) multiply the adapters: show the two busiest.
        let peak = |name: &str| {
            hist(&format!("net:{name}:recv")).iter().fold(0.0f64, |a, b| a.max(*b))
                + hist(&format!("net:{name}:sent")).iter().fold(0.0f64, |a, b| a.max(*b))
        };
        let mut nets: Vec<_> = snap.nets.iter().collect();
        nets.sort_by(|a, b| peak(&b.name).total_cmp(&peak(&a.name)));
        for net in nets.into_iter().take(2) {
            let values = hist(&format!("net:{}:recv", net.name));
            let max = nice_ceiling(values.iter().fold(0.0f64, |a, b| a.max(*b)));
            out.push(Resource {
                key: format!("net:{}", net.name),
                title: t("res.network"),
                line1: net.name.clone(),
                line2: tf(
                    "perf.sendReceive",
                    &[("sent", &bits(net.sent_bps)), ("received", &bits(net.recv_bps))],
                ),
                hue: tk.chart_net,
                values,
                max,
            });
        }
        for (index, gpu) in snap.gpus.iter().enumerate() {
            let key = format!("gpu:{}", gpu.luid);
            out.push(Resource {
                title: tf("res.gpuN", &[("n", &index.to_string())]),
                line1: gpu.name.clone(),
                line2: pct(f64::from(gpu.utilization), 0),
                hue: tk.chart_gpu,
                values: hist(&key),
                max: 100.0,
                key,
            });
        }
        out
    }

    fn disk_title(&self, key: &str) -> String {
        let mut parts = key.split(' ');
        let n = parts.next().unwrap_or("");
        let letters: Vec<&str> = parts.collect();
        if letters.is_empty() {
            tf("res.disk", &[("n", n)])
        } else {
            tf("res.diskLetters", &[("n", n), ("letters", &letters.join(" "))])
        }
    }

    fn hw_disk(&self, key: &str) -> Option<&vigil_maint::hardware::Disk> {
        let n: i64 = key.split(' ').next()?.parse().ok()?;
        self.hardware.as_ref()?.disks.iter().find(|d| d.number == Some(n))
    }

    fn disk_media(&self, key: &str) -> String {
        match self.hw_disk(key) {
            Some(disk) => {
                let media = if disk.media == "Unspecified" {
                    t("perf.disk")
                } else {
                    disk.media.clone()
                };
                if disk.bus.is_empty() {
                    media
                } else {
                    format!("{media} ({})", disk.bus)
                }
            }
            None => String::new(),
        }
    }

    fn select(&mut self, key: String, cx: &mut Context<Self>) {
        self.selected = key;
        cx.notify();
    }

    fn toggle_pause(&mut self, cx: &mut Context<Self>) {
        self.paused = match self.paused {
            Some(_) => None,
            None => Some(self.frozen(cx)),
        };
        cx.notify();
    }

    /// The right-hand side for the selected resource.
    fn detail(&self, data: &Frozen, resource: &Resource, tk: &Tokens) -> Div {
        let Some(snap) = &data.snapshot else {
            return div();
        };
        let key = resource.key.as_str();
        let range = self.range;
        let hist = |k: &str| window(&data.series.get(k).cloned().unwrap_or_default(), range);
        let mut subtitle = String::new();
        let mut caption = String::new();
        let mut lines = vec![Line {
            values: window(&resource.values, range),
            dashed: false,
        }];
        let mut max = resource.max;
        let mut top_label = pct(100.0, 0);
        let mut second: Option<(String, Vec<Line>, f64, String)> = None;
        let mut stats: Vec<(String, String)> = Vec::new();
        let mut facts: Vec<(String, String)> = Vec::new();
        let mut extra = String::new();
        let mut cores: Option<Vec<f32>> = None;
        let mut composition: Option<Vec<(String, f64, Hsla)>> = None;
        let hw = self.hardware.clone();
        if key == "cpu" {
            subtitle = hw
                .as_ref()
                .and_then(|h| h.cpu.as_ref())
                .and_then(|c| c.name.clone())
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| self.cpu_name.clone());
            caption = t("perf.utilizationPct");
            cores = Some(snap.per_core.clone());
            stats = vec![
                (t("perf.utilization"), pct(f64::from(snap.cpu), 0)),
                (t("perf.speed"), ghz(snap.freq_mhz)),
                (t("perf.processes"), num(f64::from(snap.processes), 0)),
                (t("perf.threads"), num(f64::from(snap.threads), 0)),
                (t("perf.handles"), num(f64::from(snap.handles), 0)),
                (t("perf.uptime"), uptime(snap.uptime_s)),
            ];
            let cpu = hw.as_ref().and_then(|h| h.cpu.clone());
            facts = vec![
                (t("perf.baseSpeed"), ghz(snap.base_mhz)),
                (
                    t("perf.sockets"),
                    cpu.as_ref().map_or("—".into(), |c| c.sockets.to_string()),
                ),
                (
                    t("perf.cores"),
                    cpu.as_ref().map_or("—".into(), |c| c.cores.to_string()),
                ),
                (t("perf.logical"), snap.per_core.len().to_string()),
                (
                    t("perf.virtualization"),
                    cpu.as_ref().map_or("—".into(), |c| {
                        if c.virtualization {
                            t("common.enabled")
                        } else {
                            t("common.disabled")
                        }
                    }),
                ),
            ];
        } else if key == "memory" {
            let m = &snap.memory;
            subtitle = size(m.total as f64, 1);
            caption = t("perf.memoryUsage");
            composition = Some(vec![
                (
                    t("perf.inUse"),
                    m.used.saturating_sub(m.modified) as f64,
                    tk.chart_memory,
                ),
                (t("perf.modified"), m.modified as f64, tk.chart_memory.opacity(0.6)),
                (t("perf.standby"), m.standby as f64, tk.chart_memory.opacity(0.25)),
                (t("perf.free"), m.free as f64, tk.surface2),
            ]);
            stats = vec![
                (
                    t("perf.inUseCompressed"),
                    format!("{} ({})", size(m.used as f64, 1), size(m.compressed as f64, 1)),
                ),
                (t("perf.available"), size(m.available as f64, 1)),
                (
                    t("perf.committed"),
                    format!("{}/{}", size(m.commit as f64, 1), size(m.commit_limit as f64, 1)),
                ),
                (t("perf.cached"), size((m.standby + m.modified) as f64, 1)),
                (t("perf.pagedPool"), size(m.paged_pool as f64, 1)),
                (t("perf.nonPagedPool"), size(m.nonpaged_pool as f64, 1)),
            ];
            let memory = hw.as_ref().and_then(|h| h.memory.as_ref());
            let speed = memory
                .and_then(|m| m.modules.first())
                .map(|m| {
                    if m.configured_speed > 0 {
                        m.configured_speed
                    } else {
                        m.speed
                    }
                })
                .filter(|s| *s > 0);
            facts = vec![
                (
                    t("perf.speed"),
                    speed.map_or("—".into(), |s| tf("unit.mts", &[("n", &s.to_string())])),
                ),
                (
                    t("perf.slotsUsed"),
                    memory.filter(|m| !m.modules.is_empty()).map_or("—".into(), |m| {
                        let used = m.modules.len() as i64;
                        tf(
                            "perf.slotsValue",
                            &[("used", &used.to_string()), ("total", &m.slots.max(used).to_string())],
                        )
                    }),
                ),
            ];
            extra = t("perf.memoryExtra");
        } else if let Some(disk_key) = key.strip_prefix("disk:") {
            if let Some(disk) = snap.disks.iter().find(|d| d.key == disk_key) {
                subtitle = self.hw_disk(disk_key).and_then(|d| d.name.clone()).unwrap_or_default();
                caption = t("perf.activeTime");
                let read = hist(&format!("{key}:read"));
                let write = hist(&format!("{key}:write"));
                let peak = read.iter().chain(write.iter()).fold(0.0f64, |a, b| a.max(*b));
                let top = nice_ceiling(peak);
                second = Some((
                    t("perf.transferRate"),
                    vec![
                        Line {
                            values: read,
                            dashed: false,
                        },
                        Line {
                            values: write,
                            dashed: true,
                        },
                    ],
                    top,
                    rate(top),
                ));
                stats = vec![
                    (t("perf.activeTime"), pct(f64::from(disk.active), 0)),
                    (t("perf.readSpeed"), rate(disk.read_bps)),
                    (t("perf.writeSpeed"), rate(disk.write_bps)),
                    (t("perf.queue"), num(f64::from(disk.queue), 1)),
                ];
                let info = self.hw_disk(disk_key);
                let media = self.disk_media(disk_key);
                facts = vec![
                    (
                        t("perf.capacity"),
                        info.filter(|d| d.size > 0)
                            .map_or("—".into(), |d| size(d.size as f64, 0)),
                    ),
                    (t("perf.type"), if media.is_empty() { "—".into() } else { media }),
                    (
                        t("perf.health"),
                        info.map(|d| d.health.clone())
                            .filter(|h| !h.is_empty())
                            .unwrap_or_else(|| "—".into()),
                    ),
                    (
                        t("perf.temperature"),
                        info.and_then(|d| d.temperature)
                            .map_or("—".into(), |c| format!("{c} °C")),
                    ),
                ];
            }
        } else if let Some(name) = key.strip_prefix("net:") {
            if let Some(net) = snap.nets.iter().find(|n| n.name == name) {
                subtitle = net.name.clone();
                caption = t("perf.throughput");
                let recv = hist(&format!("{key}:recv"));
                let sent = hist(&format!("{key}:sent"));
                let peak = recv.iter().chain(sent.iter()).fold(0.0f64, |a, b| a.max(*b));
                max = nice_ceiling(peak);
                top_label = bits(max);
                lines = vec![
                    Line {
                        values: recv,
                        dashed: false,
                    },
                    Line {
                        values: sent,
                        dashed: true,
                    },
                ];
                stats = vec![
                    (t("perf.send"), bits(net.sent_bps)),
                    (t("perf.receive"), bits(net.recv_bps)),
                ];
                facts = vec![
                    (t("perf.adapter"), net.name.clone()),
                    (
                        t("perf.linkSpeed"),
                        if net.link_bps > 0.0 {
                            bits(net.link_bps / 8.0)
                        } else {
                            "—".into()
                        },
                    ),
                ];
                extra = t("perf.netExtra");
            }
        } else if let Some(luid) = key.strip_prefix("gpu:")
            && let Some(gpu) = snap.gpus.iter().find(|g| g.luid == luid)
        {
            subtitle = gpu.name.clone();
            caption = t("perf.gpuCaption");
            second = Some((
                t("perf.dedicatedUsage"),
                vec![Line {
                    values: hist(&format!("vram:{luid}")),
                    dashed: false,
                }],
                100.0,
                size(gpu.dedicated_total as f64, 1),
            ));
            let mut engines = gpu.engines.clone();
            engines.sort_by(|a, b| b.1.total_cmp(&a.1));
            if !engines.is_empty() {
                let list: Vec<String> = engines
                    .iter()
                    .take(5)
                    .map(|(n, v)| format!("{n} {}", pct(f64::from(*v), 0)))
                    .collect();
                extra = tf("perf.engines", &[("list", &list.join(" · "))]);
            }
            stats = vec![
                (t("perf.utilization"), pct(f64::from(gpu.utilization), 0)),
                (
                    t("perf.dedicatedMemory"),
                    format!(
                        "{}/{}",
                        size(gpu.dedicated_used as f64, 1),
                        size(gpu.dedicated_total as f64, 1)
                    ),
                ),
                (
                    t("perf.sharedMemory"),
                    format!(
                        "{}/{}",
                        size(gpu.shared_used as f64, 1),
                        size(gpu.shared_total as f64, 1)
                    ),
                ),
            ];
            let info = hw
                .as_ref()
                .and_then(|h| h.gpus.iter().find(|g| g.name.as_deref() == Some(gpu.name.as_str())));
            facts = vec![
                (
                    t("perf.driverVersion"),
                    info.and_then(|g| g.driver_version.clone())
                        .unwrap_or_else(|| "—".into()),
                ),
                (
                    t("perf.driverDate"),
                    info.and_then(|g| g.driver_date.clone()).unwrap_or_else(|| "—".into()),
                ),
            ];
        }

        let tk2 = *tk;
        let axis = move |left: String, right: String| {
            div()
                .flex()
                .text_size(px(12.))
                .text_color(tk2.ink2)
                .child(div().flex_1().child(left))
                .child(right)
        };
        let seconds = tn("chart.seconds", range as u64, &[]);
        let hue = resource.hue;
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
                            .child(resource.title.clone()),
                    )
                    .child(div().text_size(px(16.)).text_color(tk.ink2).child(subtitle)),
            )
            .child(axis(caption, top_label))
            .child(
                div()
                    .id("perf-chart")
                    .role(Role::Image)
                    .aria_label(resource.title.clone())
                    .h(px(if second.is_some() { 180. } else { 240. }))
                    .border_1()
                    .border_color(hue)
                    .child(chart(lines, max, range, hue, tk2, true)),
            )
            .child(axis(seconds.clone(), "0".into()))
            .when_some(second, |this, (caption, lines, max, top)| {
                this.child(axis(caption, top))
                    .child(
                        div()
                            .h(px(90.))
                            .border_1()
                            .border_color(hue)
                            .child(chart(lines, max, range, hue, tk2, true)),
                    )
                    .child(axis(seconds.clone(), "0".into()))
            })
            .when_some(cores, |this, cores| this.child(core_grid(&cores, hue, &tk2)))
            .when_some(composition, |this, parts| this.child(composition_bar(parts, &tk2)))
            .child(
                div()
                    .pt_2()
                    .flex()
                    .gap_8()
                    .child(
                        div()
                            .flex()
                            .flex_wrap()
                            .gap_x_6()
                            .gap_y_3()
                            .max_w(px(460.))
                            .children(stats.into_iter().map(|(name, value)| stat(name, value, &tk2))),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .children(facts.into_iter().map(|(name, value)| {
                                div()
                                    .flex()
                                    .gap_3()
                                    .text_size(px(12.))
                                    .child(div().w(px(130.)).text_color(tk2.ink2).child(name))
                                    .child(value)
                            })),
                    ),
            )
            .when(!extra.is_empty(), |this| {
                this.child(div().text_size(px(12.)).text_color(tk.ink3).child(extra))
            })
            .child(self.consumers(data, key, &tk2))
    }

    /// "Using the most …": the processes behind the selected resource, with Show in Processes.
    fn consumers(&self, data: &Frozen, key: &str, tk: &Tokens) -> AnyElement {
        let rows: Vec<&ProcessRow> = data.processes.iter().filter(|r| r.pid > 4).collect();
        let gpu_use: HashMap<u32, (f32, u64)> = data
            .snapshot
            .as_ref()
            .map(|s| {
                s.gpu_by_pid
                    .iter()
                    .map(|g| (g.pid, (g.utilization, g.dedicated)))
                    .collect()
            })
            .unwrap_or_default();
        type Consumer<'a> = (&'a ProcessRow, f64, String);
        let (title, column, mut items, note): (String, String, Vec<Consumer>, String) = if key == "memory" {
            let items = rows
                .iter()
                .map(|r| (*r, r.private_bytes as f64, size(r.private_bytes as f64, 0)))
                .collect();
            (t("perf.mostMemory"), t("res.memory"), items, String::new())
        } else if key.starts_with("gpu:") {
            let items = rows
                .iter()
                .filter_map(|r| {
                    gpu_use.get(&r.pid).map(|(u, d)| {
                        (
                            *r,
                            f64::from(*u),
                            format!("{} · {}", pct(f64::from(*u), 0), size(*d as f64, 0)),
                        )
                    })
                })
                .collect();
            (t("perf.mostGpu"), t("perf.colGpu"), items, String::new())
        } else if key.starts_with("disk:") {
            let items = rows
                .iter()
                .filter(|r| r.io_bps > 0.0)
                .map(|r| (*r, r.io_bps, rate(r.io_bps)))
                .collect();
            (t("perf.mostIo"), t("perf.colIo"), items, t("perf.ioNote"))
        } else if key.starts_with("net:") {
            (t("res.network"), String::new(), Vec::new(), t("perf.netNote"))
        } else {
            let items = rows
                .iter()
                .map(|r| (*r, f64::from(r.cpu), pct(f64::from(r.cpu), 1)))
                .collect();
            (t("perf.mostCpu"), t("res.cpu"), items, String::new())
        };
        items.sort_by(|a, b| b.1.total_cmp(&a.1));
        items.truncate(8);
        let on_show = Rc::clone(&self.on_show);
        let tk = *tk;
        div()
            .pt_2()
            .flex()
            .flex_col()
            .gap_1()
            .child(
                div()
                    .flex()
                    .text_size(px(12.))
                    .text_color(tk.ink2)
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(div().flex_1().child(title))
                    .child(column),
            )
            .children(items.into_iter().enumerate().map(move |(i, (row, _, text))| {
                let pid = row.pid;
                let show = Rc::clone(&on_show);
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .h(px(28.))
                    .px_2()
                    .rounded(RADIUS)
                    .text_size(px(13.))
                    .child(
                        div()
                            .flex_1()
                            .overflow_hidden()
                            .text_ellipsis()
                            .child(crate::groups::display_name(row)),
                    )
                    .child(div().text_color(tk.ink3).child(format!("PID {pid}")))
                    .child(div().w(px(130.)).text_right().font_family(FONT_DISPLAY).child(text))
                    .child(
                        ui::FButton::new(("show", i), ui::Kind::Subtle)
                            .label(t("perf.showInProcesses"))
                            .h(px(26.))
                            .on_click(move |_, window, cx| show(pid, window, cx)),
                    )
            }))
            .when(!note.is_empty(), |this| {
                this.child(div().text_size(px(12.)).text_color(tk.ink3).child(note))
            })
            .into_any_element()
    }
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

/// One small square per logical processor, filled to its use.
fn core_grid(cores: &[f32], hue: Hsla, tk: &Tokens) -> impl IntoElement {
    div()
        .id("cores")
        .role(Role::Group)
        .aria_label(t("chart.coresLabel"))
        .flex()
        .flex_wrap()
        .gap_1()
        .children(cores.iter().enumerate().map(|(index, value)| {
            let share = (value / 100.0).clamp(0.0, 1.0);
            div()
                .id(("core", index))
                .aria_label(tf(
                    "chart.core",
                    &[("index", &index.to_string()), ("value", &pct(f64::from(*value), 0))],
                ))
                .w(px(34.))
                .h(px(22.))
                .border_1()
                .border_color(hue.opacity(0.6))
                .bg(tk.surface)
                .flex()
                .flex_col()
                .justify_end()
                .child(div().w_full().h(px(20. * share)).bg(hue.opacity(0.55)))
        }))
}

/// The memory composition: in use, modified, standby and free, side by side.
fn composition_bar(parts: Vec<(String, f64, Hsla)>, tk: &Tokens) -> impl IntoElement {
    let total: f64 = parts.iter().map(|(_, v, _)| v).sum();
    let total = if total > 0.0 { total } else { 1.0 };
    div()
        .flex()
        .flex_col()
        .gap_1()
        .child(
            div()
                .text_size(px(12.))
                .text_color(tk.ink2)
                .child(t("perf.composition")),
        )
        .child(
            div()
                .flex()
                .h(px(28.))
                .border_1()
                .border_color(tk.chart_memory)
                .children(parts.iter().map(|(_, value, color)| {
                    div()
                        .h_full()
                        .w(gpui_kit::relative((value / total) as f32))
                        .bg(*color)
                        .border_r_1()
                        .border_color(tk.chart_memory.opacity(0.5))
                })),
        )
        .child(
            div()
                .flex()
                .gap_4()
                .text_size(px(12.))
                .text_color(tk.ink2)
                .children(parts.into_iter().map(|(name, value, color)| {
                    div()
                        .flex()
                        .items_center()
                        .gap_1()
                        .child(
                            div()
                                .w(px(10.))
                                .h(px(10.))
                                .bg(color)
                                .border_1()
                                .border_color(tk.chart_memory),
                        )
                        .child(format!("{name} {}", size(value, 1)))
                })),
        )
}

impl Render for PerformancePage {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tk = *tokens(cx);
        let data = self.frozen(cx);
        let resources = self.resources(&data, &tk);
        if !resources.iter().any(|r| r.key == self.selected) && !resources.is_empty() {
            self.selected = "cpu".into();
        }
        let recorded = data.cpu.len();
        let status = match (&self.paused, &data.snapshot) {
            (Some(_), _) => t("perf.paused"),
            (None, Some(s)) => tf("perf.everySecond", &[("uptime", &uptime(s.uptime_s))]),
            (None, None) => t("perf.sampling"),
        };
        let weak = cx.entity().downgrade();
        let range_options: Vec<(usize, String)> = RANGES
            .iter()
            .map(|&s| (s, tn("perf.range", (s / 60) as u64, &[])))
            .collect();
        let range_picker = ui::segmented(
            "perf-range",
            t("perf.timeShown"),
            range_options,
            self.range,
            move |value, _, cx| {
                let _ = weak.update(cx, |page, cx| {
                    page.range = value;
                    cx.notify();
                });
            },
            &tk,
        );
        let current = resources.iter().find(|r| r.key == self.selected);
        let detail = current.map(|r| self.detail(&data, r, &tk));
        div()
            .size_full()
            .flex()
            .flex_col()
            .gap_3()
            .px(px(20.))
            .py(px(14.))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(ui::page_title(t("page.performance")))
                    .child(div().flex_1())
                    .child(div().text_size(px(12.)).text_color(tk.ink3).child(status))
                    .child(range_picker)
                    .child(if self.paused.is_some() {
                        ui::accent_button("perf-live", t("perf.backToLive"))
                            .on_click(cx.listener(|this, _, _, cx| this.toggle_pause(cx)))
                    } else {
                        ui::button("perf-pause", t("perf.pause"))
                            .glyph(crate::icons::PAUSE)
                            .on_click(cx.listener(|this, _, _, cx| this.toggle_pause(cx)))
                    }),
            )
            .when(recorded < self.range / 2 && self.range > 60, |this| {
                this.child(div().text_size(px(12.)).text_color(tk.ink3).child(t("perf.notEnough")))
            })
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .flex()
                    .gap_4()
                    .child(
                        div()
                            .id("perf-resources")
                            .role(Role::ListBox)
                            .aria_label(t("perf.resources"))
                            .w(px(270.))
                            .flex_none()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .overflow_y_scroll()
                            .children(resources.iter().enumerate().map(|(i, r)| {
                                let selected = r.key == self.selected;
                                let key = r.key.clone();
                                let values = window(&r.values, 60);
                                div()
                                    .id(("tile", i))
                                    .role(Role::ListBoxOption)
                                    .aria_label(format!("{} {}", r.title, r.line1))
                                    .aria_selected(selected)
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
                                            .border_color(r.hue)
                                            .bg(tk.surface)
                                            .child(chart(
                                                vec![Line { values, dashed: false }],
                                                r.max,
                                                60,
                                                r.hue,
                                                tk,
                                                false,
                                            )),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .flex_col()
                                            .min_w_0()
                                            .child(
                                                div()
                                                    .font_weight(FontWeight::SEMIBOLD)
                                                    .child(crate::ui::kit::plain(r.title.clone())),
                                            )
                                            .child(
                                                div()
                                                    .text_size(px(12.))
                                                    .text_color(tk.ink2)
                                                    .overflow_hidden()
                                                    .text_ellipsis()
                                                    .whitespace_nowrap()
                                                    .child(r.line1.clone()),
                                            )
                                            .when(!r.line2.is_empty(), |this| {
                                                this.child(
                                                    div().text_size(px(12.)).text_color(tk.ink2).child(r.line2.clone()),
                                                )
                                            }),
                                    )
                                    .on_click(cx.listener(move |this, _, _, cx| this.select(key.clone(), cx)))
                            })),
                    )
                    .child(
                        div()
                            .id("perf-detail")
                            .flex_1()
                            .min_w_0()
                            .overflow_y_scroll()
                            .flex()
                            .flex_col()
                            .children(detail)
                            .when(current.is_none(), |this| {
                                this.child(div().text_color(tk.ink3).child(t("perf.readingCounters")))
                            }),
                    ),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::live::HISTORY;

    #[test]
    fn uptime_reads_like_task_manager() {
        assert_eq!(vigil_i18n::with_language("en", || uptime(3_660.0)), "1:01");
        assert_eq!(vigil_i18n::with_language("en", || uptime(93_784.0)), "1 d 2:03");
    }

    #[test]
    fn throughput_charts_get_a_round_top() {
        assert_eq!(nice_ceiling(0.0), 1.0);
        assert_eq!(nice_ceiling(130.0), 200.0);
        assert_eq!(nice_ceiling(4_800.0), 5_000.0);
    }

    #[test]
    fn rates_use_the_language() {
        assert_eq!(vigil_i18n::with_language("en", || bits(58_000.0)), "464 Kbps");
        assert_eq!(vigil_i18n::with_language("en", || rate(6_082_000.0)), "5.8 MB/s");
    }

    #[test]
    fn ranges_keep_the_newest_values() {
        let values: Vec<f64> = (0..HISTORY).map(|v| v as f64).collect();
        let last = window(&values, 60);
        assert_eq!(last.len(), 60);
        assert_eq!(last.first().copied(), Some((HISTORY - 60) as f64));
    }
}
