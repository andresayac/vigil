//! Live system metrics: CPU, memory, GPU, disks and network.
//!
//! Sources: performance counters (pdh.dll, English counter names so they work in any display
//! language), DXGI for the graphics adapters, GetPerformanceInfo, the per-processor times of
//! the kernel and the IP Helper interface counters. A missing counter or GPU never makes a
//! sample fail: the figure degrades to zero or an empty list.

use std::collections::HashMap;
use std::time::Instant;

use serde::Serialize;
use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
use windows::Win32::Graphics::Dxgi::{CreateDXGIFactory1, DXGI_ADAPTER_FLAG_SOFTWARE, IDXGIFactory1};
use windows::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST,
    GetAdaptersAddresses, GetIfEntry2, IP_ADAPTER_ADDRESSES_LH, MIB_IF_ROW2,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::Networking::WinSock::AF_UNSPEC;
use windows::Win32::System::Performance::{
    PDH_FMT, PDH_FMT_COUNTERVALUE_ITEM_W, PDH_FMT_DOUBLE, PDH_HCOUNTER, PDH_HQUERY, PDH_MORE_DATA,
    PdhAddEnglishCounterW, PdhCloseQuery, PdhCollectQueryData, PdhGetFormattedCounterArrayW, PdhOpenQueryW,
};
use windows::Win32::System::ProcessStatus::{GetPerformanceInfo, PERFORMANCE_INFORMATION};
use windows::Win32::System::SystemInformation::{GetTickCount64, GlobalMemoryStatusEx, MEMORYSTATUSEX};
use windows::core::PCWSTR;

use crate::SysError;
use crate::nt::{ProcessorTimes, SystemProcesses};
use crate::util::{from_wide, hklm_dword, hklm_string, now_unix_ms, wide};

// --------------------------------------------------------------------------- data

/// A graphics adapter as DXGI reports it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GpuAdapter {
    /// "0xHHHHHHHH_0xLLLLLLLL": the form used in the GPU performance counter names.
    pub luid: String,
    pub name: String,
    pub vendor_id: u32,
    /// Bytes of video memory on the card.
    pub dedicated_total: u64,
    /// Bytes of system memory the adapter may borrow.
    pub shared_total: u64,
    /// WARP / Microsoft Basic Render Driver: not a real GPU.
    pub software: bool,
}

/// Memory composition, in bytes.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryState {
    pub total: u64,
    pub available: u64,
    pub used: u64,
    pub commit: u64,
    pub commit_limit: u64,
    /// Cached pages that can be reused at once.
    pub standby: u64,
    /// Pages waiting to be written to disk before they can be reused.
    pub modified: u64,
    /// Free and zeroed pages.
    pub free: u64,
    /// Working set of the Memory Compression process.
    pub compressed: u64,
    pub paged_pool: u64,
    pub nonpaged_pool: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GpuState {
    pub luid: String,
    pub name: String,
    /// Busiest engine type, 0-100 (what Task Manager shows).
    pub utilization: f32,
    /// Engine type ("3D", "Copy", "VideoDecode"...) and its load, sorted by name.
    pub engines: Vec<(String, f32)>,
    pub dedicated_used: u64,
    pub dedicated_total: u64,
    pub shared_used: u64,
    pub shared_total: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiskState {
    /// Performance counter instance, e.g. "0 C:".
    pub key: String,
    /// "Disk 0 (C:)".
    pub label: String,
    pub read_bps: f64,
    pub write_bps: f64,
    /// Share of time the disk was busy, 0-100.
    pub active: f32,
    pub queue: f32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetState {
    pub name: String,
    /// Bytes per second.
    pub sent_bps: f64,
    pub recv_bps: f64,
    /// Link speed in bits per second, 0 when unknown.
    pub link_bps: f64,
}

/// GPU use of one process.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GpuUse {
    pub pid: u32,
    /// Busiest engine the process uses, 0-100.
    pub utilization: f32,
    /// Dedicated video memory, bytes.
    pub dedicated: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub time_ms: i64,
    /// Whole-machine CPU use, 0-100.
    pub cpu: f32,
    pub per_core: Vec<f32>,
    pub freq_mhz: f32,
    pub base_mhz: f32,
    pub processes: u32,
    pub threads: u32,
    pub handles: u32,
    pub uptime_s: f64,
    pub memory: MemoryState,
    pub gpus: Vec<GpuState>,
    pub disks: Vec<DiskState>,
    pub nets: Vec<NetState>,
    pub gpu_by_pid: Vec<GpuUse>,
}

// --------------------------------------------------------------------------- performance counters

const PDH_FMT_NOCAP100: u32 = 0x0000_8000;
const PDH_CSTATUS_VALID_DATA: u32 = 0;
const PDH_CSTATUS_NEW_DATA: u32 = 1;

/// A performance-counter query. Rate counters (bytes/sec, % time) need two collections, so
/// the first `collect()` returns nothing for them. Paths that do not exist are skipped.
pub(crate) struct Pdh {
    query: PDH_HQUERY,
    counters: Vec<(&'static str, PDH_HCOUNTER)>,
    missing: Vec<&'static str>,
}

// SAFETY: PDH query and counter handles may be used from any thread; `Pdh` only uses them
// through `&mut self`, so they are never used from two threads at the same time.
unsafe impl Send for Pdh {}

impl Pdh {
    pub(crate) fn new(paths: &[(&'static str, &str)]) -> Self {
        let mut query = PDH_HQUERY::default();
        // SAFETY: `query` receives a new query handle, closed in Drop.
        let opened = unsafe { PdhOpenQueryW(PCWSTR::null(), 0, &mut query) } == 0;
        let mut pdh = Self {
            query,
            counters: Vec::new(),
            missing: Vec::new(),
        };
        for &(key, path) in paths {
            let mut counter = PDH_HCOUNTER::default();
            let text = wide(path);
            // SAFETY: the query is open (checked) and `text` is NUL-terminated.
            let added =
                opened && unsafe { PdhAddEnglishCounterW(pdh.query, PCWSTR(text.as_ptr()), 0, &mut counter) } == 0;
            if added {
                pdh.counters.push((key, counter));
            } else {
                pdh.missing.push(key);
            }
        }
        pdh
    }

    /// Keys whose counter path does not exist on this computer.
    pub(crate) fn missing(&self) -> &[&'static str] {
        &self.missing
    }

    /// {key: {instance: value}}; single-instance counters use their instance name or "".
    pub(crate) fn collect(&mut self) -> HashMap<&'static str, HashMap<String, f64>> {
        let mut out = HashMap::new();
        if self.query.is_invalid() {
            return out;
        }
        // SAFETY: the query handle is valid until Drop.
        if unsafe { PdhCollectQueryData(self.query) } != 0 {
            return out;
        }
        for &(key, counter) in &self.counters {
            out.insert(key, counter_values(counter));
        }
        out
    }
}

impl Drop for Pdh {
    fn drop(&mut self) {
        if !self.query.is_invalid() {
            // SAFETY: the query was opened in `new` and is closed once.
            unsafe {
                PdhCloseQuery(self.query);
            }
        }
    }
}

fn counter_values(counter: PDH_HCOUNTER) -> HashMap<String, f64> {
    let format = PDH_FMT(PDH_FMT_DOUBLE.0 | PDH_FMT_NOCAP100);
    let mut size = 0u32;
    let mut count = 0u32;
    // SAFETY: with no buffer PDH only writes the required size and item count.
    let status = unsafe { PdhGetFormattedCounterArrayW(counter, format, &mut size, &mut count, None) };
    if status != PDH_MORE_DATA || size == 0 {
        return HashMap::new();
    }
    let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
    let items = buffer.as_mut_ptr().cast::<PDH_FMT_COUNTERVALUE_ITEM_W>();
    // SAFETY: the buffer is writable for `size` bytes and aligned for the item structure.
    let status = unsafe { PdhGetFormattedCounterArrayW(counter, format, &mut size, &mut count, Some(items)) };
    if status != 0 {
        return HashMap::new();
    }
    let count = (count as usize).min(buffer.len() * 8 / size_of::<PDH_FMT_COUNTERVALUE_ITEM_W>());
    // SAFETY: PDH wrote `count` items at the start of the buffer; their name pointers point into
    // the same buffer, which stays alive while the slice is used.
    let items = unsafe { std::slice::from_raw_parts(items, count) };
    let mut out = HashMap::with_capacity(count);
    for item in items {
        if item.FmtValue.CStatus != PDH_CSTATUS_VALID_DATA && item.FmtValue.CStatus != PDH_CSTATUS_NEW_DATA {
            continue;
        }
        // SAFETY: the name is a NUL-terminated string inside the buffer (or null).
        let name = if item.szName.is_null() {
            String::new()
        } else {
            unsafe { item.szName.to_string() }.unwrap_or_default()
        };
        // SAFETY: PDH_FMT_DOUBLE was requested, so the union holds a double.
        let value = unsafe { item.FmtValue.Anonymous.doubleValue };
        out.insert(name, value);
    }
    out
}

const COUNTERS: &[(&str, &str)] = &[
    ("cpu_utility", r"\Processor Information(_Total)\% Processor Utility"),
    ("cpu_time", r"\Processor Information(_Total)\% Processor Time"),
    ("cpu_perf", r"\Processor Information(_Total)\% Processor Performance"),
    ("standby_normal", r"\Memory\Standby Cache Normal Priority Bytes"),
    ("standby_reserve", r"\Memory\Standby Cache Reserve Bytes"),
    ("standby_core", r"\Memory\Standby Cache Core Bytes"),
    ("modified", r"\Memory\Modified Page List Bytes"),
    ("free_zero", r"\Memory\Free & Zero Page List Bytes"),
    ("pool_paged", r"\Memory\Pool Paged Bytes"),
    ("pool_nonpaged", r"\Memory\Pool Nonpaged Bytes"),
    ("gpu_engine", r"\GPU Engine(*)\Utilization Percentage"),
    ("gpu_dedicated", r"\GPU Adapter Memory(*)\Dedicated Usage"),
    ("gpu_shared", r"\GPU Adapter Memory(*)\Shared Usage"),
    ("gpu_proc_dedicated", r"\GPU Process Memory(*)\Dedicated Usage"),
    ("disk_read", r"\PhysicalDisk(*)\Disk Read Bytes/sec"),
    ("disk_write", r"\PhysicalDisk(*)\Disk Write Bytes/sec"),
    ("disk_idle", r"\PhysicalDisk(*)\% Idle Time"),
    ("disk_queue", r"\PhysicalDisk(*)\Current Disk Queue Length"),
];

type Counters = HashMap<&'static str, HashMap<String, f64>>;

fn first(counters: &Counters, key: &str) -> Option<f64> {
    counters.get(key).and_then(|values| values.values().next().copied())
}

// --------------------------------------------------------------------------- graphics adapters

pub(crate) fn format_luid(high: i32, low: u32) -> String {
    format!("0x{:08X}_0x{:08X}", high as u32, low)
}

/// Every graphics adapter DXGI reports, software ones marked. Empty when DXGI is unavailable.
pub fn adapters() -> Vec<GpuAdapter> {
    // SAFETY: plain factory creation; the COM pointer is released when dropped.
    let Ok(factory) = (unsafe { CreateDXGIFactory1::<IDXGIFactory1>() }) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for index in 0..64u32 {
        // SAFETY: valid factory; DXGI_ERROR_NOT_FOUND ends the list.
        let Ok(adapter) = (unsafe { factory.EnumAdapters1(index) }) else {
            break;
        };
        // SAFETY: valid adapter interface.
        let Ok(desc) = (unsafe { adapter.GetDesc1() }) else {
            continue;
        };
        let name = from_wide(&desc.Description).trim().to_string();
        let software = desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE.0 as u32 != 0 || name == "Microsoft Basic Render Driver";
        out.push(GpuAdapter {
            luid: format_luid(desc.AdapterLuid.HighPart, desc.AdapterLuid.LowPart),
            name,
            vendor_id: desc.VendorId,
            dedicated_total: desc.DedicatedVideoMemory as u64,
            shared_total: desc.SharedSystemMemory as u64,
            software,
        });
    }
    out
}

fn parse_hex(text: &str) -> Option<u32> {
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    u32::from_str_radix(digits, 16).ok()
}

fn luid_from(high: &str, low: &str) -> Option<String> {
    Some(format_luid(parse_hex(high)? as i32, parse_hex(low)?))
}

/// "pid_1234_luid_0x00000000_0x0000D1B5_phys_0_eng_3_engtype_VideoDecode"
/// -> (pid, luid, "phys_eng", engine type).
fn parse_engine(instance: &str) -> Option<(u32, String, String, String)> {
    let parts: Vec<&str> = instance.split('_').collect();
    if parts.len() < 10
        || parts[0] != "pid"
        || parts[2] != "luid"
        || parts[5] != "phys"
        || parts[7] != "eng"
        || parts[9] != "engtype"
    {
        return None;
    }
    let pid = parts[1].parse().ok()?;
    let luid = luid_from(parts[3], parts[4])?;
    let kind = parts[10..].join("_");
    let kind = if kind.trim().is_empty() {
        format!("Engine {}", parts[8])
    } else {
        kind
    };
    Some((pid, luid, format!("{}_{}", parts[6], parts[8]), kind))
}

/// "luid_0x00000000_0x0000D1B5_phys_0" -> luid.
fn parse_adapter_memory(instance: &str) -> Option<String> {
    let parts: Vec<&str> = instance.split('_').collect();
    (parts.len() >= 3 && parts[0] == "luid")
        .then(|| luid_from(parts[1], parts[2]))
        .flatten()
}

/// "pid_1234_luid_0x00000000_0x0000D1B5_phys_0" -> pid.
fn parse_process_memory(instance: &str) -> Option<u32> {
    let parts: Vec<&str> = instance.split('_').collect();
    (parts.len() >= 5 && parts[0] == "pid" && parts[2] == "luid")
        .then(|| parts[1].parse().ok())
        .flatten()
}

type EngineLoads = (HashMap<String, HashMap<String, f32>>, HashMap<u32, f32>);

/// Per adapter {engine type: %} and per process GPU %, the way Task Manager computes them: an
/// engine's load is the sum over processes, an engine type shows its busiest engine, and a
/// process shows its busiest engine.
fn gpu_engines(values: &HashMap<String, f64>) -> EngineLoads {
    let mut engine_load: HashMap<(String, String, String), f64> = HashMap::new();
    let mut by_pid: HashMap<u32, f32> = HashMap::new();
    for (instance, &value) in values {
        let Some((pid, luid, engine, kind)) = parse_engine(instance) else {
            continue;
        };
        let value = value.max(0.0);
        *engine_load.entry((luid, engine, kind)).or_default() += value;
        if value > 0.0 {
            let entry = by_pid.entry(pid).or_default();
            *entry = entry.max(value.min(100.0) as f32);
        }
    }
    let mut per_adapter: HashMap<String, HashMap<String, f32>> = HashMap::new();
    for ((luid, _engine, kind), load) in engine_load {
        let types = per_adapter.entry(luid).or_default();
        let entry = types.entry(kind).or_default();
        *entry = entry.max(load.min(100.0) as f32);
    }
    (per_adapter, by_pid)
}

// --------------------------------------------------------------------------- processor

const CPU_KEY: &str = r"HARDWARE\DESCRIPTION\System\CentralProcessor\0";

/// The processor model, e.g. "AMD Ryzen 7 9700X 8-Core Processor".
pub fn cpu_name() -> String {
    hklm_string(CPU_KEY, "ProcessorNameString")
}

fn base_mhz() -> f32 {
    hklm_dword(CPU_KEY, "~MHz").map(|mhz| mhz as f32).unwrap_or(0.0)
}

/// "0 C:" -> "Disk 0 (C:)"; "1 D: E:" -> "Disk 1 (D:, E:)"; "2" -> "Disk 2".
fn disk_label(instance: &str) -> String {
    let mut words = instance.split_whitespace();
    let number = words.next().unwrap_or(instance);
    let letters: Vec<&str> = words.collect();
    if letters.is_empty() {
        format!("Disk {number}")
    } else {
        format!("Disk {number} ({})", letters.join(", "))
    }
}

fn disk_order(key: &str) -> (u8, u32, String) {
    let head = key.split(' ').next().unwrap_or("");
    match head.parse::<u32>() {
        Ok(number) => (0, number, key.to_string()),
        Err(_) => (1, 0, key.to_string()),
    }
}

// --------------------------------------------------------------------------- network

const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
const NET_REFRESH_EVERY: u64 = 10;

struct NetAdapter {
    luid: u64,
    name: String,
    link_bps: f64,
}

/// Network interfaces that are up (refreshed every few samples: they rarely change and
/// listing them costs more than reading their counters).
fn network_adapters() -> Vec<NetAdapter> {
    let flags = GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size = 16 * 1024u32;
    for _ in 0..4 {
        let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
        let first = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        // SAFETY: the buffer is writable for `size` bytes and 8-byte aligned.
        let status = unsafe { GetAdaptersAddresses(AF_UNSPEC.0 as u32, flags, None, Some(first), &mut size) };
        if status == ERROR_BUFFER_OVERFLOW.0 {
            continue;
        }
        if status != NO_ERROR.0 {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut current = first.cast_const();
        while !current.is_null() {
            // SAFETY: `current` is the first entry or a `Next` link written by GetAdaptersAddresses;
            // every entry lives inside `buffer`, which outlives this loop.
            let adapter = unsafe { &*current };
            current = adapter.Next.cast_const();
            if adapter.OperStatus != IfOperStatusUp || adapter.IfType == IF_TYPE_SOFTWARE_LOOPBACK {
                continue;
            }
            // SAFETY: FriendlyName is a NUL-terminated string inside the buffer (or null).
            let name = if adapter.FriendlyName.is_null() {
                String::new()
            } else {
                unsafe { adapter.FriendlyName.to_string() }.unwrap_or_default()
            };
            if name.to_ascii_lowercase().contains("loopback") {
                continue;
            }
            let speed = adapter.TransmitLinkSpeed;
            // Virtual adapters report 0xFFFFFFFF bit/s ("4294 Mbps"): that means unknown.
            let link_bps = if speed == u64::from(u32::MAX) || speed == u64::MAX {
                0.0
            } else {
                speed as f64
            };
            // SAFETY: NET_LUID_LH is a union whose `Value` view covers the whole 64-bit LUID.
            let luid = unsafe { adapter.Luid.Value };
            out.push(NetAdapter { luid, name, link_bps });
        }
        return out;
    }
    Vec::new()
}

/// (sent, received) octets of one interface.
fn interface_octets(luid: u64) -> Option<(u64, u64)> {
    let mut row = MIB_IF_ROW2::default();
    row.InterfaceLuid.Value = luid;
    // SAFETY: `row` is a valid MIB_IF_ROW2 identified by its LUID; the call fills it in.
    let status = unsafe { GetIfEntry2(&mut row) };
    (status == NO_ERROR).then_some((row.OutOctets, row.InOctets))
}

// --------------------------------------------------------------------------- monitor

/// Samples the whole machine. Rates (CPU, disk, network) are measured between two calls, so
/// the first sample reports them as 0. Use it from one thread at a time.
pub struct SystemMonitor {
    pdh: Pdh,
    adapters: Vec<GpuAdapter>,
    base_mhz: f32,
    processors: ProcessorTimes,
    previous_cores: Option<Vec<(i64, i64, i64)>>,
    processes: SystemProcesses,
    net_adapters: Vec<NetAdapter>,
    previous_net: HashMap<u64, (u64, u64)>,
    net_time: Option<Instant>,
    samples: u64,
}

impl SystemMonitor {
    pub fn new() -> Result<Self, SysError> {
        Ok(Self {
            pdh: Pdh::new(COUNTERS),
            adapters: adapters().into_iter().filter(|a| !a.software).collect(),
            base_mhz: base_mhz(),
            processors: ProcessorTimes::new(),
            previous_cores: None,
            processes: SystemProcesses::new(),
            net_adapters: Vec::new(),
            previous_net: HashMap::new(),
            net_time: None,
            samples: 0,
        })
    }

    /// The real (non-software) graphics adapters.
    pub fn adapters(&self) -> &[GpuAdapter] {
        &self.adapters
    }

    /// Performance counters that do not exist on this computer (their figures read as zero).
    pub fn missing_counters(&self) -> &[&'static str] {
        self.pdh.missing()
    }

    pub fn sample(&mut self) -> Result<Snapshot, SysError> {
        let counters = self.pdh.collect();
        let info = performance_info();
        let cpu = first(&counters, "cpu_utility")
            .or_else(|| first(&counters, "cpu_time"))
            .unwrap_or(0.0);
        let freq_mhz = match first(&counters, "cpu_perf") {
            Some(perf) if perf > 0.0 => (f64::from(self.base_mhz) * perf / 100.0).round() as f32,
            _ => self.base_mhz,
        };
        let (gpu_by_pid, gpus) = self.gpus(&counters);
        let snapshot = Snapshot {
            time_ms: now_unix_ms(),
            cpu: cpu.clamp(0.0, 100.0) as f32,
            per_core: self.per_core(),
            freq_mhz,
            base_mhz: self.base_mhz,
            processes: info.as_ref().map_or(0, |i| i.ProcessCount),
            threads: info.as_ref().map_or(0, |i| i.ThreadCount),
            handles: info.as_ref().map_or(0, |i| i.HandleCount),
            // SAFETY: no pointers are involved.
            uptime_s: unsafe { GetTickCount64() } as f64 / 1000.0,
            memory: self.memory(&counters, info.as_ref()),
            gpus,
            disks: disks(&counters),
            nets: self.nets(),
            gpu_by_pid,
        };
        self.samples += 1;
        Ok(snapshot)
    }

    fn per_core(&mut self) -> Vec<f32> {
        let Ok(now) = self.processors.sample() else {
            return Vec::new();
        };
        let before = self.previous_cores.replace(now.clone());
        match before {
            Some(before) if before.len() == now.len() => before
                .iter()
                .zip(&now)
                .map(|(&(idle0, kernel0, user0), &(idle1, kernel1, user1))| {
                    let total = (kernel1 - kernel0) + (user1 - user0);
                    let idle = idle1 - idle0;
                    if total > 0 {
                        (((total - idle) as f64 * 100.0 / total as f64).clamp(0.0, 100.0) * 10.0).round() as f32 / 10.0
                    } else {
                        0.0
                    }
                })
                .collect(),
            _ => vec![0.0; now.len()],
        }
    }

    fn memory(&mut self, counters: &Counters, info: Option<&PERFORMANCE_INFORMATION>) -> MemoryState {
        let counter = |key: &str| first(counters, key).map(|v| v.max(0.0) as u64);
        let page = info.map_or(4096, |i| i.PageSize as u64);
        let (mut total, mut available) = info.map_or((0, 0), |i| {
            (i.PhysicalTotal as u64 * page, i.PhysicalAvailable as u64 * page)
        });
        if info.is_none() {
            let mut status = MEMORYSTATUSEX {
                dwLength: size_of::<MEMORYSTATUSEX>() as u32,
                ..Default::default()
            };
            // SAFETY: `status` is writable and its length field is set.
            if unsafe { GlobalMemoryStatusEx(&mut status) }.is_ok() {
                total = status.ullTotalPhys;
                available = status.ullAvailPhys;
            }
        }
        let standby = ["standby_normal", "standby_reserve", "standby_core"]
            .iter()
            .filter_map(|k| counter(k))
            .sum();
        MemoryState {
            total,
            available,
            used: total.saturating_sub(available),
            commit: info.map_or(0, |i| i.CommitTotal as u64 * page),
            commit_limit: info.map_or(0, |i| i.CommitLimit as u64 * page),
            standby,
            modified: counter("modified").unwrap_or(0),
            free: counter("free_zero").unwrap_or(0),
            compressed: self.compressed(),
            paged_pool: counter("pool_paged").unwrap_or_else(|| info.map_or(0, |i| i.KernelPaged as u64 * page)),
            nonpaged_pool: counter("pool_nonpaged")
                .unwrap_or_else(|| info.map_or(0, |i| i.KernelNonpaged as u64 * page)),
        }
    }

    fn compressed(&mut self) -> u64 {
        self.processes
            .sample()
            .ok()
            .and_then(|list| {
                list.into_iter()
                    .find(|p| p.name == "Memory Compression" || p.name == "MemCompression")
            })
            .map_or(0, |p| p.working_set)
    }

    fn gpus(&self, counters: &Counters) -> (Vec<GpuUse>, Vec<GpuState>) {
        let empty = HashMap::new();
        let (per_adapter, util_by_pid) = gpu_engines(counters.get("gpu_engine").unwrap_or(&empty));
        let sum_by_luid = |key: &str| {
            let mut out: HashMap<String, u64> = HashMap::new();
            for (instance, &value) in counters.get(key).unwrap_or(&empty) {
                if let Some(luid) = parse_adapter_memory(instance) {
                    *out.entry(luid).or_default() += value.max(0.0) as u64;
                }
            }
            out
        };
        let dedicated = sum_by_luid("gpu_dedicated");
        let shared = sum_by_luid("gpu_shared");
        let mut vram_by_pid: HashMap<u32, u64> = HashMap::new();
        for (instance, &value) in counters.get("gpu_proc_dedicated").unwrap_or(&empty) {
            if let Some(pid) = parse_process_memory(instance) {
                *vram_by_pid.entry(pid).or_default() += value.max(0.0) as u64;
            }
        }
        // DXGI can list a stale second LUID for the same card; the kernel's counters only
        // cover adapters that really exist.
        let known = |luid: &str| dedicated.is_empty() || dedicated.contains_key(luid) || per_adapter.contains_key(luid);
        let gpus = self
            .adapters
            .iter()
            .filter(|a| known(&a.luid))
            .map(|adapter| {
                let mut engines: Vec<(String, f32)> = per_adapter
                    .get(&adapter.luid)
                    .map(|m| m.iter().map(|(k, v)| (k.clone(), *v)).collect())
                    .unwrap_or_default();
                engines.sort_by(|a, b| a.0.cmp(&b.0));
                GpuState {
                    luid: adapter.luid.clone(),
                    name: adapter.name.clone(),
                    utilization: engines.iter().map(|e| e.1).fold(0.0, f32::max),
                    engines,
                    dedicated_used: dedicated.get(&adapter.luid).copied().unwrap_or(0),
                    dedicated_total: adapter.dedicated_total,
                    shared_used: shared.get(&adapter.luid).copied().unwrap_or(0),
                    shared_total: adapter.shared_total,
                }
            })
            .collect();
        let mut pids: Vec<u32> = util_by_pid.keys().chain(vram_by_pid.keys()).copied().collect();
        pids.sort_unstable();
        pids.dedup();
        let by_pid = pids
            .into_iter()
            .map(|pid| GpuUse {
                pid,
                utilization: (util_by_pid.get(&pid).copied().unwrap_or(0.0) * 10.0).round() / 10.0,
                dedicated: vram_by_pid.get(&pid).copied().unwrap_or(0),
            })
            .collect();
        (by_pid, gpus)
    }

    fn nets(&mut self) -> Vec<NetState> {
        if self.samples.is_multiple_of(NET_REFRESH_EVERY) || self.net_adapters.is_empty() {
            self.net_adapters = network_adapters();
        }
        let now = Instant::now();
        let seconds = self
            .net_time
            .map(|t| now.duration_since(t).as_secs_f64())
            .unwrap_or(0.0);
        self.net_time = Some(now);
        let before = std::mem::take(&mut self.previous_net);
        let mut out = Vec::new();
        for adapter in &self.net_adapters {
            let Some((sent, recv)) = interface_octets(adapter.luid) else {
                continue;
            };
            if sent == 0 && recv == 0 {
                continue;
            }
            self.previous_net.insert(adapter.luid, (sent, recv));
            let (sent_bps, recv_bps) = match before.get(&adapter.luid) {
                Some(&(sent0, recv0)) if seconds > 0.0 => (
                    sent.saturating_sub(sent0) as f64 / seconds,
                    recv.saturating_sub(recv0) as f64 / seconds,
                ),
                _ => (0.0, 0.0),
            };
            out.push(NetState {
                name: adapter.name.clone(),
                sent_bps,
                recv_bps,
                link_bps: adapter.link_bps,
            });
        }
        out
    }
}

fn performance_info() -> Option<PERFORMANCE_INFORMATION> {
    let mut info = PERFORMANCE_INFORMATION {
        cb: size_of::<PERFORMANCE_INFORMATION>() as u32,
        ..Default::default()
    };
    // SAFETY: `info` is writable and its size field is set.
    unsafe { GetPerformanceInfo(&mut info, info.cb) }.ok().map(|()| info)
}

fn disks(counters: &Counters) -> Vec<DiskState> {
    let empty = HashMap::new();
    let read = counters.get("disk_read").unwrap_or(&empty);
    let write = counters.get("disk_write").unwrap_or(&empty);
    let idle = counters.get("disk_idle").unwrap_or(&empty);
    let queue = counters.get("disk_queue").unwrap_or(&empty);
    let mut keys: Vec<&String> = read
        .keys()
        .chain(write.keys())
        .chain(idle.keys())
        .chain(queue.keys())
        .collect();
    keys.sort_by_key(|k| disk_order(k));
    keys.dedup();
    keys.into_iter()
        .filter(|k| !k.is_empty() && k.as_str() != "_Total")
        .map(|key| {
            let busy = idle.get(key).map_or(0.0, |i| 100.0 - i);
            DiskState {
                key: key.clone(),
                label: disk_label(key),
                read_bps: read.get(key).copied().unwrap_or(0.0).max(0.0),
                write_bps: write.get(key).copied().unwrap_or(0.0).max(0.0),
                active: ((busy.clamp(0.0, 100.0) * 10.0).round() / 10.0) as f32,
                queue: queue.get(key).copied().unwrap_or(0.0).max(0.0) as f32,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gpu_instance_names_are_parsed() {
        let (pid, luid, engine, kind) =
            parse_engine("pid_1234_luid_0x00000000_0x0000D1B5_phys_0_eng_3_engtype_VideoDecode").expect("engine");
        assert_eq!(
            (pid, luid.as_str(), engine.as_str(), kind.as_str()),
            (1234, "0x00000000_0x0000D1B5", "0_3", "VideoDecode")
        );
        let (_, _, _, kind) = parse_engine("pid_1_luid_0x0_0x1_phys_0_eng_7_engtype_").expect("engine");
        assert_eq!(kind, "Engine 7");
        assert_eq!(
            parse_adapter_memory("luid_0x00000000_0x0000d1b5_phys_0").as_deref(),
            Some("0x00000000_0x0000D1B5")
        );
        assert_eq!(
            parse_process_memory("pid_42_luid_0x00000000_0x0000D1B5_phys_0"),
            Some(42)
        );
        assert!(parse_engine("_Total").is_none());
    }

    #[test]
    fn engine_loads_follow_task_manager() {
        let values: HashMap<String, f64> = [
            ("pid_1_luid_0x0_0x1_phys_0_eng_0_engtype_3D", 30.0),
            ("pid_2_luid_0x0_0x1_phys_0_eng_0_engtype_3D", 25.0),
            ("pid_2_luid_0x0_0x1_phys_0_eng_1_engtype_Copy", 5.0),
            ("pid_3_luid_0x0_0x1_phys_0_eng_2_engtype_VideoDecode", 0.0),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        let (per_adapter, by_pid) = gpu_engines(&values);
        let engines = &per_adapter["0x00000000_0x00000001"];
        assert_eq!(engines["3D"], 55.0);
        assert_eq!(engines["Copy"], 5.0);
        assert_eq!(engines["VideoDecode"], 0.0);
        assert_eq!(by_pid[&1], 30.0);
        assert_eq!(by_pid[&2], 25.0);
        assert!(!by_pid.contains_key(&3));
    }

    #[test]
    fn disk_labels() {
        assert_eq!(disk_label("0 C:"), "Disk 0 (C:)");
        assert_eq!(disk_label("1 D: E:"), "Disk 1 (D:, E:)");
        assert_eq!(disk_label("2"), "Disk 2");
    }

    #[test]
    fn unknown_counter_paths_degrade() {
        let mut pdh = Pdh::new(&[
            ("bogus", r"\No Such Object(*)\Nothing At All"),
            ("cpu", r"\Processor Information(_Total)\% Processor Time"),
        ]);
        assert_eq!(pdh.missing(), ["bogus"]);
        let values = pdh.collect();
        assert!(!values.contains_key("bogus"));
    }

    #[test]
    fn luid_format() {
        assert_eq!(format_luid(0, 0xD1B5), "0x00000000_0x0000D1B5");
        assert_eq!(format_luid(-1, 1), "0xFFFFFFFF_0x00000001");
    }
}
