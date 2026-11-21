//! Native (ntdll) system queries: every process with its counters in one call, per-processor
//! times and the image path of any process without opening it.
//!
//! The kernel structures below are the full x64 layouts (the Windows SDK only documents a
//! reduced version). They are read from the query buffer with bounds checks; pointers inside
//! the buffer (process names) are resolved only when they point back into the same buffer.

use std::mem::size_of;

use windows::Wdk::System::SystemInformation::{NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS};

use crate::SysError;

const STATUS_BUFFER_OVERFLOW: i32 = 0x8000_0005_u32 as i32;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;
const STATUS_BUFFER_TOO_SMALL: i32 = 0xC000_0023_u32 as i32;

const SYSTEM_PROCESS_INFORMATION: i32 = 5;
const SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION: i32 = 8;
const SYSTEM_PROCESS_ID_INFORMATION: i32 = 0x58;

const THREAD_STATE_WAITING: u32 = 5;
const WAIT_REASON_SUSPENDED: u32 = 5;

#[repr(C)]
#[derive(Clone, Copy)]
struct RawUnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcessInformation {
    next_entry_offset: u32,
    number_of_threads: u32,
    working_set_private_size: i64,
    hard_fault_count: u32,
    number_of_threads_high_watermark: u32,
    cycle_time: u64,
    create_time: i64,
    user_time: i64,
    kernel_time: i64,
    image_name: RawUnicodeString,
    base_priority: i32,
    unique_process_id: usize,
    inherited_from_unique_process_id: usize,
    handle_count: u32,
    session_id: u32,
    unique_process_key: usize,
    peak_virtual_size: usize,
    virtual_size: usize,
    page_fault_count: u32,
    peak_working_set_size: usize,
    working_set_size: usize,
    quota_peak_paged_pool_usage: usize,
    quota_paged_pool_usage: usize,
    quota_peak_non_paged_pool_usage: usize,
    quota_non_paged_pool_usage: usize,
    pagefile_usage: usize,
    peak_pagefile_usage: usize,
    private_page_count: usize,
    read_operation_count: i64,
    write_operation_count: i64,
    other_operation_count: i64,
    read_transfer_count: i64,
    write_transfer_count: i64,
    other_transfer_count: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ThreadInformation {
    kernel_time: i64,
    user_time: i64,
    create_time: i64,
    wait_time: u32,
    start_address: usize,
    unique_process: usize,
    unique_thread: usize,
    priority: i32,
    base_priority: i32,
    context_switches: u32,
    thread_state: u32,
    wait_reason: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcessorPerformance {
    idle_time: i64,
    kernel_time: i64,
    user_time: i64,
    dpc_time: i64,
    interrupt_time: i64,
    interrupt_count: u32,
}

#[repr(C)]
struct ProcessIdInformation {
    process_id: usize,
    image_name: RawUnicodeString,
}

#[cfg(target_pointer_width = "64")]
const _: () = {
    assert!(size_of::<ProcessInformation>() == 256);
    assert!(size_of::<ThreadInformation>() == 80);
    assert!(size_of::<ProcessorPerformance>() == 48);
};

/// Plain-old-data structures that may be copied out of a byte buffer (every bit pattern is valid).
trait Pod: Copy {}
impl Pod for ProcessInformation {}
impl Pod for ThreadInformation {}
impl Pod for ProcessorPerformance {}

/// Copies a `T` out of `bytes` at `offset`, or None when it does not fit.
fn read<T: Pod>(bytes: &[u8], offset: usize) -> Option<T> {
    let end = offset.checked_add(size_of::<T>())?;
    if end > bytes.len() {
        return None;
    }
    // SAFETY: the range [offset, end) is inside `bytes`, `T` is plain old data for which any bit
    // pattern is valid, and `read_unaligned` copes with any alignment.
    Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr().add(offset).cast::<T>()) })
}

/// A reusable, 8-byte aligned buffer for NtQuerySystemInformation that grows on demand.
pub(crate) struct QueryBuffer {
    words: Vec<u64>,
}

impl QueryBuffer {
    pub(crate) fn new(bytes: usize) -> Self {
        Self {
            words: vec![0; bytes.div_ceil(8)],
        }
    }

    fn byte_len(&self) -> usize {
        self.words.len() * 8
    }

    /// Runs the query for `class` and returns the filled buffer.
    fn query(&mut self, class: i32) -> Result<&[u8], SysError> {
        for _ in 0..8 {
            let length = u32::try_from(self.byte_len()).unwrap_or(u32::MAX);
            let mut needed = 0u32;
            // SAFETY: the pointer and length describe our own writable buffer.
            let status = unsafe {
                NtQuerySystemInformation(
                    SYSTEM_INFORMATION_CLASS(class),
                    self.words.as_mut_ptr().cast(),
                    length,
                    &mut needed,
                )
            };
            match status.0 {
                STATUS_INFO_LENGTH_MISMATCH | STATUS_BUFFER_TOO_SMALL | STATUS_BUFFER_OVERFLOW => {
                    // Processes may start between two calls: leave room for them.
                    let bytes = (needed as usize).max(self.byte_len()) + 256 * 1024;
                    self.words.resize(bytes.div_ceil(8), 0);
                }
                code if code < 0 => return Err(SysError::ntstatus("NtQuerySystemInformation", code)),
                _ => {
                    let len = self.byte_len();
                    // SAFETY: `words` owns `len` initialized bytes; u8 has no alignment requirement.
                    return Ok(unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast::<u8>(), len) });
                }
            }
        }
        Err(SysError::new(
            "the process list kept growing while it was being read",
            0,
        ))
    }
}

/// One process as the kernel reports it.
#[derive(Debug, Clone)]
pub(crate) struct RawProcess {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub threads: u32,
    pub handles: u32,
    pub session: u32,
    /// FILETIME of the creation (0 for the Idle process).
    pub created_raw: i64,
    /// User + kernel time, 100 ns units.
    pub cpu_time: i64,
    /// Private working set: the "Memory" column of Task Manager.
    pub private_ws: u64,
    pub working_set: u64,
    pub io_read: u64,
    pub io_write: u64,
    pub suspended: bool,
}

/// The bytes of an 8-byte aligned word buffer.
pub(crate) fn as_bytes(words: &[u64]) -> &[u8] {
    // SAFETY: the slice owns `len * 8` initialized bytes and u8 has no alignment requirement.
    unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), words.len() * 8) }
}

/// The UNICODE_STRING stored at `offset` of `bytes`, when its text lies inside `bytes` too.
pub(crate) fn unicode_string_at(bytes: &[u8], offset: usize) -> Option<String> {
    let header = bytes.get(offset..offset.checked_add(size_of::<RawUnicodeString>())?)?;
    let length = u16::from_le_bytes([header[0], header[1]]);
    let pointer_bytes: [u8; size_of::<usize>()] = header[size_of::<usize>()..].try_into().ok()?;
    let text = RawUnicodeString {
        length,
        maximum_length: 0,
        buffer: usize::from_le_bytes(pointer_bytes),
    };
    string_in_buffer(bytes, text)
}

/// UTF-16 text a kernel pointer refers to, when it points inside `bytes`.
fn string_in_buffer(bytes: &[u8], text: RawUnicodeString) -> Option<String> {
    let base = bytes.as_ptr() as usize;
    let start = text.buffer.checked_sub(base)?;
    let end = start.checked_add(text.length as usize)?;
    let slice = bytes.get(start..end)?;
    let units: Vec<u16> = slice
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&pair| u16::from_le_bytes(pair))
        .collect();
    Some(String::from_utf16_lossy(&units))
}

/// Suspended = every thread waits with the "suspended" reason (as Task Manager shows it).
fn all_threads_suspended(bytes: &[u8], first_thread: usize, threads: u32, pid: u32) -> bool {
    if threads == 0 || pid <= 4 {
        return false;
    }
    (0..threads as usize).all(|index| {
        read::<ThreadInformation>(bytes, first_thread + index * size_of::<ThreadInformation>())
            .is_some_and(|t| t.thread_state == THREAD_STATE_WAITING && t.wait_reason == WAIT_REASON_SUSPENDED)
    })
}

/// Every process with its figures, in one kernel call.
pub(crate) struct SystemProcesses {
    buffer: QueryBuffer,
}

impl SystemProcesses {
    pub(crate) fn new() -> Self {
        Self {
            buffer: QueryBuffer::new(1 << 20),
        }
    }

    pub(crate) fn sample(&mut self) -> Result<Vec<RawProcess>, SysError> {
        let bytes = self.buffer.query(SYSTEM_PROCESS_INFORMATION)?;
        let mut out = Vec::with_capacity(512);
        let mut offset = 0usize;
        while let Some(info) = read::<ProcessInformation>(bytes, offset) {
            let pid = info.unique_process_id as u32;
            let name = if info.image_name.length > 0 {
                string_in_buffer(bytes, info.image_name).unwrap_or_default()
            } else if pid == 0 {
                "System Idle Process".to_string()
            } else {
                String::new()
            };
            let first_thread = offset + size_of::<ProcessInformation>();
            out.push(RawProcess {
                pid,
                ppid: info.inherited_from_unique_process_id as u32,
                name,
                threads: info.number_of_threads,
                handles: info.handle_count,
                session: info.session_id,
                created_raw: info.create_time,
                cpu_time: info.user_time.saturating_add(info.kernel_time),
                private_ws: info.working_set_private_size.max(0) as u64,
                working_set: info.working_set_size as u64,
                io_read: info.read_transfer_count.max(0) as u64,
                io_write: info.write_transfer_count.max(0) as u64,
                suspended: all_threads_suspended(bytes, first_thread, info.number_of_threads, pid),
            });
            if info.next_entry_offset == 0 {
                break;
            }
            offset += info.next_entry_offset as usize;
        }
        Ok(out)
    }
}

/// Idle, kernel (which includes idle) and user time of every processor, 100 ns units.
pub(crate) struct ProcessorTimes {
    buffer: QueryBuffer,
}

impl ProcessorTimes {
    pub(crate) fn new() -> Self {
        Self {
            buffer: QueryBuffer::new(size_of::<ProcessorPerformance>() * 64),
        }
    }

    pub(crate) fn sample(&mut self) -> Result<Vec<(i64, i64, i64)>, SysError> {
        let bytes = self.buffer.query(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION)?;
        let count = (crate::util::logical_processors() as usize).min(bytes.len() / size_of::<ProcessorPerformance>());
        Ok((0..count)
            .filter_map(|index| read::<ProcessorPerformance>(bytes, index * size_of::<ProcessorPerformance>()))
            .map(|p| (p.idle_time, p.kernel_time, p.user_time))
            .collect())
    }
}

/// The NT image path ("\Device\HarddiskVolume3\...") of any process, without opening it.
/// Works for protected and SYSTEM processes and does not need administrator rights.
pub(crate) fn nt_image_path(pid: u32) -> Option<String> {
    if pid <= 4 {
        return None;
    }
    let mut units = vec![0u16; 0x7FFF];
    let mut info = ProcessIdInformation {
        process_id: pid as usize,
        image_name: RawUnicodeString {
            length: 0,
            maximum_length: 0xFFFE,
            buffer: units.as_mut_ptr() as usize,
        },
    };
    let size = size_of::<ProcessIdInformation>() as u32;
    // SAFETY: `info` is a valid SYSTEM_PROCESS_ID_INFORMATION whose name buffer (`units`, 0xFFFE
    // bytes) stays alive and writable for the duration of the call.
    let status = unsafe {
        NtQuerySystemInformation(
            SYSTEM_INFORMATION_CLASS(SYSTEM_PROCESS_ID_INFORMATION),
            (&mut info as *mut ProcessIdInformation).cast(),
            size,
            std::ptr::null_mut(),
        )
    };
    let length = (info.image_name.length as usize / 2).min(units.len());
    if status.0 < 0 || length == 0 {
        return None;
    }
    Some(String::from_utf16_lossy(&units[..length]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::offset_of;

    #[test]
    fn own_process_is_in_the_kernel_list() {
        let mut processes = SystemProcesses::new();
        let list = processes.sample().expect("process list");
        let me = list.iter().find(|p| p.pid == std::process::id()).expect("own process");
        assert!(!me.name.is_empty());
        assert!(me.threads >= 1);
        assert!(me.created_raw > 0);
        assert!(!me.suspended);
        assert!(list.iter().any(|p| p.pid == 4));
    }

    #[test]
    fn processor_times_cover_every_core() {
        let times = ProcessorTimes::new().sample().expect("processor times");
        assert!(!times.is_empty());
        assert!(times.iter().all(|&(idle, kernel, _)| kernel >= idle));
    }

    #[test]
    fn own_image_path_is_found() {
        let path = nt_image_path(std::process::id()).expect("own path");
        assert!(path.starts_with('\\'));
        assert!(path.to_ascii_lowercase().ends_with(".exe"));
        assert!(nt_image_path(0).is_none());
    }

    #[test]
    fn layout_offsets_match_windows() {
        assert_eq!(offset_of!(ProcessInformation, image_name), 56);
        assert_eq!(offset_of!(ProcessInformation, unique_process_id), 80);
        assert_eq!(offset_of!(ProcessInformation, read_transfer_count), 232);
        assert_eq!(offset_of!(ThreadInformation, thread_state), 68);
    }
}
