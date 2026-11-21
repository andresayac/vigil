//! The logical processors of this computer as Windows CPU Sets (they span processor groups, unlike the
//! old affinity masks), and the CPU Sets a process is limited to. Read-only.

use serde::Serialize;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::SystemInformation::{
    CpuSetInformation, GetSystemCpuSetInformation, SYSTEM_CPU_SET_INFORMATION,
};
use windows::Win32::System::Threading::{GetProcessDefaultCpuSets, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

use crate::error::SysError;

/// One logical processor. `index` is Vigil's number for it (0..n, by processor group and number), the
/// one the UI shows and the affinity action takes; `id` is the CPU Set id Windows uses.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LogicalProcessor {
    pub index: u32,
    pub id: u32,
    pub group: u16,
    pub number: u8,
    /// Physical core: logical processors that share it are its SMT siblings.
    pub core: u8,
    /// Higher is faster: on hybrid CPUs the performance cores have the highest class.
    pub efficiency_class: u8,
    pub numa_node: u8,
}

/// Every logical processor, ordered by processor group and number.
pub fn logical_processors() -> Vec<LogicalProcessor> {
    let mut needed = 0u32;
    // SAFETY: a size query: no buffer, `needed` receives the length in bytes.
    let _ = unsafe { GetSystemCpuSetInformation(None, 0, &mut needed, None, None) };
    if needed == 0 || needed > 1 << 20 {
        return Vec::new();
    }
    // u64 storage keeps the entries 8-byte aligned.
    let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
    let mut returned = 0u32;
    // SAFETY: `buffer` holds `needed` writable bytes, as announced.
    let ok = unsafe {
        GetSystemCpuSetInformation(
            Some(buffer.as_mut_ptr().cast::<SYSTEM_CPU_SET_INFORMATION>()),
            needed,
            &mut returned,
            None,
            None,
        )
    };
    if !ok.as_bool() {
        return Vec::new();
    }
    let bytes = (returned as usize).min(buffer.len() * 8);
    let base = buffer.as_ptr().cast::<u8>();
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset + size_of::<SYSTEM_CPU_SET_INFORMATION>() <= bytes {
        // SAFETY: `offset` is inside the returned bytes and entries are aligned (Size is a multiple of 8).
        let entry = unsafe { &*base.add(offset).cast::<SYSTEM_CPU_SET_INFORMATION>() };
        if entry.Size == 0 {
            break;
        }
        if entry.Type == CpuSetInformation {
            // SAFETY: the union holds a CpuSet when Type is CpuSetInformation.
            let set = unsafe { entry.Anonymous.CpuSet };
            out.push(LogicalProcessor {
                index: 0,
                id: set.Id,
                group: set.Group,
                number: set.LogicalProcessorIndex,
                core: set.CoreIndex,
                efficiency_class: set.EfficiencyClass,
                numa_node: set.NumaNodeIndex,
            });
        }
        offset += entry.Size as usize;
    }
    out.sort_by_key(|p| (p.group, p.number));
    for (index, processor) in out.iter_mut().enumerate() {
        processor.index = index as u32;
    }
    out
}

struct Process(HANDLE);

impl Drop for Process {
    fn drop(&mut self) {
        // SAFETY: the handle came from OpenProcess and is closed once.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// The CPU Set ids a process is limited to by default; empty when it may use every processor.
pub fn process_cpu_sets(pid: u32) -> Result<Vec<u32>, SysError> {
    // SAFETY: plain call; the handle is owned by `Process`.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
        .map_err(|e| SysError::new(format!("process {pid} cannot be read ({})", e.message()), e.code().0))?;
    let handle = Process(handle);
    let mut ids = vec![0u32; 256];
    let mut required = 0u32;
    // SAFETY: `ids` is writable for its length; `required` receives the count.
    let mut ok = unsafe { GetProcessDefaultCpuSets(handle.0, Some(&mut ids), &mut required) };
    if !ok.as_bool() && required as usize > ids.len() && required <= 4096 {
        ids = vec![0u32; required as usize];
        // SAFETY: as above, with room for `required` ids.
        ok = unsafe { GetProcessDefaultCpuSets(handle.0, Some(&mut ids), &mut required) };
    }
    if !ok.as_bool() {
        let error = windows::core::Error::from_thread();
        return Err(SysError::new(
            format!("the processors of process {pid} cannot be read ({})", error.message()),
            error.code().0,
        ));
    }
    ids.truncate(required as usize);
    Ok(ids)
}

/// The logical-processor indexes a process may run on (every index when it is not limited).
pub fn process_processors(pid: u32) -> Result<Vec<u32>, SysError> {
    let all = logical_processors();
    let sets = process_cpu_sets(pid)?;
    Ok(all
        .iter()
        .filter(|p| sets.is_empty() || sets.contains(&p.id))
        .map(|p| p.index)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_logical_processor_is_listed_once() {
        let all = logical_processors();
        let expected = std::thread::available_parallelism().map_or(1, |n| n.get());
        assert_eq!(all.len(), expected, "{all:?}");
        let mut ids: Vec<u32> = all.iter().map(|p| p.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), all.len());
        assert!(all.iter().enumerate().all(|(i, p)| p.index as usize == i));
    }

    #[test]
    fn this_process_may_use_every_processor() {
        let mine = process_processors(std::process::id()).unwrap_or_default();
        assert_eq!(mine.len(), logical_processors().len());
    }
}
