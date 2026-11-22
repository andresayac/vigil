//! A few Windows logs read the cheap way for the background watch: the newest record of a log, and
//! the events with given ids recorded after a record number (each log numbers its records in
//! order). No message is formatted, nothing is changed. Read-only.

use windows::Win32::System::EventLog::{
    EVT_HANDLE, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryForwardDirection, EvtQueryReverseDirection,
};
use windows::core::HSTRING;

use crate::SysError;
use crate::reliability::{Handle, Record, render_xml};

/// One event, as the watch needs it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogEvent {
    /// The log it was read from ("System").
    pub log: String,
    pub provider: String,
    pub event_id: u32,
    pub record_id: u64,
    /// ms since 1970.
    pub time_ms: i64,
    /// EventData values (with their names) or UserData leaves.
    pub data: Vec<(String, String)>,
}

impl LogEvent {
    /// A rendered event (`EvtRenderEventXml`); `None` when it is not one.
    pub fn from_xml(log: &str, xml: &str) -> Option<Self> {
        let record = Record::parse(xml)?;
        Some(Self {
            log: log.to_string(),
            provider: record.provider,
            event_id: record.event_id,
            record_id: record.record_id,
            time_ms: record.time_ms,
            data: record.data,
        })
    }

    /// A value by name ("" when missing).
    pub fn get(&self, name: &str) -> &str {
        self.data
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map_or("", |(_, v)| v.as_str())
    }
}

fn open(log: &str, query: &str, newest_first: bool) -> Result<Handle, SysError> {
    let direction = if newest_first {
        EvtQueryReverseDirection.0
    } else {
        EvtQueryForwardDirection.0
    };
    // SAFETY: both strings are NUL-terminated HSTRINGs that outlive the call.
    unsafe {
        EvtQuery(
            None,
            &HSTRING::from(log),
            &HSTRING::from(query),
            EvtQueryChannelPath.0 | direction,
        )
    }
    .map(Handle)
    .map_err(|e| SysError::from_windows(&format!("could not read the {log} log"), &e))
}

/// Up to `max` rendered events of an open query.
fn take(results: &Handle, max: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut batch = [0isize; 32];
    while out.len() < max {
        let mut returned = 0u32;
        // SAFETY: `batch` is writable for its length; `returned` receives how many were filled.
        if unsafe { EvtNext(results.0, &mut batch, 2000, 0, &mut returned) }.is_err() {
            break; // ERROR_NO_MORE_ITEMS (the end) or a failure: keep what was read
        }
        let handles: Vec<Handle> = batch[..returned as usize]
            .iter()
            .map(|&raw| Handle(EVT_HANDLE(raw)))
            .collect();
        for event in &handles {
            if out.len() < max
                && let Some(xml) = render_xml(event.0)
            {
                out.push(xml);
            }
        }
    }
    out
}

/// The newest record of a log: (record number, time). `Ok(None)` when the log is empty, `Err` when
/// it cannot be read (no rights, or it does not exist on this edition of Windows).
pub fn newest(log: &str) -> Result<Option<(u64, i64)>, SysError> {
    let results = open(log, "*", true)?;
    Ok(take(&results, 1)
        .first()
        .and_then(|xml| LogEvent::from_xml(log, xml))
        .map(|e| (e.record_id, e.time_ms)))
}

/// The events with one of `ids` recorded after record `after`, oldest first, at most `max`.
pub fn read_after(log: &str, ids: &[u32], after: u64, max: usize) -> Result<Vec<LogEvent>, SysError> {
    let results = open(log, &query(ids, after), false)?;
    Ok(take(&results, max)
        .iter()
        .filter_map(|xml| LogEvent::from_xml(log, xml))
        .collect())
}

/// `*[System[(EventID=1 or EventID=2) and EventRecordID>10]]`.
pub fn query(ids: &[u32], after: u64) -> String {
    let ids: Vec<String> = ids.iter().map(|id| format!("EventID={id}")).collect();
    format!("*[System[({}) and EventRecordID>{after}]]", ids.join(" or "))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVICE_INSTALLED: &str = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><Provider Name="Service Control Manager"/><EventID Qualifiers="16384">7045</EventID><Level>4</Level>
  <TimeCreated SystemTime="2026-11-20T10:00:00.5000000Z"/><EventRecordID>4242</EventRecordID>
  <Channel>System</Channel><Computer>PC-VICTIM</Computer></System>
  <EventData><Data Name="ServiceName">Contoso Helper</Data><Data Name="ImagePath">C:\Users\jdoe\AppData\Local\Temp\ch.exe</Data>
  <Data Name="ServiceType">user mode service</Data><Data Name="StartType">auto start</Data><Data Name="AccountName">LocalSystem</Data></EventData>
</Event>"#;

    #[test]
    fn events_are_parsed() {
        let event = LogEvent::from_xml("System", SERVICE_INSTALLED).expect("parsed");
        assert_eq!(event.event_id, 7045);
        assert_eq!(event.record_id, 4242);
        assert_eq!(event.provider, "Service Control Manager");
        assert_eq!(event.get("servicename"), "Contoso Helper");
        assert_eq!(event.get("ImagePath"), r"C:\Users\jdoe\AppData\Local\Temp\ch.exe");
        assert_eq!(event.get("missing"), "");
        assert!(event.time_ms > 0);
    }

    #[test]
    fn the_query_filters_ids_and_records() {
        assert_eq!(
            query(&[7045, 104], 10),
            "*[System[(EventID=7045 or EventID=104) and EventRecordID>10]]"
        );
    }

    #[test]
    fn the_queries_are_accepted_by_windows() {
        // Read-only: the Application log is readable by every user; the filter must be valid XPath.
        let newest = newest("Application");
        assert!(newest.is_ok(), "{newest:?}");
        let read = read_after("Application", &[1000, 1001], u64::MAX / 2, 5);
        assert!(read.is_ok(), "{read:?}");
    }
}
