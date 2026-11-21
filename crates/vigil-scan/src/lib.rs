//! Vigil's read-only security scan.
//!
//! `collect` takes an inventory of the computer (processes, services, drivers, scheduled tasks,
//! startup entries, programs, browser extensions, event logs, security settings), the local rules
//! evaluate it, and the result is an [`model::Analysis`]: items with signals, a score, a provisional
//! verdict and manual remediation steps. The optional AI review ([`ai`]) and VirusTotal lookups
//! ([`vt`]) refine it.
//!
//! The scan never changes the system. Everything read from the system is untrusted data: it is
//! never executed, it is escaped in the HTML report, and in AI prompts it is data, not instructions.

use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::Value;

pub mod ai;
pub mod cmdline;
pub mod model;
pub mod pipeline;
pub mod privacy;
pub mod remedy;
pub mod report;
pub mod rules;
pub mod vt;

mod analyze;
mod collect;
mod engine;
mod error;
mod ip;
mod lenient;
mod ntpath;
mod posture;
mod winreg;

#[cfg(test)]
mod reference;

pub use analyze::signature_text;
pub use engine::{local_verdict, sort_for_report};
pub use error::ScanError;

/// Collects the inventory of this computer and evaluates it (read-only).
///
/// `days`: how far back the event logs are read. `vt_key`: the user's VirusTotal key (only the
/// hashes of unsigned or flagged files are sent). `progress` receives readable status lines;
/// setting `cancel` stops the collectors and returns [`ScanError::Cancelled`].
pub fn collect_and_analyze(
    days: u32,
    vt_key: Option<&str>,
    progress: &dyn Fn(&str),
    cancel: &AtomicBool,
) -> Result<(Value, model::Analysis), ScanError> {
    let workdir = collect::WorkDir::create()
        .map_err(|e| ScanError::Collector(format!("could not create a temporary folder: {e}")))?;
    let mut raw = collect::collect_all(workdir.path(), days, progress, cancel);
    if cancel.load(Ordering::Relaxed) {
        return Err(ScanError::Cancelled);
    }
    let live = engine::Live {
        workdir: Some(workdir.path()),
        vt_key,
        vt_limit: 25,
        progress,
        cancel,
    };
    let analysis = engine::analyze(&mut raw, Some(&live));
    if cancel.load(Ordering::Relaxed) {
        return Err(ScanError::Cancelled);
    }
    Ok((raw, analysis))
}

/// Evaluates a raw inventory. With `live = false` nothing on the system is touched (saved or test
/// inventories); with `live = true` missing signatures are verified and hashes computed.
pub fn run_analysis(raw: &Value, live: bool) -> model::Analysis {
    let mut raw = raw.clone();
    if live {
        let cancel = AtomicBool::new(false);
        let quiet = |_: &str| {};
        let options = engine::Live {
            workdir: None,
            vt_key: None,
            vt_limit: 25,
            progress: &quiet,
            cancel: &cancel,
        };
        engine::analyze(&mut raw, Some(&options))
    } else {
        engine::analyze(&mut raw, None)
    }
}
