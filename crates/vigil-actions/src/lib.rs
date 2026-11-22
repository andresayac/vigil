//! Vigil's action engine: the only part of Vigil that changes the system.
//!
//! Every action
//!   * runs only after the user confirms it in the app (the scan itself is read-only);
//!   * re-reads the live state first, so it never acts on stale scan data;
//!   * refuses to touch critical Windows components (the guards here are the last line of defence:
//!     the app also hides actions for trusted items);
//!   * writes a journal record with everything needed to undo it whenever that is possible
//!     (previous values, exported registry keys, task definitions, quarantined file contents).
//!
//! External tools are always called by absolute path and with argument lists (never through a
//! shell), and values that reach PowerShell travel in environment variables, never inside the
//! script text, so a crafted name cannot inject commands.
//!
//! The journal, the quarantine records and the backups have stable formats (see `tests/data/formats`), so
//! History can always undo what an earlier session recorded and restore what it quarantined.

mod browser;
mod cmdline;
mod datadir;
pub mod desktop;
mod engine;
mod error;
mod firewall;
#[cfg(test)]
mod fuzz;
#[cfg(test)]
mod fuzz_tests;
mod guards;
mod json_text;
mod labels;
mod ops;
mod params;
mod posture;
mod procs;
mod programs;
mod quarantine;
mod registry;
mod runner;
mod signature;
mod store;
mod tuning;

pub mod accounts;
pub mod defender;
pub mod run;
pub mod shell;
#[doc(hidden)]
pub mod testing;

pub use datadir::{data_dir, data_dir_warning, is_admin, is_reparse_point, record_data_dir_notice};
pub use engine::{
    ActionSpec, Outcome, RunFn, UndoFn, can_undo, execute, execute_plan, known_ops, register, undo, undo_batch,
};
pub use error::ActionError;
pub use guards::{ESSENTIAL_SERVICES, guard_file, guard_service};
pub use labels::{known_op_label, op_label};
pub use ops::{
    approved_location, create_restore_point, service_status, startup_folder_approved, task_enabled,
    task_stores_password,
};
pub use procs::{CRITICAL_PROCESSES, Proc, find_processes, io_memory_priority, process_protection};
pub use quarantine::{delete_quarantined, mask, quarantine_file, restore_quarantined};
pub use registry::{reg_delete, reg_read, reg_write, restore_value, split_key};
pub use runner::{Runner, SystemRunner, ToolResult, first_line, set_runner};
pub use signature::{SignatureInfo, is_microsoft_signed, verify_signature, verify_signatures};
pub use store::{QuarantineEntry, Record, Store};
pub use tuning::size_text;

/// Runs a PowerShell snippet through the current runner; `values` become `$env:PC_<NAME>`.
#[doc(hidden)]
pub fn run_powershell(script: &str, values: &[(&str, &str)]) -> Result<ToolResult, ActionError> {
    runner::ps(script, 180, values)
}
