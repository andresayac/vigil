//! Vigil's service layer, shared by the window and the command lines.
//!
//! The window displays data and asks for things; it never decides. It reads through the plain
//! functions here and in `vigil-sys` / `vigil-maint`, and asks for a change with a typed
//! [`requests::Request`] handed to [`service::run_action`]. That rebuilds the action from Rust's
//! own state (`requests`), confirms it in a native Windows dialog (`confirm`) and runs it through
//! `vigil_actions::execute()`, which journals it. Nothing here depends on a UI toolkit.

pub mod accounts;
pub mod api;
pub mod autoscan;
pub mod autostart;
pub mod cli;
pub mod confirm;
pub mod export;
pub mod extensions;
pub mod firewall;
pub mod inspect;
pub mod investigate;
pub mod mcp;
pub mod notify;
pub mod planner;
pub mod posture;
pub mod programs;
pub mod protection;
pub mod reliability;
pub mod requests;
pub mod secrets;
pub mod service;
pub mod settings;
pub mod state;
pub mod storage_ops;
pub mod tools;
pub mod userdir;
pub mod watch;

/// `vigil scan`: the command-line scan. Returns the exit code.
pub fn scan_cli(args: &[String]) -> i32 {
    cli::run(args)
}

/// The read-only commands `vigil list`, `vigil ports`, `vigil services`, `vigil reliability` and
/// `vigil --help`; `None` when `command` is not one of them.
pub fn tool_cli(command: &str, args: &[String]) -> Option<i32> {
    tools::COMMANDS.contains(&command).then(|| tools::run(command, args))
}
