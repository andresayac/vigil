//! Windows access layer for Vigil: running processes, live system metrics, network
//! connections and elevation.
//!
//! Everything here only reads the system (apart from `elevation::relaunch_elevated`, which
//! starts a new copy of the app after the user accepts the UAC prompt). Data structs derive
//! `serde::Serialize` with camelCase field names: the desktop UI consumes them as JSON.
#![cfg(windows)]

mod error;
mod nt;
mod util;
mod xml;

pub mod accounts;
pub mod apps;
pub mod cpusets;
pub mod defender;
pub mod elevation;
pub mod firewall;
pub mod hooks;
pub mod inspect;
pub mod metrics;
pub mod net;
pub mod posture;
pub mod process;
pub mod programs;
pub mod reliability;
pub mod services;
pub mod signins;
pub mod startup;
pub mod tasks;
pub mod watchlog;

pub use error::SysError;
