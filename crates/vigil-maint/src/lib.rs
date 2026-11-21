//! Vigil's maintenance layer: what the Storage, Optimize and System pages read and clean.
//!
//! * [`storage`]: drives, cleanup of caches and temporary files, the Recycle Bin and the space
//!   analyzer. Cleaning follows strict rules against links planted by other programs.
//! * [`hardware`]: the hardware inventory (runs an embedded, read-only PowerShell collector).
//! * [`tuning`]: the current power plan, hibernation, Game Mode, GPU scheduling and per-app GPU
//!   preferences (read-only).
//! * [`insights`]: health and performance findings computed from the two above.
//!
//! Nothing in this crate asks for elevation; cleaning simply skips what the caller may not touch.

mod date;
mod error;
pub mod hardware;
pub mod insights;
mod registry;
pub mod storage;
pub mod tuning;
mod walk;
mod win;

pub use date::Date;
pub use error::{MaintError, MaintErrorKind};
