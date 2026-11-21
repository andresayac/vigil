//! Errors of the scan, the reports and the AI review.

use std::fmt;
use std::path::PathBuf;

#[derive(Debug)]
pub enum ScanError {
    /// Reading or writing a file failed.
    Io { path: PathBuf, error: std::io::Error },
    /// The file is not a report this version can open (with the reason for the user).
    InvalidReport(String),
    /// The inventory could not be collected.
    Collector(String),
    /// The AI review failed.
    Ai(String),
    /// The user cancelled the scan.
    Cancelled,
}

impl ScanError {
    pub(crate) fn io(path: impl Into<PathBuf>, error: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            error,
        }
    }
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, error } => write!(f, "{}: {error}", path.display()),
            Self::InvalidReport(reason) => f.write_str(reason),
            Self::Collector(reason) => write!(f, "the inventory could not be collected: {reason}"),
            Self::Ai(reason) => write!(f, "AI review failed: {reason}"),
            Self::Cancelled => f.write_str("the scan was cancelled"),
        }
    }
}

impl std::error::Error for ScanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { error, .. } => Some(error),
            _ => None,
        }
    }
}
