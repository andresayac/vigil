use std::fmt;

/// What went wrong, so callers can react (for example, tell "not a full path" from a Windows
/// failure) without parsing messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaintErrorKind {
    /// A path argument was empty, relative or malformed.
    InvalidPath,
    /// A path that should exist does not.
    NotFound,
    /// The operation does not apply there (network or removable drive without a Recycle Bin).
    Unsupported,
    /// A Windows call failed.
    Windows,
    /// The hardware collector failed or produced unreadable output.
    Collector,
}

/// An error with a message that can be shown to the user as is.
#[derive(Debug, Clone)]
pub struct MaintError {
    pub kind: MaintErrorKind,
    pub message: String,
    /// Win32 error or HRESULT, when the error comes from Windows.
    pub code: Option<i64>,
}

impl MaintError {
    pub(crate) fn new(kind: MaintErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            code: None,
        }
    }

    pub(crate) fn windows(message: impl Into<String>, code: i64) -> Self {
        Self {
            kind: MaintErrorKind::Windows,
            message: message.into(),
            code: Some(code),
        }
    }
}

impl fmt::Display for MaintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for MaintError {}
