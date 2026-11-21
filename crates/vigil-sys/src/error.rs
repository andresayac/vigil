use std::fmt;

/// An operating-system call failed. Carries a readable message and the Win32 error or
/// NTSTATUS code (0 when there is none).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysError {
    message: String,
    code: i32,
}

impl SysError {
    pub fn new(message: impl Into<String>, code: i32) -> Self {
        Self {
            message: message.into(),
            code,
        }
    }

    /// What failed, in words.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The Win32 error code, HRESULT or NTSTATUS behind the failure (0 when unknown).
    pub fn code(&self) -> i32 {
        self.code
    }

    pub(crate) fn from_windows(context: &str, error: &windows::core::Error) -> Self {
        Self::new(format!("{context}: {}", error.message()), error.code().0)
    }

    pub(crate) fn ntstatus(context: &str, status: i32) -> Self {
        Self::new(format!("{context} failed"), status)
    }
}

impl fmt::Display for SysError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.code == 0 {
            f.write_str(&self.message)
        } else {
            write!(f, "{} (0x{:08X})", self.message, self.code as u32)
        }
    }
}

impl std::error::Error for SysError {}

impl serde::Serialize for SysError {
    /// Serialized as its display text, so it can be returned from UI commands as is.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}
