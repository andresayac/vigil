use std::fmt;

/// The action could not be carried out. The message is shown to the user as is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionError(String);

impl ActionError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    pub fn message(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ActionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ActionError {}

impl serde::Serialize for ActionError {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

pub type Result<T> = std::result::Result<T, ActionError>;

/// Shorthand for `Err(ActionError::new(...))`.
pub(crate) fn fail<T>(message: impl Into<String>) -> Result<T> {
    Err(ActionError::new(message))
}

/// The readable part of an I/O error ("Access is denied." rather than the debug form).
pub(crate) fn io_text(error: &std::io::Error) -> String {
    let text = error.to_string();
    match text.find(" (os error") {
        Some(index) => text[..index].to_string(),
        None => text,
    }
}
