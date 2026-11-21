//! Reading action parameters and undo data leniently: missing keys and empty values read as absent.

use serde_json::{Map, Value};

use crate::error::{ActionError, Result};

/// Truthiness of a JSON value: `null`, `false`, `0`, `""`, `[]` and `{}` are false.
pub fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// The text of the simple values parameters hold (strings as they are, numbers and booleans spelled out).
pub fn text_of(value: &Value) -> String {
    match value {
        Value::Null => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Parameters (or undo data) of one action.
#[derive(Clone, Copy)]
pub struct Params<'a>(pub &'a Value);

static EMPTY: Value = Value::Null;

impl<'a> Params<'a> {
    pub fn new(value: &'a Value) -> Self {
        Params(value)
    }

    pub fn get(&self, key: &str) -> &'a Value {
        self.0.get(key).unwrap_or(&EMPTY)
    }

    /// `params[key]` as text; a missing key is an error (the action cannot run without it).
    pub fn req_str(&self, key: &str) -> Result<String> {
        match self.0.get(key) {
            None => Err(ActionError::new(format!("unexpected error: KeyError: '{key}'"))),
            Some(value) => Ok(text_of(value)),
        }
    }

    /// `params.get(key) or ""`.
    pub fn str_or_empty(&self, key: &str) -> String {
        let value = self.get(key);
        if truthy(value) { text_of(value) } else { String::new() }
    }

    pub fn flag(&self, key: &str) -> bool {
        truthy(self.get(key))
    }

    /// `params.get(key, default)` as a boolean.
    pub fn flag_or(&self, key: &str, default: bool) -> bool {
        self.0.get(key).map_or(default, truthy)
    }

    /// `int(params[key])`.
    pub fn req_int(&self, key: &str) -> Result<i64> {
        let value = self
            .0
            .get(key)
            .ok_or_else(|| ActionError::new(format!("unexpected error: KeyError: '{key}'")))?;
        as_int(value).ok_or_else(|| {
            ActionError::new(format!(
                "unexpected error: ValueError: invalid literal for int(): {}",
                text_of(value)
            ))
        })
    }

    /// `int(params.get(key, default))`.
    pub fn int_or(&self, key: &str, default: i64) -> Result<i64> {
        match self.0.get(key) {
            None => Ok(default),
            Some(_) => self.req_int(key),
        }
    }

    pub fn float(&self, key: &str) -> Option<f64> {
        match self.get(key) {
            Value::Number(n) => n.as_f64(),
            Value::String(s) => s.trim().parse().ok(),
            _ => None,
        }
    }

    pub fn list(&self, key: &str) -> Vec<&'a Value> {
        self.get(key)
            .as_array()
            .map(|items| items.iter().collect())
            .unwrap_or_default()
    }

    pub fn object(&self, key: &str) -> Option<&'a Map<String, Value>> {
        self.get(key).as_object()
    }
}

pub fn as_int(value: &Value) -> Option<i64> {
    match value {
        Value::Number(n) => n
            .as_i64()
            .or_else(|| n.as_f64().filter(|f| f.is_finite()).map(|f| f.trunc() as i64)),
        Value::String(s) => s.trim().parse().ok(),
        Value::Bool(b) => Some(i64::from(*b)),
        _ => None,
    }
}
