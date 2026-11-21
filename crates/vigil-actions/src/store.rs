//! The journal of actions, the quarantine and the backups inside the data folder, in the formats
//! History reads (stable across sessions).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::{ActionError, Result, io_text};
use crate::json_text;

/// One journal entry. Keys and their order are fixed: `id, batch, time, op, label,
/// target, item, params, ok, message, undo, undone` (+ `undone_at, undo_message` once undone).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Record(pub Map<String, Value>);

impl Record {
    fn text(&self, key: &str) -> &str {
        self.0.get(key).and_then(Value::as_str).unwrap_or("")
    }

    pub fn id(&self) -> &str {
        self.text("id")
    }

    pub fn op(&self) -> &str {
        self.text("op")
    }

    pub fn label(&self) -> &str {
        self.text("label")
    }

    pub fn target(&self) -> &str {
        self.text("target")
    }

    pub fn item(&self) -> &str {
        self.text("item")
    }

    pub fn time(&self) -> &str {
        self.text("time")
    }

    pub fn message(&self) -> &str {
        self.text("message")
    }

    pub fn batch(&self) -> Option<&str> {
        self.0.get("batch").and_then(Value::as_str)
    }

    pub fn ok(&self) -> bool {
        self.0.get("ok").is_some_and(crate::params::truthy)
    }

    pub fn undone(&self) -> bool {
        self.0.get("undone").is_some_and(crate::params::truthy)
    }

    /// What the undo handler needs (`None` when the action cannot be undone).
    pub fn undo_data(&self) -> Option<&Value> {
        self.0.get("undo").filter(|value| !value.is_null())
    }

    pub fn undo_message(&self) -> Option<&str> {
        self.0.get("undo_message").and_then(Value::as_str)
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0.get(key)
    }

    pub fn as_value(&self) -> Value {
        Value::Object(self.0.clone())
    }
}

/// A file in quarantine (its `.json` record plus whether the masked copy is still there).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: String,
    pub name: String,
    pub size: u64,
    pub sha256: String,
    /// Local time, ISO 8601 to the second.
    pub quarantined_at: String,
    /// Seconds since 1970 (file times when it was quarantined).
    pub modified: Option<f64>,
    pub created: Option<f64>,
    pub reason: String,
    /// `removed`, or `scheduled` when Windows deletes the original at the next restart.
    pub state: Option<String>,
    pub present: bool,
}

impl QuarantineEntry {
    /// Reads a quarantine record leniently (missing or null fields become empty).
    pub(crate) fn from_value(value: &Value) -> Option<Self> {
        let map = value.as_object()?;
        let text = |key: &str| match map.get(key) {
            Some(Value::String(text)) => text.clone(),
            Some(Value::Null) | None => String::new(),
            Some(other) => other.to_string(),
        };
        Some(QuarantineEntry {
            id: text("id"),
            original_path: text("original_path"),
            name: text("name"),
            size: map
                .get("size")
                .and_then(Value::as_f64)
                .map(|n| n.max(0.0) as u64)
                .unwrap_or(0),
            sha256: text("sha256"),
            quarantined_at: text("quarantined_at"),
            modified: map.get("modified").and_then(Value::as_f64),
            created: map.get("created").and_then(Value::as_f64),
            reason: text("reason"),
            state: map.get("state").and_then(Value::as_str).map(str::to_string),
            present: false,
        })
    }
}

/// Journal, quarantine and backups of one data folder.
#[derive(Debug)]
pub struct Store {
    root: PathBuf,
    lock: Mutex<()>,
}

impl Store {
    /// Opens (and creates when needed) the folders of a data folder.
    pub fn open(root: &Path) -> Result<Self> {
        let store = Store {
            root: root.to_path_buf(),
            lock: Mutex::new(()),
        };
        for folder in [store.root.clone(), store.quarantine_dir(), store.backup_dir()] {
            fs::create_dir_all(&folder)
                .map_err(|e| ActionError::new(format!("could not create {}: {}", folder.display(), io_text(&e))))?;
        }
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn quarantine_dir(&self) -> PathBuf {
        self.root.join("quarantine")
    }

    pub fn backup_dir(&self) -> PathBuf {
        self.root.join("backups")
    }

    pub fn journal_path(&self) -> PathBuf {
        self.root.join("journal.jsonl")
    }

    /// Every journal record, oldest first. Lines that are not valid records are skipped.
    pub fn records(&self) -> Vec<Record> {
        let Ok(bytes) = fs::read(self.journal_path()) else {
            return Vec::new();
        };
        let text = String::from_utf8_lossy(&bytes);
        text.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .filter_map(|line| match serde_json::from_str::<Value>(line) {
                Ok(Value::Object(map)) => Some(Record(map)),
                _ => None,
            })
            .collect()
    }

    pub fn find(&self, record_id: &str) -> Option<Record> {
        self.records()
            .into_iter()
            .find(|r| r.0.get("id").and_then(Value::as_str) == Some(record_id))
    }

    /// Adds a record at the end of the journal (execute does this for every action).
    pub fn append(&self, record: &Record) -> Result<()> {
        let _guard = self.lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let line = json_text::dumps(&record.as_value()) + "\n";
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.journal_path())
            .and_then(|mut file| file.write_all(line.as_bytes()))
            .map_err(|e| ActionError::new(format!("could not write the journal: {}", io_text(&e))))
    }

    /// Replaces the record with the same id (the journal is rewritten through a temporary file).
    pub fn update(&self, record: &Record) -> Result<()> {
        let _guard = self.lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut text = String::new();
        for existing in self.records() {
            let same = existing.0.get("id") == record.0.get("id");
            text.push_str(&json_text::dumps(&if same {
                record.as_value()
            } else {
                existing.as_value()
            }));
            text.push('\n');
        }
        let tmp = self.root.join("journal.tmp");
        fs::write(&tmp, text.as_bytes())
            .and_then(|()| fs::rename(&tmp, self.journal_path()))
            .map_err(|e| ActionError::new(format!("could not write the journal: {}", io_text(&e))))
    }

    /// Files in quarantine, most recent first.
    pub fn quarantined(&self) -> Vec<QuarantineEntry> {
        let dir = self.quarantine_dir();
        let mut metas: Vec<PathBuf> = fs::read_dir(&dir)
            .map(|entries| {
                entries
                    .filter_map(|entry| entry.ok().map(|e| e.path()))
                    .filter(|path| path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("json")))
                    .collect()
            })
            .unwrap_or_default();
        metas.sort();
        let mut entries: Vec<QuarantineEntry> = metas
            .iter()
            .filter_map(|meta| {
                let text = fs::read_to_string(meta).ok()?;
                let value: Value = serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()?;
                let mut entry = QuarantineEntry::from_value(&value)?;
                entry.present = dir.join(format!("{}.bin", entry.id)).is_file();
                Some(entry)
            })
            .collect();
        entries.sort_by(|a, b| b.quarantined_at.cmp(&a.quarantined_at));
        entries
    }
}
