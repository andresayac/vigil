//! Data types of the analysis and their JSON form (the `-report.json` format).

use serde::{Serialize, Serializer};
use serde_json::{Map, Value, json};

use crate::lenient::{Get, as_int, list, obj, str_of, text, truthy};
use vigil_i18n::tl;

/// Verdicts in order of severity (most severe first).
///   remove / disable / review / safe -> assigned by the AI
///   no_signals                       -> local heuristics found nothing to object to (no AI analysis)
///   trusted                          -> Microsoft component verified automatically
pub const VERDICTS: [&str; 6] = ["remove", "disable", "review", "no_signals", "safe", "trusted"];

/// Position of a verdict in [`VERDICTS`] (unknown verdicts sort like "review").
pub fn verdict_rank(verdict: &str) -> usize {
    VERDICTS.iter().position(|v| *v == verdict).unwrap_or(2)
}

/// Letter that prefixes the ids of each kind of item (B1, C2...).
pub fn kind_prefix(kind: &str) -> &'static str {
    match kind {
        "executable" => "B",
        "command" => "C",
        "group" => "G",
        "program" => "P",
        "extension" => "X",
        "event" => "E",
        "config" => "S",
        _ => "Z",
    }
}

/// Readable name of each kind of item.
pub fn kind_label(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "executable" => tl!("Executable"),
        "command" => tl!("Command"),
        "group" => tl!("Publisher group"),
        "program" => tl!("Program"),
        "extension" => tl!("Extension"),
        "event" => tl!("Event"),
        "config" => tl!("Setting"),
        _ => return None,
    })
}

/// A local signal: a rule that matched, its weight in the score and its explanation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Flag {
    pub code: String,
    pub weight: i64,
    pub text: String,
}

impl Flag {
    pub fn new(code: impl Into<String>, weight: i64, text: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            weight,
            text: text.into(),
        }
    }

    pub fn to_value(&self) -> Value {
        json!({"code": self.code, "weight": self.weight, "text": self.text})
    }

    fn from_value(value: &Value) -> Self {
        Self {
            code: text(value.at("code")),
            weight: as_int(value.at("weight")).unwrap_or(0),
            text: text(value.at("text")),
        }
    }
}

/// One way a file or command is present on the system.
#[derive(Clone, Debug, PartialEq)]
pub struct Role {
    /// process | service | driver | task | startup | wmi
    pub kind: String,
    /// Short readable description.
    pub label: String,
    /// Data used to build the remediation steps.
    pub detail: Map<String, Value>,
    pub command: String,
    /// Starts on its own (survives a reboot).
    pub persistent: bool,
    /// Runs as SYSTEM or with elevated privileges.
    pub privileged: bool,
    /// Enabled.
    pub active: bool,
}

impl Role {
    pub fn new(kind: &str, label: impl Into<String>, detail: Map<String, Value>) -> Self {
        Self {
            kind: kind.to_string(),
            label: label.into(),
            detail,
            command: String::new(),
            persistent: false,
            privileged: false,
            active: true,
        }
    }

    pub fn to_value(&self) -> Value {
        json!({
            "kind": self.kind, "label": self.label, "detail": self.detail, "command": self.command,
            "persistent": self.persistent, "privileged": self.privileged, "active": self.active,
        })
    }

    fn from_value(value: &Value) -> Self {
        let flag = |key: &str, default: bool| value.get(key).map_or(default, truthy);
        Self {
            kind: text(value.at("kind")),
            label: text(value.at("label")),
            detail: obj(value.at("detail")).clone(),
            command: text(value.at("command")),
            persistent: flag("persistent", false),
            privileged: flag("privileged", false),
            active: flag("active", true),
        }
    }
}

/// An evaluated item: what the AI sees and what appears in the report.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Item {
    pub kind: String,
    pub title: String,
    pub subtitle: String,
    pub id: String,
    pub path: Option<String>,
    pub file: Option<Map<String, Value>>,
    pub roles: Vec<Role>,
    pub commands: Vec<String>,
    pub decoded: Vec<String>,
    pub network: Map<String, Value>,
    pub flags: Vec<Flag>,
    pub score: i64,
    pub trusted: bool,
    pub facts: Map<String, Value>,
    pub members: Vec<Value>,
    pub sha256: Option<String>,
    pub vt: Option<Map<String, Value>>,
    // Result
    pub verdict: String,
    /// ai | heuristic | automatic
    pub verdict_source: String,
    pub confidence: String,
    pub what: String,
    pub reason: String,
    pub action: String,
    pub remediation: Vec<Value>,
    /// Actions taken from the desktop app: `[{"time", "label", "ok", "message"}]`.
    pub actions_taken: Vec<Value>,
}

impl Item {
    pub fn new(kind: &str, title: impl Into<String>, subtitle: impl Into<String>) -> Self {
        Self {
            kind: kind.to_string(),
            title: title.into(),
            subtitle: subtitle.into(),
            ..Self::default()
        }
    }

    /// Adds a flag unless one with the same code is already there.
    pub fn add_flag(&mut self, flag: Flag) {
        if self.flags.iter().all(|existing| existing.code != flag.code) {
            self.flags.push(flag);
        }
    }

    /// Score = sum of the flag weights, clamped to 0..=100.
    pub fn rescore(&mut self) {
        self.score = self.flags.iter().map(|f| f.weight).sum::<i64>().clamp(0, 100);
    }

    /// Risk level according to the local heuristics.
    pub fn level(&self) -> &'static str {
        if self.trusted {
            "trusted"
        } else if self.score >= 70 {
            "critical"
        } else if self.score >= 40 {
            "suspicious"
        } else if self.score >= 15 {
            "attention"
        } else {
            "no_signals"
        }
    }

    /// Starts on its own through at least one enabled role.
    pub fn persistent(&self) -> bool {
        self.roles.iter().any(|role| role.persistent && role.active)
    }

    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("kind".into(), json!(self.kind));
        map.insert("title".into(), json!(self.title));
        map.insert("subtitle".into(), json!(self.subtitle));
        map.insert("id".into(), json!(self.id));
        map.insert("path".into(), json!(self.path));
        map.insert("file".into(), json!(self.file));
        map.insert(
            "roles".into(),
            Value::Array(self.roles.iter().map(Role::to_value).collect()),
        );
        map.insert("commands".into(), json!(self.commands));
        map.insert("decoded".into(), json!(self.decoded));
        map.insert("network".into(), Value::Object(self.network.clone()));
        map.insert(
            "flags".into(),
            Value::Array(self.flags.iter().map(Flag::to_value).collect()),
        );
        map.insert("score".into(), json!(self.score));
        map.insert("trusted".into(), json!(self.trusted));
        map.insert("facts".into(), Value::Object(self.facts.clone()));
        map.insert("members".into(), Value::Array(self.members.clone()));
        map.insert("sha256".into(), json!(self.sha256));
        map.insert("vt".into(), json!(self.vt));
        map.insert("verdict".into(), json!(self.verdict));
        map.insert("verdict_source".into(), json!(self.verdict_source));
        map.insert("confidence".into(), json!(self.confidence));
        map.insert("what".into(), json!(self.what));
        map.insert("reason".into(), json!(self.reason));
        map.insert("action".into(), json!(self.action));
        map.insert("remediation".into(), Value::Array(self.remediation.clone()));
        map.insert("actions_taken".into(), Value::Array(self.actions_taken.clone()));
        map.insert("level".into(), json!(self.level()));
        Value::Object(map)
    }

    /// Rebuilds an item from its JSON form (unknown keys, such as `level`, are ignored).
    pub fn from_value(value: &Value) -> Self {
        let strings = |key: &str| list(value.at(key)).iter().map(str_of).collect::<Vec<_>>();
        let opt_string = |key: &str| match value.at(key) {
            Value::Null => None,
            other => Some(str_of(other)),
        };
        let opt_map = |key: &str| value.at(key).as_object().cloned();
        Self {
            kind: text(value.at("kind")),
            title: text(value.at("title")),
            subtitle: text(value.at("subtitle")),
            id: text(value.at("id")),
            path: opt_string("path"),
            file: opt_map("file"),
            roles: list(value.at("roles")).iter().map(Role::from_value).collect(),
            commands: strings("commands"),
            decoded: strings("decoded"),
            network: obj(value.at("network")).clone(),
            flags: list(value.at("flags")).iter().map(Flag::from_value).collect(),
            score: as_int(value.at("score")).unwrap_or(0),
            trusted: truthy(value.at("trusted")),
            facts: obj(value.at("facts")).clone(),
            members: list(value.at("members")).to_vec(),
            sha256: opt_string("sha256"),
            vt: opt_map("vt"),
            verdict: text(value.at("verdict")),
            verdict_source: text(value.at("verdict_source")),
            confidence: text(value.at("confidence")),
            what: text(value.at("what")),
            reason: text(value.at("reason")),
            action: text(value.at("action")),
            remediation: list(value.at("remediation")).to_vec(),
            actions_taken: list(value.at("actions_taken")).to_vec(),
        }
    }
}

/// The result of a scan: metadata, items, security posture, coverage notes and AI results.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Analysis {
    pub meta: Map<String, Value>,
    pub items: Vec<Item>,
    /// State summary (Defender, firewall, accounts...).
    pub posture: Map<String, Value>,
    /// Coverage limitations: `[{"area", "message"}]`.
    pub notes: Vec<Value>,
    pub stats: Map<String, Value>,
    /// Executive summary written by the AI.
    pub summary: Option<Value>,
    pub ai: Map<String, Value>,
}

impl Analysis {
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("meta".into(), Value::Object(self.meta.clone()));
        map.insert("stats".into(), Value::Object(self.stats.clone()));
        map.insert("summary".into(), self.summary.clone().unwrap_or(Value::Null));
        map.insert("ai".into(), Value::Object(self.ai.clone()));
        map.insert("posture".into(), Value::Object(self.posture.clone()));
        map.insert("notes".into(), Value::Array(self.notes.clone()));
        map.insert(
            "items".into(),
            Value::Array(self.items.iter().map(Item::to_value).collect()),
        );
        Value::Object(map)
    }

    /// Rebuilds an analysis saved as `-report.json` (with its verdicts).
    pub fn from_value(data: &Value) -> Self {
        Self {
            meta: obj(data.at("meta")).clone(),
            items: list(data.at("items")).iter().map(Item::from_value).collect(),
            posture: obj(data.at("posture")).clone(),
            notes: list(data.at("notes")).to_vec(),
            stats: obj(data.at("stats")).clone(),
            summary: match data.at("summary") {
                Value::Null => None,
                other => Some(other.clone()),
            },
            ai: obj(data.at("ai")).clone(),
        }
    }
}

impl Serialize for Analysis {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_value().serialize(serializer)
    }
}

impl Serialize for Item {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_value().serialize(serializer)
    }
}
