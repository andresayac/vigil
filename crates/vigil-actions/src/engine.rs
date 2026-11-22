//! The dispatcher: runs an action, journals it, and undoes it later from the journal.

use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, LazyLock, RwLock};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::datadir::is_admin;
use crate::error::{ActionError, Result};
use crate::params::Params;
use crate::quarantine::{new_id, now_iso};
use crate::store::{Record, Store};
use vigil_i18n::tr;

/// An action the app can offer for a finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ActionSpec {
    /// Operation id, e.g. `service.disable`.
    pub op: String,
    /// Button / menu text.
    pub label: String,
    /// What it acts on, shown in the confirmation.
    pub target: String,
    /// One sentence: what will happen.
    pub explain: String,
    pub params: Value,
    /// contain | disable | remove | fix | inspect
    pub group: String,
    /// Deletes or kills something.
    pub destructive: bool,
    /// Can be undone from History.
    pub reversible: bool,
    /// Needs an elevated app.
    pub admin: bool,
    /// Extra caution shown in the confirmation.
    pub warning: String,
    /// The steps of a composite action.
    pub steps: Vec<ActionSpec>,
}

impl Default for ActionSpec {
    fn default() -> Self {
        ActionSpec {
            op: String::new(),
            label: String::new(),
            target: String::new(),
            explain: String::new(),
            params: Value::Object(Map::new()),
            group: "inspect".to_string(),
            destructive: false,
            reversible: true,
            admin: true,
            warning: String::new(),
            steps: Vec::new(),
        }
    }
}

impl ActionSpec {
    pub fn new(op: &str, label: &str, target: &str, explain: &str, params: Value) -> Self {
        ActionSpec {
            op: op.to_string(),
            label: label.to_string(),
            target: target.to_string(),
            explain: explain.to_string(),
            params,
            ..ActionSpec::default()
        }
    }
}

/// What an operation did, and the data its undo handler needs (`None` = it cannot be undone).
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    pub message: String,
    pub undo: Option<Value>,
}

impl Outcome {
    pub fn new(message: impl Into<String>, undo: Option<Value>) -> Self {
        Outcome {
            message: message.into(),
            undo,
        }
    }

    pub fn done(message: impl Into<String>) -> Self {
        Outcome {
            message: message.into(),
            undo: None,
        }
    }
}

/// Runs an operation: (params, store, id of the journal record being written).
pub type RunFn = Arc<dyn Fn(&Value, &Store, &str) -> Result<Outcome> + Send + Sync>;
/// Undoes an operation from its undo data; returns the message for the journal.
pub type UndoFn = Arc<dyn Fn(&Value, &Store) -> Result<String> + Send + Sync>;

#[derive(Clone)]
struct OpEntry {
    run: RunFn,
    undo: Option<UndoFn>,
    no_admin: bool,
}

static OPS: LazyLock<RwLock<HashMap<String, OpEntry>>> = LazyLock::new(|| {
    let mut table = HashMap::new();
    for (op, run, undo, no_admin) in crate::ops::builtin()
        .into_iter()
        .chain(crate::tuning::builtin())
        .chain(crate::firewall::builtin())
        .chain(crate::defender::builtin())
        .chain(crate::programs::builtin())
        .chain(crate::accounts::builtin())
        .chain(crate::browser::builtin())
        .chain(crate::posture::builtin())
    {
        table.insert(op.to_string(), OpEntry { run, undo, no_admin });
    }
    RwLock::new(table)
});

fn entry(op: &str) -> Option<OpEntry> {
    OPS.read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(op)
        .cloned()
}

/// Adds an operation defined elsewhere (disk cleanup, later ones) to the dispatcher. Without `undo`,
/// an undo handler registered earlier for the same op is kept.
pub fn register(op: &str, run: RunFn, undo: Option<UndoFn>, no_admin: bool) {
    let mut table = OPS.write().unwrap_or_else(|poisoned| poisoned.into_inner());
    let previous = table.remove(op);
    let undo = undo.or_else(|| previous.as_ref().and_then(|p| p.undo.clone()));
    let no_admin = no_admin || previous.is_some_and(|p| p.no_admin);
    table.insert(op.to_string(), OpEntry { run, undo, no_admin });
}

/// Every operation id the dispatcher knows.
pub fn known_ops() -> Vec<String> {
    let mut ops: Vec<String> = OPS.read().unwrap_or_else(|p| p.into_inner()).keys().cloned().collect();
    ops.sort();
    ops
}

fn panic_text(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_string()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        tr!("internal error")
    }
}

/// Runs one action and journals it. Never fails or panics: the record says whether it worked.
pub fn execute(spec: &ActionSpec, store: &Store, batch: Option<&str>, item: &str) -> Record {
    let id = new_id();
    let params = if spec.params.is_null() {
        Value::Object(Map::new())
    } else {
        spec.params.clone()
    };
    let mut map = Map::new();
    map.insert("id".into(), json!(id));
    map.insert("batch".into(), batch.map_or(Value::Null, |b| json!(b)));
    map.insert("time".into(), json!(now_iso()));
    map.insert("op".into(), json!(spec.op));
    map.insert("label".into(), json!(spec.label));
    map.insert("target".into(), json!(spec.target));
    map.insert("item".into(), json!(item));
    map.insert("params".into(), params.clone());
    map.insert("ok".into(), json!(false));
    map.insert("message".into(), json!(""));
    map.insert("undo".into(), Value::Null);
    map.insert("undone".into(), json!(false));
    let handler = entry(&spec.op);
    let result: Result<Outcome> = match &handler {
        None => Err(ActionError::new(tr!("unknown action {0}", spec.op))),
        Some(op) if spec.admin && !op.no_admin && !is_admin() => {
            Err(ActionError::new(tr!("this action needs Vigil to run as administrator")))
        }
        Some(op) => match catch_unwind(AssertUnwindSafe(|| (op.run)(&params, store, &id))) {
            Ok(result) => result,
            Err(payload) => Err(ActionError::new(tr!(
                "unexpected error: {0}",
                panic_text(payload.as_ref())
            ))),
        },
    };
    match result {
        Ok(outcome) => {
            map.insert("ok".into(), json!(true));
            map.insert("message".into(), json!(outcome.message));
            let has_undo = handler.as_ref().is_some_and(|op| op.undo.is_some());
            map.insert(
                "undo".into(),
                if has_undo {
                    outcome.undo.unwrap_or(Value::Null)
                } else {
                    Value::Null
                },
            );
        }
        Err(error) => {
            map.insert("message".into(), json!(error.message()));
        }
    }
    let record = Record(map);
    if let Err(error) = store.append(&record) {
        let mut map = record.0.clone();
        let message = tr!("{0} (not saved in the journal: {1})", record.message(), error);
        map.insert("message".into(), json!(message));
        return Record(map);
    }
    record
}

/// Runs a single action, or every step of a composite one (sharing a batch id).
pub fn execute_plan(spec: &ActionSpec, store: &Store, item: &str, progress: &dyn Fn(&str)) -> Vec<Record> {
    let single = [spec.clone()];
    let steps: &[ActionSpec] = if spec.steps.is_empty() { &single } else { &spec.steps };
    let batch = if spec.steps.is_empty() { None } else { Some(new_id()) };
    steps
        .iter()
        .map(|step| {
            progress(&step.label);
            execute(step, store, batch.as_deref(), item)
        })
        .collect()
}

/// True when History can offer to undo this record.
pub fn can_undo(record: &Record) -> bool {
    record.ok()
        && record.undo_data().is_some()
        && !record.undone()
        && entry(record.op()).is_some_and(|op| op.undo.is_some())
}

/// Undoes one journaled action and marks it undone.
pub fn undo(record_id: &str, store: &Store) -> Result<Record> {
    let Some(mut record) = store.find(record_id) else {
        return Err(ActionError::new(tr!("that action is not in the journal")));
    };
    if !can_undo(&record) {
        return Err(ActionError::new(tr!("that action cannot be undone")));
    }
    let op = entry(record.op()).ok_or_else(|| ActionError::new(tr!("that action cannot be undone")))?;
    if !is_admin() && !op.no_admin {
        return Err(ActionError::new(tr!("undoing needs Vigil to run as administrator")));
    }
    let Some(undo_fn) = op.undo else {
        return Err(ActionError::new(tr!("that action cannot be undone")));
    };
    let data = record.undo_data().cloned().unwrap_or(Value::Null);
    let message = match catch_unwind(AssertUnwindSafe(|| undo_fn(&data, store))) {
        Ok(result) => result?,
        Err(payload) => {
            return Err(ActionError::new(tr!(
                "unexpected error: {0}",
                panic_text(payload.as_ref())
            )));
        }
    };
    record.0.insert("undone".into(), json!(true));
    record.0.insert("undone_at".into(), json!(now_iso()));
    record.0.insert("undo_message".into(), json!(message));
    store.update(&record)?;
    Ok(record)
}

/// Undoes every step of a composite action, last step first. Each result carries the error, if any.
pub fn undo_batch(batch: &str, store: &Store) -> Vec<(Record, Option<String>)> {
    let records: Vec<Record> = store
        .records()
        .into_iter()
        .filter(|r| r.batch() == Some(batch))
        .collect();
    let mut results = Vec::new();
    for record in records.into_iter().rev() {
        if !can_undo(&record) {
            continue;
        }
        match undo(record.id(), store) {
            Ok(done) => results.push((done, None)),
            Err(error) => results.push((record, Some(error.message().to_string()))),
        }
    }
    results
}

/// Wraps a plain handler into a [`RunFn`].
pub(crate) fn run_fn(f: fn(Params<'_>, &Store, &str) -> Result<Outcome>) -> RunFn {
    Arc::new(move |params: &Value, store: &Store, record_id: &str| f(Params::new(params), store, record_id))
}

/// Wraps a plain undo handler into an [`UndoFn`].
pub(crate) fn undo_fn(f: fn(Params<'_>, &Store) -> Result<String>) -> UndoFn {
    Arc::new(move |data: &Value, store: &Store| f(Params::new(data), store))
}

pub(crate) type Builtin = (&'static str, RunFn, Option<UndoFn>, bool);
