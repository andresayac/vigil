//! What the report and maintenance pages read, as JSON with the same camelCase fields the core
//! serializes: from the core (blocking: call it off the UI thread) or, in the demo, from
//! fictitious data (`data/demo.json`: jdoe, PC-VICTIM, Contoso, documentation addresses).

use std::sync::{Arc, OnceLock};

use serde::Serialize;
use serde_json::{Value, json};
use vigil_core::state::AppState;

/// One thing a page reads.
#[derive(Debug, Clone)]
pub enum Src {
    Report,
    Ignored,
    Plans(String),
    Accounts(u32),
    Extensions,
    ExtensionIcons(Vec<String>),
    Firewall,
    Posture,
    Programs,
    ProgramSignatures(Vec<String>),
    Protection,
    Reliability(u32),
    Tasks,
    Connections,
    Startup,
    Tuning,
    Hardware(bool),
    Insights,
    Volumes,
    Settings,
    AiStatus,
    AiProviders,
    AiModels(String, String),
    Affinity(u32, i64),
    Icons(Vec<String>),
    Adapters,
}

fn demo_all() -> &'static Value {
    static DEMO: OnceLock<Value> = OnceLock::new();
    DEMO.get_or_init(|| serde_json::from_str(include_str!("../data/demo.json")).unwrap_or(Value::Null))
}

/// One part of the demo data.
pub fn demo(key: &str) -> Value {
    demo_all().get(key).cloned().unwrap_or(Value::Null)
}

fn to<T: Serialize>(value: T) -> Result<Value, String> {
    serde_json::to_value(value).map_err(|e| e.to_string())
}

/// Reads `src` (`core` missing: the demo).
pub fn fetch(core: Option<&Arc<AppState>>, src: Src) -> Result<Value, String> {
    let Some(st) = core else {
        return Ok(from_demo(src));
    };
    use vigil_core::api;
    match src {
        Src::Report => Ok(st.lock().analysis_json.clone().unwrap_or(Value::Null)),
        Src::Ignored => to(api::ignored_list(st)),
        Src::Plans(id) => Ok(Value::Array(api::plan_actions(st, &id))),
        Src::Accounts(days) => to(vigil_core::accounts::read(Some(days), &st.store.records())),
        Src::Extensions => to(vigil_core::extensions::list()),
        Src::ExtensionIcons(keys) => to(vigil_core::extensions::icons(keys)),
        Src::Firewall => to(vigil_core::firewall::view()?),
        Src::Posture => to(vigil_core::posture::read()),
        Src::Programs => to(vigil_core::programs::list()),
        Src::ProgramSignatures(paths) => to(vigil_core::programs::signatures(paths)),
        Src::Protection => to(vigil_core::protection::view()),
        Src::Reliability(days) => to(vigil_core::reliability::load(days)?),
        Src::Tasks => to(vigil_sys::tasks::list().map_err(|e| e.to_string())?),
        Src::Connections => to(vigil_sys::net::connections().map_err(|e| e.to_string())?),
        Src::Startup => to(vigil_sys::startup::list()),
        Src::Tuning => to(vigil_maint::tuning::tuning_state()),
        Src::Hardware(force) => to(st.hardware(force)?),
        Src::Insights => to(api::insights(st)?),
        Src::Volumes => to(api::volumes()),
        Src::Settings => to(api::settings_get(st)),
        Src::AiStatus => to(api::ai_status(st)),
        Src::AiProviders => to(api::ai_providers(st)),
        Src::AiModels(provider, endpoint) => to(api::ai_models(st, &provider, &endpoint)?),
        Src::Affinity(pid, created) => to(api::process_affinity(pid, created)?),
        Src::Icons(paths) => to(api::process_icons(paths)),
        Src::Adapters => to(vigil_sys::metrics::adapters()),
    }
}

fn from_demo(src: Src) -> Value {
    match src {
        Src::Report => demo("analysis"),
        Src::Ignored => json!([]),
        Src::Plans(id) => demo("plans").get(&id).cloned().unwrap_or(json!([])),
        Src::Accounts(_) => demo("accounts"),
        Src::Extensions => demo("extensions"),
        Src::Firewall => demo("firewall"),
        Src::Posture => demo("posture"),
        Src::Programs => demo("programs"),
        Src::Protection => demo("protection"),
        Src::Reliability(_) => demo("reliability"),
        Src::Tasks => demo("tasks"),
        Src::Connections => demo("connections"),
        Src::Startup => serde_json::to_value(crate::demo_pages::startup().0).unwrap_or(json!([])),
        Src::Tuning => demo("tuning"),
        Src::Hardware(_) => demo("hardware"),
        Src::Insights => demo("insights"),
        Src::Volumes => demo("volumes"),
        Src::Settings => demo("settings"),
        Src::AiStatus => demo("aiStatus"),
        Src::AiProviders => demo("aiProviders"),
        Src::AiModels(..) => demo("aiModels"),
        Src::Affinity(..) => demo("affinity"),
        Src::Adapters => demo("appInfo").get("adapters").cloned().unwrap_or(json!([])),
        Src::ExtensionIcons(_) | Src::ProgramSignatures(_) | Src::Icons(_) => json!({}),
    }
}
