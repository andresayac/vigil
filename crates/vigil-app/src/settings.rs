//! Settings and ignored findings, stored in the data folder (`settings.json`, `ignored.json`).
//! API keys are not settings: they live in the Windows Credential Manager (see `secrets.rs`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use vigil_i18n::tr;
use vigil_scan::ai::{self, AiConfig};

pub const THEMES: [&str; 3] = ["system", "light", "dark"];
pub const LANGUAGES: [&str; 6] = ["auto", "en", "es", "fr", "pt", "zh"];

/// How the AI review is done (the same shape on disk and in the UI).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct AiSettings {
    /// A provider id from [`ai::PROVIDERS`].
    pub provider: String,
    /// Empty: the provider's default model.
    pub model: String,
    /// Empty: the provider's default endpoint (only providers that need one use it).
    pub endpoint: String,
    pub effort: String,
    /// Replace the user and computer names before anything is sent.
    pub redact: bool,
}

impl Default for AiSettings {
    fn default() -> Self {
        Self {
            provider: "auto".into(),
            model: String::new(),
            endpoint: String::new(),
            effort: ai::DEFAULT_EFFORT.into(),
            redact: true,
        }
    }
}

impl AiSettings {
    pub fn config(&self) -> AiConfig {
        AiConfig {
            provider: self.provider.clone(),
            model: self.model.clone(),
            endpoint: self.endpoint.clone(),
            effort: self.effort.clone(),
        }
    }
}

/// `settings.json` (snake_case keys).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Stored {
    pub theme: String,
    /// "auto" (the Windows display language), "en", "es", "fr", "pt" or "zh".
    pub language: String,
    pub ai: AiSettings,
    pub days: u32,
    pub virustotal: bool,
    pub restore_point: bool,
    pub auto_refresh: bool,
}

impl Default for Stored {
    fn default() -> Self {
        Self {
            theme: "system".into(),
            language: "auto".into(),
            ai: AiSettings::default(),
            days: 30,
            virustotal: false,
            restore_point: true,
            auto_refresh: true,
        }
    }
}

/// What the UI sees and sends (camelCase). `secrets` says which API keys are stored, never their values.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct View {
    pub theme: String,
    pub language: String,
    pub ai: AiSettings,
    pub days: u32,
    pub virustotal: bool,
    pub restore_point: bool,
    pub auto_refresh: bool,
    #[serde(default)]
    pub secrets: HashMap<String, bool>,
}

fn pick(value: &str, allowed: &[&str], fallback: &str) -> String {
    if allowed.contains(&value) {
        value.to_string()
    } else {
        fallback.to_string()
    }
}

impl Stored {
    pub fn load(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|text| serde_json::from_str::<Stored>(&text).ok())
            .map(Stored::sanitized)
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let text = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(path, text).map_err(|e| tr!("Settings could not be saved to {0} ({1}).", path.display(), e))
    }

    /// Replaces anything invalid with its default (a hand-edited or damaged file never breaks the app).
    fn sanitized(mut self) -> Self {
        self.theme = pick(&self.theme, &THEMES, "system");
        self.language = pick(&self.language, &LANGUAGES, "auto");
        if ai::provider_info(&self.ai.provider).is_none() {
            self.ai.provider = "auto".into();
        }
        self.ai.model = self.ai.model.trim().to_string();
        if !self.ai.model.is_empty() && !ai::valid_model(&self.ai.model) {
            self.ai.model.clear();
        }
        self.ai.endpoint = match self.ai.endpoint.trim() {
            "" => String::new(),
            endpoint => ai::check_endpoint(endpoint).unwrap_or_default(),
        };
        self.ai.effort = pick(&self.ai.effort, &ai::EFFORTS, ai::DEFAULT_EFFORT);
        self.days = self.days.clamp(1, 365);
        self
    }

    pub fn view(&self, secrets: HashMap<String, bool>) -> View {
        View {
            theme: self.theme.clone(),
            language: self.language.clone(),
            ai: self.ai.clone(),
            days: self.days,
            virustotal: self.virustotal,
            restore_point: self.restore_point,
            auto_refresh: self.auto_refresh,
            secrets,
        }
    }

    /// Applies what the UI sent. A model name or endpoint that is not valid is refused with a
    /// message (the user typed it); every other field falls back to its default.
    pub fn apply(&mut self, view: &View) -> Result<(), String> {
        let model = view.ai.model.trim();
        if !model.is_empty() && !ai::valid_model(model) {
            return Err(tr!(
                "The model name \"{0}\" is not valid.",
                model.chars().take(60).collect::<String>()
            ));
        }
        let endpoint = view.ai.endpoint.trim();
        if !endpoint.is_empty() {
            ai::check_endpoint(endpoint).map_err(|problem| tr!("The endpoint is not accepted: {0}", problem))?;
        }
        let next = Stored {
            theme: view.theme.clone(),
            language: view.language.clone(),
            ai: view.ai.clone(),
            days: view.days,
            virustotal: view.virustotal,
            restore_point: view.restore_point,
            auto_refresh: view.auto_refresh,
        };
        *self = next.sanitized();
        Ok(())
    }
}

/// `ignored.json`: `kind|path-or-title` (lower case) -> `{title, kind}`.
#[derive(Debug, Default)]
pub struct Ignored {
    path: PathBuf,
    entries: Map<String, Value>,
}

pub fn item_key(kind: &str, path: Option<&str>, title: &str) -> String {
    let base = path.filter(|p| !p.is_empty()).unwrap_or(title);
    format!("{kind}|{}", base.to_lowercase())
}

impl Ignored {
    pub fn load(path: PathBuf) -> Self {
        let entries = std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_json::from_str::<Value>(&text).ok())
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default();
        Self { path, entries }
    }

    pub fn contains(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }

    pub fn set(&mut self, key: String, title: &str, kind: &str, ignored: bool) -> Result<(), String> {
        if ignored {
            self.entries.insert(key, json!({"title": title, "kind": kind}));
        } else {
            self.entries.remove(&key);
        }
        let text = serde_json::to_string_pretty(&Value::Object(self.entries.clone())).map_err(|e| e.to_string())?;
        std::fs::write(&self.path, text).map_err(|e| format!("Could not save {} ({e}).", self.path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vigil-app-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).ok();
        dir
    }

    #[test]
    fn saved_settings_round_trip_with_snake_case_keys() {
        let dir = temp_dir("settings");
        let path = dir.join("settings.json");
        let saved = r#"{"theme": "dark", "language": "es", "ai": {"provider": "openai-compatible", "model": "qwen3:14b",
                        "endpoint": "http://localhost:11434/v1", "effort": "xhigh", "redact": false},
                        "days": 14, "virustotal": true, "restore_point": false, "auto_refresh": false, "unknown": 1}"#;
        std::fs::write(&path, saved).ok();
        let stored = Stored::load(&path);
        assert_eq!((stored.theme.as_str(), stored.language.as_str()), ("dark", "es"));
        assert_eq!(stored.ai.provider, "openai-compatible");
        assert_eq!(stored.ai.endpoint, "http://localhost:11434/v1");
        assert_eq!(stored.days, 14);
        stored.save(&path).ok();
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        for key in ["\"restore_point\"", "\"auto_refresh\"", "\"provider\"", "\"endpoint\""] {
            assert!(text.contains(key), "{key} missing");
        }
        assert!(!text.contains("key"), "no secret in settings.json");
        let view =
            serde_json::to_value(stored.view(HashMap::from([("openai-compatible".into(), true)]))).unwrap_or_default();
        assert_eq!(view["restorePoint"], false);
        assert_eq!(view["ai"]["provider"], "openai-compatible");
        assert_eq!(view["secrets"]["openai-compatible"], true);
        // Provider ids that are not offered any more fall back to "auto".
        std::fs::write(&path, r#"{"ai": {"provider": "ollama"}}"#).ok();
        assert_eq!(Stored::load(&path).ai.provider, "auto");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn damaged_values_fall_back() {
        let dir = temp_dir("damaged");
        let path = dir.join("settings.json");
        std::fs::write(
            &path,
            r#"{"theme": "neon", "language": "xx", "ai": {"provider": "skynet", "model": "a b", "endpoint": "http://203.0.113.9", "effort": "huge"}, "days": 9999}"#,
        )
        .ok();
        let stored = Stored::load(&path);
        assert_eq!((stored.theme.as_str(), stored.language.as_str()), ("system", "auto"));
        assert_eq!(
            stored.ai,
            AiSettings {
                redact: true,
                ..AiSettings::default()
            }
        );
        assert_eq!(stored.days, 365);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn typed_model_and_endpoint_are_checked() {
        let mut stored = Stored::default();
        let mut view = stored.view(HashMap::new());
        view.ai.provider = "openai-compatible".into();
        view.ai.model = "x; rm -rf".into();
        assert!(stored.apply(&view).expect_err("model").contains("not valid"));
        view.ai.model = "local-model".into();
        view.ai.endpoint = "http://203.0.113.5:1234/v1".into();
        assert!(stored.apply(&view).expect_err("endpoint").contains("https"));
        view.ai.endpoint = "http://localhost:1234/v1/".into();
        view.language = "zh".into();
        assert!(stored.apply(&view).is_ok());
        assert_eq!(stored.ai.endpoint, "http://localhost:1234/v1");
        assert_eq!(stored.language, "zh");
    }

    #[test]
    fn ignored_round_trip() {
        let dir = temp_dir("ignored");
        let path = dir.join("ignored.json");
        let key = item_key("executable", Some(r"C:\Users\jdoe\AppData\Tool.exe"), "Tool");
        assert_eq!(key, r"executable|c:\users\jdoe\appdata\tool.exe");
        let mut ignored = Ignored::load(path.clone());
        ignored.set(key.clone(), "Tool", "executable", true).ok();
        assert!(Ignored::load(path.clone()).contains(&key));
        ignored.set(key.clone(), "Tool", "executable", false).ok();
        assert!(!Ignored::load(path).contains(&key));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
