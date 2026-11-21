//! Ollama on this computer, seen through the OpenAI- or Anthropic-compatible API it serves.
//!
//! Ollama also offers cloud models (`gpt-oss:120b-cloud`, `kimi-k2:cloud`, or a model republished
//! under a user's name): the local server only relays them to ollama.com. When an API endpoint on this
//! computer turns out to be Ollama (`GET /api/version` answers), Vigil asks `/api/tags` which models
//! really run here. Cloud models are recognized by the `remote_host` / `remote_model` fields the server
//! reports, by a size of a mere manifest, or by a `cloud` tag; they are left out of the model list and
//! refused before anything is sent, because a local endpoint promises that the data stays here.

use std::time::Duration;

use serde_json::Value;

use super::net;
use crate::lenient::{Get, int_of, list};

/// A model name whose tag marks an Ollama cloud model (`name:cloud`, `name:120b-cloud`).
pub fn is_cloud_name(model: &str) -> bool {
    let tag = model.rsplit_once(':').map_or("", |(_, tag)| tag).to_ascii_lowercase();
    tag == "cloud" || tag.ends_with("-cloud")
}

/// An entry of `/api/tags` that runs in Ollama's cloud rather than on this computer.
fn is_cloud_entry(entry: &Value, name: &str) -> bool {
    let remote = ["remote_host", "remote_model"]
        .iter()
        .any(|key| entry.at(key).as_str().is_some_and(|v| !v.trim().is_empty()));
    // A cloud entry is only a small manifest (hundreds of bytes); real local weights take hundreds of MB.
    let tiny = entry.get("size").is_some_and(|size| int_of(size) < 50 * 1024 * 1024);
    remote || tiny || is_cloud_name(name)
}

/// `http://localhost:11434/v1` -> `http://localhost:11434`.
pub fn origin_of(endpoint: &str) -> String {
    let (scheme, rest) = endpoint.split_once("://").unwrap_or(("http", endpoint));
    let authority = rest.split('/').next().unwrap_or(rest);
    format!("{scheme}://{authority}")
}

/// True when the server behind a local endpoint is Ollama (short timeout, loopback only).
pub(super) fn is_ollama(endpoint: &str) -> bool {
    if !net::is_loopback_url(endpoint) {
        return false;
    }
    let agent = net::agent(Duration::from_millis(800), Duration::from_secs(2));
    let Ok(mut response) = agent.get(format!("{}/api/version", origin_of(endpoint))).call() else {
        return false;
    };
    if !(200..300).contains(&response.status().as_u16()) {
        return false;
    }
    // Ollama answers `{"version": "0.x.y"}`; another server that answers any path is not Ollama.
    let body = response
        .body_mut()
        .with_config()
        .limit(4096)
        .read_to_string()
        .unwrap_or_default();
    serde_json::from_str::<Value>(&body)
        .ok()
        .and_then(|v| v.get("version").and_then(Value::as_str).map(|v| !v.trim().is_empty()))
        .unwrap_or(false)
}

/// The models installed on this computer (`GET /api/tags`, cloud models left out), sorted.
pub(super) fn local_models(endpoint: &str) -> Result<Vec<String>, String> {
    let origin = origin_of(endpoint);
    let agent = net::agent(Duration::from_secs(3), Duration::from_secs(10));
    let mut response = agent
        .get(format!("{origin}/api/tags"))
        .call()
        .map_err(|_| vigil_i18n::tr!("could not connect to Ollama at {0}; is it running?", origin))?;
    let status = response.status().as_u16();
    let body = net::read_capped(&mut response, "Ollama").map_err(|e| e.to_string())?;
    if !(200..300).contains(&status) {
        return Err(net::status_error("Ollama", status, "", &body).to_string());
    }
    let parsed: Value =
        serde_json::from_str(&body).map_err(|e| vigil_i18n::tr!("invalid answer from Ollama: {0}", e))?;
    let mut names: Vec<String> = list(parsed.at("models"))
        .iter()
        .filter_map(|m| {
            let name = m.at("name").as_str().or_else(|| m.at("model").as_str())?;
            (!is_cloud_entry(m, name)).then(|| name.to_string())
        })
        .filter(|id| super::valid_model(id))
        .collect();
    names.sort();
    names.dedup();
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cloud_models_are_recognized() {
        assert!(is_cloud_name("kimi-k3:cloud"));
        assert!(is_cloud_name("gemma4:31b-cloud"));
        assert!(!is_cloud_name("qwen3:14b"));
        assert!(!is_cloud_name("cloudy-model:latest"));
        let relay = json!({"name": "someone/helper:latest", "size": 719, "remote_host": "https://ollama.com:443"});
        assert!(is_cloud_entry(&relay, "someone/helper:latest"));
        let small = json!({"name": "stub:latest", "size": 384});
        assert!(is_cloud_entry(&small, "stub:latest"));
        let real = json!({"name": "qwen3:14b", "size": 9_276_198_565_u64});
        assert!(!is_cloud_entry(&real, "qwen3:14b"));
    }

    #[test]
    fn origins_drop_the_api_path() {
        assert_eq!(origin_of("http://localhost:11434/v1"), "http://localhost:11434");
        assert_eq!(origin_of("http://127.0.0.1:11434"), "http://127.0.0.1:11434");
        assert_eq!(origin_of("http://[::1]:11434/v1/"), "http://[::1]:11434");
    }
}
