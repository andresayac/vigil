//! The OpenAI Chat Completions standard: OpenAI itself and any compatible server (OpenRouter,
//! Google's OpenAI endpoint, DeepSeek, Groq, Ollama, LM Studio, vLLM, llama.cpp server...). Structured output is asked for with a strict JSON schema;
//! servers that do not support it get `json_object`, and then plain text with the schema in the prompt.

use std::time::Duration;

use serde_json::{Value, json};

use super::net;
use super::{AiError, Provider, failed, parse_json_text};
use crate::lenient::{Get, dumps_compact, int_of, list, text};

/// The standard's own address (OpenAI); `OPENAI_BASE_URL` or the settings choose another.
pub const DEFAULT_BASE: &str = "https://api.openai.com/v1";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Format {
    Schema,
    JsonObject,
    Plain,
}

fn body(provider: &Provider, system: &str, user: &str, schema: &Value, format: Format) -> Value {
    let user = match format {
        Format::Schema => user.to_string(),
        _ => format!(
            "{user}\n\nRespond only with a JSON object that conforms to this schema:\n{}",
            dumps_compact(schema)
        ),
    };
    let mut body = json!({
        "model": provider.model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    });
    if let Some(map) = body.as_object_mut() {
        match format {
            Format::Schema => {
                map.insert(
                    "response_format".into(),
                    json!({"type": "json_schema", "json_schema": {"name": "answer", "strict": true, "schema": schema}}),
                );
            }
            Format::JsonObject => {
                map.insert("response_format".into(), json!({"type": "json_object"}));
            }
            Format::Plain => {}
        }
    }
    body
}

/// True when a 400 answer complains about the structured-output request itself.
fn rejects_format(message: &str) -> bool {
    let lower = message.to_lowercase();
    [
        "response_format",
        "json_schema",
        "json schema",
        "structured",
        "json_object",
    ]
    .iter()
    .any(|k| lower.contains(k))
}

pub(super) fn complete(
    provider: &Provider,
    base: &str,
    key: Option<&str>,
    retries: u32,
    system: &str,
    user: &str,
    schema: &Value,
) -> Result<Value, AiError> {
    let agent = net::agent(Duration::from_secs(20), Duration::from_secs(1800));
    let url = format!("{base}/chat/completions");
    let what = provider.name.as_str();
    let mut format = Format::Schema;
    let mut attempt = 0;
    loop {
        let payload = dumps_compact(&body(provider, system, user, schema, format));
        let mut request = agent.post(&url).header("content-type", "application/json");
        if let Some(key) = key.filter(|k| !k.is_empty()) {
            request = request.header("authorization", format!("Bearer {key}"));
        }
        let mut response = match request.send(payload.as_str()) {
            Ok(response) => response,
            Err(_) if attempt < retries => {
                std::thread::sleep(net::backoff(attempt, None));
                attempt += 1;
                continue;
            }
            Err(_) => return Err(failed(format!("could not connect to {what} ({base})"))),
        };
        let status = response.status().as_u16();
        let answer = net::read_capped(&mut response, what)?;
        if (200..300).contains(&status) {
            return read_answer(provider, &answer);
        }
        if status == 400 && format != Format::Plain && rejects_format(&net::error_message(&answer)) {
            // The server does not take this structured-output request: ask more simply.
            format = if format == Format::Schema {
                Format::JsonObject
            } else {
                Format::Plain
            };
            continue;
        }
        if (status == 429 || status >= 500) && attempt < retries {
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<f64>().ok());
            std::thread::sleep(net::backoff(attempt, retry_after));
            attempt += 1;
            continue;
        }
        return Err(net::status_error(what, status, &provider.model, &answer));
    }
}

fn read_answer(provider: &Provider, body: &str) -> Result<Value, AiError> {
    let parsed: Value =
        serde_json::from_str(body).map_err(|e| failed(format!("{} returned invalid JSON: {e}", provider.name)))?;
    let usage = parsed.at("usage");
    provider.record_usage(
        int_of(usage.at("prompt_tokens")),
        int_of(usage.at("completion_tokens")),
        0.0,
    );
    let choice = list(parsed.at("choices")).first().cloned().unwrap_or(Value::Null);
    let message = choice.at("message");
    if let Some(refusal) = message.at("refusal").as_str().filter(|r| !r.trim().is_empty()) {
        return Err(AiError::Refusal(format!(
            "the model refused the analysis: {}",
            crate::privacy::clip(refusal, 200)
        )));
    }
    match choice.at("finish_reason").as_str() {
        Some("length") => return Err(AiError::Truncated("the response was cut off by the token limit".into())),
        Some("content_filter") => {
            return Err(AiError::Refusal(
                "the model refused the analysis because of its content filter".into(),
            ));
        }
        _ => {}
    }
    let content = text(message.at("content"));
    if content.trim().is_empty() {
        return Err(failed(format!("{} returned no text", provider.name)));
    }
    parse_json_text(&content)
}

/// The models a server offers (`GET /models`).
pub(super) fn models(base: &str, key: Option<&str>) -> Result<Vec<String>, String> {
    let agent = net::agent(Duration::from_secs(5), Duration::from_secs(20));
    let mut request = agent.get(format!("{base}/models"));
    if let Some(key) = key.filter(|k| !k.is_empty()) {
        request = request.header("authorization", format!("Bearer {key}"));
    }
    let mut response = request.call().map_err(|_| format!("could not connect to {base}"))?;
    let status = response.status().as_u16();
    let body = net::read_capped(&mut response, base).map_err(|e| e.to_string())?;
    if !(200..300).contains(&status) {
        return Err(net::status_error(base, status, "", &body).to_string());
    }
    let parsed: Value = serde_json::from_str(&body).map_err(|e| format!("invalid answer from {base}: {e}"))?;
    let mut names: Vec<String> = list(parsed.at("data"))
        .iter()
        .filter_map(|m| m.at("id").as_str().map(str::to_string))
        .filter(|id| super::valid_model(id))
        .collect();
    names.sort();
    names.dedup();
    Ok(names)
}

/// True when a server answers `GET /models` at `base` (short timeouts: used to show availability).
pub(super) fn reachable(base: &str, key: Option<&str>) -> bool {
    let agent = net::agent(Duration::from_millis(800), Duration::from_secs(3));
    let mut request = agent.get(format!("{base}/models"));
    if let Some(key) = key.filter(|k| !k.is_empty()) {
        request = request.header("authorization", format!("Bearer {key}"));
    }
    request.call().is_ok_and(|r| (200..300).contains(&r.status().as_u16()))
}
