//! The Anthropic Messages API standard, streamed (server-sent events): Anthropic itself and any
//! server that speaks the same protocol. Structured output is asked for with `output_config`; a
//! server that rejects it gets the schema in the prompt instead.

use std::io::{BufRead, BufReader};
use std::time::Duration;

use serde_json::{Map, Value, json};

use super::net::{self, MAX_ANSWER_BYTES};
use super::{AiError, ApiAuth, Provider, failed, parse_json_text};
use crate::lenient::{Get, dumps_compact, int_of, obj, str_of, text};
use crate::privacy::clip;

pub const DEFAULT_MODEL: &str = "claude-opus-5-5";
pub const API_BASE: &str = "https://api.anthropic.com";
const API_VERSION: &str = "2026-10-21";
/// Models that accept the `fallbacks` parameter (automatic retry on another model when a
/// safety classifier rejects the request).
const FALLBACK_MODELS: &[&str] = &[
    "claude-opus-5-5",
    "claude-opus-5",
    "claude-sonnet-5-5",
    "claude-fable-5-2",
    "claude-fable-5-1",
];
const FALLBACK_BETA: &str = "server-side-fallback-2026-07-01";

fn body(provider: &Provider, system: &str, user: &str, schema: &Value, structured: bool, fallback: bool) -> Value {
    let user = if structured {
        user.to_string()
    } else {
        format!(
            "{user}\n\nRespond only with a JSON object that conforms to this schema:\n{}",
            dumps_compact(schema)
        )
    };
    let mut body = json!({
        "model": provider.model,
        "max_tokens": 64000,
        // The system prompt is identical in every batch: it is marked for caching.
        "system": [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
        "messages": [{"role": "user", "content": user}],
        "stream": true,
    });
    if let Some(map) = body.as_object_mut() {
        if structured {
            map.insert(
                "output_config".into(),
                json!({"effort": provider.effort, "format": {"type": "json_schema", "schema": schema}}),
            );
        }
        if fallback {
            // If a safety classifier rejects the request (the inventory talks about malware),
            // the API retries it by itself on the recommended fallback model.
            map.insert("fallbacks".into(), json!("default"));
        }
    }
    body
}

/// True when a 400 answer complains about the structured-output request itself.
fn rejects_format(message: &str) -> bool {
    let lower = message.to_lowercase();
    ["output_config", "json_schema", "effort", "format"]
        .iter()
        .any(|k| lower.contains(k))
}

pub(super) fn complete(
    provider: &Provider,
    base: &str,
    auth: &ApiAuth,
    retries: u32,
    system: &str,
    user: &str,
    schema: &Value,
) -> Result<Value, AiError> {
    // Server-side fallbacks exist only for Claude models, which only Anthropic serves.
    let fallback = FALLBACK_MODELS.contains(&provider.model.as_str());
    let agent = net::agent(Duration::from_secs(30), Duration::from_secs(1800));
    let url = format!("{base}/v1/messages");
    let mut structured = true;
    let mut payload = dumps_compact(&body(provider, system, user, schema, structured, fallback));
    let mut attempt = 0;
    loop {
        let mut request = agent
            .post(&url)
            .header("content-type", "application/json")
            .header("accept", "text/event-stream")
            .header("anthropic-version", API_VERSION);
        request = match auth {
            ApiAuth::Key(key) => request.header("x-api-key", key),
            ApiAuth::Bearer(token) => request.header("authorization", format!("Bearer {token}")),
            ApiAuth::None => request,
        };
        if fallback {
            request = request.header("anthropic-beta", FALLBACK_BETA);
        }
        let response = match request.send(payload.as_str()) {
            Ok(response) => response,
            Err(_) if attempt < retries => {
                std::thread::sleep(net::backoff(attempt, None));
                attempt += 1;
                continue;
            }
            Err(_) => return Err(failed(format!("could not connect to {base}"))),
        };
        let status = response.status().as_u16();
        if (200..300).contains(&status) {
            return read_stream(provider, response);
        }
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        let should_retry =
            header("x-should-retry").map_or(matches!(status, 408 | 409 | 429) || status >= 500, |v| v == "true");
        let retry_after = header("retry-after").and_then(|v| v.trim().parse::<f64>().ok());
        if should_retry && attempt < retries {
            std::thread::sleep(net::backoff(attempt, retry_after));
            attempt += 1;
            continue;
        }
        let mut response = response;
        let detail = response
            .body_mut()
            .with_config()
            .limit(1024 * 1024)
            .read_to_string()
            .unwrap_or_default();
        let message = net::error_message(&detail);
        if status == 400 && structured && rejects_format(&message) {
            // A compatible server that does not take `output_config`: ask with the schema in the prompt.
            structured = false;
            payload = dumps_compact(&body(provider, system, user, schema, structured, fallback));
            continue;
        }
        return Err(failed(match status {
            401 => "the API rejected the key (check it in Settings or ANTHROPIC_API_KEY)".to_string(),
            403 => format!("the key does not have permission for this model: {message}"),
            404 => format!("model not found: {}", provider.model),
            429 => "rate limit reached; try again in a few minutes".to_string(),
            400 => format!("request rejected by the API: {message}"),
            301..=308 => "the API answered with a redirect, which is not followed".to_string(),
            _ => format!("API error {status}: {message}"),
        }));
    }
}

/// Reads the server-sent events of a streamed message and returns the JSON answer.
fn read_stream(provider: &Provider, mut response: ureq::http::Response<ureq::Body>) -> Result<Value, AiError> {
    let reader = response.body_mut().with_config().limit(MAX_ANSWER_BYTES).reader();
    let mut lines = BufReader::new(reader);
    let mut usage = Map::new();
    // (index, type, text) of each content block, in arrival order.
    let mut blocks: Vec<(i64, String, String)> = Vec::new();
    let mut stop_reason = Value::Null;
    let mut stop_details = Value::Null;
    let mut data = String::new();
    let mut line = String::new();
    loop {
        line.clear();
        let read = lines
            .read_line(&mut line)
            .map_err(|_| failed("the connection to the Anthropic API was interrupted"))?;
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if read == 0 || trimmed.is_empty() {
            if !data.is_empty() {
                let event: Value =
                    serde_json::from_str(&data).map_err(|e| failed(format!("the API returned invalid JSON: {e}")))?;
                data.clear();
                match event.at("type").as_str().unwrap_or("") {
                    "message_start" => {
                        usage = obj(event.at("message").at("usage")).clone();
                    }
                    "content_block_start" => {
                        let block = event.at("content_block");
                        blocks.push((
                            int_of(event.at("index")),
                            text(block.at("type")),
                            text(block.at("text")),
                        ));
                    }
                    "content_block_delta" => {
                        let delta = event.at("delta");
                        let index = int_of(event.at("index"));
                        if delta.at("type").as_str() == Some("text_delta")
                            && let Some((_, kind, text_so_far)) = blocks.iter_mut().rev().find(|(i, ..)| *i == index)
                            && kind == "text"
                        {
                            text_so_far.push_str(&text(delta.at("text")));
                        }
                    }
                    "message_delta" => {
                        let delta = event.at("delta");
                        if !delta.at("stop_reason").is_null() {
                            stop_reason = delta.at("stop_reason").clone();
                        }
                        if !delta.at("stop_details").is_null() {
                            stop_details = delta.at("stop_details").clone();
                        }
                        for (k, v) in obj(event.at("usage")) {
                            if !v.is_null() {
                                usage.insert(k.clone(), v.clone());
                            }
                        }
                    }
                    "error" => {
                        let message = text(event.at("error").at("message"));
                        return Err(failed(format!("API error: {}", clip(&message, 300))));
                    }
                    _ => {}
                }
            }
            if read == 0 {
                break;
            }
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(rest.strip_prefix(' ').unwrap_or(rest));
        }
    }

    let tokens = |key: &str| int_of(usage.at(key));
    provider.record_usage(
        tokens("input_tokens") + tokens("cache_read_input_tokens") + tokens("cache_creation_input_tokens"),
        tokens("output_tokens"),
        0.0,
    );
    match stop_reason.as_str() {
        Some("refusal") => {
            return Err(AiError::Refusal(format!(
                "the model refused the analysis (category: {})",
                str_of(stop_details.at("category"))
            )));
        }
        Some("max_tokens") => return Err(AiError::Truncated("the response was cut off by the token limit".into())),
        _ => {}
    }
    // After a server-side fallback the answer is what follows the last `fallback` block.
    let start = blocks
        .iter()
        .rposition(|(_, kind, _)| kind == "fallback")
        .map_or(0, |i| i + 1);
    let answer = blocks[start..]
        .iter()
        .find(|(_, kind, _)| kind == "text")
        .map(|(.., t)| t.as_str())
        .unwrap_or("");
    if answer.is_empty() {
        return Err(failed("the API returned no text"));
    }
    match serde_json::from_str::<Value>(answer) {
        Ok(value) => Ok(value),
        // Without structured output the JSON may come wrapped in a code fence or a sentence.
        Err(_) => parse_json_text(answer),
    }
}

/// The models a server lists (`GET /v1/models`); an error when it does not offer the list.
pub(super) fn models(base: &str, auth: &ApiAuth) -> Result<Vec<String>, String> {
    let agent = net::agent(Duration::from_secs(5), Duration::from_secs(20));
    let mut request = agent
        .get(format!("{base}/v1/models?limit=100"))
        .header("anthropic-version", API_VERSION);
    request = match auth {
        ApiAuth::Key(key) => request.header("x-api-key", key),
        ApiAuth::Bearer(token) => request.header("authorization", format!("Bearer {token}")),
        ApiAuth::None => request,
    };
    let mut response = request.call().map_err(|_| format!("could not connect to {base}"))?;
    let status = response.status().as_u16();
    let body = net::read_capped(&mut response, base).map_err(|e| e.to_string())?;
    if !(200..300).contains(&status) {
        return Err(net::status_error(base, status, "", &body).to_string());
    }
    let parsed: Value = serde_json::from_str(&body).map_err(|e| format!("invalid answer from {base}: {e}"))?;
    let mut names: Vec<String> = crate::lenient::list(parsed.at("data"))
        .iter()
        .filter_map(|m| m.at("id").as_str().map(str::to_string))
        .filter(|id| super::valid_model(id))
        .collect();
    names.sort();
    names.dedup();
    Ok(names)
}
