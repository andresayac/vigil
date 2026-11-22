//! HTTP plumbing shared by the AI providers: endpoint rules, one agent configuration, size caps.
//!
//! Rules: a provider endpoint is `https://`, except a model served on this computer
//! (`http://localhost`, `http://127.0.0.1`, `http://[::1]`). Redirects are never followed (a server
//! cannot bounce the inventory to another host), and every answer is read with a size cap.

use std::time::Duration;

use serde_json::Value;

use super::{AiError, failed};
use crate::lenient::{Get, strip};
use crate::privacy::clip;

/// Largest answer read from a provider (a classification of 45 items is well under 1 MB).
pub(crate) const MAX_ANSWER_BYTES: u64 = 16 * 1024 * 1024;

/// The host of an `http(s)://host[:port]/...` URL, lower case, brackets kept for IPv6.
fn host_of(rest: &str) -> &str {
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.starts_with('[') {
        return authority.split_inclusive(']').next().unwrap_or(authority);
    }
    authority.split(':').next().unwrap_or(authority)
}

/// True for the loopback hosts a local model server listens on.
pub fn is_loopback_url(url: &str) -> bool {
    let lower = url.trim().to_ascii_lowercase();
    let rest = lower
        .strip_prefix("http://")
        .or_else(|| lower.strip_prefix("https://"))
        .unwrap_or("");
    matches!(host_of(rest), "localhost" | "127.0.0.1" | "[::1]")
}

/// For a loopback endpoint: its port (the scheme's default when none is given) and whether a
/// connection to it goes over IPv4 and/or IPv6 (`localhost` may use either).
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn loopback_target(url: &str) -> Option<(u16, bool, bool)> {
    let lower = url.trim().to_ascii_lowercase();
    let (default_port, rest) = match lower.strip_prefix("http://") {
        Some(rest) => (80, rest),
        None => (443, lower.strip_prefix("https://")?),
    };
    let host = host_of(rest);
    let (v4, v6) = match host {
        "localhost" => (true, true),
        "127.0.0.1" => (true, false),
        "[::1]" => (false, true),
        _ => return None,
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let port = match authority.strip_prefix(host).and_then(|p| p.strip_prefix(':')) {
        Some(port) => port.parse().ok()?,
        None => default_port,
    };
    Some((port, v4, v6))
}

/// Checks a provider endpoint and returns it without a trailing slash.
///
/// `https://` anywhere; `http://` only on this computer. No credentials in the URL, no spaces,
/// no fragments or queries (the provider adds its own path).
pub fn check_endpoint(url: &str) -> Result<String, String> {
    let url = url.trim().trim_end_matches('/');
    if url.is_empty() {
        return Err("the endpoint is empty".into());
    }
    if url.len() > 300 || url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("the endpoint is not a valid URL".into());
    }
    let lower = url.to_ascii_lowercase();
    let (secure, rest) = if let Some(rest) = lower.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = lower.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err("the endpoint must start with https:// (or http:// for a server on this computer)".into());
    };
    let authority = rest.split('/').next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') || rest.contains(['?', '#']) {
        return Err("the endpoint is not a valid URL".into());
    }
    let host = host_of(rest);
    if host.is_empty() || !host.chars().all(|c| c.is_ascii_alphanumeric() || "-.[]:".contains(c)) {
        return Err("the endpoint is not a valid URL".into());
    }
    if let Some(port) = authority.strip_prefix(host).and_then(|p| p.strip_prefix(':'))
        && port.parse::<u16>().is_err()
    {
        return Err("the endpoint is not a valid URL".into());
    }
    if !secure && !is_loopback_url(url) {
        return Err("plain http:// is only allowed for a server on this computer; use https://".into());
    }
    Ok(url.to_string())
}

/// One HTTP agent for every provider: no redirects, status codes as values, the given timeouts.
pub(crate) fn agent(connect: Duration, answer: Duration) -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_connect(Some(connect))
        .timeout_recv_response(Some(answer))
        .timeout_recv_body(Some(answer))
        .user_agent("vigil")
        .build()
        .into()
}

/// Reads a whole answer, refusing more than [`MAX_ANSWER_BYTES`].
pub(crate) fn read_capped(response: &mut ureq::http::Response<ureq::Body>, what: &str) -> Result<String, AiError> {
    response
        .body_mut()
        .with_config()
        .limit(MAX_ANSWER_BYTES)
        .read_to_string()
        .map_err(|e| {
            failed(format!(
                "could not read the answer of {what}: {}",
                clip(&e.to_string(), 200)
            ))
        })
}

/// The message an API puts in an error body (`{"error": {"message": ...}}` and similar shapes).
pub(crate) fn error_message(body: &str) -> String {
    let parsed: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    let candidates = [
        parsed.at("error").at("message"),
        parsed.at("error"),
        parsed.at("message"),
        parsed.at("detail"),
    ];
    let message = candidates
        .iter()
        .find_map(|v| v.as_str().filter(|s| !s.trim().is_empty()))
        .map_or_else(|| strip(body).to_string(), str::to_string);
    clip(&message, 300)
}

/// The usual meaning of an HTTP error status, for the user.
pub(crate) fn status_error(provider: &str, status: u16, model: &str, body: &str) -> AiError {
    let message = error_message(body);
    failed(match status {
        401 => format!("{provider} rejected the API key; check it in Settings"),
        403 => format!("{provider} refused the request: {message}"),
        404 => format!("{provider}: model or endpoint not found ({model})"),
        429 => format!("{provider}: rate limit or quota reached; try again later"),
        400 | 422 => format!("{provider} rejected the request: {message}"),
        301..=308 => format!("{provider} answered with a redirect, which is not followed"),
        _ => format!("{provider} error {status}: {message}"),
    })
}

/// Waits before a retry: `retry-after` when the server gives a sane one, else exponential.
pub(crate) fn backoff(attempt: u32, retry_after: Option<f64>) -> Duration {
    match retry_after {
        Some(seconds) if (0.0..=60.0).contains(&seconds) => Duration::from_secs_f64(seconds),
        _ => Duration::from_secs_f64((0.5 * f64::from(2u32.saturating_pow(attempt))).min(8.0)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_must_be_https_unless_local() {
        assert_eq!(
            check_endpoint("https://api.example.com/v1/").as_deref(),
            Ok("https://api.example.com/v1")
        );
        assert_eq!(
            check_endpoint("http://localhost:11434").as_deref(),
            Ok("http://localhost:11434")
        );
        assert_eq!(
            check_endpoint("http://127.0.0.1:1234/v1").as_deref(),
            Ok("http://127.0.0.1:1234/v1")
        );
        assert_eq!(check_endpoint("http://[::1]:8080").as_deref(), Ok("http://[::1]:8080"));
        for bad in [
            "http://203.0.113.5:11434",
            "http://localhost.example.com",
            "ftp://localhost",
            "https://user:pw@api.example.com",
            "https://api.example.com/v1?x=1",
            "https://api.example.com:99999",
            "https://exa mple.com",
            "",
            "localhost:11434",
        ] {
            assert!(check_endpoint(bad).is_err(), "{bad}");
        }
        assert!(is_loopback_url("http://LOCALHOST:11434/api"));
        assert!(!is_loopback_url("https://ollama.example.com"));
    }

    #[test]
    fn error_bodies_are_summarized() {
        assert_eq!(error_message(r#"{"error": {"message": "bad model"}}"#), "bad model");
        assert_eq!(error_message(r#"{"error": "model not found"}"#), "model not found");
        assert_eq!(error_message("plain text"), "plain text");
    }
}
