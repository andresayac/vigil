//! Optional reputation lookup on VirusTotal.
//!
//! Only the SHA-256 hash of each file is sent, never the file itself or its path.
//! It needs the user's own (free) API key.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};

use crate::lenient::{Get, as_int, int_of, obj, rx, str_of, truthy};
use crate::model::{Flag, Item};

pub const API_BASE: &str = "https://www.virustotal.com/api/v3/files/";

rx!(SHA256_RE, r"^[0-9a-f]{64}$");

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VtError {
    /// The lookup quota of the key is exhausted.
    Quota(String),
    Failed(String),
}

impl fmt::Display for VtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Quota(message) | Self::Failed(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for VtError {}

/// Reputation of a hash. `known` is false when VirusTotal has never seen the file.
pub fn lookup(sha256: &str, api_key: &str, base: &str, timeout: Duration) -> Result<Map<String, Value>, VtError> {
    if !SHA256_RE.is_match(sha256) {
        return Err(VtError::Failed("invalid SHA-256 hash".into()));
    }
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .http_status_as_error(false)
        .user_agent("vigil-scan")
        .build()
        .into();
    let failed = |error: &dyn fmt::Display| VtError::Failed(format!("could not query VirusTotal: {error}"));
    let mut response = agent
        .get(format!("{base}{sha256}"))
        .header("x-apikey", api_key)
        .header("accept", "application/json")
        .call()
        .map_err(|e| failed(&e))?;
    match response.status().as_u16() {
        200..=299 => {}
        404 => {
            return Ok(json!({"known": false, "summary": "VirusTotal does not know this file"})
                .as_object()
                .cloned()
                .unwrap_or_default());
        }
        401 | 403 => return Err(VtError::Failed("the VirusTotal API key is not valid".into())),
        429 => return Err(VtError::Quota("the VirusTotal lookup quota is exhausted".into())),
        code => return Err(VtError::Failed(format!("VirusTotal answered HTTP {code}"))),
    }
    let data: Value = response.body_mut().read_json().map_err(|e| failed(&e))?;

    let attributes = obj(data.at("data").at("attributes"));
    let stats = obj(attributes.at("last_analysis_stats"));
    let malicious = int_of(stats.at("malicious"));
    let suspicious = int_of(stats.at("suspicious"));
    let engines: i64 = stats.values().filter_map(as_int).sum();
    let label = attributes
        .at("popular_threat_classification")
        .at("suggested_threat_label")
        .clone();
    let mut summary = format!("{malicious} of {engines} engines flag it as malicious");
    if suspicious != 0 {
        summary.push_str(&format!(" and {suspicious} as suspicious"));
    }
    if truthy(&label) {
        summary.push_str(&format!(" (classification: {})", str_of(&label)));
    }
    let result = json!({
        "known": true, "malicious": malicious, "suspicious": suspicious, "engines": engines,
        "label": label, "summary": summary,
    });
    Ok(result.as_object().cloned().unwrap_or_default())
}

/// Looks up the hashed files with the highest risk. Returns (files looked up, notice).
///
/// `delay` (seconds) separates the lookups: a free key allows 4 per minute.
pub fn enrich(
    items: &mut [Item],
    api_key: &str,
    limit: usize,
    delay: f64,
    base: &str,
    progress: &dyn Fn(&str),
) -> (usize, Option<String>) {
    enrich_with(items, api_key, limit, delay, base, progress, &AtomicBool::new(false))
}

pub(crate) fn enrich_with(
    items: &mut [Item],
    api_key: &str,
    limit: usize,
    delay: f64,
    base: &str,
    progress: &dyn Fn(&str),
    cancel: &AtomicBool,
) -> (usize, Option<String>) {
    let mut targets: Vec<usize> = (0..items.len())
        .filter(|&i| items[i].sha256.as_deref().is_some_and(|s| !s.is_empty()) && !items[i].trusted)
        .collect();
    targets.sort_by_key(|&i| -items[i].score);
    targets.truncate(limit);
    let total = targets.len();
    let mut done = 0;
    for (index, &i) in targets.iter().enumerate() {
        if index > 0 && !wait(delay, cancel) {
            return (done, None);
        }
        let item = &mut items[i];
        let vt = match lookup(
            item.sha256.as_deref().unwrap_or(""),
            api_key,
            base,
            Duration::from_secs(30),
        ) {
            Ok(vt) => vt,
            Err(error) => return (done, Some(error.to_string())),
        };
        done += 1;
        let summary = str_of(vt.at("summary"));
        let count = |key: &str| vt.get(key).map_or(0, int_of);
        if !truthy(vt.at("known")) {
            item.add_flag(Flag::new(
                "virustotal_unknown",
                10,
                "VirusTotal does not know this file (it is uncommon)",
            ));
        } else if count("malicious") >= 5 {
            item.add_flag(Flag::new("virustotal_malicious", 70, format!("VirusTotal: {summary}")));
        } else if count("malicious") != 0 || count("suspicious") != 0 {
            item.add_flag(Flag::new("virustotal_suspicious", 25, format!("VirusTotal: {summary}")));
        }
        item.vt = Some(vt);
        item.rescore();
        progress(&format!(
            "  VirusTotal {}/{total}: {} → {summary}",
            index + 1,
            item.title
        ));
    }
    (done, None)
}

/// Sleeps `seconds`, waking up early when the scan is cancelled (returns false then).
pub(crate) fn wait(seconds: f64, cancel: &AtomicBool) -> bool {
    let deadline = Instant::now()
        + Duration::from_secs_f64(if seconds.is_finite() {
            seconds.clamp(0.0, 86_400.0)
        } else {
            0.0
        });
    while Instant::now() < deadline {
        if cancel.load(Ordering::Relaxed) {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100).min(deadline.saturating_duration_since(Instant::now())));
    }
    !cancel.load(Ordering::Relaxed)
}
