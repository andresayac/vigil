//! Report files: where a new scan is saved, how it is written and how it is opened again.

use std::fs;
use std::path::{Path, PathBuf};

use chrono::Local;
use serde_json::Value;

use crate::collect::read_text;
use crate::engine::sort_for_report;
use crate::error::ScanError;
use crate::lenient::{Get, list};
use crate::model::Analysis;
use crate::report;
use vigil_i18n::tr;

/// Base name for the files of a new scan: `<dir>\scan-YYYYMMDD-HHMMSS` (the folder is created).
pub fn scan_base(dir: &Path) -> PathBuf {
    let _ = fs::create_dir_all(dir);
    dir.join(format!("scan-{}", Local::now().format("%Y%m%d-%H%M%S")))
}

fn with_suffix(base: &Path, suffix: &str) -> PathBuf {
    let name = base
        .file_name()
        .map_or_else(|| "scan".to_string(), |n| n.to_string_lossy().into_owned());
    base.with_file_name(format!("{name}{suffix}"))
}

/// Writes `<base>-report.json` and, when `html` is set, `<base>-report.html` (items in report order).
pub fn save_report(analysis: &Analysis, base: &Path, html: bool) -> Result<(PathBuf, Option<PathBuf>), ScanError> {
    let mut sorted = analysis.clone();
    sort_for_report(&mut sorted);
    if let Some(parent) = base.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|e| ScanError::io(parent, e))?;
    }
    let json_path = with_suffix(base, "-report.json");
    fs::write(&json_path, report::render_json(&sorted)).map_err(|e| ScanError::io(&json_path, e))?;
    let html_path = if html {
        let path = with_suffix(base, "-report.html");
        fs::write(&path, report::render_html(&sorted)).map_err(|e| ScanError::io(&path, e))?;
        Some(path)
    } else {
        None
    };
    Ok((json_path, html_path))
}

/// Opens a saved `-report.json`.
pub fn load_report(path: &Path) -> Result<Analysis, ScanError> {
    let text = read_text(path).map_err(|e| ScanError::io(path, e))?;
    let data: Value = serde_json::from_str(&text)
        .map_err(|e| ScanError::InvalidReport(tr!("not a Vigil report (invalid JSON: {0})", e)))?;
    if !data.as_object().is_some_and(|m| m.contains_key("items")) {
        return Err(ScanError::InvalidReport(tr!("not a Vigil report")));
    }
    let known = ["remove", "disable", "review", "no_signals", "safe", "trusted", ""];
    if let Some(verdict) = list(data.at("items"))
        .iter()
        .filter_map(|item| item.at("verdict").as_str())
        .find(|v| !known.contains(v))
    {
        return Err(ScanError::InvalidReport(tr!(
            "not a Vigil report (unknown verdict \"{0}\")",
            verdict
        )));
    }
    Ok(Analysis::from_value(&data))
}
