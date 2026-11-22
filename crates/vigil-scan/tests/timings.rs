//! Phase timings of a real, read-only scan of this computer, without and with a warm signature
//! cache (kept in a temporary folder). Prints durations and counts only, never data.
//!
//!     cargo test -p vigil-scan --test timings -- --ignored --nocapture

use std::sync::atomic::AtomicBool;
use std::time::Instant;

fn scan(label: &str, cache: Option<&std::path::Path>) {
    let cancel = AtomicBool::new(false);
    // Only the signature step's line is shown: it holds a count, no data.
    let progress = |line: &str| {
        if line.contains("digital signature") {
            println!("  {}", line.trim());
        }
    };
    let started = Instant::now();
    let (_raw, analysis) = vigil_scan::collect_and_analyze_cached(30, None, cache, &progress, &cancel).expect("scan");
    let total = started.elapsed().as_secs_f64();
    let render = Instant::now();
    let json = vigil_scan::report::render_json(&analysis);
    let html = vigil_scan::report::render_html(&analysis);
    let render = render.elapsed().as_secs_f64();
    let mut timings: Vec<(String, f64)> = analysis
        .meta
        .get("timings")
        .and_then(|t| t.as_object())
        .map(|t| t.iter().map(|(k, v)| (k.clone(), v.as_f64().unwrap_or(0.0))).collect())
        .unwrap_or_default();
    timings.sort_by(|a, b| b.1.total_cmp(&a.1));
    println!("--- {label}");
    for (name, seconds) in timings {
        println!("{name:<24} {seconds:>6.1} s");
    }
    let verified = analysis
        .stats
        .get("files_verified")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    println!(
        "{:<24} {render:>6.1} s ({} + {} bytes)",
        "report_render",
        json.len(),
        html.len()
    );
    println!(
        "{:<24} {total:>6.1} s ({} items, {verified} files)",
        "total",
        analysis.items.len()
    );
}

#[test]
#[ignore = "scans this computer (read-only); run by hand"]
fn scan_phase_timings() {
    let dir = std::env::temp_dir().join(format!("vigil-timings-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    let cache = dir.join("signature-cache.json");
    scan("cold (no cache)", Some(&cache));
    scan("warm (cache filled)", Some(&cache));
    let _ = std::fs::remove_dir_all(&dir);
}
