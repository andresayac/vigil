//! Runs a real, read-only scan of this computer and prints only counts and timings
//! (no names, paths or other data from the machine).
//!
//!     cargo run --release -p vigil-scan --example scan_bench [-- <inventory.json>]
//!
//! With a path, the raw inventory is also written there (it contains data about this computer:
//! keep it private and delete it when done).

use std::sync::atomic::AtomicBool;
use std::time::Instant;

fn main() {
    let started = Instant::now();
    let cancel = AtomicBool::new(false);
    let stages = std::cell::Cell::new(0usize);
    let progress = |_: &str| stages.set(stages.get() + 1);
    match vigil_scan::collect_and_analyze(30, None, &progress, &cancel) {
        Ok((raw, analysis)) => {
            if let Some(path) = std::env::args().nth(1)
                && let Err(error) = std::fs::write(&path, raw.to_string())
            {
                eprintln!("{path}: {error}");
            }
            println!(
                "total: {:.1} s ({} progress messages)",
                started.elapsed().as_secs_f64(),
                stages.get()
            );
            println!("collector timings (s): {}", raw["meta"]["timings"]);
            println!("administrator: {}", raw["meta"]["is_admin"]);
            println!(
                "paths filled from the kernel: {}",
                raw["meta"]["paths_filled_from_kernel"]
            );
            let stats = &analysis.stats;
            for key in [
                "processes",
                "services",
                "drivers",
                "tasks",
                "autoruns",
                "programs",
                "extensions",
                "files_verified",
            ] {
                println!("{key}: {}", stats.get(key).cloned().unwrap_or_default());
            }
            println!(
                "items: {} (trusted automatically: {}, to analyze: {})",
                analysis.items.len(),
                stats["auto_trusted"],
                stats["to_analyze"]
            );
            println!("by level: {}", stats["by_level"]);
            println!("coverage notes: {}", analysis.notes.len());
        }
        Err(error) => {
            eprintln!("scan failed after {:.1} s: {error}", started.elapsed().as_secs_f64());
            std::process::exit(1);
        }
    }
}
