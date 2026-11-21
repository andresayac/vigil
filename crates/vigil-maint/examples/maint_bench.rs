//! Speed of the space scan and of measuring the cleanup targets. Read-only; prints counts and
//! timings only (no paths).
//!
//! ```text
//! cargo run --release -p vigil-maint --example maint_bench -- scan <folder> [runs]
//! cargo run --release -p vigil-maint --example maint_bench -- measure [runs]
//! ```

use std::path::PathBuf;
use std::time::Instant;

use vigil_maint::storage::{self, NeverCancel, Node, no_progress};

fn count(node: &Node) -> usize {
    let mut total = 0;
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        total += 1;
        stack.extend(current.children.iter());
    }
    total
}

fn scan(folder: PathBuf, runs: usize) {
    for run in 1..=runs {
        let scan = storage::scan_space(&folder, &no_progress, &NeverCancel, 500, 300);
        let rate = scan.files as f64 / scan.seconds.max(1e-9);
        println!(
            "scan run {run}: {} files, {} folders, {} unreadable, {:.2} s, {:.0} files/s, {} nodes kept, merged below {} bytes",
            scan.files,
            scan.folders,
            scan.errors,
            scan.seconds,
            rate,
            count(&scan.root),
            scan.merged_below
        );
    }
}

fn measure(runs: usize) {
    for run in 1..=runs {
        let started = Instant::now();
        let mut targets = storage::cleanup_targets(None);
        let listed = started.elapsed().as_secs_f64();
        let mut timings = Vec::new();
        for target in targets.iter_mut() {
            let one = Instant::now();
            storage::measure(std::slice::from_mut(target), &no_progress, &NeverCancel);
            timings.push((target.key.clone(), target.files, one.elapsed().as_secs_f64()));
        }
        let files: u64 = timings.iter().map(|t| t.1).sum();
        println!(
            "measure run {run}: {} targets listed in {:.3} s, {files} files measured in {:.2} s",
            targets.len(),
            listed,
            started.elapsed().as_secs_f64() - listed
        );
        for (key, files, seconds) in timings {
            println!("  {key:<24} {files:>8} files {:>8.3} s", seconds);
        }
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_default();
    match mode.as_str() {
        "scan" => {
            let Some(folder) = args.next() else {
                eprintln!("usage: bench scan <folder> [runs]");
                std::process::exit(2);
            };
            let runs = args.next().and_then(|r| r.parse().ok()).unwrap_or(1);
            scan(PathBuf::from(folder), runs);
        }
        "measure" => measure(args.next().and_then(|r| r.parse().ok()).unwrap_or(1)),
        _ => {
            eprintln!("usage: bench scan <folder> [runs] | bench measure [runs]");
            std::process::exit(2);
        }
    }
}
