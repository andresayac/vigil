//! Evaluates a saved raw inventory without touching the system and writes the report JSON.
//!
//!     cargo run --release --example analyze_file -- <inventory.json> <report.json>

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (Some(input), Some(output)) = (args.first(), args.get(1)) else {
        eprintln!("usage: analyze_file <inventory.json> <report.json>");
        std::process::exit(2);
    };
    let text = match std::fs::read_to_string(input) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("{input}: {error}");
            std::process::exit(1);
        }
    };
    let raw: serde_json::Value = match serde_json::from_str(text.trim_start_matches('\u{feff}')) {
        Ok(raw) => raw,
        Err(error) => {
            eprintln!("{input}: {error}");
            std::process::exit(1);
        }
    };
    let analysis = vigil_scan::run_analysis(&raw, false);
    if let Err(error) = std::fs::write(output, vigil_scan::report::render_json(&analysis)) {
        eprintln!("{output}: {error}");
        std::process::exit(1);
    }
}
