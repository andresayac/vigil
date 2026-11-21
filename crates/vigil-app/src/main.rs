// No console window in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use vigil_sys::elevation;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let has = |flag: &str| args.iter().any(|a| a == flag);

    // `vigil scan ...`: the read-only scan in the console, without the window and without UAC.
    if args.first().map(String::as_str) == Some("scan") {
        std::process::exit(vigil_app::scan_cli(&args[1..]));
    }

    // Vigil asks for administrator rights when it starts (UAC). If the user declines, it keeps
    // running in read-only mode. Debug builds only ask with --elevate, so `cargo run` stays simple.
    let ask = if cfg!(debug_assertions) {
        has("--elevate")
    } else {
        !has("--no-elevate")
    };
    if ask
        && !has("--elevated")
        && !elevation::is_elevated()
        && let Ok(true) = elevation::relaunch_elevated(&["--elevated"])
    {
        return; // the elevated copy takes over
    }
    vigil_app::run();
}
