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
    // `vigil mcp`: the read-only tools for AI clients over stdio (no window, no UAC).
    if args.first().map(String::as_str) == Some("mcp") {
        std::process::exit(vigil_app::mcp_cli(&args[1..]));
    }
    // `vigil list | ports | services | --help`: read-only views for a terminal or a script.
    if let Some(command) = args.first()
        && let Some(code) = vigil_app::tool_cli(command, &args[1..])
    {
        std::process::exit(code);
    }

    // Vigil asks for administrator rights when it starts (UAC). If the user declines, it keeps
    // running in read-only mode. Debug builds only ask with --elevate, so `cargo run` stays simple.
    // `--tray` (the start at sign-in) never asks: a prompt nobody expects is not shown at sign-in.
    let ask = if cfg!(debug_assertions) {
        has("--elevate")
    } else {
        !has("--no-elevate") && !has("--tray")
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
