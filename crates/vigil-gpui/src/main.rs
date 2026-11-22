//! Vigil with a native interface drawn by GPUI (gpui-kit): the migration prototype.
//!
//! It shares the Tauri app's core (`vigil-core`): the same state, the same request checks, the
//! same native confirmation and the same action engine. This window only displays data and asks.
//!
//! `vigil-gpui [--demo] [--page KEY] [--pid PID] [--theme system|light|dark] [--lang CODE]`
//! (`--pid`: the process the Processes page selects, as "Show in Processes" does)
//!
//! It never asks for administrator rights: it runs with the rights it was started with (a
//! standard user sees and changes less). `--demo` shows fictitious data and reads nothing.

// No console window in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod actions;
mod demo;
mod format;
mod groups;
mod i18n;
mod icons;
mod live;
mod pages;
mod shell;
mod theme;
mod win;

use std::sync::Arc;

use gpui_kit::{
    AppContext, Bounds, TitlebarOptions, WindowBackgroundAppearance, WindowBounds, WindowOptions, px, size,
};

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let demo = args.iter().any(|a| a == "--demo");
    let page = arg(&args, "--page")
        .and_then(|p| shell::PAGES.iter().map(|(key, _)| *key).find(|key| *key == p))
        .unwrap_or("processes");
    let focus_pid = arg(&args, "--pid").and_then(|pid| pid.parse::<u32>().ok());

    // The shared state (data folder, settings, the last report). The demo reads none of it.
    let core = if demo {
        None
    } else {
        match vigil_core::state::AppState::new() {
            Ok(state) => Some(Arc::new(state)),
            Err(error) => {
                vigil_core::confirm::tell(
                    windows::Win32::Foundation::HWND(std::ptr::null_mut()),
                    "Vigil could not prepare its data folder",
                    &error,
                );
                std::process::exit(1);
            }
        }
    };
    let stored_theme = core.as_ref().map(|c| c.lock().settings.theme.clone());
    let choice = theme::Choice::parse(&arg(&args, "--theme").or(stored_theme).unwrap_or_default());
    match arg(&args, "--lang") {
        Some(code) => {
            vigil_i18n::set_language(&code);
        }
        None if demo => {
            vigil_i18n::set_language("en");
        }
        // AppState::new already set the language from the settings.
        None => {}
    }
    let mica = win::has_mica();

    gpui_kit::application().run(move |cx| {
        gpui_kit::init(cx);
        pages::processes::bind_keys(cx);
        let bounds = Bounds::centered(None, size(px(1280.), px(820.)), cx);
        let options = WindowOptions {
            window_bounds: Some(WindowBounds::Windowed(bounds)),
            // The native title bar: snap layouts, caption buttons, the system menu and their
            // accessibility come from Windows; over Mica it blends with the window.
            titlebar: Some(TitlebarOptions {
                title: Some("Vigil".into()),
                appears_transparent: false,
                traffic_light_position: None,
            }),
            window_background: if mica {
                WindowBackgroundAppearance::MicaBackdrop
            } else {
                WindowBackgroundAppearance::Opaque
            },
            window_min_size: Some(size(px(860.), px(560.))),
            app_id: Some("Vigil".into()),
            ..Default::default()
        };
        let start = shell::Options {
            page,
            focus_pid,
            demo,
            choice,
            mica,
        };
        let opened = gpui_kit::open_window(options, cx, |window, cx| {
            cx.new(|cx| shell::Shell::new(start, core.clone(), window, cx))
        });
        if let Err(error) = opened {
            eprintln!("Vigil could not open its window: {error}");
            cx.quit();
            return;
        }
        cx.on_window_closed(|cx, _| {
            if cx.windows().is_empty() {
                cx.quit();
            }
        })
        .detach();
    });
}
