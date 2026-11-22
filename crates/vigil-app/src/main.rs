//! Vigil for Windows: the window, the tray and the command lines in one executable.
//!
//! The window is drawn with gpui-kit and shares everything else with the command lines through
//! `vigil-core`: the state, the request checks, the native confirmation, the action engine and
//! the background watch. The window only displays data and asks.
//!
//! `vigil [--page KEY] [--pid PID] [--theme system|light|dark] [--lang CODE] [--tray] [--no-elevate] [--elevate]`
//! - `--pid`: the process the Processes page selects, as "Show in Processes" does;
//! - `--tray`: start hidden, watching from the tray (the start at sign-in); never asks for rights;
//! - `--no-elevate`: start in read-only mode without asking for administrator rights;
//! - `--elevate`: ask for them in a debug build too (release builds ask unless `--no-elevate`);
//! - `--demo` (with `--item ID`, `--size WxH`, `--dialog settings|scan|run` for previews):
//!   fictitious data; reads nothing, changes nothing, no tray, no watch.
//!
//! `vigil scan | list | ports | services | programs | reliability | mcp | --help` run in the
//! console without the window and without asking for rights; they only read.

// No console window in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// GPUI's derive macros name the crate `gpui`; the Kit stands in for it.
extern crate gpui_kit as gpui;

mod actions;
mod app;
mod data;
mod demo;
mod demo_pages;
mod dialogs;
mod format;
mod groups;
mod i18n;
mod icons;
mod live;
mod pages;
mod platform;
mod settings_ui;
mod shell;
mod theme;
mod ui;
mod win;

use std::sync::Arc;

use futures::StreamExt as _;
use futures::channel::mpsc::unbounded;
use gpui_kit::{
    AppContext, Bounds, TitlebarOptions, WindowBackgroundAppearance, WindowBounds, WindowOptions, px, size,
};
use vigil_core::watch::{self, Store, Watcher};

use crate::platform::{Command, Tray};

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let has = |flag: &str| args.iter().any(|a| a == flag);

    // `vigil scan ...`: the read-only scan in the console, without the window and without UAC.
    if args.first().map(String::as_str) == Some("scan") {
        std::process::exit(vigil_core::scan_cli(&args[1..]));
    }
    // `vigil mcp`: the read-only tools for AI clients over stdio (no window, no UAC).
    if args.first().map(String::as_str) == Some("mcp") {
        std::process::exit(vigil_core::mcp::cli(&args[1..]));
    }
    // `vigil list | ports | services | programs | reliability | --help`: read-only views for a
    // terminal or a script.
    if let Some(command) = args.first()
        && let Some(code) = vigil_core::tool_cli(command, &args[1..])
    {
        std::process::exit(code);
    }

    let demo = has("--demo");
    let tray_start = has("--tray") && !demo;

    // Vigil asks for administrator rights when it starts (UAC). If the user declines, it keeps
    // running in read-only mode. Debug builds only ask with --elevate, so `cargo run` stays simple.
    // `--tray` (the start at sign-in) never asks: a prompt nobody expects is not shown at sign-in.
    let ask = if cfg!(debug_assertions) {
        has("--elevate")
    } else {
        !has("--no-elevate") && !has("--tray")
    };
    if ask
        && !demo
        && !has("--elevated")
        && !vigil_sys::elevation::is_elevated()
        && let Ok(true) = vigil_sys::elevation::relaunch_elevated(&["--elevated"])
    {
        return; // the elevated copy takes over
    }

    let page = arg(&args, "--page")
        .and_then(|p| shell::PAGES.iter().map(|(key, _)| *key).find(|key| *key == p))
        .unwrap_or("overview");
    let focus_pid = arg(&args, "--pid").and_then(|pid| pid.parse::<u32>().ok());
    let focus_item = arg(&args, "--item").map(|s| s.to_string());
    let dialog = arg(&args, "--dialog").map(|s| s.to_string());

    // One native window per session: a second copy asks the first to show itself and quits.
    if !demo && !platform::claim_window() {
        return;
    }

    // The shared state (data folder, settings, the last report). The demo reads none of it.
    let core = if demo {
        None
    } else {
        match vigil_core::state::AppState::new() {
            Ok(state) => {
                // The actions that live outside the engine (cleanup, Vigil's own start at sign-in).
                vigil_core::storage_ops::register_all();
                vigil_core::autostart::register_all();
                Some(Arc::new(state))
            }
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

    // The background watch: its named mutex decides which copy of
    // Vigil watches and shows the tray icon. Started at sign-in while another copy watches:
    // nothing to do.
    let (commands, mut command_rx) = unbounded::<Command>();
    let watcher = core.as_ref().map(|core| {
        let owner = watch::claim_watch();
        let store = Store::in_profile().unwrap_or_else(|| Store::new(core.root.join("watch")));
        let watcher = Arc::new(Watcher::new(store, core.admin, owner));
        // A state saved before a language was ever chosen takes this copy's language.
        watcher.adopt_language(vigil_i18n::language());
        watcher
    });
    if tray_start && !watcher.as_ref().is_some_and(|w| w.owner()) {
        return;
    }
    if let Some(watcher) = &watcher {
        Tray::start(commands.clone(), Some(Arc::clone(watcher)), watcher.owner());
        watcher.start(Arc::new(platform::Host));
    }

    gpui_kit::application().run(move |cx| {
        gpui_kit::init(cx);
        pages::processes::bind_keys(cx);
        ui::grid::bind_keys(cx);
        let (width, height) = arg(&args, "--size")
            .and_then(|s| {
                s.split_once('x')
                    .map(|(w, h)| (w.parse::<f32>().ok(), h.parse::<f32>().ok()))
            })
            .and_then(|(w, h)| Some((w?.max(860.), h?.max(560.))))
            .unwrap_or((1280., 820.));
        let bounds = Bounds::centered(None, size(px(width), px(height)), cx);
        let options = WindowOptions {
            window_bounds: Some(WindowBounds::Windowed(bounds)),
            // The native title bar: snap layouts, caption buttons, the system menu and their
            // accessibility come from Windows; over Mica it blends with the window.
            titlebar: Some(TitlebarOptions {
                title: Some("Vigil".into()),
                appears_transparent: false,
                traffic_light_position: None,
            }),
            // Started at sign-in: hidden until opened from the tray.
            show: !tray_start,
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
            focus_item,
            dialog,
            demo,
            choice,
            mica,
            watcher: watcher.clone(),
        };
        let opened = gpui_kit::open_window(options, cx, |window, cx| {
            cx.new(|cx| shell::Shell::new(start, core.clone(), window, cx))
        });
        let (handle, shell) = match opened {
            Ok(opened) => opened,
            Err(error) => {
                eprintln!("Vigil could not open its window: {error}");
                cx.quit();
                return;
            }
        };
        if tray_start {
            shell.update(cx, |shell, cx| {
                shell.live.update(cx, |live, cx| live.set_visible(false, cx))
            });
        } else {
            let _ = handle.update(cx, |_, window, _| win::restore_if_minimized(window));
        }
        // The close button: to the tray when this copy watches and the settings say so.
        let closing = shell.clone();
        let _ = handle.update(cx, |_, window, cx| {
            window.on_window_should_close(cx, move |window, cx| {
                closing.update(cx, |shell, cx| shell.should_close(window, cx))
            });
        });
        // What the tray, a notification or a second copy asks, carried out on the UI thread.
        cx.spawn(async move |cx| {
            while let Some(command) = command_rx.next().await {
                let shell = shell.clone();
                let _ = handle.update(cx, |_, window, cx| {
                    shell.update(cx, |shell, cx| shell.command(command, window, cx));
                });
            }
        })
        .detach();
        cx.on_window_closed(|cx, _| {
            if cx.windows().is_empty() {
                platform::remove_icon();
                cx.quit();
            }
        })
        .detach();
    });
}
