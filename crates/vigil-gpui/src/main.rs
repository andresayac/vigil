//! Vigil with a native interface drawn by GPUI (gpui-kit).
//!
//! It shares the Tauri app's core (`vigil-core`): the same state, the same request checks, the
//! same native confirmation, the same action engine and the same background watch. This window
//! only displays data and asks.
//!
//! `vigil-gpui [--demo] [--page KEY] [--pid PID] [--item ID] [--size WxH] [--theme system|light|dark] [--lang CODE] [--tray]`
//! - `--pid`: the process the Processes page selects, as "Show in Processes" does;
//! - `--tray`: start hidden, watching from the tray (the start at sign-in);
//! - `--demo`: fictitious data; reads nothing, changes nothing, no tray, no watch.
//!
//! It never asks for administrator rights by itself: "Restart as administrator" in the navigation
//! pane does, when the user picks it.

// No console window in release builds.
#![allow(dead_code)] // TEMPORARY: the pages still being written use the new shared pieces.
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
    let demo = has("--demo");
    let tray_start = has("--tray") && !demo;
    let page = arg(&args, "--page")
        .and_then(|p| shell::PAGES.iter().map(|(key, _)| *key).find(|key| *key == p))
        .unwrap_or("processes");
    let focus_pid = arg(&args, "--pid").and_then(|pid| pid.parse::<u32>().ok());
    let focus_item = arg(&args, "--item").map(|s| s.to_string());

    // One native window per session: a second copy asks the first to show itself and quits.
    if !demo && !platform::claim_window() {
        return;
    }

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

    // The background watch, shared with the Tauri app: its named mutex decides which copy of
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
