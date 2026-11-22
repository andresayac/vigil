//! The tray icon: Vigil keeps watching after its window is closed.
//!
//! Menu: Open Vigil, Pause / Resume watching, Pause / Resume notifications, New scan, Quit. A left
//! click opens the window. Only the copy that owns the watch (see `watch::claim_watch`) has an
//! icon; another copy simply quits when its window closes.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::Serialize;
use tauri::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, Wry};
use vigil_i18n::tr;

use crate::live::Live;
use crate::watch::{self, Watcher};

/// The icon exists (closing the window may hide it instead of quitting).
static READY: AtomicBool = AtomicBool::new(false);

/// The menu items whose text changes.
struct TrayMenu {
    open: MenuItem<Wry>,
    watching: MenuItem<Wry>,
    notifications: MenuItem<Wry>,
    scan: MenuItem<Wry>,
    quit: MenuItem<Wry>,
}

/// What the page is asked to open (event "open").
#[derive(Serialize, Clone)]
struct OpenPage<'a> {
    page: &'a str,
    scan: bool,
}

fn watcher(app: &AppHandle) -> Option<Arc<Watcher>> {
    app.try_state::<Arc<Watcher>>().map(|w| Arc::clone(&w))
}

fn texts(app: &AppHandle) -> (String, String) {
    let file = watcher(app).map(|w| w.store.load()).unwrap_or_default();
    let watching = if file.settings.watching {
        tr!("Pause watching")
    } else {
        tr!("Resume watching")
    };
    let notifications = if file.notifications_paused(watch::now_ms()) {
        tr!("Resume notifications")
    } else {
        tr!("Pause notifications for 1 hour")
    };
    (watching, notifications)
}

/// Puts the menu texts in the current language and state.
pub fn refresh(app: &AppHandle) {
    let Some(menu) = app.try_state::<TrayMenu>() else {
        return;
    };
    let (watching, notifications) = texts(app);
    let _ = menu.open.set_text(tr!("Open Vigil"));
    let _ = menu.watching.set_text(watching);
    let _ = menu.notifications.set_text(notifications);
    let _ = menu.scan.set_text(tr!("New scan"));
    let _ = menu.quit.set_text(tr!("Quit Vigil"));
    if let Some(tray) = app.tray_by_id("vigil") {
        let paused = watcher(app).is_some_and(|w| !w.settings().watching);
        let _ = tray.set_tooltip(Some(if paused {
            tr!("Vigil: watching paused")
        } else {
            tr!("Vigil: watching")
        }));
    }
}

fn create(app: &AppHandle) -> tauri::Result<()> {
    let (watching, notifications) = texts(app);
    let open = MenuItem::with_id(app, "open", tr!("Open Vigil"), true, None::<&str>)?;
    let watching = MenuItem::with_id(app, "watching", watching, true, None::<&str>)?;
    let notifications = MenuItem::with_id(app, "notifications", notifications, true, None::<&str>)?;
    let scan = MenuItem::with_id(app, "scan", tr!("New scan"), true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", tr!("Quit Vigil"), true, None::<&str>)?;
    let first = PredefinedMenuItem::separator(app)?;
    let second = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(app, &[&open, &first, &watching, &notifications, &scan, &second, &quit])?;
    let mut builder = TrayIconBuilder::with_id("vigil")
        .tooltip(tr!("Vigil: watching"))
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(on_menu)
        .on_tray_icon_event(on_icon);
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder.build(app)?;
    app.manage(TrayMenu {
        open,
        watching,
        notifications,
        scan,
        quit,
    });
    READY.store(true, Ordering::Release);
    refresh(app);
    Ok(())
}

/// Creates the icon (on the main thread, where Windows wants it).
pub fn install(app: &AppHandle) {
    let handle = app.clone();
    let _ = app.run_on_main_thread(move || {
        if let Err(error) = create(&handle) {
            eprintln!("could not create the tray icon: {error}");
        }
    });
}

/// This copy took over the watch from one that quit: it gets the icon.
pub fn became_owner(app: &AppHandle) {
    if !READY.load(Ordering::Acquire) {
        install(app);
    }
}

fn on_icon(tray: &TrayIcon<Wry>, event: TrayIconEvent) {
    match event {
        TrayIconEvent::Click {
            button: MouseButton::Left,
            button_state: MouseButtonState::Up,
            ..
        } => show(tray.app_handle()),
        // The pointer is over the icon: the menu that may open next shows the current state.
        TrayIconEvent::Enter { .. } => refresh(tray.app_handle()),
        _ => {}
    }
}

fn on_menu(app: &AppHandle, event: MenuEvent) {
    match event.id.as_ref() {
        "open" => show(app),
        "watching" => {
            if set_watching(app, None)
                && let Some(w) = watcher(app)
            {
                w.check_soon();
            }
        }
        "notifications" => {
            let paused = watcher(app).is_some_and(|w| w.store.load().notifications_paused(watch::now_ms()));
            pause_notifications(app, !paused);
        }
        "scan" => {
            show(app);
            let _ = app.emit(
                "open",
                OpenPage {
                    page: "overview",
                    scan: true,
                },
            );
        }
        "quit" => app.exit(0),
        _ => {}
    }
}

/// Turns the checks on or off (`None` toggles). Returns whether watching is on now.
pub fn set_watching(app: &AppHandle, value: Option<bool>) -> bool {
    let Some(w) = watcher(app) else { return false };
    let now = w
        .store
        .update(|file| {
            file.settings.watching = value.unwrap_or(!file.settings.watching);
            file.settings.watching
        })
        .unwrap_or(false);
    refresh(app);
    let _ = app.emit("watch", w.status());
    now
}

/// Pauses notifications for an hour (true) or resumes them (false).
pub fn pause_notifications(app: &AppHandle, pause: bool) {
    let Some(w) = watcher(app) else { return };
    let _ = w.store.update(|file| {
        file.notify_paused_until = pause.then(|| watch::now_ms() + watch::PAUSE_MS);
    });
    refresh(app);
    let _ = app.emit("watch", w.status());
}

/// Shows and focuses the window (live pages sample again).
pub fn show(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
    if let Some(live) = app.try_state::<Live>() {
        live.set_visible(true);
    }
}

/// Opens the window on a page (a notification was clicked).
pub fn open_page(app: &AppHandle, page: &str) {
    show(app);
    let _ = app.emit("open", OpenPage { page, scan: false });
}

/// The window's close button: hides it and keeps watching in the tray when the settings say so.
/// Returns true when the close was turned into a hide.
pub fn close_to_tray(app: &AppHandle) -> bool {
    let Some(w) = watcher(app) else { return false };
    if !READY.load(Ordering::Acquire) || !w.owner() {
        return false;
    }
    let settings = w.settings();
    if !settings.close_to_tray {
        return false;
    }
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.hide();
    }
    if let Some(live) = app.try_state::<Live>() {
        live.set_visible(false);
    }
    if !settings.tray_notice_shown {
        let _ = w.store.update(|file| file.settings.tray_notice_shown = true);
        crate::notify::show(
            app,
            &tr!("Vigil keeps watching in the tray"),
            &tr!("Open it or quit from its icon in the notification area. You can change this in Settings."),
            "overview",
        );
    }
    true
}
