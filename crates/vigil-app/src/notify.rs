//! Notifications for the Tauri window: clicking one opens the window on its page. The toasts
//! themselves are `vigil_core::notify`.

use std::sync::Arc;

use tauri::AppHandle;

/// Shows a notification; clicking it opens the window on `page`.
pub fn show(app: &AppHandle, title: &str, body: &str, page: &str) {
    let handle = app.clone();
    let open: vigil_core::notify::OnActivate = Arc::new(move |target: &str| crate::tray::open_page(&handle, target));
    vigil_core::notify::show(&open, title, body, page);
}
