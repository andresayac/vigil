//! The few Win32 calls the window needs that GPUI does not make: its HWND (the owner of the
//! native confirmation), a title bar that follows Vigil's theme rather than Windows', and whether
//! this Windows draws Mica.

use gpui_kit::Window;
use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use windows::Wdk::System::SystemServices::RtlGetVersion;
use windows::Win32::Foundation::HWND;
use windows::Win32::Graphics::Dwm::{DWMWA_USE_IMMERSIVE_DARK_MODE, DwmSetWindowAttribute};
use windows::Win32::System::SystemInformation::OSVERSIONINFOW;
use windows::Win32::UI::WindowsAndMessaging::{SHOW_WINDOW_CMD, SW_HIDE, SW_SHOW, ShowWindow};
use windows::core::BOOL;

/// The window's HWND as an integer (0 when it has none), for `vigil_core::service::Ui::owner`.
pub fn hwnd(window: &Window) -> isize {
    match HasWindowHandle::window_handle(window).map(|handle| handle.as_raw()) {
        Ok(RawWindowHandle::Win32(handle)) => handle.hwnd.get(),
        _ => 0,
    }
}

/// Paints the native title bar and caption buttons dark or light, whatever Windows uses, so
/// "Dark" in Settings gives a dark title bar on a light Windows (as the Tauri app does).
pub fn set_dark_title_bar(window: &Window, dark: bool) {
    let raw = hwnd(window);
    if raw == 0 {
        return;
    }
    let value = BOOL::from(dark);
    // SAFETY: the HWND belongs to this live window, and the attribute reads exactly one BOOL
    // from the pointer, which outlives the call.
    let _ = unsafe {
        DwmSetWindowAttribute(
            HWND(raw as *mut core::ffi::c_void),
            DWMWA_USE_IMMERSIVE_DARK_MODE,
            (&raw const value).cast(),
            size_of::<BOOL>() as u32,
        )
    };
}

/// Hides the window (it keeps running in the tray).
pub fn hide(window: &Window) {
    show_window(window, SW_HIDE);
}

/// Shows the window again (restored if it was minimized).
pub fn show(window: &Window) {
    show_window(window, SW_SHOW);
}

fn show_window(window: &Window, command: SHOW_WINDOW_CMD) {
    let raw = hwnd(window);
    if raw == 0 {
        return;
    }
    // SAFETY: the HWND belongs to this live window; ShowWindow takes no pointers.
    let _ = unsafe { ShowWindow(HWND(raw as *mut core::ffi::c_void), command) };
}

/// Windows 11 22H2 or later: the build that has the Mica system backdrop (DWMWA_SYSTEMBACKDROP_TYPE).
pub fn has_mica() -> bool {
    windows_build() >= 22621
}

/// The Windows build number (0 when it cannot be read).
fn windows_build() -> u32 {
    let mut info = OSVERSIONINFOW {
        dwOSVersionInfoSize: size_of::<OSVERSIONINFOW>() as u32,
        ..Default::default()
    };
    // SAFETY: `info` is a valid OSVERSIONINFOW with its size set; RtlGetVersion only writes it.
    let status = unsafe { RtlGetVersion(&mut info) };
    if status.is_ok() { info.dwBuildNumber } else { 0 }
}
