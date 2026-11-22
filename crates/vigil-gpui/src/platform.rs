//! The Windows pieces GPUI does not provide: the tray icon and its menu, one window per user
//! session, and the system accent colour.
//!
//! The tray lives on its own thread with a hidden message-only window (class `VigilGpuiTray`):
//! `Shell_NotifyIconW` reports clicks there, and the menu is a native popup menu, so it looks and
//! reads (Narrator) like every other tray menu. What the user picks travels to the UI thread as a
//! [`Command`]. A second copy of the window finds that hidden window and asks it to show the first
//! copy, then quits. The watch's own named mutex (`watch::claim_watch`) still decides which copy
//! of Vigil watches and owns the icon, Tauri or native alike.

use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::{Arc, OnceLock};

use futures::channel::mpsc::UnboundedSender;
use vigil_core::watch::{self, Watcher};
use windows::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError, HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Threading::CreateMutexW;
use windows::Win32::UI::Shell::{
    NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY, NIM_SETVERSION, NOTIFYICON_VERSION_4,
    NOTIFYICONDATAW, Shell_NotifyIconW,
};
use windows::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreateIconFromResourceEx, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu,
    DispatchMessageW, FindWindowExW, GetCursorPos, GetMessageW, GetSystemMetrics, HICON, HWND_MESSAGE, LR_DEFAULTCOLOR,
    LookupIconIdFromDirectoryEx, MF_SEPARATOR, MF_STRING, MSG, PostMessageW, RegisterClassW, RegisterWindowMessageW,
    SM_CXSMICON, SM_CYSMICON, SetForegroundWindow, TPM_RETURNCMD, TPM_RIGHTBUTTON, TrackPopupMenu, TranslateMessage,
    WINDOW_EX_STYLE, WINDOW_STYLE, WM_APP, WM_CONTEXTMENU, WM_LBUTTONUP, WM_NULL, WM_RBUTTONUP, WNDCLASSW,
};
use windows::core::{PCWSTR, w};

/// What the tray, a notification or a second copy asks the window to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Show and focus the window.
    Open,
    /// Show the window on a page (a notification was clicked).
    OpenPage(String),
    /// New scan: open the window where scans start.
    Scan,
    ToggleWatching,
    ToggleNotifications,
    Quit,
    /// The watch's state changed: draw it again.
    Refresh,
}

const CLASS: PCWSTR = w!("VigilGpuiTray");
const WM_TRAY: u32 = WM_APP + 1;
/// Re-read the watch's state for the tooltip.
const WM_REFRESH: u32 = WM_APP + 2;
/// A second copy asks this one to show its window.
const WM_ACTIVATE_COPY: u32 = WM_APP + 3;
/// This copy took the watch over: show the icon.
const WM_SHOW_ICON: u32 = WM_APP + 4;
const ICON_ID: u32 = 1;

const ID_OPEN: usize = 1;
const ID_WATCHING: usize = 2;
const ID_NOTIFICATIONS: usize = 3;
const ID_SCAN: usize = 4;
const ID_QUIT: usize = 5;

/// What the tray thread's window procedure reads.
struct Shared {
    commands: UnboundedSender<Command>,
    watcher: Option<Arc<Watcher>>,
    icon: bool,
}

static SHARED: OnceLock<Shared> = OnceLock::new();
static TRAY_HWND: AtomicIsize = AtomicIsize::new(0);
static TASKBAR_CREATED: OnceLock<u32> = OnceLock::new();

/// The icon in the notification area and its menu.
pub struct Tray;

impl Tray {
    /// Starts the tray thread. `icon`: this copy owns the watch and shows the icon now (otherwise
    /// it appears when the watch is taken over, see [`Tray::show_icon`]).
    pub fn start(commands: UnboundedSender<Command>, watcher: Option<Arc<Watcher>>, icon: bool) {
        if SHARED
            .set(Shared {
                commands,
                watcher,
                icon,
            })
            .is_err()
        {
            return;
        }
        let spawned = std::thread::Builder::new().name("vigil-tray".into()).spawn(run);
        if let Err(error) = spawned {
            eprintln!("could not start the tray: {error}");
        }
    }

    /// The watch's state changed: the tooltip says it again.
    pub fn refresh() {
        post(WM_REFRESH);
    }

    /// This copy took the watch over: the icon appears.
    pub fn show_icon() {
        post(WM_SHOW_ICON);
    }
}

fn post(message: u32) {
    let hwnd = TRAY_HWND.load(Ordering::Acquire);
    if hwnd != 0 {
        // SAFETY: posting to a window of this process; a stale handle only makes the call fail.
        let _ = unsafe { PostMessageW(Some(HWND(hwnd as *mut _)), message, WPARAM(0), LPARAM(0)) };
    }
}

/// Holds this session's "one native window" mutex. `false`: another copy holds it; that copy has
/// been asked to show its window and this one should quit.
pub fn claim_window() -> bool {
    // SAFETY: plain Win32 call with a static name; the handle stays open for the life of the
    // process on purpose (it is what marks this copy as the one with the window).
    let handle = unsafe { CreateMutexW(None, false, w!("Local\\Vigil.GpuiWindow")) };
    // SAFETY: reads this thread's last error, set by CreateMutexW just above.
    let exists = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
    if handle.is_ok() && !exists {
        return true;
    }
    // SAFETY: looks for the other copy's message-only window by class; nothing is dereferenced.
    if let Ok(other) = unsafe { FindWindowExW(Some(HWND_MESSAGE), None, CLASS, PCWSTR::null()) } {
        // SAFETY: posts a message without pointers to another process's window.
        let _ = unsafe { PostMessageW(Some(other), WM_ACTIVATE_COPY, WPARAM(0), LPARAM(0)) };
    }
    false
}

fn send(command: Command) {
    if let Some(shared) = SHARED.get() {
        let _ = shared.commands.unbounded_send(command);
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Vigil's icon at the small-icon size, from the same `.ico` the Tauri app ships.
fn load_icon() -> Option<HICON> {
    static ICO: &[u8] = include_bytes!("../../vigil-app/icons/icon.ico");
    // SAFETY: GetSystemMetrics has no preconditions.
    let (cx, cy) = unsafe { (GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON)) };
    // SAFETY: `ICO` is a complete icon directory resource; the call only reads it.
    let offset = unsafe { LookupIconIdFromDirectoryEx(ICO.as_ptr(), true, cx, cy, LR_DEFAULTCOLOR) };
    let image = ICO.get(usize::try_from(offset).ok()?..)?;
    // SAFETY: `image` is the icon image the directory points at, inside the same static buffer.
    unsafe { CreateIconFromResourceEx(image, true, 0x0003_0000, cx, cy, LR_DEFAULTCOLOR) }.ok()
}

fn notify_data(hwnd: HWND) -> NOTIFYICONDATAW {
    let mut data = NOTIFYICONDATAW {
        cbSize: size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: hwnd,
        uID: ICON_ID,
        ..Default::default()
    };
    data.Anonymous.uVersion = NOTIFYICON_VERSION_4;
    data
}

fn tooltip() -> String {
    let Some(watcher) = SHARED.get().and_then(|s| s.watcher.clone()) else {
        return "Vigil".into();
    };
    let language = watcher.language();
    watch::in_language(&language, || {
        if watcher.settings().watching {
            vigil_i18n::tr!("Vigil: watching")
        } else {
            vigil_i18n::tr!("Vigil: watching paused")
        }
    })
}

fn set_tip(data: &mut NOTIFYICONDATAW) {
    let tip = wide(&tooltip());
    let room = data.szTip.len() - 1;
    for (slot, c) in data.szTip.iter_mut().zip(tip.iter().take(room)) {
        *slot = *c;
    }
}

fn add_icon(hwnd: HWND) {
    let mut data = notify_data(hwnd);
    data.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    data.uCallbackMessage = WM_TRAY;
    if let Some(icon) = load_icon() {
        data.hIcon = icon;
    }
    set_tip(&mut data);
    // SAFETY: `data` is fully initialised and outlives both calls.
    unsafe {
        let _ = Shell_NotifyIconW(NIM_ADD, &data);
        let _ = Shell_NotifyIconW(NIM_SETVERSION, &data);
    }
}

fn refresh_tip(hwnd: HWND) {
    let mut data = notify_data(hwnd);
    data.uFlags = NIF_TIP;
    set_tip(&mut data);
    // SAFETY: `data` is initialised and outlives the call.
    let _ = unsafe { Shell_NotifyIconW(NIM_MODIFY, &data) };
}

/// The menu: Open Vigil, Pause / Resume watching, Pause / Resume notifications, New scan, Quit.
/// Texts follow the watch's language, as the Tauri tray does.
fn show_menu(hwnd: HWND) {
    let file = SHARED
        .get()
        .and_then(|s| s.watcher.clone())
        .map(|w| (w.store.load(), w.language()));
    let (file, language) = file.unwrap_or_default();
    let texts = watch::in_language(&language, || {
        let (watching, notifications) = watch::tray_texts(&file);
        [
            vigil_i18n::tr!("Open Vigil"),
            watching,
            notifications,
            vigil_i18n::tr!("New scan"),
            vigil_i18n::tr!("Quit Vigil"),
        ]
    });
    // SAFETY: the menu is created, used and destroyed here; every string outlives its call.
    unsafe {
        let Ok(menu) = CreatePopupMenu() else { return };
        let items = [
            (ID_OPEN, &texts[0]),
            (0, &String::new()),
            (ID_WATCHING, &texts[1]),
            (ID_NOTIFICATIONS, &texts[2]),
            (ID_SCAN, &texts[3]),
            (0, &String::new()),
            (ID_QUIT, &texts[4]),
        ];
        for (id, text) in items {
            if id == 0 {
                let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
            } else {
                let label = wide(text);
                let _ = AppendMenuW(menu, MF_STRING, id, PCWSTR(label.as_ptr()));
            }
        }
        let mut at = POINT::default();
        let _ = GetCursorPos(&mut at);
        // The menu closes when the user clicks elsewhere only if its owner is in the foreground.
        let _ = SetForegroundWindow(hwnd);
        let picked = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, at.x, at.y, None, hwnd, None);
        let _ = PostMessageW(Some(hwnd), WM_NULL, WPARAM(0), LPARAM(0));
        let _ = DestroyMenu(menu);
        match picked.0 as usize {
            ID_OPEN => send(Command::Open),
            ID_WATCHING => send(Command::ToggleWatching),
            ID_NOTIFICATIONS => send(Command::ToggleNotifications),
            ID_SCAN => send(Command::Scan),
            ID_QUIT => send(Command::Quit),
            _ => {}
        }
    }
}

extern "system" fn window_proc(hwnd: HWND, message: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match message {
        WM_TRAY => {
            // NOTIFYICON_VERSION_4: the event is the low word of lParam.
            match (lparam.0 & 0xffff) as u32 {
                WM_LBUTTONUP | 0x400 /* NIN_SELECT */ => send(Command::Open),
                WM_CONTEXTMENU | WM_RBUTTONUP => show_menu(hwnd),
                _ => {}
            }
            LRESULT(0)
        }
        WM_REFRESH => {
            refresh_tip(hwnd);
            LRESULT(0)
        }
        WM_SHOW_ICON => {
            add_icon(hwnd);
            LRESULT(0)
        }
        WM_ACTIVATE_COPY => {
            send(Command::Open);
            LRESULT(0)
        }
        _ if TASKBAR_CREATED.get().is_some_and(|m| *m == message) => {
            // Explorer restarted: the icon must be added again.
            if SHARED.get().is_some_and(|s| s.icon) {
                add_icon(hwnd);
            }
            LRESULT(0)
        }
        // SAFETY: the default handling for every other message, with the arguments as received.
        _ => unsafe { DefWindowProcW(hwnd, message, wparam, lparam) },
    }
}

fn run() {
    // SAFETY: registering a window class and creating a message-only window on this thread; the
    // class name and procedure are static.
    let hwnd = unsafe {
        let Ok(module) = GetModuleHandleW(None) else { return };
        let class = WNDCLASSW {
            lpfnWndProc: Some(window_proc),
            hInstance: module.into(),
            lpszClassName: CLASS,
            ..Default::default()
        };
        RegisterClassW(&class);
        let _ = TASKBAR_CREATED.set(RegisterWindowMessageW(w!("TaskbarCreated")));
        match CreateWindowExW(
            WINDOW_EX_STYLE(0),
            CLASS,
            w!("Vigil"),
            WINDOW_STYLE(0),
            0,
            0,
            0,
            0,
            Some(HWND_MESSAGE),
            None,
            Some(module.into()),
            None,
        ) {
            Ok(hwnd) => hwnd,
            Err(_) => return,
        }
    };
    TRAY_HWND.store(hwnd.0 as isize, Ordering::Release);
    if SHARED.get().is_some_and(|s| s.icon) {
        add_icon(hwnd);
    }
    let mut message = MSG::default();
    // SAFETY: the standard message loop of this thread's window.
    unsafe {
        while GetMessageW(&mut message, None, 0, 0).as_bool() {
            let _ = TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
}

/// Shows a notification; clicking it opens the window on `page` (a page key; anything else opens
/// Alerts).
pub fn notify(title: &str, body: &str, page: &str) {
    let open: vigil_core::notify::OnActivate = Arc::new(|target: &str| send(Command::OpenPage(target.to_string())));
    vigil_core::notify::show(&open, title, body, page);
}

/// The watch's view of the native window: the tray icon, notifications and a refresh.
pub struct Host;

impl watch::WatchHost for Host {
    fn became_owner(&self) {
        Tray::show_icon();
    }

    fn notify(&self, title: &str, body: &str, page: &str) {
        notify(title, body, page);
    }

    fn changed(&self, _status: &watch::Status) {
        Tray::refresh();
        send(Command::Refresh);
    }
}

/// Removes the icon (Quit), so it does not linger until the pointer passes over it.
pub fn remove_icon() {
    let hwnd = TRAY_HWND.load(Ordering::Acquire);
    if hwnd == 0 {
        return;
    }
    let data = notify_data(HWND(hwnd as *mut _));
    // SAFETY: `data` names this process's icon and outlives the call.
    let _ = unsafe { Shell_NotifyIconW(NIM_DELETE, &data) };
}

/// The Windows accent colour, in the shade WinUI uses for the theme: AccentDark1 on light,
/// AccentLight2 on dark. `None` when it cannot be read (the Fluent default stays).
pub fn accent(dark: bool) -> Option<gpui_kit::Hsla> {
    use windows::UI::ViewManagement::{UIColorType, UISettings};
    let settings = UISettings::new().ok()?;
    let kind = if dark {
        UIColorType::AccentLight2
    } else {
        UIColorType::AccentDark1
    };
    let c = settings.GetColorValue(kind).ok()?;
    let rgba = (u32::from(c.R) << 24) | (u32::from(c.G) << 16) | (u32::from(c.B) << 8) | 0xff;
    Some(gpui_kit::rgba(rgba).into())
}
