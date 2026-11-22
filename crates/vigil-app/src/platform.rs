//! The Windows pieces GPUI does not provide: the tray icon and its menu, one window per user
//! session, and the system accent colour.
//!
//! The tray lives on its own thread with a hidden message-only window (class `VigilTray`):
//! `Shell_NotifyIconW` reports clicks there, and the menu is a native popup menu, so it looks and
//! reads (Narrator) like every other tray menu. What the user picks travels to the UI thread as a
//! [`Command`]. A second copy of the window finds that hidden window and asks it to show the first
//! copy, then quits, unless it runs elevated and the first copy does not: then the first copy is
//! asked to quit and the elevated one takes over (see [`claim_window`]). The watch's own named
//! mutex (`watch::claim_watch`) still decides which copy of Vigil watches and owns the icon.

use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::{Arc, OnceLock};

use futures::channel::mpsc::UnboundedSender;
use vigil_core::watch::{self, Watcher};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE, HWND, LPARAM, LRESULT, POINT, WPARAM,
};
use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Threading::{
    CreateMutexW, OpenProcess, OpenProcessToken, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE, QueryFullProcessImageNameW, WaitForSingleObject,
};
use windows::Win32::UI::Shell::{
    NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY, NIM_SETVERSION, NOTIFYICON_VERSION_4,
    NOTIFYICONDATAW, Shell_NotifyIconW,
};
use windows::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, ChangeWindowMessageFilterEx, CreateIconFromResourceEx, CreatePopupMenu, CreateWindowExW,
    DefWindowProcW, DestroyMenu, DispatchMessageW, FindWindowExW, GetCursorPos, GetMessageW, GetSystemMetrics,
    GetWindowThreadProcessId, HICON, HWND_MESSAGE, LR_DEFAULTCOLOR, LookupIconIdFromDirectoryEx, MF_SEPARATOR,
    MF_STRING, MSG, MSGFLT_ALLOW, PostMessageW, RegisterClassW, RegisterWindowMessageW, SM_CXSMICON, SM_CYSMICON,
    SetForegroundWindow, TPM_RETURNCMD, TPM_RIGHTBUTTON, TrackPopupMenu, TranslateMessage, WINDOW_EX_STYLE,
    WINDOW_STYLE, WM_APP, WM_CONTEXTMENU, WM_LBUTTONUP, WM_NULL, WM_RBUTTONUP, WNDCLASSW,
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

const CLASS: PCWSTR = w!("VigilTray");
const WM_TRAY: u32 = WM_APP + 1;
/// Re-read the watch's state for the tooltip.
const WM_REFRESH: u32 = WM_APP + 2;
/// A second copy asks this one to show its window.
const WM_ACTIVATE_COPY: u32 = WM_APP + 3;
/// This copy took the watch over: show the icon.
const WM_SHOW_ICON: u32 = WM_APP + 4;
/// An elevated copy starts while this copy (not elevated) has the window: quit so it takes over.
/// Windows only delivers it from a process of the same or a higher integrity level.
const WM_YIELD_TO_ELEVATED: u32 = WM_APP + 5;
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

/// Who holds this session's window, found through its hidden tray window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Holder {
    /// No Vigil window answers: the holder is still starting, has hung, or another program took
    /// the mutex's name.
    None,
    /// This same `vigil.exe`: its process id and whether it runs elevated (`None`: unknown).
    Vigil { pid: u32, elevated: Option<bool> },
    /// A window with Vigil's class that belongs to another program.
    Other,
}

/// What a copy that starts does about the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Claim {
    /// Open the window.
    Open,
    /// Ask the copy that has it to show it, and quit.
    Activate,
    /// Ask that copy (not elevated) to quit, wait for its process, then open: the person approved
    /// UAC and must get the elevated window.
    Replace(u32),
}

/// The decision, without side effects. `taken`: the session's window mutex already existed.
///
/// - Free: open.
/// - Held by this same `vigil.exe`: show that window, unless this copy is elevated and that one
///   is not, which then quits and lets this one take over.
/// - Held by anything else (no Vigil window answers, or the window belongs to another program):
///   open anyway. Another program creating the name first must not keep Vigil from opening.
pub fn decide(taken: bool, holder: Holder, elevated: bool) -> Claim {
    match holder {
        _ if !taken => Claim::Open,
        Holder::Vigil {
            pid,
            elevated: Some(false),
        } if elevated => Claim::Replace(pid),
        Holder::Vigil { .. } => Claim::Activate,
        Holder::None | Holder::Other => Claim::Open,
    }
}

/// This session's "one native window" mutex (kept open for the life of the process on purpose: it
/// is what marks this copy as the one with the window).
static WINDOW_MUTEX: AtomicIsize = AtomicIsize::new(0);

/// Decides whether this copy opens the window (see [`decide`]). `false`: another copy shows its
/// window and this one should quit.
pub fn claim_window() -> bool {
    let elevated = vigil_sys::elevation::is_elevated();
    for _ in 0..3 {
        let taken = create_window_mutex();
        if !taken {
            return true;
        }
        let (holder, window) = find_holder();
        match decide(taken, holder, elevated) {
            Claim::Open => {
                eprintln!("the window mutex is held by something other than Vigil: opening anyway");
                return true;
            }
            Claim::Activate => {
                if let Some(window) = window {
                    // SAFETY: posts a message without pointers to another process's window.
                    let _ = unsafe { PostMessageW(Some(window), WM_ACTIVATE_COPY, WPARAM(0), LPARAM(0)) };
                }
                return false;
            }
            Claim::Replace(pid) => {
                if let Some(window) = window {
                    // SAFETY: as above; an elevated sender reaches a window of lower integrity.
                    let _ = unsafe { PostMessageW(Some(window), WM_YIELD_TO_ELEVATED, WPARAM(0), LPARAM(0)) };
                }
                wait_for_exit(pid, 15_000);
                release_window_mutex();
            }
        }
    }
    // The other copy did not quit: open rather than leave the person without a window.
    true
}

/// Creates (or opens) the window mutex. Returns whether it already existed.
fn create_window_mutex() -> bool {
    // SAFETY: plain Win32 call with a static name; the handle is kept in WINDOW_MUTEX.
    let handle = unsafe { CreateMutexW(None, false, w!("Local\\Vigil.Window")) };
    // SAFETY: reads this thread's last error, set by CreateMutexW just above.
    let exists = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
    if let Ok(handle) = handle {
        release_window_mutex();
        WINDOW_MUTEX.store(handle.0 as isize, Ordering::Release);
    }
    exists
}

/// Closes this copy's handle on the window mutex: before taking it again, and before "Restart as
/// administrator" starts the elevated copy that must get it.
pub fn release_window_mutex() {
    let raw = WINDOW_MUTEX.swap(0, Ordering::AcqRel);
    if raw != 0 {
        // SAFETY: the handle came from CreateMutexW and is closed once (swapped out above).
        let _ = unsafe { CloseHandle(HANDLE(raw as *mut _)) };
    }
}

/// The copy that holds the window, by its hidden tray window: the first window of Vigil's class
/// whose process runs this same executable. A copy that is still starting gets two seconds to
/// create its window.
fn find_holder() -> (Holder, Option<HWND>) {
    let own = own_image();
    for attempt in 0..10 {
        let mut other = false;
        let mut after: Option<HWND> = None;
        // SAFETY: walks the message-only windows of Vigil's class; nothing is dereferenced.
        while let Ok(window) = unsafe { FindWindowExW(Some(HWND_MESSAGE), after, CLASS, PCWSTR::null()) } {
            after = Some(window);
            let mut pid = 0u32;
            // SAFETY: `pid` is a valid out pointer for the window's process id.
            unsafe { GetWindowThreadProcessId(window, Some(&mut pid)) };
            if pid == 0 || pid == std::process::id() {
                continue;
            }
            let (image, elevated) = process_facts(pid);
            if own.is_some() && image.is_some() && image == own {
                return (Holder::Vigil { pid, elevated }, Some(window));
            }
            other = true;
        }
        if other {
            return (Holder::Other, None);
        }
        if attempt < 9 {
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }
    (Holder::None, None)
}

/// This executable's path, lower case, as Windows names it.
fn own_image() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let full = std::fs::canonicalize(&exe).unwrap_or(exe);
    Some(normalize(&full.to_string_lossy()))
}

fn normalize(path: &str) -> String {
    path.trim_start_matches(r"\\?\").to_lowercase()
}

/// The image path (lower case) of process `pid`, and whether it runs elevated (`None` when its
/// token cannot be read, as from a standard process for an elevated one).
fn process_facts(pid: u32) -> (Option<String>, Option<bool>) {
    // SAFETY: opens the process for limited queries only; the handle is closed below.
    let Ok(process) = (unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }) else {
        return (None, None);
    };
    let mut buffer = vec![0u16; 1024];
    let mut size = buffer.len() as u32;
    // SAFETY: `buffer` holds `size` characters; Windows writes the path and its length.
    let image = unsafe {
        QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_WIN32,
            windows::core::PWSTR(buffer.as_mut_ptr()),
            &mut size,
        )
    }
    .ok()
    .map(|()| String::from_utf16_lossy(&buffer[..size as usize]))
    .map(|path| {
        let full = std::fs::canonicalize(&path).map_or(path, |p| p.to_string_lossy().into_owned());
        normalize(&full)
    });
    let elevated = token_elevated(process);
    // SAFETY: the handle came from OpenProcess above.
    let _ = unsafe { CloseHandle(process) };
    (image, elevated)
}

fn token_elevated(process: HANDLE) -> Option<bool> {
    let mut token = HANDLE::default();
    // SAFETY: opens the process token for queries; closed below.
    unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }.ok()?;
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0u32;
    // SAFETY: `elevation` is the structure TokenElevation fills, of the size given.
    let read = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some(std::ptr::from_mut(&mut elevation).cast()),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    };
    // SAFETY: the token handle came from OpenProcessToken above.
    let _ = unsafe { CloseHandle(token) };
    read.ok().map(|()| elevation.TokenIsElevated != 0)
}

/// Waits up to `timeout_ms` for process `pid` to end (at once when it already has, or when it
/// cannot be opened).
pub fn wait_for_exit(pid: u32, timeout_ms: u32) {
    if pid == 0 || pid == std::process::id() {
        return;
    }
    // SAFETY: opens the process only to wait on it; the handle is closed below.
    let Ok(process) = (unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, pid) }) else {
        return;
    };
    // SAFETY: waits on a valid process handle for a bounded time.
    let _ = unsafe { WaitForSingleObject(process, timeout_ms) };
    // SAFETY: the handle came from OpenProcess above.
    let _ = unsafe { CloseHandle(process) };
}

fn send(command: Command) {
    if let Some(shared) = SHARED.get() {
        let _ = shared.commands.unbounded_send(command);
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Vigil's icon at the small-icon size, from the `.ico` the executable carries.
fn load_icon() -> Option<HICON> {
    static ICO: &[u8] = include_bytes!("../icons/icon.ico");
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
/// Texts follow the watch's language.
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
        WM_YIELD_TO_ELEVATED => {
            // Only a process of this integrity level or higher can deliver it: an elevated copy
            // takes the window over, so this one quits (the watch goes with it).
            if !vigil_sys::elevation::is_elevated() {
                send(Command::Quit);
            }
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
            Err(error) => {
                eprintln!("could not create the tray window: {error}");
                return;
            }
        }
    };
    TRAY_HWND.store(hwnd.0 as isize, Ordering::Release);
    // Explorer (not elevated) announces a restart with TaskbarCreated; an elevated copy must let it
    // through, or the icon never comes back. It carries no data.
    if let Some(message) = TASKBAR_CREATED.get() {
        // SAFETY: changes the message filter of this thread's own window.
        let _ = unsafe { ChangeWindowMessageFilterEx(hwnd, *message, MSGFLT_ALLOW, None) };
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_free_window_opens() {
        assert_eq!(decide(false, Holder::None, false), Claim::Open);
        assert_eq!(decide(false, Holder::None, true), Claim::Open);
    }

    #[test]
    fn a_second_copy_shows_the_first() {
        let vigil = |elevated| Holder::Vigil { pid: 42, elevated };
        assert_eq!(decide(true, vigil(Some(false)), false), Claim::Activate);
        assert_eq!(decide(true, vigil(Some(true)), false), Claim::Activate);
        assert_eq!(decide(true, vigil(None), false), Claim::Activate);
        assert_eq!(decide(true, vigil(Some(true)), true), Claim::Activate);
        // An elevated copy that cannot read the other's token does not take its window.
        assert_eq!(decide(true, vigil(None), true), Claim::Activate);
    }

    #[test]
    fn an_elevated_copy_takes_over_from_a_standard_one() {
        // The sign-in copy (`--tray`, not elevated) holds the window; the person then starts
        // Vigil from the Start menu and approves UAC: the elevated window must open.
        let holder = Holder::Vigil {
            pid: 42,
            elevated: Some(false),
        };
        assert_eq!(decide(true, holder, true), Claim::Replace(42));
    }

    #[test]
    fn something_else_holding_the_name_does_not_keep_vigil_closed() {
        assert_eq!(decide(true, Holder::Other, false), Claim::Open);
        assert_eq!(decide(true, Holder::None, true), Claim::Open);
    }

    #[test]
    fn image_paths_compare_without_the_long_path_prefix() {
        assert_eq!(
            normalize(r"\\?\C:\Program Files\Vigil\vigil.exe"),
            r"c:\program files\vigil\vigil.exe"
        );
        assert_eq!(
            normalize(r"C:\Program Files\Vigil\VIGIL.EXE"),
            r"c:\program files\vigil\vigil.exe"
        );
    }
}
