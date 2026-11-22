//! Starting something as the signed-in user, without Vigil's administrator rights.
//!
//! An elevated program that calls ShellExecute resolves protocols and file types through the
//! user's own registrations (`HKCU\Software\Classes`), which any program the user runs can change:
//! the elevated program would then start that program's command with administrator rights. So
//! while Vigil is elevated, links, browsers and other programs the user controls are started by
//! Explorer instead, which runs with the user's normal rights: Vigil asks the desktop's shell
//! window for its `IShellDispatch2` (the shell's automation object) and calls its `ShellExecute`.
//! If Explorer is not running or does not answer, nothing is started: the caller gets an error,
//! never an elevated fallback.

use std::mem::ManuallyDrop;

use windows::Win32::System::Com::{
    CLSCTX_LOCAL_SERVER, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoCreateInstance, CoInitializeEx,
    CoUninitialize, IDispatch, IServiceProvider,
};
use windows::Win32::System::Variant::{VARIANT, VT_BSTR, VT_I4, VariantClear};
use windows::Win32::UI::Shell::{
    CSIDL_DESKTOP, IShellBrowser, IShellDispatch2, IShellFolderViewDual, IShellWindows, SID_STopLevelBrowser,
    SVGIO_BACKGROUND, SWC_DESKTOP, SWFO_NEEDDISPATCH, ShellWindows,
};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use windows::core::{BSTR, Interface};

use crate::error::{Result, fail};
use vigil_i18n::tr;

/// A VARIANT that frees what it holds.
struct Variant(VARIANT);

impl Variant {
    fn empty() -> Self {
        Self(VARIANT::default())
    }

    fn int(value: i32) -> Self {
        let mut v = VARIANT::default();
        // SAFETY: fills the active members of a zeroed VARIANT: the VT_I4 tag and its 32-bit value.
        unsafe {
            let inner = &mut *v.Anonymous.Anonymous;
            inner.vt = VT_I4;
            inner.Anonymous.lVal = value;
        }
        Self(v)
    }

    /// A string, or an empty VARIANT for an empty string (the shell then uses its default).
    fn text(value: &str) -> Self {
        if value.is_empty() {
            return Self::empty();
        }
        let mut v = VARIANT::default();
        // SAFETY: fills the active members of a zeroed VARIANT: the VT_BSTR tag and an owned BSTR,
        // which `VariantClear` frees in `Drop`.
        unsafe {
            let inner = &mut *v.Anonymous.Anonymous;
            inner.vt = VT_BSTR;
            inner.Anonymous.bstrVal = ManuallyDrop::new(BSTR::from(value));
        }
        Self(v)
    }
}

impl Drop for Variant {
    fn drop(&mut self) {
        // SAFETY: the VARIANT was built above (empty, VT_I4 or VT_BSTR with an owned BSTR).
        unsafe {
            let _ = VariantClear(&mut self.0);
        }
    }
}

/// The shell automation object of the desktop window, which belongs to Explorer.
fn desktop_shell() -> windows::core::Result<IShellDispatch2> {
    // SAFETY: plain COM calls on interfaces this function owns; each result is checked.
    unsafe {
        let windows: IShellWindows = CoCreateInstance(&ShellWindows, None, CLSCTX_LOCAL_SERVER)?;
        let location = Variant::int(CSIDL_DESKTOP as i32);
        let root = Variant::empty();
        let mut hwnd = 0i32;
        let window = windows.FindWindowSW(&location.0, &root.0, SWC_DESKTOP, &mut hwnd, SWFO_NEEDDISPATCH)?;
        let provider: IServiceProvider = window.cast()?;
        let browser: IShellBrowser = provider.QueryService(&SID_STopLevelBrowser)?;
        let view = browser.QueryActiveShellView()?;
        let background: IDispatch = view.GetItemObject(SVGIO_BACKGROUND)?;
        let folder: IShellFolderViewDual = background.cast()?;
        folder.Application()?.cast()
    }
}

fn shell_execute(file: &str, args: &str, dir: &str) -> windows::core::Result<()> {
    let shell = desktop_shell()?;
    let args = Variant::text(args);
    let dir = Variant::text(dir);
    let verb = Variant::text("open");
    let show = Variant::int(SW_SHOWNORMAL.0);
    // SAFETY: every argument lives until the call returns; Explorer copies what it keeps.
    unsafe { shell.ShellExecute(&BSTR::from(file), &args.0, &dir.0, &verb.0, &show.0) }
}

/// Starts `file` (a program, document or link) with `args` in `dir`, as the signed-in user with
/// normal rights, through Explorer. Explorer gives no process ID back. Fails, starting nothing,
/// when Explorer is not available.
pub fn launch_as_user(file: &str, args: &str, dir: &str) -> Result<()> {
    if let Some(fake) = crate::testing::user_launch() {
        return fake(file, args, dir);
    }
    let (file, args, dir) = (file.to_string(), args.to_string(), dir.to_string());
    // Explorer's automation objects want a single-threaded apartment: a thread of its own.
    let outcome = std::thread::spawn(move || {
        // SAFETY: initializes COM on this new thread; balanced below when it succeeded.
        let initialized = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) }.is_ok();
        let result = shell_execute(&file, &args, &dir);
        if initialized {
            // SAFETY: pairs the successful CoInitializeEx above, on the same thread; every
            // interface was released when `shell_execute` returned.
            unsafe { CoUninitialize() };
        }
        result.map_err(|e| e.message())
    })
    .join();
    match outcome {
        Ok(Ok(())) => Ok(()),
        Ok(Err(reason)) => fail(tr!(
            "Vigil runs as administrator and starts this only with your normal rights, through Explorer, which did not answer ({0}). Open it yourself, or start Vigil without administrator rights.",
            reason
        )),
        Err(_) => fail(tr!(
            "Vigil runs as administrator and starts this only with your normal rights, through Explorer, which did not answer ({0}). Open it yourself, or start Vigil without administrator rights.",
            "panic"
        )),
    }
}

/// Starts `file` the usual way when Vigil has normal rights, and as the signed-in user through
/// Explorer when Vigil runs as administrator.
pub fn launch_unelevated(file: &str, args: &str, dir: &str, normal: impl FnOnce() -> Result<()>) -> Result<()> {
    if crate::is_admin() {
        launch_as_user(file, args, dir)
    } else {
        normal()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[test]
    fn elevated_launches_go_through_the_user_and_never_run_directly() {
        let calls: Rc<RefCell<Vec<String>>> = Rc::default();
        let seen = calls.clone();
        crate::testing::set_user_launch(Some(Rc::new(move |file: &str, args: &str, dir: &str| {
            seen.borrow_mut().push(format!("{file}|{args}|{dir}"));
            Ok(())
        })));
        crate::testing::set_admin(Some(true));
        let mut direct = false;
        launch_unelevated("ms-settings:windowsupdate", "", "", || {
            direct = true;
            Ok(())
        })
        .expect("launched");
        assert!(!direct, "an elevated Vigil never starts it itself");
        assert_eq!(calls.borrow().as_slice(), ["ms-settings:windowsupdate||"]);

        crate::testing::set_admin(Some(false));
        launch_unelevated("ms-settings:windowsupdate", "", "", || {
            direct = true;
            Ok(())
        })
        .expect("launched");
        assert!(direct, "with normal rights the usual way is used");
        assert_eq!(calls.borrow().len(), 1);

        // Explorer unavailable: an error, nothing started elevated.
        crate::testing::set_user_launch(Some(Rc::new(|_: &str, _: &str, _: &str| fail("no Explorer"))));
        crate::testing::set_admin(Some(true));
        assert!(launch_unelevated("https://example.com", "", "", || Ok(())).is_err());
        crate::testing::reset();
    }

    #[test]
    fn variants_hold_their_values() {
        let text = Variant::text("open");
        // SAFETY: reads the members `Variant::text` filled.
        unsafe {
            let inner = &*text.0.Anonymous.Anonymous;
            assert_eq!(inner.vt, VT_BSTR);
            assert_eq!(inner.Anonymous.bstrVal.to_string(), "open");
        }
        let number = Variant::int(5);
        // SAFETY: reads the members `Variant::int` filled.
        unsafe {
            assert_eq!((*number.0.Anonymous.Anonymous).Anonymous.lVal, 5);
        }
        let empty = Variant::text("");
        // SAFETY: a zeroed VARIANT is VT_EMPTY.
        unsafe { assert_eq!((*empty.0.Anonymous.Anonymous).vt.0, 0) }
    }

    /// Opens a harmless Settings page through Explorer, as a user would see it. Run by hand.
    #[test]
    #[ignore = "opens a Settings window"]
    fn explorer_opens_a_settings_page() {
        launch_as_user("ms-settings:about", "", "").expect("Explorer answered");
    }
}
