//! Native confirmation with a Windows task dialog. The web view never decides that an action
//! runs: Rust rebuilds the action, shows exactly what it will do here, and runs it only on "yes".
//!
//! The text is plain (hyperlinks are not enabled), so names and paths that come from the system
//! cannot inject anything. TaskDialogIndirect lives only in Common Controls 6; it is loaded at call
//! time so that binaries without the application manifest (tests) still start, and a plain message
//! box is used when it is not available.

use windows::Win32::Foundation::HWND;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::UI::Controls::{
    TASKDIALOG_BUTTON, TASKDIALOG_FLAGS, TASKDIALOGCONFIG, TD_WARNING_ICON, TDCBF_CANCEL_BUTTON,
    TDF_ALLOW_DIALOG_CANCELLATION, TDF_POSITION_RELATIVE_TO_WINDOW, TDF_VERIFICATION_FLAG_CHECKED,
};
use windows::Win32::UI::WindowsAndMessaging::{
    IDCANCEL, IDOK, MB_DEFBUTTON2, MB_ICONWARNING, MB_OKCANCEL, MESSAGEBOX_STYLE, MessageBoxW,
};
use windows::core::{BOOL, HRESULT, PCWSTR, s, w};

/// What the dialog shows.
#[derive(Debug, Clone, Default)]
pub struct Prompt {
    pub title: String,
    pub body: String,
    pub warning: String,
    pub confirm: String,
    /// Destructive actions get "Cancel" as the default button.
    pub destructive: bool,
    /// `None`: no restore point checkbox. `Some(checked)`: the checkbox and its initial state.
    pub restore_point: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    Cancel,
    Confirm { restore_point: bool },
}

const ID_CONFIRM: i32 = 100;

type TaskDialogIndirectFn =
    unsafe extern "system" fn(*const TASKDIALOGCONFIG, *mut i32, *mut i32, *mut BOOL) -> HRESULT;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn task_dialog_fn() -> Option<TaskDialogIndirectFn> {
    // SAFETY: plain library load by name; the handle stays loaded for the life of the process
    // (comctl32 is already loaded by the web view host).
    let module = unsafe { LoadLibraryW(w!("comctl32.dll")) }.ok()?;
    // SAFETY: the symbol name is a valid NUL-terminated string.
    let proc = unsafe { GetProcAddress(module, s!("TaskDialogIndirect")) }?;
    // SAFETY: TaskDialogIndirect has exactly this signature (commctrl.h).
    Some(unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, TaskDialogIndirectFn>(proc) })
}

/// Shows the confirmation. Must run on the thread that owns `parent` (the main thread).
pub fn ask(parent: HWND, prompt: &Prompt) -> Answer {
    match task_dialog_fn() {
        Some(dialog) => ask_task_dialog(dialog, parent, prompt),
        None => ask_message_box(parent, prompt),
    }
}

fn ask_task_dialog(dialog: TaskDialogIndirectFn, parent: HWND, prompt: &Prompt) -> Answer {
    let caption = wide("Vigil");
    let main = wide(&prompt.title);
    let content = wide(&prompt.body);
    let footer = wide(&prompt.warning);
    let confirm = wide(&prompt.confirm);
    let verification = wide(&vigil_i18n::tr!("Create a system restore point first"));
    let buttons = [TASKDIALOG_BUTTON {
        nButtonID: ID_CONFIRM,
        pszButtonText: PCWSTR(confirm.as_ptr()),
    }];

    let mut flags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_POSITION_RELATIVE_TO_WINDOW;
    if prompt.restore_point == Some(true) {
        flags |= TDF_VERIFICATION_FLAG_CHECKED;
    }
    let mut config = TASKDIALOGCONFIG {
        cbSize: size_of::<TASKDIALOGCONFIG>() as u32,
        hwndParent: parent,
        dwFlags: TASKDIALOG_FLAGS(flags.0),
        dwCommonButtons: TDCBF_CANCEL_BUTTON,
        pszWindowTitle: PCWSTR(caption.as_ptr()),
        pszMainInstruction: PCWSTR(main.as_ptr()),
        pszContent: PCWSTR(content.as_ptr()),
        cButtons: buttons.len() as u32,
        pButtons: buttons.as_ptr(),
        nDefaultButton: if prompt.destructive { IDCANCEL.0 } else { ID_CONFIRM },
        ..Default::default()
    };
    if prompt.restore_point.is_some() {
        config.pszVerificationText = PCWSTR(verification.as_ptr());
    }
    if !prompt.warning.is_empty() {
        config.Anonymous2.pszFooterIcon = TD_WARNING_ICON;
        config.pszFooter = PCWSTR(footer.as_ptr());
    }
    let mut pressed = 0i32;
    let mut checked = BOOL(0);
    // SAFETY: every string and the button array outlive the call; the out pointers are valid.
    let result = unsafe { dialog(&config, &mut pressed, std::ptr::null_mut(), &mut checked) };
    if result.is_err() {
        return ask_message_box(parent, prompt);
    }
    if pressed == ID_CONFIRM {
        Answer::Confirm {
            restore_point: prompt.restore_point.is_some() && checked.as_bool(),
        }
    } else {
        Answer::Cancel
    }
}

fn ask_message_box(parent: HWND, prompt: &Prompt) -> Answer {
    let mut text = format!("{}\n\n{}", prompt.title, prompt.body);
    if !prompt.warning.is_empty() {
        text.push_str("\n\n");
        text.push_str(&prompt.warning);
    }
    let text = wide(&text);
    let caption = wide("Vigil");
    let mut style: MESSAGEBOX_STYLE = MB_OKCANCEL | MB_ICONWARNING;
    if prompt.destructive {
        style |= MB_DEFBUTTON2;
    }
    // SAFETY: both strings are NUL-terminated and outlive the call.
    let pressed = unsafe { MessageBoxW(Some(parent), PCWSTR(text.as_ptr()), PCWSTR(caption.as_ptr()), style) };
    // Without the task dialog there is no checkbox: keep the restore point when it was pre-checked.
    if pressed == IDOK {
        Answer::Confirm {
            restore_point: prompt.restore_point == Some(true),
        }
    } else {
        Answer::Cancel
    }
}

/// A plain information or error message (results that need attention).
pub fn tell(parent: HWND, title: &str, text: &str) {
    let text = wide(&format!("{title}\n\n{text}"));
    let caption = wide("Vigil");
    // SAFETY: both strings are NUL-terminated and outlive the call.
    unsafe {
        MessageBoxW(
            Some(parent),
            PCWSTR(text.as_ptr()),
            PCWSTR(caption.as_ptr()),
            MB_ICONWARNING,
        )
    };
}
