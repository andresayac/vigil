//! Windows notifications (toasts) through WinRT's `ToastNotificationManager`.
//!
//! Texts come from the watch and may quote names and command lines read from the computer, so they
//! are XML-escaped and shown as plain text. Clicking a notification opens the page it is about.
//!
//! An installed Vigil has a Start menu shortcut carrying its AppUserModelID (`com.andresayac.vigil`),
//! which Windows needs before it shows notifications for an app. A portable or development copy has
//! none, so it borrows Windows PowerShell's well-known ID: the notification then says "Windows
//! PowerShell" in its header and "Vigil" at the bottom.

use std::path::PathBuf;
use std::sync::{Mutex, OnceLock, PoisonError};

use tauri::AppHandle;
use windows::Data::Xml::Dom::XmlDocument;
use windows::Foundation::TypedEventHandler;
use windows::UI::Notifications::{ToastNotification, ToastNotificationManager};
use windows::core::{HSTRING, IInspectable};

const APP_ID: &str = "com.andresayac.vigil";
const POWERSHELL_ID: &str = r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe";

/// Shown notifications are kept alive so that their click handler still runs.
static SHOWN: Mutex<Vec<ToastNotification>> = Mutex::new(Vec::new());

/// Prepares the calling thread for WinRT (harmless when it already is).
pub fn init_thread() {
    // SAFETY: initializes the Windows Runtime for this thread; an already initialized thread
    // (another apartment type) returns an error that is ignored on purpose.
    let _ =
        unsafe { windows::Win32::System::WinRT::RoInitialize(windows::Win32::System::WinRT::RO_INIT_MULTITHREADED) };
}

fn start_menu_folders() -> Vec<PathBuf> {
    ["ProgramData", "APPDATA"]
        .iter()
        .filter_map(|name| std::env::var_os(name).filter(|v| !v.is_empty()))
        .map(|base| PathBuf::from(base).join(r"Microsoft\Windows\Start Menu\Programs"))
        .collect()
}

/// The AppUserModelID notifications are sent with.
fn app_id() -> &'static str {
    static ID: OnceLock<&'static str> = OnceLock::new();
    ID.get_or_init(|| {
        let installed = start_menu_folders()
            .iter()
            .any(|folder| folder.join("Vigil.lnk").is_file() || folder.join(r"Vigil\Vigil.lnk").is_file());
        if installed { APP_ID } else { POWERSHELL_ID }
    })
}

/// Escapes text for an XML element or attribute.
pub fn xml_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            // Control characters are not allowed in XML 1.0.
            c if (c as u32) < 0x20 && c != '\n' && c != '\t' => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

/// The toast XML: title, body, attribution; `launch` carries the page to open.
pub fn toast_xml(title: &str, body: &str, page: &str) -> String {
    let short = |text: &str, max: usize| {
        if text.chars().count() > max {
            format!("{}…", text.chars().take(max).collect::<String>())
        } else {
            text.to_string()
        }
    };
    format!(
        "<toast launch=\"{}\"><visual><binding template=\"ToastGeneric\"><text>{}</text><text>{}</text>\
         <text placement=\"attribution\">Vigil</text></binding></visual></toast>",
        xml_escape(page),
        xml_escape(&short(title, 120)),
        xml_escape(&short(body, 400)),
    )
}

fn try_show(app: &AppHandle, title: &str, body: &str, page: &str) -> windows::core::Result<()> {
    let doc = XmlDocument::new()?;
    doc.LoadXml(&HSTRING::from(toast_xml(title, body, page)))?;
    let toast = ToastNotification::CreateToastNotification(&doc)?;
    let handle = app.clone();
    let target = page.to_string();
    toast.Activated(&TypedEventHandler::<ToastNotification, IInspectable>::new(
        move |_, _| {
            crate::tray::open_page(&handle, &target);
            Ok(())
        },
    ))?;
    ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(app_id()))?.Show(&toast)?;
    let mut shown = SHOWN.lock().unwrap_or_else(PoisonError::into_inner);
    shown.push(toast);
    if shown.len() > 8 {
        shown.remove(0);
    }
    Ok(())
}

/// Shows a notification; failures are only logged (notifications are a convenience).
pub fn show(app: &AppHandle, title: &str, body: &str, page: &str) {
    if title.is_empty() {
        return;
    }
    init_thread();
    if let Err(error) = try_show(app, title, body, page) {
        eprintln!("could not show a notification: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untrusted_text_is_escaped() {
        let xml = toast_xml(
            "New startup entry: <evil> & \"co\"",
            "cmd.exe /c 'x' \u{7}",
            "startup\"><script/>",
        );
        assert!(xml.contains("New startup entry: &lt;evil&gt; &amp; &quot;co&quot;"));
        assert!(xml.contains("cmd.exe /c &apos;x&apos;  "));
        assert!(xml.contains("launch=\"startup&quot;&gt;&lt;script/&gt;\""));
        assert!(!xml.contains("<evil>") && !xml.contains("<script/>"));
        let long = toast_xml(&"a".repeat(500), "", "alerts");
        assert!(long.contains(&format!("{}…", "a".repeat(120))));
    }
}
