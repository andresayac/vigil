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
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use windows::Data::Xml::Dom::XmlDocument;
use windows::Foundation::TypedEventHandler;
use windows::UI::Notifications::{ToastNotification, ToastNotificationManager};
use windows::core::{HSTRING, IInspectable};

const APP_ID: &str = "com.andresayac.vigil";
const POWERSHELL_ID: &str = r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe";

/// Shown notifications are kept alive so that their click handler still runs when they are
/// clicked later from the notification center (Windows keeps a few dozen per app there).
static SHOWN: Mutex<Vec<ToastNotification>> = Mutex::new(Vec::new());
const KEEP_SHOWN: usize = 64;

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

/// Whether XML 1.0 allows a character: tab, line feed, carriage return, U+0020–U+D7FF,
/// U+E000–U+FFFD and U+10000 and above (a Rust `char` is never a lone surrogate).
fn xml_allowed(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..)
}

/// Escapes text for an XML element or attribute. Characters XML 1.0 forbids (they come from
/// names read on the computer, which malware chooses) would make Windows refuse the whole
/// notification: control characters become spaces, the rest are left out.
pub fn xml_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c if (c as u32) < 0x20 && !xml_allowed(c) => out.push(' '),
            c if !xml_allowed(c) => {}
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

/// What clicking a notification does: open the window on a page (given the page's key).
pub type OnActivate = Arc<dyn Fn(&str) + Send + Sync>;

fn try_show(open: &OnActivate, title: &str, body: &str, page: &str) -> windows::core::Result<()> {
    let doc = XmlDocument::new()?;
    doc.LoadXml(&HSTRING::from(toast_xml(title, body, page)))?;
    let toast = ToastNotification::CreateToastNotification(&doc)?;
    let open = Arc::clone(open);
    let target = page.to_string();
    toast.Activated(&TypedEventHandler::<ToastNotification, IInspectable>::new(
        move |_, _| {
            open(&target);
            Ok(())
        },
    ))?;
    ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(app_id()))?.Show(&toast)?;
    let mut shown = SHOWN.lock().unwrap_or_else(PoisonError::into_inner);
    shown.push(toast);
    if shown.len() > KEEP_SHOWN {
        let extra = shown.len() - KEEP_SHOWN;
        shown.drain(..extra);
    }
    Ok(())
}

/// Shows a notification; failures are only logged (notifications are a convenience). When the
/// text cannot be shown (Windows refused it), a plain notification still says something changed.
pub fn show(open: &OnActivate, title: &str, body: &str, page: &str) {
    if title.is_empty() {
        return;
    }
    init_thread();
    if let Err(error) = try_show(open, title, body, page) {
        eprintln!("could not show a notification: {error}");
        let (title, body) = generic_text();
        if let Err(error) = try_show(open, &title, &body, "alerts") {
            eprintln!("could not show a notification: {error}");
        }
    }
}

/// The notification shown when the real one could not be.
pub fn generic_text() -> (String, String) {
    (
        vigil_i18n::tr!("Vigil noticed changes"),
        vigil_i18n::tr!("Open Vigil to see them on the Alerts page."),
    )
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

    #[test]
    fn characters_xml_forbids_never_reach_windows() {
        let title = "Run\u{FFFF}Me\u{FFFE}\u{1}\r\nok \u{1F600} \u{E000}";
        let escaped = xml_escape(title);
        assert_eq!(escaped, "RunMe \r\nok \u{1F600} \u{E000}");
        // The whole document is accepted by the XML parser Windows uses for notifications.
        let xml = toast_xml(title, "C:\\Users\\jdoe\\x\u{FFFF}.exe", "startup");
        let doc = XmlDocument::new().expect("XML document");
        doc.LoadXml(&HSTRING::from(xml)).expect("valid XML");
        // The plain notification is valid too.
        let (title, body) = vigil_i18n::with_language("en", generic_text);
        assert_eq!(title, "Vigil noticed changes");
        let doc = XmlDocument::new().expect("XML document");
        doc.LoadXml(&HSTRING::from(toast_xml(&title, &body, "alerts")))
            .expect("valid XML");
    }
}
