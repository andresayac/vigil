//! `--demo` data for the Services, Startup apps, Quarantine and History pages: fictitious
//! services, startup entries, quarantined files and journal records (Contoso, Fabrikam, jdoe on
//! PC-VICTIM). Nothing here reads the computer.

use std::collections::HashMap;

use vigil_core::inspect::StartupSignature;
use vigil_core::state::QuarantineEntry;
use vigil_sys::services::Service;
use vigil_sys::startup::StartupEntry;

use crate::pages::history::Entry;
use crate::pages::services::Row;

/// (name, display name, state, start type, pid, account, path, description, protected)
type ServiceSpec = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    u32,
    &'static str,
    &'static str,
    &'static str,
    bool,
);

#[rustfmt::skip]
const SERVICES: &[ServiceSpec] = &[
    // (name, display name, state, start type, pid, account, path, description, protected)
    ("AudioSrv", "Windows Audio", "running", "auto", 2310, r"NT AUTHORITY\LocalService", r"C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p", "Manages audio for Windows-based programs.", true),
    ("BITS", "Background Intelligent Transfer Service", "stopped", "demand", 0, "LocalSystem", r"C:\Windows\System32\svchost.exe -k netsvcs -p", "Transfers files in the background using idle network bandwidth.", true),
    ("ContosoSync", "Contoso Sync Service", "running", "auto", 2640, "LocalSystem", r#""C:\Program Files\Contoso\Sync\ContosoSyncService.exe""#, "Keeps Contoso documents in step with the cloud.", false),
    ("ContosoPrint", "Contoso Print Agent", "running", "delayed-auto", 4820, "LocalSystem", r#""C:\Program Files\Contoso\Print\ContosoPrintAgent.exe" /service"#, "", false),
    ("Dhcp", "DHCP Client", "running", "auto", 1236, r"NT AUTHORITY\LocalService", r"C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p", "Registers and updates IP addresses and DNS records for this computer.", true),
    ("FabrikamUpdate", "Fabrikam Updater", "stopped", "demand", 0, "LocalSystem", r#""C:\Program Files (x86)\Fabrikam\Updater\FabrikamUpdater.exe" /svc"#, "Keeps Fabrikam software up to date.", false),
    ("MpsSvc", "Windows Defender Firewall", "running", "auto", 1408, r"NT AUTHORITY\LocalService", r"C:\Windows\System32\svchost.exe -k LocalServiceNoNetworkFirewall -p", "Helps protect your computer by preventing unauthorized users from gaining access.", true),
    ("Spooler", "Print Spooler", "running", "auto", 2390, "LocalSystem", r"C:\Windows\System32\spoolsv.exe", "Spools print jobs and handles interaction with the printer.", false),
    ("TailspinVPN", "Tailspin VPN", "running", "auto", 4410, "LocalSystem", r#""C:\Program Files\Tailspin\VPN\TailspinVPN.exe""#, "Tailspin VPN tunnel service.", false),
    ("RemoteHelper", "Remote Helper", "stopped", "disabled", 0, "LocalSystem", r"C:\ProgramData\RemoteHelper\rhsvc.exe", "", false),
    ("WinDefend", "Microsoft Defender Antivirus Service", "running", "auto", 2210, "LocalSystem", r#""C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2601.4-0\MsMpEng.exe""#, "Helps protect users from malware and other potentially unwanted software.", true),
    ("wuauserv", "Windows Update", "stopped", "demand", 0, "LocalSystem", r"C:\Windows\System32\svchost.exe -k netsvcs -p", "Enables the detection, download and installation of updates.", true),
];

pub fn services() -> Vec<Row> {
    SERVICES
        .iter()
        .map(
            |&(name, display, state, start, pid, account, path, description, protected)| Row {
                service: Service {
                    name: name.into(),
                    display_name: display.into(),
                    description: description.into(),
                    state: state.into(),
                    start_type: start.into(),
                    pid,
                    service_type: if path.contains("svchost") {
                        "share".into()
                    } else {
                        "own".into()
                    },
                    path: path.into(),
                    executable: path
                        .trim_start_matches('"')
                        .split(".exe")
                        .next()
                        .map(|p| format!("{p}.exe"))
                        .unwrap_or_default(),
                    dll: String::new(),
                    account: account.into(),
                    group: path
                        .split("-k ")
                        .nth(1)
                        .map(|g| g.split(' ').next().unwrap_or("").to_string())
                        .unwrap_or_default(),
                },
                protected,
            },
        )
        .collect()
}

fn entry(id: &str, name: &str, exe: &str, publisher: &str, kind: &str, scope: &str, enabled: bool) -> StartupEntry {
    let location = match (kind, scope) {
        ("folder", "user") => r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup".to_string(),
        (_, "user") => r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run".to_string(),
        _ => r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run".to_string(),
    };
    StartupEntry {
        id: id.into(),
        name: name.into(),
        command: format!("\"{exe}\" --background"),
        executable: exe.into(),
        location,
        kind: kind.into(),
        scope: scope.into(),
        enabled,
        disabled_at_ms: None,
        can_toggle: kind != "run_once",
        approved_key: String::new(),
        value: name.into(),
        file: if kind == "folder" {
            format!(r"C:\Users\jdoe\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\{name}.lnk")
        } else {
            String::new()
        },
        publisher: publisher.into(),
        description: String::new(),
        exists: true,
        host: false,
        own: false,
    }
}

pub fn startup() -> (Vec<StartupEntry>, HashMap<String, StartupSignature>) {
    let rows = vec![
        entry(
            "reg:1",
            "ContosoMail",
            r"C:\Program Files\Contoso\Mail\ContosoMail.exe",
            "Contoso Ltd.",
            "run",
            "user",
            true,
        ),
        entry(
            "reg:2",
            "OneSync",
            r"C:\Users\jdoe\AppData\Local\Contoso\OneSync\OneSync.exe",
            "Contoso Ltd.",
            "run",
            "user",
            true,
        ),
        entry(
            "reg:3",
            "FabrikamChat",
            r"C:\Users\jdoe\AppData\Local\Fabrikam\Chat\Fabrikam.Chat.exe",
            "Fabrikam, Inc.",
            "run",
            "user",
            false,
        ),
        entry(
            "reg:4",
            "SecurityHealth",
            r"C:\Windows\System32\SecurityHealthSystray.exe",
            "Microsoft Corporation",
            "run",
            "machine",
            true,
        ),
        entry(
            "reg:5",
            "TailspinVPN",
            r"C:\Program Files\Tailspin\VPN\TailspinVPN.exe",
            "Tailspin Toys",
            "run",
            "machine",
            true,
        ),
        entry(
            "reg:6",
            "updater",
            r"C:\Users\jdoe\AppData\Roaming\Microsft\updater.exe",
            "",
            "run",
            "user",
            true,
        ),
        entry(
            "fold:1",
            "Woodgrove Notes",
            r"C:\Program Files\Woodgrove\Notes\Notes.exe",
            "Woodgrove Bank",
            "folder",
            "user",
            true,
        ),
    ];
    let signature = |status: &str, signer: &str| StartupSignature {
        status: status.into(),
        signer: signer.into(),
    };
    let signatures = HashMap::from([
        (rows[0].executable.clone(), signature("valid", "Contoso Ltd.")),
        (rows[1].executable.clone(), signature("valid", "Contoso Ltd.")),
        (rows[2].executable.clone(), signature("valid", "Fabrikam, Inc.")),
        (rows[3].executable.clone(), signature("valid", "Microsoft Windows")),
        (rows[4].executable.clone(), signature("valid", "Tailspin Toys")),
        (rows[5].executable.clone(), signature("unsigned", "")),
        (rows[6].executable.clone(), signature("valid", "Woodgrove Bank")),
    ]);
    (rows, signatures)
}

pub fn quarantine() -> Vec<QuarantineEntry> {
    vec![
        QuarantineEntry {
            id: "q-1".into(),
            original_path: r"C:\Users\jdoe\AppData\Roaming\Microsft\updater.exe".into(),
            name: "updater.exe".into(),
            size: 1_482_752,
            sha256: "9f2c4e1a7b3d5f60c8e2a4b6d8f0123456789abcdef0123456789abcdef0123".into(),
            quarantined_at: "2026-11-18T09:42:10".into(),
            reason: "Runs at sign-in from a folder that imitates Microsoft's".into(),
            present: true,
            ..Default::default()
        },
        QuarantineEntry {
            id: "q-2".into(),
            original_path: r"C:\Users\jdoe\Downloads\invoice-scan.pdf.exe".into(),
            name: "invoice-scan.pdf.exe".into(),
            size: 352_256,
            sha256: "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f80".into(),
            quarantined_at: "2026-11-19T16:05:44".into(),
            reason: "Program disguised as a document".into(),
            state: Some("scheduled".into()),
            present: true,
            ..Default::default()
        },
    ]
}

pub fn history() -> Vec<Entry> {
    let record = |id: &str,
                  batch: Option<&str>,
                  time: &str,
                  label: &str,
                  target: &str,
                  item: &str,
                  message: &str,
                  can_undo: bool| Entry {
        id: id.into(),
        batch: batch.map(str::to_string),
        time: time.into(),
        op_label: label.into(),
        target: target.into(),
        item: item.into(),
        ok: true,
        message: message.into(),
        undone: false,
        can_undo,
    };
    let mut failed = record(
        "j-5",
        None,
        "2026-11-20T11:03:12",
        "Stop service",
        "Remote Helper",
        "Remote Helper",
        "the service did not stop in time",
        false,
    );
    failed.ok = false;
    let mut undone = record(
        "j-6",
        None,
        "2026-11-19T08:15:00",
        "Disable startup app",
        "FabrikamChat",
        "FabrikamChat",
        "disabled FabrikamChat",
        true,
    );
    undone.undone = true;
    undone.can_undo = false;
    vec![
        record(
            "j-1",
            Some("b-1"),
            "2026-11-21T09:30:02",
            "End process",
            "updater.exe (PID 4388)",
            "updater.exe",
            "ended updater.exe (PID 4388)",
            false,
        ),
        record(
            "j-2",
            Some("b-1"),
            "2026-11-21T09:30:03",
            "Disable startup entry",
            "updater",
            "updater.exe",
            "disabled updater",
            true,
        ),
        record(
            "j-3",
            Some("b-1"),
            "2026-11-21T09:30:04",
            "Quarantine file",
            r"C:\Users\jdoe\AppData\Roaming\Microsft\updater.exe",
            "updater.exe",
            "moved to quarantine",
            true,
        ),
        record(
            "j-4",
            None,
            "2026-11-20T18:22:40",
            "Efficiency mode",
            "Edgeview.exe (PID 3850)",
            "Edgeview.exe",
            "Efficiency mode on",
            false,
        ),
        failed,
        undone,
    ]
}
