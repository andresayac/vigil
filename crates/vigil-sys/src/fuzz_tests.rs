//! Robustness of the parsers that read data other programs control (event and task XML, files
//! Windows tools write, registry values, kernel buffers): random and mutated input must never
//! panic or stall. Case counts keep the whole file to a few seconds in a debug build.

use windows::Win32::System::Registry::{
    REG_BINARY, REG_DWORD, REG_DWORD_BIG_ENDIAN, REG_EXPAND_SZ, REG_LINK, REG_MULTI_SZ, REG_QWORD, REG_SZ,
    REG_VALUE_TYPE,
};

use crate::fuzz::{Rng, check, check_text};

const EVENT: &str = r#"<?xml version="1.0"?><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Kernel-Power" Guid="{331C3B3A-2005-44C2-AC5E-77220C37D6B4}"/><EventID Qualifiers="0">41</EventID><Version>8</Version><Level>1</Level><TimeCreated SystemTime="2026-11-01T10:00:00.1234567Z"/><EventRecordID>123</EventRecordID><Computer>PC-VICTIM</Computer></System><EventData><Data Name="BugcheckCode">209</Data><Data Name="BugcheckParameter1">0xfffff80312345678</Data><Data Name="LogonType">10</Data><Data Name="IpAddress">203.0.113.5</Data><Data Name="TargetUserName">jdoe</Data><Data Name="Status">0xc000006d</Data><Data Name="updateTitle">2026-11 Cumulative Update (KB5050009)</Data><Data Name="errorCode">0x80073701</Data><Data Name="WakeSourceText">Power Button</Data><Data Name="Name">Contoso Updater</Data><Data Name="DegradationTime">1500</Data><Data>&amp;&lt;&#65;&#x42;</Data></EventData></Event>"#;

const TASK: &str = r#"<?xml version="1.0" encoding="UTF-16"?><Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><RegistrationInfo><Author>PC-VICTIM\jdoe</Author><Date>2026-11-01T10:00:00</Date><Description>Contoso &amp; updater</Description></RegistrationInfo><Triggers><LogonTrigger><Enabled>true</Enabled><Delay>PT30S</Delay></LogonTrigger><CalendarTrigger><StartBoundary>2026-11-01T03:00:00</StartBoundary><Repetition><Interval>PT1H</Interval><Duration>P1D</Duration></Repetition><ScheduleByWeek><WeeksInterval>2</WeeksInterval><DaysOfWeek><Monday/><Friday/></DaysOfWeek></ScheduleByWeek></CalendarTrigger></Triggers><Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><WakeToRun>true</WakeToRun><Hidden>true</Hidden></Settings><Actions Context="Author"><Exec><Command>"C:\Users\jdoe\AppData\Roaming\upd.exe"</Command><Arguments>-q &quot;x&quot;</Arguments><WorkingDirectory>%TEMP%</WorkingDirectory></Exec><ComHandler><ClassId>{00000000-0000-0000-0000-000000000000}</ClassId></ComHandler></Actions></Task>"#;

const XML_TOKENS: &[&str] = &[
    "<",
    ">",
    "</",
    "/>",
    "<Event>",
    "</Event>",
    "<Data Name=\"",
    "\">",
    "</Data>",
    "<![CDATA[",
    "]]>",
    "<!--",
    "-->",
    "&amp;",
    "&#x41;",
    "&#99999999;",
    "&#;",
    "&#x110000;",
    "&#xD800;",
    "<?xml version=\"1.0\"?>",
    "=\"",
    "\"",
    "'",
    " ",
    "<EventID>",
    "</EventID>",
    "SystemTime=\"",
    "2026-11-01T10:00:00Z",
    "<System>",
    "</System>",
    "<EventData>",
    "</EventData>",
    "0x",
    "4294967295",
    "18446744073709551616",
    "-1",
    "PT",
    "P99999999D",
    "<Exec>",
    "<Command>",
];

const LINE_TOKENS: &[&str] = &[
    "DISPLAY:",
    "SYSTEM:",
    "AWAYMODE:",
    "EXECUTION:",
    "PERFBOOST:",
    "ACTIVELOCKSCREEN:",
    "None.",
    "[PROCESS] ",
    "[DRIVER] ",
    "[SERVICE] ",
    "\\Device\\HarddiskVolume3\\",
    "\r\n",
    "\n",
    "NONE",
    ":",
    "  ",
    "HID Keyboard Device",
];

/// Event XML: random tokens and mutations of a real-shaped event, through every event reader.
#[test]
fn event_readers_survive_any_xml() {
    let mut rng = Rng::new(1);
    // The sample is a real-shaped event, so its mutations reach the field readers.
    assert!(crate::xml::parse_xml(EVENT).is_some());
    for case in 0..1_500 {
        let xml = if case % 3 == 0 {
            rng.text(40, XML_TOKENS)
        } else {
            rng.mutate_text(EVENT, XML_TOKENS)
        };
        check_text("event readers", &xml, || {
            let _ = crate::xml::parse_xml(&xml);
            let _ = crate::xml::unescape(&xml);
            let _ = crate::reliability::event_from_xml(&xml, &xml);
            let _ = crate::reliability::boot_from_xml(&xml);
            let _ = crate::signins::event_from_xml(&xml, |_| true);
            let _ = crate::updates::entry_from_event(&xml);
            let _ = crate::power::event_from(&xml);
            let _ = crate::bootimpact::degradation_from_xml(&xml);
            let _ = crate::bootimpact::parse_startup_info(&xml, 0);
            let _ = crate::drvblock::blocked_event(&xml);
        });
    }
}

/// Task definitions are written by whoever registered the task.
#[test]
fn task_readers_survive_any_xml() {
    let mut rng = Rng::new(2);
    assert!(
        !crate::tasks::from_xml(r"\x", TASK).actions.is_empty(),
        "the sample task parses"
    );
    for case in 0..1_200 {
        let xml = if case % 4 == 0 {
            rng.text(40, XML_TOKENS)
        } else {
            rng.mutate_text(TASK, XML_TOKENS)
        };
        check_text("task readers", &xml, || {
            let task = crate::tasks::from_xml(r"\Contoso\Updater", &xml);
            let _ = crate::tasks::file_actions(r"\Contoso\Updater", &xml);
            let _ = crate::power::wake_tasks(&[task]);
        });
    }
}

/// Task files on disk: any bytes, with or without a UTF-16 byte order mark.
#[test]
fn task_files_decode_any_bytes() {
    let mut rng = Rng::new(3);
    let utf16: Vec<u8> = [0xFF, 0xFE]
        .into_iter()
        .chain(TASK.encode_utf16().flat_map(u16::to_le_bytes))
        .collect();
    for case in 0..1_500 {
        let bytes = match case % 3 {
            0 => rng.bytes(512),
            1 => rng.mutate(&utf16[..utf16.len().min(400)]),
            _ => rng.mutate(TASK.as_bytes()),
        };
        check("task file", &bytes, || {
            let text = crate::tasks::decode_task_file(&bytes);
            let _ = crate::tasks::from_xml(r"\x", &text);
            let _ = crate::bootimpact::decode(&bytes);
        });
    }
}

/// Durations, dates and times from untrusted text and numbers.
#[test]
fn durations_dates_and_times_survive_anything() {
    let mut rng = Rng::new(4);
    let tokens = &[
        "P",
        "T",
        "D",
        "H",
        "M",
        "S",
        "W",
        "Y",
        ".",
        "-",
        "+",
        "Z",
        ":",
        "9",
        "99999999999999999999",
        "0",
    ];
    for _ in 0..3_000 {
        let text = rng.text(12, tokens);
        check_text("durations and dates", &text, || {
            let _ = crate::tasks::duration_secs(&text);
            let _ = crate::reliability::iso_utc_ms(&text);
            let _ = crate::updates::kb_of(&text);
            let _ = crate::updates::newest_version([text.clone(), "10.0.26100.1".to_string()]);
            let _ = crate::reliability::clean_message(&text);
        });
    }
    for value in [i64::MIN, -1, 0, 1, i64::MAX, 253_402_300_800_000, -62_135_596_800_000] {
        check("local time", &value.to_le_bytes(), || {
            let _ = crate::reliability::local_time(value);
        });
    }
    for value in [
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::MAX,
        f64::MIN,
        0.0,
        -1e300,
        1e300,
    ] {
        check("OLE date", &value.to_le_bytes(), || {
            let _ = crate::updates::ole_date_ms(value);
        });
    }
}

/// `powercfg` output: whatever the tool, its language or a hostile driver name puts in it.
#[test]
fn powercfg_output_parses_anything() {
    let mut rng = Rng::new(5);
    let sample = "DISPLAY:\r\n[PROCESS] \\Device\\HarddiskVolume3\\Program Files\\Contoso\\player.exe\r\nVideo Wake Lock\r\n\r\nSYSTEM:\r\nNone.\r\n\r\nAWAYMODE:\r\nNone.\r\n";
    for case in 0..2_000 {
        let text = if case % 2 == 0 {
            rng.text(30, LINE_TOKENS)
        } else {
            rng.mutate_text(sample, LINE_TOKENS)
        };
        check_text("powercfg", &text, || {
            let _ = crate::power::parse_requests(&text);
            let _ = crate::power::parse_device_list(&text);
        });
    }
}

/// Registry values of any type and length: odd byte counts, missing terminators, empty data.
#[test]
fn registry_values_decode_any_data() {
    let mut rng = Rng::new(6);
    let kinds: [REG_VALUE_TYPE; 9] = [
        REG_SZ,
        REG_EXPAND_SZ,
        REG_BINARY,
        REG_DWORD,
        REG_DWORD_BIG_ENDIAN,
        REG_LINK,
        REG_MULTI_SZ,
        REG_QWORD,
        REG_VALUE_TYPE(0xFFFF_FFFF),
    ];
    for _ in 0..4_000 {
        let kind = kinds[rng.below(kinds.len())];
        let data = rng.bytes(300);
        check("registry value", &data, || {
            let _ = crate::hooks::text(kind, &data);
        });
    }
}

/// Binary structures read from the registry or the kernel.
#[test]
fn binary_structures_survive_any_bytes() {
    let mut rng = Rng::new(7);
    // A task cache Actions blob: version, then a counted UTF-16 string.
    let mut actions = vec![3u8, 0];
    actions.extend_from_slice(&0x6666u16.to_le_bytes());
    actions.extend_from_slice(&0u32.to_le_bytes());
    let command: Vec<u8> = "C:\\x.exe".encode_utf16().flat_map(u16::to_le_bytes).collect();
    actions.extend_from_slice(&(command.len() as u32).to_le_bytes());
    actions.extend_from_slice(&command);
    for case in 0..3_000 {
        let blob = if case % 2 == 0 {
            rng.bytes(256)
        } else {
            rng.mutate(&actions)
        };
        let offset = rng.below(blob.len() + 8);
        // An offset near the top of the address range tests the overflow guard.
        let far = usize::MAX - offset % 16;
        check("binary structures", &blob, || {
            let _ = crate::svcsec::parse_actions(&blob);
            let _ = crate::nt::unicode_string_at(&blob, offset);
            let _ = crate::nt::unicode_string_at(&blob, far);
        });
    }
}

/// Encoded trust lists handed to CryptoAPI: garbage must be refused, not crash.
#[test]
fn certificate_trust_lists_refuse_garbage() {
    let mut rng = Rng::new(8);
    for _ in 0..300 {
        let encoded = rng.bytes(200);
        check("trust list", &encoded, || {
            let _ = crate::certs::ctl_thumbprints(&encoded);
        });
    }
}

/// Driver paths from service keys any administrator program can write.
#[test]
fn driver_paths_survive_anything() {
    let mut rng = Rng::new(9);
    let tokens = &[
        "\\SystemRoot\\",
        "System32\\drivers\\",
        "\\??\\",
        "\\\\?\\",
        "C:\\Windows\\",
        "..\\",
        "DriverStore\\",
        "%SystemRoot%\\",
        "x.sys",
        "\\",
        "/",
        ".",
    ];
    for _ in 0..3_000 {
        let path = rng.text(10, tokens);
        check_text("driver path", &path, || {
            let _ = crate::hooks::standard_driver_path(&path);
        });
    }
}

/// Battery figures come from the battery's own driver: any value, including zero, "unknown" and
/// the extremes, gives a battery description without a panic, and the percentages stay in range.
#[test]
fn battery_figures_decode_any_values() {
    use windows::Win32::System::Power::{BATTERY_INFORMATION, BATTERY_STATUS};
    let mut rng = Rng::new(11);
    let pick = |rng: &mut Rng| [0u32, 1, 99, 0xFFFF_FFFF, 0x7FFF_FFFF, rng.next() as u32][rng.below(6)];
    for _ in 0..3_000 {
        let mut chemistry = [0u8; 4];
        for b in &mut chemistry {
            *b = rng.byte();
        }
        let info = BATTERY_INFORMATION {
            Capabilities: pick(&mut rng),
            Technology: rng.byte(),
            Reserved: [0; 3],
            Chemistry: chemistry,
            DesignedCapacity: pick(&mut rng),
            FullChargedCapacity: pick(&mut rng),
            DefaultAlert1: pick(&mut rng),
            DefaultAlert2: pick(&mut rng),
            CriticalBias: pick(&mut rng),
            CycleCount: pick(&mut rng),
        };
        let status = BATTERY_STATUS {
            PowerState: pick(&mut rng),
            Capacity: pick(&mut rng),
            Voltage: pick(&mut rng),
            Rate: pick(&mut rng) as i32,
        };
        let estimate = pick(&mut rng);
        let shown = [info.DesignedCapacity, info.FullChargedCapacity, status.Capacity];
        let bytes: Vec<u8> = shown.iter().flat_map(|v| v.to_le_bytes()).collect();
        check("battery figures", &bytes, || {
            let battery = crate::power::battery_from(&info, Some(&status), String::new(), String::new(), estimate);
            if let Some(charge) = battery.charge_percent {
                assert!(charge <= 100, "charge {charge}");
            }
        });
    }
}
