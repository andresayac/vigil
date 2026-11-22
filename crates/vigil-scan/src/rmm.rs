//! Remote access and remote management (RMM) agents: who can control this computer from
//! elsewhere. READ-ONLY: the inventory already lists services, processes, connections and file
//! signatures; [`collect_config`] only adds a few local settings, as yes/no answers (a password
//! being set, never the password itself).
//!
//! An agent is recognized by its service, its program's name and folder, and its version data
//! (product, company, original file name), not by a display name alone, so a renamed copy is
//! still found. [`items`] reports an agent when it starts with Windows or when something about it
//! deserves a look:
//!
//! - signed by someone other than its maker, or not signed (high);
//! - renamed: its version data names the agent but its file name does not (high);
//! - a relay server that is not its maker's (worth a look; an IP address alone is high);
//! - installed in the last 7 days, or a portable copy running from a folder users can change
//!   (worth a look);
//! - unattended access set up, i.e. a permanent password (adds a little).
//!
//! An agent that runs now and then from its install folder, properly signed, gets no item: the
//! file's own finding already says it is a remote access tool.

use std::collections::BTreeMap;

use chrono::{Local, NaiveDate, NaiveDateTime};
use serde_json::{Map, Value, json};
use vigil_i18n::tr;

use crate::cmdline::parse_command;
use crate::lenient::{Get, int_of, list, lower, rx, strip, take, text};
use crate::model::{Flag, Item};
use crate::ntpath::basename;
use crate::rules::is_user_writable;

/// One remote access or remote management product.
pub(crate) struct Agent {
    pub(crate) id: &'static str,
    pub(crate) name: &'static str,
    /// Lower-case words matched at the start of a word in the program's file name, its service
    /// name, its folder or its version data.
    pub(crate) tokens: &'static [&'static str],
    /// Lower-case parts of the expected signer's name; empty when the maker does not sign a fixed
    /// way (self-hosted agents are signed by whoever runs the server).
    pub(crate) signers: &'static [&'static str],
    /// The maker's relay domains (lower case, with the leading dot); empty when not known.
    pub(crate) relays: &'static [&'static str],
}

/// The agents Vigil recognizes. The broader name pattern in `rules.rs` (`REMOTE_TOOLS`) also
/// covers VNC servers and tunnelling tools; this table adds what is needed to judge an agent.
pub(crate) const AGENTS: &[Agent] = &[
    Agent {
        id: "anydesk",
        name: "AnyDesk",
        tokens: &["anydesk"],
        signers: &["anydesk", "philandro"],
        relays: &[],
    },
    Agent {
        id: "teamviewer",
        name: "TeamViewer",
        tokens: &["teamviewer", "tv_w32", "tv_x64"],
        signers: &["teamviewer"],
        relays: &[],
    },
    Agent {
        id: "rustdesk",
        name: "RustDesk",
        tokens: &["rustdesk"],
        signers: &["purslane", "rustdesk"],
        relays: &[],
    },
    Agent {
        id: "screenconnect",
        name: "ScreenConnect (ConnectWise Control)",
        tokens: &["screenconnect", "connectwise control"],
        signers: &["connectwise"],
        relays: &[".screenconnect.com", ".connectwise.com", ".hostedrmm.com"],
    },
    Agent {
        id: "splashtop",
        name: "Splashtop",
        tokens: &["splashtop", "srservice", "srmanager", "srfeature", "strwinclt"],
        signers: &["splashtop"],
        relays: &[],
    },
    Agent {
        id: "atera",
        name: "Atera",
        tokens: &["atera", "ateraagent"],
        signers: &["atera"],
        relays: &[],
    },
    Agent {
        id: "ninjaone",
        name: "NinjaOne",
        tokens: &["ninjarmm", "ninjaone", "ninjarmmagent"],
        signers: &["ninjarmm", "ninjaone"],
        relays: &[],
    },
    Agent {
        id: "kaseya",
        name: "Kaseya",
        tokens: &["kaseya", "agentmon", "kasetup"],
        signers: &["kaseya"],
        relays: &[],
    },
    Agent {
        id: "nable",
        name: "N-able",
        tokens: &[
            "n-able",
            "solarwinds msp",
            "basupsrvc",
            "basupsrvcupdater",
            "advanced monitoring agent",
        ],
        signers: &["n-able", "solarwinds"],
        relays: &[],
    },
    Agent {
        id: "action1",
        name: "Action1",
        tokens: &["action1"],
        signers: &["action1"],
        relays: &[],
    },
    Agent {
        id: "meshcentral",
        name: "MeshCentral",
        tokens: &["meshagent", "meshcentral", "mesh agent"],
        signers: &[],
        relays: &[],
    },
    Agent {
        id: "tacticalrmm",
        name: "Tactical RMM",
        tokens: &["tacticalrmm", "tacticalagent", "tactical rmm"],
        signers: &["amidaware"],
        relays: &[],
    },
    Agent {
        id: "remoteutilities",
        name: "Remote Utilities",
        tokens: &["remote utilities", "rutserv", "rfusclient"],
        signers: &["remote utilities", "usoris"],
        relays: &[],
    },
    Agent {
        id: "chromeremotedesktop",
        name: "Chrome Remote Desktop",
        tokens: &["remoting_host", "chromoting", "chrome remote desktop"],
        signers: &["google"],
        relays: &[],
    },
    Agent {
        id: "parsec",
        name: "Parsec",
        tokens: &["parsecd", "parsec"],
        signers: &["parsec"],
        relays: &[],
    },
    Agent {
        id: "logmein",
        name: "LogMeIn",
        tokens: &["logmein", "lmiguardian", "lmi_rescue"],
        signers: &["logmein", "goto"],
        relays: &[],
    },
    Agent {
        id: "goto",
        name: "GoTo Resolve / GoTo Assist",
        tokens: &["gotoassist", "goto resolve", "gotoresolve"],
        signers: &["goto", "logmein"],
        relays: &[],
    },
    Agent {
        id: "zohoassist",
        name: "Zoho Assist",
        tokens: &["zoho assist", "zohomeeting", "zaservice", "za_connect"],
        signers: &["zoho"],
        relays: &[],
    },
    Agent {
        id: "dwservice",
        name: "DWService",
        tokens: &["dwagent", "dwservice", "dwagsvc"],
        signers: &[],
        relays: &[],
    },
    Agent {
        id: "supremo",
        name: "Supremo",
        tokens: &["supremo"],
        signers: &["nanosystems"],
        relays: &[],
    },
    Agent {
        id: "aeroadmin",
        name: "AeroAdmin",
        tokens: &["aeroadmin"],
        signers: &["aeroadmin"],
        relays: &[],
    },
    Agent {
        id: "netsupport",
        name: "NetSupport Manager",
        tokens: &["netsupport", "client32"],
        signers: &["netsupport"],
        relays: &[],
    },
];

/// `token` at the start of a word of `hay` (both lower case): "srservice" in "srservice.exe",
/// not "atera" inside "literature".
fn word_match(hay: &str, token: &str) -> bool {
    hay.match_indices(token)
        .any(|(at, _)| hay[..at].chars().next_back().is_none_or(|c| !c.is_alphanumeric()))
}

/// The agent a text names (a program's file name, service, folder or version data).
pub(crate) fn agent_for(text: &str) -> Option<&'static Agent> {
    let hay = lower(text);
    if hay.is_empty() {
        return None;
    }
    AGENTS
        .iter()
        .find(|agent| agent.tokens.iter().any(|token| word_match(&hay, token)))
}

// --------------------------------------------------------------------------- local settings

/// Whether a small text file has a `key=value` line (or `key = 'value'`) with a non-empty value.
/// Only the answer is kept, never the value.
fn has_setting(path: &std::path::Path, key: &str) -> Option<bool> {
    let bytes = read_head(path)?;
    let text = String::from_utf8_lossy(&bytes).to_string();
    Some(setting(&text, key).is_some_and(|v| !v.is_empty()))
}

/// The first 64 KiB of a settings file, read without loading the rest: these files sit in folders
/// the user can write to, so a huge one must not exhaust memory in an elevated scan.
fn read_head(path: &std::path::Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let file = std::fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take(64 * 1024).read_to_end(&mut bytes).ok()?;
    Some(bytes)
}

/// The value of `key` in a `key=value` / `key = 'value'` text (TOML-like or AnyDesk's .conf).
fn setting<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines().find_map(|line| {
        let (name, value) = line.split_once('=')?;
        (name.trim() == key).then(|| value.trim().trim_matches(|c| c == '\'' || c == '"'))
    })
}

fn env_path(var: &str, rest: &[&str]) -> Option<std::path::PathBuf> {
    let mut path = std::path::PathBuf::from(std::env::var_os(var)?);
    for part in rest {
        path.push(part);
    }
    Some(path)
}

#[cfg(windows)]
fn teamviewer_password() -> Option<bool> {
    use crate::winreg::{self, Hive, View};
    let mut seen = false;
    for view in [View::V64, View::V32] {
        let values = winreg::values(Hive::Hklm, r"SOFTWARE\TeamViewer", view);
        if values.is_empty() {
            continue;
        }
        seen = true;
        if values
            .iter()
            .any(|(name, data)| matches!(name.as_str(), "SecurityPasswordAES" | "PermanentPassword") && data.truthy())
        {
            return Some(true);
        }
    }
    seen.then_some(false)
}

#[cfg(not(windows))]
fn teamviewer_password() -> Option<bool> {
    None
}

/// A few yes/no answers from the agents' own settings: whether unattended access with a permanent
/// password is set up, and a self-hosted relay server's address (not a secret). Never a password.
pub(crate) fn collect_config() -> Value {
    let anydesk = [
        env_path("ProgramData", &["AnyDesk", "system.conf"]),
        env_path("APPDATA", &["AnyDesk", "system.conf"]),
    ]
    .into_iter()
    .flatten()
    .filter_map(|p| has_setting(&p, "ad.anynet.pwd_hash"))
    .reduce(|a, b| a || b);
    let rustdesk_dirs = [
        env_path("APPDATA", &["RustDesk", "config"]),
        env_path(
            "SystemRoot",
            &[
                "ServiceProfiles",
                "LocalService",
                "AppData",
                "Roaming",
                "RustDesk",
                "config",
            ],
        ),
    ];
    let mut rustdesk_password = None;
    let mut rustdesk_server = String::new();
    for dir in rustdesk_dirs.into_iter().flatten() {
        if let Some(set) = has_setting(&dir.join("RustDesk.toml"), "password") {
            rustdesk_password = Some(rustdesk_password.unwrap_or(false) || set);
        }
        if rustdesk_server.is_empty()
            && let Some(bytes) = read_head(&dir.join("RustDesk2.toml"))
        {
            let text = String::from_utf8_lossy(&bytes).to_string();
            rustdesk_server = setting(&text, "custom-rendezvous-server")
                .or_else(|| setting(&text, "relay-server"))
                .map(|s| take(strip(s), 255).to_string())
                .unwrap_or_default();
        }
    }
    json!({
        "teamviewer_password": teamviewer_password(),
        "anydesk_unattended": anydesk,
        "rustdesk_password": rustdesk_password,
        "rustdesk_server": rustdesk_server,
    })
}

// --------------------------------------------------------------------------- judging

rx!(RELAY_HOST, r#"(?i)[?&]h=([^&"\s]+)"#);
rx!(IP_HOST, r"^\[?[0-9a-f:.]+\]?(:\d+)?$");

/// Days between an ISO date and the scan (its start time when known, so a saved inventory is
/// judged as it was).
fn days_between(iso: &str, reference: Option<NaiveDateTime>) -> Option<i64> {
    let head = take(iso, 19);
    let parsed = NaiveDateTime::parse_from_str(head, "%Y-%m-%dT%H:%M:%S")
        .or_else(|_| NaiveDateTime::parse_from_str(head, "%Y-%m-%d %H:%M:%S"))
        .ok()
        .or_else(|| {
            NaiveDate::parse_from_str(take(iso, 10), "%Y-%m-%d")
                .ok()
                .and_then(|d| d.and_hms_opt(0, 0, 0))
        })?;
    let now = reference.unwrap_or_else(|| Local::now().naive_local());
    Some((now - parsed).num_seconds().div_euclid(86_400))
}

fn reference_time(raw: &Value) -> Option<NaiveDateTime> {
    let started = text(raw.at("meta").at("started"));
    NaiveDateTime::parse_from_str(take(&started, 19), "%Y-%m-%dT%H:%M:%S").ok()
}

#[derive(Default)]
struct Found<'a> {
    path: String,
    services: Vec<&'a Value>,
    pids: Vec<i64>,
}

fn loopback(address: &str) -> bool {
    address.starts_with("127.") || address == "::1" || address.is_empty() || address == "0.0.0.0" || address == "::"
}

fn signer_matches(agent: &Agent, signer: &str) -> bool {
    let signer = lower(signer);
    agent.signers.iter().any(|s| signer.contains(s))
}

fn config(title: String, score: i64, text: String, facts: Map<String, Value>, extra: Vec<Flag>) -> Item {
    let mut item = Item::new("config", title, text.clone());
    let mut all = Map::new();
    all.insert("topic".into(), json!("rmm_agent"));
    all.extend(facts);
    item.facts = all;
    item.add_flag(Flag::new("rmm_agent", score, text));
    for flag in extra {
        item.add_flag(flag);
    }
    item.rescore();
    item
}

/// The remote access agents worth reporting (see the module comment).
pub(crate) fn items(raw: &Value) -> Vec<Item> {
    let files = raw.at("files");
    let reference = reference_time(raw);
    let settings = raw.at("sysconfig").at("remote_agents");

    // Every program a service or a process runs, once.
    let mut found: BTreeMap<String, Found> = BTreeMap::new();
    for svc in list(raw.at("services")) {
        let Some(program) = parse_command(&text(svc.at("path")), None)
            .program
            .filter(|p| !p.is_empty())
        else {
            continue;
        };
        let entry = found.entry(lower(&program)).or_default();
        entry.path = program;
        entry.services.push(svc);
        let pid = int_of(svc.at("pid"));
        if pid > 0 {
            entry.pids.push(pid);
        }
    }
    for process in list(raw.at("processes")) {
        let path = text(process.at("path"));
        if path.is_empty() {
            continue;
        }
        let entry = found.entry(lower(&path)).or_default();
        entry.path = path;
        let pid = int_of(process.at("pid"));
        if pid > 0 {
            entry.pids.push(pid);
        }
    }

    let tcp = list(raw.at("network").at("tcp"));
    let mut out = Vec::new();
    for (key, entry) in &found {
        let info = files.at(key);
        let file_name = basename(&entry.path).to_string();
        let folder = take(&entry.path, entry.path.len().saturating_sub(file_name.len())).to_string();
        let service_names: Vec<String> = entry
            .services
            .iter()
            .flat_map(|s| [text(s.at("name")), text(s.at("display"))])
            .collect();
        let by_name = agent_for(&format!("{file_name} {}", service_names.join(" "))).or_else(|| agent_for(&folder));
        let metadata = ["original", "product", "description", "company"]
            .iter()
            .map(|k| text(info.at(k)))
            .collect::<Vec<_>>()
            .join(" ");
        let by_data = agent_for(&metadata);
        let Some(agent) = by_name.or(by_data) else {
            continue;
        };
        // The version data names an agent the file and service names do not mention.
        let renamed = by_name.is_none();

        let at_boot = entry.services.iter().any(|s| {
            matches!(
                lower(&text(s.at("start"))).as_str(),
                "auto" | "automatic" | "boot" | "system"
            )
        });
        let service = entry.services.first().map(|s| text(s.at("name"))).unwrap_or_default();
        let listening = tcp.iter().any(|c| {
            entry.pids.contains(&int_of(c.at("pid")))
                && lower(&text(c.at("state"))) == "listen"
                && !text(c.at("laddr")).starts_with("127.")
                && text(c.at("laddr")) != "::1"
        });
        let connected = tcp.iter().any(|c| {
            entry.pids.contains(&int_of(c.at("pid")))
                && lower(&text(c.at("state"))) == "established"
                && !loopback(&text(c.at("raddr")))
        });

        let sig_status = text(info.at("sig_status"));
        let signer = text(info.at("signer"));
        let signature_known = !sig_status.is_empty();
        let signed_by_maker = sig_status == "Valid" && signer_matches(agent, &signer);
        let mismatch = signature_known && !agent.signers.is_empty() && !signed_by_maker;

        let created = text(info.at("created"));
        let installed = if created.is_empty() {
            list(raw.at("programs"))
                .iter()
                .find(|p| {
                    agent_for(&format!("{} {}", text(p.at("name")), text(p.at("publisher"))))
                        .is_some_and(|a| a.id == agent.id)
                })
                .map(|p| text(p.at("installed")))
                .unwrap_or_default()
        } else {
            created
        };
        let recent = days_between(&installed, reference).is_some_and(|d| (0..=7).contains(&d));
        let lower_path = lower(&entry.path);
        let portable = is_user_writable(&entry.path) && !lower_path.contains("\\program files");

        let relay = entry
            .services
            .iter()
            .find_map(|s| RELAY_HOST.captures(&text(s.at("path"))).map(|c| c[1].to_string()))
            .or_else(|| {
                (agent.id == "rustdesk")
                    .then(|| text(settings.at("rustdesk_server")))
                    .filter(|s| !s.is_empty())
            })
            .unwrap_or_default();
        let relay_host = lower(relay.split(':').next().unwrap_or(""));
        let relay_ip = !relay.is_empty() && IP_HOST.is_match(&relay);
        let relay_own = !relay_host.is_empty()
            && agent
                .relays
                .iter()
                .any(|d| relay_host.ends_with(d) || format!(".{relay_host}") == *d);
        let relay_odd = !relay.is_empty() && !relay_own;

        let unattended = match agent.id {
            "teamviewer" => settings.at("teamviewer_password").as_bool(),
            "anydesk" => settings.at("anydesk_unattended").as_bool(),
            "rustdesk" => settings.at("rustdesk_password").as_bool(),
            _ => None,
        };

        let mut flags = Vec::new();
        if mismatch {
            flags.push(Flag::new(
                "rmm_signature",
                70,
                if sig_status == "Valid" {
                    tr!("signed by \"{0}\", not by the maker of {1}", signer, agent.name)
                } else {
                    tr!("not signed by the maker of {0}: a modified or fake copy", agent.name)
                },
            ));
        }
        if renamed {
            flags.push(Flag::new(
                "rmm_renamed",
                70,
                tr!(
                    "the file \"{0}\" is really {1}: remote access tools are renamed to hide them",
                    file_name,
                    agent.name
                ),
            ));
        }
        if relay_odd {
            flags.push(Flag::new(
                "rmm_relay",
                if relay_ip { 60 } else { 45 },
                tr!(
                    "connects through the server {0}, not one of its maker's; IT providers run their own, so do attackers",
                    relay
                ),
            ));
        }
        if recent {
            flags.push(Flag::new("rmm_recent", 35, tr!("installed in the last 7 days")));
        }
        if portable {
            flags.push(Flag::new(
                "rmm_portable",
                35,
                tr!("runs from a folder standard users can change (a copy downloaded and run, not installed)"),
            ));
        }
        if unattended == Some(true) {
            flags.push(Flag::new(
                "rmm_unattended",
                10,
                tr!("unattended access is set up: whoever has its password can connect at any time"),
            ));
        }
        if !at_boot && flags.iter().all(|f| f.code == "rmm_unattended") {
            continue;
        }

        let mut facts_text = Vec::new();
        facts_text.push(if at_boot {
            tr!("it starts with Windows")
        } else {
            tr!("it does not start with Windows")
        });
        if signature_known {
            facts_text.push(if sig_status == "Valid" {
                tr!("signed by {0}", signer)
            } else {
                tr!("not signed")
            });
        }
        if !installed.is_empty() {
            facts_text.push(tr!("installed on {0}", take(&installed, 10)));
        }
        match unattended {
            Some(true) => facts_text.push(tr!("unattended access: set")),
            Some(false) => facts_text.push(tr!("unattended access: not set")),
            None => {}
        }
        if listening {
            facts_text.push(tr!("waiting for connections now"));
        }
        if connected {
            facts_text.push(tr!("connected now"));
        }
        let summary = tr!(
            "{0} lets someone control this computer from elsewhere: {1}.",
            agent.name,
            facts_text.join("; ")
        );
        let facts = [
            ("agent", json!(agent.name)),
            ("path", json!(entry.path)),
            ("service", json!(service)),
            ("starts_with_windows", json!(at_boot)),
            ("signer", json!(signer)),
            ("signed_by_maker", json!(signed_by_maker)),
            ("installed", json!(take(&installed, 10))),
            ("unattended_access", json!(unattended)),
            ("relay", json!(relay)),
            ("listening", json!(listening)),
            ("connected", json!(connected)),
            ("running", json!(!entry.pids.is_empty())),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        // Installed, signed and starting with Windows: information only.
        out.push(config(
            tr!("Remote access agent: {0}", agent.name),
            10,
            summary,
            facts,
            flags,
        ));
    }
    out.sort_by_key(|i| std::cmp::Reverse(i.score));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_files_are_read_up_to_64_kib() {
        let dir = std::env::temp_dir().join(format!("vigil-rmm-head-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let big = dir.join("system.conf");
        let mut text = String::from("ad.anynet.pwd_hash=abc\n");
        text.push_str(&"x".repeat(200 * 1024));
        std::fs::write(&big, &text).ok();
        assert_eq!(read_head(&big).map(|b| b.len()), Some(64 * 1024));
        assert_eq!(has_setting(&big, "ad.anynet.pwd_hash"), Some(true));
        assert_eq!(read_head(&dir.join("missing.conf")), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn by(id: &str) -> &'static Agent {
        AGENTS.iter().find(|a| a.id == id).expect("agent")
    }

    #[test]
    fn agents_are_found_by_words_not_by_parts_of_words() {
        assert_eq!(agent_for("AnyDesk.exe").map(|a| a.id), Some("anydesk"));
        assert_eq!(agent_for("SRService.exe").map(|a| a.id), Some("splashtop"));
        assert_eq!(
            agent_for(r"C:\Program Files\ATERA Networks\AteraAgent").map(|a| a.id),
            Some("atera")
        );
        assert_eq!(
            agent_for("remoting_host.exe").map(|a| a.id),
            Some("chromeremotedesktop")
        );
        assert!(agent_for("literature.exe").is_none());
        assert!(agent_for("notepad.exe").is_none());
        assert!(agent_for("").is_none());
        assert!(crate::rules::is_remote_access_tool("Action1 Agent"));
    }

    #[test]
    fn settings_are_read_as_yes_or_no() {
        let conf = "ad.anynet.alias=\nad.anynet.pwd_hash=abcdef\n";
        assert_eq!(setting(conf, "ad.anynet.pwd_hash"), Some("abcdef"));
        assert_eq!(setting(conf, "ad.anynet.alias"), Some(""));
        let toml = "password = ''\ncustom-rendezvous-server = 'rd.contoso.example'\n";
        assert_eq!(setting(toml, "password"), Some(""));
        assert_eq!(setting(toml, "custom-rendezvous-server"), Some("rd.contoso.example"));
        assert!(signer_matches(by("anydesk"), "philandro Software GmbH"));
        assert!(!signer_matches(by("anydesk"), "Fake Co"));
    }

    fn inventory(services: Value, processes: Value, files: Value, extra: Value) -> Value {
        let mut raw = json!({
            "meta": {"started": "2026-03-10T10:00:00"},
            "services": services,
            "processes": processes,
            "files": files,
            "network": {"tcp": [
                {"state": "Listen", "laddr": "0.0.0.0", "lport": 7070, "raddr": "0.0.0.0", "rport": 0, "pid": 3100},
                {"state": "Established", "laddr": "192.168.1.5", "lport": 50200, "raddr": "203.0.113.9", "rport": 443, "pid": 3100}
            ]},
            "programs": [],
            "sysconfig": {"remote_agents": {"anydesk_unattended": true}},
        });
        if let (Some(map), Some(more)) = (raw.as_object_mut(), extra.as_object()) {
            for (k, v) in more {
                map.insert(k.clone(), v.clone());
            }
        }
        raw
    }

    #[test]
    fn an_installed_signed_agent_is_information() {
        let raw = inventory(
            json!([{"name": "AnyDesk", "display": "AnyDesk Service", "state": "Running", "start": "Auto",
                    "path": "\"C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe\" --service", "pid": 3100}]),
            json!([]),
            json!({"c:\\program files (x86)\\anydesk\\anydesk.exe": {"exists": true, "sig_status": "Valid",
                    "signer": "philandro Software GmbH", "created": "2025-01-02T08:00:00"}}),
            json!({}),
        );
        let items = items(&raw);
        assert_eq!(items.len(), 1);
        let item = &items[0];
        assert_eq!(item.facts["agent"], "AnyDesk");
        assert_eq!(item.facts["starts_with_windows"], true);
        assert_eq!(item.facts["signed_by_maker"], true);
        assert_eq!(item.facts["unattended_access"], true);
        assert_eq!(item.facts["listening"], true);
        assert_eq!(item.facts["connected"], true);
        let codes: Vec<&str> = item.flags.iter().map(|f| f.code.as_str()).collect();
        assert_eq!(codes, ["rmm_agent", "rmm_unattended"]);
        assert!(item.score <= 25, "{}", item.score);
    }

    #[test]
    fn an_agent_run_now_and_then_from_its_folder_is_left_to_the_file_finding() {
        let raw = inventory(
            json!([]),
            json!([{"pid": 5800, "name": "AnyDesk.exe", "path": "C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe"}]),
            json!({"c:\\program files (x86)\\anydesk\\anydesk.exe": {"exists": true, "sig_status": "Valid",
                    "signer": "philandro Software GmbH", "issuer": "DigiCert"}}),
            json!({}),
        );
        assert!(items(&raw).is_empty());
    }

    #[test]
    fn renamed_unsigned_portable_and_relayed_agents_stand_out() {
        let raw = inventory(
            json!([{"name": "svcupd", "display": "Update Service", "state": "Running", "start": "Auto",
                    "path": "\"C:\\Users\\jdoe\\AppData\\Local\\Temp\\svcupd.exe\" ?e=Access&y=Guest&h=198.51.100.7&p=8041", "pid": 3100}]),
            json!([]),
            json!({"c:\\users\\jdoe\\appdata\\local\\temp\\svcupd.exe": {"exists": true, "sig_status": "NotSigned",
                    "product": "ScreenConnect", "original": "ScreenConnect.ClientService.exe",
                    "created": "2026-03-08T22:00:00"}}),
            json!({}),
        );
        let items = items(&raw);
        assert_eq!(items.len(), 1);
        let item = &items[0];
        let codes: Vec<&str> = item.flags.iter().map(|f| f.code.as_str()).collect();
        for code in [
            "rmm_signature",
            "rmm_renamed",
            "rmm_relay",
            "rmm_recent",
            "rmm_portable",
        ] {
            assert!(codes.contains(&code), "{code} in {codes:?}");
        }
        assert_eq!(item.facts["relay"], "198.51.100.7");
        assert!(item.score >= 60, "{}", item.score);
    }

    #[test]
    fn the_makers_relay_is_not_a_signal() {
        let raw = inventory(
            json!([{"name": "ScreenConnect Client (abc)", "display": "ScreenConnect Client (abc)", "state": "Running", "start": "Auto",
                    "path": "\"C:\\Program Files (x86)\\ScreenConnect Client (abc)\\ScreenConnect.ClientService.exe\" ?e=Access&h=instance-abc-relay.screenconnect.com&p=443", "pid": 4200}]),
            json!([]),
            json!({"c:\\program files (x86)\\screenconnect client (abc)\\screenconnect.clientservice.exe":
                    {"exists": true, "sig_status": "Valid", "signer": "ConnectWise, LLC", "created": "2024-05-01T08:00:00"}}),
            json!({}),
        );
        let items = items(&raw);
        assert_eq!(items.len(), 1);
        let codes: Vec<&str> = items[0].flags.iter().map(|f| f.code.as_str()).collect();
        assert_eq!(codes, ["rmm_agent"]);
    }

    /// Counts only: `cargo test -p vigil-scan rmm::tests::live_settings -- --ignored --nocapture`
    #[test]
    #[ignore = "reads this computer's agent settings"]
    fn live_settings() {
        let cfg = collect_config();
        let answered = |key: &str| !cfg[key].is_null();
        println!(
            "rmm settings: teamviewer answered {}, anydesk answered {}, rustdesk answered {}, custom server set {}",
            answered("teamviewer_password"),
            answered("anydesk_unattended"),
            answered("rustdesk_password"),
            !cfg["rustdesk_server"].as_str().unwrap_or("").is_empty()
        );
    }
}
