//! BITS jobs in the scan. READ-ONLY: the BITS COM API (through `vigil_sys::bits`) and the
//! Bits-Client event log.
//!
//! - A job's notify command line (the program BITS runs when the job finishes or fails) becomes a
//!   startup entry (`bits_notify`), so its program is judged like every other one, with a signal of
//!   its own: few normal programs use it, and malware uses it to start again after restarts.
//! - Jobs that download a program or a script into a folder standard users can change are worth a
//!   look, more so from a bare IP address or over plain HTTP.
//! - Recent transfers in the Bits-Client log (event 59) of a program or script from a bare IP
//!   address or over plain HTTP are listed, grouped.
//!
//! Windows' own jobs (Windows Update, Delivery Optimization, the Store and other Microsoft
//! downloads) are quiet. A standard user sees only their own jobs; the coverage note says so.

use serde_json::{Map, Value, json};
use vigil_i18n::tr;

use crate::lenient::{Get, list, lower, text};
use crate::model::{Flag, Item};

/// Where collection stores the jobs in the inventory (`sysconfig.bits`).
pub(crate) const SECTION: &str = "bits";
/// Files kept per job in the inventory.
const FILES_KEPT: usize = 5;
/// The Bits-Client log and how far back it is read.
const LOG: &str = "Microsoft-Windows-Bits-Client/Operational";
const LOG_DAYS: u32 = 14;
const LOG_MAX: usize = 200;
/// Recent transfers listed at most in the grouped finding.
const TRANSFERS_SHOWN: usize = 10;

/// File types that run code when opened or loaded.
const RUNNABLE: [&str; 14] = [
    ".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".hta", ".msi", ".sys",
];

/// Hosts of Microsoft's own downloads (a host equal to one of these or ending with `.` + one).
const MICROSOFT_HOSTS: [&str; 12] = [
    "microsoft.com",
    "windowsupdate.com",
    "windows.com",
    "windows.net",
    "msftconnecttest.com",
    "office.com",
    "office.net",
    "live.com",
    "msn.com",
    "bing.com",
    "xboxlive.com",
    "microsoftonline.com",
];

/// The jobs and recent transfers (`sysconfig.bits`); `admin` lists every account's jobs.
#[cfg(windows)]
pub(crate) fn collect(admin: bool) -> Value {
    let events = vigil_sys::watchlog::read_recent(LOG, &[3, 59], LOG_DAYS, LOG_MAX);
    let mut notes = Vec::new();
    // Creating the BITS object starts the service when it is stopped; the scan only reads, so it
    // lists jobs only while BITS already runs (the log below still shows recent jobs).
    let running = vigil_sys::bits::service_running() == Some(true);
    let jobs = if running {
        vigil_sys::bits::list(admin)
    } else {
        notes.push(json!({
            "area": tr!("BITS jobs"),
            "message": tr!("the BITS service was not running, so its jobs were not listed (starting it would change the computer); recent jobs come from its event log"),
        }));
        Ok(vigil_sys::bits::BitsJobs::default())
    };
    let section = match jobs {
        Ok(found) => {
            if running && !found.all_users {
                notes.push(json!({
                    "area": tr!("BITS jobs"),
                    "message": tr!("only this account's BITS jobs were listed (every account's need administrator rights)"),
                }));
            }
            if found.capped {
                notes.push(json!({
                    "area": tr!("BITS jobs"),
                    "message": tr!("only the first {0} BITS jobs were read", vigil_sys::bits::MAX_JOBS),
                }));
            }
            json!({
                "all_users": found.all_users,
                "jobs": found.jobs.iter().map(job_value).collect::<Vec<_>>(),
            })
        }
        Err(error) => {
            notes.push(json!({"area": tr!("BITS jobs"), "message": tr!("could not be collected: {0}", error)}));
            json!({"all_users": false, "jobs": []})
        }
    };
    let transfers: Vec<Value> = events
        .unwrap_or_default()
        .iter()
        .map(|event| {
            json!({
                "event_id": event.event_id,
                "time": event.time_ms,
                "name": first_of(event, &["name", "jobTitle"]),
                "url": event.data.iter().map(|(_, v)| v.as_str()).find(|v| looks_like_url(v)).unwrap_or(""),
                "process": event.get("processPath"),
            })
        })
        .collect();
    let mut out = section;
    if let Value::Object(map) = &mut out {
        map.insert("transfers".into(), json!(transfers));
        map.insert("notes".into(), json!(notes));
    }
    out
}

#[cfg(not(windows))]
pub(crate) fn collect(_admin: bool) -> Value {
    json!({"all_users": false, "jobs": [], "transfers": [], "notes": []})
}

#[cfg(windows)]
fn first_of(event: &vigil_sys::watchlog::LogEvent, names: &[&str]) -> String {
    names
        .iter()
        .map(|name| event.get(name))
        .find(|value| !value.is_empty())
        .unwrap_or("")
        .to_string()
}

#[cfg(windows)]
fn job_value(job: &vigil_sys::bits::BitsJob) -> Value {
    json!({
        "id": job.id,
        "name": job.name,
        "owner": job.owner,
        "state": job.state,
        "kind": job.kind,
        "created": job.created,
        "modified": job.modified,
        "file_count": job.file_count,
        "files": job.files.iter().take(FILES_KEPT).map(|f| json!({"remote": f.remote, "local": f.local})).collect::<Vec<_>>(),
        "notify_program": job.notify_program,
        "notify_parameters": job.notify_parameters,
    })
}

/// The jobs with a notify command line, as startup entries (`bits_notify`), from `sysconfig.bits`
/// (the analysis adds them to the inventory's own startup entries).
pub(crate) fn autoruns(section: &Value) -> Vec<Value> {
    list(section.at("jobs"))
        .iter()
        .filter(|job| !text(job.at("notify_program")).is_empty())
        .map(|job| {
            let program = text(job.at("notify_program"));
            let parameters = text(job.at("notify_parameters"));
            // BITS passes the parameters as the whole command line; the program is the file run.
            let command = if parameters.is_empty() {
                format!("\"{program}\"")
            } else if lower(&parameters).contains(&lower(&program)) {
                parameters.clone()
            } else {
                format!("\"{program}\" {parameters}")
            };
            json!({
                "source": "bits_notify",
                "location": tr!("BITS job {0}", text(job.at("id"))),
                "name": text(job.at("name")),
                "command": command,
                "file": program,
                "job": text(job.at("id")),
                "owner": text(job.at("owner")),
                "enabled": true,
            })
        })
        .collect()
}

fn looks_like_url(value: &str) -> bool {
    let low = lower(value);
    low.starts_with("http://") || low.starts_with("https://")
}

/// The host of a URL, lower case, without user info or port ("" when it is not a URL).
pub(crate) fn host_of(url: &str) -> String {
    let low = lower(url);
    let Some(rest) = low.strip_prefix("http://").or_else(|| low.strip_prefix("https://")) else {
        return String::new();
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    if let Some(inner) = authority.strip_prefix('[') {
        return inner.split(']').next().unwrap_or("").to_string();
    }
    authority.split(':').next().unwrap_or("").to_string()
}

fn bare_ip(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
}

fn microsoft_host(host: &str) -> bool {
    MICROSOFT_HOSTS
        .iter()
        .any(|known| host == *known || host.ends_with(&format!(".{known}")))
}

fn runnable(path: &str) -> bool {
    let low = lower(path);
    let name = low.split(['?', '#']).next().unwrap_or(&low);
    RUNNABLE.iter().any(|ext| name.ends_with(ext))
}

/// A folder a standard user can change (the profile folders, ProgramData, Public, Temp).
fn user_folder(path: &str) -> bool {
    let low = lower(path).replace('/', "\\");
    low.contains(r"\users\") || low.contains(r"\programdata\") || low.contains(r"\temp\") || low.contains(r"\tmp\")
}

/// Windows' own job: every file comes from a Microsoft host (or a job with no remote file and a
/// Microsoft-looking name that BITS itself uses).
fn windows_job(job: &Value) -> bool {
    let files = list(job.at("files"));
    if files.is_empty() {
        let name = lower(&text(job.at("name")));
        return ["windows update", "microsoft", "delivery optimization", "dosvc", "store"]
            .iter()
            .any(|known| name.contains(known));
    }
    files.iter().all(|f| microsoft_host(&host_of(&text(f.at("remote")))))
}

/// The findings for `sysconfig.bits`.
pub(crate) fn items(raw: &Value) -> Vec<Item> {
    let section = raw.at("sysconfig").at(SECTION);
    if section.as_object().is_none() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for job in list(section.at("jobs")) {
        if windows_job(job) || text(job.at("kind")) != "download" {
            continue;
        }
        let risky: Vec<&Value> = list(job.at("files"))
            .iter()
            .filter(|f| runnable(&text(f.at("local"))) && user_folder(&text(f.at("local"))))
            .collect();
        if risky.is_empty() {
            continue;
        }
        let mut score = 30;
        let mut reasons = vec![tr!(
            "it downloads a program or script into a folder any program you run can change"
        )];
        if risky.iter().any(|f| bare_ip(&host_of(&text(f.at("remote"))))) {
            score += 20;
            reasons.push(tr!("from a bare IP address instead of a named server"));
        }
        if risky
            .iter()
            .any(|f| lower(&text(f.at("remote"))).starts_with("http://"))
        {
            score += 5;
            reasons.push(tr!("over plain HTTP, which anyone on the network path can change"));
        }
        let name = text(job.at("name"));
        let files: Vec<Value> = risky
            .iter()
            .map(|f| json!({"remote": text(f.at("remote")), "local": text(f.at("local"))}))
            .collect();
        out.push(item(
            "bits_download_program",
            tr!("BITS job downloads a program: {0}", if name.is_empty() { text(job.at("id")) } else { name }),
            score,
            tr!(
                "A background transfer (BITS) job {0}. BITS keeps jobs across restarts and retries them; malware uses it to fetch its next stage quietly.",
                reasons.join("; ")
            ),
            facts(vec![
                ("job", job.at("id").clone()),
                ("owner", job.at("owner").clone()),
                ("state", job.at("state").clone()),
                ("created", job.at("created").clone()),
                ("files", json!(files)),
            ]),
        ));
    }

    // Event 59: a transfer started (with its URL); event 3: a job was created (with the program
    // that created it).
    let suspicious: Vec<Value> = list(section.at("transfers"))
        .iter()
        .filter(|t| match t.at("event_id").as_u64() {
            Some(59) => {
                let url = text(t.at("url"));
                let host = host_of(&url);
                runnable(&url) && !microsoft_host(&host) && (bare_ip(&host) || lower(&url).starts_with("http://"))
            }
            Some(3) => {
                let process = text(t.at("process"));
                runnable(&process) && user_folder(&process)
            }
            _ => false,
        })
        .take(TRANSFERS_SHOWN)
        .map(|t| {
            json!({"time": t.at("time").clone(), "name": text(t.at("name")), "url": text(t.at("url")),
                   "process": text(t.at("process"))})
        })
        .collect();
    if !suspicious.is_empty() {
        out.push(item(
            "bits_recent_download",
            tr!("Unusual background transfers (BITS) in the last two weeks: {0}", suspicious.len()),
            25,
            tr!(
                "The Bits-Client log shows programs or scripts fetched in the background from a bare IP address or over plain HTTP, or transfer jobs created by a program in a folder any program you run can change. Check which program created those jobs."
            ),
            facts(vec![("transfers", json!(suspicious))]),
        ));
    }
    out
}

fn item(topic: &str, title: String, score: i64, summary: String, facts: Map<String, Value>) -> Item {
    let mut item = Item::new("config", title, summary.clone());
    let mut all = Map::new();
    all.insert("topic".into(), json!(topic));
    all.extend(facts);
    item.facts = all;
    item.add_flag(Flag::new(topic, score, summary));
    item.rescore();
    item
}

fn facts(pairs: Vec<(&str, Value)>) -> Map<String, Value> {
    pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(name: &str, remote: &str, local: &str) -> Value {
        json!({"id": "{11111111-2222-3333-4444-555555555555}", "name": name, "owner": "S-1-5-21-1-2-3-1001",
               "state": "transferring", "kind": "download", "created": 1_700_000_000_000_i64,
               "files": [{"remote": remote, "local": local}], "notify_program": "", "notify_parameters": ""})
    }

    fn run(jobs: Vec<Value>, transfers: Vec<Value>) -> Vec<Item> {
        items(&json!({"sysconfig": {"bits": {"jobs": jobs, "transfers": transfers}}}))
    }

    fn topics(found: &[Item]) -> Vec<String> {
        found
            .iter()
            .map(|i| text(i.facts.get("topic").unwrap_or(&Value::Null)))
            .collect()
    }

    #[test]
    fn hosts_are_parsed() {
        assert_eq!(
            host_of("https://user:pw@Download.Contoso.example:8443/a.exe?x=1"),
            "download.contoso.example"
        );
        assert_eq!(host_of("http://203.0.113.5/p.exe"), "203.0.113.5");
        assert_eq!(host_of("http://[2001:db8::1]:80/p.exe"), "2001:db8::1");
        assert_eq!(host_of(r"\\server\share\file"), "");
        assert!(microsoft_host("au.download.windowsupdate.com"));
        assert!(!microsoft_host("windowsupdate.com.contoso.example"));
    }

    #[test]
    fn windows_jobs_and_harmless_files_are_quiet() {
        let found = run(
            vec![
                job(
                    "Windows Update",
                    "http://au.download.windowsupdate.com/c/msdownload/update.exe",
                    r"C:\Users\jdoe\AppData\Local\Temp\update.exe",
                ),
                job(
                    "Fabrikam sync",
                    "https://cdn.fabrikam.example/data.json",
                    r"C:\Users\jdoe\data.json",
                ),
                job(
                    "Contoso updater",
                    "https://cdn.contoso.example/setup.exe",
                    r"C:\Program Files\Contoso\setup.exe",
                ),
            ],
            vec![],
        );
        assert!(found.is_empty(), "{:?}", topics(&found));
    }

    #[test]
    fn a_program_into_a_user_folder_from_an_ip_scores_higher() {
        let named = run(
            vec![job(
                "helper",
                "https://cdn.contoso.example/p.exe",
                r"C:\Users\jdoe\AppData\Roaming\p.exe",
            )],
            vec![],
        );
        let bare = run(
            vec![job("helper", "http://203.0.113.5/p.exe", r"C:\ProgramData\p.exe")],
            vec![],
        );
        assert_eq!(topics(&named), ["bits_download_program"]);
        assert_eq!(topics(&bare), ["bits_download_program"]);
        assert!(
            bare[0].score > named[0].score,
            "{} vs {}",
            bare[0].score,
            named[0].score
        );
    }

    #[test]
    fn suspicious_transfers_are_grouped() {
        let transfers = vec![
            json!({"event_id": 59, "time": 1, "name": "x", "url": "http://203.0.113.9/stage2.ps1"}),
            json!({"event_id": 59, "time": 2, "name": "y", "url": "https://cdn.contoso.example/app.exe"}),
            json!({"event_id": 59, "time": 3, "name": "z", "url": "http://download.windowsupdate.com/a.exe"}),
            json!({"event_id": 3, "time": 4, "name": "w", "url": "http://203.0.113.9/other.exe",
                   "process": r"C:\Windows\System32\svchost.exe"}),
            json!({"event_id": 3, "time": 5, "name": "v", "url": "",
                   "process": r"C:\Users\jdoe\AppData\Local\Temp\dropper.exe"}),
        ];
        let found = run(vec![], transfers);
        assert_eq!(topics(&found), ["bits_recent_download"]);
        assert_eq!(list(found[0].facts.get("transfers").unwrap_or(&Value::Null)).len(), 2);
    }

    #[test]
    fn notify_command_lines_become_startup_entries() {
        let mut with_notify = job("updater", "https://cdn.contoso.example/a.zip", r"C:\Users\jdoe\a.zip");
        with_notify["notify_program"] = json!(r"C:\Users\jdoe\AppData\Local\Temp\run.exe");
        with_notify["notify_parameters"] = json!("--quiet");
        let mut parameters_whole = job("other", "", "");
        parameters_whole["notify_program"] = json!(r"C:\Windows\System32\cmd.exe");
        parameters_whole["notify_parameters"] = json!(r"C:\Windows\System32\cmd.exe /c start evil");
        let entries = autoruns(&json!({"jobs": [with_notify, parameters_whole, job("none", "", "")]}));
        assert_eq!(entries.len(), 2);
        assert_eq!(text(entries[0].at("source")), "bits_notify");
        assert_eq!(
            text(entries[0].at("command")),
            r#""C:\Users\jdoe\AppData\Local\Temp\run.exe" --quiet"#
        );
        assert_eq!(
            text(entries[1].at("command")),
            r"C:\Windows\System32\cmd.exe /c start evil"
        );
    }
}
