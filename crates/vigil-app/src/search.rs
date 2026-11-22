//! Global search (Ctrl+K): what the palette finds and in what order.
//!
//! It only searches what Vigil already has: the pages, the loaded report's findings, the processes
//! of the last live sample, the background watch's alerts, and what the Services, Startup apps,
//! Scheduled tasks, Installed programs, Firewall rules and Browser extensions pages read the last
//! time they were open ([`remember`]). Nothing is read, scanned or started just to search, and
//! nothing runs from a result: it only opens the item on its page.

use std::cell::RefCell;
use std::sync::Mutex;

use serde_json::Value;

use crate::ui::kit::J as _;

/// What a result is (its group in the palette).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    Page,
    Finding,
    Process,
    Service,
    Startup,
    Task,
    Program,
    Firewall,
    Extension,
    Alert,
}

impl Kind {
    /// The kinds pages read and the palette remembers ([`remember`]).
    pub const REMEMBERED: [Kind; 6] = [
        Kind::Service,
        Kind::Startup,
        Kind::Task,
        Kind::Program,
        Kind::Firewall,
        Kind::Extension,
    ];

    /// The page that shows this kind (its title names the group).
    pub fn page(self) -> &'static str {
        match self {
            Kind::Page => "overview",
            Kind::Finding => "findings",
            Kind::Process => "processes",
            Kind::Service => "services",
            Kind::Startup => "startup",
            Kind::Task => "tasks",
            Kind::Program => "programs",
            Kind::Firewall => "firewall",
            Kind::Extension => "extensions",
            Kind::Alert => "alerts",
        }
    }
}

/// What opening a result does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Page(&'static str),
    /// Processes, with this process selected.
    Process(u32),
    /// Findings, with this finding selected.
    Finding(String),
    /// A page whose search box starts with `text` (the item shows alone or near the top).
    Seek {
        page: &'static str,
        text: String,
    },
}

/// One thing the palette can find.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub kind: Kind,
    pub title: String,
    pub detail: String,
    /// Lower-case text the query is matched against: the title, the detail and other names.
    pub words: String,
    pub target: Target,
}

impl Entry {
    pub fn new(kind: Kind, title: &str, detail: &str, extra: &[&str], target: Target) -> Self {
        let mut words = format!("{title} {detail}");
        for e in extra {
            words.push(' ');
            words.push_str(e);
        }
        Self {
            kind,
            title: title.to_string(),
            detail: detail.to_string(),
            words: words.to_lowercase(),
            target,
        }
    }
}

/// How well `entry` matches the query words (higher first); `None` when a word is missing.
pub fn score(entry: &Entry, words: &[String]) -> Option<u32> {
    if words.is_empty() || words.iter().any(|w| !entry.words.contains(w.as_str())) {
        return None;
    }
    let title = entry.title.to_lowercase();
    let query = words.join(" ");
    let mut score: u32 = if title == query {
        1000
    } else if title.starts_with(&query) {
        800
    } else {
        0
    };
    let title_words: Vec<&str> = title
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();
    for w in words {
        score += if title_words.iter().any(|t| t.starts_with(w.as_str())) {
            100
        } else if title.contains(w.as_str()) {
            50
        } else {
            10
        };
    }
    if entry.kind == Kind::Page {
        score += 300;
    }
    // Shorter titles first among equals.
    Some(score.saturating_sub((title.chars().count() as u32 / 8).min(40)))
}

/// One group of results: indexes into the entries, best first.
#[derive(Debug, Clone, PartialEq)]
pub struct Group {
    pub kind: Kind,
    pub hits: Vec<usize>,
    /// How many matched in all (more than shown when capped).
    pub total: usize,
}

/// The results for `query`: the pages first, then the other groups by their best match. Each
/// group shows at most `per_group`, and at most `limit` in all. An empty query lists the pages.
pub fn search(entries: &[Entry], query: &str, per_group: usize, limit: usize) -> Vec<Group> {
    let words: Vec<String> = query.split_whitespace().map(str::to_lowercase).collect();
    let mut scored: Vec<(usize, u32)> = if words.is_empty() {
        entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.kind == Kind::Page)
            .map(|(i, _)| (i, 0))
            .collect()
    } else {
        entries
            .iter()
            .enumerate()
            .filter_map(|(i, e)| score(e, &words).map(|s| (i, s)))
            .collect()
    };
    // Best first; ties by title, so the order does not change from one key to the next.
    scored.sort_by(|a, b| {
        b.1.cmp(&a.1).then_with(|| {
            entries[a.0]
                .title
                .to_lowercase()
                .cmp(&entries[b.0].title.to_lowercase())
        })
    });
    let mut groups: Vec<Group> = Vec::new();
    for (i, _) in &scored {
        let kind = entries[*i].kind;
        match groups.iter_mut().find(|g| g.kind == kind) {
            Some(group) => {
                group.total += 1;
                if group.hits.len() < per_group {
                    group.hits.push(*i);
                }
            }
            None => groups.push(Group {
                kind,
                hits: vec![*i],
                total: 1,
            }),
        }
    }
    // The pages first; the others keep the order of their best match.
    groups.sort_by_key(|g| g.kind != Kind::Page);
    let mut left = limit;
    for group in &mut groups {
        group.hits.truncate(left);
        left -= group.hits.len();
    }
    groups.retain(|g| !g.hits.is_empty());
    groups
}

/// The results in the order they are shown (for the keyboard).
pub fn rows(groups: &[Group]) -> Vec<usize> {
    groups.iter().flat_map(|g| g.hits.iter().copied()).collect()
}

/// The selected row after a key: moves by `delta` and stays inside the list.
pub fn step(selected: usize, count: usize, delta: isize) -> usize {
    if count == 0 {
        return 0;
    }
    (selected as isize + delta).clamp(0, count as isize - 1) as usize
}

// ------------------------------------------------------------------------------------------------
// What the pages read, kept for the palette.

static REMEMBERED: Mutex<Vec<(Kind, Vec<Entry>)>> = Mutex::new(Vec::new());

/// Keeps what a page read (`kind`'s entries replace the earlier ones). Called on any thread.
pub fn remember(kind: Kind, entries: Vec<Entry>) {
    let mut kept = REMEMBERED.lock().unwrap_or_else(|p| p.into_inner());
    kept.retain(|(k, _)| *k != kind);
    kept.push((kind, entries));
}

/// Everything remembered, and the kinds no page has read yet.
pub fn remembered() -> (Vec<Entry>, Vec<Kind>) {
    let kept = REMEMBERED.lock().unwrap_or_else(|p| p.into_inner());
    let entries = kept.iter().flat_map(|(_, e)| e.iter().cloned()).collect();
    let missing = Kind::REMEMBERED
        .into_iter()
        .filter(|k| !kept.iter().any(|(kind, _)| kind == k))
        .collect();
    (entries, missing)
}

/// The entries of what `data::fetch` read (tasks, programs, firewall rules, extensions, startup).
pub fn entries_of(kind: Kind, value: &Value) -> Vec<Entry> {
    match kind {
        Kind::Task => value
            .as_array()
            .map(|tasks| {
                tasks
                    .iter()
                    .map(|task| {
                        let actions: Vec<&str> = task.a("actions").iter().map(|a| a.s("path")).collect();
                        let mut extra = vec![task.s("author")];
                        extra.extend(actions);
                        Entry::new(
                            Kind::Task,
                            task.s("name"),
                            task.s("folder"),
                            &extra,
                            Target::Seek {
                                page: "tasks",
                                text: task.s("name").to_string(),
                            },
                        )
                    })
                    .collect()
            })
            .unwrap_or_default(),
        Kind::Program => value
            .as_array()
            .map(|programs| {
                programs
                    .iter()
                    .map(|p| {
                        let detail = [p.s("publisher"), p.s("version")]
                            .into_iter()
                            .filter(|s| !s.is_empty())
                            .collect::<Vec<_>>()
                            .join(" ");
                        Entry::new(
                            Kind::Program,
                            p.s("name"),
                            &detail,
                            &[p.s("location")],
                            Target::Seek {
                                page: "programs",
                                text: p.s("name").to_string(),
                            },
                        )
                    })
                    .collect()
            })
            .unwrap_or_default(),
        Kind::Firewall => value
            .a("rules")
            .iter()
            .map(|r| {
                let detail = if r.has("program") {
                    r.s("program").to_string()
                } else {
                    [r.s("protocolName"), r.s("localPorts")]
                        .into_iter()
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>()
                        .join(" ")
                };
                Entry::new(
                    Kind::Firewall,
                    r.s("name"),
                    &detail,
                    &[r.s("group"), r.s("service"), r.s("localPorts")],
                    Target::Seek {
                        page: "firewall",
                        text: r.s("name").to_string(),
                    },
                )
            })
            .collect(),
        Kind::Extension => value
            .a("extensions")
            .iter()
            .map(|e| {
                Entry::new(
                    Kind::Extension,
                    e.s("name"),
                    e.s("browser"),
                    &[e.s("id"), e.s("profile")],
                    Target::Seek {
                        page: "extensions",
                        text: e.s("name").to_string(),
                    },
                )
            })
            .collect(),
        Kind::Startup => value
            .as_array()
            .map(|rows| {
                rows.iter()
                    .map(|e| {
                        Entry::new(
                            Kind::Startup,
                            e.s("name"),
                            e.s("command"),
                            &[e.s("executable")],
                            Target::Seek {
                                page: "startup",
                                text: e.s("name").to_string(),
                            },
                        )
                    })
                    .collect()
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Remembers the services the Services page read.
pub fn remember_services<'a>(services: impl IntoIterator<Item = &'a vigil_sys::services::Service>) {
    let entries = services
        .into_iter()
        .map(|s| {
            let title = if s.display_name.is_empty() {
                &s.name
            } else {
                &s.display_name
            };
            Entry::new(
                Kind::Service,
                title,
                &s.name,
                &[&s.description],
                Target::Seek {
                    page: "services",
                    text: title.clone(),
                },
            )
        })
        .collect();
    remember(Kind::Service, entries);
}

/// Remembers the startup entries the Startup apps page read.
pub fn remember_startup(rows: &[vigil_sys::startup::StartupEntry]) {
    let entries = rows
        .iter()
        .map(|e| {
            Entry::new(
                Kind::Startup,
                &e.name,
                &e.command,
                &[&e.executable],
                Target::Seek {
                    page: "startup",
                    text: e.name.clone(),
                },
            )
        })
        .collect();
    remember(Kind::Startup, entries);
}

// ------------------------------------------------------------------------------------------------
// Opening a result on a page with a search box.

thread_local! {
    static SEED: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// The text the next page's search box starts with (set just before the page opens).
pub fn set_seed(text: Option<String>) {
    SEED.with(|s| *s.borrow_mut() = text);
}

/// Takes the text the search box of the page being opened starts with.
pub fn take_seed() -> Option<String> {
    SEED.with(|s| s.borrow_mut().take())
}

/// English names and other words that find a page, besides its title in the current language and
/// in English.
pub fn page_synonyms(page: &str) -> &'static str {
    match page {
        "overview" => "home summary dashboard verdict",
        "findings" => "scan results threats malware suspicious",
        "alerts" => "notifications watch background",
        "protection" => "defender antivirus threats exclusions",
        "posture" => "hardening secure boot tpm bitlocker uac smb memory integrity",
        "firewall" => "rules ports blocked allowed",
        "accounts" => "users sign-ins logins administrators sessions passwords",
        "extensions" => "browser add-ons chrome edge firefox brave policies",
        "quarantine" => "isolated restore",
        "history" => "undo journal changes",
        "performance" => "cpu memory ram gpu disk network usage",
        "processes" => "task manager running apps pid end task",
        "network" => "connections ports listening internet",
        "services" => "svchost start stop",
        "optimize" => "power plan game mode tuning speed",
        "startup" => "autorun run key sign-in login boot",
        "tasks" => "scheduled task scheduler",
        "programs" => "installed apps uninstall software",
        "storage" => "disk space cleanup junk files",
        "system" => "hardware drives memory bios battery",
        "updates" => "windows update kb patches",
        "reliability" => "crashes blue screen bsod hangs errors",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn entries() -> Vec<Entry> {
        vec![
            Entry::new(
                Kind::Page,
                "Processes",
                "",
                &["task manager"],
                Target::Page("processes"),
            ),
            Entry::new(Kind::Page, "Services", "", &[], Target::Page("services")),
            Entry::new(
                Kind::Process,
                "contoso.exe",
                "PID 4012",
                &[r"C:\Program Files\Contoso\contoso.exe"],
                Target::Process(4012),
            ),
            Entry::new(
                Kind::Process,
                "notepad.exe",
                "PID 5004",
                &[r"C:\Windows\notepad.exe"],
                Target::Process(5004),
            ),
            Entry::new(
                Kind::Service,
                "Contoso Sync Service",
                "ContosoSync",
                &[],
                Target::Seek {
                    page: "services",
                    text: "Contoso Sync Service".into(),
                },
            ),
        ]
    }

    #[test]
    fn every_word_must_match_and_titles_rank_first() {
        let all = entries();
        let groups = search(&all, "contoso", 8, 50);
        assert_eq!(groups.len(), 2);
        // The process whose title starts with the word comes before the service.
        let first = &all[groups[0].hits[0]];
        assert_eq!(first.title, "contoso.exe");
        assert!(search(&all, "contoso notepad", 8, 50).is_empty());
        // A word found only in another field still matches (the path).
        let by_path = search(&all, "program files", 8, 50);
        assert_eq!(all[by_path[0].hits[0]].target, Target::Process(4012));
    }

    #[test]
    fn pages_come_first_and_synonyms_find_them() {
        let all = entries();
        let groups = search(&all, "task", 8, 50);
        assert_eq!(groups[0].kind, Kind::Page);
        assert_eq!(all[groups[0].hits[0]].target, Target::Page("processes"));
        // An empty query lists the pages only.
        let groups = search(&all, "  ", 8, 50);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].hits.len(), 2);
    }

    #[test]
    fn matching_ignores_case_and_caps_each_group() {
        let mut all = entries();
        for i in 0..20 {
            all.push(Entry::new(
                Kind::Process,
                &format!("worker{i}.exe"),
                "",
                &[],
                Target::Process(i),
            ));
        }
        let groups = search(&all, "WORKER", 5, 50);
        assert_eq!(groups[0].hits.len(), 5);
        assert_eq!(groups[0].total, 20);
        let limited = search(&all, "exe", 50, 7);
        assert_eq!(rows(&limited).len(), 7);
    }

    #[test]
    fn the_keyboard_stays_inside_the_list() {
        assert_eq!(step(0, 5, -1), 0);
        assert_eq!(step(4, 5, 1), 4);
        assert_eq!(step(2, 5, 10), 4);
        assert_eq!(step(3, 0, 1), 0);
    }

    #[test]
    fn page_data_becomes_entries() {
        let tasks = json!([{ "name": "ContosoUpdate", "folder": "\\Contoso", "author": "Contoso",
            "actions": [{ "path": "C:\\Program Files\\Contoso\\update.exe" }] }]);
        let found = entries_of(Kind::Task, &tasks);
        assert_eq!(found.len(), 1);
        assert!(found[0].words.contains("update.exe"));
        assert_eq!(
            found[0].target,
            Target::Seek {
                page: "tasks",
                text: "ContosoUpdate".into()
            }
        );
        let firewall = json!({ "rules": [{ "name": "Fabrikam Chat", "program": "C:\\Fabrikam\\chat.exe" }] });
        assert_eq!(
            entries_of(Kind::Firewall, &firewall)[0].detail,
            "C:\\Fabrikam\\chat.exe"
        );
        let extensions = json!({ "extensions": [{ "name": "Contoso Notes", "browser": "Edge", "id": "abc" }] });
        assert_eq!(entries_of(Kind::Extension, &extensions)[0].title, "Contoso Notes");
        assert!(entries_of(Kind::Program, &json!({})).is_empty());
    }

    #[test]
    fn what_was_read_is_remembered_and_the_rest_is_missing() {
        remember(
            Kind::Program,
            vec![Entry::new(Kind::Program, "Contoso", "", &[], Target::Page("programs"))],
        );
        let (found, missing) = remembered();
        assert!(found.iter().any(|e| e.title == "Contoso"));
        assert!(!missing.contains(&Kind::Program));
        set_seed(Some("Contoso".into()));
        assert_eq!(take_seed().as_deref(), Some("Contoso"));
        assert_eq!(take_seed(), None);
    }
}
