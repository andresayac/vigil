//! The opt-in check for a newer Vigil (Settings > General > "Check for new versions once a day").
//!
//! Off by default. When it is on, the copy that owns the background watch asks GitHub's "latest
//! release" endpoint of Vigil's repository at most once a day (`vigil_scan::release`: a fixed
//! User-Agent with the version, nothing about the computer). "Check now" in Settings asks once,
//! whether the daily check is on or not. A newer release becomes one quiet information alert (no
//! notification) and a bar in the window with a link to its page; Vigil never downloads or
//! installs anything itself.
//!
//! The last check and what it found live in the watch's shared state (`watch.json`), so the tray
//! copy and the window agree and the check is not repeated by both.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};
use vigil_i18n::tr;
use vigil_scan::release;

use crate::watch::{Store, WatchFile, Watcher, alert, in_language, now_ms};

/// The daily check runs at most this often.
pub const DAY_MS: i64 = 24 * 60 * 60 * 1000;

/// A newer release found by the last check.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "camelCase")]
pub struct Latest {
    /// "2.4.0".
    pub version: String,
    /// Its release page (`https://github.com/andresayac/vigil/releases/...`).
    pub url: String,
}

/// What the checks found (in `watch.json`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "camelCase")]
pub struct UpdateState {
    /// When a check last ran, successful or not (ms since 1970; 0: never).
    pub last_check: i64,
    /// A release newer than the copy that checked; `None` when that copy was the latest.
    pub latest: Option<Latest>,
    /// The version an alert was already raised for (one alert per release).
    pub notified: String,
    /// Why the last check failed (`None` after a successful one).
    pub error: Option<String>,
}

/// This copy's version.
pub fn current() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Whether the daily check is due: never ran, ran a day ago or more, or the clock went back.
pub fn due(state: &UpdateState, now: i64) -> bool {
    state.last_check <= 0 || now < state.last_check || now - state.last_check >= DAY_MS
}

/// The release to offer this copy: the one found, when it is still newer than this copy and its
/// page is Vigil's (the saved state is a file any program of the user can change).
pub fn offer(state: &UpdateState) -> Option<Latest> {
    offer_for(state, current())
}

fn offer_for(state: &UpdateState, version: &str) -> Option<Latest> {
    state
        .latest
        .clone()
        .filter(|l| release::is_newer(&l.version, version) && release::valid_release_url_for(&l.url, &l.version))
}

/// Stores the result of a check made at `now`.
fn record(state: &mut UpdateState, result: &Result<Option<release::Release>, String>, now: i64) {
    state.last_check = now;
    match result {
        Ok(found) => {
            state.latest = found.as_ref().map(|r| Latest {
                version: r.version.clone(),
                url: r.url.clone(),
            });
            state.error = None;
        }
        Err(problem) => state.error = Some(problem.clone()),
    }
}

/// One information alert per newer release (kind "update"; its `target` is the release page).
/// Returns whether one was added.
fn raise_alert(file: &mut WatchFile, now: i64) -> bool {
    let Some(latest) = offer_for(&file.update, current()) else {
        return false;
    };
    if file.update.notified == latest.version {
        return false;
    }
    file.update.notified = latest.version.clone();
    let found = alert(
        "update",
        "info",
        &latest.url,
        tr!("Vigil {0} is available", latest.version),
        tr!(
            "This computer has Vigil {0}. Open the release page to download the new version; Vigil does not download or install anything itself.",
            current()
        ),
    );
    file.add_alerts(vec![found], now);
    true
}

/// Asks `url` for the latest release and records the answer in `store` (when given).
fn check_with(url: &str, store: Option<&Store>) -> Result<Option<Latest>, String> {
    let result = release::latest(url, current());
    let now = now_ms();
    if let Some(store) = store {
        let _ = store.update(|file| {
            record(&mut file.update, &result, now);
            raise_alert(file, now);
        });
    }
    result.map(|found| {
        found.map(|r| Latest {
            version: r.version,
            url: r.url,
        })
    })
}

/// "Check now" in Settings: asks GitHub once, now (also when the daily check is off). `store` is
/// the watch's shared state, so the window and the tray copy see the answer.
pub fn check_now(store: Option<&Store>) -> Result<Option<Latest>, String> {
    check_with(release::LATEST_URL, store)
}

/// A daily check runs in this process.
static RUNNING: AtomicBool = AtomicBool::new(false);

/// Whether the owner of the watch starts a check now.
fn should_check(file: &WatchFile, now: i64, running: bool) -> bool {
    file.settings.update_check && !running && due(&file.update, now)
}

/// Called by the copy that owns the watch after each of its rounds: when the daily check is on and
/// due, asks once on its own thread (the network never holds the watch up).
pub(crate) fn tick(watcher: &Arc<Watcher>) {
    let file = watcher.store.load();
    if !should_check(&file, now_ms(), RUNNING.load(Ordering::Acquire)) || RUNNING.swap(true, Ordering::AcqRel) {
        return;
    }
    let watcher = Arc::clone(watcher);
    let spawned = std::thread::Builder::new()
        .name("vigil-update-check".into())
        .spawn(move || {
            let language = watcher.language();
            in_language(&language, || {
                let _ = check_with(release::LATEST_URL, Some(&watcher.store));
            });
            RUNNING.store(false, Ordering::Release);
        });
    if spawned.is_err() {
        RUNNING.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(version: &str) -> release::Release {
        release::Release {
            version: version.into(),
            url: format!("https://github.com/andresayac/vigil/releases/tag/v{version}"),
            assets: Vec::new(),
        }
    }

    #[test]
    fn the_check_is_due_once_a_day() {
        let mut state = UpdateState::default();
        assert!(due(&state, 1_000), "never checked");
        state.last_check = 10 * DAY_MS;
        assert!(!due(&state, 10 * DAY_MS + DAY_MS - 1));
        assert!(due(&state, 11 * DAY_MS));
        assert!(due(&state, 9 * DAY_MS), "the clock went back");
    }

    #[test]
    fn only_the_owner_with_the_setting_on_checks() {
        let mut file = WatchFile::default();
        assert!(!should_check(&file, DAY_MS * 5, false), "off by default");
        file.settings.update_check = true;
        assert!(should_check(&file, DAY_MS * 5, false));
        assert!(!should_check(&file, DAY_MS * 5, true), "one at a time");
        file.update.last_check = DAY_MS * 5;
        assert!(
            !should_check(&file, DAY_MS * 5 + 60_000, false),
            "already checked today"
        );
    }

    #[test]
    fn results_are_recorded() {
        let mut state = UpdateState::default();
        record(&mut state, &Ok(Some(found("99.0.0"))), 5);
        assert_eq!(state.last_check, 5);
        assert_eq!(state.latest.as_ref().map(|l| l.version.as_str()), Some("99.0.0"));
        // A failure keeps what was found and says why.
        record(&mut state, &Err("offline".into()), 6);
        assert_eq!(state.error.as_deref(), Some("offline"));
        assert!(state.latest.is_some());
        // Up to date: nothing to offer.
        record(&mut state, &Ok(None), 7);
        assert!(state.latest.is_none() && state.error.is_none());
    }

    #[test]
    fn what_is_offered_is_still_newer_and_on_vigils_page() {
        let mut state = UpdateState {
            latest: Some(Latest {
                version: "99.0.0".into(),
                url: "https://github.com/andresayac/vigil/releases/tag/v99.0.0".into(),
            }),
            ..UpdateState::default()
        };
        assert!(offer_for(&state, "2.3.0").is_some());
        assert!(offer_for(&state, "99.0.0").is_none(), "already this version");
        // A page edited in the saved state is never offered.
        if let Some(latest) = &mut state.latest {
            latest.url = "https://evil.example.com/vigil.exe".into();
        }
        assert!(offer_for(&state, "2.3.0").is_none());
    }

    #[test]
    fn one_quiet_alert_per_release() {
        let mut file = WatchFile::default();
        record(&mut file.update, &Ok(Some(found("99.0.0"))), 1);
        assert!(raise_alert(&mut file, 1));
        assert!(!raise_alert(&mut file, 2), "the same release again");
        assert_eq!(file.alerts.len(), 1);
        let raised = &file.alerts[0];
        assert_eq!((raised.kind.as_str(), raised.severity.as_str()), ("update", "info"));
        assert!(release::valid_release_url(&raised.target));
        assert!(!file.settings.notifies("update"), "no notification for it");
        record(&mut file.update, &Ok(Some(found("99.1.0"))), 3);
        assert!(raise_alert(&mut file, 3), "a newer release again");
    }
}
