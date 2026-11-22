//! The Restore points page: System Restore as `vigil_sys::restore` reads it, with every fixed
//! drive and whether System Protection covers it, and the description of a restore point the user
//! asks for.

use serde::Serialize;
use vigil_i18n::tr;
use vigil_maint::storage::Volume;
use vigil_sys::restore::{RestorePoint, RestoreState, VIGIL_PREFIX};

/// The longest description a user may type (Windows takes up to 256 characters; this keeps the
/// list readable).
pub const MAX_DESCRIPTION: usize = 64;

/// System Protection on one fixed drive.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DriveProtection {
    /// "C:".
    pub drive: String,
    pub label: String,
    pub total: u64,
    /// `None`: not readable without administrator rights.
    pub protected: Option<bool>,
    /// `None` when the shadow storage could not be read (it needs administrator rights).
    pub used: Option<u64>,
    pub allocated: Option<u64>,
    pub max: Option<u64>,
    /// The shadow storage has no size limit.
    pub unlimited: bool,
}

/// Everything the page shows.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreView {
    /// Newest first.
    pub points: Vec<RestorePoint>,
    pub points_readable: bool,
    pub drives: Vec<DriveProtection>,
    pub storage_readable: bool,
    pub off_by_policy: bool,
    pub config_locked: bool,
    pub frequency_minutes: u32,
    pub elevated: bool,
    pub problem: String,
}

/// Reads System Restore and the drives (blocking: WMI can take a second).
pub fn view(elevated: bool) -> RestoreView {
    compose(
        &vigil_sys::restore::read(elevated),
        &vigil_maint::storage::volumes(),
        elevated,
    )
}

/// The page's view from what was read: one row per fixed drive.
pub fn compose(state: &RestoreState, volumes: &[Volume], elevated: bool) -> RestoreView {
    let drives = volumes
        .iter()
        .filter(|v| !v.removable && !v.network)
        .map(|v| {
            let drive = v.mount.trim_end_matches('\\').to_ascii_uppercase();
            let storage = state.storage.iter().find(|s| s.drive.eq_ignore_ascii_case(&drive));
            DriveProtection {
                protected: state
                    .protected_readable
                    .then(|| state.protected.iter().any(|p| p.eq_ignore_ascii_case(&drive))),
                label: v.label.clone(),
                total: v.total,
                used: storage.map(|s| s.used),
                allocated: storage.map(|s| s.allocated),
                max: storage.and_then(|s| s.max),
                unlimited: storage.is_some_and(|s| s.max.is_none()),
                drive,
            }
        })
        .collect();
    RestoreView {
        points: state.points.clone(),
        points_readable: state.points_readable,
        drives,
        storage_readable: state.storage_readable,
        off_by_policy: state.off_by_policy,
        config_locked: state.config_locked,
        frequency_minutes: state.frequency_minutes,
        elevated,
        problem: state.problem.clone(),
    }
}

/// The description of a restore point the user asks for: "Vigil", or "Vigil: <what they typed>"
/// (control and invisible characters dropped, at most [`MAX_DESCRIPTION`] characters), so the
/// page can mark Vigil's own points.
pub fn description(typed: &str) -> Result<String, String> {
    let clean: String = typed
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .filter(|c| crate::display::is_plain(c.encode_utf8(&mut [0u8; 4])))
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if clean.chars().count() > MAX_DESCRIPTION {
        return Err(tr!("The description can have at most {0} characters.", MAX_DESCRIPTION));
    }
    Ok(if clean.is_empty() {
        VIGIL_PREFIX.to_string()
    } else {
        format!("{VIGIL_PREFIX}: {clean}")
    })
}

#[cfg(test)]
mod tests {
    use vigil_sys::restore::ShadowStorage;

    use super::*;

    fn volume(mount: &str, removable: bool) -> Volume {
        Volume {
            mount: mount.into(),
            label: "Data".into(),
            fs: "NTFS".into(),
            total: 1 << 40,
            used: 1 << 39,
            free: 1 << 39,
            removable,
            network: false,
        }
    }

    #[test]
    fn every_fixed_drive_gets_a_row() {
        let state = RestoreState {
            protected: vec!["C:".into()],
            protected_readable: true,
            storage: vec![ShadowStorage {
                drive: "C:".into(),
                used: 5,
                allocated: 6,
                max: None,
            }],
            storage_readable: true,
            frequency_minutes: 1440,
            ..Default::default()
        };
        let view = compose(
            &state,
            &[volume(r"C:\", false), volume(r"D:\", false), volume(r"E:\", true)],
            true,
        );
        assert_eq!(view.drives.len(), 2, "removable drives are left out");
        assert_eq!(view.drives[0].drive, "C:");
        assert!(view.drives[0].protected == Some(true) && view.drives[0].unlimited);
        assert_eq!(view.drives[0].used, Some(5));
        assert_eq!(view.drives[1].protected, Some(false));
        let unknown = compose(&RestoreState::default(), &[volume(r"C:\", false)], false);
        assert_eq!(unknown.drives[0].protected, None, "an unreadable key is not off");
        assert_eq!(view.drives[1].used, None);
        assert!(view.elevated);
    }

    #[test]
    fn descriptions_are_cleaned_and_marked_as_vigil() {
        assert_eq!(description("").unwrap(), "Vigil");
        assert_eq!(
            description("  before   the\tupdate ").unwrap(),
            "Vigil: before the update"
        );
        assert_eq!(description("evil\u{202E}txt\u{7}").unwrap(), "Vigil: eviltxt");
        assert!(description(&"x".repeat(MAX_DESCRIPTION + 1)).is_err());
        assert!(description(&"x".repeat(MAX_DESCRIPTION)).is_ok());
    }
}
