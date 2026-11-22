//! Cleanup targets, measuring and cleaning (only inside temporary folders), the folder size
//! scan, volumes and the Recycle Bin (read-only checks). Everything runs on fake trees in temporary folders.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::space::scan_space_with_budget;
use super::*;

const HOUR: f64 = 3600.0;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A fresh folder under the system temporary folder, removed (links first) when dropped.
pub(crate) struct TempTree {
    pub base: PathBuf,
    links: Vec<PathBuf>,
}

impl TempTree {
    pub fn new(prefix: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!("{prefix}{}-{n}-{nanos}", std::process::id()));
        fs::create_dir_all(&base).unwrap();
        Self {
            base,
            links: Vec::new(),
        }
    }

    pub fn file(&self, path: &Path, size: usize) -> PathBuf {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, vec![b'x'; size]).unwrap();
        path.to_path_buf()
    }

    /// Modified one hour before the shifted clock (`real_now + 71 h`).
    pub fn recent_file(&self, path: &Path, size: usize, real_now: f64) -> PathBuf {
        let path = self.file(path, size);
        let future = UNIX_EPOCH + Duration::from_secs_f64(real_now + 71.0 * HOUR);
        fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(future)
            .unwrap();
        path
    }

    /// A junction, made without administrator rights.
    pub fn junction(&mut self, link: &Path, target: &Path) -> PathBuf {
        fs::create_dir_all(target).unwrap();
        fs::create_dir_all(link.parent().unwrap()).unwrap();
        let cmd = std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .unwrap()
            .join("System32")
            .join("cmd.exe");
        let status = std::process::Command::new(cmd)
            .arg("/c")
            .arg("mklink")
            .arg("/J")
            .arg(link)
            .arg(target)
            .creation_flags(0x0800_0000)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "could not create a junction");
        self.links.push(link.to_path_buf());
        link.to_path_buf()
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        for link in &self.links {
            if lstat(link).is_ok() {
                let _ = fs::remove_dir(link); // the junction only, never its target
            }
        }
        if self.base.starts_with(std::env::temp_dir()) {
            let _ = fs::remove_dir_all(&self.base);
        }
    }
}

/// A fake user profile and Windows folder. Every cleanup location points inside it, and the
/// clock is moved three days ahead so that files created now count as old.
pub(crate) struct Fake {
    pub tree: TempTree,
    pub local: PathBuf,
    pub roaming: PathBuf,
    pub temp: PathBuf,
    pub windir: PathBuf,
    pub programdata: PathBuf,
    pub outside: PathBuf,
    pub env: HashMap<String, String>,
    pub real_now: f64,
    pub files: BTreeMap<&'static str, PathBuf>,
    pub keep: BTreeMap<&'static str, PathBuf>,
}

impl Fake {
    pub fn new() -> Self {
        let tree = TempTree::new("vm-storage-");
        let base = tree.base.clone();
        let (local, roaming) = (base.join("Local"), base.join("Roaming"));
        let (temp, windir) = (local.join("Temp"), base.join("Windows"));
        let (programdata, outside) = (base.join("ProgramData"), base.join("Outside"));
        let text = |p: &Path| p.to_string_lossy().into_owned();
        let env = HashMap::from([
            ("LOCALAPPDATA".to_string(), text(&local)),
            ("APPDATA".to_string(), text(&roaming)),
            ("TEMP".to_string(), text(&temp)),
            ("SystemRoot".to_string(), text(&windir)),
            ("ProgramData".to_string(), text(&programdata)),
            ("USERPROFILE".to_string(), text(&base.join("User"))),
        ]);
        Self {
            tree,
            local,
            roaming,
            temp,
            windir,
            programdata,
            outside,
            env,
            real_now: now_seconds(),
            files: BTreeMap::new(),
            keep: BTreeMap::new(),
        }
    }

    pub fn now(&self) -> f64 {
        self.real_now + 72.0 * HOUR
    }

    pub fn targets(&self) -> BTreeMap<String, CleanupTarget> {
        cleanup_targets(Some(&self.env))
            .into_iter()
            .map(|t| (t.key.clone(), t))
            .collect()
    }

    pub fn ordered_targets(&self) -> Vec<CleanupTarget> {
        cleanup_targets(Some(&self.env))
    }

    pub fn build(&mut self) -> BTreeMap<String, CleanupTarget> {
        let (local, roaming, temp, windir, pd) = (
            self.local.clone(),
            self.roaming.clone(),
            self.temp.clone(),
            self.windir.clone(),
            self.programdata.clone(),
        );
        let explorer = local.join(r"Microsoft\Windows\Explorer");
        let user_data = local.join(r"Google\Chrome\User Data");
        let t = &self.tree;
        let files: Vec<(&'static str, PathBuf, usize)> = vec![
            ("temp_old", temp.join("old.tmp"), 1000),
            ("temp_nested", temp.join(r"setup-123\data.bin"), 500),
            ("wintemp", windir.join(r"Temp\svc.log"), 300),
            ("update", windir.join(r"SoftwareDistribution\Download\abc\kb.cab"), 4000),
            ("thumb", explorer.join("thumbcache_256.db"), 200),
            ("thumb_idx", explorer.join("thumbcache_idx.db"), 20),
            ("iconcache", explorer.join("iconcache_32.db"), 30),
            ("explorer_log", explorer.join("ExplorerStartupLog.etl"), 40),
            (
                "wer_user",
                local.join(r"Microsoft\Windows\WER\ReportArchive\r1\Report.wer"),
                60,
            ),
            ("wer_system", pd.join(r"Microsoft\Windows\WER\ReportQueue\q\a.wer"), 70),
            ("dump_user", local.join(r"CrashDumps\app.exe.123.dmp"), 800),
            ("memory_dmp", windir.join("MEMORY.DMP"), 9000),
            ("d3d", local.join(r"D3DSCache\abc\shader.bin"), 111),
            ("nvidia", local.join(r"NVIDIA\DXCache\n.bin"), 222),
            (
                "chrome_cache",
                user_data.join(r"Default\Cache\Cache_Data\f_000001"),
                3000,
            ),
            ("chrome_code", user_data.join(r"Default\Code Cache\js\x"), 400),
            ("chrome_p1", user_data.join(r"Profile 1\GPUCache\data_0"), 50),
            ("chrome_shader", user_data.join(r"ShaderCache\s"), 25),
            (
                "firefox",
                local.join(r"Mozilla\Firefox\Profiles\ab.default\cache2\entries\E1"),
                700,
            ),
            ("discord", roaming.join(r"discord\Cache\Cache_Data\d"), 90),
        ];
        for (name, path, size) in files {
            let path = t.file(&path, size);
            self.files.insert(name, path);
        }
        let recent = t.recent_file(&temp.join("recent.tmp"), 70, self.real_now);
        self.files.insert("temp_recent", recent);
        let keep: Vec<(&'static str, PathBuf, usize)> = vec![
            ("cookies", user_data.join(r"Default\Network\Cookies"), 10),
            ("history", user_data.join(r"Default\History"), 10),
            ("prefs", user_data.join(r"Default\Preferences"), 10),
            ("prefs1", user_data.join(r"Profile 1\Preferences"), 10),
            ("no_profile", user_data.join(r"System Profile\Cache\Cache_Data\f"), 10),
            ("outside", self.outside.join("precious.txt"), 5000),
        ];
        for (name, path, size) in keep {
            let path = t.file(&path, size);
            self.keep.insert(name, path);
        }
        let (link, outside) = (temp.join("link-to-outside"), self.outside.clone());
        self.tree.junction(&link, &outside);
        self.targets()
    }

    pub fn measure(&self, targets: &mut [CleanupTarget]) {
        measure_at(targets, self.now(), &no_progress, &NeverCancel);
    }

    pub fn clean(&self, targets: &[CleanupTarget]) -> CleanResult {
        clean_at(targets, self.now(), &no_progress, &NeverCancel)
    }
}

fn forced(key: &str, roots: Vec<String>) -> CleanupTarget {
    CleanupTarget {
        key: key.to_string(),
        label: "x".to_string(),
        description: "x".to_string(),
        group: "Graphics".to_string(),
        roots,
        kind: TargetKind::Files,
        size: 0,
        files: 0,
        admin: false,
        selected: true,
        note: String::new(),
        min_age_hours: 0,
        patterns: Vec::new(),
    }
}

// --------------------------------------------------------------------------- targets

#[test]
fn targets_found_and_defaults() {
    let mut fake = Fake::new();
    let targets = fake.build();
    for key in [
        "user_temp",
        "windows_temp",
        "update_cache",
        "thumbnails",
        "wer_user",
        "wer_system",
        "crash_dumps_user",
        "crash_dumps_system",
        "d3d_cache",
        "nvidia_cache",
        "browser_chrome",
        "browser_firefox",
        "app_discord",
    ] {
        assert!(targets.contains_key(key), "{key}");
    }
    for key in ["amd_cache", "intel_cache", "browser_edge", "app_teams"] {
        assert!(!targets.contains_key(key), "{key}: nothing on disk");
    }
    // System-wide targets cleaned through Windows itself are never offered for a fake environment.
    assert!(!targets.contains_key("recycle_bin"));
    assert!(!targets.contains_key("delivery_optimization"));
    let selected: BTreeSet<&str> = targets
        .values()
        .filter(|t| t.selected)
        .map(|t| t.key.as_str())
        .collect();
    let expected: BTreeSet<&str> = [
        "user_temp",
        "windows_temp",
        "update_cache",
        "thumbnails",
        "wer_user",
        "wer_system",
        "crash_dumps_user",
        "crash_dumps_system",
    ]
    .into();
    assert_eq!(selected, expected);
    assert!(targets["windows_temp"].admin && targets["crash_dumps_system"].admin);
    assert!(!targets["user_temp"].admin);
    let chrome = &targets["browser_chrome"].roots;
    assert!(chrome.iter().any(|r| r.ends_with(r"Default\Cache\Cache_Data")));
    assert!(chrome.iter().any(|r| r.ends_with(r"Profile 1\GPUCache")));
    assert!(
        !chrome.iter().any(|r| r.contains("System Profile")),
        "no Preferences: not a profile"
    );
}

#[test]
fn empty_variables_never_become_relative_paths() {
    let env = HashMap::from([
        ("TEMP".to_string(), String::new()),
        ("LOCALAPPDATA".to_string(), r"relative\path".to_string()),
    ]);
    assert_eq!(cleanup_targets(Some(&env)), Vec::new());
}

#[test]
fn variable_names_are_case_insensitive() {
    let fake = Fake::new();
    fake.tree.file(&fake.temp.join("a.tmp"), 10);
    let env = HashMap::from([("temp".to_string(), fake.temp.to_string_lossy().into_owned())]);
    assert!(cleanup_targets(Some(&env)).iter().any(|t| t.key == "user_temp"));
}

#[test]
fn a_linked_root_is_not_offered_and_never_cleaned() {
    let mut fake = Fake::new();
    let keep = fake.tree.file(&fake.outside.join("keep.bin"), 100);
    let (link, outside) = (fake.local.join("D3DSCache"), fake.outside.clone());
    let link = fake.tree.junction(&link, &outside);
    assert!(!fake.targets().contains_key("d3d_cache"));
    let mut targets = vec![forced("d3d_cache", vec![link.to_string_lossy().into_owned()])];
    fake.measure(&mut targets);
    assert_eq!(targets[0].size, 0);
    let result = fake.clean(&targets);
    assert_eq!(result.deleted, 0);
    assert!(keep.exists());
    assert!(result.errors.iter().any(|e| e.contains("link")), "{:?}", result.errors);
}

#[test]
fn a_link_anywhere_above_the_root_is_refused() {
    let mut fake = Fake::new();
    let keep = fake.tree.file(&fake.outside.join(r"inner\keep.bin"), 100);
    let (link, outside) = (fake.local.join("Linked"), fake.outside.clone());
    fake.tree.junction(&link, &outside);
    let root = link.join("inner");
    assert!(has_link(&root));
    let mut targets = vec![forced("x", vec![root.to_string_lossy().into_owned()])];
    fake.measure(&mut targets);
    assert_eq!((targets[0].size, targets[0].files), (0, 0));
    let result = fake.clean(&targets);
    assert_eq!(result.deleted, 0);
    assert!(keep.exists());
}

// --------------------------------------------------------------------------- measure and clean

#[test]
fn measure_counts_only_what_would_be_removed() {
    let mut fake = Fake::new();
    let mut targets: Vec<CleanupTarget> = fake.build().into_values().collect();
    fake.measure(&mut targets);
    let sizes: HashMap<String, (u64, u64)> = targets.iter().map(|t| (t.key.clone(), (t.size, t.files))).collect();
    assert_eq!(
        sizes["user_temp"],
        (1500, 2),
        "not the recent file, not through the junction"
    );
    assert_eq!(sizes["thumbnails"], (220, 2), "only thumbcache_*.db");
    assert_eq!(
        sizes["crash_dumps_system"],
        (9000, 1),
        "MEMORY.DMP is a single-file root"
    );
    assert_eq!(sizes["browser_chrome"], (3475, 4));
    assert_eq!(sizes["update_cache"], (4000, 1));
}

#[test]
fn clean_removes_selected_old_files_only() {
    let mut fake = Fake::new();
    let targets: Vec<CleanupTarget> = fake.ordered_targets_after_build();
    let messages = std::cell::RefCell::new(Vec::new());
    let progress = |m: &str| messages.borrow_mut().push(m.to_string());
    let result = clean_at(&targets, fake.now(), &progress, &NeverCancel);
    let gone: BTreeSet<&str> = fake
        .files
        .iter()
        .filter(|(_, p)| !p.exists())
        .map(|(n, _)| *n)
        .collect();
    let expected: BTreeSet<&str> = [
        "temp_old",
        "temp_nested",
        "wintemp",
        "update",
        "thumb",
        "thumb_idx",
        "wer_user",
        "wer_system",
        "dump_user",
        "memory_dmp",
    ]
    .into();
    assert_eq!(gone, expected);
    for path in fake.keep.values() {
        assert!(path.exists(), "{}", path.display());
    }
    assert!(fake.temp.is_dir(), "the root folder stays");
    assert!(!fake.temp.join("setup-123").exists(), "an old folder left empty goes");
    assert!(
        lstat(&fake.temp.join("link-to-outside")).is_ok(),
        "links are left alone"
    );
    assert_eq!(result.freed, 1500 + 300 + 4000 + 220 + 60 + 70 + 800 + 9000);
    assert_eq!(result.per_target["user_temp"], 1500);
    assert_eq!(result.per_target["thumbnails"], 220);
    assert!(!result.per_target.contains_key("browser_chrome"));
    assert_eq!(result.errors, Vec::<String>::new());
    assert!(!messages.borrow().is_empty());
    let _ = &mut fake;
}

impl Fake {
    fn ordered_targets_after_build(&mut self) -> Vec<CleanupTarget> {
        self.build();
        self.ordered_targets()
    }
}

#[test]
fn browser_cache_keeps_sign_ins_and_history() {
    let mut fake = Fake::new();
    let targets = fake.build();
    let mut chrome = targets["browser_chrome"].clone();
    chrome.selected = true;
    let result = fake.clean(&[chrome]);
    assert_eq!(result.freed, 3475);
    for name in ["chrome_cache", "chrome_code", "chrome_p1", "chrome_shader"] {
        assert!(!fake.files[name].exists(), "{name}");
    }
    for name in ["cookies", "history", "prefs", "prefs1", "no_profile"] {
        assert!(fake.keep[name].exists(), "{name}");
    }
}

#[test]
fn read_only_files_are_removed() {
    let fake = Fake::new();
    let path = fake.tree.file(&fake.temp.join("ro.tmp"), 10);
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&path, permissions).unwrap();
    let result = fake.clean(&[fake.targets()["user_temp"].clone()]);
    assert!(!path.exists());
    assert_eq!(result.deleted, 1);
}

#[test]
fn files_in_use_are_skipped() {
    let fake = Fake::new();
    let path = fake.tree.file(&fake.temp.join("busy.tmp"), 10);
    fake.tree.file(&fake.temp.join("free.tmp"), 10);
    // Opened without delete sharing, as most programs open files.
    let busy = fs::File::options().read(true).share_mode(0x1).open(&path).unwrap();
    let result = fake.clean(&[fake.targets()["user_temp"].clone()]);
    drop(busy);
    assert!(path.exists());
    assert_eq!((result.deleted, result.skipped), (1, 1));
    assert_eq!(result.errors, Vec::<String>::new());
}

#[test]
fn cancel_stops_early() {
    let fake = Fake::new();
    for n in 0..300 {
        fake.tree.file(&fake.temp.join(format!("f{n:03}.tmp")), 1);
    }
    let calls = Cell::new(0usize);
    let cancel = || {
        calls.set(calls.get() + 1);
        calls.get() > 40
    };
    let result = clean_at(
        &[fake.targets()["user_temp"].clone()],
        fake.now(),
        &no_progress,
        &cancel,
    );
    let remaining = fs::read_dir(&fake.temp).unwrap().count();
    assert!(remaining > 200, "{remaining}");
    assert!(result.deleted < 60, "{}", result.deleted);
}

#[test]
fn unselected_targets_are_untouched() {
    let mut fake = Fake::new();
    let mut targets: Vec<CleanupTarget> = fake.build().into_values().collect();
    for target in &mut targets {
        target.selected = false;
    }
    let result = fake.clean(&targets);
    assert_eq!((result.freed, result.deleted, result.per_target.len()), (0, 0, 0));
    assert!(fake.files.values().all(|p| p.exists()));
}

#[test]
fn deep_paths_are_measured_and_cleaned() {
    let fake = Fake::new();
    let mut deep = fake.temp.clone();
    for n in 0..12 {
        deep.push(format!("a-rather-long-folder-name-{n:02}"));
    }
    assert!(deep.as_os_str().len() > 300);
    let wide = crate::win::wide_path(&deep);
    let wide_text = String::from_utf16_lossy(&wide[..wide.len() - 1]);
    fs::create_dir_all(&wide_text).unwrap();
    fs::write(format!(r"{wide_text}\deep.bin"), [0u8; 64]).unwrap();
    let mut targets = vec![fake.targets()["user_temp"].clone()];
    fake.measure(&mut targets);
    assert_eq!((targets[0].size, targets[0].files), (64, 1));
    let result = fake.clean(&targets);
    assert_eq!(result.deleted, 1);
    assert!(
        !fake.temp.join("a-rather-long-folder-name-00").exists(),
        "the emptied folders go too"
    );
}

// --------------------------------------------------------------------------- space scan

fn check_consistent(node: &Node) {
    if !node.is_dir {
        return;
    }
    assert_eq!(
        node.size,
        node.children.iter().map(|c| c.size).sum::<u64>() + node.other,
        "{}",
        node.path
    );
    let sizes: Vec<u64> = node.children.iter().map(|c| c.size).collect();
    let mut sorted = sizes.clone();
    sorted.sort_by(|a, b| b.cmp(a));
    assert_eq!(sizes, sorted);
    for child in &node.children {
        check_consistent(child);
    }
}

fn count(node: &Node) -> usize {
    1 + node.children.iter().map(count).sum::<usize>()
}

fn wide_tree(tree: &TempTree) -> (PathBuf, u64) {
    let root = tree.base.join("wide");
    let mut expected = 0u64;
    for a in 0..6usize {
        for b in 0..6usize {
            for c in 0..3usize {
                let size = (a + 1) * 100 + b * 10 + c;
                tree.file(
                    &root
                        .join(format!("a{a}"))
                        .join(format!("b{b}"))
                        .join(format!("f{c}.bin")),
                    size,
                );
                expected += size as u64;
            }
        }
    }
    (root, expected)
}

#[test]
fn sizes_order_merge_and_largest_files() {
    let mut fake = Fake::new();
    let root = fake.tree.base.join("scan");
    fake.tree.file(&root.join(r"a\one.bin"), 1000);
    fake.tree.file(&root.join(r"a\two.bin"), 10);
    fake.tree.file(&root.join(r"b\big.bin"), 5000);
    fake.tree.file(&root.join("c.bin"), 300);
    let outside = fake.outside.clone();
    fake.tree.file(&outside.join("huge.bin"), 99999);
    fake.tree.junction(&root.join("j"), &outside);
    let seen = Cell::new(0usize);
    let progress = |_: &str| seen.set(seen.get() + 1);
    let scan = scan_space(&root, &progress, &NeverCancel, 2, 2);
    assert_eq!((scan.root.size, scan.root.files, scan.files), (6310, 4, 4));
    let names: Vec<&str> = scan.root.children.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, ["b", "a"]);
    assert_eq!(scan.root.other, 300, "c.bin merged away");
    let names: Vec<&str> = scan.root.children[1].children.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, ["one.bin", "two.bin"]);
    let sizes: Vec<u64> = scan.largest_files.iter().map(|f| f.size).collect();
    assert_eq!(sizes, [5000, 1000]);
    assert!(scan.largest_files[0].path.ends_with("big.bin"));
    assert_eq!((scan.folders, scan.errors, scan.cancelled), (3, 0, false));
    assert_eq!(scan.root.path, root.to_string_lossy());
    assert!(scan.root.children[0].path.ends_with(r"scan\b"));
    assert!(scan.largest_files[0].modified_ms > 1_600_000_000_000);
    let json = serde_json::to_value(&scan).unwrap();
    assert!(json["root"]["isDir"].as_bool().unwrap());
    assert!(json["largestFiles"][0]["modifiedMs"].is_i64());
    assert!(json.get("mergedBelow").is_some());
}

#[test]
fn folders_read_in_parallel_add_up() {
    let tree = TempTree::new("vm-scan-");
    let (root, expected) = wide_tree(&tree);
    let scan = scan_space(&root, &no_progress, &NeverCancel, 500, 300);
    assert_eq!((scan.root.size, scan.files, scan.folders), (expected, 108, 1 + 6 + 36));
    check_consistent(&scan.root);
}

#[test]
fn large_trees_group_small_entries_but_keep_exact_totals() {
    let tree = TempTree::new("vm-scan-");
    let (root, expected) = wide_tree(&tree); // 151 nodes; files of 100..652 bytes
    let scan = scan_space_with_budget(&root, &no_progress, &NeverCancel, 5, 300, 40);
    assert!(scan.merged_below > 0);
    assert_eq!((scan.root.size, scan.root.files), (expected, 108), "totals stay exact");
    assert!(count(&scan.root) <= 40, "{}", count(&scan.root));
    check_consistent(&scan.root);
    let sizes: Vec<u64> = scan.largest_files.iter().map(|f| f.size).collect();
    assert_eq!(sizes, [652, 651, 650, 642, 641]);
}

#[test]
fn cancel_midway_keeps_totals_consistent() {
    let tree = TempTree::new("vm-scan-");
    let (root, expected) = wide_tree(&tree);
    let calls = Cell::new(0usize);
    let cancel = || {
        calls.set(calls.get() + 1);
        calls.get() > 10
    };
    let scan = scan_space(&root, &no_progress, &cancel, 500, 300);
    assert!(scan.cancelled);
    assert!(scan.root.size < expected);
    check_consistent(&scan.root);
}

#[test]
fn cancel_returns_partial_results() {
    let tree = TempTree::new("vm-scan-");
    let root = tree.base.join("scan");
    for n in 0..20 {
        tree.file(&root.join(format!("d{n}")).join("f.bin"), 10);
    }
    let scan = scan_space(&root, &no_progress, &|| true, 500, 300);
    assert!(scan.cancelled);
    assert_eq!(scan.files, 0);
}

#[test]
fn a_missing_root_reports_one_error() {
    let tree = TempTree::new("vm-scan-");
    let scan = scan_space(&tree.base.join("missing"), &no_progress, &NeverCancel, 500, 300);
    assert_eq!((scan.files, scan.folders, scan.errors, scan.root.size), (0, 1, 1, 0));
}

// --------------------------------------------------------------------------- this PC (read-only)

#[test]
fn volumes_include_the_system_drive() {
    let drive = format!(
        "{}\\",
        std::env::var("SystemDrive")
            .unwrap_or_else(|_| "C:".into())
            .to_uppercase()
    );
    let all = volumes();
    let system: Vec<&Volume> = all.iter().filter(|v| v.mount.to_uppercase() == drive).collect();
    assert_eq!(system.len(), 1);
    assert!(system[0].total > system[0].free);
    assert!(!system[0].network);
}

#[test]
fn recycle_bin_size_reads() {
    let (size, items) = recycle_bin_size();
    assert!(items > 0 || size == 0);
}

#[test]
fn real_targets_include_the_recycle_bin() {
    assert!(
        cleanup_targets(None)
            .iter()
            .any(|t| t.key == "recycle_bin" && t.kind == TargetKind::RecycleBin)
    );
}

#[test]
fn send_to_recycle_bin_checks_every_path_first() {
    let tree = TempTree::new("vm-recycle-");
    let keep = tree.file(&tree.base.join("keep.txt"), 1);
    send_to_recycle_bin(&[]).unwrap();
    let error = send_to_recycle_bin(&[keep.clone(), PathBuf::from("relative.txt")]).unwrap_err();
    assert_eq!(error.kind, MaintErrorKind::InvalidPath);
    let error = send_to_recycle_bin(&[tree.base.join("missing.txt")]).unwrap_err();
    assert_eq!(error.kind, MaintErrorKind::NotFound);
    let error = send_to_recycle_bin(&[PathBuf::from(r"\\server\share\file.txt")]).unwrap_err();
    assert_eq!(error.kind, MaintErrorKind::Unsupported);
    assert!(keep.exists(), "validation failed before anything moved");
}

#[test]
fn formats_sizes() {
    assert_eq!(format_size(512.0), "512 bytes");
    assert_eq!(format_size(1536.0), "1.5 KB");
    assert_eq!(format_size(3.0 * 1024f64.powi(3)), "3.0 GB");
    assert_eq!(format_size(5.0 * 1024f64.powi(5)), "5,120.0 TB");
    assert_eq!(group_thousands("1234567"), "1,234,567");
}

#[test]
fn simple_globs() {
    assert!(glob_match("thumbcache_*.db", "thumbcache_256.db"));
    assert!(!glob_match("thumbcache_*.db", "iconcache_32.db"));
    assert!(glob_match("a?c*", "abcdef"));
    assert!(!glob_match("a?c", "ac"));
    assert!(glob_match("*", ""));
}

// --------------------------------------------------------------------------- golden data

const GOLDEN: &str = include_str!("../../tests/data/storage_golden.json");

/// The same fake tree, listed, measured and cleaned: the recorded reference result.
#[test]
fn cleanup_matches_the_reference() {
    let golden: serde_json::Value = serde_json::from_str(GOLDEN).unwrap();
    let mut fake = Fake::new();
    fake.build();
    let prefix = format!("{}\\", fake.tree.base.display());
    let mut targets = fake.ordered_targets();

    let listed: Vec<serde_json::Value> = targets
        .iter()
        .map(|t| {
            let roots: Vec<String> = t.roots.iter().map(|r| r.replace(&prefix, "")).collect();
            serde_json::json!({
                "key": t.key, "label": t.label, "description": t.description, "group": t.group, "roots": roots,
                "kind": t.kind, "size": t.size, "files": t.files, "admin": t.admin, "selected": t.selected,
                "note": t.note, "min_age_hours": t.min_age_hours, "patterns": t.patterns,
            })
        })
        .collect();
    assert_eq!(serde_json::Value::Array(listed), golden["targets"]);

    fake.measure(&mut targets);
    let measured: serde_json::Map<String, serde_json::Value> = targets
        .iter()
        .map(|t| (t.key.clone(), serde_json::json!([t.size, t.files])))
        .collect();
    assert_eq!(serde_json::Value::Object(measured), golden["measured"]);

    let result = fake.clean(&targets);
    let clean = serde_json::json!({
        "freed": result.freed, "deleted": result.deleted, "skipped": result.skipped, "errors": result.errors,
        "per_target": result.per_target,
    });
    assert_eq!(clean, golden["clean"]);
    let gone: Vec<&str> = fake
        .files
        .iter()
        .filter(|(_, p)| !p.exists())
        .map(|(n, _)| *n)
        .collect();
    assert_eq!(serde_json::json!(gone), golden["gone"]);
    let kept: Vec<&str> = fake.keep.iter().filter(|(_, p)| p.exists()).map(|(n, _)| *n).collect();
    assert_eq!(serde_json::json!(kept), golden["kept"]);

    // Folders left behind (not the link, nothing reached through it).
    let mut left = Vec::new();
    let mut stack = vec![fake.tree.base.clone()];
    while let Some(folder) = stack.pop() {
        for entry in read_folder(&folder).unwrap_or_default() {
            if entry.is_dir() && !entry.is_reparse() && entry.path != fake.outside {
                left.push(entry.path.to_string_lossy().replace(&prefix, ""));
                stack.push(entry.path);
            }
        }
    }
    left.sort();
    assert_eq!(serde_json::json!(left), golden["folders_left"]);
}

#[test]
fn firefox_profiles_are_ordered_by_joined_path() {
    let fake = Fake::new();
    let profiles = fake.local.join(r"Mozilla\Firefox\Profiles");
    fake.tree.file(&profiles.join(r"x.default\cache2\a"), 1);
    fake.tree.file(&profiles.join(r"x.default-release\cache2\b"), 1);
    let firefox = fake.targets().remove("browser_firefox").unwrap();
    let names: Vec<&str> = firefox
        .roots
        .iter()
        .map(|r| r.rsplit('\\').nth(1).unwrap_or(""))
        .collect();
    assert_eq!(names, ["x.default-release", "x.default"]);
}

#[test]
fn only_recycling_is_allowed_never_a_permanent_delete() {
    use windows::Win32::UI::Shell::TSF_DELETE_RECYCLE_IF_POSSIBLE;
    let recycle = TSF_DELETE_RECYCLE_IF_POSSIBLE.0 as u32;
    assert!(allows_delete(recycle));
    assert!(allows_delete(recycle | 0x1));
    // The shell plans a permanent deletion (too large for the bin, bin turned off): refused.
    assert!(!allows_delete(0));
    assert!(!allows_delete(0x1 | 0x2));
    // Paths are checked before anything moves: a missing one stops the whole request.
    let missing = std::env::temp_dir().join("vigil-missing-for-the-recycle-test.bin");
    assert!(send_to_recycle_bin(&[missing]).is_err());
}

// --------------------------------------------------------------------------- root policy

#[test]
fn cleanup_never_deletes_outside_the_folders_windows_names() {
    let mut tree = TempTree::new("vigil-roots-");
    let allowed = tree.base.join("Profile");
    let protected = allowed.join(r"AppData\Local\Vigil");
    let elsewhere = tree.base.join("ProgramFiles");
    let policy = RootPolicy::new(std::slice::from_ref(&allowed), std::slice::from_ref(&protected));
    // A root redirected (through a changed environment, say) into a protected folder or out of
    // every allowed one is refused; the files there stay.
    let kept_protected = tree.file(&protected.join("journal.jsonl"), 10);
    let kept_elsewhere = tree.file(&elsewhere.join("agent.exe"), 10);
    let cleaned = tree.file(&allowed.join(r"AppData\Local\Temp\old.tmp"), 10);
    // A root that is a junction to a protected folder is refused before the policy is asked.
    let link = allowed.join(r"AppData\Local\LinkedTemp");
    tree.junction(&link, &protected);
    let text = |p: &Path| p.to_string_lossy().into_owned();
    let targets = vec![
        forced("protected", vec![text(&protected)]),
        forced("elsewhere", vec![text(&elsewhere)]),
        forced("link", vec![text(&link)]),
        forced("temp", vec![text(&allowed.join(r"AppData\Local\Temp"))]),
    ];
    let result = clean_with(
        &targets,
        now_seconds() + 72.0 * HOUR,
        &policy,
        &no_progress,
        &NeverCancel,
    );
    assert!(kept_protected.exists() && kept_elsewhere.exists());
    assert!(!cleaned.exists(), "the allowed root is still cleaned");
    assert_eq!(result.deleted, 1);
    assert!(
        result.errors.iter().filter(|e| e.contains("outside")).count() >= 2,
        "{:?}",
        result.errors
    );
    assert!(result.errors.iter().any(|e| e.contains("link")), "{:?}", result.errors);
}

#[test]
fn the_real_policy_protects_vigil_and_program_files() {
    let policy = RootPolicy::from_windows();
    let real = |p: PathBuf| crate::win::normcase(&p.to_string_lossy());
    assert!(!policy.allows(&real(vigil_sys::paths::program_data().join(r"Vigil\journal"))));
    assert!(!policy.allows(&real(vigil_sys::paths::program_files().join("Vendor"))));
    assert!(!policy.allows(&real(vigil_sys::paths::system_dir())));
    assert!(policy.allows(&real(vigil_sys::paths::windows_dir().join("Temp"))));
    assert!(!policy.allows(&real(vigil_sys::paths::windows_dir().join("Fonts"))));
    if let Some(local) = vigil_sys::paths::local_app_data() {
        assert!(!policy.allows(&real(local.join(r"Vigil\watch"))));
    }
}

#[test]
fn real_targets_take_their_folders_from_windows_not_the_environment() {
    // The user's temporary folder is LocalAppData\Temp, whatever TEMP says.
    let targets = cleanup_targets(None);
    if let (Some(temp), Some(local)) = (
        targets.iter().find(|t| t.key == "user_temp"),
        vigil_sys::paths::local_app_data(),
    ) {
        let expected = local.join("Temp").to_string_lossy().to_lowercase();
        assert!(
            temp.roots.iter().all(|r| r.to_lowercase() == expected),
            "{:?}",
            temp.roots
        );
    }
}
