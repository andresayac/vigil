//! Task Manager's grouping of the process list (a port of `ui/src/lib/process-groups.ts`).
//!
//! Apps: programs that own a visible window, one entry per executable, together with the processes
//! they started (a terminal inside an editor belongs to the editor). Explorer is a boundary:
//! everything started from the Start menu descends from it, so its children are never pulled in.
//! Background processes / Windows processes: the rest, split by where the file lives (the Windows
//! folder, or no file at all). A process and the processes it started from the same file form one
//! entry ("Steam Client WebHelper (4)").

use std::collections::{HashMap, HashSet};

use vigil_sys::process::ProcessRow;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Section {
    Apps,
    Background,
    Windows,
}

pub const SECTIONS: [Section; 3] = [Section::Apps, Section::Background, Section::Windows];

#[derive(Debug, Clone)]
pub struct Entry {
    /// Selection key: "pid:created" for a single process, "g:pid:created" (its main process) for a group.
    pub key: String,
    pub section: Section,
    pub label: String,
    /// Index of the process actions apply to; for a group, the root of its main process tree.
    pub main: usize,
    /// Indexes of every process in the entry.
    pub members: Vec<usize>,
}

/// `pid:createdMs`: identifies a process instance (PIDs are reused).
pub fn key(row: &ProcessRow) -> String {
    format!("{}:{}", row.pid, row.created_ms)
}

/// The file description ("Google Chrome"), or the image name without ".exe".
pub fn display_name(row: &ProcessRow) -> String {
    if !row.description.is_empty() {
        return row.description.clone();
    }
    let name = row.name.as_str();
    match name.len().checked_sub(4) {
        Some(cut) if name.is_char_boundary(cut) && name[cut..].eq_ignore_ascii_case(".exe") => name[..cut].to_string(),
        _ => name.to_string(),
    }
}

fn in_windows_dir(exe: &str) -> bool {
    let low = exe.to_ascii_lowercase();
    low.len() > 11 && low.as_bytes()[1] == b':' && low[2..].starts_with("\\windows\\")
}

fn is_shell(exe: &str) -> bool {
    in_windows_dir(exe) && exe.to_ascii_lowercase().ends_with("\\windows\\explorer.exe")
}

pub fn group(rows: &[ProcessRow]) -> Vec<Entry> {
    let by_pid: HashMap<u32, usize> = rows.iter().enumerate().map(|(i, r)| (r.pid, i)).collect();
    // A parent must have started before its child; otherwise the PID was reused.
    let parent_of = |i: usize| -> Option<usize> {
        let r = &rows[i];
        let p = *by_pid.get(&r.ppid)?;
        (rows[p].pid != r.pid && rows[p].created_ms <= r.created_ms).then_some(p)
    };
    let exe_of = |i: usize| rows[i].exe.to_lowercase();
    let app_exes: HashSet<String> = rows
        .iter()
        .filter(|r| r.window && !r.exe.is_empty())
        .map(|r| r.exe.to_lowercase())
        .collect();

    let mut order: Vec<String> = Vec::new();
    let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
    for i in 0..rows.len() {
        let exe = exe_of(i);
        let mut id = if !exe.is_empty() && app_exes.contains(&exe) {
            format!("app:{exe}")
        } else {
            String::new()
        };
        let mut parent = parent_of(i);
        let mut depth = 0;
        while id.is_empty()
            && let Some(p) = parent
            && depth < 8
            && !is_shell(&rows[p].exe)
        {
            if app_exes.contains(&exe_of(p)) {
                id = format!("app:{}", exe_of(p));
            }
            parent = parent_of(p);
            depth += 1;
        }
        if id.is_empty() {
            let mut root = i;
            let mut parent = parent_of(i);
            let mut depth = 0;
            while let Some(p) = parent
                && !exe.is_empty()
                && depth < 64
                && exe_of(p) == exe
            {
                root = p;
                parent = parent_of(p);
                depth += 1;
            }
            id = format!("run:{}", key(&rows[root]));
        }
        groups
            .entry(id.clone())
            .or_insert_with(|| {
                order.push(id);
                Vec::new()
            })
            .push(i);
    }

    let mut entries = Vec::with_capacity(order.len());
    for id in order {
        let Some(members) = groups.remove(&id) else { continue };
        let in_group: HashSet<usize> = members.iter().copied().collect();
        let roots: Vec<usize> = members
            .iter()
            .copied()
            .filter(|&m| parent_of(m).is_none_or(|p| !in_group.contains(&p)))
            .collect();
        let app = id.starts_with("app:");
        let owner = if app {
            members.iter().copied().find(|&m| rows[m].window)
        } else {
            None
        };
        let candidates: Vec<usize> = if app {
            let exe = &id[4..];
            roots.iter().copied().filter(|&m| exe_of(m) == exe).collect()
        } else {
            roots.clone()
        };
        let pool = if !candidates.is_empty() {
            &candidates
        } else if !roots.is_empty() {
            &roots
        } else {
            &members
        };
        let Some(main) = pool.iter().copied().reduce(|a, b| {
            let (ra, rb) = (&rows[a], &rows[b]);
            if (rb.window && !ra.window) || (rb.window == ra.window && rb.created_ms < ra.created_ms) {
                b
            } else {
                a
            }
        }) else {
            continue;
        };
        let main_exe = &rows[main].exe;
        let section = if app {
            Section::Apps
        } else if main_exe.is_empty() || in_windows_dir(main_exe) {
            Section::Windows
        } else {
            Section::Background
        };
        entries.push(Entry {
            key: if members.len() > 1 {
                format!("g:{}", key(&rows[main]))
            } else {
                key(&rows[main])
            },
            section,
            label: display_name(&rows[owner.unwrap_or(main)]),
            main,
            members,
        });
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use vigil_sys::process::ProcessStatus;

    pub(crate) fn row(pid: u32, ppid: u32, name: &str, exe: &str, window: bool) -> ProcessRow {
        ProcessRow {
            pid,
            ppid,
            name: name.into(),
            exe: exe.into(),
            user: r"PC-VICTIM\jdoe".into(),
            cmdline: String::new(),
            cpu: 0.0,
            private_bytes: 0,
            working_set: 0,
            threads: 1,
            handles: 1,
            session: 1,
            created_ms: i64::from(pid),
            io_bps: 0.0,
            status: ProcessStatus::Running,
            window,
            description: String::new(),
        }
    }

    #[test]
    fn apps_take_their_children_and_explorer_is_a_boundary() {
        let rows = vec![
            row(4, 0, "System", "", false),
            row(100, 4, "explorer.exe", r"C:\Windows\explorer.exe", true),
            row(200, 100, "editor.exe", r"C:\Program Files\Contoso\editor.exe", true),
            row(201, 200, "helper.exe", r"C:\Program Files\Contoso\helper.exe", false),
            row(300, 100, "agent.exe", r"C:\Program Files\Contoso\agent.exe", false),
            row(301, 300, "agent.exe", r"C:\Program Files\Contoso\agent.exe", false),
        ];
        let entries = group(&rows);
        let find = |label: &str| entries.iter().find(|e| e.label == label);
        let editor = find("editor").map(|e| (e.section, e.members.len()));
        assert_eq!(editor, Some((Section::Apps, 2)));
        // Started from Explorer, but Explorer does not pull it in: a background group of two.
        let agent = find("agent").map(|e| (e.section, e.members.len(), e.key.starts_with("g:")));
        assert_eq!(agent, Some((Section::Background, 2, true)));
        assert_eq!(find("System").map(|e| e.section), Some(Section::Windows));
    }

    #[test]
    fn names_drop_the_extension() {
        assert_eq!(display_name(&row(1, 0, "Agent.EXE", "", false)), "Agent");
    }
}
