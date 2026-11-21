//! Folder sizes: what takes the space under a folder or a whole drive.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::{Cancel, format_size, group_thousands};
use crate::walk::listings;
use crate::win::{ATTR_DIRECTORY, ATTR_NOT_LOCAL, Entry};

/// A folder or file of a space scan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Node {
    pub name: String,
    pub path: String,
    pub size: u64,
    pub files: u64,
    pub is_dir: bool,
    /// Largest first.
    pub children: Vec<Node>,
    /// Bytes of children merged away (beyond `keep_children`, or below `merged_below`).
    pub other: u64,
}

/// One of the largest files of a scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LargeFile {
    pub size: u64,
    pub path: String,
    /// Last modification, milliseconds since 1970-01-01 UTC.
    pub modified_ms: i64,
}

/// The result of [`scan_space`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpaceScan {
    pub root: Node,
    /// Largest first.
    pub largest_files: Vec<LargeFile>,
    pub files: u64,
    pub folders: u64,
    /// Folders that could not be read.
    pub errors: u64,
    pub seconds: f64,
    pub cancelled: bool,
    /// Entries smaller than this were grouped into `other` (memory bound); 0 if none were.
    pub merged_below: u64,
}

/// Nodes kept in memory by a scan (a few tens of MB).
const NODE_BUDGET: usize = 200_000;
/// Never group entries of 1 GB or more.
const MAX_FLOOR: u64 = 1 << 30;
const NO_PARENT: usize = usize::MAX;

/// Size of every folder under `root`, without entering links.
///
/// Each folder keeps its `keep_children` largest entries; the rest is summed in `other`. Sizes
/// and file counts are always exact. A whole drive can hold millions of files, and a node per
/// file would take gigabytes: once the tree passes a node budget, entries smaller than a growing
/// threshold (4 KB, 16 KB, 64 KB...) are grouped into `other` too, and `merged_below` reports
/// the threshold. The `top_files` largest files of the whole tree are listed separately and are
/// never grouped. Online-only cloud files count as 0 bytes: their data is not on this disk.
pub fn scan_space(
    root: &Path,
    progress: &dyn Fn(&str),
    cancel: &dyn Cancel,
    top_files: usize,
    keep_children: usize,
) -> SpaceScan {
    scan_space_with_budget(root, progress, cancel, top_files, keep_children, NODE_BUDGET)
}

/// A tree node while scanning. Nodes live in an arena; pruned ones are recycled.
struct Slot {
    name: OsString,
    size: u64,
    files: u64,
    is_dir: bool,
    /// A folder whose totals are not complete yet.
    open: bool,
    other: u64,
    parent: usize,
    depth: usize,
    /// Subfolders still open.
    waiting: usize,
    children: Vec<usize>,
}

/// Largest-files candidate, ordered by (size, path).
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Candidate {
    size: u64,
    path: PathBuf,
    modified_ms: i64,
}

struct Tree {
    slots: Vec<Slot>,
    free: Vec<usize>,
    alive: usize,
    open: usize,
    floor: u64,
    check: usize,
    budget: usize,
    keep_children: usize,
}

impl Tree {
    fn add(&mut self, name: OsString, size: u64, is_dir: bool, parent: usize, depth: usize) -> usize {
        let slot = Slot {
            name,
            size,
            files: u64::from(!is_dir),
            is_dir,
            open: is_dir,
            other: 0,
            parent,
            depth,
            waiting: 0,
            children: Vec::new(),
        };
        self.alive += 1;
        self.open += usize::from(is_dir);
        if let Some(index) = self.free.pop() {
            self.slots[index] = slot;
            index
        } else {
            self.slots.push(slot);
            self.slots.len() - 1
        }
    }

    /// Drops a finished subtree; returns how many nodes it held.
    fn release(&mut self, index: usize) -> usize {
        let mut count = 0;
        let mut stack = vec![index];
        while let Some(current) = stack.pop() {
            count += 1;
            let slot = &mut self.slots[current];
            stack.append(&mut slot.children);
            slot.name = OsString::new();
            self.free.push(current);
        }
        count
    }

    /// Keeps the largest children above the floor. Open subfolders are never dropped: they still
    /// have to report their totals.
    fn prune(&mut self, index: usize, finished: bool) {
        let floor = self.floor;
        let mut children = std::mem::take(&mut self.slots[index].children);
        children.sort_by_key(|&child| Reverse(self.slots[child].size));
        let mut kept = Vec::with_capacity(children.len());
        for (position, child) in children.into_iter().enumerate() {
            let slot = &self.slots[child];
            if (slot.is_dir && slot.open) || (slot.size >= floor && (!finished || position < self.keep_children)) {
                kept.push(child);
            } else {
                let released = self.release(child);
                self.alive -= released;
            }
        }
        if finished {
            let kept_size: u64 = kept.iter().map(|&child| self.slots[child].size).sum();
            let slot = &mut self.slots[index];
            slot.other = slot.size.saturating_sub(kept_size);
        }
        self.slots[index].children = kept;
    }

    /// Open folders cannot be grouped: they still have to report.
    fn prunable(&self) -> usize {
        self.alive.saturating_sub(self.open)
    }

    fn tighten(&mut self, root: usize) {
        while self.prunable() > self.budget && self.floor < MAX_FLOOR {
            let before = self.alive;
            self.floor = (self.floor * 4).max(4096);
            let mut stack = vec![root];
            while let Some(index) = stack.pop() {
                let finished = !self.slots[index].open;
                self.prune(index, finished);
                let slots = &self.slots;
                stack.extend(slots[index].children.iter().copied().filter(|&c| slots[c].is_dir));
            }
            if self.alive == before && self.floor >= 1 << 20 {
                break; // what is left is large: grouping more would hide real data
            }
        }
        self.check = self.budget.max(self.prunable() + self.budget / 4);
    }

    /// Finishes one folder and adds its totals to its parent; returns the parent.
    fn close(&mut self, index: usize) -> Option<usize> {
        self.slots[index].open = false;
        self.open -= 1;
        self.prune(index, true);
        let parent = self.slots[index].parent;
        if parent == NO_PARENT || !self.slots[parent].open {
            return None;
        }
        let (size, files) = (self.slots[index].size, self.slots[index].files);
        let parent_slot = &mut self.slots[parent];
        parent_slot.size += size;
        parent_slot.files += files;
        Some(parent)
    }

    fn complete(&mut self, mut index: usize) {
        loop {
            let Some(parent) = self.close(index) else { return };
            let slot = &mut self.slots[parent];
            slot.waiting = slot.waiting.saturating_sub(1);
            if slot.waiting > 0 {
                return;
            }
            index = parent;
        }
    }

    /// Bytes counted in folders that have not passed their totals up yet (progress only).
    fn open_bytes(&self, root: usize) -> u64 {
        let mut total = 0;
        let mut stack = vec![root];
        while let Some(index) = stack.pop() {
            let slot = &self.slots[index];
            if slot.open {
                total += slot.size;
                stack.extend(slot.children.iter().copied().filter(|&c| self.slots[c].open));
            }
        }
        total
    }

    /// Open folders, deepest first.
    fn still_open(&self, root: usize) -> Vec<usize> {
        let mut found = Vec::new();
        let mut stack = vec![root];
        while let Some(index) = stack.pop() {
            let slot = &self.slots[index];
            if slot.open {
                found.push(index);
                stack.extend(slot.children.iter().copied().filter(|&c| self.slots[c].open));
            }
        }
        found.sort_by_key(|&index| Reverse(self.slots[index].depth));
        found
    }

    /// The public tree, built without recursion (folders can be very deep).
    fn into_node(mut self, root: usize, root_path: &Path) -> Node {
        let mut order: Vec<(usize, PathBuf)> = Vec::new();
        let mut stack = vec![(root, root_path.to_path_buf())];
        while let Some((index, path)) = stack.pop() {
            for &child in &self.slots[index].children {
                stack.push((child, path.join(&self.slots[child].name)));
            }
            order.push((index, path));
        }
        let mut built: HashMap<usize, Node> = HashMap::with_capacity(order.len());
        for (index, path) in order.into_iter().rev() {
            let slot = &mut self.slots[index];
            let children = slot.children.iter().filter_map(|child| built.remove(child)).collect();
            let node = Node {
                name: std::mem::take(&mut slot.name).to_string_lossy().into_owned(),
                path: path.to_string_lossy().into_owned(),
                size: slot.size,
                files: slot.files,
                is_dir: slot.is_dir,
                children,
                other: slot.other,
            };
            built.insert(index, node);
        }
        let text = root_path.to_string_lossy().into_owned();
        built.remove(&root).unwrap_or(Node {
            name: text.clone(),
            path: text,
            size: 0,
            files: 0,
            is_dir: true,
            children: Vec::new(),
            other: 0,
        })
    }
}

fn modified_ms(entry: &Entry) -> i64 {
    (entry.modified * 1000.0).round() as i64
}

/// [`scan_space`] with another node budget (tests use a small one to exercise the grouping).
pub(crate) fn scan_space_with_budget(
    root: &Path,
    progress: &dyn Fn(&str),
    cancel: &dyn Cancel,
    top_files: usize,
    keep_children: usize,
    budget: usize,
) -> SpaceScan {
    let started = Instant::now();
    let root = std::path::absolute(root).unwrap_or_else(|_| root.to_path_buf());
    let mut tree = Tree {
        slots: Vec::new(),
        free: Vec::new(),
        alive: 0,
        open: 0,
        floor: 0,
        check: budget,
        budget,
        keep_children,
    };
    let top = tree.add(root.as_os_str().to_os_string(), 0, true, NO_PARENT, 0);
    // Folders whose listing has not arrived yet: path -> slot.
    let mut pending: HashMap<PathBuf, usize> = HashMap::from([(root.clone(), top)]);
    let mut heap: BinaryHeap<Reverse<Candidate>> = BinaryHeap::new();
    let (mut files, mut folders, mut errors) = (0u64, 0u64, 0u64);
    let mut cancelled = false;
    let mut next_report = started + Duration::from_millis(250);

    // Folders are read in parallel and arrive in any order (parents first). Each one adds its
    // files to its own totals at once and its subfolders' totals as they finish; `waiting`
    // counts the subfolders still open, and a folder whose count reaches zero is finished and
    // passes its totals up.
    listings(&root, &|entry: &Entry| !entry.is_link(), &mut |listing| {
        if cancel.cancelled() {
            cancelled = true;
            return false;
        }
        folders += 1;
        errors += u64::from(listing.error.is_some());
        let Some(node) = pending.remove(&listing.folder) else {
            return true;
        };
        let depth = tree.slots[node].depth;
        let floor = tree.floor;
        let mut subfolders = 0usize;
        for entry in listing.entries {
            if entry.is_link() {
                continue;
            }
            if entry.attributes & ATTR_DIRECTORY != 0 {
                let child = tree.add(entry.name, 0, true, node, depth + 1);
                tree.slots[node].children.push(child);
                pending.insert(entry.path, child);
                subfolders += 1;
                continue;
            }
            let size = if entry.attributes & ATTR_NOT_LOCAL != 0 {
                0
            } else {
                entry.size
            };
            files += 1;
            let slot = &mut tree.slots[node];
            slot.size += size;
            slot.files += 1;
            if top_files > 0 {
                let smallest = heap.peek().map(|item| item.0.size);
                if heap.len() < top_files || smallest.is_some_and(|smallest| size > smallest) {
                    if heap.len() >= top_files {
                        heap.pop();
                    }
                    let modified_ms = modified_ms(&entry);
                    heap.push(Reverse(Candidate {
                        size,
                        path: entry.path.clone(),
                        modified_ms,
                    }));
                }
            }
            if size >= floor {
                let child = tree.add(entry.name, size, false, node, depth + 1);
                tree.slots[node].children.push(child);
            }
        }
        if subfolders > 0 {
            tree.slots[node].waiting = subfolders;
        } else {
            tree.complete(node);
        }
        if tree.prunable() > tree.check {
            tree.tighten(top);
        }
        let now = Instant::now();
        if now >= next_report {
            next_report = now + Duration::from_millis(250);
            progress(&format!(
                "{} files · {} · {}",
                group_thousands(&files.to_string()),
                format_size(tree.open_bytes(top) as f64),
                listing.folder.display()
            ));
        }
        true
    });

    // After a cancel some folders are still open: finish them deepest first with what was read.
    for index in tree.still_open(top) {
        tree.close(index);
    }
    // Largest first; ties by path (descending), as the heap orders them.
    let largest_files = heap
        .into_sorted_vec()
        .into_iter()
        .map(|Reverse(item)| LargeFile {
            size: item.size,
            path: item.path.to_string_lossy().into_owned(),
            modified_ms: item.modified_ms,
        })
        .collect();
    let merged_below = tree.floor;
    let root_node = tree.into_node(top, &root);
    SpaceScan {
        root: root_node,
        largest_files,
        files,
        folders,
        errors,
        seconds: started.elapsed().as_secs_f64(),
        cancelled,
        merged_below,
    }
}
