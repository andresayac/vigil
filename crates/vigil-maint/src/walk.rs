//! Parallel folder listing.
//!
//! Reading folders is mostly waiting for the disk, so several folders are read at once: on a
//! cold disk this is about twice as fast as one by one. Workers take the most recently found
//! folder first (depth first): subtrees finish early and few folders are pending at any time,
//! where a first-in-first-out queue would hold a whole level of the tree. A folder is handed to
//! the caller only after its subfolders were queued, so the caller always sees a parent before
//! its children.

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Condvar, Mutex, PoisonError};
use std::thread;

use crate::win::{Entry, StatError, read_folder};

const WORKERS: usize = 8;

/// One folder's entries.
pub(crate) struct Listing {
    pub folder: PathBuf,
    pub depth: usize,
    pub entries: Vec<Entry>,
    pub error: Option<StatError>,
}

struct Queue {
    items: Vec<(PathBuf, usize)>,
    stop: bool,
}

/// Calls `visit` for `root` and for every folder below it that `descend` accepts, in no
/// particular order but parents first. `visit` returns false to stop the walk early.
pub(crate) fn listings(root: &Path, descend: &dyn Fn(&Entry) -> bool, visit: &mut dyn FnMut(Listing) -> bool) {
    let queue = Mutex::new(Queue {
        items: vec![(root.to_path_buf(), 0)],
        stop: false,
    });
    let ready = Condvar::new();
    let (sender, receiver) = mpsc::channel::<Listing>();

    thread::scope(|scope| {
        for _ in 0..WORKERS {
            let sender = sender.clone();
            let queue = &queue;
            let ready = &ready;
            scope.spawn(move || worker(queue, ready, &sender));
        }
        drop(sender);

        let mut outstanding = 1usize;
        while outstanding > 0 {
            let Ok(listing) = receiver.recv() else { break };
            outstanding -= 1;
            let found: Vec<(PathBuf, usize)> = listing
                .entries
                .iter()
                .filter(|entry| entry.is_dir() && descend(entry))
                .map(|entry| (entry.path.clone(), listing.depth + 1))
                .collect();
            if !found.is_empty() {
                outstanding += found.len();
                let mut guard = queue.lock().unwrap_or_else(PoisonError::into_inner);
                guard.items.extend(found);
                drop(guard);
                ready.notify_all();
            }
            if !visit(listing) {
                break;
            }
        }
        let mut guard = queue.lock().unwrap_or_else(PoisonError::into_inner);
        guard.stop = true;
        guard.items.clear();
        drop(guard);
        ready.notify_all();
        // Workers still reading finish that folder, fail to send (the receiver goes away with
        // this scope) and return; the scope joins them.
        drop(receiver);
    });
}

fn worker(queue: &Mutex<Queue>, ready: &Condvar, sender: &mpsc::Sender<Listing>) {
    loop {
        let (folder, depth) = {
            let mut guard = queue.lock().unwrap_or_else(PoisonError::into_inner);
            loop {
                if guard.stop {
                    return;
                }
                if let Some(item) = guard.items.pop() {
                    break item;
                }
                guard = ready.wait(guard).unwrap_or_else(PoisonError::into_inner);
            }
        };
        let listing = match read_folder(&folder) {
            Ok(entries) => Listing {
                folder,
                depth,
                entries,
                error: None,
            },
            Err(error) => Listing {
                folder,
                depth,
                entries: Vec::new(),
                error: Some(error),
            },
        };
        if sender.send(listing).is_err() {
            return;
        }
    }
}
