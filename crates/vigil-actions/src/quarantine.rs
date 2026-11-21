//! Quarantine: the file is copied through a XOR mask (so the stored copy cannot run and antivirus does
//! not keep flagging it), its record saved next to it, and the original removed. The record format is stable,
//! so a file quarantined in any session can be restored later.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::LazyLock;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use windows::Win32::Storage::FileSystem::{MOVEFILE_DELAY_UNTIL_REBOOT, MoveFileExW};
use windows::core::{HSTRING, PCWSTR};

use crate::cmdline::{basename, dirname, normalize_path};
use crate::engine::Outcome;
use crate::error::{ActionError, Result, fail, io_text};
use crate::guards::guard_file;
use crate::json_text;
use crate::procs;
use crate::store::Store;
use vigil_i18n::tr;

/// Never change this key: files already in quarantine were masked with it and could not be restored.
static QKEY: LazyLock<[u8; 32]> = LazyLock::new(|| Sha256::digest(b"process-checker quarantine v1").into());
const CHUNK: usize = 1024 * 1024;

/// XOR with the quarantine key, starting at `offset` of the file (the mask is symmetric).
pub fn mask(chunk: &[u8], offset: u64) -> Vec<u8> {
    let key = &*QKEY;
    let start = (offset % key.len() as u64) as usize;
    chunk
        .iter()
        .enumerate()
        .map(|(i, byte)| byte ^ key[(start + i) % key.len()])
        .collect()
}

/// Copies through the mask; returns the SHA-256 of the plain content.
fn copy_masked(src: &Path, dst: &Path, plain_input: bool) -> std::io::Result<String> {
    let mut input = File::open(src)?;
    let mut output = File::create(dst)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; CHUNK];
    let mut offset = 0u64;
    loop {
        let read = read_full(&mut input, &mut buffer)?;
        if read == 0 {
            break;
        }
        let chunk = &buffer[..read];
        let out = mask(chunk, offset);
        digest.update(if plain_input { chunk } else { &out[..] });
        output.write_all(&out)?;
        offset += read as u64;
    }
    output.flush()?;
    Ok(digest.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

fn read_full(input: &mut File, buffer: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match input.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

fn delete_or_schedule(path: &str) -> std::io::Result<&'static str> {
    if let Ok(meta) = fs::metadata(path) {
        let mut permissions = meta.permissions();
        if permissions.readonly() {
            #[allow(clippy::permissions_set_readonly_false)]
            permissions.set_readonly(false);
            let _ = fs::set_permissions(path, permissions);
        }
    }
    match fs::remove_file(path) {
        Ok(()) => Ok("removed"),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            let wide = HSTRING::from(path);
            // SAFETY: `wide` outlives the call; a null target with DELAY_UNTIL_REBOOT schedules a delete.
            match unsafe { MoveFileExW(&wide, PCWSTR::null(), MOVEFILE_DELAY_UNTIL_REBOOT) } {
                Ok(()) => Ok("scheduled"),
                Err(_) => Err(e),
            }
        }
        Err(e) => Err(e),
    }
}

fn file_times(meta: &fs::Metadata) -> (f64, f64) {
    use std::os::windows::fs::MetadataExt;
    let seconds = |ticks: u64| (ticks as f64 - 116_444_736_000_000_000.0) / 10_000_000.0;
    (seconds(meta.last_write_time()), seconds(meta.creation_time()))
}

pub(crate) fn now_iso() -> String {
    chrono::Local::now().format("%Y-%m-%dT%H:%M:%S").to_string()
}

pub(crate) fn new_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// Moves a file into quarantine (ending the processes that run it first when `kill`).
pub fn quarantine_file(path: &str, store: &Store, reason: &str, kill: bool, check_signature: bool) -> Result<Outcome> {
    let path = normalize_path(path);
    guard_file(&path, check_signature)?;
    if !Path::new(&path).is_file() {
        return fail(tr!("the file no longer exists"));
    }
    let mut killed = Vec::new();
    if kill {
        let procs = procs::find_processes(Some(&path), &[], &[], None);
        if !procs.is_empty() {
            let (done, failed) = procs::terminate(&procs, false);
            if !failed.is_empty() {
                return fail(tr!(
                    "the file is in use and its process could not be ended: {0}",
                    failed.join("; ")
                ));
            }
            killed = done;
        }
    }
    let qid = new_id();
    let blob = store.quarantine_dir().join(format!("{qid}.bin"));
    let meta = fs::metadata(&path).map_err(|e| ActionError::new(tr!("could not read the file: {0}", io_text(&e))))?;
    let sha256 = match copy_masked(Path::new(&path), &blob, true) {
        Ok(hash) => hash,
        Err(e) => {
            let _ = fs::remove_file(&blob);
            return fail(tr!("could not read the file: {0}", io_text(&e)));
        }
    };
    let (modified, created) = file_times(&meta);
    let name = basename(&path).to_string();
    let mut record = json!({
        "id": qid, "original_path": path, "name": name, "size": meta.len(), "sha256": sha256,
        "quarantined_at": now_iso(), "modified": modified, "created": created, "reason": reason,
    });
    let state = match delete_or_schedule(&path) {
        Ok(state) => state,
        Err(e) => {
            let _ = fs::remove_file(&blob);
            return fail(tr!("could not remove the original file: {0}", io_text(&e)));
        }
    };
    if let Some(map) = record.as_object_mut() {
        map.insert("state".into(), Value::String(state.into()));
    }
    let meta_path = store.quarantine_dir().join(format!("{qid}.json"));
    fs::write(&meta_path, json_text::dumps_indent1(&record))
        .map_err(|e| ActionError::new(tr!("could not save the quarantine record: {0}", io_text(&e))))?;
    let mut message = if state == "scheduled" {
        tr!(
            "copied {0} to quarantine; the file is in use, so Windows will delete it at the next restart",
            name
        )
    } else {
        tr!("moved {0} to quarantine", name)
    };
    if !killed.is_empty() {
        message.push_str(&format!(" (ended {})", killed.join(", ")));
    }
    Ok(Outcome::new(message, Some(json!({ "quarantine_id": qid }))))
}

fn valid_id(qid: &str) -> Result<()> {
    // Ids are uuid hex; anything else could point outside the quarantine folder.
    if qid.is_empty() || !qid.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return fail(tr!("that file is no longer in quarantine"));
    }
    Ok(())
}

/// Puts a quarantined file back where it was (refuses to overwrite a file that is there now).
pub fn restore_quarantined(qid: &str, store: &Store) -> Result<String> {
    valid_id(qid)?;
    let meta_path = store.quarantine_dir().join(format!("{qid}.json"));
    let blob = store.quarantine_dir().join(format!("{qid}.bin"));
    if !meta_path.is_file() || !blob.is_file() {
        return fail(tr!("that file is no longer in quarantine"));
    }
    let text = fs::read_to_string(&meta_path)
        .map_err(|e| ActionError::new(tr!("could not read the quarantine record: {0}", io_text(&e))))?;
    let meta: Value = serde_json::from_str(text.trim_start_matches('\u{feff}'))
        .map_err(|e| ActionError::new(tr!("the quarantine record is damaged: {0}", e)))?;
    let target = meta
        .get("original_path")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if target.is_empty() {
        return fail(tr!("the quarantine record is damaged: it has no original path"));
    }
    if Path::new(&target).exists() {
        let scheduled = meta.get("state").and_then(Value::as_str) == Some("scheduled");
        return fail(tr!(
            "a file already exists at {0}{1}",
            target,
            if scheduled {
                tr!(" (it is scheduled for deletion at the next restart; restart first)")
            } else {
                String::new()
            }
        ));
    }
    let folder = dirname(&target);
    if !folder.is_empty() {
        fs::create_dir_all(&folder)
            .map_err(|e| ActionError::new(tr!("could not create {0}: {1}", folder, io_text(&e))))?;
    }
    let tmp = format!("{target}.pc-restore");
    let sha256 = copy_masked(&blob, Path::new(&tmp), false)
        .map_err(|e| ActionError::new(tr!("could not restore: {0}", io_text(&e))))?;
    if Some(sha256.as_str()) != meta.get("sha256").and_then(Value::as_str) {
        let _ = fs::remove_file(&tmp);
        return fail(tr!(
            "the quarantined copy is damaged (hash mismatch); it was not restored"
        ));
    }
    fs::rename(&tmp, &target).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        ActionError::new(tr!("could not restore: {0}", io_text(&e)))
    })?;
    let modified = meta.get("modified").and_then(Value::as_f64).filter(|m| *m != 0.0);
    if let Some(modified) = modified
        && let Ok(file) = fs::OpenOptions::new().write(true).open(&target)
    {
        let time = std::time::UNIX_EPOCH + std::time::Duration::from_secs_f64(modified.max(0.0));
        let _ = file.set_times(fs::FileTimes::new().set_modified(time).set_accessed(time));
    }
    let _ = fs::remove_file(&blob);
    let _ = fs::remove_file(&meta_path);
    let name = meta.get("name").and_then(Value::as_str).unwrap_or(qid);
    Ok(format!("restored {name} to {target}"))
}

/// Deletes the quarantined copy and its record for good.
pub fn delete_quarantined(qid: &str, store: &Store) -> Result<String> {
    valid_id(qid)?;
    let meta_path = store.quarantine_dir().join(format!("{qid}.json"));
    let mut name = qid.to_string();
    if let Ok(text) = fs::read_to_string(&meta_path)
        && let Ok(meta) = serde_json::from_str::<Value>(text.trim_start_matches('\u{feff}'))
        && let Some(saved) = meta.get("name").and_then(Value::as_str).filter(|n| !n.is_empty())
    {
        name = saved.to_string();
    }
    let _ = fs::remove_file(store.quarantine_dir().join(format!("{qid}.bin")));
    let _ = fs::remove_file(&meta_path);
    Ok(tr!("permanently deleted {0}", name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_is_symmetric_across_chunks() {
        let data: Vec<u8> = (0..70_001u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        let mut masked = mask(&data[..33_333], 0);
        masked.extend(mask(&data[33_333..], 33_333));
        assert_ne!(masked, data);
        assert_eq!(mask(&masked, 0), data);
    }

    #[test]
    fn key_is_the_vigil_2_key() {
        assert_eq!(&QKEY[..4], &Sha256::digest(b"process-checker quarantine v1")[..4]);
        assert_eq!(mask(&[0, 0], 0), QKEY[..2].to_vec());
    }
}
