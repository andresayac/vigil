//! Size caps on the files Vigil reads back from its folders: saved reports and its state files.
//! Another program could put a huge file there, and reading it whole would take the memory of the
//! elevated app. Nothing Vigil writes comes near these sizes, so a larger file is refused with a
//! clear message and left as it is.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use vigil_i18n::tr;

/// A saved `-report.json` (the largest real ones are a few megabytes).
pub const MAX_REPORT_BYTES: u64 = 64 * 1024 * 1024;
/// A state file: `watch.json`, `settings.json`, `ignored.json`.
pub const MAX_STATE_BYTES: u64 = 8 * 1024 * 1024;

const MB: u64 = 1024 * 1024;

/// The whole file, or an `InvalidData` error saying it is too large when it holds more than
/// `limit` bytes (checked before reading, and again while reading in case it grows).
pub fn read_capped(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    read_open(File::open(path)?, limit)
}

/// [`read_capped`] for a file already open.
pub fn read_open(file: File, limit: u64) -> io::Result<Vec<u8>> {
    let len = file.metadata()?.len();
    if len > limit {
        return Err(too_large(limit));
    }
    let mut bytes = Vec::with_capacity(len as usize);
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(too_large(limit));
    }
    Ok(bytes)
}

/// The error for a file over `limit` bytes.
pub fn too_large(limit: u64) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        tr!(
            "the file is larger than {0} MB, more than Vigil ever writes, so it was not read",
            limit.div_ceil(MB)
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_over_the_cap_are_refused_unread() {
        let dir = std::env::temp_dir().join(format!("vigil-limits-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let small = dir.join("small.json");
        let big = dir.join("big.json");
        std::fs::write(&small, b"{}").expect("small");
        std::fs::write(&big, vec![b' '; 2 * 1024 * 1024 + 1]).expect("big");
        assert_eq!(read_capped(&small, 2).expect("at the cap"), b"{}");
        assert_eq!(
            read_capped(&small, 1).expect_err("over").kind(),
            io::ErrorKind::InvalidData
        );
        let error = read_capped(&big, 2 * 1024 * 1024).expect_err("over");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("larger than 2 MB"), "{error}");
        assert_eq!(
            read_capped(&dir.join("missing.json"), 1).expect_err("missing").kind(),
            io::ErrorKind::NotFound
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
