//! Incremental readers for append-only JSONL session logs.

use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};

pub mod claude;
pub mod codex;

/// Recursively collects files under `dir` accepted by `filter`. Missing dirs yield nothing.
pub fn walk(dir: &Path, filter: &dyn Fn(&Path) -> bool, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, filter, out);
        } else if path.is_file() && filter(&path) {
            out.push(path);
        }
    }
}

/// Reads complete lines appended after `offset`.
///
/// Returns `(text, new_offset, shrunk)`. `new_offset` only advances past the last newline so a
/// partially written trailing line is picked up on the next scan. `shrunk` flags a file that is
/// now smaller than the cursor (a rewrite), in which case it is re-read from the start.
pub fn read_new_lines(path: &Path, offset: u64) -> Result<(String, u64, bool)> {
    let mut file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let size = file.metadata()?.len();
    let (start, shrunk) = if size < offset {
        (0, true)
    } else {
        (offset, false)
    };
    if size == start {
        return Ok((String::new(), start, shrunk));
    }
    file.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::with_capacity((size - start) as usize);
    file.read_to_end(&mut buf)?;
    let Some(last_newline) = buf.iter().rposition(|b| *b == b'\n') else {
        return Ok((String::new(), start, shrunk));
    };
    let complete = &buf[..=last_newline];
    Ok((
        String::from_utf8_lossy(complete).into_owned(),
        start + complete.len() as u64,
        shrunk,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_only_complete_lines_and_detects_rewrites() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.jsonl");
        std::fs::write(&path, "a\nb\npartial").unwrap();
        let (text, offset, shrunk) = read_new_lines(&path, 0).unwrap();
        assert_eq!((text.as_str(), offset, shrunk), ("a\nb\n", 4, false));
        std::fs::write(&path, "a\nb\npartial\n").unwrap();
        let (text, offset, _) = read_new_lines(&path, offset).unwrap();
        assert_eq!((text.as_str(), offset), ("partial\n", 12));
        std::fs::write(&path, "x\n").unwrap();
        let (text, offset, shrunk) = read_new_lines(&path, 12).unwrap();
        assert_eq!((text.as_str(), offset, shrunk), ("x\n", 2, true));
    }
}
