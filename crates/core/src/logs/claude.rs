//! Claude Code session logs: `<config home>/projects/**/*.jsonl` (including subagent files).
//!
//! Each assistant message line carries exact API usage. Streamed chunks repeat the same
//! `requestId`, so records are deduplicated by request id keeping the largest usage.
//!
//! Only Anthropic Claude models consume a Claude subscription. Lines from a gateway or another
//! vendor (`ANTHROPIC_BASE_URL` pointed elsewhere: `glm-4.6`, `openai/gpt-5`, Bedrock ARNs, …)
//! advance the cursor but contribute no records, like foreign Codex sessions.
//!
//! A home reads only files that really live under its own `projects/`: a symlinked project
//! directory or log file leading into another home (or anywhere else) is skipped, or the same
//! usage would be credited to two accounts. Hard links and copies are indistinguishable from a
//! home's own files without tracking every other home's inodes; the server's per-account dedupe
//! and the proof bound are the backstop for those.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use anyhow::Result;
use serde::Deserialize;

use crate::{api::LocalRecord, claude_homes};

use super::{read_new_lines, walk};

#[derive(Deserialize)]
struct Line {
    #[serde(rename = "type")]
    kind: String,
    #[serde(rename = "requestId", default)]
    request_id: Option<String>,
    #[serde(default)]
    uuid: Option<String>,
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default)]
    message: Option<Message>,
}
#[derive(Deserialize)]
struct Message {
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    usage: Option<Usage>,
}
#[derive(Deserialize, Default)]
struct Usage {
    #[serde(default)]
    input_tokens: u64,
    #[serde(default)]
    output_tokens: u64,
    #[serde(default)]
    cache_creation_input_tokens: u64,
    #[serde(default)]
    cache_read_input_tokens: u64,
}

/// Session logs of the default config home.
pub fn projects_dir() -> Result<PathBuf> {
    claude_homes::default_projects_dir()
}

/// A model id served by Anthropic's own API: `claude-` plus lowercase letters, digits, `-`, `.`.
/// Rejects `<synthetic>`, gateway and vendor ids (`glm-4.6`, `kimi-k2`, `gpt-5`, `openai/gpt-5`),
/// and cloud ids (`anthropic.claude-…`, `claude-…@date`) that bill a cloud account, not the plan.
pub fn is_claude_model(model: &str) -> bool {
    model.strip_prefix("claude-").is_some_and(|rest| {
        !rest.is_empty()
            && rest
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
    })
}

#[derive(Debug, Default)]
pub struct ScanResult {
    pub records: Vec<LocalRecord>,
    pub cursors: BTreeMap<String, u64>,
    pub warnings: Vec<String>,
    /// Billed lines left out because their model is not an Anthropic Claude model.
    pub foreign_records: u64,
}

/// Scans the default home for records appended since `cursors`.
pub fn scan(cursors: &BTreeMap<String, u64>) -> Result<ScanResult> {
    scan_in(&projects_dir()?, cursors)
}

/// [`scan`] over one home's projects directory. Cursors are only advanced past complete lines.
pub fn scan_in(dir: &Path, cursors: &BTreeMap<String, u64>) -> Result<ScanResult> {
    let mut files = Vec::new();
    walk(
        dir,
        &|p| p.extension().is_some_and(|e| e == "jsonl"),
        &mut files,
    );
    files.sort();
    // Resolved once, so a home whose `projects/` is itself a symlink still reads its own logs.
    let root = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());

    let mut by_request: BTreeMap<String, LocalRecord> = BTreeMap::new();
    let mut result = ScanResult {
        cursors: cursors.clone(),
        ..Default::default()
    };
    let mut read = BTreeSet::new();
    let mut outside = 0usize;

    for path in files {
        match path.canonicalize() {
            // The first path (in sorted order) to reach a file of this home reads it.
            Ok(real) if real.starts_with(&root) => {
                if !read.insert(real) {
                    continue;
                }
            }
            Ok(_) => {
                outside += 1;
                continue;
            }
            Err(e) => {
                result
                    .warnings
                    .push(format!("cannot resolve {}: {e}", path.display()));
                continue;
            }
        }
        let key = path.to_string_lossy().into_owned();
        let offset = cursors.get(&key).copied().unwrap_or(0);
        let (text, new_offset, shrunk) = match read_new_lines(&path, offset) {
            Ok(v) => v,
            Err(e) => {
                result.warnings.push(format!("{e:#}"));
                continue;
            }
        };
        if shrunk {
            result
                .warnings
                .push(format!("log file shrank (rewrite?): {}", path.display()));
        }
        result.cursors.insert(key, new_offset);
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let Ok(parsed) = serde_json::from_str::<Line>(line) else {
                continue;
            };
            if parsed.kind != "assistant" {
                continue;
            }
            let Some(message) = parsed.message else {
                continue;
            };
            let Some(usage) = message.usage else { continue };
            // Claude writes synthetic interruption/error messages with zero usage.
            if usage.input_tokens == 0
                && usage.output_tokens == 0
                && usage.cache_creation_input_tokens == 0
                && usage.cache_read_input_tokens == 0
            {
                continue;
            }
            let Some(timestamp) = parsed.timestamp else {
                continue;
            };
            let id = match (parsed.request_id, parsed.uuid) {
                (Some(r), _) if !r.is_empty() => r,
                (_, Some(u)) if !u.is_empty() => format!("uuid:{u}"),
                _ => continue,
            };
            let Some(model) = message.model.filter(|m| is_claude_model(m)) else {
                result.foreign_records += 1;
                continue;
            };
            let record = LocalRecord {
                external_key: id.clone(),
                occurred_at: timestamp,
                model,
                input_tokens: usage.input_tokens,
                output_tokens: usage.output_tokens,
                cache_creation_tokens: usage.cache_creation_input_tokens,
                cache_read_tokens: usage.cache_read_input_tokens,
            };
            match by_request.get(&id) {
                Some(existing) if existing.total() >= record.total() => {}
                _ => {
                    by_request.insert(id, record);
                }
            }
        }
    }
    result.records = by_request.into_values().collect();
    if outside > 0 {
        result.warnings.push(format!(
            "{outside} Claude Code log files reached through a symlink leading out of {} were not read",
            dir.display()
        ));
    }
    if result.foreign_records > 0 {
        result.warnings.push(format!(
            "{} Claude Code log lines from non-Anthropic models (a gateway or another vendor) were not submitted",
            result.foreign_records
        ));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(request: &str, ts: &str, out: u64) -> String {
        format!(
            r#"{{"type":"assistant","requestId":"{request}","uuid":"u-{request}","timestamp":"{ts}","message":{{"model":"claude-fable-5","usage":{{"input_tokens":2,"cache_creation_input_tokens":100,"cache_read_input_tokens":300,"output_tokens":{out}}}}}}}"#
        )
    }

    #[test]
    fn skips_unbilled_messages_dedupes_streams_and_advances_cursors_incrementally() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("-Users-x-proj");
        std::fs::create_dir_all(project.join("s1/subagents")).unwrap();
        let main = project.join("s1.jsonl");
        std::fs::write(
            &main,
            format!(
                "{}\n{}\n{}\n{}\n",
                r#"{"type":"assistant","uuid":"synthetic-error","timestamp":"2026-09-01T12:00:00Z","message":{"model":"<synthetic>","usage":{"input_tokens":0,"output_tokens":0,"cache_creation_input_tokens":0,"cache_read_input_tokens":0}}}"#,
                r#"{"type":"assistant","requestId":"req_a","timestamp":"2026-09-01T12:00:00Z","message":{"model":"claude-fable-5","usage":{"input_tokens":0,"output_tokens":0}}}"#,
                line("req_a", "2026-09-01T12:00:00Z", 10),
                line("req_a", "2026-09-01T12:00:01Z", 171)
            ),
        )
        .unwrap();
        std::fs::write(
            project.join("s1/subagents/agent.jsonl"),
            format!("{}\n", line("req_b", "2026-09-01T12:01:00Z", 5)),
        )
        .unwrap();
        // SAFETY: tests in this module run single-threaded with respect to this variable.
        unsafe { std::env::set_var("TMX_CLAUDE_PROJECTS_DIR", dir.path()) };

        let first = scan(&BTreeMap::new()).unwrap();
        assert_eq!(first.records.len(), 2);
        let a = first
            .records
            .iter()
            .find(|r| r.external_key == "req_a")
            .unwrap();
        assert_eq!(a.output_tokens, 171);
        assert_eq!(a.total(), 2 + 100 + 300 + 171);

        // Append a partial line: it must not be consumed yet.
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&main)
            .unwrap();
        use std::io::Write as _;
        write!(f, "{}", &line("req_c", "2026-09-01T12:02:00Z", 1)[..40]).unwrap();
        let second = scan(&first.cursors).unwrap();
        assert!(second.records.is_empty());
        writeln!(f, "{}", &line("req_c", "2026-09-01T12:02:00Z", 1)[40..]).unwrap();
        let third = scan(&second.cursors).unwrap();
        assert_eq!(third.records.len(), 1);
        assert_eq!(third.records[0].external_key, "req_c");
    }

    fn billed(request: &str, model: &str) -> String {
        format!(
            r#"{{"type":"assistant","requestId":"{request}","timestamp":"2026-09-01T12:00:00Z","message":{{"model":"{model}","usage":{{"input_tokens":3,"output_tokens":4}}}}}}"#
        )
    }

    #[test]
    fn only_anthropic_claude_models_are_submitted() {
        for ok in [
            "claude-opus-5",
            "claude-fable-5-1",
            "claude-haiku-4-5-20251001",
            "claude-3.5-sonnet",
        ] {
            assert!(is_claude_model(ok), "{ok}");
        }
        for foreign in [
            "<synthetic>",
            "glm-4.6",
            "kimi-k2",
            "gpt-5",
            "openai/gpt-5.6-luna",
            "anthropic/claude-opus-5",
            "anthropic.claude-3-sonnet-v1:0",
            "claude-opus-4-1@20250805",
            "Claude-Opus-5",
            "claude-",
            "unknown",
            "",
        ] {
            assert!(!is_claude_model(foreign), "{foreign}");
        }

        let dir = tempfile::tempdir().unwrap();
        // Joined per component: cursor keys use the platform separator.
        let log = dir.path().join("p").join("s.jsonl");
        std::fs::create_dir_all(log.parent().unwrap()).unwrap();
        let no_model = r#"{"type":"assistant","requestId":"req_n","timestamp":"2026-09-01T12:00:00Z","message":{"usage":{"input_tokens":3,"output_tokens":4}}}"#;
        std::fs::write(
            &log,
            format!(
                "{}\n{}\n{}\n{}\n",
                billed("req_ok", "claude-opus-5"),
                billed("req_gw", "openai/gpt-5.6-luna"),
                billed("req_glm", "glm-4.6"),
                no_model
            ),
        )
        .unwrap();
        let scan = scan_in(dir.path(), &BTreeMap::new()).unwrap();
        assert_eq!(
            scan.records
                .iter()
                .map(|r| r.external_key.as_str())
                .collect::<Vec<_>>(),
            ["req_ok"]
        );
        assert_eq!(scan.foreign_records, 3);
        assert!(scan.warnings.iter().any(|w| w.contains("non-Anthropic")));
        // The cursor still moves past foreign lines, so they are never reconsidered.
        let size = std::fs::metadata(&log).unwrap().len();
        assert_eq!(scan.cursors[&log.to_string_lossy().into_owned()], size);
    }

    #[test]
    fn each_home_scans_only_its_own_projects() {
        let root = tempfile::tempdir().unwrap();
        let default = root.path().join(".claude/projects");
        let work = root.path().join(".claude-work/projects");
        for (dir, req) in [(&default, "req_default"), (&work, "req_work")] {
            std::fs::create_dir_all(dir.join("p")).unwrap();
            std::fs::write(
                dir.join("p/s.jsonl"),
                format!("{}\n", billed(req, "claude-opus-5")),
            )
            .unwrap();
        }
        let d = scan_in(&default, &BTreeMap::new()).unwrap();
        let w = scan_in(&work, &BTreeMap::new()).unwrap();
        assert_eq!(d.records.len(), 1);
        assert_eq!(d.records[0].external_key, "req_default");
        assert_eq!(w.records.len(), 1);
        assert_eq!(w.records[0].external_key, "req_work");
        // Cursor keys use the platform separator.
        let unix = |k: &String| k.replace('\\', "/");
        assert!(
            d.cursors
                .keys()
                .all(|k| unix(k).contains("/.claude/projects/"))
        );
        assert!(
            w.cursors
                .keys()
                .all(|k| unix(k).contains("/.claude-work/projects/"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_into_another_home_are_read_only_by_that_home() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let a = root.path().join(".claude/projects");
        let b = root.path().join(".claude-work/projects");
        std::fs::create_dir_all(a.join("shared")).unwrap();
        std::fs::create_dir_all(a.join("single")).unwrap();
        std::fs::create_dir_all(b.join("own")).unwrap();
        std::fs::write(
            a.join("shared/s.jsonl"),
            format!("{}\n", billed("req_dir", "claude-opus-5")),
        )
        .unwrap();
        std::fs::write(
            a.join("single/s.jsonl"),
            format!("{}\n", billed("req_file", "claude-opus-5")),
        )
        .unwrap();
        std::fs::write(
            b.join("own/s.jsonl"),
            format!("{}\n", billed("req_b", "claude-opus-5")),
        )
        .unwrap();
        // Home B links in one of A's project directories and one of A's log files.
        symlink(a.join("shared"), b.join("linked-dir")).unwrap();
        symlink(a.join("single/s.jsonl"), b.join("own/linked.jsonl")).unwrap();
        // A links one of its own files twice: read once.
        symlink(a.join("single/s.jsonl"), a.join("single/alias.jsonl")).unwrap();

        let keys = |r: &ScanResult| {
            r.records
                .iter()
                .map(|x| x.external_key.clone())
                .collect::<Vec<_>>()
        };
        let in_a = scan_in(&a, &BTreeMap::new()).unwrap();
        let in_b = scan_in(&b, &BTreeMap::new()).unwrap();
        assert_eq!(keys(&in_a), ["req_dir", "req_file"]);
        assert_eq!(keys(&in_b), ["req_b"]);
        assert_eq!(in_a.cursors.len(), 2, "{:?}", in_a.cursors);
        assert_eq!(in_b.cursors.len(), 1, "{:?}", in_b.cursors);
        assert!(
            in_b.warnings
                .iter()
                .any(|w| w.starts_with("2 Claude Code log files reached through a symlink")),
            "{:?}",
            in_b.warnings
        );
        assert!(in_a.warnings.is_empty(), "{:?}", in_a.warnings);

        // A home whose `projects/` is itself a symlink still reads its own logs.
        let alias = root.path().join("alias-projects");
        symlink(&b, &alias).unwrap();
        assert_eq!(keys(&scan_in(&alias, &BTreeMap::new()).unwrap()), ["req_b"]);
    }
}
