//! Codex session logs: `~/.codex/sessions/**/rollout-*.jsonl`.
//!
//! `token_count` events carry the session's cumulative usage. Per-request records are the
//! deltas between consecutive cumulative snapshots, so re-emitted snapshots never double count.
//!
//! Only sessions on the built-in `openai` provider consume the ChatGPT plan. A session whose
//! `session_meta.model_provider` names another provider (a custom gateway, Foundry, …) is
//! scanned for its cursor but contributes no records: the API could only reject them.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::{api::LocalRecord, paths::home_dir};

use super::{read_new_lines, walk};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Totals {
    pub input_tokens: u64,
    pub cached_input_tokens: u64,
    pub cache_write_input_tokens: u64,
    pub output_tokens: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CodexFileCursor {
    pub offset: u64,
    #[serde(default)]
    pub last_total: Totals,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub lines: u64,
    /// `session_meta.model_provider`; `None` until the header line has been read.
    #[serde(default)]
    pub provider: Option<String>,
}

/// The provider id of sessions that run on the ChatGPT subscription.
pub const PLAN_PROVIDER: &str = "openai";

/// Records of this session would not have consumed the plan: another provider, or a
/// provider-prefixed model id (`vendor/model`) even when the header was not seen.
fn is_foreign(cursor: &CodexFileCursor, model: &str) -> bool {
    cursor
        .provider
        .as_deref()
        .is_some_and(|p| p != PLAN_PROVIDER)
        || model.contains('/')
}

#[derive(Deserialize)]
struct Line {
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    ordinal: Option<u64>,
    #[serde(default)]
    payload: Option<serde_json::Value>,
}

pub fn sessions_dir() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("TMX_CODEX_SESSIONS_DIR") {
        return Ok(PathBuf::from(dir));
    }
    if let Ok(dir) = std::env::var("CODEX_HOME") {
        return Ok(PathBuf::from(dir).join("sessions"));
    }
    Ok(home_dir()?.join(".codex").join("sessions"))
}

#[derive(Debug, Default)]
pub struct ScanResult {
    pub records: Vec<LocalRecord>,
    pub cursors: BTreeMap<String, CodexFileCursor>,
    pub warnings: Vec<String>,
    /// Records left out because their session ran on another model provider.
    pub foreign_records: u64,
}

pub fn scan(cursors: &BTreeMap<String, CodexFileCursor>) -> Result<ScanResult> {
    scan_in(&sessions_dir()?, cursors)
}

/// [`scan`] over an explicit sessions directory.
pub fn scan_in(dir: &Path, cursors: &BTreeMap<String, CodexFileCursor>) -> Result<ScanResult> {
    let mut files = Vec::new();
    walk(
        dir,
        &|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("rollout-") && n.ends_with(".jsonl"))
        },
        &mut files,
    );
    files.sort();

    let mut result = ScanResult {
        cursors: cursors.clone(),
        ..Default::default()
    };
    for path in files {
        let key = path.to_string_lossy().into_owned();
        let mut cursor = cursors.get(&key).cloned().unwrap_or_default();
        let (text, new_offset, shrunk) = match read_new_lines(&path, cursor.offset) {
            Ok(v) => v,
            Err(e) => {
                result.warnings.push(format!("{e:#}"));
                continue;
            }
        };
        if shrunk {
            result
                .warnings
                .push(format!("rollout shrank (rewrite?): {}", path.display()));
            cursor = CodexFileCursor {
                offset: new_offset,
                ..Default::default()
            };
            result.cursors.insert(key, cursor);
            continue;
        }
        let session = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("rollout")
            .to_string();
        for line in text.lines() {
            cursor.lines += 1;
            if line.trim().is_empty() {
                continue;
            }
            let Ok(parsed) = serde_json::from_str::<Line>(line) else {
                continue;
            };
            let Some(payload) = parsed.payload else {
                continue;
            };
            if parsed.kind == "session_meta" {
                if let Some(provider) = payload.get("model_provider").and_then(|m| m.as_str()) {
                    cursor.provider = Some(provider.to_string());
                }
                continue;
            }
            if parsed.kind == "turn_context" {
                if let Some(model) = payload.get("model").and_then(|m| m.as_str()) {
                    cursor.model = Some(model.to_string());
                }
                continue;
            }
            if parsed.kind != "event_msg"
                || payload.get("type").and_then(|t| t.as_str()) != Some("token_count")
            {
                continue;
            }
            let Some(total) = payload.pointer("/info/total_token_usage") else {
                continue;
            };
            let totals = Totals {
                input_tokens: total
                    .get("input_tokens")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                cached_input_tokens: total
                    .get("cached_input_tokens")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                cache_write_input_tokens: total
                    .get("cache_write_input_tokens")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                output_tokens: total
                    .get("output_tokens")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
            };
            let prev = &cursor.last_total;
            let d_input = totals.input_tokens.saturating_sub(prev.input_tokens);
            let d_cached = totals
                .cached_input_tokens
                .saturating_sub(prev.cached_input_tokens);
            let d_write = totals
                .cache_write_input_tokens
                .saturating_sub(prev.cache_write_input_tokens);
            let d_output = totals.output_tokens.saturating_sub(prev.output_tokens);
            if totals != *prev {
                cursor.last_total = totals;
            }
            if d_input + d_write + d_output == 0 {
                continue;
            }
            let Some(timestamp) = parsed.timestamp else {
                continue;
            };
            let model = cursor.model.clone().unwrap_or_else(|| "codex".into());
            if is_foreign(&cursor, &model) {
                result.foreign_records += 1;
                continue;
            }
            let ordinal = parsed.ordinal.unwrap_or(cursor.lines);
            // Codex counts cached tokens inside input_tokens; split them out like the API expects.
            result.records.push(LocalRecord {
                external_key: format!("{session}:{ordinal}"),
                occurred_at: timestamp,
                model,
                input_tokens: d_input.saturating_sub(d_cached),
                output_tokens: d_output,
                cache_creation_tokens: d_write,
                cache_read_tokens: d_cached.min(d_input),
            });
        }
        cursor.offset = new_offset;
        result.cursors.insert(key, cursor);
    }
    if result.foreign_records > 0 {
        result.warnings.push(format!(
            "{} Codex records from sessions on other model providers were not submitted (they do not use the ChatGPT plan)",
            result.foreign_records
        ));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token_count(ordinal: u64, ts: &str, input: u64, cached: u64, output: u64) -> String {
        format!(
            r#"{{"timestamp":"{ts}","ordinal":{ordinal},"type":"event_msg","payload":{{"type":"token_count","info":{{"total_token_usage":{{"input_tokens":{input},"cached_input_tokens":{cached},"cache_write_input_tokens":0,"output_tokens":{output},"reasoning_output_tokens":0,"total_tokens":{}}},"last_token_usage":{{}},"model_context_window":950000}},"rate_limits":null}}}}"#,
            input + output
        )
    }

    #[test]
    fn emits_deltas_between_cumulative_snapshots() {
        let dir = tempfile::tempdir().unwrap();
        let day = dir.path().join("2026/09/01");
        std::fs::create_dir_all(&day).unwrap();
        let file = day.join("rollout-2026-09-01T03-14-08-abc.jsonl");
        let turn = r#"{"timestamp":"2026-09-01T01:14:00Z","type":"turn_context","payload":{"model":"gpt-5.6-sol"}}"#;
        std::fs::write(
            &file,
            format!(
                "{turn}\n{}\n{}\n{}\n",
                token_count(10, "2026-09-01T01:14:32Z", 50_000, 49_000, 1_000),
                token_count(11, "2026-09-01T01:14:33Z", 50_000, 49_000, 1_000),
                token_count(20, "2026-09-01T01:15:00Z", 110_000, 100_000, 2_500),
            ),
        )
        .unwrap();
        let first = scan_in(dir.path(), &BTreeMap::new()).unwrap();
        assert_eq!(
            first.records.len(),
            2,
            "repeated snapshot must not produce a record"
        );
        let a = &first.records[0];
        assert_eq!(a.external_key, "rollout-2026-09-01T03-14-08-abc:10");
        assert_eq!(a.model, "gpt-5.6-sol");
        assert_eq!(
            (a.input_tokens, a.cache_read_tokens, a.output_tokens),
            (1_000, 49_000, 1_000)
        );
        let b = &first.records[1];
        assert_eq!(
            (b.input_tokens, b.cache_read_tokens, b.output_tokens),
            (9_000, 51_000, 1_500)
        );

        let second = scan_in(dir.path(), &first.cursors).unwrap();
        assert!(second.records.is_empty());
    }

    #[test]
    fn sessions_on_other_providers_yield_no_records() {
        let dir = tempfile::tempdir().unwrap();
        let day = dir.path().join("2026/09/03");
        std::fs::create_dir_all(&day).unwrap();
        let meta = |provider: &str| {
            format!(
                r#"{{"timestamp":"2026-09-03T01:00:00Z","type":"session_meta","payload":{{"id":"s","model_provider":"{provider}"}}}}"#
            )
        };
        let turn = |model: &str| {
            format!(
                r#"{{"timestamp":"2026-09-03T01:00:01Z","type":"turn_context","payload":{{"model":"{model}"}}}}"#
            )
        };
        std::fs::write(
            day.join("rollout-2026-09-03T01-00-00-gateway.jsonl"),
            format!(
                "{}
{}
{}
",
                meta("custom_gateway"),
                turn("anthropic/claude-opus-5"),
                token_count(1, "2026-09-03T01:00:02Z", 5_000, 0, 100)
            ),
        )
        .unwrap();
        std::fs::write(
            day.join("rollout-2026-09-03T01-00-00-plan.jsonl"),
            format!(
                "{}
{}
{}
",
                meta("openai"),
                turn("gpt-5.6-sol"),
                token_count(1, "2026-09-03T01:00:02Z", 7_000, 0, 200)
            ),
        )
        .unwrap();
        // No header at all (a cursor that started mid-file): the model id still tells.
        std::fs::write(
            day.join("rollout-2026-09-03T01-00-00-noheader.jsonl"),
            format!(
                "{}
{}
",
                turn("openrouter/some-model"),
                token_count(1, "2026-09-03T01:00:02Z", 9_000, 0, 300)
            ),
        )
        .unwrap();
        let scan = scan_in(dir.path(), &BTreeMap::new()).unwrap();
        assert_eq!(scan.records.len(), 1);
        assert_eq!(scan.records[0].model, "gpt-5.6-sol");
        assert_eq!(scan.foreign_records, 2);
        assert_eq!(scan.warnings.len(), 1);
        assert_eq!(
            scan.cursors
                .values()
                .filter(|c| c.provider.as_deref() == Some("custom_gateway"))
                .count(),
            1
        );
    }
}
