//! Persisted sync state (`state.json`): log cursors and per-provider results.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    api::LocalRecord,
    logs::codex::CodexFileCursor,
    paths::{Paths, write_private},
    provider::Provider,
};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncSummary {
    pub purpose: String,
    pub credited_records: u64,
    /// Verified tokens: the share of the claim the calibrated envelope covers, i.e. what ranks.
    pub credited_tokens: u64,
    /// The raw claim, verified or not.
    #[serde(default)]
    pub reported_tokens: u64,
    /// `reported − credited`: claimed but above the envelope (docs/calibration.md §3).
    #[serde(default)]
    pub unverified_tokens: u64,
    pub rejected_records: u64,
    #[serde(default)]
    pub rejected_reasons: BTreeMap<String, u64>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub plan: Option<String>,
    #[serde(default)]
    pub catch_up_rounds: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProviderState {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub last_attempt_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_success_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub backoff_until: Option<DateTime<Utc>>,
    #[serde(default)]
    pub syncs: u64,
    #[serde(default)]
    pub lifetime_credited_tokens: u64,
    #[serde(default)]
    pub lifetime_unverified_tokens: u64,
    #[serde(default)]
    pub last_result: Option<SyncSummary>,
    /// Records waiting for proof coverage or the next bounded upload batch.
    #[serde(default)]
    pub pending_records: Vec<LocalRecord>,
}

/// One extra Claude Code config home: its own cursors and its own account state.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClaudeHomeState {
    /// The home directory, for people reading `state.json`.
    #[serde(default)]
    pub dir: String,
    #[serde(default)]
    pub cursors: BTreeMap<String, u64>,
    /// `enabled` defaults to off here: linking an account to a profile is permanent.
    #[serde(default)]
    pub account: ProviderState,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct State {
    /// Cursors of the default Claude home (`~/.claude/projects`).
    #[serde(default)]
    pub claude_cursors: BTreeMap<String, u64>,
    #[serde(default)]
    pub codex_cursors: BTreeMap<String, CodexFileCursor>,
    #[serde(default)]
    pub providers: BTreeMap<Provider, ProviderState>,
    /// Extra Claude homes by [`crate::claude_homes::ClaudeHome::id`].
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub claude_homes: BTreeMap<String, ClaudeHomeState>,
    /// Extra Claude home directories the user added (`tmx claude-homes add`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claude_home_dirs: Vec<String>,
}

impl State {
    pub fn load(paths: &Paths) -> Result<Self> {
        let path = paths.state_file();
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw =
            std::fs::read(&path).with_context(|| format!("cannot read {}", path.display()))?;
        Ok(serde_json::from_slice(&raw).unwrap_or_default())
    }

    pub fn save(&self, paths: &Paths) -> Result<()> {
        write_private(&paths.state_file(), &serde_json::to_vec_pretty(self)?)
    }

    pub fn provider(&mut self, provider: Provider) -> &mut ProviderState {
        self.providers.entry(provider).or_default()
    }

    /// A provider syncs when the user has not disabled it (default on).
    pub fn is_enabled(&self, provider: Provider) -> bool {
        self.providers
            .get(&provider)
            .and_then(|p| p.enabled)
            .unwrap_or(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_roundtrips_and_defaults_missing_fields() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path().to_path_buf()).unwrap();
        let mut state = State::load(&paths).unwrap();
        state.claude_cursors.insert("/tmp/a.jsonl".into(), 42);
        state.provider(Provider::Codex).syncs = 3;
        state.provider(Provider::Codex).lifetime_unverified_tokens = 7;
        state
            .provider(Provider::Codex)
            .pending_records
            .push(LocalRecord {
                external_key: "pending".into(),
                occurred_at: "2026-09-07T10:00:00Z".into(),
                model: "gpt-5".into(),
                input_tokens: 7,
                output_tokens: 3,
                cache_creation_tokens: 0,
                cache_read_tokens: 0,
            });
        state.provider(Provider::Zai).enabled = Some(false);
        state.save(&paths).unwrap();
        let loaded = State::load(&paths).unwrap();
        assert_eq!(loaded.claude_cursors["/tmp/a.jsonl"], 42);
        assert_eq!(loaded.providers[&Provider::Codex].syncs, 3);
        assert_eq!(
            loaded.providers[&Provider::Codex].lifetime_unverified_tokens,
            7
        );
        assert_eq!(
            loaded.providers[&Provider::Codex].pending_records,
            state.providers[&Provider::Codex].pending_records
        );

        // Older state files predate the calibration counters.
        let old: SyncSummary = serde_json::from_str(
            r#"{"purpose":"SYNC","credited_records":1,"credited_tokens":2,"rejected_records":0}"#,
        )
        .unwrap();
        assert_eq!((old.reported_tokens, old.unverified_tokens), (0, 0));
        assert!(loaded.is_enabled(Provider::Claude));
        assert!(!loaded.is_enabled(Provider::Zai));
    }

    #[test]
    fn older_state_files_keep_their_default_claude_cursors() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path().to_path_buf()).unwrap();
        // A state.json written before extra Claude homes existed.
        std::fs::write(
            paths.state_file(),
            r#"{"claude_cursors":{"/Users/x/.claude/projects/p/s.jsonl":4096},"codex_cursors":{},"providers":{"CLAUDE":{"enabled":true,"syncs":9}}}"#,
        )
        .unwrap();
        let mut state = State::load(&paths).unwrap();
        assert_eq!(
            state.claude_cursors["/Users/x/.claude/projects/p/s.jsonl"],
            4096
        );
        assert_eq!(state.providers[&Provider::Claude].syncs, 9);
        assert!(state.claude_homes.is_empty());
        assert!(state.claude_home_dirs.is_empty());
        // Nothing new is written until a home is used, so older clients read the file unchanged.
        state.save(&paths).unwrap();
        let raw = std::fs::read_to_string(paths.state_file()).unwrap();
        assert!(!raw.contains("claude_homes") && !raw.contains("claude_home_dirs"));

        state.claude_homes.insert(
            "abcd1234".into(),
            ClaudeHomeState {
                dir: "/Users/x/.claude-work".into(),
                cursors: BTreeMap::from([("/Users/x/.claude-work/projects/a.jsonl".into(), 9)]),
                account: ProviderState {
                    enabled: Some(true),
                    ..Default::default()
                },
            },
        );
        state.claude_home_dirs.push("/Users/x/elsewhere".into());
        state.save(&paths).unwrap();
        let loaded = State::load(&paths).unwrap();
        assert_eq!(loaded.claude_homes["abcd1234"].cursors.len(), 1);
        assert_eq!(loaded.claude_homes["abcd1234"].account.enabled, Some(true));
        assert_eq!(loaded.claude_home_dirs, ["/Users/x/elsewhere"]);
        assert_eq!(
            loaded.claude_cursors["/Users/x/.claude/projects/p/s.jsonl"],
            4096
        );
    }
}
