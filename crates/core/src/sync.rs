//! The sync engine: nonce → fill credential → MPC-TLS proof → local records → device-signed
//! submission → catch-up rounds. One call per provider; safe to run on a timer.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Duration, Utc};
use tmx_attest::{ProofSpec, prove::prove_with_ticket, spec::CREDENTIAL_PLACEHOLDER};
use tracing::{info, warn};

use crate::{
    account::{self, Account},
    api::{ApiClient, ApiError, ClientInfo, LocalRecord, SyncRequest},
    credentials, logs,
    paths::Paths,
    provider::Provider,
    state::{State, SyncSummary},
};

const MAX_CATCH_UP_ROUNDS: u32 = 12;
/// Upper bound on local records per submission (mirrors the API schema limit).
pub const MAX_RECORDS_PER_SYNC: usize = 20_000;
/// Diagnostics the API accepts alongside a submission (mirrors the API schema limits).
pub const MAX_WARNINGS: usize = 20;
pub const MAX_WARNING_CHARS: usize = 300;

/// Returned (inside `anyhow::Error`) when a provider is skipped because an earlier failure put
/// it on a back-off timer. Callers should treat it as "skipped", not as a new failure.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("backing off until {}", .0.format("%H:%M:%S UTC"))]
pub struct BackingOff(pub chrono::DateTime<Utc>);

/// Accounts that would take part in a sync round: enabled by the user and with a credential
/// available on this machine. Extra Claude homes take part only once enabled.
pub fn eligible_accounts(paths: &Paths) -> Result<Vec<(Account, credentials::CredentialStatus)>> {
    let state = State::load(paths)?;
    Ok(account::all(&state)
        .into_iter()
        .filter(|a| a.is_enabled(&state))
        .map(|a| {
            let status = a.credential_status(paths, &state);
            (a, status)
        })
        .filter(|(_, status)| status.available)
        .collect())
}

#[derive(Debug, Clone)]
pub struct SyncOutcome {
    pub provider: Provider,
    /// [`Account::key`] of what was synced.
    pub account: String,
    pub summary: SyncSummary,
    pub warnings: Vec<String>,
}

pub struct SyncEngine {
    paths: Paths,
    api: ApiClient,
}

impl SyncEngine {
    pub fn new(paths: Paths, api: ApiClient) -> Self {
        Self { paths, api }
    }

    /// Runs one full sync of `provider`'s usual login.
    pub async fn sync(&self, provider: Provider) -> Result<SyncOutcome> {
        self.sync_account(&Account::Provider(provider)).await
    }

    /// Runs one full sync for `account`, persisting state on every outcome.
    pub async fn sync_account(&self, account: &Account) -> Result<SyncOutcome> {
        let mut state = State::load(&self.paths)?;
        // The first sync links the account for good, so an extra home never syncs unasked.
        if account.home().is_some() && !account.is_enabled(&state) {
            bail!(
                "{account} is not enabled; run `tmx enable {}` to link it (linking is permanent)",
                account.handle()
            );
        }
        {
            let ps = account.state_mut(&mut state);
            ps.last_attempt_at = Some(Utc::now());
            if let Some(until) = ps.backoff_until
                && until > Utc::now()
            {
                return Err(BackingOff(until).into());
            }
        }
        state.save(&self.paths)?;

        match self.run(account, &mut state).await {
            Ok(outcome) => {
                let ps = account.state_mut(&mut state);
                ps.last_success_at = Some(Utc::now());
                ps.last_error = None;
                ps.backoff_until = None;
                ps.syncs += 1;
                ps.last_result = Some(outcome.summary.clone());
                state.save(&self.paths)?;
                Ok(outcome)
            }
            Err(e) => {
                self.remember_failure(account, &mut state, &e)?;
                Err(e)
            }
        }
    }

    fn remember_failure(
        &self,
        account: &Account,
        state: &mut State,
        error: &anyhow::Error,
    ) -> Result<()> {
        let ps = account.state_mut(state);
        ps.last_error = Some(describe(error));
        ps.backoff_until = Some(Utc::now() + backoff_for(error));
        state.save(&self.paths)
    }

    async fn run(&self, account: &Account, state: &mut State) -> Result<SyncOutcome> {
        let provider = account.provider();
        let credential = account.load_credential(&self.paths)?;
        let mut warnings = Vec::new();
        let mut summary = SyncSummary::default();
        let mut rounds = 0u32;

        loop {
            let issued = self
                .api
                .nonce(provider, credential.external_id_hint.as_deref())
                .await?;
            let spec = fill_credential(issued.spec, &credential.secret)?;

            info!(%account, requests = spec.requests.len(), "proving");
            let admission = self.api.notary_admission().await?;
            let proof = prove_with_ticket(&spec, &issued.notary, &admission.ticket)
                .await
                .with_context(|| format!("{account}: proof failed"))?;
            if let Some(bad) = proof.responses.iter().find(|r| r.status != 200) {
                let hint = match bad.status {
                    401 | 403 => "credential rejected; log in to the provider again",
                    429 => "rate limited; retrying later",
                    _ => "unexpected provider response",
                };
                bail!("{account}: provider answered HTTP {} ({hint})", bad.status);
            }

            // BOUNDED providers add exact local records; the server caps them by the proof.
            let (mut records, scanned, mut scan_warnings) =
                if provider.has_local_logs() && issued.tier == "BOUNDED" {
                    collect_records(account, state)?
                } else {
                    (Vec::new(), Scanned::Nothing, Vec::new())
                };
            records.extend(account.state_mut(state).pending_records.iter().cloned());
            let last_proof_at = issued
                .account
                .as_ref()
                .and_then(|a| a.last_proof_at.as_deref())
                .and_then(parse_time);
            let proof_at =
                DateTime::from_timestamp(proof.time as i64, 0).context("invalid proof time")?;
            let trimmed = trim_records(&mut records, last_proof_at, Utc::now(), proof_at);
            if trimmed.pending.len() > 200_000 {
                bail!(
                    "more than 200000 pending records: cursors preserved; reduce the local backlog before syncing"
                );
            }
            if trimmed.outside_interval > 0 {
                info!(%account, dropped = trimmed.outside_interval, "records older than the backfill horizon were not submitted");
            }
            if trimmed.over_cap > 0 {
                scan_warnings.push(format!(
                    "{} records queued for the next sync: upload limit is {MAX_RECORDS_PER_SYNC}",
                    trimmed.over_cap
                ));
            }
            warnings.extend(scan_warnings.iter().cloned());

            let request = SyncRequest {
                nonce: issued.nonce.clone(),
                provider,
                presentation: STANDARD.encode(&proof.presentation),
                records,
                client: ClientInfo {
                    version: crate::VERSION.to_string(),
                    warnings: clamp_warnings(scan_warnings),
                },
            };
            let response = self.api.sync(&request).await?;

            // Commit log cursors only once the server accepted the submission.
            commit_cursors(account, state, scanned);
            // Account totals can decrease when another device contributes late records.
            let ps = account.state_mut(state);
            ps.pending_records = trimmed.pending;
            ps.lifetime_credited_tokens = response.account_totals.tokens;
            ps.lifetime_unverified_tokens = response.account_totals.unverified;
            state.save(&self.paths)?;

            if rounds == 0 {
                summary.purpose = response.purpose.clone();
            }
            summary.credited_records += response.credited.records;
            summary.credited_tokens += response.credited.tokens;
            summary.reported_tokens += response.credited.reported;
            summary.unverified_tokens += response.credited.unverified;
            summary.rejected_records += response.rejected.records;
            for (reason, n) in response.rejected.reasons {
                *summary.rejected_reasons.entry(reason).or_insert(0) += n;
            }
            summary.label = response.account.label.clone().or(summary.label);
            summary.plan = response.account.plan.clone().or(summary.plan);
            info!(
                %account,
                verified = response.credited.tokens,
                unverified = response.credited.unverified,
                reported = response.credited.reported,
                rejected = response.rejected.records,
                "synced"
            );

            rounds += 1;
            summary.catch_up_rounds = rounds - 1;
            if response.catch_up.is_none() || rounds >= MAX_CATCH_UP_ROUNDS {
                break;
            }
        }

        Ok(SyncOutcome {
            provider,
            account: account.key(),
            summary,
            warnings,
        })
    }
}

/// Scanner cursors waiting for the server to accept a submission.
enum Scanned {
    Nothing,
    Claude(BTreeMap<String, u64>),
    Codex(BTreeMap<String, logs::codex::CodexFileCursor>),
}

type Collected = (Vec<LocalRecord>, Scanned, Vec<String>);

/// What [`trim_records`] removed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Trimmed {
    pub outside_interval: usize,
    pub over_cap: usize,
    pub pending: Vec<LocalRecord>,
}

/// Keep seven days of late records for linked accounts. Upload oldest first; preserve overflow
/// and records newer than the proof until a later sync. Scanner cursors and this queue commit together.
pub fn trim_records(
    records: &mut Vec<LocalRecord>,
    last_proof_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    proof_at: DateTime<Utc>,
) -> Trimmed {
    let mut trimmed = Trimmed::default();
    let floor = if last_proof_at.is_some() {
        now - Duration::days(7)
    } else {
        now - Duration::hours(1)
    };
    let before = records.len();
    records.retain(|r| parse_time(&r.occurred_at).is_none_or(|t| t >= floor));
    trimmed.outside_interval = before - records.len();
    // New scanner data precedes the pending queue; keep the largest complete usage for a key.
    let mut unique = BTreeMap::<String, LocalRecord>::new();
    for record in records.drain(..) {
        match unique.entry(record.external_key.clone()) {
            std::collections::btree_map::Entry::Vacant(e) => {
                e.insert(record);
            }
            std::collections::btree_map::Entry::Occupied(mut e) => {
                if record.total() > e.get().total() {
                    e.insert(record);
                }
            }
        }
    }
    let mut eligible: Vec<LocalRecord> = Vec::new();
    for record in unique.into_values() {
        if parse_time(&record.occurred_at).is_some_and(|t| t > proof_at) {
            trimmed.pending.push(record);
        } else {
            eligible.push(record);
        }
    }
    eligible.sort_by_key(|r| parse_time(&r.occurred_at));
    if eligible.len() > MAX_RECORDS_PER_SYNC {
        trimmed.over_cap = eligible.len() - MAX_RECORDS_PER_SYNC;
        trimmed
            .pending
            .extend(eligible.split_off(MAX_RECORDS_PER_SYNC));
    }
    *records = eligible;
    trimmed
}

/// Diagnostics never block a submission: keep the first `MAX_WARNINGS`, each cut to `MAX_WARNING_CHARS`.
pub fn clamp_warnings(warnings: Vec<String>) -> Vec<String> {
    warnings
        .into_iter()
        .take(MAX_WARNINGS)
        .map(|w| w.chars().take(MAX_WARNING_CHARS).collect())
        .collect()
}

fn parse_time(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

/// Each Claude home reads only its own `projects/` with its own cursors: a record is claimed by
/// the login stored next to the log that holds it, never by another home's.
fn collect_records(account: &Account, state: &State) -> Result<Collected> {
    match account {
        Account::Provider(Provider::Claude) => {
            let scan = logs::claude::scan(&state.claude_cursors)?;
            Ok((scan.records, Scanned::Claude(scan.cursors), scan.warnings))
        }
        Account::ClaudeHome(home) => {
            let empty = BTreeMap::new();
            let cursors = state
                .claude_homes
                .get(&home.id)
                .map_or(&empty, |h| &h.cursors);
            let scan = logs::claude::scan_in(&home.projects_dir(), cursors)?;
            Ok((scan.records, Scanned::Claude(scan.cursors), scan.warnings))
        }
        Account::Provider(Provider::Codex) => {
            let scan = logs::codex::scan(&state.codex_cursors)?;
            Ok((scan.records, Scanned::Codex(scan.cursors), scan.warnings))
        }
        Account::Provider(_) => Ok((Vec::new(), Scanned::Nothing, Vec::new())),
    }
}

fn commit_cursors(account: &Account, state: &mut State, scanned: Scanned) {
    match (account, scanned) {
        (_, Scanned::Nothing) => {}
        (Account::ClaudeHome(home), Scanned::Claude(c)) => {
            state
                .claude_homes
                .entry(home.id.clone())
                .or_default()
                .cursors = c;
        }
        (Account::Provider(_), Scanned::Claude(c)) => state.claude_cursors = c,
        (_, Scanned::Codex(c)) => state.codex_cursors = c,
    }
}

/// Substitutes the credential into hidden headers only; refuses specs that would reveal it.
pub fn fill_credential(mut spec: ProofSpec, secret: &str) -> Result<ProofSpec> {
    let mut substituted = 0;
    for request in &mut spec.requests {
        let secret_headers: Vec<String> = request
            .secret_headers
            .iter()
            .map(|h| h.to_ascii_lowercase())
            .collect();
        if request.path.contains(CREDENTIAL_PLACEHOLDER)
            || request
                .body
                .as_deref()
                .is_some_and(|b| b.contains(CREDENTIAL_PLACEHOLDER))
        {
            bail!("server spec would place the credential outside a hidden header");
        }
        for (name, value) in &mut request.headers {
            if value.contains(CREDENTIAL_PLACEHOLDER) {
                if !secret_headers.contains(&name.to_ascii_lowercase()) {
                    bail!("server spec would reveal the credential in header {name}");
                }
                *value = value.replace(CREDENTIAL_PLACEHOLDER, secret);
                substituted += 1;
            }
        }
    }
    if substituted == 0 {
        warn!("spec contains no credential placeholder");
    }
    Ok(spec)
}

fn backoff_for(error: &anyhow::Error) -> Duration {
    if error
        .downcast_ref::<tmx_attest::prove::NotaryBusy>()
        .is_some()
    {
        return Duration::seconds(30 + i64::from(rand::random::<u8>() % 30));
    }
    if let Some(api) = error.downcast_ref::<ApiError>() {
        return match api.code.as_str() {
            "notary_busy" => Duration::seconds(30 + i64::from(rand::random::<u8>() % 30)),
            "nonce_expired" | "proof_stale" => Duration::seconds(30),
            // A revoked or unpaired device answers 401 `unauthorized`; nothing changes until re-pairing.
            "account_bound_elsewhere" | "fingerprint_collision" | "unauthorized" => {
                Duration::hours(6)
            }
            "rate_limited" => api
                .details
                .as_ref()
                .and_then(|d| d.get("retryAfterMs"))
                .and_then(|v| v.as_i64())
                .map(|ms| Duration::milliseconds(ms.max(1_000)))
                .unwrap_or_else(|| Duration::minutes(15)),
            _ => Duration::minutes(5),
        };
    }
    let text = error.to_string();
    if text.contains("HTTP 429") {
        Duration::minutes(15)
    } else if text.contains("not logged in")
        || text.contains("expired")
        || text.contains("credential rejected")
        || text.contains("no ")
    {
        Duration::minutes(30)
    } else {
        Duration::minutes(5)
    }
}

/// Human-readable error: API rejections show `message (code)`, everything else its full cause chain.
pub fn describe(error: &anyhow::Error) -> String {
    error
        .downcast_ref::<ApiError>()
        .map(|e| format!("{} ({})", e.message, e.code))
        .unwrap_or_else(|| format!("{error:#}"))
}

impl SyncEngine {
    pub fn api(&self) -> &ApiClient {
        &self.api
    }
    pub fn paths(&self) -> &Paths {
        &self.paths
    }
}

pub fn unreachable_hint(e: &anyhow::Error) -> Option<&'static str> {
    if e.to_string().contains("API unreachable") {
        Some("Cannot reach the Tokenmaxxing API. Check your connection or server URL.")
    } else if e.to_string().contains("cannot reach notary") {
        Some("Cannot reach the notary. Proofs need it; try again in a minute.")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use tmx_attest::{RequestSpec, spec::ProofSpec};

    fn spec(headers: Vec<(String, String)>, secret: Vec<String>) -> ProofSpec {
        ProofSpec {
            server_name: "api.example.com".into(),
            port: 443,
            requests: vec![RequestSpec {
                method: "GET".into(),
                path: "/usage".into(),
                headers,
                secret_headers: secret,
                body: None,
            }],
            redactions: vec![],
            secret_response_headers: vec![],
            max_sent_data: 4096,
            max_recv_data: 4096,
            max_recv_data_online: None,
        }
    }

    #[tokio::test]
    async fn proof_timeout_persists_diagnostic_and_preserves_pending_work_for_retry() {
        let directory = tempfile::tempdir().unwrap();
        let paths = Paths::at(directory.path().to_owned()).unwrap();
        let engine = SyncEngine::new(
            paths.clone(),
            ApiClient::new("http://127.0.0.1:9", None).unwrap(),
        );
        let mut state = State::default();
        state.claude_cursors.insert("retained-log".into(), 123);
        let pending = rec(Utc::now(), 1);
        state
            .provider(Provider::Claude)
            .pending_records
            .push(pending.clone());
        state.provider(Provider::Claude).lifetime_credited_tokens = 42;
        let error = anyhow::Error::new(tmx_attest::prove::ProofTimedOut { seconds: 300 })
            .context("claude: proof failed");
        engine
            .remember_failure(&Account::Provider(Provider::Claude), &mut state, &error)
            .unwrap();
        let mut stored = State::load(&paths).unwrap();
        assert_eq!(stored.claude_cursors["retained-log"], 123);
        let provider = stored.provider(Provider::Claude);
        assert_eq!(provider.pending_records, vec![pending]);
        assert_eq!(provider.lifetime_credited_tokens, 42);
        assert!(
            provider
                .last_error
                .as_ref()
                .unwrap()
                .contains("timed out after 300 seconds")
        );
        assert!(provider.backoff_until.unwrap() > Utc::now());
        assert!(
            engine
                .sync(Provider::Claude)
                .await
                .unwrap_err()
                .downcast_ref::<BackingOff>()
                .is_some()
        );
    }

    #[test]
    fn claude_homes_collect_and_commit_only_their_own_logs() {
        use crate::claude_homes::{ClaudeHome, HomeOrigin};
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join(".claude-work");
        std::fs::create_dir_all(dir.join("projects/p")).unwrap();
        // Joined per component: cursor keys use the platform separator.
        let log = dir.join("projects").join("p").join("s.jsonl");
        std::fs::write(
            &log,
            concat!(
                r#"{"type":"assistant","requestId":"req_w","timestamp":"2026-09-01T12:00:00Z","message":{"model":"claude-opus-5","usage":{"input_tokens":3,"output_tokens":4}}}"#,
                "\n"
            ),
        )
        .unwrap();
        let work = Account::ClaudeHome(ClaudeHome {
            id: "abcd1234".into(),
            name: "work".into(),
            dir,
            origin: HomeOrigin::Discovered,
        });
        let mut state = State::default();
        state.claude_cursors.insert("/default/log.jsonl".into(), 7);

        let (records, scanned, _) = collect_records(&work, &state).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].external_key, "req_w");
        commit_cursors(&work, &mut state, scanned);
        let key = log.to_string_lossy().into_owned();
        assert!(state.claude_homes["abcd1234"].cursors.contains_key(&key));
        // The default home's cursors are neither read nor replaced by the extra home.
        assert_eq!(
            state.claude_cursors,
            BTreeMap::from([("/default/log.jsonl".to_string(), 7)])
        );
        // Committed cursors mean the next scan finds nothing new.
        let (again, _, _) = collect_records(&work, &state).unwrap();
        assert!(again.is_empty());
    }

    #[tokio::test]
    async fn an_extra_claude_home_never_syncs_until_enabled() {
        use crate::claude_homes::{ClaudeHome, HomeOrigin};
        let directory = tempfile::tempdir().unwrap();
        let paths = Paths::at(directory.path().join("data")).unwrap();
        let engine = SyncEngine::new(
            paths.clone(),
            ApiClient::new("http://127.0.0.1:9", None).unwrap(),
        );
        let work = Account::ClaudeHome(ClaudeHome {
            id: "abcd1234".into(),
            name: "work".into(),
            dir: directory.path().join(".claude-work"),
            origin: HomeOrigin::Discovered,
        });
        let error = engine.sync_account(&work).await.unwrap_err();
        assert!(
            error.to_string().contains("tmx enable claude:work"),
            "{error}"
        );
        // Refused before anything was recorded for it.
        assert!(State::load(&paths).unwrap().claude_homes.is_empty());
    }

    #[tokio::test]
    async fn records_queued_under_the_default_login_never_go_out_with_another_homes_proof() {
        use crate::claude_homes::{self, DiscoveryInput, HomeOrigin};
        let directory = tempfile::tempdir().unwrap();
        let home = directory.path();
        let paths = Paths::at(home.join("data")).unwrap();
        let other = home.join("elsewhere/other");
        std::fs::create_dir_all(other.join("projects/p")).unwrap();
        std::fs::write(
            other.join("projects/p/s.jsonl"),
            concat!(
                r#"{"type":"assistant","requestId":"req_other","timestamp":"2026-09-01T12:00:00Z","message":{"model":"claude-opus-5","usage":{"input_tokens":3,"output_tokens":4}}}"#,
                "\n"
            ),
        )
        .unwrap();
        // Queued while syncing the ~/.claude login.
        let mut state = State::default();
        let queued = rec(Utc::now(), 1);
        state
            .provider(Provider::Claude)
            .pending_records
            .push(queued.clone());
        state.save(&paths).unwrap();

        // A shell exporting CLAUDE_CONFIG_DIR=<other> finds that login as an extra home only.
        let found = claude_homes::discover_in(&DiscoveryInput {
            home,
            default_projects: &home.join(".claude/projects"),
            env: None,
            config_dir: Some(other.as_os_str()),
            configured: &[],
        });
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].origin, HomeOrigin::ConfigDirEnv);
        let default = Account::Provider(Provider::Claude);
        let work = Account::ClaudeHome(found[0].clone());
        assert!(default.is_enabled(&state));
        assert!(!work.is_enabled(&state), "an env-named home is opt-in");

        // The default account proves only the ~/.claude login.
        let default_login = claude_homes::default_login().unwrap();
        assert_eq!(
            default_login.keychain_services,
            [claude_homes::KEYCHAIN_SERVICE]
        );
        assert_eq!(
            default_login.credentials_file,
            crate::paths::home_dir()
                .unwrap()
                .join(".claude/.credentials.json")
        );
        assert!(
            !work
                .home()
                .unwrap()
                .login_store()
                .keychain_services
                .contains(&claude_homes::KEYCHAIN_SERVICE.to_string())
        );

        // What the other home would submit: its own logs and its own (empty) queue.
        let (records, _, _) = collect_records(&work, &state).unwrap();
        assert_eq!(
            records
                .iter()
                .map(|r| r.external_key.as_str())
                .collect::<Vec<_>>(),
            ["req_other"]
        );
        assert!(work.state(&state).pending_records.is_empty());
        assert_eq!(
            default.state(&state).pending_records,
            std::slice::from_ref(&queued)
        );

        // And it cannot sync at all until linked; the default queue is untouched.
        let engine = SyncEngine::new(
            paths.clone(),
            ApiClient::new("http://127.0.0.1:9", None).unwrap(),
        );
        assert!(engine.sync_account(&work).await.is_err());
        let stored = State::load(&paths).unwrap();
        assert_eq!(
            stored.providers[&Provider::Claude].pending_records,
            [queued]
        );
        assert!(stored.claude_homes.is_empty());
    }

    #[test]
    fn fills_only_hidden_headers() {
        let filled = fill_credential(
            spec(
                vec![
                    ("Authorization".into(), "Bearer {{credential}}".into()),
                    ("User-Agent".into(), "x".into()),
                ],
                vec!["authorization".into()],
            ),
            "s3cret",
        )
        .unwrap();
        assert_eq!(filled.requests[0].headers[0].1, "Bearer s3cret");
        let leak = fill_credential(
            spec(vec![("X-Key".into(), "{{credential}}".into())], vec![]),
            "s3cret",
        );
        assert!(leak.is_err());
    }

    #[test]
    fn api_errors_get_targeted_backoff() {
        let e: anyhow::Error = ApiError {
            status: 403,
            code: "account_bound_elsewhere".into(),
            message: "x".into(),
            details: None,
        }
        .into();
        assert_eq!(backoff_for(&e), Duration::hours(6));
        let revoked: anyhow::Error = ApiError {
            status: 401,
            code: "unauthorized".into(),
            message: "x".into(),
            details: None,
        }
        .into();
        assert_eq!(backoff_for(&revoked), Duration::hours(6));
        let limited: anyhow::Error = ApiError {
            status: 429,
            code: "rate_limited".into(),
            message: "x".into(),
            details: Some(serde_json::json!({ "retryAfterMs": 42_000 })),
        }
        .into();
        assert_eq!(backoff_for(&limited), Duration::milliseconds(42_000));
        let limited_no_hint: anyhow::Error = ApiError {
            status: 429,
            code: "rate_limited".into(),
            message: "x".into(),
            details: None,
        }
        .into();
        assert_eq!(backoff_for(&limited_no_hint), Duration::minutes(15));
        assert_eq!(
            backoff_for(&anyhow!("provider answered HTTP 429")),
            Duration::minutes(15)
        );
        let _ = unreachable_hint(&anyhow!("API unreachable"));
    }

    #[test]
    fn warnings_are_clamped_to_what_the_api_accepts() {
        let long = "x".repeat(400);
        let clamped = clamp_warnings((0..25).map(|_| long.clone()).collect());
        assert_eq!(clamped.len(), MAX_WARNINGS);
        assert!(
            clamped
                .iter()
                .all(|w| w.chars().count() == MAX_WARNING_CHARS)
        );
    }

    fn rec(now: DateTime<Utc>, mins_ago: i64) -> LocalRecord {
        LocalRecord {
            external_key: format!("r{mins_ago}"),
            occurred_at: (now - Duration::minutes(mins_ago)).to_rfc3339(),
            model: "m".into(),
            input_tokens: 1,
            output_tokens: 0,
            cache_creation_tokens: 0,
            cache_read_tokens: 0,
        }
    }

    #[test]
    fn keeps_second_device_history_and_defers_records_after_the_proof() {
        let now = Utc::now();
        let mut records = vec![rec(now, 8 * 1440), rec(now, 600), rec(now, 30), rec(now, 1)];
        let t = trim_records(
            &mut records,
            Some(now - Duration::minutes(40)),
            now,
            now - Duration::minutes(2),
        );
        assert_eq!(t.outside_interval, 1);
        assert_eq!(
            t.pending
                .iter()
                .map(|r| r.external_key.as_str())
                .collect::<Vec<_>>(),
            ["r1"]
        );
        assert_eq!(
            records
                .iter()
                .map(|r| r.external_key.as_str())
                .collect::<Vec<_>>(),
            ["r600", "r30"]
        );
        // The next proof can accept the queued record even though another device closed its interval.
        let mut queued = t.pending;
        let next = trim_records(
            &mut queued,
            Some(now),
            now + Duration::minutes(10),
            now + Duration::minutes(10),
        );
        assert!(next.pending.is_empty());
        assert_eq!(queued.len(), 1);

        let mut records = vec![rec(now, 600), rec(now, 30)];
        assert_eq!(
            trim_records(&mut records, None, now, now).outside_interval,
            1
        );
    }

    #[test]
    fn caps_uploads_without_discarding_the_backlog() {
        let now = Utc::now();
        let mut records: Vec<LocalRecord> = (0..(MAX_RECORDS_PER_SYNC as i64 + 3))
            .map(|i| {
                let mut r = rec(now, 1);
                r.external_key = format!("r{i:05}");
                r.occurred_at = (now - Duration::seconds(i)).to_rfc3339();
                r
            })
            .collect();
        let t = trim_records(&mut records, Some(now), now, now);
        assert_eq!(t.over_cap, 3);
        assert_eq!(t.outside_interval, 0);
        assert_eq!(records.len(), MAX_RECORDS_PER_SYNC);
        assert_eq!(t.pending.len(), 3);
        assert!(
            t.pending
                .iter()
                .all(|r| matches!(r.external_key.as_str(), "r00000" | "r00001" | "r00002"))
        );
    }

    #[test]
    fn deduplicates_pending_records_against_updated_scanner_data() {
        let now = Utc::now();
        let original = rec(now, 2);
        let updated = LocalRecord {
            input_tokens: 10,
            ..original.clone()
        };
        let mut records = vec![original, updated];
        let t = trim_records(&mut records, Some(now), now, now);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].input_tokens, 10);
        assert!(t.pending.is_empty());
    }
}
