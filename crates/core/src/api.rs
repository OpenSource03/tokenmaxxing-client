//! Device-signed HTTP client for the Tokenmaxxing API (`apps/api`).

use std::{collections::BTreeMap, fmt, time::Duration};

use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rand::RngCore;
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use tmx_attest::ProofSpec;

use crate::{identity::DeviceIdentity, provider::Provider};

/// Structured API rejection (`{ error: { code, message, details } }`).
#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
#[error("{message} ({code})")]
pub struct ApiError {
    pub status: u16,
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub details: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}
#[derive(Deserialize)]
struct ErrorBody {
    code: String,
    message: String,
    #[serde(default)]
    details: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairRequest {
    pub code: String,
    pub public_key: String,
    pub name: String,
    pub platform: String,
    pub app_version: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfo {
    pub id: String,
    pub name: String,
    pub platform: String,
    pub status: String,
    #[serde(default)]
    pub app_version: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserInfo {
    pub id: String,
    pub username: String,
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderInfo {
    pub id: String,
    pub name: String,
    pub tier: String,
    pub server_name: String,
    pub credential: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerInfo {
    pub notary: String,
    pub providers: Vec<ProviderInfo>,
    /// Public web origin (leaderboard, dashboard) — where users get pairing codes.
    #[serde(default)]
    pub web: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairResponse {
    pub device: DeviceInfo,
    pub user: UserInfo,
    pub server: ServerInfo,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NonceRequest<'a> {
    provider: Provider,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_id: Option<&'a str>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountInfo {
    pub id: String,
    #[serde(default)]
    pub provider: Option<String>,
    pub external_id: String,
    #[serde(default)]
    pub tier: Option<String>,
    #[serde(default)]
    pub plan: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub last_proof_at: Option<String>,
    #[serde(default)]
    pub total_tokens: Option<u64>,
    /// Claimed tokens the calibrated envelope could not verify (docs/calibration.md §3).
    #[serde(default)]
    pub unverified_tokens: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuedNonce {
    pub nonce: String,
    pub issued_at: String,
    pub expires_at: String,
    pub notary: String,
    pub provider: String,
    pub tier: String,
    pub spec: ProofSpec,
    #[serde(default)]
    pub account: Option<AccountInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LocalRecord {
    pub external_key: String,
    pub occurred_at: String,
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_creation_tokens: u64,
    pub cache_read_tokens: u64,
}

impl LocalRecord {
    pub fn total(&self) -> u64 {
        self.input_tokens + self.output_tokens + self.cache_creation_tokens + self.cache_read_tokens
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientInfo {
    pub version: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncRequest {
    pub nonce: String,
    pub provider: Provider,
    pub presentation: String,
    pub records: Vec<LocalRecord>,
    pub client: ClientInfo,
}

/// `credited` of a sync response. `tokens` is the verified share that is ranked; `reported` is
/// the raw claim and `unverified` the remainder. Older servers send neither, hence the defaults.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Counts {
    #[serde(default)]
    pub records: u64,
    pub tokens: u64,
    #[serde(default)]
    pub reported: u64,
    #[serde(default)]
    pub unverified: u64,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Rejected {
    pub records: u64,
    #[serde(default)]
    pub reasons: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncResponse {
    pub proof_id: String,
    pub purpose: String,
    pub session_time: String,
    pub account: AccountInfo,
    pub credited: Counts,
    pub account_totals: Counts,
    pub rejected: Rejected,
    #[serde(default)]
    pub envelope: Option<serde_json::Value>,
    #[serde(default)]
    pub windows: Vec<serde_json::Value>,
    #[serde(default)]
    pub catch_up: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceMe {
    pub device: DeviceInfo,
    pub user: UserInfo,
    /// Verified tokens, i.e. what the board ranks.
    pub total_tokens: u64,
    #[serde(default)]
    pub reported_tokens: u64,
    #[serde(default)]
    pub unverified_tokens: u64,
    pub accounts: Vec<AccountInfo>,
    pub server: ServerInfo,
}

// ---- reference burns (docs/calibration.md §8) --------------------------------------------------

/// What a scheduled burn measures. Serialised exactly as the API's `BurnProfile` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BurnProfile {
    /// Unique filler once: fresh input tokens, no cache hits.
    FreshInput,
    /// The same filler `repeats` times: one cache write, `repeats − 1` cache reads.
    CachedInput,
    /// A short instruction that asks for `targetTokens` worth of prose.
    Output,
}

impl BurnProfile {
    pub fn id(self) -> &'static str {
        match self {
            BurnProfile::FreshInput => "FRESH_INPUT",
            BurnProfile::CachedInput => "CACHED_INPUT",
            BurnProfile::Output => "OUTPUT",
        }
    }
}

impl fmt::Display for BurnProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

/// A burn the server scheduled for a reference account of this device's user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingBurn {
    pub id: String,
    pub provider: Provider,
    pub model: String,
    pub profile: BurnProfile,
    pub target_tokens: u64,
    pub repeats: u32,
    pub scheduled_at: String,
}

/// The burn as it comes back from `claim` — the server's values win over the polled ones.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimedBurn {
    pub id: String,
    pub provider: Provider,
    pub model: String,
    pub profile: BurnProfile,
    pub target_tokens: u64,
    pub repeats: u32,
    pub status: String,
    #[serde(default)]
    pub started_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompletedBurn {
    pub id: String,
    pub status: String,
    #[serde(default)]
    pub finished_at: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

/// What the client believes it burned. Informational: the measurement comes from the proofs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BurnTokens {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<u64>,
}

#[derive(Deserialize)]
struct PendingBurnsEnvelope {
    #[serde(default)]
    burns: Vec<PendingBurn>,
}

#[derive(Deserialize)]
struct BurnEnvelope<T> {
    burn: T,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CompleteBurnRequest {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tokens: Option<BurnTokens>,
}

/// One-use admission capability for the notary TCP endpoint.
#[derive(Deserialize)]
pub struct NotaryAdmission {
    pub ticket: String,
    pub expires_in: u64,
}

/// `{}` — empty signed requests still cover a body hash.
#[derive(Serialize)]
struct EmptyBody {}

pub struct ApiClient {
    http: Client,
    base: String,
    identity: Option<DeviceIdentity>,
}

impl ApiClient {
    pub fn new(base_url: &str, identity: Option<DeviceIdentity>) -> Result<Self> {
        let http = Client::builder()
            .user_agent(format!("tokenmaxxing-app/{}", crate::VERSION))
            .timeout(Duration::from_secs(90))
            .build()?;
        Ok(Self {
            http,
            base: base_url.trim_end_matches('/').to_string(),
            identity,
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base
    }

    pub fn identity(&self) -> Option<&DeviceIdentity> {
        self.identity.as_ref()
    }

    pub async fn meta(&self) -> Result<ServerInfo> {
        let res = self
            .http
            .get(format!("{}/v1/meta", self.base))
            .send()
            .await
            .context("API unreachable")?;
        Self::handle(res).await
    }

    pub async fn pair(&self, request: &PairRequest) -> Result<PairResponse> {
        let res = self
            .http
            .post(format!("{}/v1/devices/pair", self.base))
            .json(request)
            .send()
            .await
            .context("API unreachable")?;
        Self::handle(res).await
    }

    pub async fn notary_admission(&self) -> Result<NotaryAdmission> {
        self.signed(Method::POST, "/v1/notary/admission", Some(&EmptyBody {}))
            .await
    }

    pub async fn nonce(
        &self,
        provider: Provider,
        external_id: Option<&str>,
    ) -> Result<IssuedNonce> {
        self.signed(
            Method::POST,
            "/v1/sync/nonce",
            Some(&NonceRequest {
                provider,
                external_id,
            }),
        )
        .await
    }

    pub async fn sync(&self, request: &SyncRequest) -> Result<SyncResponse> {
        self.signed(Method::POST, "/v1/sync", Some(request)).await
    }

    pub async fn device_me(&self) -> Result<DeviceMe> {
        self.signed::<(), DeviceMe>(Method::GET, "/v1/device/me", None)
            .await
    }

    /// Burns waiting for this device's user, optionally narrowed to one provider.
    pub async fn pending_burns(&self, provider: Option<Provider>) -> Result<Vec<PendingBurn>> {
        // The device signature covers path *and* query, so the query has to travel inside `path`.
        let path = match provider {
            Some(p) => format!("/v1/reference/burns?provider={}", p.id()),
            None => "/v1/reference/burns".to_string(),
        };
        let envelope: PendingBurnsEnvelope = self.signed::<(), _>(Method::GET, &path, None).await?;
        Ok(envelope.burns)
    }

    pub async fn claim_burn(&self, id: &str) -> Result<ClaimedBurn> {
        let path = format!("/v1/reference/burns/{}/claim", urlencoding::encode(id));
        let envelope: BurnEnvelope<ClaimedBurn> = self
            .signed(Method::POST, &path, Some(&EmptyBody {}))
            .await?;
        Ok(envelope.burn)
    }

    pub async fn complete_burn(
        &self,
        id: &str,
        ok: bool,
        error: Option<String>,
        tokens: Option<BurnTokens>,
    ) -> Result<CompletedBurn> {
        let path = format!("/v1/reference/burns/{}/complete", urlencoding::encode(id));
        let envelope: BurnEnvelope<CompletedBurn> = self
            .signed(
                Method::POST,
                &path,
                Some(&CompleteBurnRequest { ok, error, tokens }),
            )
            .await?;
        Ok(envelope.burn)
    }

    async fn signed<B: Serialize, T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<T> {
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| anyhow!("this device is not paired"))?;
        let text = body
            .map(serde_json::to_string)
            .transpose()?
            .unwrap_or_default();
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let mut nonce_bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = hex::encode(nonce_bytes);
        let payload = format!(
            "tmx-v1\n{}\n{}\n{}\n{}\n{}",
            method.as_str().to_ascii_uppercase(),
            path,
            timestamp,
            nonce,
            hex::encode(Sha256::digest(text.as_bytes()))
        );
        let signature = STANDARD.encode(identity.sign(payload.as_bytes())?);
        let mut request = self
            .http
            .request(method, format!("{}{}", self.base, path))
            .header("x-tmx-device", &identity.device_id)
            .header("x-tmx-timestamp", timestamp)
            .header("x-tmx-nonce", nonce)
            .header("x-tmx-signature", signature);
        if !text.is_empty() {
            request = request
                .header("content-type", "application/json")
                .body(text);
        }
        Self::handle(request.send().await.context("API unreachable")?).await
    }

    async fn handle<T: DeserializeOwned>(res: reqwest::Response) -> Result<T> {
        let status = res.status();
        let text = res.text().await.context("cannot read API response")?;
        if status.is_success() {
            return serde_json::from_str(&text)
                .with_context(|| format!("unexpected API response ({status})"));
        }
        match serde_json::from_str::<ErrorEnvelope>(&text) {
            Ok(envelope) => Err(ApiError {
                status: status.as_u16(),
                code: envelope.error.code,
                message: envelope.error.message,
                details: envelope.error.details,
            }
            .into()),
            Err(_) => Err(anyhow!(
                "API error {status}: {}",
                text.chars().take(200).collect::<String>()
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialises_the_api_contract_in_camel_case() {
        let request = SyncRequest {
            nonce: "n".into(),
            provider: Provider::Claude,
            presentation: "AAAA".into(),
            records: vec![LocalRecord {
                external_key: "req_1".into(),
                occurred_at: "2026-09-02T10:00:00Z".into(),
                model: "claude".into(),
                input_tokens: 1,
                output_tokens: 2,
                cache_creation_tokens: 3,
                cache_read_tokens: 4,
            }],
            client: ClientInfo {
                version: "0.2.0".into(),
                warnings: vec![],
            },
        };
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&request).unwrap()).unwrap();
        assert_eq!(json["provider"], "CLAUDE");
        assert_eq!(json["records"][0]["externalKey"], "req_1");
        assert_eq!(json["records"][0]["cacheReadTokens"], 4);
        assert_eq!(request.records[0].total(), 10);
    }

    #[test]
    fn counts_parse_without_the_calibration_fields() {
        let old: Counts = serde_json::from_str(r#"{"records":3,"tokens":120}"#).unwrap();
        assert_eq!(
            (old.records, old.tokens, old.reported, old.unverified),
            (3, 120, 0, 0)
        );
        let new: Counts =
            serde_json::from_str(r#"{"records":3,"tokens":120,"reported":200,"unverified":80}"#)
                .unwrap();
        assert_eq!((new.reported, new.unverified), (200, 80));

        let me: DeviceMe = serde_json::from_str(
            r#"{"device":{"id":"d","name":"n","platform":"macos","status":"ACTIVE"},"user":{"id":"u","username":"u"},"totalTokens":10,"accounts":[{"id":"a","externalId":"x"}],"server":{"notary":"n","providers":[]}}"#,
        )
        .unwrap();
        assert_eq!((me.reported_tokens, me.unverified_tokens), (0, 0));
        assert_eq!(me.accounts[0].unverified_tokens, None);
    }

    #[test]
    fn burn_types_round_trip_through_the_wire_shape() {
        let json = r#"{"burns":[{"id":"b1","provider":"CLAUDE","model":"claude-opus-4","profile":"CACHED_INPUT","targetTokens":100000,"repeats":10,"scheduledAt":"2026-09-04T10:00:00.000Z"}]}"#;
        let envelope: PendingBurnsEnvelope = serde_json::from_str(json).unwrap();
        let burn = &envelope.burns[0];
        assert_eq!(burn.profile, BurnProfile::CachedInput);
        assert_eq!(burn.provider, Provider::Claude);
        assert_eq!((burn.target_tokens, burn.repeats), (100_000, 10));
        let back: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(burn).unwrap()).unwrap();
        assert_eq!(back["targetTokens"], 100_000);
        assert_eq!(back["profile"], "CACHED_INPUT");
        assert_eq!(back["scheduledAt"], "2026-09-04T10:00:00.000Z");
        assert_eq!(
            serde_json::from_str::<PendingBurnsEnvelope>(r#"{}"#)
                .unwrap()
                .burns
                .len(),
            0
        );

        let claimed: BurnEnvelope<ClaimedBurn> = serde_json::from_str(
            r#"{"burn":{"id":"b1","provider":"CODEX","model":"gpt-5","profile":"OUTPUT","targetTokens":20000,"repeats":1,"status":"RUNNING","startedAt":"2026-09-04T10:01:00.000Z"}}"#,
        )
        .unwrap();
        assert_eq!(claimed.burn.profile, BurnProfile::Output);
        assert_eq!(claimed.burn.status, "RUNNING");

        let done: BurnEnvelope<CompletedBurn> =
            serde_json::from_str(r#"{"burn":{"id":"b1","status":"FAILED","finishedAt":"2026-09-04T10:20:00.000Z","error":"boom"}}"#).unwrap();
        assert_eq!(done.burn.error.as_deref(), Some("boom"));

        for (profile, id) in [
            (BurnProfile::FreshInput, "FRESH_INPUT"),
            (BurnProfile::CachedInput, "CACHED_INPUT"),
            (BurnProfile::Output, "OUTPUT"),
        ] {
            assert_eq!(profile.id(), id);
            assert_eq!(
                serde_json::to_string(&profile).unwrap(),
                format!("\"{id}\"")
            );
            assert_eq!(profile.to_string(), id);
        }
    }

    #[test]
    fn burn_requests_serialise_as_the_protocol_expects() {
        assert_eq!(serde_json::to_string(&EmptyBody {}).unwrap(), "{}");
        let body = serde_json::to_string(&CompleteBurnRequest {
            ok: true,
            error: None,
            tokens: Some(BurnTokens {
                input: Some(120_000),
                output: Some(40),
            }),
        })
        .unwrap();
        assert_eq!(body, r#"{"ok":true,"tokens":{"input":120000,"output":40}}"#);
        let failed = serde_json::to_string(&CompleteBurnRequest {
            ok: false,
            error: Some("timed out".into()),
            tokens: None,
        })
        .unwrap();
        assert_eq!(failed, r#"{"ok":false,"error":"timed out"}"#);
    }

    #[test]
    fn parses_error_envelopes() {
        let env: ErrorEnvelope = serde_json::from_str(
            r#"{"error":{"code":"nonce_used","message":"nonce already consumed"}}"#,
        )
        .unwrap();
        assert_eq!(env.error.code, "nonce_used");
    }
}
