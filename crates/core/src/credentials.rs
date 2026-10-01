//! Provider credentials, read from where the official tools already keep them.
//!
//! Rule: a credential is only ever placed into the hidden header of an MPC-TLS session. It is
//! never logged, persisted by us (except the API keys the user pastes, stored 0600), or sent to
//! the Tokenmaxxing API.

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

use crate::{
    claude_homes::{self, ClaudeHome, HomeLogin, LoginStore, StoredLogin},
    paths::{Paths, home_dir, write_private},
    provider::Provider,
};

/// A resolved credential plus the identity hint the API may need before the proof.
pub struct Credential {
    /// Substituted for `{{credential}}` in the spec's hidden header.
    pub secret: String,
    /// Provider account id known locally (Codex account id, Claude account uuid). Not secret.
    pub external_id_hint: Option<String>,
    /// Where it came from, for the status screen.
    pub source: String,
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("external_id_hint", &self.external_id_hint)
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

/// API keys the user pasted for providers without a desktop login.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ProviderKeys {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zai: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub openrouter: Option<String>,
}

impl ProviderKeys {
    pub fn load(paths: &Paths) -> Result<Self> {
        let path = paths.providers_file();
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw =
            std::fs::read(&path).with_context(|| format!("cannot read {}", path.display()))?;
        serde_json::from_slice(&raw).context("providers.json is corrupt")
    }

    pub fn save(&self, paths: &Paths) -> Result<()> {
        write_private(&paths.providers_file(), &serde_json::to_vec_pretty(self)?)
    }

    pub fn set(&mut self, provider: Provider, key: Option<String>) -> Result<()> {
        let key = key.map(|k| k.trim().to_string()).filter(|k| !k.is_empty());
        match provider {
            Provider::Zai => self.zai = key,
            Provider::Openrouter => self.openrouter = key,
            other => bail!("{other} does not take an API key"),
        }
        Ok(())
    }

    pub fn has(&self, provider: Provider) -> bool {
        match provider {
            Provider::Zai => self.zai.is_some(),
            Provider::Openrouter => self.openrouter.is_some(),
            _ => false,
        }
    }
}

/// Whether a credential is available, without exposing it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialStatus {
    pub provider: Provider,
    pub available: bool,
    pub source: String,
    #[serde(default)]
    pub detail: Option<String>,
}

pub fn status(paths: &Paths, provider: Provider) -> CredentialStatus {
    status_from(provider, load(paths, provider))
}

/// The status of an attempted load, keeping the secret out of it.
pub fn status_from(provider: Provider, loaded: Result<Credential>) -> CredentialStatus {
    match loaded {
        Ok(c) => CredentialStatus {
            provider,
            available: true,
            source: c.source,
            detail: c.external_id_hint,
        },
        Err(e) => CredentialStatus {
            provider,
            available: false,
            source: String::new(),
            detail: Some(e.to_string()),
        },
    }
}

pub fn load(paths: &Paths, provider: Provider) -> Result<Credential> {
    match provider {
        Provider::Claude => claude(),
        Provider::Codex => codex(),
        Provider::Cursor => cursor(),
        Provider::Zai => {
            let keys = ProviderKeys::load(paths)?;
            Ok(Credential {
                secret: keys
                    .zai
                    .ok_or_else(|| anyhow!("no Z.ai API key configured"))?,
                external_id_hint: None,
                source: "Z.ai API key (local settings)".into(),
            })
        }
        Provider::Openrouter => {
            let keys = ProviderKeys::load(paths)?;
            Ok(Credential {
                secret: keys
                    .openrouter
                    .ok_or_else(|| anyhow!("no OpenRouter API key configured"))?,
                external_id_hint: None,
                source: "OpenRouter API key (local settings)".into(),
            })
        }
    }
}

// ---- Claude Code ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ClaudeCredentials {
    #[serde(rename = "claudeAiOauth")]
    oauth: Option<ClaudeOauth>,
}
#[derive(Deserialize)]
struct ClaudeOauth {
    #[serde(rename = "accessToken")]
    access_token: String,
    #[serde(rename = "expiresAt", default)]
    expires_at: Option<i64>,
}

fn claude() -> Result<Credential> {
    claude_from(&claude_homes::default_login()?)
}

/// The login of an extra Claude Code config home: its one stored login, never a guess among several.
pub fn claude_home(home: &ClaudeHome) -> Result<Credential> {
    let store = home.login_store();
    match store.locate(&claude_homes::keychain_has) {
        HomeLogin::Found(login) => claude_parse(&store, read_stored(&login)?),
        other => bail!(
            "{}: {}",
            home.dir.display(),
            other.problem().unwrap_or_default()
        ),
    }
}

fn claude_from(store: &LoginStore) -> Result<Credential> {
    claude_parse(store, claude_raw_credentials(store)?)
}

fn claude_parse(store: &LoginStore, (raw, source): (String, String)) -> Result<Credential> {
    let creds: ClaudeCredentials =
        serde_json::from_str(&raw).context("Claude credentials are not JSON")?;
    let oauth = creds
        .oauth
        .ok_or_else(|| anyhow!("Claude Code is not logged in with a claude.ai account"))?;
    if let Some(exp) = oauth.expires_at {
        let now_ms = chrono::Utc::now().timestamp_millis();
        if exp < now_ms {
            bail!("Claude Code login has expired; open Claude Code once to refresh it");
        }
    }
    let hint = std::fs::read_to_string(&store.account_file)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| {
            v.pointer("/oauthAccount/accountUuid")
                .and_then(|x| x.as_str())
                .map(str::to_string)
        });
    Ok(Credential {
        secret: oauth.access_token,
        external_id_hint: hint,
        source,
    })
}

fn claude_raw_credentials(store: &LoginStore) -> Result<(String, String)> {
    #[cfg(target_os = "macos")]
    for service in &store.keychain_services {
        let out = std::process::Command::new("security")
            .args(["find-generic-password", "-s", service, "-w"])
            .output();
        if let Ok(out) = out
            && out.status.success()
        {
            let source = if service == claude_homes::KEYCHAIN_SERVICE {
                "Claude Code login (macOS Keychain)".to_string()
            } else {
                format!("Claude Code login (macOS Keychain, {service})")
            };
            return Ok((
                String::from_utf8_lossy(&out.stdout).trim().to_string(),
                source,
            ));
        }
    }
    let path = &store.credentials_file;
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("Claude Code is not logged in ({} missing)", path.display()))?;
    let source = match home_dir() {
        Ok(home) if path == &home.join(".claude").join(".credentials.json") => {
            "Claude Code login (~/.claude/.credentials.json)".to_string()
        }
        _ => format!("Claude Code login ({})", path.display()),
    };
    Ok((raw, source))
}

/// Reads exactly the stored login that was located.
fn read_stored(login: &StoredLogin) -> Result<(String, String)> {
    match login {
        #[cfg(target_os = "macos")]
        StoredLogin::Keychain(service) => {
            let out = std::process::Command::new("security")
                .args(["find-generic-password", "-s", service, "-w"])
                .output()
                .context("cannot run `security`")?;
            if !out.status.success() {
                bail!("cannot read the Keychain item {service}");
            }
            Ok((
                String::from_utf8_lossy(&out.stdout).trim().to_string(),
                login.describe(),
            ))
        }
        #[cfg(not(target_os = "macos"))]
        StoredLogin::Keychain(service) => bail!("no Keychain on this platform ({service})"),
        StoredLogin::File(path) => Ok((
            std::fs::read_to_string(path)
                .with_context(|| format!("cannot read {}", path.display()))?,
            login.describe(),
        )),
    }
}

// ---- Codex ---------------------------------------------------------------------------------

#[derive(Deserialize)]
struct CodexAuth {
    tokens: Option<CodexTokens>,
}
#[derive(Deserialize)]
struct CodexTokens {
    access_token: String,
    #[serde(default)]
    account_id: Option<String>,
}

pub fn codex_auth_path() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("CODEX_HOME") {
        return Ok(PathBuf::from(dir).join("auth.json"));
    }
    Ok(home_dir()?.join(".codex").join("auth.json"))
}

fn codex() -> Result<Credential> {
    let path = codex_auth_path()?;
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("Codex is not logged in ({} missing)", path.display()))?;
    let auth: CodexAuth = serde_json::from_str(&raw).context("Codex auth.json is not JSON")?;
    let tokens = auth
        .tokens
        .ok_or_else(|| anyhow!("Codex is logged in with an API key, not a ChatGPT account"))?;
    let account_id = tokens
        .account_id
        .ok_or_else(|| anyhow!("Codex auth.json has no account id"))?;
    // The access token is a JWT; an expired one makes the provider answer 401 and the proof fail.
    // Codex refreshes it whenever it runs, so tell the user exactly that.
    if let Some(exp) = jwt_claim(&tokens.access_token, "exp").and_then(|v| v.parse::<i64>().ok())
        && exp < chrono::Utc::now().timestamp()
    {
        bail!("Codex login has expired; run any `codex` command once to refresh it");
    }
    Ok(Credential {
        secret: tokens.access_token,
        external_id_hint: Some(account_id),
        source: "Codex login (~/.codex/auth.json)".into(),
    })
}

// ---- Cursor --------------------------------------------------------------------------------

pub fn cursor_state_db() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("TMX_CURSOR_STATE_DB") {
        return Ok(PathBuf::from(p));
    }
    let home = home_dir()?;
    #[cfg(target_os = "macos")]
    let base = home.join("Library/Application Support/Cursor");
    #[cfg(target_os = "windows")]
    let base = std::env::var("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| home.join("AppData/Roaming"))
        .join("Cursor");
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let base = home.join(".config/Cursor");
    Ok(base.join("User/globalStorage/state.vscdb"))
}

fn cursor() -> Result<Credential> {
    let db_path = cursor_state_db()?;
    if !db_path.exists() {
        bail!(
            "Cursor is not installed or not logged in ({} missing)",
            db_path.display()
        );
    }
    // Cursor keeps the database open; copy it so we never take a lock on the live file.
    let tmp = std::env::temp_dir().join(format!("tmx-cursor-{}.vscdb", std::process::id()));
    std::fs::copy(&db_path, &tmp).context("cannot copy Cursor state database")?;
    let result = read_cursor_token(&tmp);
    let _ = std::fs::remove_file(&tmp);
    let access = result?;

    let sub =
        jwt_claim(&access, "sub").ok_or_else(|| anyhow!("Cursor access token has no subject"))?;
    if let Some(exp) = jwt_claim(&access, "exp").and_then(|v| v.parse::<i64>().ok())
        && exp < chrono::Utc::now().timestamp()
    {
        bail!("Cursor login has expired; open Cursor once to refresh it");
    }
    let secret = format!("{}%3A%3A{}", urlencoding::encode(&sub), access);
    Ok(Credential {
        secret,
        external_id_hint: None,
        source: "Cursor login (local state database)".into(),
    })
}

fn read_cursor_token(path: &std::path::Path) -> Result<String> {
    let conn =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .context("cannot open Cursor state database")?;
    let value: Option<String> = conn
        .query_row(
            "SELECT value FROM ItemTable WHERE key = 'cursorAuth/accessToken'",
            [],
            |row| row.get(0),
        )
        .ok();
    value
        .filter(|v| !v.is_empty())
        .ok_or_else(|| anyhow!("Cursor is not logged in"))
}

/// Reads a string or number claim from an unverified JWT payload (we only need routing data).
fn jwt_claim(token: &str, claim: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?;
    let json: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    match json.get(claim)? {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_jwt_claims_without_verifying() {
        let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"auth0|user_1","exp":1793432690}"#);
        let token = format!("eyJhbGciOiJIUzI1NiJ9.{payload}.sig");
        assert_eq!(jwt_claim(&token, "sub").as_deref(), Some("auth0|user_1"));
        assert_eq!(jwt_claim(&token, "exp").as_deref(), Some("1793432690"));
        assert_eq!(jwt_claim(&token, "nope"), None);
    }

    #[test]
    fn provider_keys_roundtrip_with_private_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path().to_path_buf()).unwrap();
        let mut keys = ProviderKeys::default();
        keys.set(Provider::Zai, Some(" k1 ".into())).unwrap();
        assert!(keys.set(Provider::Claude, Some("x".into())).is_err());
        keys.save(&paths).unwrap();
        let loaded = ProviderKeys::load(&paths).unwrap();
        assert_eq!(loaded.zai.as_deref(), Some("k1"));
        assert!(!loaded.has(Provider::Openrouter));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(paths.providers_file())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
