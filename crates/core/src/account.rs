//! What the client syncs: each provider's login, plus one Claude account per extra Claude Code
//! config home that has its own stored login.

use anyhow::Result;
use tracing::warn;

use crate::{
    claude_homes::{self, ClaudeHome, HomeLogin},
    credentials::{self, Credential, CredentialStatus},
    paths::Paths,
    provider::Provider,
    state::{ProviderState, State},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Account {
    /// A provider's usual login; for Claude, the default config home.
    Provider(Provider),
    /// An extra Claude Code config home: its own login, logs, cursors and sync.
    ClaudeHome(ClaudeHome),
}

impl From<Provider> for Account {
    fn from(provider: Provider) -> Self {
        Account::Provider(provider)
    }
}

impl std::fmt::Display for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.name())
    }
}

impl Account {
    pub fn provider(&self) -> Provider {
        match self {
            Account::Provider(p) => *p,
            Account::ClaudeHome(_) => Provider::Claude,
        }
    }

    /// Stable machine key: `CLAUDE`, `CODEX`, …, or `CLAUDE:<home id>`.
    pub fn key(&self) -> String {
        match self {
            Account::Provider(p) => p.id().to_string(),
            Account::ClaudeHome(h) => h.key(),
        }
    }

    /// What people type: `claude`, `codex`, …, or `claude:<home name>`.
    pub fn handle(&self) -> String {
        match self {
            Account::Provider(p) => p.id().to_lowercase(),
            Account::ClaudeHome(h) => format!("claude:{}", h.name),
        }
    }

    pub fn name(&self) -> String {
        match self {
            Account::Provider(p) => p.name().to_string(),
            Account::ClaudeHome(h) => format!("{} ({})", Provider::Claude.name(), h.name),
        }
    }

    pub fn home(&self) -> Option<&ClaudeHome> {
        match self {
            Account::Provider(_) => None,
            Account::ClaudeHome(h) => Some(h),
        }
    }

    /// Providers are on by default; extra homes are opt-in because linking is permanent.
    pub fn is_enabled(&self, state: &State) -> bool {
        match self {
            Account::Provider(p) => state.is_enabled(*p),
            Account::ClaudeHome(h) => state
                .claude_homes
                .get(&h.id)
                .and_then(|s| s.account.enabled)
                .unwrap_or(false),
        }
    }

    pub fn state(&self, state: &State) -> ProviderState {
        match self {
            Account::Provider(p) => state.providers.get(p).cloned(),
            Account::ClaudeHome(h) => state.claude_homes.get(&h.id).map(|s| s.account.clone()),
        }
        .unwrap_or_default()
    }

    pub fn state_mut<'a>(&self, state: &'a mut State) -> &'a mut ProviderState {
        match self {
            Account::Provider(p) => state.provider(*p),
            Account::ClaudeHome(h) => {
                let entry = state.claude_homes.entry(h.id.clone()).or_default();
                entry.dir = h.dir.display().to_string();
                &mut entry.account
            }
        }
    }

    /// The stored logins of an extra home, located without reading them. `None` for providers.
    pub fn home_login(&self) -> Option<HomeLogin> {
        self.home()
            .map(|h| h.login_store().locate(&claude_homes::keychain_has))
    }

    pub fn load_credential(&self, paths: &Paths) -> Result<Credential> {
        match self {
            Account::Provider(p) => credentials::load(paths, *p),
            Account::ClaudeHome(h) => credentials::claude_home(h),
        }
    }

    /// Credential status. A disabled extra home is only located, never read: reading a Keychain
    /// item can prompt, and nothing should touch a login the user has not opted in.
    pub fn credential_status(&self, paths: &Paths, state: &State) -> CredentialStatus {
        self.credential_status_with(paths, state, self.home_login())
    }

    /// [`Self::credential_status`] given an already located [`Self::home_login`].
    pub fn credential_status_with(
        &self,
        paths: &Paths,
        state: &State,
        home_login: Option<HomeLogin>,
    ) -> CredentialStatus {
        let provider = self.provider();
        let unusable = |login: &HomeLogin| CredentialStatus {
            provider,
            available: false,
            source: String::new(),
            detail: login.problem(),
        };
        match self {
            Account::Provider(p) => credentials::status(paths, *p),
            Account::ClaudeHome(_) => match home_login {
                Some(HomeLogin::Found(login)) if !self.is_enabled(state) => CredentialStatus {
                    provider,
                    available: true,
                    source: login.describe(),
                    detail: None,
                },
                Some(HomeLogin::Found(_)) => {
                    credentials::status_from(provider, self.load_credential(paths))
                }
                Some(login) => unusable(&login),
                None => unusable(&HomeLogin::Missing),
            },
        }
    }
}

/// Every account this machine can show: all providers, then every extra Claude home found (usable
/// or not, so status screens can say why one is skipped).
pub fn all(state: &State) -> Vec<Account> {
    let homes = claude_homes::discover(&state.claude_home_dirs).unwrap_or_else(|e| {
        warn!("cannot look for extra Claude homes: {e:#}");
        Vec::new()
    });
    with_homes(homes)
}

pub fn with_homes(homes: Vec<ClaudeHome>) -> Vec<Account> {
    Provider::ALL
        .into_iter()
        .map(Account::Provider)
        .chain(homes.into_iter().map(Account::ClaudeHome))
        .collect()
}

/// Resolves `claude`, `CODEX`, `claude:<name>`, `claude:<id>` or `CLAUDE:<id>` (the key).
pub fn find(accounts: &[Account], handle: &str) -> Option<Account> {
    let handle = handle.trim();
    match handle.split_once(':') {
        None => Provider::from_id(handle).map(Account::Provider),
        Some((provider, home)) if provider.eq_ignore_ascii_case("claude") => accounts
            .iter()
            .find(|a| {
                a.home()
                    .is_some_and(|h| h.name.eq_ignore_ascii_case(home) || h.id == home)
            })
            .cloned(),
        Some(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claude_homes::HomeOrigin;

    fn home(name: &str) -> ClaudeHome {
        ClaudeHome {
            id: format!("id{name}"),
            name: name.into(),
            dir: format!("/h/.claude-{name}").into(),
            origin: HomeOrigin::Discovered,
        }
    }

    #[test]
    fn extra_homes_are_opt_in_and_keep_separate_state() {
        let work = Account::ClaudeHome(home("work"));
        let default = Account::Provider(Provider::Claude);
        let mut state = State::default();
        assert!(default.is_enabled(&state));
        assert!(!work.is_enabled(&state));

        work.state_mut(&mut state).enabled = Some(true);
        work.state_mut(&mut state).syncs = 2;
        assert!(work.is_enabled(&state));
        assert_eq!(state.claude_homes["idwork"].dir, "/h/.claude-work");
        // The default Claude account is untouched by the extra home.
        assert_eq!(default.state(&state).syncs, 0);
        assert!(!state.providers.contains_key(&Provider::Claude));

        assert_eq!(work.key(), "CLAUDE:idwork");
        assert_eq!(work.handle(), "claude:work");
        assert_eq!(work.name(), "Claude Code (work)");
        assert_eq!(work.provider(), Provider::Claude);
    }

    #[test]
    fn finds_accounts_by_handle_name_or_key() {
        let accounts = with_homes(vec![home("work")]);
        assert_eq!(
            find(&accounts, "claude"),
            Some(Account::Provider(Provider::Claude))
        );
        assert_eq!(
            find(&accounts, "claude:WORK"),
            Some(Account::ClaudeHome(home("work")))
        );
        assert_eq!(
            find(&accounts, "CLAUDE:idwork"),
            Some(Account::ClaudeHome(home("work")))
        );
        assert_eq!(find(&accounts, "claude:other"), None);
        assert_eq!(find(&accounts, "codex:work"), None);
        assert_eq!(find(&accounts, "kimi"), None);
    }

    #[test]
    fn a_disabled_home_is_located_but_never_read() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::at(tmp.path().join("data")).unwrap();
        let dir = tmp.path().join(".claude-work");
        std::fs::create_dir_all(dir.join("projects")).unwrap();
        let mut h = home("work");
        h.dir = dir.clone();
        let account = Account::ClaudeHome(h);
        let state = State::default();

        let missing = account.credential_status(&paths, &state);
        assert!(!missing.available);

        // Not valid credentials: a read would fail, so `available` proves it was not read.
        std::fs::write(dir.join(".credentials.json"), "not json").unwrap();
        let located = account.credential_status(&paths, &state);
        assert!(located.available, "{located:?}");

        let mut enabled = State::default();
        account.state_mut(&mut enabled).enabled = Some(true);
        let read = account.credential_status(&paths, &enabled);
        assert!(!read.available);
    }

    #[test]
    fn an_ambiguous_home_is_unusable_and_never_read() {
        use crate::claude_homes::StoredLogin;
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::at(tmp.path().join("data")).unwrap();
        let dir = tmp.path().join(".claude-work");
        std::fs::create_dir_all(dir.join("projects")).unwrap();
        // A readable, unexpired login: reading it would succeed.
        std::fs::write(
            dir.join(".credentials.json"),
            r#"{"claudeAiOauth":{"accessToken":"t"}}"#,
        )
        .unwrap();
        let mut h = home("work");
        h.dir = dir.clone();
        let account = Account::ClaudeHome(h);
        let mut state = State::default();
        account.state_mut(&mut state).enabled = Some(true);

        let ambiguous = HomeLogin::Ambiguous(vec![
            StoredLogin::Keychain("Claude Code-credentials-00000000".into()),
            StoredLogin::File(dir.join(".credentials.json")),
        ]);
        let status = account.credential_status_with(&paths, &state, Some(ambiguous));
        assert!(!status.available, "{status:?}");
        assert!(
            status
                .detail
                .as_deref()
                .is_some_and(|d| d.contains("2 stored logins")),
            "{status:?}"
        );
        // The same home with that one login is usable.
        let found = HomeLogin::Found(StoredLogin::File(dir.join(".credentials.json")));
        assert!(
            account
                .credential_status_with(&paths, &state, Some(found))
                .available
        );
    }
}
