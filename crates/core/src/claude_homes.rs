//! Claude Code config homes: the default one (`~/.claude`) and the extra homes some users keep
//! per account (`CLAUDE_CONFIG_DIR=~/.claude-work claude`).
//!
//! Claude Code log lines carry no account identity, so a home's logs are attributed only to the
//! login stored for that same home. A home without its own stored login (sessions run with
//! `CLAUDE_CODE_OAUTH_TOKEN`, an API key or a gateway) is never synced: its logs belong to nobody.
//!
//! The default account is always `~/.claude` with the unsuffixed Keychain service, whatever this
//! process's environment says: its cursors and queued records are not keyed by home, so letting
//! `$CLAUDE_CONFIG_DIR` redirect it would prove one login and submit another's records. A
//! `$CLAUDE_CONFIG_DIR` naming another directory is just one more extra home, and opt-in.

use std::{
    collections::BTreeSet,
    ffi::OsStr,
    path::{Path, PathBuf},
};

use anyhow::Result;
use serde::Serialize;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::paths::home_dir;

/// Keychain service of the default login (no `CLAUDE_CONFIG_DIR`).
pub const KEYCHAIN_SERVICE: &str = "Claude Code-credentials";
/// Extra homes named explicitly, as a platform path list.
pub const HOMES_ENV: &str = "TMX_CLAUDE_HOMES";
/// Overrides the default home's projects directory (tests, unusual layouts).
pub const PROJECTS_DIR_ENV: &str = "TMX_CLAUDE_PROJECTS_DIR";
/// Claude Code's own home override; to this client only a candidate extra home.
pub const CONFIG_DIR_ENV: &str = "CLAUDE_CONFIG_DIR";

/// The Keychain service Claude Code stores a login under, given its verbatim `CLAUDE_CONFIG_DIR`.
///
/// Claude Code 2.1.278 (`bO()`): no suffix when `CLAUDE_CONFIG_DIR` is unset or empty, otherwise
/// `-` plus the first 8 hex chars of sha256 over the NFC-normalised value, as given (no resolving).
pub fn keychain_service(config_dir: Option<&str>) -> String {
    match config_dir.filter(|d| !d.is_empty()) {
        None => KEYCHAIN_SERVICE.to_string(),
        Some(dir) => format!("{KEYCHAIN_SERVICE}-{}", short_hash(dir)),
    }
}

fn short_hash(text: &str) -> String {
    let normalized: String = text.nfc().collect();
    hex::encode(Sha256::digest(normalized.as_bytes()))[..8].to_string()
}

/// Where one home's Claude Code login lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginStore {
    /// macOS Keychain services to try, in order.
    pub keychain_services: Vec<String>,
    /// The plaintext store Claude Code uses where there is no Keychain.
    pub credentials_file: PathBuf,
    /// Global config holding `oauthAccount.accountUuid` (the account hint, not secret).
    pub account_file: PathBuf,
}

/// Where a stored login was found, without reading it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredLogin {
    Keychain(String),
    File(PathBuf),
}

impl StoredLogin {
    pub fn describe(&self) -> String {
        match self {
            StoredLogin::Keychain(service) => {
                format!("Claude Code login (macOS Keychain, {service})")
            }
            StoredLogin::File(path) => format!("Claude Code login ({})", path.display()),
        }
    }
}

/// What an extra home holds in the way of stored logins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HomeLogin {
    /// None: its logs belong to nobody.
    Missing,
    /// Exactly one: the account its logs are attributed to.
    Found(StoredLogin),
    /// Several (Keychain items under different spellings of the directory, or a Keychain item
    /// and a `.credentials.json`). Nothing says which one wrote the logs, so the home is unusable.
    Ambiguous(Vec<StoredLogin>),
}

/// [`HomeLogin`] without the locations, for status screens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum HomeLoginKind {
    Missing,
    Found,
    Ambiguous,
}

impl HomeLogin {
    pub fn kind(&self) -> HomeLoginKind {
        match self {
            HomeLogin::Missing => HomeLoginKind::Missing,
            HomeLogin::Found(_) => HomeLoginKind::Found,
            HomeLogin::Ambiguous(_) => HomeLoginKind::Ambiguous,
        }
    }

    pub fn found(&self) -> Option<&StoredLogin> {
        match self {
            HomeLogin::Found(login) => Some(login),
            _ => None,
        }
    }

    /// Why the home cannot be synced, or `None` when it can.
    pub fn problem(&self) -> Option<String> {
        match self {
            HomeLogin::Found(_) => None,
            HomeLogin::Missing => {
                Some("no stored login in this home; its logs are not synced".to_string())
            }
            HomeLogin::Ambiguous(logins) => Some(format!(
                "{} stored logins in this home ({}); remove all but one to sync it",
                logins.len(),
                logins
                    .iter()
                    .map(|l| match l {
                        StoredLogin::Keychain(service) => format!("Keychain {service}"),
                        StoredLogin::File(path) => path.display().to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        }
    }
}

impl LoginStore {
    /// Every stored login, in lookup order. `keychain_has` checks metadata only, so nothing
    /// secret is read.
    pub fn probe(&self, keychain_has: &dyn Fn(&str) -> bool) -> Vec<StoredLogin> {
        let mut seen = BTreeSet::new();
        let mut found: Vec<StoredLogin> = self
            .keychain_services
            .iter()
            .filter(|s| seen.insert(s.as_str()) && keychain_has(s))
            .map(|s| StoredLogin::Keychain(s.clone()))
            .collect();
        if self.credentials_file.is_file() {
            found.push(StoredLogin::File(self.credentials_file.clone()));
        }
        found
    }

    /// The one stored login of an extra home; several make it [`HomeLogin::Ambiguous`].
    pub fn locate(&self, keychain_has: &dyn Fn(&str) -> bool) -> HomeLogin {
        let mut found = self.probe(keychain_has);
        match found.len() {
            0 => HomeLogin::Missing,
            1 => HomeLogin::Found(found.remove(0)),
            _ => HomeLogin::Ambiguous(found),
        }
    }
}

/// Whether the login Keychain has an item for `service`. Reads attributes only (no `-w`), which
/// never prompts and never touches the secret.
pub fn keychain_has(service: &str) -> bool {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("security")
            .args(["find-generic-password", "-s", service])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = service;
        false
    }
}

/// The default home: always `~/.claude`. `$CLAUDE_CONFIG_DIR` never moves it (see the module docs).
pub fn default_dir() -> Result<PathBuf> {
    Ok(default_dir_for(&home_dir()?))
}

fn default_dir_for(home: &Path) -> PathBuf {
    home.join(".claude")
}

/// Session logs of the default home.
pub fn default_projects_dir() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var(PROJECTS_DIR_ENV) {
        return Ok(PathBuf::from(dir));
    }
    Ok(default_dir()?.join("projects"))
}

/// Login of the default home: the unsuffixed Keychain service, then `~/.claude/.credentials.json`,
/// with the account hint in `~/.claude.json`. Exactly where the client looked before extra homes.
pub fn default_login() -> Result<LoginStore> {
    Ok(default_login_for(&home_dir()?))
}

fn default_login_for(home: &Path) -> LoginStore {
    LoginStore {
        keychain_services: vec![keychain_service(None)],
        credentials_file: default_dir_for(home).join(".credentials.json"),
        account_file: home.join(".claude.json"),
    }
}

/// How an extra home was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum HomeOrigin {
    /// `~/.claude-*` or `~/.config/claude*` with a `projects/` directory.
    Discovered,
    /// Listed in `$TMX_CLAUDE_HOMES`.
    Env,
    /// This process's `$CLAUDE_CONFIG_DIR`, when it names a directory other than `~/.claude`.
    ConfigDirEnv,
    /// Added with `tmx claude-homes add`.
    Setting,
}

/// An extra Claude Code config home: a separate Claude account in this client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaudeHome {
    /// Stable state key: 8 hex chars of sha256 over the canonical directory.
    pub id: String,
    /// Short handle for `tmx enable claude:<name>`.
    pub name: String,
    pub dir: PathBuf,
    pub origin: HomeOrigin,
}

impl ClaudeHome {
    pub fn projects_dir(&self) -> PathBuf {
        self.dir.join("projects")
    }

    /// Account key used by the CLI JSON, the desktop app and `state.json`.
    pub fn key(&self) -> String {
        format!("CLAUDE:{}", self.id)
    }

    /// Where Claude Code run with `CLAUDE_CONFIG_DIR=<dir>` stores its login.
    pub fn login_store(&self) -> LoginStore {
        // Claude Code hashes the variable verbatim; people write it with or without a trailing
        // slash, or through a symlink. Every variant names this directory, so any hit is its login.
        let raw = self.dir.to_string_lossy().into_owned();
        let trimmed = raw.trim_end_matches('/').to_string();
        let mut variants = vec![raw.clone(), trimmed.clone(), format!("{trimmed}/")];
        if let Ok(canonical) = self.dir.canonicalize() {
            variants.push(canonical.to_string_lossy().into_owned());
        }
        let mut seen = BTreeSet::new();
        LoginStore {
            keychain_services: variants
                .into_iter()
                .filter(|v| !v.is_empty() && seen.insert(v.clone()))
                .map(|v| keychain_service(Some(&v)))
                .collect(),
            credentials_file: self.dir.join(".credentials.json"),
            account_file: self.dir.join(".claude.json"),
        }
    }
}

/// Everything discovery looks at, so tests can run it against a temporary directory.
pub struct DiscoveryInput<'a> {
    pub home: &'a Path,
    /// The default home's projects directory; extra homes may not overlap it.
    pub default_projects: &'a Path,
    /// `$TMX_CLAUDE_HOMES`.
    pub env: Option<&'a OsStr>,
    /// `$CLAUDE_CONFIG_DIR`: a candidate like any other, never the default home.
    pub config_dir: Option<&'a OsStr>,
    /// Directories added with `tmx claude-homes add`.
    pub configured: &'a [String],
}

/// Extra homes on this machine, with or without a stored login.
pub fn discover(configured: &[String]) -> Result<Vec<ClaudeHome>> {
    let home = home_dir()?;
    let default_projects = default_projects_dir()?;
    let env = std::env::var_os(HOMES_ENV);
    let config_dir = std::env::var_os(CONFIG_DIR_ENV);
    Ok(discover_in(&DiscoveryInput {
        home: &home,
        default_projects: &default_projects,
        env: env.as_deref(),
        config_dir: config_dir.as_deref(),
        configured,
    }))
}

pub fn discover_in(input: &DiscoveryInput<'_>) -> Vec<ClaudeHome> {
    let mut candidates: Vec<(PathBuf, HomeOrigin)> = Vec::new();
    for (parent, prefix) in [
        (input.home.to_path_buf(), ".claude-"),
        (input.home.join(".config"), "claude"),
    ] {
        let Ok(entries) = std::fs::read_dir(&parent) else {
            continue;
        };
        let mut found: Vec<PathBuf> = entries
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(prefix))
            .map(|e| e.path())
            .filter(|p| p.join("projects").is_dir())
            .collect();
        found.sort();
        candidates.extend(found.into_iter().map(|p| (p, HomeOrigin::Discovered)));
    }
    if let Some(env) = input.env {
        candidates.extend(
            std::env::split_paths(env)
                .filter_map(|p| expand(&p, input.home))
                .map(|p| (p, HomeOrigin::Env)),
        );
    }
    if let Some(dir) = input.config_dir.filter(|d| !d.is_empty()) {
        // Kept verbatim (not resolved): Claude Code hashes this exact spelling for the Keychain.
        candidates
            .extend(expand(Path::new(dir), input.home).map(|p| (p, HomeOrigin::ConfigDirEnv)));
    }
    candidates.extend(
        input
            .configured
            .iter()
            .filter_map(|p| expand(Path::new(p), input.home))
            .map(|p| (p, HomeOrigin::Setting)),
    );

    // A home whose logs overlap another's would let one login claim the other's sessions.
    let mut taken = vec![canonical(input.default_projects)];
    let mut homes: Vec<ClaudeHome> = Vec::new();
    for (dir, origin) in candidates {
        let projects = canonical(&dir.join("projects"));
        if taken
            .iter()
            .any(|t| projects.starts_with(t) || t.starts_with(&projects))
        {
            continue;
        }
        taken.push(projects);
        let id = short_hash(&canonical(&dir).to_string_lossy());
        homes.push(ClaudeHome {
            name: base_name(&dir),
            id,
            dir,
            origin,
        });
    }
    // Names are handles only (state is keyed by id); disambiguate collisions with the id.
    let names: Vec<String> = homes.iter().map(|h| h.name.clone()).collect();
    for home in &mut homes {
        if names.iter().filter(|n| **n == home.name).count() > 1 {
            home.name = format!("{}-{}", home.name, &home.id[..4]);
        }
    }
    homes
}

/// `~/x` and absolute paths; relative entries are ambiguous (whose working directory?) and skipped.
fn expand(path: &Path, home: &Path) -> Option<PathBuf> {
    if let Ok(rest) = path.strip_prefix("~") {
        return Some(home.join(rest));
    }
    path.is_absolute().then(|| path.to_path_buf())
}

/// Resolves symlinks through the deepest existing ancestor, so `~/.claude-x`, a link to it and a
/// not-yet-created `projects/` below either compare equal.
fn canonical(path: &Path) -> PathBuf {
    let mut rest = Vec::new();
    let mut base = path;
    loop {
        if let Ok(resolved) = base.canonicalize() {
            return rest.iter().rev().fold(resolved, |p, c| p.join(c));
        }
        match (base.parent(), base.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name.to_os_string());
                base = parent;
            }
            _ => return path.to_path_buf(),
        }
    }
}

/// `~/.claude-work` → `work`, `~/.config/claude` → `config-claude`, anything else its directory name.
fn base_name(dir: &Path) -> String {
    let file = dir
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let stripped = file.trim_start_matches('.');
    let stripped = stripped
        .strip_prefix("claude")
        .map(|s| s.trim_start_matches(['-', '_', '.']))
        .unwrap_or(stripped);
    let name: String = stripped
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let name = name.trim_matches('-').to_string();
    if !name.is_empty() {
        return name;
    }
    let parent = dir
        .parent()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().trim_start_matches('.').to_lowercase())
        .unwrap_or_default();
    if parent.is_empty() {
        "home".into()
    } else {
        format!("{parent}-claude")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keychain_service_matches_claude_code() {
        assert_eq!(keychain_service(None), "Claude Code-credentials");
        assert_eq!(keychain_service(Some("")), "Claude Code-credentials");
        // The scheme matches a Keychain item Claude Code created on a real Mac for such a directory.
        assert_eq!(
            keychain_service(Some("/Users/a/.claude-alt/config")),
            "Claude Code-credentials-4f73262e"
        );
        // Verbatim: a trailing slash is a different service.
        assert_ne!(
            keychain_service(Some("/Users/a/.claude-work")),
            keychain_service(Some("/Users/a/.claude-work/"))
        );
        // NFC normalisation: decomposed and composed spellings hash the same.
        assert_eq!(
            keychain_service(Some("/Users/jose\u{301}/.claude-x")),
            keychain_service(Some("/Users/jos\u{e9}/.claude-x"))
        );
    }

    #[test]
    fn the_default_home_is_where_it_always_was() {
        let home = Path::new("/Users/a");
        // Exactly the locations the client used before extra homes.
        assert_eq!(
            default_login_for(home),
            LoginStore {
                keychain_services: vec!["Claude Code-credentials".into()],
                credentials_file: "/Users/a/.claude/.credentials.json".into(),
                account_file: "/Users/a/.claude.json".into(),
            }
        );
        assert_eq!(default_dir_for(home), Path::new("/Users/a/.claude"));
    }

    #[test]
    fn claude_config_dir_in_the_environment_never_moves_the_default_account() {
        let tmp = tempfile::tempdir().unwrap();
        let other = tmp.path().join(".claude-other");
        std::fs::create_dir_all(other.join("projects")).unwrap();
        // SAFETY: only discovery reads this variable, and no other test calls `discover()`.
        unsafe { std::env::set_var(CONFIG_DIR_ENV, &other) };
        let login = default_login();
        let dir = default_dir();
        unsafe { std::env::remove_var(CONFIG_DIR_ENV) };

        let home = home_dir().unwrap();
        assert_eq!(login.unwrap(), default_login_for(&home));
        assert_eq!(dir.unwrap(), home.join(".claude"));
    }

    #[test]
    fn claude_config_dir_is_only_a_candidate_extra_home() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let default = mkhome(home, ".claude", true);
        let other = mkhome(home, "elsewhere/acct", false);
        let found = discover_in(&DiscoveryInput {
            home,
            default_projects: &default.join("projects"),
            env: None,
            config_dir: Some(other.as_os_str()),
            configured: &[],
        });
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].origin, HomeOrigin::ConfigDirEnv);
        assert_eq!(found[0].dir, other);
        // Its login is the one Claude Code stores for that exact value, never the default one.
        let store = found[0].login_store();
        assert!(
            store
                .keychain_services
                .contains(&keychain_service(Some(&other.to_string_lossy())))
        );
        assert!(
            !store
                .keychain_services
                .contains(&KEYCHAIN_SERVICE.to_string())
        );
        assert_ne!(store.credentials_file, default.join(".credentials.json"));

        // Pointing at the default home (any spelling) adds nothing.
        for same in [default.clone(), home.join(".claude/")] {
            let none = discover_in(&DiscoveryInput {
                home,
                default_projects: &default.join("projects"),
                env: None,
                config_dir: Some(same.as_os_str()),
                configured: &[],
            });
            assert!(none.is_empty(), "{none:?}");
        }
        // An empty or relative value is ignored.
        for ignored in ["", "relative/dir"] {
            let none = discover_in(&DiscoveryInput {
                home,
                default_projects: &default.join("projects"),
                env: None,
                config_dir: Some(OsStr::new(ignored)),
                configured: &[],
            });
            assert!(none.is_empty(), "{none:?}");
        }
    }

    fn mkhome(root: &Path, rel: &str, projects: bool) -> PathBuf {
        let dir = root.join(rel);
        std::fs::create_dir_all(&dir).unwrap();
        if projects {
            std::fs::create_dir_all(dir.join("projects")).unwrap();
        }
        dir
    }

    #[test]
    fn discovers_sibling_homes_env_and_settings_without_the_default() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let default = mkhome(home, ".claude", true);
        mkhome(home, ".claude-work", true);
        mkhome(home, ".claude-mem", false); // a tool's cache, not a config home
        mkhome(home, ".config/claude", true);
        mkhome(home, ".config/claude-empty", false);
        let explicit = mkhome(home, "elsewhere/acct", false);
        let listed = std::env::join_paths([explicit.clone(), home.join(".claude-work")]).unwrap();
        let configured = vec!["~/.claude".to_string(), "relative/dir".to_string()];

        let homes = discover_in(&DiscoveryInput {
            home,
            default_projects: &default.join("projects"),
            env: Some(&listed),
            config_dir: None,
            configured: &configured,
        });
        let summary: Vec<(&str, HomeOrigin)> =
            homes.iter().map(|h| (h.name.as_str(), h.origin)).collect();
        assert_eq!(
            summary,
            [
                ("work", HomeOrigin::Discovered),
                ("config-claude", HomeOrigin::Discovered),
                ("acct", HomeOrigin::Env),
            ]
        );
        assert!(homes.iter().all(|h| h.dir != default));
        // Ids are stable: the same directory hashes the same however it was found.
        let again = discover_in(&DiscoveryInput {
            home,
            default_projects: &default.join("projects"),
            env: None,
            config_dir: None,
            configured: &[],
        });
        assert_eq!(again[0].id, homes[0].id);
        assert_eq!(again[0].key(), format!("CLAUDE:{}", homes[0].id));
    }

    #[test]
    fn rejects_homes_whose_logs_overlap_another_home() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let default = mkhome(home, ".claude", true);
        mkhome(home, ".claude/projects/nested", true);
        let listed =
            std::env::join_paths([home.join(".claude/projects/nested"), default.clone()]).unwrap();
        let homes = discover_in(&DiscoveryInput {
            home,
            default_projects: &default.join("projects"),
            env: Some(&listed),
            config_dir: None,
            configured: &[],
        });
        // Neither the default home itself nor a home inside its logs can become an extra account.
        assert!(homes.is_empty(), "{homes:?}");
        // A default home that does not exist yet still blocks its own path.
        let missing = home.join("missing/.claude/projects");
        assert_eq!(
            canonical(&missing),
            canonical(home).join("missing/.claude/projects")
        );
    }

    #[test]
    fn colliding_names_are_disambiguated_by_id() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        mkhome(home, ".claude-work", true);
        mkhome(home, ".config/claude-work", true);
        let homes = discover_in(&DiscoveryInput {
            home,
            default_projects: &home.join(".claude/projects"),
            env: None,
            config_dir: None,
            configured: &[],
        });
        assert_eq!(homes.len(), 2);
        assert_ne!(homes[0].name, homes[1].name);
        assert!(homes.iter().all(|h| h.name.starts_with("work-")));
    }

    #[test]
    fn a_home_is_usable_only_with_its_own_stored_login() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = mkhome(tmp.path(), ".claude-work", true);
        let home = ClaudeHome {
            id: "x".into(),
            name: "work".into(),
            dir: dir.clone(),
            origin: HomeOrigin::Discovered,
        };
        let store = home.login_store();
        let no_keychain = |_: &str| false;
        // Logs but no login (e.g. sessions run with CLAUDE_CODE_OAUTH_TOKEN): not usable.
        assert_eq!(store.locate(&no_keychain), HomeLogin::Missing);
        assert!(store.locate(&no_keychain).problem().is_some());

        // A Keychain entry under whichever spelling of the directory Claude Code hashed.
        let slashed = keychain_service(Some(&format!("{}/", dir.display())));
        assert!(store.keychain_services.contains(&slashed));
        assert!(
            !store
                .keychain_services
                .contains(&KEYCHAIN_SERVICE.to_string())
        );
        let only_slashed = |s: &str| s == slashed;
        let found = store.locate(&only_slashed);
        assert_eq!(
            found,
            HomeLogin::Found(StoredLogin::Keychain(slashed.clone()))
        );
        assert_eq!(found.kind(), HomeLoginKind::Found);
        assert_eq!(found.problem(), None);
        assert_eq!(store.account_file, dir.join(".claude.json"));

        // Only the plaintext store: that is the login.
        std::fs::write(dir.join(".credentials.json"), "{}").unwrap();
        assert_eq!(
            store.locate(&no_keychain),
            HomeLogin::Found(StoredLogin::File(dir.join(".credentials.json")))
        );
    }

    #[test]
    fn a_home_with_several_stored_logins_is_ambiguous() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = mkhome(tmp.path(), ".claude-work", true);
        let home = ClaudeHome {
            id: "x".into(),
            name: "work".into(),
            dir: dir.clone(),
            origin: HomeOrigin::Discovered,
        };
        let store = home.login_store();
        let plain = keychain_service(Some(&dir.to_string_lossy()));
        let slashed = keychain_service(Some(&format!("{}/", dir.display())));
        assert_ne!(plain, slashed);

        // Two Keychain spellings of the same directory: two logins, maybe two accounts.
        let both = |s: &str| s == plain || s == slashed;
        let login = store.locate(&both);
        assert_eq!(
            login,
            HomeLogin::Ambiguous(vec![
                StoredLogin::Keychain(plain.clone()),
                StoredLogin::Keychain(slashed.clone()),
            ])
        );
        assert_eq!(login.kind(), HomeLoginKind::Ambiguous);
        assert_eq!(login.found(), None);
        let problem = login.problem().unwrap();
        assert!(problem.contains("2 stored logins"), "{problem}");

        // A Keychain item plus a plaintext `.credentials.json` is ambiguous too.
        std::fs::write(dir.join(".credentials.json"), "{}").unwrap();
        let one_keychain = |s: &str| s == plain;
        assert_eq!(
            store.locate(&one_keychain),
            HomeLogin::Ambiguous(vec![
                StoredLogin::Keychain(plain.clone()),
                StoredLogin::File(dir.join(".credentials.json")),
            ])
        );
        // Every variant is probed, not just up to the first hit.
        let probed = std::cell::RefCell::new(Vec::new());
        let record = |s: &str| {
            probed.borrow_mut().push(s.to_string());
            s == plain
        };
        store.probe(&record);
        assert_eq!(*probed.borrow(), store.keychain_services);
    }

    #[test]
    fn names_come_from_the_directory() {
        assert_eq!(base_name(Path::new("/h/.claude-Work")), "work");
        assert_eq!(base_name(Path::new("/h/.config/claude")), "config-claude");
        assert_eq!(base_name(Path::new("/h/.config/claude_team")), "team");
        assert_eq!(base_name(Path::new("/h/x/config")), "config");
        assert_eq!(base_name(Path::new("/h/acct two")), "acct-two");
    }
}
