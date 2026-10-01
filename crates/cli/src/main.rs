//! `tmx` — the headless Tokenmaxxing client.
//!
//! Same core as the desktop app (`tmx-core`): it reads provider credentials where the official
//! tools keep them, proves usage over MPC-TLS with our notary, and submits device-signed reports.
//! Useful on servers, in CI, and for live end-to-end testing.

use std::{io::Read, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use serde::Serialize;
use tmx_core::{
    Account, Provider, VERSION, account,
    api::{ApiClient, PairRequest},
    burn::{self, BurnPlan},
    claude_homes::{HomeLogin, HomeLoginKind},
    credentials::{self, ProviderKeys},
    identity::{DeviceIdentity, DeviceKey},
    paths::Paths,
    state::State,
    sync::{self, BackingOff, SyncEngine},
};

const DEFAULT_SERVER: &str = "http://localhost:8787";

#[derive(Parser, Debug)]
#[command(name = "tmx", version, about = "Tokenmaxxing client (headless)")]
struct Cli {
    /// API base URL. Precedence: this flag, $TMX_SERVER, the paired server, http://localhost:8787.
    #[arg(long, global = true, env = "TMX_SERVER")]
    server: Option<String>,
    /// Print machine-readable JSON instead of text.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Pair this device with your profile using a code from the web dashboard.
    Pair {
        /// Pairing code, e.g. TMX-7KQ4-XN2R
        code: String,
        /// Device name shown on the dashboard (defaults to the hostname).
        #[arg(long)]
        name: Option<String>,
    },
    /// Forget the device identity stored on this machine.
    Unpair,
    /// Show pairing, credentials and last sync results.
    Status,
    /// List the providers the server supports.
    Providers,
    /// Manage API keys for providers without a desktop login (Z.ai, OpenRouter).
    Keys {
        #[command(subcommand)]
        action: KeysAction,
    },
    /// Enable a provider (on by default) or an extra Claude home, e.g. `claude:work` (opt-in).
    Enable { provider: String },
    /// Disable a provider or an extra Claude home.
    Disable { provider: String },
    /// Extra Claude Code config homes (one per account, via CLAUDE_CONFIG_DIR).
    ClaudeHomes {
        #[command(subcommand)]
        action: ClaudeHomesAction,
    },
    /// Run one sync round. Defaults to every enabled provider with a credential on this machine.
    Sync { providers: Vec<String> },
    /// Run the reference burns the server scheduled for this machine (Claude and Codex only).
    Burn { providers: Vec<String> },
    /// Keep syncing on an interval until interrupted.
    Daemon {
        /// Seconds between rounds (minimum 60).
        #[arg(long, default_value_t = 600)]
        interval: u64,
        /// Opt in to scheduled reference burns (spends subscription usage). Off by default.
        #[arg(long)]
        run_reference_burns: bool,
    },
}

#[derive(Subcommand, Debug)]
enum KeysAction {
    /// Store a key, from --key or from stdin.
    Set {
        provider: String,
        #[arg(long, conflicts_with = "stdin")]
        key: Option<String>,
        /// Read the key from stdin (keeps it out of your shell history).
        #[arg(long)]
        stdin: bool,
    },
    /// Remove a stored key.
    Clear { provider: String },
    /// Show which keys are stored (never their values).
    List,
}

#[derive(Subcommand, Debug)]
enum ClaudeHomesAction {
    /// Show extra Claude homes found on this machine.
    List,
    /// Remember a Claude config directory that discovery does not find on its own.
    Add { dir: String },
    /// Forget a directory added with `add`.
    Remove { dir: String },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProviderStatus {
    /// `CLAUDE`, …, or `CLAUDE:<home id>` for an extra Claude home.
    id: String,
    /// What `tmx enable` / `tmx sync` accept: `claude`, …, `claude:<home name>`.
    handle: String,
    name: String,
    enabled: bool,
    credential: credentials::CredentialStatus,
    state: tmx_core::state::ProviderState,
    #[serde(skip_serializing_if = "Option::is_none")]
    home: Option<HomeReport>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HomeReport {
    id: String,
    name: String,
    dir: String,
    origin: tmx_core::claude_homes::HomeOrigin,
    /// Has exactly one stored login of its own; other homes are never synced.
    usable: bool,
    /// `found`, `missing`, or `ambiguous` (several stored logins: unusable).
    login: HomeLoginKind,
}

impl HomeReport {
    fn of(account: &Account) -> Option<Self> {
        let login = account.home_login()?.kind();
        account.home().map(|h| HomeReport {
            id: h.id.clone(),
            name: h.name.clone(),
            dir: h.dir.display().to_string(),
            origin: h.origin,
            usable: login == HomeLoginKind::Found,
            login,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusReport {
    version: &'static str,
    data_dir: String,
    server: String,
    device: Option<DeviceReport>,
    /// Verified tokens: what the board ranks.
    total_tokens: Option<u64>,
    reported_tokens: Option<u64>,
    unverified_tokens: Option<u64>,
    providers: Vec<ProviderStatus>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeviceReport {
    device_id: String,
    username: String,
    paired_at: chrono::DateTime<chrono::Utc>,
}

/// JSON reports keep snake_case fields (`credited_tokens`); only the `outcome` tag is camelCase.
#[derive(Serialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "snake_case",
    tag = "outcome"
)]
enum SyncReport {
    Synced {
        provider: &'static str,
        account: String,
        /// Verified tokens (the ranked share of the claim); the name predates calibration.
        credited_tokens: u64,
        unverified_tokens: u64,
        reported_tokens: u64,
        credited_records: u64,
        rejected_records: u64,
        label: Option<String>,
        catch_up_rounds: u32,
        warnings: Vec<String>,
    },
    Skipped {
        provider: &'static str,
        account: String,
        reason: String,
    },
    Failed {
        provider: &'static str,
        account: String,
        error: String,
    },
}

/// One scheduled burn, or the reason a provider produced none.
#[derive(Serialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "snake_case",
    tag = "outcome"
)]
enum BurnRunReport {
    Burned {
        provider: &'static str,
        burn_id: String,
        model: String,
        profile: &'static str,
        invocations: u32,
        input_tokens: u64,
        output_tokens: u64,
        /// The server acknowledged the completion; false means it will learn of it from the proof alone.
        complete_reported: bool,
    },
    Failed {
        provider: &'static str,
        burn_id: String,
        error: String,
    },
    /// The burn list itself could not be fetched.
    Unavailable {
        provider: &'static str,
        error: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn,tmx_core=info,tmx_attest=info".into()),
        )
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();

    let cli = Cli::parse();
    let paths = Paths::discover()?;
    let identity = DeviceIdentity::load(&paths)?;
    let server = cli
        .server
        .clone()
        .or_else(|| identity.as_ref().map(|i| i.server_url.clone()))
        .unwrap_or_else(|| DEFAULT_SERVER.to_string())
        .trim_end_matches('/')
        .to_string();

    match cli.command {
        Command::Pair { code, name } => {
            if identity.is_some() {
                bail!("this device is already paired; run `tmx unpair` first");
            }
            let key = DeviceKey::generate();
            let api = ApiClient::new(&server, None)?;
            let response = api
                .pair(&PairRequest {
                    code: code.trim().to_uppercase(),
                    public_key: key.public_key_base64(),
                    name: name.unwrap_or_else(tmx_core::device_name),
                    platform: tmx_core::platform().to_string(),
                    app_version: VERSION.to_string(),
                })
                .await
                .map_err(|e| anyhow!("pairing failed: {}", sync::describe(&e)))?;
            let identity = DeviceIdentity::new(
                &key,
                response.device.id.clone(),
                server.clone(),
                response.user.id.clone(),
                response.user.username.clone(),
                response.user.display_name.clone(),
            );
            identity.save(&paths)?;
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &serde_json::json!({ "device": response.device.id, "username": response.user.username, "server": server })
                    )?
                );
            } else {
                println!(
                    "Paired as @{} (device {}) with {}",
                    response.user.username, response.device.id, server
                );
                println!(
                    "Credentials are read locally and never uploaded. Run `tmx sync` to submit your first proof."
                );
            }
        }
        Command::Unpair => {
            DeviceIdentity::forget(&paths)?;
            println!(
                "Device identity removed from {}",
                paths.device_file().display()
            );
        }
        Command::Status => {
            let state = State::load(&paths)?;
            let mut totals: Option<(u64, u64, u64)> = None;
            if let Some(id) = identity.clone()
                && let Ok(api) = ApiClient::new(&server, Some(id))
            {
                match api.device_me().await {
                    Ok(me) => {
                        totals = Some((me.total_tokens, me.reported_tokens, me.unverified_tokens))
                    }
                    Err(e) => eprintln!("warning: {}", sync::describe(&e)),
                }
            }
            let report = StatusReport {
                version: VERSION,
                data_dir: paths.root().display().to_string(),
                server: server.clone(),
                device: identity.as_ref().map(|i| DeviceReport {
                    device_id: i.device_id.clone(),
                    username: i.username.clone(),
                    paired_at: i.paired_at,
                }),
                total_tokens: totals.map(|t| t.0),
                reported_tokens: totals.map(|t| t.1),
                unverified_tokens: totals.map(|t| t.2),
                providers: account::all(&state)
                    .into_iter()
                    .map(|a| ProviderStatus {
                        id: a.key(),
                        handle: a.handle(),
                        name: a.name(),
                        enabled: a.is_enabled(&state),
                        credential: a.credential_status(&paths, &state),
                        state: a.state(&state),
                        home: HomeReport::of(&a),
                    })
                    .collect(),
            };
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_status(&report);
            }
        }
        Command::Providers => {
            let meta = ApiClient::new(&server, None)?
                .meta()
                .await
                .map_err(|e| anyhow!(sync::describe(&e)))?;
            let state = State::load(&paths)?;
            let homes = home_reports(&state);
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &serde_json::json!({ "notary": meta.notary, "web": meta.web, "providers": meta.providers.iter().map(|p| serde_json::json!({"id": p.id, "name": p.name, "tier": p.tier, "server": p.server_name, "credential": p.credential})).collect::<Vec<_>>(), "claudeHomes": homes })
                    )?
                );
            } else {
                println!(
                    "Server {server}  notary {}  web {}",
                    meta.notary,
                    meta.web.as_deref().unwrap_or("-")
                );
                for p in meta.providers {
                    println!(
                        "  {:<11} {:<8} {:<20} {}",
                        p.id.to_lowercase(),
                        p.tier,
                        p.server_name,
                        p.credential
                    );
                }
                print_homes(&homes);
            }
        }
        Command::Keys { action } => match action {
            KeysAction::Set {
                provider,
                key,
                stdin,
            } => {
                let provider = parse_provider(&provider)?;
                let value = match (key, stdin) {
                    (Some(k), _) => k,
                    (None, true) => {
                        let mut buf = String::new();
                        std::io::stdin()
                            .read_to_string(&mut buf)
                            .context("cannot read stdin")?;
                        buf
                    }
                    (None, false) => bail!("provide --key <KEY> or --stdin"),
                };
                let mut keys = ProviderKeys::load(&paths)?;
                keys.set(provider, Some(value))?;
                keys.save(&paths)?;
                println!(
                    "Stored {} key in {} (owner-only permissions)",
                    provider,
                    paths.providers_file().display()
                );
            }
            KeysAction::Clear { provider } => {
                let provider = parse_provider(&provider)?;
                let mut keys = ProviderKeys::load(&paths)?;
                keys.set(provider, None)?;
                keys.save(&paths)?;
                println!("Removed {provider} key");
            }
            KeysAction::List => {
                let keys = ProviderKeys::load(&paths)?;
                for p in Provider::ALL.into_iter().filter(|p| p.takes_api_key()) {
                    println!(
                        "{:<11} {}",
                        p.id().to_lowercase(),
                        if keys.has(p) { "stored" } else { "-" }
                    );
                }
            }
        },
        Command::Enable { provider } => set_enabled(&paths, &provider, true)?,
        Command::Disable { provider } => set_enabled(&paths, &provider, false)?,
        Command::ClaudeHomes { action } => {
            let mut state = State::load(&paths)?;
            match action {
                ClaudeHomesAction::List => {}
                ClaudeHomesAction::Add { dir } => {
                    let dir = absolute_dir(&dir)?;
                    if !state.claude_home_dirs.contains(&dir) {
                        state.claude_home_dirs.push(dir.clone());
                        state.save(&paths)?;
                    }
                    if !cli.json {
                        println!("Added {dir}");
                    }
                }
                ClaudeHomesAction::Remove { dir } => {
                    let before = state.claude_home_dirs.len();
                    let absolute = absolute_dir(&dir).unwrap_or_else(|_| dir.clone());
                    state
                        .claude_home_dirs
                        .retain(|d| *d != dir && *d != absolute);
                    if state.claude_home_dirs.len() == before {
                        bail!("{dir} was not added with `tmx claude-homes add`");
                    }
                    state.save(&paths)?;
                    if !cli.json {
                        println!("Removed {dir}");
                    }
                }
            }
            let homes = home_reports(&state);
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&homes)?);
            } else {
                print_homes(&homes);
            }
        }
        Command::Sync { providers } => {
            let identity = identity
                .ok_or_else(|| anyhow!("this device is not paired; run `tmx pair <code>`"))?;
            let selected: Vec<Account> = if providers.is_empty() {
                sync::eligible_accounts(&paths)?
                    .into_iter()
                    .map(|(a, _)| a)
                    .collect()
            } else {
                let accounts = account::all(&State::load(&paths)?);
                providers
                    .iter()
                    .map(|p| parse_account(&accounts, p))
                    .collect::<Result<_>>()?
            };
            if selected.is_empty() {
                bail!(
                    "nothing to sync: no enabled provider has a credential on this machine (see `tmx status`)"
                );
            }
            let engine = SyncEngine::new(paths.clone(), ApiClient::new(&server, Some(identity))?);
            let reports = run_round(&engine, &selected, cli.json).await;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&reports)?);
            }
            if reports
                .iter()
                .any(|r| matches!(r, SyncReport::Failed { .. }))
            {
                std::process::exit(1);
            }
        }
        Command::Burn { providers } => {
            let identity = identity
                .ok_or_else(|| anyhow!("this device is not paired; run `tmx pair <code>`"))?;
            let selected = burn_providers(&paths, &providers)?;
            if selected.is_empty() {
                bail!(
                    "nothing to burn: neither Claude Code nor Codex is enabled with a credential on this machine (see `tmx status`)"
                );
            }
            let engine = SyncEngine::new(paths.clone(), ApiClient::new(&server, Some(identity))?);
            let reports = run_burns(&engine, &selected, cli.json).await;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&reports)?);
            } else if reports.is_empty() {
                println!("No burns scheduled for this machine.");
            }
            if reports
                .iter()
                .any(|r| !matches!(r, BurnRunReport::Burned { .. }))
            {
                std::process::exit(1);
            }
        }
        Command::Daemon {
            interval,
            run_reference_burns,
        } => {
            let identity = identity
                .ok_or_else(|| anyhow!("this device is not paired; run `tmx pair <code>`"))?;
            let interval = Duration::from_secs(interval.max(60));
            let engine = SyncEngine::new(paths.clone(), ApiClient::new(&server, Some(identity))?);
            loop {
                let selected: Vec<Account> = sync::eligible_accounts(&paths)?
                    .into_iter()
                    .map(|(a, _)| a)
                    .collect();
                if selected.is_empty() {
                    eprintln!("nothing to sync this round (no enabled provider has a credential)");
                } else {
                    let reports = run_round(&engine, &selected, cli.json).await;
                    if cli.json {
                        println!("{}", serde_json::to_string(&reports)?);
                    }
                    // Reference machines also run the burns the server scheduled; everyone else
                    // gets an empty list and notices nothing.
                    if run_reference_burns {
                        let burners = burners(selected);
                        let burns = run_burns(&engine, &burners, cli.json).await;
                        if cli.json && !burns.is_empty() {
                            println!("{}", serde_json::to_string(&burns)?);
                        }
                    }
                }
                eprintln!("next round in {}s", interval.as_secs());
                tokio::select! {
                    _ = tokio::time::sleep(interval) => {}
                    _ = tokio::signal::ctrl_c() => {
                        eprintln!("stopping");
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

fn parse_provider(id: &str) -> Result<Provider> {
    Provider::from_id(id).ok_or_else(|| {
        anyhow!("unknown provider {id}; expected one of claude, codex, cursor, zai, openrouter")
    })
}

/// A provider id, or `claude:<home name>` for an extra Claude home found on this machine.
fn parse_account(accounts: &[Account], handle: &str) -> Result<Account> {
    if let Some(found) = account::find(accounts, handle) {
        return Ok(found);
    }
    if handle.contains(':') {
        let known: Vec<String> = accounts
            .iter()
            .filter(|a| a.home().is_some())
            .map(Account::handle)
            .collect();
        bail!(
            "unknown Claude home {handle}; known: {} (see `tmx claude-homes list`)",
            if known.is_empty() {
                "none".to_string()
            } else {
                known.join(", ")
            }
        );
    }
    parse_provider(handle).map(Account::Provider)
}

fn set_enabled(paths: &Paths, handle: &str, enabled: bool) -> Result<()> {
    let mut state = State::load(paths)?;
    let account = parse_account(&account::all(&state), handle)?;
    match account.home_login() {
        Some(HomeLogin::Missing) if enabled => bail!(
            "{} has no stored login of its own, so its logs cannot be attributed to an account; log in with `CLAUDE_CONFIG_DIR={} claude` first",
            account.handle(),
            account
                .home()
                .map(|h| h.dir.display().to_string())
                .unwrap_or_default()
        ),
        Some(login @ HomeLogin::Ambiguous(_)) if enabled => bail!(
            "{} cannot be linked: {}",
            account.handle(),
            login.problem().unwrap_or_default()
        ),
        _ => {}
    }
    account.state_mut(&mut state).enabled = Some(enabled);
    state.save(paths)?;
    println!(
        "{} {}",
        account.name(),
        if enabled { "enabled" } else { "disabled" }
    );
    if enabled && account.home().is_some() {
        println!("The next sync links this Claude account to your profile; linking is permanent.");
    }
    Ok(())
}

fn absolute_dir(dir: &str) -> Result<String> {
    let path = match dir.strip_prefix("~/") {
        Some(rest) => tmx_core::paths::home_dir()?.join(rest),
        None => std::path::absolute(dir).with_context(|| format!("cannot resolve {dir}"))?,
    };
    if !path.is_dir() {
        bail!("{} is not a directory", path.display());
    }
    Ok(path.display().to_string())
}

fn home_reports(state: &State) -> Vec<HomeReport> {
    account::all(state)
        .iter()
        .filter_map(|a| {
            HomeReport::of(a).map(|mut r| {
                // Report the enable handle, which `tmx enable` accepts.
                r.name = a.handle();
                r
            })
        })
        .collect()
}

fn print_homes(homes: &[HomeReport]) {
    if homes.is_empty() {
        println!("No extra Claude homes (~/.claude-*, ~/.config/claude*, $TMX_CLAUDE_HOMES).");
        return;
    }
    println!("Extra Claude homes on this machine (opt-in: `tmx enable <handle>`):");
    for h in homes {
        println!(
            "  {:<20} {:<9} {}",
            h.name,
            match h.login {
                HomeLoginKind::Found => "login",
                HomeLoginKind::Missing => "no login",
                HomeLoginKind::Ambiguous => "ambiguous",
            },
            h.dir
        );
    }
}

/// Only the usual Claude and Codex logins run reference burns.
fn burners(accounts: Vec<Account>) -> Vec<Provider> {
    accounts
        .into_iter()
        .filter_map(|a| match a {
            Account::Provider(p) if p.has_local_logs() => Some(p),
            _ => None,
        })
        .collect()
}

async fn run_round(engine: &SyncEngine, accounts: &[Account], json: bool) -> Vec<SyncReport> {
    let mut reports = Vec::with_capacity(accounts.len());
    for account in accounts {
        let provider = account.provider();
        if !json {
            println!("{}: proving…", account.name());
        }
        let report = match engine.sync_account(account).await {
            Ok(outcome) => SyncReport::Synced {
                provider: provider.id(),
                account: account.key(),
                credited_tokens: outcome.summary.credited_tokens,
                unverified_tokens: outcome.summary.unverified_tokens,
                reported_tokens: outcome.summary.reported_tokens,
                credited_records: outcome.summary.credited_records,
                rejected_records: outcome.summary.rejected_records,
                label: outcome.summary.label.clone(),
                catch_up_rounds: outcome.summary.catch_up_rounds,
                warnings: outcome.warnings.clone(),
            },
            Err(e) => match e.downcast_ref::<BackingOff>() {
                Some(b) => SyncReport::Skipped {
                    provider: provider.id(),
                    account: account.key(),
                    reason: b.to_string(),
                },
                None => SyncReport::Failed {
                    provider: provider.id(),
                    account: account.key(),
                    error: sync::describe(&e),
                },
            },
        };
        if !json {
            match &report {
                SyncReport::Synced {
                    credited_tokens,
                    unverified_tokens,
                    credited_records,
                    rejected_records,
                    label,
                    catch_up_rounds,
                    warnings,
                    ..
                } => {
                    println!(
                        "{}: credited {} verified tokens (+{} unverified) across {} records, {} rejected{}{}",
                        account.name(),
                        group(*credited_tokens),
                        group(*unverified_tokens),
                        credited_records,
                        rejected_records,
                        label
                            .as_ref()
                            .map(|l| format!(" [{l}]"))
                            .unwrap_or_default(),
                        if *catch_up_rounds > 0 {
                            format!(" (+{catch_up_rounds} catch-up rounds)")
                        } else {
                            String::new()
                        }
                    );
                    for w in warnings {
                        println!("  warning: {w}");
                    }
                }
                SyncReport::Skipped { reason, .. } => {
                    println!("{}: skipped, {reason}", account.name())
                }
                SyncReport::Failed { error, .. } => {
                    println!("{}: FAILED, {error}", account.name())
                }
            }
        }
        reports.push(report);
    }
    reports
}

/// Providers that may burn: the named ones, or every enabled Claude/Codex with a credential.
fn burn_providers(paths: &Paths, named: &[String]) -> Result<Vec<Provider>> {
    if named.is_empty() {
        return Ok(burners(
            sync::eligible_accounts(paths)?
                .into_iter()
                .map(|(a, _)| a)
                .collect(),
        ));
    }
    named
        .iter()
        .map(|name| {
            let provider = parse_provider(name)?;
            if !provider.has_local_logs() {
                bail!("{provider} cannot run reference burns; expected claude or codex");
            }
            Ok(provider)
        })
        .collect()
}

/// Runs every burn the server has waiting: proof before → claim → burn → complete → proof after.
async fn run_burns(engine: &SyncEngine, providers: &[Provider], json: bool) -> Vec<BurnRunReport> {
    let mut reports = Vec::new();
    for provider in providers {
        let pending = match engine.api().pending_burns(Some(*provider)).await {
            Ok(pending) => pending,
            Err(e) => {
                let error = sync::describe(&e);
                if !json {
                    println!("{}: cannot list burns, {error}", provider.name());
                }
                reports.push(BurnRunReport::Unavailable {
                    provider: provider.id(),
                    error,
                });
                continue;
            }
        };
        for scheduled in pending {
            if !json {
                println!(
                    "{}: burn {} {} {} ({} tokens ×{})",
                    provider.name(),
                    scheduled.id,
                    scheduled.model,
                    scheduled.profile,
                    group(scheduled.target_tokens),
                    scheduled.repeats
                );
            }
            let report = run_one_burn(engine, *provider, &scheduled.id, json).await;
            if !json {
                match &report {
                    BurnRunReport::Burned {
                        invocations,
                        input_tokens,
                        output_tokens,
                        ..
                    } => println!(
                        "  done: {invocations} invocation(s), ~{} input / ~{} output tokens",
                        group(*input_tokens),
                        group(*output_tokens)
                    ),
                    BurnRunReport::Failed { error, .. }
                    | BurnRunReport::Unavailable { error, .. } => println!("  FAILED, {error}"),
                }
            }
            reports.push(report);
        }
    }
    reports
}

async fn run_one_burn(
    engine: &SyncEngine,
    provider: Provider,
    burn_id: &str,
    json: bool,
) -> BurnRunReport {
    let failed = |error: String| BurnRunReport::Failed {
        provider: provider.id(),
        burn_id: burn_id.to_string(),
        error,
    };

    // The proof before bounds the measurement interval; without it the burn cannot be measured.
    if let Err(e) = engine.sync(provider).await {
        return failed(format!(
            "proof before the burn failed: {}",
            sync::describe(&e)
        ));
    }
    let claimed = match engine.api().claim_burn(burn_id).await {
        Ok(claimed) => claimed,
        Err(e) => return failed(format!("claim failed: {}", sync::describe(&e))),
    };
    if claimed.provider != provider {
        return failed(format!(
            "the server claimed this burn for {} but it was listed under {provider}",
            claimed.provider
        ));
    }

    let plan = BurnPlan {
        provider: claimed.provider,
        model: claimed.model.clone(),
        profile: claimed.profile,
        target_tokens: claimed.target_tokens,
        repeats: claimed.repeats,
    };
    let outcome = burn::execute(&plan, burn_id).await;
    let error = outcome.as_ref().err().map(sync::describe);
    let tokens = outcome.as_ref().ok().map(|r| r.tokens());
    // The completion is diagnostic (the proof after is the measurement) but worth a few retries.
    let mut complete_reported = false;
    for attempt in 1..=3u64 {
        match engine
            .api()
            .complete_burn(burn_id, error.is_none(), error.clone(), tokens)
            .await
        {
            Ok(_) => {
                complete_reported = true;
                break;
            }
            Err(_) if attempt < 3 => tokio::time::sleep(Duration::from_secs(5 * attempt)).await,
            Err(e) => {
                if !json {
                    println!(
                        "  warning: cannot report the burn as finished, {}",
                        sync::describe(&e)
                    );
                }
            }
        }
    }

    // Providers update their meters asynchronously; give them a moment before the proof after.
    tokio::time::sleep(burn::settle_delay()).await;

    // The proof after closes the interval even when the burn failed part-way.
    if let Err(e) = engine.sync(provider).await
        && !json
    {
        println!(
            "  warning: proof after the burn failed, {}",
            sync::describe(&e)
        );
    }

    match outcome {
        Ok(report) => BurnRunReport::Burned {
            provider: provider.id(),
            burn_id: burn_id.to_string(),
            model: claimed.model,
            profile: claimed.profile.id(),
            invocations: report.invocations,
            input_tokens: report.input_tokens_estimate,
            output_tokens: report.output_tokens_estimate,
            complete_reported,
        },
        Err(_) => failed(error.unwrap_or_default()),
    }
}

fn print_status(r: &StatusReport) {
    println!("tmx {}  data {}", r.version, r.data_dir);
    match &r.device {
        Some(d) => println!(
            "Paired as @{} (device {}) with {}  since {}",
            d.username,
            d.device_id,
            r.server,
            d.paired_at.format("%Y-%m-%d")
        ),
        None => println!(
            "Not paired. Get a code at <web>/dashboard and run `tmx pair <code> --server {}`",
            r.server
        ),
    }
    if let Some(total) = r.total_tokens {
        println!(
            "On the board: {} verified tokens (+{} unverified)",
            group(total),
            group(r.unverified_tokens.unwrap_or(0))
        );
    }
    println!();
    println!(
        "{:<16} {:<8} {:<44} {:<17} result",
        "provider", "enabled", "credential", "last sync"
    );
    for p in &r.providers {
        let cred = if p.credential.available {
            p.credential.source.clone()
        } else {
            format!(
                "missing: {}",
                p.credential.detail.clone().unwrap_or_default()
            )
        };
        let last = p
            .state
            .last_success_at
            .map(|t| t.format("%m-%d %H:%M UTC").to_string())
            .unwrap_or_else(|| "-".into());
        let result = match (&p.state.last_error, &p.state.last_result) {
            (Some(e), _) => format!("error: {e}"),
            (None, Some(s)) => format!(
                "+{} verified{}, {} rejected{}",
                group(s.credited_tokens),
                if s.unverified_tokens > 0 {
                    format!(" (+{} unverified)", group(s.unverified_tokens))
                } else {
                    String::new()
                },
                s.rejected_records,
                s.label
                    .as_ref()
                    .map(|l| format!(" [{l}]"))
                    .unwrap_or_default()
            ),
            _ => "-".into(),
        };
        println!(
            "{:<16} {:<8} {:<44} {:<17} {}",
            p.handle,
            if p.enabled { "yes" } else { "no" },
            truncate(&cred, 44),
            last,
            result
        );
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n - 1).collect::<String>())
    }
}

fn group(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_thousands() {
        assert_eq!(group(0), "0");
        assert_eq!(group(999), "999");
        assert_eq!(group(1000), "1,000");
        assert_eq!(group(6_330_412), "6,330,412");
    }

    #[test]
    fn burns_only_accept_providers_with_local_logs() {
        let root = std::env::temp_dir().join(format!("tmx-cli-burn-test-{}", std::process::id()));
        let paths = Paths::at(root.clone()).unwrap();
        assert_eq!(
            burn_providers(&paths, &["claude".into(), "CODEX".into()]).unwrap(),
            [Provider::Claude, Provider::Codex]
        );
        assert!(burn_providers(&paths, &["cursor".into()]).is_err());
        assert!(burn_providers(&paths, &["kimi".into()]).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn reports_keep_the_credited_field_and_add_the_calibration_ones() {
        let synced = SyncReport::Synced {
            provider: "CLAUDE",
            account: "CLAUDE:abcd1234".into(),
            credited_tokens: 10,
            unverified_tokens: 4,
            reported_tokens: 14,
            credited_records: 2,
            rejected_records: 0,
            label: None,
            catch_up_rounds: 0,
            warnings: vec![],
        };
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&synced).unwrap()).unwrap();
        assert_eq!(json["outcome"], "synced");
        assert_eq!(json["provider"], "CLAUDE");
        assert_eq!(json["account"], "CLAUDE:abcd1234");
        // Field names are snake_case (the enum only renames variants); keep them stable.
        assert_eq!(json["credited_tokens"], 10);
        assert_eq!(json["unverified_tokens"], 4);
        assert_eq!(json["reported_tokens"], 14);

        let burned = BurnRunReport::Burned {
            provider: "CODEX",
            burn_id: "b1".into(),
            model: "gpt-5".into(),
            profile: "OUTPUT",
            invocations: 1,
            input_tokens: 30,
            output_tokens: 20_000,
            complete_reported: true,
        };
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&burned).unwrap()).unwrap();
        assert_eq!(json["outcome"], "burned");
        assert_eq!(json["burn_id"], "b1");
        assert_eq!(json["output_tokens"], 20_000);
    }

    #[test]
    fn daemon_never_burns_without_explicit_opt_in() {
        assert!(matches!(
            Cli::try_parse_from(["tmx", "daemon"]).unwrap().command,
            Command::Daemon {
                run_reference_burns: false,
                ..
            }
        ));
        assert!(matches!(
            Cli::try_parse_from(["tmx", "daemon", "--run-reference-burns"])
                .unwrap()
                .command,
            Command::Daemon {
                run_reference_burns: true,
                ..
            }
        ));
    }

    #[test]
    fn extra_claude_homes_resolve_by_handle_and_never_burn() {
        use tmx_core::claude_homes::{ClaudeHome, HomeOrigin};
        let home = ClaudeHome {
            id: "abcd1234".into(),
            name: "work".into(),
            dir: "/h/.claude-work".into(),
            origin: HomeOrigin::Discovered,
        };
        let accounts = account::with_homes(vec![home.clone()]);
        assert_eq!(
            parse_account(&accounts, "claude:work").unwrap(),
            Account::ClaudeHome(home.clone())
        );
        assert_eq!(
            parse_account(&accounts, "CODEX").unwrap(),
            Account::Provider(Provider::Codex)
        );
        let unknown = parse_account(&accounts, "claude:nope").unwrap_err();
        assert!(unknown.to_string().contains("claude:work"), "{unknown}");
        assert!(parse_account(&accounts, "kimi").is_err());
        // Reference burns drive the tool's usual login only.
        assert_eq!(burners(accounts), [Provider::Claude, Provider::Codex]);
    }

    #[test]
    fn parses_providers_case_insensitively() {
        assert_eq!(parse_provider("claude").unwrap(), Provider::Claude);
        assert_eq!(parse_provider("OPENROUTER").unwrap(), Provider::Openrouter);
        assert!(parse_provider("kimi").is_err());
    }
}
