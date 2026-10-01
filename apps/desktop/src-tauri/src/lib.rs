//! Tokenmaxxing desktop: a menu-bar / tray app around `tmx-core`.
//!
//! The window is a popover under the tray icon. A background task runs a sync round every
//! `SYNC_INTERVAL` (or when the user asks), one provider at a time — MPC-TLS proofs are
//! CPU-heavy, so rounds are sequential. All trust decisions happen on the server; this
//! process only holds the device key and the provider credentials it reads locally.

use std::{sync::Arc, time::Duration};

use chrono::{DateTime, Utc};
use serde::Serialize;
#[cfg(target_os = "macos")]
use tauri::ActivationPolicy;
use tauri::{
    AppHandle, Emitter, Manager, RunEvent, State, WebviewWindow, WindowEvent,
    image::Image,
    menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
};
use tauri_plugin_autostart::{MacosLauncher, ManagerExt as _};
use tauri_plugin_opener::OpenerExt as _;
use tauri_plugin_positioner::{Position, WindowExt as _};
use tmx_core::{
    Account, Provider, VERSION, account,
    api::{AccountInfo, ApiClient, DeviceMe, PairRequest},
    claude_homes::{HomeLogin, HomeLoginKind},
    credentials::ProviderKeys,
    identity::{DeviceIdentity, DeviceKey},
    paths::Paths,
    state::State as SyncState,
    sync::{self, SyncEngine},
};
use tokio::sync::{Mutex, Notify};
use tracing::{info, warn};

const DEFAULT_SERVER: &str = "http://localhost:8787";
const DEFAULT_INTERVAL_SECONDS: u64 = 600;
const STATUS_EVENT: &str = "status";
const WINDOW: &str = "main";

/// Shared app state (managed by Tauri).
pub struct AppState {
    paths: Paths,
    /// Key of the account currently being proven, if any.
    syncing: Mutex<Option<String>>,
    /// A user-requested round: `Some(None)` = every account, `Some(Some(key))` = one account.
    requested: Mutex<Option<Option<String>>>,
    wake: Notify,
    last_round_at: Mutex<Option<DateTime<Utc>>>,
    next_round_at: Mutex<Option<DateTime<Utc>>>,
    me: Mutex<Option<DeviceMe>>,
    interval: Duration,
}

impl AppState {
    fn new(paths: Paths) -> Self {
        let interval = std::env::var("TMX_SYNC_INTERVAL_SECONDS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|n| *n >= 60)
            .unwrap_or(DEFAULT_INTERVAL_SECONDS);
        Self {
            paths,
            syncing: Mutex::new(None),
            requested: Mutex::new(None),
            wake: Notify::new(),
            last_round_at: Mutex::new(None),
            next_round_at: Mutex::new(None),
            me: Mutex::new(None),
            interval: Duration::from_secs(interval),
        }
    }
}

// ---- DTOs shown by the UI ----------------------------------------------------------------

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DeviceDto {
    device_id: String,
    username: String,
    display_name: Option<String>,
    server: String,
    paired_at: DateTime<Utc>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CredentialDto {
    available: bool,
    source: String,
    detail: Option<String>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ProviderDto {
    /// `CLAUDE`, … or `CLAUDE:<home id>` for an extra Claude home.
    id: String,
    name: String,
    enabled: bool,
    /// An extra Claude home: off until the user links it, because linking is permanent.
    opt_in: bool,
    home_dir: Option<String>,
    /// An extra home's stored logins: `found`, `missing`, or `ambiguous` (several; unusable).
    home_login: Option<HomeLoginKind>,
    takes_api_key: bool,
    has_key: bool,
    credential: CredentialDto,
    syncing: bool,
    last_attempt_at: Option<DateTime<Utc>>,
    last_success_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
    backoff_until: Option<DateTime<Utc>>,
    syncs: u64,
    /// Verified tokens (what the board ranks) and the claimed remainder above the envelope.
    lifetime_credited_tokens: u64,
    lifetime_unverified_tokens: u64,
    label: Option<String>,
    plan: Option<String>,
    last_credited_tokens: Option<u64>,
    last_unverified_tokens: Option<u64>,
    last_rejected_records: Option<u64>,
    /// Provider-verified total on the board (from the API), when known.
    board_tokens: Option<u64>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct StatusDto {
    version: &'static str,
    platform: &'static str,
    data_dir: String,
    paired: bool,
    device: Option<DeviceDto>,
    server: String,
    web: Option<String>,
    providers: Vec<ProviderDto>,
    syncing: Option<String>,
    autostart: bool,
    interval_seconds: u64,
    last_round_at: Option<DateTime<Utc>>,
    next_round_at: Option<DateTime<Utc>>,
    total_tokens: Option<u64>,
}

async fn build_status(app: &AppHandle, state: &AppState) -> Result<StatusDto, String> {
    let identity = DeviceIdentity::load(&state.paths).map_err(err)?;
    let sync_state = SyncState::load(&state.paths).map_err(err)?;
    let keys = ProviderKeys::load(&state.paths).unwrap_or_default();
    let syncing = state.syncing.lock().await.clone();
    let me = state.me.lock().await.clone();

    let accounts = account::all(&sync_state);
    let has_homes = accounts.iter().any(|a| a.home().is_some());
    let providers = accounts
        .into_iter()
        .map(|a| {
            let p = a.provider();
            let home_login = a.home_login();
            let home_login_kind = home_login.as_ref().map(HomeLogin::kind);
            let cred = a.credential_status_with(&state.paths, &sync_state, home_login);
            let ps = a.state(&sync_state);
            // With several Claude logins, each Claude row shows only its own account (by uuid).
            let own = (has_homes && p == Provider::Claude)
                .then(|| cred.detail.clone().filter(|_| cred.available));
            let board = me
                .as_ref()
                .and_then(|m| board_tokens(&m.accounts, p, own.as_ref().map(Option::as_deref)));
            ProviderDto {
                id: a.key(),
                name: a.name(),
                enabled: a.is_enabled(&sync_state),
                opt_in: a.home().is_some(),
                home_dir: a.home().map(|h| h.dir.display().to_string()),
                home_login: home_login_kind,
                takes_api_key: p.takes_api_key(),
                has_key: keys.has(p),
                credential: CredentialDto {
                    available: cred.available,
                    source: cred.source,
                    detail: cred.detail,
                },
                syncing: syncing.as_deref() == Some(a.key().as_str()),
                last_attempt_at: ps.last_attempt_at,
                last_success_at: ps.last_success_at,
                last_error: ps.last_error,
                backoff_until: ps.backoff_until,
                syncs: ps.syncs,
                lifetime_credited_tokens: ps.lifetime_credited_tokens,
                lifetime_unverified_tokens: ps.lifetime_unverified_tokens,
                label: ps.last_result.as_ref().and_then(|r| r.label.clone()),
                plan: ps.last_result.as_ref().and_then(|r| r.plan.clone()),
                last_credited_tokens: ps.last_result.as_ref().map(|r| r.credited_tokens),
                last_unverified_tokens: ps.last_result.as_ref().map(|r| r.unverified_tokens),
                last_rejected_records: ps.last_result.as_ref().map(|r| r.rejected_records),
                board_tokens: board,
            }
        })
        .collect();

    let server = identity
        .as_ref()
        .map(|i| i.server_url.clone())
        .or_else(|| std::env::var("TMX_SERVER").ok())
        .unwrap_or_else(|| DEFAULT_SERVER.to_string());
    let web = me.as_ref().and_then(|m| m.server.web.clone());

    Ok(StatusDto {
        version: VERSION,
        platform: tmx_core::platform(),
        data_dir: state.paths.root().display().to_string(),
        paired: identity.is_some(),
        device: identity.map(|i| DeviceDto {
            device_id: i.device_id,
            username: i.username,
            display_name: i.display_name,
            server: i.server_url,
            paired_at: i.paired_at,
        }),
        server,
        web,
        providers,
        syncing,
        autostart: app.autolaunch().is_enabled().unwrap_or(false),
        interval_seconds: state.interval.as_secs(),
        last_round_at: *state.last_round_at.lock().await,
        next_round_at: *state.next_round_at.lock().await,
        total_tokens: me.as_ref().map(|m| m.total_tokens),
    })
}

/// Verified tokens on the board for a row: the provider's accounts summed, or with `own` set
/// (several Claude logins on this machine) only the account with that uuid, if known.
fn board_tokens(
    accounts: &[AccountInfo],
    provider: Provider,
    own: Option<Option<&str>>,
) -> Option<u64> {
    if own == Some(None) {
        return None;
    }
    let mine: Vec<u64> = accounts
        .iter()
        .filter(|x| x.provider.as_deref() == Some(provider.id()))
        .filter(|x| own.is_none_or(|id| id == Some(x.external_id.as_str())))
        .map(|x| x.total_tokens.unwrap_or(0))
        .collect();
    (!mine.is_empty()).then(|| mine.iter().sum())
}

async fn broadcast(app: &AppHandle) {
    let state = app.state::<AppState>();
    if let Ok(dto) = build_status(app, &state).await {
        let _ = app.emit(STATUS_EVENT, dto);
    }
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

fn parse_provider(id: &str) -> Result<Provider, String> {
    Provider::from_id(id).ok_or_else(|| format!("unknown provider {id}"))
}

/// A provider id or an extra Claude home's key, as the UI sends them.
fn parse_account(sync_state: &SyncState, id: &str) -> Result<Account, String> {
    account::find(&account::all(sync_state), id)
        .ok_or_else(|| format!("unknown provider or Claude home {id}"))
}

// ---- commands ---------------------------------------------------------------------------

#[tauri::command]
async fn get_status(app: AppHandle, state: State<'_, AppState>) -> Result<StatusDto, String> {
    build_status(&app, &state).await
}

#[tauri::command]
async fn pair(
    app: AppHandle,
    state: State<'_, AppState>,
    code: String,
    server: String,
    name: Option<String>,
) -> Result<StatusDto, String> {
    if DeviceIdentity::load(&state.paths).map_err(err)?.is_some() {
        return Err("this device is already paired".into());
    }
    let server = server.trim().trim_end_matches('/').to_string();
    if !(server.starts_with("http://") || server.starts_with("https://")) {
        return Err("server must be an http(s) URL".into());
    }
    let key = DeviceKey::generate();
    let api = ApiClient::new(&server, None).map_err(err)?;
    let response = api
        .pair(&PairRequest {
            code: code.trim().to_uppercase(),
            public_key: key.public_key_base64(),
            name: name
                .filter(|n| !n.trim().is_empty())
                .unwrap_or_else(tmx_core::device_name),
            platform: tmx_core::platform().to_string(),
            app_version: VERSION.to_string(),
        })
        .await
        .map_err(|e| sync::describe(&e))?;
    let identity = DeviceIdentity::new(
        &key,
        response.device.id,
        server,
        response.user.id,
        response.user.username,
        response.user.display_name,
    );
    identity.save(&state.paths).map_err(err)?;
    refresh_me(&state).await;
    request_round(&app, None).await;
    build_status(&app, &state).await
}

#[tauri::command]
async fn unpair(app: AppHandle, state: State<'_, AppState>) -> Result<StatusDto, String> {
    DeviceIdentity::forget(&state.paths).map_err(err)?;
    *state.me.lock().await = None;
    build_status(&app, &state).await
}

#[tauri::command]
async fn set_key(
    app: AppHandle,
    state: State<'_, AppState>,
    provider: String,
    key: String,
) -> Result<StatusDto, String> {
    let provider = parse_provider(&provider)?;
    let mut keys = ProviderKeys::load(&state.paths).map_err(err)?;
    let value = key.trim().to_string();
    keys.set(provider, if value.is_empty() { None } else { Some(value) })
        .map_err(err)?;
    keys.save(&state.paths).map_err(err)?;
    build_status(&app, &state).await
}

#[tauri::command]
async fn set_enabled(
    app: AppHandle,
    state: State<'_, AppState>,
    provider: String,
    enabled: bool,
) -> Result<StatusDto, String> {
    let mut sync_state = SyncState::load(&state.paths).map_err(err)?;
    let account = parse_account(&sync_state, &provider)?;
    match account.home_login() {
        Some(HomeLogin::Missing) if enabled => {
            return Err(
                "This Claude home has no login of its own, so its usage cannot be attributed."
                    .into(),
            );
        }
        Some(HomeLogin::Ambiguous(_)) if enabled => {
            return Err(
                "This Claude home has several stored logins, so its usage cannot be attributed to one. Remove all but one first."
                    .into(),
            );
        }
        _ => {}
    }
    account.state_mut(&mut sync_state).enabled = Some(enabled);
    sync_state.save(&state.paths).map_err(err)?;
    if enabled && account.home().is_some() {
        request_round(&app, Some(account.key())).await;
    }
    build_status(&app, &state).await
}

#[tauri::command]
async fn sync_now(
    app: AppHandle,
    state: State<'_, AppState>,
    provider: Option<String>,
) -> Result<(), String> {
    let key = match provider {
        Some(id) => {
            let sync_state = SyncState::load(&state.paths).map_err(err)?;
            Some(parse_account(&sync_state, &id)?.key())
        }
        None => None,
    };
    request_round(&app, key).await;
    Ok(())
}

#[tauri::command]
async fn set_autostart(
    app: AppHandle,
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<StatusDto, String> {
    let launcher = app.autolaunch();
    if enabled {
        launcher.enable()
    } else {
        launcher.disable()
    }
    .map_err(err)?;
    build_status(&app, &state).await
}

#[tauri::command]
async fn open_web(app: AppHandle, state: State<'_, AppState>, path: String) -> Result<(), String> {
    let web = match state
        .me
        .lock()
        .await
        .as_ref()
        .and_then(|m| m.server.web.clone())
    {
        Some(w) => w,
        None => {
            let identity = DeviceIdentity::load(&state.paths).map_err(err)?;
            let server = identity
                .map(|i| i.server_url)
                .or_else(|| std::env::var("TMX_SERVER").ok())
                .unwrap_or_else(|| DEFAULT_SERVER.into());
            ApiClient::new(&server, None)
                .map_err(err)?
                .meta()
                .await
                .map_err(|e| sync::describe(&e))?
                .web
                .unwrap_or(server)
        }
    };
    let url = format!(
        "{}/{}",
        web.trim_end_matches('/'),
        path.trim_start_matches('/')
    );
    app.opener().open_url(url, None::<&str>).map_err(err)
}

#[tauri::command]
async fn hide_window(app: AppHandle) -> Result<(), String> {
    if let Some(w) = app.get_webview_window(WINDOW) {
        w.hide().map_err(err)?;
    }
    Ok(())
}

#[tauri::command]
fn quit(app: AppHandle) {
    app.exit(0);
}

// ---- sync loop --------------------------------------------------------------------------

async fn request_round(app: &AppHandle, account: Option<String>) {
    let state = app.state::<AppState>();
    *state.requested.lock().await = Some(account);
    state.wake.notify_one();
}

async fn refresh_me(state: &AppState) {
    let Ok(Some(identity)) = DeviceIdentity::load(&state.paths) else {
        *state.me.lock().await = None;
        return;
    };
    let server_url = identity.server_url.clone();
    match ApiClient::new(&server_url, Some(identity)) {
        Ok(api) => match api.device_me().await {
            Ok(me) => *state.me.lock().await = Some(me),
            Err(e) => warn!("cannot refresh device status: {}", sync::describe(&e)),
        },
        Err(e) => warn!("api client: {e}"),
    }
}

/// Runs one provider sync on a dedicated thread with its own runtime.
///
/// The prover's future is not `Send` (it keeps transcript views across awaits), so it cannot be
/// polled on Tauri's shared runtime. A separate thread also keeps the CPU-heavy MPC work from
/// competing with the UI.
async fn sync_on_thread(
    paths: Paths,
    identity: DeviceIdentity,
    account: Account,
) -> anyhow::Result<sync::SyncOutcome> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name(format!(
            "tmx-sync-{}",
            account.key().to_lowercase().replace(':', "-")
        ))
        .spawn(move || {
            let result: anyhow::Result<sync::SyncOutcome> = (|| {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()?;
                let server_url = identity.server_url.clone();
                let api = ApiClient::new(&server_url, Some(identity))?;
                let engine = SyncEngine::new(paths, api);
                runtime.block_on(engine.sync_account(&account))
            })();
            let _ = tx.send(result);
        })
        .map_err(|e| anyhow::anyhow!("cannot start the sync thread: {e}"))?;
    rx.await
        .map_err(|_| anyhow::anyhow!("the sync thread ended unexpectedly"))?
}

async fn run_round(app: &AppHandle, only: Option<String>) {
    let state = app.state::<AppState>();
    let Ok(Some(identity)) = DeviceIdentity::load(&state.paths) else {
        return;
    };
    let accounts: Vec<Account> = match only {
        Some(key) => SyncState::load(&state.paths)
            .ok()
            .and_then(|s| account::find(&account::all(&s), &key))
            .into_iter()
            .collect(),
        None => sync::eligible_accounts(&state.paths)
            .map(|v| v.into_iter().map(|(a, _)| a).collect())
            .unwrap_or_default(),
    };
    for account in accounts {
        *state.syncing.lock().await = Some(account.key());
        broadcast(app).await;
        match sync_on_thread(state.paths.clone(), identity.clone(), account.clone()).await {
            Ok(o) => {
                info!(%account, verified = o.summary.credited_tokens, unverified = o.summary.unverified_tokens, "synced")
            }
            Err(e) => warn!(%account, "sync failed: {}", sync::describe(&e)),
        }
        *state.syncing.lock().await = None;
        broadcast(app).await;
    }
    *state.last_round_at.lock().await = Some(Utc::now());
    refresh_me(&state).await;
    broadcast(app).await;
}

async fn sync_loop(app: AppHandle) {
    let state = app.state::<AppState>();
    // Give the UI a moment to come up, then start with a round.
    tokio::time::sleep(Duration::from_secs(3)).await;
    refresh_me(&state).await;
    broadcast(&app).await;
    loop {
        let requested = state.requested.lock().await.take();
        run_round(&app, requested.flatten()).await;
        let next = Utc::now()
            + chrono::Duration::from_std(state.interval).unwrap_or(chrono::Duration::minutes(10));
        *state.next_round_at.lock().await = Some(next);
        broadcast(&app).await;
        tokio::select! {
            _ = tokio::time::sleep(state.interval) => {}
            _ = state.wake.notified() => {}
        }
    }
}

// ---- window + tray ----------------------------------------------------------------------

fn window(app: &AppHandle) -> Option<WebviewWindow> {
    app.get_webview_window(WINDOW)
}

fn show_window(app: &AppHandle) {
    if let Some(w) = window(app) {
        let _ = w.move_window(Position::TrayBottomCenter);
        let _ = w.show();
        let _ = w.set_focus();
        let handle = app.clone();
        tauri::async_runtime::spawn(async move { broadcast(&handle).await });
    }
}

fn toggle_window(app: &AppHandle) {
    match window(app) {
        Some(w) if w.is_visible().unwrap_or(false) && w.is_focused().unwrap_or(true) => {
            let _ = w.hide();
        }
        _ => show_window(app),
    }
}

fn build_tray(app: &AppHandle) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Open Tokenmaxxing", true, None::<&str>)?;
    let sync_item = MenuItem::with_id(app, "sync", "Sync now", true, None::<&str>)?;
    let board = MenuItem::with_id(app, "board", "Open leaderboard", true, None::<&str>)?;
    let autostart = CheckMenuItem::with_id(
        app,
        "autostart",
        "Launch at login",
        true,
        app.autolaunch().is_enabled().unwrap_or(false),
        None::<&str>,
    )?;
    let quit_item = PredefinedMenuItem::quit(app, Some("Quit Tokenmaxxing"))?;
    let menu = Menu::with_items(
        app,
        &[
            &open,
            &sync_item,
            &board,
            &PredefinedMenuItem::separator(app)?,
            &autostart,
            &PredefinedMenuItem::separator(app)?,
            &quit_item,
        ],
    )?;
    let autostart_item = autostart.clone();

    TrayIconBuilder::with_id("main")
        .icon(Image::from_bytes(include_bytes!("../icons/tray.png"))?)
        .icon_as_template(true)
        .tooltip("Tokenmaxxing")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(move |app, event| match event.id.as_ref() {
            "open" => show_window(app),
            "sync" => {
                let handle = app.clone();
                tauri::async_runtime::spawn(async move { request_round(&handle, None).await });
            }
            "board" => {
                let handle = app.clone();
                tauri::async_runtime::spawn(async move {
                    let state = handle.state::<AppState>();
                    if let Err(e) = open_web(handle.clone(), state, "/".into()).await {
                        warn!("open leaderboard: {e}");
                    }
                });
            }
            "autostart" => {
                let launcher = app.autolaunch();
                let enabled = launcher.is_enabled().unwrap_or(false);
                let result = if enabled {
                    launcher.disable()
                } else {
                    launcher.enable()
                };
                if let Err(e) = result {
                    warn!("autostart: {e}");
                }
                let _ = autostart_item.set_checked(launcher.is_enabled().unwrap_or(false));
                let handle = app.clone();
                tauri::async_runtime::spawn(async move { broadcast(&handle).await });
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            tauri_plugin_positioner::on_tray_event(tray.app_handle(), &event);
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                toggle_window(tray.app_handle());
            }
        })
        .build(app)?;
    Ok(())
}

/// Entry point used by `main.rs`.
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,yamux=warn,uid_mux=warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let paths = Paths::discover().expect("cannot create the application data directory");
    let state = AppState::new(paths);
    let keep_open = std::env::var("TMX_KEEP_OPEN").is_ok();

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            show_window(app)
        }))
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec!["--minimized"]),
        ))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_positioner::init())
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            get_status,
            pair,
            unpair,
            set_key,
            set_enabled,
            sync_now,
            set_autostart,
            open_web,
            hide_window,
            quit
        ])
        .setup(move |app| {
            #[cfg(target_os = "macos")]
            app.set_activation_policy(ActivationPolicy::Accessory);
            build_tray(app.handle())?;
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(sync_loop(handle));
            if !std::env::args().any(|a| a == "--minimized") {
                show_window(app.handle());
            }
            Ok(())
        })
        .on_window_event(move |window, event| match event {
            WindowEvent::CloseRequested { api, .. } => {
                api.prevent_close();
                let _ = window.hide();
            }
            WindowEvent::Focused(false) if !keep_open => {
                let _ = window.hide();
            }
            _ => {}
        })
        .build(tauri::generate_context!())
        .expect("error while building Tokenmaxxing");

    app.run(|_app, event| {
        if let RunEvent::ExitRequested {
            api, code: None, ..
        } = event
        {
            api.prevent_exit();
        }
    });
}

#[allow(dead_code)]
fn _assert_send() {
    fn is_send<T: Send>() {}
    is_send::<Arc<AppState>>();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(provider: &str, external_id: &str, tokens: u64) -> AccountInfo {
        AccountInfo {
            id: format!("a-{external_id}"),
            provider: Some(provider.into()),
            external_id: external_id.into(),
            tier: None,
            plan: None,
            label: None,
            last_proof_at: None,
            total_tokens: Some(tokens),
            unverified_tokens: None,
        }
    }

    #[test]
    fn board_rows_split_claude_accounts_only_when_several_logins_exist() {
        let accounts = [
            account("CLAUDE", "uuid-default", 10),
            account("CLAUDE", "uuid-work", 5),
            account("CODEX", "acct", 7),
        ];
        // One Claude login on this machine: the provider total, as before.
        assert_eq!(board_tokens(&accounts, Provider::Claude, None), Some(15));
        assert_eq!(board_tokens(&accounts, Provider::Codex, None), Some(7));
        assert_eq!(board_tokens(&accounts, Provider::Cursor, None), None);
        // Several: each row its own account; an unknown uuid shows nothing rather than a sum.
        assert_eq!(
            board_tokens(&accounts, Provider::Claude, Some(Some("uuid-work"))),
            Some(5)
        );
        assert_eq!(board_tokens(&accounts, Provider::Claude, Some(None)), None);
        assert_eq!(
            board_tokens(&accounts, Provider::Claude, Some(Some("unlinked"))),
            None
        );
    }
}
