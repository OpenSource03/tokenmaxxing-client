//! `tmx-attest` — notary service, verifier service and a proving CLI.

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, FromRequest, Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use tmx_attest::{
    keys,
    notary::{Notary, NotaryLimits, WsListener},
    prove::{prove, prove_with_ticket},
    spec::{ProofSpec, ResponseRedaction},
    verify::{VerifyInput, verify},
};

#[derive(Parser, Debug)]
#[command(
    name = "tmx-attest",
    version,
    about = "Tokenmaxxing attestation tooling"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate a notary signing key.
    Keygen {
        /// Where to write the hex key (0600).
        #[arg(long)]
        out: PathBuf,
    },
    /// Run the notary (MPC endpoint) and the verifier HTTP service.
    Serve {
        /// TCP address for prover sessions.
        #[arg(long, default_value = "0.0.0.0:7047")]
        listen: SocketAddr,
        /// Also accept prover sessions over WebSocket at `/notary` on this address, for HTTP-only
        /// proxies such as Cloudflare Tunnel (clients use `wss://<host>/notary`). Always ticketed.
        #[arg(long, env = "TMX_NOTARY_WS_LISTEN")]
        ws_listen: Option<SocketAddr>,
        /// Request header carrying the client IP for WebSocket per-IP limits (e.g.
        /// `cf-connecting-ip`). Safe only when the WebSocket port is reachable solely through a
        /// proxy that overwrites this header; otherwise clients can spoof it.
        #[arg(long, env = "TMX_NOTARY_WS_CLIENT_IP_HEADER", requires = "ws_listen")]
        ws_client_ip_header: Option<String>,
        /// HTTP address for `/verify` and `/health` (keep private).
        #[arg(long, default_value = "127.0.0.1:7048")]
        verify_listen: SocketAddr,
        /// Notary signing key file (hex).
        #[arg(long, env = "TMX_NOTARY_KEY_FILE")]
        key_file: PathBuf,
        /// Additional trusted notary verifying keys (hex), e.g. during rotation.
        #[arg(long = "trusted-key")]
        trusted_keys: Vec<String>,
        /// Max bytes a prover may send in a session.
        #[arg(long, default_value_t = 1 << 14)]
        max_sent_data: usize,
        /// Max bytes a prover may receive in a session.
        #[arg(long, default_value_t = 1 << 16)]
        max_recv_data: usize,
        /// Maximum simultaneous expensive MPC sessions.
        #[arg(long, env = "TMX_NOTARY_MAX_SESSIONS", default_value_t = 2)]
        max_sessions: usize,
        #[arg(long, env = "TMX_NOTARY_MAX_HANDSHAKES", default_value_t = 32)]
        max_handshakes: usize,
        #[arg(long, env = "TMX_NOTARY_MAX_PER_IP", default_value_t = 4)]
        max_connections_per_ip: usize,
        /// Local development only; requires a loopback --listen address.
        #[arg(long)]
        allow_unauthenticated: bool,
    },
    /// Run a proving session and write the presentation.
    Prove {
        /// Proof spec JSON file.
        #[arg(long)]
        spec: PathBuf,
        /// Notary address: `host:port` (TCP) or `ws://`/`wss://` URL (WebSocket, ticket required).
        #[arg(long, default_value = "127.0.0.1:7047")]
        notary: String,
        /// Short-lived admission ticket from the paired API (hex); kept out of argv via env.
        #[arg(long, env = "TMX_NOTARY_TICKET", hide_env_values = true)]
        ticket: Option<String>,
        /// Explicitly use a loopback notary started with --allow-unauthenticated.
        #[arg(long, conflicts_with = "ticket")]
        allow_unauthenticated: bool,
        /// Output path for the presentation bytes.
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify a presentation file and print the authenticated session as JSON.
    Verify {
        /// Presentation file.
        #[arg(long)]
        presentation: PathBuf,
        /// Expected server DNS name.
        #[arg(long)]
        server: String,
        /// Trusted notary key (hex); repeatable.
        #[arg(long = "trusted-key", required = true)]
        trusted_keys: Vec<String>,
        /// Request header names allowed to be hidden; repeatable.
        #[arg(long = "secret-request-header")]
        secret_request_headers: Vec<String>,
        /// Response header names allowed to be hidden; repeatable.
        #[arg(long = "secret-response-header", default_values_t = vec!["set-cookie".to_string()])]
        secret_response_headers: Vec<String>,
        /// Allowed JSON redaction as `<response-index>:<path>`; repeatable.
        #[arg(long = "redact")]
        redactions: Vec<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,yamux=warn,uid_mux=warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    match Cli::parse().command {
        Command::Keygen { out } => {
            let key = keys::generate_signing_key();
            keys::write_signing_key(&out, &key)?;
            println!("{}", keys::verifying_key_hex(&key)?);
            Ok(())
        }
        Command::Serve {
            listen,
            ws_listen,
            ws_client_ip_header,
            verify_listen,
            key_file,
            trusted_keys,
            max_sent_data,
            max_recv_data,
            max_sessions,
            max_handshakes,
            max_connections_per_ip,
            allow_unauthenticated,
        } => {
            let key = keys::load_signing_key(&key_file)?;
            let notary = Notary::new(
                key,
                NotaryLimits {
                    max_sent_data,
                    max_recv_data,
                    max_sessions,
                    max_handshakes,
                    max_connections_per_ip,
                    allow_unauthenticated,
                    ..NotaryLimits::default()
                },
            );
            let own_key = notary.verifying_key_hex()?;
            let mut trusted: Vec<String> = trusted_keys
                .iter()
                .map(|k| keys::normalise_key_hex(k))
                .collect();
            trusted.push(own_key.clone());
            eprintln!("notary verifying key: {own_key}");

            let listener = tokio::net::TcpListener::bind(listen).await?;
            let websocket = match ws_listen {
                Some(addr) => Some(WsListener::new(
                    tokio::net::TcpListener::bind(addr).await?,
                    ws_client_ip_header.as_deref(),
                )?),
                None => None,
            };
            let notary_task = {
                let notary = notary.clone();
                tokio::spawn(async move { notary.serve_with_websocket(listener, websocket).await })
            };
            let verify_task = tokio::spawn(serve_verify(verify_listen, own_key, trusted, notary));
            tokio::select! {
                r = notary_task => r??,
                r = verify_task => r??,
                _ = tokio::signal::ctrl_c() => {}
            }
            Ok(())
        }
        Command::Prove {
            spec,
            notary,
            out,
            ticket,
            allow_unauthenticated,
        } => {
            let spec: ProofSpec = serde_json::from_slice(
                &std::fs::read(&spec).with_context(|| format!("cannot read {}", spec.display()))?,
            )?;
            let output = match ticket {
                Some(ticket) => prove_with_ticket(&spec, &notary, &ticket).await?,
                None if allow_unauthenticated => prove(&spec, &notary).await?,
                None => anyhow::bail!("admission ticket required (TMX_NOTARY_TICKET)"),
            };
            std::fs::write(&out, &output.presentation)?;
            let summary = serde_json::json!({
                "presentation_path": out,
                "presentation_bytes": output.presentation.len(),
                "notary_key": output.notary_key,
                "time": output.time,
                "responses": output.responses,
            });
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
        Command::Verify {
            presentation,
            server,
            trusted_keys,
            secret_request_headers,
            secret_response_headers,
            redactions,
        } => {
            let input = VerifyInput {
                presentation: std::fs::read(&presentation)?,
                expected_server_name: server,
                trusted_notary_keys: trusted_keys,
                secret_request_headers,
                secret_response_headers,
                redactions: parse_redactions(&redactions)?,
            };
            match verify(&input) {
                Ok(session) => {
                    println!("{}", serde_json::to_string_pretty(&session)?);
                    Ok(())
                }
                Err(e) => {
                    eprintln!("REJECTED: {e}");
                    std::process::exit(2);
                }
            }
        }
    }
}

fn parse_redactions(items: &[String]) -> Result<Vec<ResponseRedaction>> {
    let mut out: Vec<ResponseRedaction> = Vec::new();
    for item in items {
        let (idx, path) = item
            .split_once(':')
            .with_context(|| format!("bad --redact {item}, expected <index>:<path>"))?;
        let idx: usize = idx.parse().context("bad response index")?;
        match out.iter_mut().find(|r| r.response == idx) {
            Some(r) => r.json_paths.push(path.to_string()),
            None => out.push(ResponseRedaction {
                response: idx,
                json_paths: vec![path.to_string()],
            }),
        }
    }
    Ok(out)
}

// ---- verifier HTTP service ---------------------------------------------------------------------

struct VerifyState {
    notary: Notary,
    slots: Arc<tokio::sync::Semaphore>,
    admission_slots: Arc<tokio::sync::Semaphore>,
    own_key: String,
    trusted_keys: Vec<String>,
}

#[derive(Deserialize)]
struct VerifyHttpRequest {
    #[serde(flatten)]
    input: VerifyInput,
}

#[derive(Serialize)]
struct HealthResponse {
    ok: bool,
    notary_key: String,
    trusted_keys: Vec<String>,
}

async fn serve_verify(
    addr: SocketAddr,
    own_key: String,
    trusted_keys: Vec<String>,
    notary: Notary,
) -> Result<()> {
    let state = Arc::new(VerifyState {
        notary,
        slots: Arc::new(tokio::sync::Semaphore::new(2)),
        admission_slots: Arc::new(tokio::sync::Semaphore::new(32)),
        own_key,
        trusted_keys,
    });
    let app = verifier_router(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    eprintln!("verifier listening on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

fn verifier_router(state: Arc<VerifyState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/verify", post(verify_handler))
        .route(
            "/admission",
            post(admission_handler).layer(DefaultBodyLimit::max(256)),
        )
        .layer(DefaultBodyLimit::max(4 * 1024 * 1024))
        .with_state(state)
}

async fn health(State(state): State<Arc<VerifyState>>) -> Json<HealthResponse> {
    Json(HealthResponse {
        ok: true,
        notary_key: state.own_key.clone(),
        trusted_keys: state.trusted_keys.clone(),
    })
}

async fn verify_handler(State(state): State<Arc<VerifyState>>, request: Request) -> Response {
    let Ok(permit) = state.slots.clone().try_acquire_owned() else {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"ok":false,"error":"verification capacity unavailable"})),
        )
            .into_response();
    };
    let req: VerifyHttpRequest = match read_json(request, std::time::Duration::from_secs(5)).await {
        Ok(req) => req,
        Err(response) => return *response,
    };
    let mut input = req.input;
    // The caller may narrow the trusted set but never widen it beyond service policy.
    if input.trusted_notary_keys.is_empty() {
        input.trusted_notary_keys = state.trusted_keys.clone();
    } else {
        input.trusted_notary_keys.retain(|k| {
            let k = keys::normalise_key_hex(k);
            state.trusted_keys.contains(&k)
        });
    }
    let result = tokio::task::spawn_blocking(move || {
        // The slot stays held even if the HTTP caller disconnects during blocking work.
        let _permit = permit;
        verify(&input)
    })
    .await;
    match result {
        Ok(Ok(session)) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "session": session })),
        ),
        Ok(Err(e)) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "ok": false, "error": e.to_string() })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": format!("verifier panicked: {e}") })),
        ),
    }
    .into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionRequest {
    subject: String,
}

async fn admission_handler(State(state): State<Arc<VerifyState>>, request: Request) -> Response {
    let Ok(_permit) = state.admission_slots.clone().try_acquire_owned() else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    let req: AdmissionRequest = match read_json(request, std::time::Duration::from_secs(5)).await {
        Ok(req) => req,
        Err(response) => return *response,
    };
    match state.notary.issue_admission(req.subject) {
        Ok(ticket) => (StatusCode::OK, Json(serde_json::json!(ticket))),
        Err(_) => (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error":"admission capacity unavailable"})),
        ),
    }
    .into_response()
}

async fn read_json<T: serde::de::DeserializeOwned>(
    request: Request,
    deadline: std::time::Duration,
) -> std::result::Result<T, Box<Response>> {
    match tokio::time::timeout(deadline, Json::<T>::from_request(request, &())).await {
        Ok(Ok(Json(value))) => Ok(value),
        Ok(Err(rejection)) => Err(Box::new(rejection.into_response())),
        Err(_) => Err(Box::new(StatusCode::REQUEST_TIMEOUT.into_response())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, Bytes};
    use std::time::Duration;

    fn state() -> Arc<VerifyState> {
        Arc::new(VerifyState {
            notary: Notary::new(keys::generate_signing_key(), Default::default()),
            slots: Arc::new(tokio::sync::Semaphore::new(2)),
            admission_slots: Arc::new(tokio::sync::Semaphore::new(32)),
            own_key: String::new(),
            trusted_keys: vec![],
        })
    }
    fn request(body: Body) -> Request {
        Request::builder()
            .header("content-type", "application/json")
            .body(body)
            .unwrap()
    }
    fn stalled() -> Body {
        Body::from_stream(futures::stream::pending::<
            std::result::Result<Bytes, std::io::Error>,
        >())
    }

    #[tokio::test]
    async fn overload_is_rejected_before_reading_unbounded_or_stalled_bodies() {
        let state = state();
        let _held = state.slots.acquire_many(2).await.unwrap();
        let response = tokio::time::timeout(
            Duration::from_millis(50),
            verify_handler(State(state.clone()), request(stalled())),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn slow_body_has_a_deadline() {
        let response = read_json::<AdmissionRequest>(request(stalled()), Duration::from_millis(30))
            .await
            .err()
            .unwrap();
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    }

    #[tokio::test]
    async fn malformed_and_oversized_json_release_verification_capacity() {
        let state = state();
        let response = verify_handler(State(state.clone()), request(Body::from("{"))).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(state.slots.available_permits(), 2);
        let response = verify_handler(
            State(state.clone()),
            request(Body::from("x".repeat(5 * 1024 * 1024))),
        )
        .await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(state.slots.available_permits(), 2);
    }

    #[tokio::test]
    async fn private_admission_body_concurrency_is_bounded() {
        let state = state();
        let _held = state.admission_slots.acquire_many(32).await.unwrap();
        let response = tokio::time::timeout(
            Duration::from_millis(50),
            admission_handler(State(state.clone()), request(stalled())),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }
    #[tokio::test]
    async fn routed_admission_uses_its_small_body_limit() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, verifier_router(state()))
                .await
                .unwrap();
        });
        let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
        let body = format!("{{\"subject\":\"alice\"}}{}", " ".repeat(300));
        let request = format!(
            "POST /admission HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        socket.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        tokio::time::timeout(Duration::from_secs(2), socket.read_to_string(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 413"), "{response}");
        task.abort();
    }
}
