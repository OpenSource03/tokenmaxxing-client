//! Prover: runs on the user's machine.
//!
//! Opens an MPC-TLS session with the notary, performs the HTTP requests from a [`ProofSpec`]
//! over one keep-alive connection, obtains a signed attestation, and immediately builds a
//! presentation that reveals everything except the configured secrets. Secrets never leave
//! this process and are dropped when the function returns.

use std::{
    future::IntoFuture,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
use http_body_util::{BodyExt, Full};
use hyper::{Request, body::Bytes};
use hyper_util::rt::TokioIo;
use rangeset::{
    iter::{FromRangeIterator, RangeIterator},
    ops::Set,
    set::RangeSet,
};
use serde::{Deserialize, Serialize};
use tokio::{net::TcpStream, sync::oneshot, task::JoinSet};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::{debug, info, warn};

use tlsn::{
    Session,
    attestation::{
        Attestation, CryptoProvider,
        presentation::Presentation,
        request::{Request as AttestationRequest, RequestConfig},
    },
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::mpc::MpcTlsConfig,
    },
    connection::{DnsName, HandshakeData, ServerName},
    prover::ProverOutput,
    transcript::TranscriptCommitConfig,
    webpki::RootCertStore,
};
use tlsn_formats::http::{Body, BodyContent, DefaultHttpCommitter, HttpCommit, HttpTranscript};

use crate::{
    spec::ProofSpec,
    ws::{self, Transport},
};

/// Plaintext view of one response, for the prover's own use (it already knows the plaintext).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsePreview {
    /// HTTP status.
    pub status: u16,
    /// Response body.
    pub body: String,
}

/// Result of a proving session.
#[derive(Debug, Clone)]
pub struct ProveOutput {
    /// bincode-serialised [`Presentation`] to submit to the verifier.
    pub presentation: Vec<u8>,
    /// Hex of the notary key that signed the attestation.
    pub notary_key: String,
    /// Unix time the TLS connection started.
    pub time: u64,
    /// Plaintext responses (local use only).
    pub responses: Vec<ResponsePreview>,
}

#[derive(Debug, thiserror::Error)]
#[error("notary busy; retry later")]
pub struct NotaryBusy;

/// Includes notary setup, upstream IO, MPC, and final attestation exchange.
pub const PROOF_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug, thiserror::Error)]
#[error("proof timed out after {seconds} seconds; it will retry automatically")]
pub struct ProofTimedOut {
    pub seconds: u64,
}

/// Runs the full prove → attest → present pipeline against a loopback development notary.
pub async fn prove(spec: &ProofSpec, notary_addr: &str) -> Result<ProveOutput> {
    prove_bounded(spec, notary_addr, None, PROOF_TIMEOUT).await
}

/// Runs a session with a one-use ticket issued to the paired user. `notary_addr` is `host:port`
/// (raw TCP) or `ws://`/`wss://` URL (WebSocket, e.g. `wss://notary.example.com/notary`).
pub async fn prove_with_ticket(
    spec: &ProofSpec,
    notary_addr: &str,
    ticket: &str,
) -> Result<ProveOutput> {
    let token: [u8; 32] = hex::decode(ticket)
        .context("invalid admission ticket")?
        .try_into()
        .map_err(|_| anyhow!("invalid admission ticket length"))?;
    prove_bounded(spec, notary_addr, Some(token), PROOF_TIMEOUT).await
}

async fn prove_bounded(
    spec: &ProofSpec,
    notary_addr: &str,
    ticket: Option<[u8; 32]>,
    deadline: Duration,
) -> Result<ProveOutput> {
    let (lost, disconnected) = oneshot::channel();
    // MPC may remain pending when its mux driver exits; observe that task independently.
    let work = async {
        tokio::select! {
            result = prove_inner(spec, notary_addr, ticket, lost) => result,
            reason = async {
                match disconnected.await {
                    Ok(reason) => reason,
                    Err(_) => std::future::pending().await,
                }
            } => Err(anyhow!("notary session interrupted: {reason}")),
        }
    };
    tokio::time::timeout(deadline, work)
        .await
        .map_err(|_| ProofTimedOut {
            seconds: deadline.as_secs(),
        })?
}

async fn prove_inner(
    spec: &ProofSpec,
    notary_addr: &str,
    ticket: Option<[u8; 32]>,
    lost: oneshot::Sender<String>,
) -> Result<ProveOutput> {
    spec.validate()
        .map_err(|e| anyhow!("invalid proof spec: {e}"))?;
    let dns: DnsName = spec
        .server_name
        .as_str()
        .try_into()
        .map_err(|e| anyhow!("invalid server name {}: {e:?}", spec.server_name))?;

    // --- session with the notary ---------------------------------------------------------
    let (mut notary_socket, loopback): (Box<dyn Transport>, bool) = if ws::is_websocket(notary_addr)
    {
        if ticket.is_none() {
            bail!("a WebSocket notary requires an admission ticket");
        }
        let socket =
            tokio::time::timeout(std::time::Duration::from_secs(10), ws::connect(notary_addr))
                .await
                .context("notary connection timed out")?
                .map_err(|error| match error.downcast::<ws::UpgradeRefused>() {
                    Ok(ws::UpgradeRefused(429 | 503)) => NotaryBusy.into(),
                    Ok(refused) => anyhow::Error::new(refused),
                    Err(error) => error,
                })
                .with_context(|| format!("cannot reach notary at {notary_addr}"))?;
        (Box::new(socket), false)
    } else {
        let socket = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            TcpStream::connect(notary_addr),
        )
        .await
        .context("notary connection timed out")?
        .with_context(|| format!("cannot reach notary at {notary_addr}"))?;
        socket.set_nodelay(true)?;
        let loopback = socket.peer_addr()?.ip().is_loopback();
        (Box::new(socket), loopback)
    };
    if let Some(ticket) = ticket {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::io::AsyncWriteExt::write_all(&mut notary_socket, crate::admission::PREFACE)
                .await?;
            tokio::io::AsyncWriteExt::write_all(&mut notary_socket, &ticket).await?;
            tokio::io::AsyncWriteExt::flush(&mut notary_socket).await?;
            let status = tokio::io::AsyncReadExt::read_u8(&mut notary_socket).await?;
            if status != 0 {
                return Err(NotaryBusy.into());
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("notary admission timed out")??;
    } else if !loopback {
        bail!("unauthenticated proving is restricted to loopback development");
    }
    let session = Session::with_config(notary_socket.compat(), crate::session_config());
    let (driver, mut handle) = session.split();
    let mut drivers = JoinSet::new();
    let expected_close = Arc::new(AtomicBool::new(false));
    let driver_closing = expected_close.clone();
    drivers.spawn(async move {
        let result = driver.await;
        if !driver_closing.load(Ordering::Acquire) {
            let reason = match &result {
                Ok(_) => "connection closed before proof completion".to_string(),
                Err(error) => error.to_string(),
            };
            let _ = lost.send(reason);
        }
        result
    });

    let mpc_builder = MpcTlsConfig::builder()
        .max_sent_data(spec.max_sent_data)
        .max_recv_data(spec.max_recv_data);
    let mpc_config = match spec.max_recv_data_online {
        // Sequential requests need responses decrypted while the connection is live.
        Some(online) => mpc_builder
            .max_recv_data_online(online)
            .defer_decryption_from_start(false),
        // Single request: decrypt everything after the connection closes (cheaper MPC).
        None => mpc_builder.defer_decryption_from_start(true),
    }
    .build()?;

    let prover = handle
        .new_prover(ProverConfig::builder().build()?)?
        .commit(mpc_config)
        .await
        .context("MPC-TLS setup with notary failed")?;

    // --- TLS connection to the provider ----------------------------------------------------
    let server_socket = TcpStream::connect((spec.server_name.as_str(), spec.port))
        .await
        .with_context(|| format!("cannot connect to {}:{}", spec.server_name, spec.port))?;
    server_socket.set_nodelay(true)?;

    let tls_config = TlsClientConfig::builder()
        .server_name(ServerName::Dns(dns.clone()))
        .root_store(RootCertStore::mozilla())
        .build()?;
    let (tls_connection, prover) = prover.connect(tls_config, server_socket.compat())?;
    let tls_connection = TokioIo::new(tls_connection.compat());
    let mut provers = JoinSet::new();
    provers.spawn(prover.into_future());

    let (mut sender, connection) = hyper::client::conn::http1::handshake(tls_connection)
        .await
        .context("HTTP handshake failed")?;
    let mut connections = JoinSet::new();
    connections.spawn(connection);

    // --- requests ------------------------------------------------------------------------
    let mut previews = Vec::with_capacity(spec.requests.len());
    let total = spec.requests.len();
    for (i, req) in spec.requests.iter().enumerate() {
        let last = i + 1 == total;
        let mut builder = Request::builder()
            .method(req.method.as_str())
            .uri(req.path.as_str())
            .header("Host", spec.server_name.as_str())
            .header("Accept-Encoding", "identity")
            .header("Connection", if last { "close" } else { "keep-alive" });
        let has = |name: &str| {
            req.headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case(name))
        };
        if !has("accept") {
            builder = builder.header("Accept", "*/*");
        }
        if req.body.is_some() && !has("content-type") {
            builder = builder.header("Content-Type", "application/json");
        }
        for (k, v) in &req.headers {
            builder = builder.header(k.as_str(), v.as_str());
        }
        let body = req.body.clone().map(Bytes::from).unwrap_or_default();
        let request = builder.body(Full::new(body))?;

        debug!(index = i, target = %req.path, "sending request");
        sender.ready().await?;
        let response = sender
            .send_request(request)
            .await
            .with_context(|| format!("request {i} ({}) failed", req.path))?;
        let status = response.status().as_u16();
        let bytes = response.into_body().collect().await?.to_bytes();
        previews.push(ResponsePreview {
            status,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        });
        info!(index = i, status, bytes = bytes.len(), "response received");
    }

    let mut prover = provers
        .join_next()
        .await
        .context("prover task missing")??
        .context("MPC-TLS connection failed")?;

    // --- commit + prove -------------------------------------------------------------------
    let transcript = HttpTranscript::parse(prover.transcript())
        .map_err(|e| anyhow!("cannot parse HTTP transcript: {e}"))?;
    if transcript.responses.len() != total {
        bail!(
            "expected {total} responses in transcript, found {}",
            transcript.responses.len()
        );
    }

    let mut commit_builder = TranscriptCommitConfig::builder(prover.transcript());
    DefaultHttpCommitter::default()
        .commit_transcript(&mut commit_builder, &transcript)
        .map_err(|e| anyhow!("commit failed: {e}"))?;
    // The default committer covers headers and body *content* only. Chunked transfer-encoding
    // framing (chunk-size lines, CRLFs, trailers) stays uncommitted, yet the verifier must see
    // it to parse the body at all. Commit it explicitly so it can be revealed.
    for request in &transcript.requests {
        if let Some(framing) = chunk_framing(request.body.as_ref()) {
            commit_builder.commit_sent(&framing)?;
        }
    }
    for response in &transcript.responses {
        if let Some(framing) = chunk_framing(response.body.as_ref()) {
            commit_builder.commit_recv(&framing)?;
        }
    }
    let transcript_commit = commit_builder.build()?;

    let mut request_builder = RequestConfig::builder();
    request_builder.transcript_commit(transcript_commit);
    let request_config = request_builder.build()?;

    let mut prove_builder = ProveConfig::builder(prover.transcript());
    if let Some(config) = request_config.transcript_commit() {
        prove_builder.transcript_commit(config.clone());
    }
    let disclosure_config = prove_builder.build()?;

    let ProverOutput {
        transcript_commitments,
        transcript_secrets,
        ..
    } = prover.prove(&disclosure_config).await?;

    let prover_transcript = prover.transcript().clone();
    let tls_transcript = prover.tls_transcript().clone();
    prover.close().await?;

    // --- attestation request → notary -------------------------------------------------
    let provider = CryptoProvider::default();
    let mut att_builder = AttestationRequest::builder(&request_config);
    att_builder
        .server_name(ServerName::Dns(dns))
        .handshake_data(HandshakeData {
            certs: tls_transcript
                .server_cert_chain()
                .context("server certificate chain missing")?
                .to_vec(),
            sig: tls_transcript
                .server_signature()
                .context("server signature missing")?
                .clone(),
            binding: tls_transcript.certificate_binding().clone(),
        })
        .transcript(prover_transcript)
        .transcript_commitments(transcript_secrets, transcript_commitments);
    let (att_request, secrets) = att_builder.build(&provider)?;

    expected_close.store(true, Ordering::Release);
    handle.close();
    let mut socket = drivers
        .join_next()
        .await
        .context("driver task missing")???;
    socket.write_all(&bincode::serialize(&att_request)?).await?;
    socket.close().await?;
    let mut attestation_bytes = Vec::new();
    (&mut socket)
        .take((8 << 20) + 1)
        .read_to_end(&mut attestation_bytes)
        .await?;
    if attestation_bytes.len() > 8 << 20 {
        bail!("notary attestation exceeds size limit");
    }
    if attestation_bytes.is_empty() {
        bail!("notary closed the connection without issuing an attestation");
    }
    let attestation: Attestation =
        bincode::deserialize(&attestation_bytes).context("malformed attestation from notary")?;
    att_request
        .validate(&attestation, &provider)
        .map_err(|e| anyhow!("attestation inconsistent with request: {e}"))?;

    // --- presentation with redactions -----------------------------------------------------
    let http = HttpTranscript::parse(secrets.transcript())
        .map_err(|e| anyhow!("cannot parse committed transcript: {e}"))?;
    let mut proof_builder = secrets.transcript_proof_builder();

    for (i, request) in http.requests.iter().enumerate() {
        let secret_headers: Vec<String> = spec
            .requests
            .get(i)
            .map(|r| {
                r.secret_headers
                    .iter()
                    .map(|h| h.to_ascii_lowercase())
                    .collect()
            })
            .unwrap_or_default();
        proof_builder.reveal_sent(request.without_data())?;
        proof_builder.reveal_sent(&request.request.target)?;
        for header in &request.headers {
            if secret_headers.contains(&header.name.as_str().to_ascii_lowercase()) {
                proof_builder.reveal_sent(header.without_value())?;
            } else {
                proof_builder.reveal_sent(header)?;
            }
        }
        if let Some(body) = &request.body {
            proof_builder.reveal_sent(body.indices().clone())?;
        }
    }

    let secret_response_headers: Vec<String> = spec
        .secret_response_headers
        .iter()
        .map(|h| h.to_ascii_lowercase())
        .collect();
    for (i, response) in http.responses.iter().enumerate() {
        proof_builder.reveal_recv(response.without_data())?;
        for header in &response.headers {
            if secret_response_headers.contains(&header.name.as_str().to_ascii_lowercase()) {
                proof_builder.reveal_recv(header.without_value())?;
            } else {
                proof_builder.reveal_recv(header)?;
            }
        }
        if let Some(body) = &response.body {
            let mut reveal: RangeSet<usize> = body.indices().clone();
            // Redactions target the provider's JSON shape. An error response (4xx/5xx) is not that
            // shape and is rejected by the verifier's `upstream_status` wall on the status line alone,
            // so it is revealed as-is; a 200 that is not JSON still fails here.
            let is_error = response
                .status
                .code
                .as_str()
                .parse::<u16>()
                .map(|s| s != 200)
                .unwrap_or(false);
            for redaction in spec
                .redactions
                .iter()
                .filter(|r| r.response == i && !is_error)
            {
                let BodyContent::Json(doc) = &body.content else {
                    bail!("redaction requested for response {i} but body is not JSON");
                };
                for path in &redaction.json_paths {
                    match doc.get(path) {
                        Some(value) => {
                            let hide = RangeSet::from_range_iter(value.clone());
                            reveal = reveal.difference(&hide).into_set();
                        }
                        None => warn!(response = i, path, "redaction path not present"),
                    }
                }
            }
            proof_builder.reveal_recv(reveal)?;
        }
    }
    let transcript_proof = proof_builder.build()?;

    let mut presentation_builder = attestation.presentation_builder(&provider);
    presentation_builder
        .identity_proof(secrets.identity_proof())
        .transcript_proof(transcript_proof);
    let presentation: Presentation = presentation_builder.build()?;

    Ok(ProveOutput {
        presentation: bincode::serialize(&presentation)?,
        notary_key: hex::encode(&presentation.verifying_key().data),
        time: tls_transcript.time(),
        responses: previews,
    })
}

/// Bytes of a chunked body that are framing rather than content. `None` for non-chunked bodies.
fn chunk_framing(body: Option<&Body>) -> Option<RangeSet<usize>> {
    let body = body?;
    let chunks = body.chunks.as_ref()?;
    let mut content: RangeSet<usize> = RangeSet::default();
    for chunk in chunks {
        content.union_mut(chunk.indices());
    }
    let framing = body.indices().difference(&content).into_set();
    if framing.is_empty() {
        None
    } else {
        Some(framing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    fn spec() -> ProofSpec {
        serde_json::from_value(serde_json::json!({
            "server_name": "localhost", "port": 9,
            "requests": [{"path":"/usage"}], "max_sent_data":256, "max_recv_data":256,
        }))
        .unwrap()
    }

    async fn admitted<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(socket: &mut S) {
        let mut preface = [0; 36];
        socket.read_exact(&mut preface).await.unwrap();
        assert_eq!(&preface[..4], crate::admission::PREFACE);
        socket.write_all(&[0]).await.unwrap();
        socket.flush().await.unwrap();
        let mut first = [0; 1];
        socket.read_exact(&mut first).await.unwrap();
    }

    /// A fake notary on either transport; returns the address the prover dials.
    async fn fake_notary(websocket: bool) -> (TcpListener, String) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let dial = if websocket {
            format!("ws://{addr}/notary")
        } else {
            addr.to_string()
        };
        (listener, dial)
    }
    async fn accept(listener: &TcpListener, websocket: bool) -> Box<dyn Transport> {
        let (socket, _) = listener.accept().await.unwrap();
        if !websocket {
            return Box::new(socket);
        }
        let ws = tokio_tungstenite::accept_async(socket).await.unwrap();
        Box::new(crate::ws::WsIo::new(ws, None))
    }

    #[tokio::test]
    async fn closed_notary_returns_promptly_and_next_attempt_can_run() {
        for websocket in [false, true] {
            let (listener, addr) = fake_notary(websocket).await;
            let peer = tokio::spawn(async move {
                for _ in 0..5 {
                    let mut socket = accept(&listener, websocket).await;
                    admitted(&mut socket).await;
                    // Closing while MPC awaits progress must wake the foreground proof future.
                    socket.shutdown().await.unwrap();
                }
            });
            for _ in 0..5 {
                let result = tokio::time::timeout(
                    Duration::from_secs(2),
                    prove_bounded(&spec(), &addr, Some([7; 32]), PROOF_TIMEOUT),
                )
                .await
                .expect("disconnect must not wait for the proof deadline");
                let error = result.unwrap_err();
                assert!(error.downcast_ref::<ProofTimedOut>().is_none());
            }
            peer.await.unwrap();
        }
    }

    #[tokio::test]
    async fn stalled_mpc_times_out_closes_each_socket_and_allows_next_attempt() {
        for websocket in [false, true] {
            let (listener, addr) = fake_notary(websocket).await;
            let peer = tokio::spawn(async move {
                for _ in 0..5 {
                    let mut socket = accept(&listener, websocket).await;
                    admitted(&mut socket).await;
                    let mut remaining = Vec::new();
                    let read = tokio::time::timeout(
                        Duration::from_secs(2),
                        socket.read_to_end(&mut remaining),
                    )
                    .await
                    .expect("timeout must cancel the mux driver and release the socket");
                    // A dropped WebSocket ends without a Close frame, which reads as a reset.
                    if !websocket {
                        read.unwrap();
                    }
                }
            });
            for _ in 0..5 {
                let error = prove_bounded(&spec(), &addr, Some([7; 32]), Duration::from_millis(50))
                    .await
                    .unwrap_err();
                assert!(error.downcast_ref::<ProofTimedOut>().is_some(), "{error:#}");
            }
            peer.await.unwrap();
        }
    }

    #[tokio::test]
    async fn websocket_notary_requires_a_ticket_and_maps_refusal_to_busy() {
        let error = prove_bounded(&spec(), "ws://127.0.0.1:9/notary", None, PROOF_TIMEOUT)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("admission ticket"), "{error:#}");

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = format!("ws://{}/notary", listener.local_addr().unwrap());
        let peer = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            let refused = crate::ws::accept(socket, peer.ip(), None, |_| None).await;
            assert!(refused.is_err());
        });
        let error = prove_bounded(&spec(), &addr, Some([7; 32]), PROOF_TIMEOUT)
            .await
            .unwrap_err();
        assert!(error.downcast_ref::<NotaryBusy>().is_some(), "{error:#}");
        peer.await.unwrap();
    }

    #[test]
    fn timed_out_desktop_style_runtime_shuts_down_and_sync_thread_exits() {
        for _ in 0..3 {
            let (done, result) = std::sync::mpsc::channel();
            let thread = std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
                    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let addr = listener.local_addr().unwrap().to_string();
                    let peer = tokio::spawn(async move {
                        let (mut socket, _) = listener.accept().await.unwrap();
                        admitted(&mut socket).await;
                        socket.read_to_end(&mut Vec::new()).await.unwrap();
                    });
                    assert!(
                        prove_bounded(&spec(), &addr, Some([7; 32]), Duration::from_millis(50))
                            .await
                            .unwrap_err()
                            .downcast_ref::<ProofTimedOut>()
                            .is_some()
                    );
                    peer.await.unwrap();
                });
                drop(runtime);
                done.send(()).unwrap();
            });
            result.recv_timeout(Duration::from_secs(3)).expect(
                "sync runtime and dedicated thread must terminate after proof cancellation",
            );
            thread.join().unwrap();
        }
    }

    #[tokio::test]
    async fn deadline_also_covers_a_peer_stalled_before_admission_acknowledgement() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let peer = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            socket.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes.len(), 36);
        });
        let error = prove_bounded(&spec(), &addr, Some([7; 32]), Duration::from_millis(50))
            .await
            .unwrap_err();
        assert!(error.downcast_ref::<ProofTimedOut>().is_some());
        tokio::time::timeout(Duration::from_secs(2), peer)
            .await
            .unwrap()
            .unwrap();
    }
}
