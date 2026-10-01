//! Notary: co-signs MPC-TLS sessions and issues attestations. Runs on our infrastructure.
//!
//! The notary never learns plaintext. It enforces size limits (DoS protection), verifies the
//! server certificate chain against Mozilla roots during the session, and signs the resulting
//! commitments with our secp256k1 key.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use crate::admission::{Admission, AdmissionTicket, PREFACE, PeerPermit, StartBudget};

use anyhow::{Context, Result, bail};
use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::Instant,
};
use tokio_tungstenite::tungstenite::http::HeaderName;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{info, warn};

use tlsn::{
    Session,
    attestation::{
        Attestation, AttestationConfig, CryptoProvider, request::Request as AttestationRequest,
        signing::Secp256k1Signer,
    },
    config::verifier::VerifierConfig,
    connection::{CertBinding, ConnectionInfo, TranscriptLength},
    transcript::ContentType,
    verifier::{VerifierCommitStart, VerifierOutput},
    webpki::RootCertStore,
};

/// Per-session resource limits.
#[derive(Debug, Clone, Copy)]
pub struct NotaryLimits {
    /// Maximum bytes a prover may send to the TLS server.
    pub max_sent_data: usize,
    /// Maximum bytes a prover may receive from the TLS server.
    pub max_recv_data: usize,
    /// Wall-clock budget for one session.
    pub session_timeout: Duration,
    /// Maximum size of the attestation request message.
    pub max_request_bytes: usize,
    /// Expensive MPC sessions allowed at once.
    pub max_sessions: usize,
    /// Cheap ticket handshakes allowed at once.
    pub max_handshakes: usize,
    /// Combined live connections per source IP (no forwarding headers trusted).
    pub max_connections_per_ip: usize,
    /// Ticket preface deadline, before any MPC resources are allocated.
    pub admission_timeout: Duration,
    /// Deadline for the TLSN configuration exchange.
    pub setup_timeout: Duration,
    /// Explicit local development mode; never allowed on a public bind address.
    pub allow_unauthenticated: bool,
}

impl Default for NotaryLimits {
    fn default() -> Self {
        Self {
            max_sent_data: 1 << 14,
            max_recv_data: 1 << 16,
            session_timeout: Duration::from_secs(240),
            max_request_bytes: 8 << 20,
            max_sessions: 2,
            max_handshakes: 32,
            max_connections_per_ip: 4,
            admission_timeout: Duration::from_secs(5),
            setup_timeout: Duration::from_secs(15),
            allow_unauthenticated: false,
        }
    }
}

/// A notary bound to one signing key.
#[derive(Clone)]
pub struct Notary {
    key: Arc<[u8; 32]>,
    limits: NotaryLimits,
    admission: Admission,
}

impl Notary {
    /// Creates a notary.
    pub fn new(key: [u8; 32], limits: NotaryLimits) -> Self {
        Self {
            key: Arc::new(key),
            limits,
            admission: Admission::default(),
        }
    }

    /// Hex of the verifying key clients and verifiers must trust.
    pub fn verifying_key_hex(&self) -> Result<String> {
        crate::keys::verifying_key_hex(self.key.as_slice())
    }

    pub fn issue_admission(&self, subject: String) -> Result<AdmissionTicket> {
        self.admission.issue(subject)
    }

    /// Reject overload before spawning; unauthenticated sockets never enter MPC.
    pub async fn serve(&self, listener: TcpListener) -> Result<()> {
        self.serve_with_websocket(listener, None).await
    }

    /// Serves raw TCP and, optionally, WebSocket provers. Both share one start budget, handshake
    /// and session capacity, per-IP accounting and admission. WebSocket peers always need a ticket.
    pub async fn serve_with_websocket(
        &self,
        listener: TcpListener,
        websocket: Option<WsListener>,
    ) -> Result<()> {
        let addr = listener.local_addr()?;
        if self.limits.allow_unauthenticated && !addr.ip().is_loopback() {
            bail!("unauthenticated development mode requires a loopback bind");
        }
        if self.limits.max_sessions == 0
            || self.limits.max_handshakes == 0
            || self.limits.max_connections_per_ip == 0
            || self.limits.admission_timeout.is_zero()
            || self.limits.session_timeout.is_zero()
            || self.limits.setup_timeout.is_zero()
        {
            bail!("notary limits must be positive");
        }
        info!(%addr, max_sessions = self.limits.max_sessions, "notary listening");
        if let Some(ws) = &websocket {
            info!(addr = %ws.listener.local_addr()?, path = crate::ws::PATH, "notary WebSocket listening");
        }
        let sessions = Arc::new(Semaphore::new(self.limits.max_sessions));
        let handshakes = Arc::new(Semaphore::new(self.limits.max_handshakes));
        let mut tasks = JoinSet::new();
        let mut starts = StartBudget::new();
        loop {
            // Prefer cleanup under an accept flood; JoinSet owns cancellation on shutdown.
            let (socket, peer, is_websocket) = tokio::select! {
                biased;
                result = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Err(error)) = result { warn!(%error, "notary task failed"); }
                    continue;
                }
                accepted = listener.accept() => {
                    let (socket, peer) = accepted?;
                    (socket, peer, false)
                }
                accepted = async {
                    match &websocket {
                        Some(ws) => ws.listener.accept().await,
                        None => std::future::pending().await,
                    }
                } => {
                    let (socket, peer) = accepted?;
                    (socket, peer, true)
                }
            };
            if !starts.take(std::time::Instant::now()) {
                continue;
            }
            let Ok(handshake) = handshakes.clone().try_acquire_owned() else {
                continue;
            };
            let notary = self.clone();
            let sessions = sessions.clone();
            let max_per_ip = self.limits.max_connections_per_ip;
            if !is_websocket {
                let Some(peer_permit) = self.admission.peer(peer.ip(), max_per_ip) else {
                    continue;
                };
                if socket.set_nodelay(true).is_err() {
                    continue;
                }
                tasks.spawn(async move {
                    let deadline = Instant::now() + notary.limits.admission_timeout;
                    let authenticate = !notary.limits.allow_unauthenticated;
                    let admitted = Admitted {
                        peer,
                        handshake,
                        _peer: peer_permit,
                    };
                    notary
                        .admit(socket, authenticate, deadline, admitted, sessions)
                        .await;
                });
            } else {
                if socket.set_nodelay(true).is_err() {
                    continue;
                }
                let header = websocket
                    .as_ref()
                    .and_then(|ws| ws.client_ip_header.clone());
                tasks.spawn(async move {
                    let deadline = Instant::now() + notary.limits.admission_timeout;
                    let upgrade = crate::ws::accept(socket, peer.ip(), header.as_ref(), |ip| {
                        notary.admission.peer(ip, max_per_ip)
                    });
                    let Ok(Ok((socket, ip, peer_permit))) =
                        tokio::time::timeout_at(deadline, upgrade).await
                    else {
                        return;
                    };
                    let admitted = Admitted {
                        peer: SocketAddr::new(ip, peer.port()),
                        handshake,
                        _peer: peer_permit,
                    };
                    notary
                        .admit(socket, true, deadline, admitted, sessions)
                        .await;
                });
            }
        }
    }

    /// Ticket check, session capacity, status byte, then the session under its deadline.
    async fn admit<S>(
        &self,
        mut socket: S,
        authenticate: bool,
        deadline: Instant,
        admitted: Admitted,
        sessions: Arc<Semaphore>,
    ) where
        S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
    {
        let admission = if authenticate {
            match tokio::time::timeout_at(deadline, self.authorize(&mut socket)).await {
                Ok(Ok(permit)) => Some(permit),
                _ => return,
            }
        } else {
            None
        };
        let Ok(session_permit) = sessions.try_acquire_owned() else {
            let _ = write_status(&mut socket, 1).await;
            return;
        };
        if authenticate && write_status(&mut socket, 0).await.is_err() {
            return;
        }
        let Admitted {
            peer,
            handshake,
            _peer,
        } = admitted;
        drop(handshake);
        let _admission = admission;
        let _session = session_permit;
        let started = std::time::Instant::now();
        match tokio::time::timeout(self.limits.session_timeout, self.handle(socket)).await {
            Ok(Ok(())) => info!(%peer, elapsed = ?started.elapsed(), "attestation issued"),
            Ok(Err(e)) => warn!(%peer, error = %e, "session failed"),
            Err(_) => warn!(%peer, "session timed out"),
        }
    }

    async fn authorize<S: AsyncRead + Unpin>(
        &self,
        socket: &mut S,
    ) -> Result<crate::admission::SubjectPermit> {
        let mut preface = [0; 36];
        tokio::io::AsyncReadExt::read_exact(socket, &mut preface).await?;
        if &preface[..4] != PREFACE {
            bail!("unsupported admission protocol");
        }
        let token = preface[4..].try_into().expect("fixed ticket length");
        self.admission.consume(token)
    }

    /// Runs one full notarisation over an established prover channel.
    pub async fn handle<S>(&self, socket: S) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
    {
        let session = Session::with_config(socket.compat(), crate::session_config());
        let (driver, mut handle) = session.split();
        let mut drivers = JoinSet::new();
        drivers.spawn(driver);

        let verifier_config = VerifierConfig::builder()
            .root_store(RootCertStore::mozilla())
            .build()?;

        let commitment = tokio::time::timeout(
            self.limits.setup_timeout,
            handle.new_verifier(verifier_config)?.commit(),
        )
        .await
        .context("notary setup timed out")??;
        let verifier = match commitment {
            VerifierCommitStart::Mpc(verifier) => {
                let (sent, recv) = {
                    let cfg = verifier.config();
                    (cfg.max_sent_data(), cfg.max_recv_data())
                };
                if sent > self.limits.max_sent_data || recv > self.limits.max_recv_data {
                    verifier
                        .reject(Some("session size limits exceeded"))
                        .await?;
                    bail!("rejected session: sent={sent} recv={recv} exceed notary limits");
                }
                verifier.accept().await?.run().await?
            }
            VerifierCommitStart::Proxy(verifier) => {
                verifier.reject(Some("MPC-TLS required")).await?;
                bail!("rejected proxy-mode session");
            }
        };

        let (
            VerifierOutput {
                transcript_commitments,
                ..
            },
            verifier,
        ) = verifier.verify().await?.accept().await?;

        let tls_transcript = verifier.tls_transcript().clone();
        verifier.close().await?;

        let app_data_len = |records: &[tlsn::transcript::Record]| -> usize {
            records
                .iter()
                .filter(|r| matches!(r.typ, ContentType::ApplicationData))
                .map(|r| r.ciphertext.len())
                .sum()
        };
        let sent_len = app_data_len(tls_transcript.sent());
        let recv_len = app_data_len(tls_transcript.recv());

        handle.close();
        let mut socket = drivers
            .join_next()
            .await
            .context("session driver missing")???;

        let mut request_bytes = Vec::new();
        (&mut socket)
            .take(self.limits.max_request_bytes as u64 + 1)
            .read_to_end(&mut request_bytes)
            .await?;
        if request_bytes.len() > self.limits.max_request_bytes {
            bail!("attestation request too large");
        }
        let request: AttestationRequest =
            bincode::deserialize(&request_bytes).context("malformed attestation request")?;

        let signer = Box::new(Secp256k1Signer::new(self.key.as_slice())?);
        let mut provider = CryptoProvider::default();
        provider.signer.set_signer(signer);

        let mut att_config_builder = AttestationConfig::builder();
        att_config_builder
            .supported_signature_algs(Vec::from_iter(provider.signer.supported_algs()));
        let att_config = att_config_builder.build()?;

        let CertBinding::V1_2(binding) = tls_transcript.certificate_binding() else {
            bail!("unsupported certificate binding version");
        };
        let mut builder = Attestation::builder(&att_config).accept_request(request)?;
        builder
            .connection_info(ConnectionInfo {
                time: tls_transcript.time(),
                version: tls_transcript.version(),
                transcript_length: TranscriptLength {
                    sent: sent_len as u32,
                    received: recv_len as u32,
                },
            })
            .server_ephemeral_key(binding.server_ephemeral_key.clone())
            .transcript_commitments(transcript_commitments);
        let attestation = builder.build(&provider)?;

        socket.write_all(&bincode::serialize(&attestation)?).await?;
        socket.close().await?;
        Ok(())
    }
}

/// A WebSocket listener for prover sessions, e.g. behind Cloudflare Tunnel.
pub struct WsListener {
    pub listener: TcpListener,
    /// Header holding the client IP for per-IP limits, e.g. `cf-connecting-ip`. Safe only when
    /// this port is reachable exclusively through a proxy that overwrites the header.
    pub client_ip_header: Option<HeaderName>,
}

impl WsListener {
    pub fn new(listener: TcpListener, client_ip_header: Option<&str>) -> Result<Self> {
        let client_ip_header = client_ip_header
            .map(|name| name.parse::<HeaderName>())
            .transpose()
            .context("invalid client IP header name")?;
        Ok(Self {
            listener,
            client_ip_header,
        })
    }
}

/// Capacity held from accept until the session starts (handshake) or ends (per-IP).
struct Admitted {
    peer: SocketAddr,
    handshake: OwnedSemaphorePermit,
    _peer: PeerPermit,
}

async fn write_status<S: AsyncWrite + Unpin>(socket: &mut S, status: u8) -> std::io::Result<()> {
    tokio::io::AsyncWriteExt::write_all(socket, &[status]).await?;
    tokio::io::AsyncWriteExt::flush(socket).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    async fn server(
        limits: NotaryLimits,
    ) -> (
        Notary,
        std::net::SocketAddr,
        tokio::task::JoinHandle<Result<()>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let notary = Notary::new(crate::keys::generate_signing_key(), limits);
        let service = notary.clone();
        let task = tokio::spawn(async move { service.serve(listener).await });
        (notary, addr, task)
    }
    async fn authenticate(addr: std::net::SocketAddr, ticket: &AdmissionTicket) -> (TcpStream, u8) {
        let mut socket = TcpStream::connect(addr).await.unwrap();
        socket.write_all(PREFACE).await.unwrap();
        socket
            .write_all(&hex::decode(&ticket.ticket).unwrap())
            .await
            .unwrap();
        let status = tokio::time::timeout(Duration::from_secs(2), socket.read_u8())
            .await
            .unwrap()
            .unwrap();
        (socket, status)
    }
    async fn assert_closed(socket: &mut TcpStream) {
        let mut buffer = [0; 1024];
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match socket.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        })
        .await
        .expect("socket and session driver must close");
    }

    #[tokio::test]
    async fn silent_and_invalid_clients_never_consume_subject_or_session_capacity() {
        let (notary, addr, task) = server(NotaryLimits {
            admission_timeout: Duration::from_millis(30),
            ..Default::default()
        })
        .await;
        let mut silent = TcpStream::connect(addr).await.unwrap();
        assert_closed(&mut silent).await;
        let mut invalid = TcpStream::connect(addr).await.unwrap();
        invalid.write_all(&[0; 36]).await.unwrap();
        assert_closed(&mut invalid).await;
        let ticket = notary.issue_admission("alice".into()).unwrap();
        let (_, status) = authenticate(addr, &ticket).await;
        assert_eq!(status, 0);
        task.abort();
    }

    #[tokio::test]
    async fn expensive_session_limit_is_separate_and_setup_timeout_releases_everything() {
        let (notary, addr, task) = server(NotaryLimits {
            max_sessions: 1,
            setup_timeout: Duration::from_millis(200),
            ..Default::default()
        })
        .await;
        let first = notary.issue_admission("alice".into()).unwrap();
        let (mut alice, status) = authenticate(addr, &first).await;
        assert_eq!(status, 0);
        assert!(notary.issue_admission("alice".into()).is_err());
        let second = notary.issue_admission("bob".into()).unwrap();
        let (_, status) = authenticate(addr, &second).await;
        assert_eq!(status, 1, "capacity rejected before MPC setup");
        assert_closed(&mut alice).await;
        let renewed = notary.issue_admission("alice".into()).unwrap();
        let (mut socket, status) = authenticate(addr, &renewed).await;
        assert_eq!(status, 0, "timeout released global and subject permits");
        task.abort();
        let _ = task.await;
        assert_closed(&mut socket).await;
    }

    #[tokio::test]
    async fn session_deadline_cancels_driver_even_before_setup_deadline() {
        let (notary, addr, task) = server(NotaryLimits {
            session_timeout: Duration::from_millis(30),
            setup_timeout: Duration::from_secs(30),
            ..Default::default()
        })
        .await;
        let ticket = notary.issue_admission("alice".into()).unwrap();
        let (mut socket, status) = authenticate(addr, &ticket).await;
        assert_eq!(status, 0);
        assert_closed(&mut socket).await;
        assert!(notary.issue_admission("alice".into()).is_ok());
        task.abort();
    }

    #[tokio::test]
    async fn rejected_preface_does_not_consume_a_valid_ticket() {
        let (notary, addr, task) = server(Default::default()).await;
        let ticket = notary.issue_admission("alice".into()).unwrap();
        let mut socket = TcpStream::connect(addr).await.unwrap();
        socket.write_all(b"BAD1").await.unwrap();
        socket
            .write_all(&hex::decode(&ticket.ticket).unwrap())
            .await
            .unwrap();
        assert_closed(&mut socket).await;
        let (_, status) = authenticate(addr, &ticket).await;
        assert_eq!(status, 0);
        task.abort();
    }

    #[tokio::test]
    async fn handshake_and_per_ip_limits_reject_without_wait_queues() {
        for limits in [
            NotaryLimits {
                max_handshakes: 1,
                admission_timeout: Duration::from_secs(5),
                ..Default::default()
            },
            NotaryLimits {
                max_connections_per_ip: 1,
                admission_timeout: Duration::from_secs(5),
                ..Default::default()
            },
        ] {
            let (_, addr, task) = server(limits).await;
            let mut first = TcpStream::connect(addr).await.unwrap();
            // A silent admitted socket stays open while a second socket is rejected immediately.
            assert!(
                tokio::time::timeout(Duration::from_millis(30), first.read_u8())
                    .await
                    .is_err()
            );
            let mut second = TcpStream::connect(addr).await.unwrap();
            assert_closed(&mut second).await;
            assert!(
                tokio::time::timeout(Duration::from_millis(30), first.read_u8())
                    .await
                    .is_err()
            );
            task.abort();
            let _ = task.await;
            assert_closed(&mut first).await;
        }
    }

    #[tokio::test]
    async fn zero_limits_fail_closed() {
        let (_, _, task) = server(NotaryLimits {
            max_sessions: 0,
            ..Default::default()
        })
        .await;
        assert!(task.await.unwrap().is_err());
    }

    async fn ws_server(
        limits: NotaryLimits,
        client_ip_header: Option<&str>,
    ) -> (
        Notary,
        std::net::SocketAddr,
        std::net::SocketAddr,
        tokio::task::JoinHandle<Result<()>>,
    ) {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ws = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (tcp_addr, ws_addr) = (tcp.local_addr().unwrap(), ws.local_addr().unwrap());
        let ws = WsListener::new(ws, client_ip_header).unwrap();
        let notary = Notary::new(crate::keys::generate_signing_key(), limits);
        let service = notary.clone();
        let task = tokio::spawn(async move { service.serve_with_websocket(tcp, Some(ws)).await });
        (notary, tcp_addr, ws_addr, task)
    }
    type WsClient = crate::ws::WsIo<TcpStream>;
    async fn ws_connect(
        addr: std::net::SocketAddr,
        path: &str,
        client_ip: Option<&str>,
    ) -> std::result::Result<WsClient, tokio_tungstenite::tungstenite::Error> {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let mut request = format!("ws://{addr}{path}").into_client_request().unwrap();
        if let Some(ip) = client_ip {
            request
                .headers_mut()
                .insert("cf-connecting-ip", ip.parse().unwrap());
        }
        let socket = TcpStream::connect(addr).await.unwrap();
        let (ws, _) = tokio_tungstenite::client_async(request, socket).await?;
        Ok(crate::ws::WsIo::new(ws, None))
    }
    fn refused_with(
        result: std::result::Result<WsClient, tokio_tungstenite::tungstenite::Error>,
    ) -> u16 {
        match result {
            Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
                response.status().as_u16()
            }
            Err(error) => panic!("expected an HTTP refusal, got {error}"),
            Ok(_) => panic!("expected an HTTP refusal, got an upgrade"),
        }
    }
    async fn ws_authenticate(socket: &mut WsClient, preface: &[u8], ticket: &[u8]) -> Option<u8> {
        socket.write_all(preface).await.unwrap();
        socket.write_all(ticket).await.unwrap();
        socket.flush().await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), socket.read_u8())
            .await
            .unwrap()
            .ok()
    }
    fn ticket_bytes(ticket: &AdmissionTicket) -> Vec<u8> {
        hex::decode(&ticket.ticket).unwrap()
    }

    #[tokio::test]
    async fn websocket_ticket_is_admitted_and_invalid_tickets_do_not_consume_it() {
        let (notary, tcp_addr, ws_addr, task) = ws_server(Default::default(), None).await;
        let ticket = notary.issue_admission("alice".into()).unwrap();
        let mut bad_preface = ws_connect(ws_addr, "/notary", None).await.unwrap();
        assert_eq!(
            ws_authenticate(&mut bad_preface, b"BAD1", &ticket_bytes(&ticket)).await,
            None
        );
        let mut bad_ticket = ws_connect(ws_addr, "/notary", None).await.unwrap();
        assert_eq!(
            ws_authenticate(&mut bad_ticket, PREFACE, &[0; 32]).await,
            None
        );
        let mut admitted = ws_connect(ws_addr, "/notary", None).await.unwrap();
        assert_eq!(
            ws_authenticate(&mut admitted, PREFACE, &ticket_bytes(&ticket)).await,
            Some(0)
        );
        // The raw TCP listener keeps working next to it, with the same admission state.
        assert!(notary.issue_admission("alice".into()).is_err());
        let bob = notary.issue_admission("bob".into()).unwrap();
        let (_, status) = authenticate(tcp_addr, &bob).await;
        assert_eq!(status, 0);
        task.abort();
    }

    #[tokio::test]
    async fn websocket_only_upgrades_the_notary_path() {
        let (_, _, ws_addr, task) = ws_server(Default::default(), None).await;
        for path in ["/", "/notary/", "/other", "/notaryx"] {
            assert_eq!(
                refused_with(ws_connect(ws_addr, path, None).await),
                404,
                "{path}"
            );
        }
        let error = crate::ws::connect(&format!("ws://{ws_addr}/other"))
            .await
            .err()
            .unwrap();
        assert_eq!(
            error.downcast_ref::<crate::ws::UpgradeRefused>().unwrap().0,
            404
        );
        assert!(ws_connect(ws_addr, "/notary?v=1", None).await.is_ok());
        task.abort();
    }

    #[tokio::test]
    async fn websocket_per_ip_limit_counts_the_trusted_header_address() {
        let limits = NotaryLimits {
            max_connections_per_ip: 1,
            ..Default::default()
        };
        let (notary, _, ws_addr, task) = ws_server(limits, Some("cf-connecting-ip")).await;
        let _first = ws_connect(ws_addr, "/notary", Some("203.0.113.1"))
            .await
            .unwrap();
        assert_eq!(
            refused_with(ws_connect(ws_addr, "/notary", Some("203.0.113.1")).await),
            429
        );
        let ticket = notary.issue_admission("bob".into()).unwrap();
        let mut other = ws_connect(ws_addr, "/notary", Some("203.0.113.2"))
            .await
            .unwrap();
        assert_eq!(
            ws_authenticate(&mut other, PREFACE, &ticket_bytes(&ticket)).await,
            Some(0)
        );
        // Missing or unparseable header: the socket peer (loopback) is counted instead.
        let _peer = ws_connect(ws_addr, "/notary", Some("not-an-ip"))
            .await
            .unwrap();
        assert_eq!(
            refused_with(ws_connect(ws_addr, "/notary", None).await),
            429
        );
        task.abort();
    }

    #[tokio::test]
    async fn websocket_ignores_client_ip_header_unless_configured_and_shares_tcp_accounting() {
        let limits = NotaryLimits {
            max_connections_per_ip: 1,
            ..Default::default()
        };
        let (_, tcp_addr, ws_addr, task) = ws_server(limits, None).await;
        let mut tcp = TcpStream::connect(tcp_addr).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(30), tcp.read_u8())
                .await
                .is_err()
        );
        assert_eq!(
            refused_with(ws_connect(ws_addr, "/notary", Some("203.0.113.9")).await),
            429
        );
        drop(tcp);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            ws_connect(ws_addr, "/notary", Some("203.0.113.9"))
                .await
                .is_ok()
        );
        task.abort();
    }

    #[tokio::test]
    async fn websocket_always_requires_a_ticket_and_shares_handshake_capacity() {
        let (notary, _, ws_addr, task) = ws_server(
            NotaryLimits {
                allow_unauthenticated: true,
                max_handshakes: 1,
                admission_timeout: Duration::from_millis(300),
                ..Default::default()
            },
            None,
        )
        .await;
        let mut silent = ws_connect(ws_addr, "/notary", None).await.unwrap();
        // The one handshake slot is held, so a second upgrade is dropped without a response.
        assert!(ws_connect(ws_addr, "/notary", None).await.is_err());
        let mut rest = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), silent.read_to_end(&mut rest))
            .await
            .expect("silent WebSocket client must be closed at the admission deadline")
            .ok();
        assert!(rest.is_empty());
        let ticket = notary.issue_admission("alice".into()).unwrap();
        let mut admitted = ws_connect(ws_addr, "/notary", None).await.unwrap();
        assert_eq!(
            ws_authenticate(&mut admitted, PREFACE, &ticket_bytes(&ticket)).await,
            Some(0),
            "status byte proves the ticket path ran despite allow_unauthenticated"
        );
        task.abort();
    }
}
