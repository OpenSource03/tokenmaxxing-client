//! WebSocket transport for the prover ↔ notary channel, for proxies that carry only HTTP.
//!
//! Each side writes binary messages of at most [`MAX_MESSAGE`] bytes. An empty binary message
//! half-closes the sender's direction (WebSocket has no half-close, the attestation exchange
//! needs one); a Close frame or a dropped connection ends the read side.

use std::{
    io,
    net::IpAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
    time::Duration,
};

use anyhow::{Context as _, Result, bail};
use futures::{Sink, Stream};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    time::{Interval, MissedTickBehavior},
};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::{
    WebSocketStream, accept_hdr_async_with_config, client_async_with_config,
    tungstenite::{
        Bytes, Error as WsError, Message,
        handshake::server::{ErrorResponse, Request, Response},
        http::{HeaderName, StatusCode},
        protocol::WebSocketConfig,
    },
};

use crate::admission::PeerPermit;

/// The only path the notary upgrades.
pub const PATH: &str = "/notary";
/// Largest message either side writes or accepts.
pub const MAX_MESSAGE: usize = 64 * 1024;
/// Client pings keep idle stretches under proxy idle timeouts (Cloudflare: ~100 s).
const PING_INTERVAL: Duration = Duration::from_secs(20);

/// True when a notary address selects the WebSocket transport.
pub fn is_websocket(addr: &str) -> bool {
    addr.starts_with("ws://") || addr.starts_with("wss://")
}

fn config() -> WebSocketConfig {
    WebSocketConfig::default()
        .write_buffer_size(0)
        .max_message_size(Some(MAX_MESSAGE))
        .max_frame_size(Some(MAX_MESSAGE))
}

/// Byte stream over a WebSocket.
pub struct WsIo<S> {
    ws: WebSocketStream<S>,
    pending: Bytes,
    read_eof: bool,
    /// Our direction is half-closed; further writes fail.
    write_closed: bool,
    /// The WebSocket itself is closed (Close sent or received, or connection gone).
    closed: bool,
    unflushed: bool,
    ping: Option<Interval>,
    ping_due: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> WsIo<S> {
    pub(crate) fn new(ws: WebSocketStream<S>, ping: Option<Duration>) -> Self {
        let ping = ping.map(|period| {
            let mut interval =
                tokio::time::interval_at(tokio::time::Instant::now() + period, period);
            interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
            interval
        });
        Self {
            ws,
            pending: Bytes::new(),
            read_eof: false,
            write_closed: false,
            closed: false,
            unflushed: false,
            ping,
            ping_due: false,
        }
    }

    /// Sends due pings and finishes partial writes while the owner is only reading.
    fn drive_writes(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        if let Some(ping) = &mut self.ping {
            while ping.poll_tick(cx).is_ready() {
                self.ping_due = true;
            }
        }
        if self.ping_due
            && let Poll::Ready(ready) = Pin::new(&mut self.ws).poll_ready(cx)
        {
            ready.map_err(io_error)?;
            Pin::new(&mut self.ws)
                .start_send(Message::Ping(Bytes::new()))
                .map_err(io_error)?;
            self.ping_due = false;
            self.unflushed = true;
        }
        if self.unflushed
            && let Poll::Ready(flushed) = Pin::new(&mut self.ws).poll_flush(cx)
        {
            flushed.map_err(io_error)?;
            self.unflushed = false;
        }
        Ok(())
    }

    fn send(&mut self, cx: &mut Context<'_>, payload: Bytes) -> Poll<io::Result<()>> {
        ready!(Pin::new(&mut self.ws).poll_ready(cx)).map_err(io_error)?;
        Pin::new(&mut self.ws)
            .start_send(Message::Binary(payload))
            .map_err(io_error)?;
        self.unflushed = true;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.pending.is_empty() {
                let n = this.pending.len().min(buf.remaining());
                buf.put_slice(&this.pending.split_to(n));
                return Poll::Ready(Ok(()));
            }
            if this.read_eof || buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            this.drive_writes(cx)?;
            match ready!(Pin::new(&mut this.ws).poll_next(cx)) {
                Some(Ok(Message::Binary(data))) if data.is_empty() => this.read_eof = true,
                Some(Ok(Message::Binary(data))) => this.pending = data,
                // tungstenite queues the pong itself and flushes it on the next read or write.
                Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => {}
                Some(Ok(Message::Text(_))) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected text message",
                    )));
                }
                Some(Ok(Message::Close(_)))
                | Some(Err(WsError::ConnectionClosed | WsError::AlreadyClosed))
                | None => {
                    this.read_eof = true;
                    this.closed = true;
                }
                Some(Err(error)) => return Poll::Ready(Err(io_error(error))),
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_closed || this.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        // An empty message would read as a half-close on the other side.
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = buf.len().min(MAX_MESSAGE);
        ready!(this.send(cx, Bytes::copy_from_slice(&buf[..n])))?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(Pin::new(&mut this.ws).poll_flush(cx)).map_err(io_error)?;
        this.unflushed = false;
        Poll::Ready(Ok(()))
    }

    /// Half-closes our direction; once the peer has half-closed too, closes the WebSocket.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.closed {
            // Best effort: deliver the automatic Close reply, if any.
            let _ = ready!(Pin::new(&mut this.ws).poll_flush(cx));
            return Poll::Ready(Ok(()));
        }
        if !this.write_closed {
            ready!(this.send(cx, Bytes::new()))?;
            this.write_closed = true;
        }
        ready!(Pin::new(&mut this.ws).poll_flush(cx)).map_err(io_error)?;
        this.unflushed = false;
        if this.read_eof {
            let _ = ready!(Pin::new(&mut this.ws).poll_close(cx));
            this.closed = true;
        }
        Poll::Ready(Ok(()))
    }
}

fn io_error(error: WsError) -> io::Error {
    match error {
        WsError::Io(error) => error,
        WsError::ConnectionClosed | WsError::AlreadyClosed => io::ErrorKind::BrokenPipe.into(),
        error => io::Error::other(error),
    }
}

/// Any transport the prover can run a session over.
pub trait Transport: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> Transport for T {}

/// HTTP status a notary answered the upgrade with, when it refused it.
#[derive(Debug, thiserror::Error)]
#[error("notary refused the WebSocket upgrade with HTTP {0}")]
pub struct UpgradeRefused(pub u16);

/// Opens `ws://` or `wss://`; `wss` validates the server against the Mozilla (webpki) roots.
pub async fn connect(url: &str) -> Result<WsIo<Box<dyn Transport>>> {
    let uri: tokio_tungstenite::tungstenite::http::Uri =
        url.parse().context("invalid notary URL")?;
    let tls = match uri.scheme_str() {
        Some("wss") => true,
        Some("ws") => false,
        _ => bail!("notary URL must use ws:// or wss://"),
    };
    let host = uri.host().context("notary URL has no host")?;
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
    let tcp = TcpStream::connect((host.as_str(), port)).await?;
    tcp.set_nodelay(true)?;
    let stream: Box<dyn Transport> = if tls {
        let name =
            rustls::pki_types::ServerName::try_from(host).context("invalid notary host name")?;
        Box::new(TlsConnector::from(client_tls()?).connect(name, tcp).await?)
    } else {
        Box::new(tcp)
    };
    let (ws, _) = match client_async_with_config(url, stream, Some(config())).await {
        Ok(connected) => connected,
        Err(WsError::Http(response)) => {
            return Err(UpgradeRefused(response.status().as_u16()).into());
        }
        Err(error) => return Err(error.into()),
    };
    Ok(WsIo::new(ws, Some(PING_INTERVAL)))
}

/// Explicit ring provider: no process-wide rustls default is read or installed.
fn client_tls() -> Result<Arc<rustls::ClientConfig>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Server upgrade: only [`PATH`]; the client IP comes from `client_ip_header` when present and
/// parseable, else the socket peer. `admit` takes the per-IP permit before the upgrade succeeds.
pub(crate) async fn accept(
    socket: TcpStream,
    peer: IpAddr,
    client_ip_header: Option<&HeaderName>,
    admit: impl FnOnce(IpAddr) -> Option<PeerPermit> + Unpin,
) -> Result<(WsIo<TcpStream>, IpAddr, PeerPermit)> {
    let mut admitted = None;
    // tungstenite fixes this callback signature, including its error type.
    #[allow(clippy::result_large_err)]
    let callback = |request: &Request, response: Response| {
        if request.uri().path() != PATH {
            return Err(refusal(StatusCode::NOT_FOUND));
        }
        let ip = client_ip_header
            .and_then(|name| request.headers().get(name))
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<IpAddr>().ok())
            .unwrap_or(peer);
        let permit = admit(ip).ok_or_else(|| refusal(StatusCode::TOO_MANY_REQUESTS))?;
        admitted = Some((ip, permit));
        Ok(response)
    };
    let ws = accept_hdr_async_with_config(socket, callback, Some(config())).await?;
    let (ip, permit) = admitted.context("upgrade completed without admission")?;
    Ok((WsIo::new(ws, None), ip, permit))
}

fn refusal(status: StatusCode) -> ErrorResponse {
    let mut response = ErrorResponse::new(None);
    *response.status_mut() = status;
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{SinkExt, StreamExt};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use tokio_tungstenite::accept_async_with_config;

    async fn pair() -> (WebSocketStream<TcpStream>, WebSocketStream<TcpStream>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            accept_async_with_config(listener.accept().await.unwrap().0, Some(config()))
                .await
                .unwrap()
        });
        let socket = TcpStream::connect(addr).await.unwrap();
        let (client, _) =
            client_async_with_config(format!("ws://{addr}{PATH}"), socket, Some(config()))
                .await
                .unwrap();
        (client, server.await.unwrap())
    }

    #[tokio::test]
    async fn writes_are_bounded_binary_messages_and_shutdown_half_closes() {
        let (client, mut server) = pair().await;
        let mut client = WsIo::new(client, None);
        let payload: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
        client.write_all(&payload).await.unwrap();
        client.shutdown().await.unwrap();
        let mut received = Vec::new();
        loop {
            match server.next().await.unwrap().unwrap() {
                Message::Binary(data) if data.is_empty() => break,
                Message::Binary(data) => {
                    assert!(data.len() <= MAX_MESSAGE);
                    received.extend_from_slice(&data);
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(received, payload);
        // The half-closed client still receives the reply, then EOF.
        let mut server = WsIo::new(server, None);
        server.write_all(b"attestation").await.unwrap();
        server.shutdown().await.unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"attestation");
        assert!(client.write_all(b"late").await.is_err());
    }

    #[tokio::test]
    async fn close_frame_reads_as_eof_and_pings_are_answered() {
        let (client, mut server) = pair().await;
        let mut client = WsIo::new(client, None);
        server
            .send(Message::Ping(Bytes::from_static(b"p")))
            .await
            .unwrap();
        server
            .send(Message::Binary(Bytes::from_static(b"x")))
            .await
            .unwrap();
        let mut byte = [0; 1];
        client.read_exact(&mut byte).await.unwrap();
        assert_eq!(&byte, b"x");
        server.send(Message::Close(None)).await.unwrap();
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
        drop(client);
        let mut pong = false;
        while let Some(Ok(message)) = server.next().await {
            pong |= matches!(message, Message::Pong(ref p) if p.as_ref() == b"p");
        }
        assert!(pong, "ping must be answered");
    }

    #[tokio::test]
    async fn idle_reader_sends_keepalive_pings() {
        let (client, mut server) = pair().await;
        let mut client = WsIo::new(client, Some(Duration::from_millis(20)));
        let reader = tokio::spawn(async move {
            let mut byte = [0; 1];
            client.read_exact(&mut byte).await.map(|_| byte)
        });
        let ping = tokio::time::timeout(Duration::from_secs(2), server.next())
            .await
            .expect("idle client must ping")
            .unwrap()
            .unwrap();
        assert!(matches!(ping, Message::Ping(_)), "{ping:?}");
        server
            .send(Message::Binary(Bytes::from_static(b"y")))
            .await
            .unwrap();
        assert_eq!(&reader.await.unwrap().unwrap(), b"y");
    }

    #[tokio::test]
    async fn oversized_messages_are_rejected() {
        let (client, mut server) = pair().await;
        let mut client = WsIo::new(client, None);
        server
            .send(Message::Binary(vec![0; MAX_MESSAGE + 1].into()))
            .await
            .unwrap();
        let mut buffer = [0; 16];
        assert!(client.read(&mut buffer).await.is_err());
    }

    #[test]
    fn transport_selection_is_by_scheme_only() {
        assert!(is_websocket("wss://notary.example.com/notary"));
        assert!(is_websocket("ws://127.0.0.1:7049/notary"));
        assert!(!is_websocket("notary.example.com:7047"));
        assert!(!is_websocket("https://notary.example.com"));
    }
}
