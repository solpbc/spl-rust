// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! SPL relay carrier over a relay-blind WebSocket tunnel.
//!
//! Relay requests use two TLS legs. The outer leg is public-WebPKI WSS to the
//! relay edge with no client certificate and no CA-fingerprint pinning. The
//! inner leg is the same CA-fp-pinned mTLS stream used for direct LAN transport,
//! carried over an opaque WS binary byte-duplex so the relay sees only TLS
//! records. One-shot relay helpers use a fresh connection; the transport client
//! can instead retain the stream as a persistent mux carrier.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::{Sink, Stream};
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};
use spl_core::http::HttpResponse;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, client::TlsStream};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::error::Error as WsError;
use tokio_tungstenite::tungstenite::handshake::client::Request;
use tokio_tungstenite::tungstenite::http::header::{AUTHORIZATION, HeaderName, HeaderValue};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, connect_async_tls_with_config,
};

use crate::connection::run_request_over_stream;
use crate::tls::pinned_server_name;
use crate::{RelayError, TransportError};

/// Inner mTLS progress bound. This is not a presence-hold wait; a live relay
/// path should produce the journal's TLS response well before this.
pub(crate) const RELAY_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// Outer relay dial bound. This mirrors the direct TCP connect hygiene and is
/// separate from the typed inner-handshake stalled outcome.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_WS_CHUNK_BYTES: usize = 64 * 1024;

pub(crate) fn outer_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            #[expect(
                clippy::from_iter_instead_of_collect,
                reason = "the copied TLS-root construction keeps its target store type explicit"
            )]
            let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            #[expect(
                clippy::expect_used,
                reason = "the pinned ring provider is required to support rustls safe default protocol versions"
            )]
            let config =
                ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .expect("ring provider supports rustls safe default protocol versions")
                .with_root_certificates(roots)
                .with_no_client_auth();
            Arc::new(
                config,
            )
        })
        .clone()
}

#[derive(Clone, Copy)]
enum WsTermination {
    Close(u16),
    Abnormal,
}

fn relay_error_from_close(code: u16) -> RelayError {
    #[expect(
        clippy::match_same_arms,
        reason = "known abnormal close codes remain enumerated separately from unknown closes for protocol review"
    )]
    match code {
        4401 => RelayError::Unauthorized,
        4402 => RelayError::Unpaid,
        1009 => RelayError::Overflow,
        1006 | 1012 => RelayError::Abnormal,
        _ => RelayError::Abnormal,
    }
}

fn relay_error_from_upgrade_status(status: u16) -> RelayError {
    match status {
        503 => RelayError::HomeOffline,
        401 => RelayError::Unauthorized,
        402 => RelayError::Unpaid,
        404 => RelayError::UnknownInstance,
        _ => RelayError::UpgradeRejected,
    }
}

fn relay_error_from_pair_upgrade_status(status: u16) -> RelayError {
    match status {
        401 => RelayError::PairWindowClosed,
        _ => RelayError::UpgradeRejected,
    }
}

fn relay_error_from_termination(termination: WsTermination) -> RelayError {
    match termination {
        WsTermination::Close(code) => relay_error_from_close(code),
        WsTermination::Abnormal => RelayError::Abnormal,
    }
}

fn current_termination(termination: &Arc<Mutex<Option<WsTermination>>>) -> Option<WsTermination> {
    #[expect(
        clippy::expect_used,
        reason = "relay termination state is process-local and poisoning is an invariant failure"
    )]
    *termination
        .lock()
        .expect("relay termination mutex poisoned")
}

fn record_termination(termination: &Arc<Mutex<Option<WsTermination>>>, value: WsTermination) {
    #[expect(
        clippy::expect_used,
        reason = "relay termination state is process-local and poisoning is an invariant failure"
    )]
    let mut guard = termination
        .lock()
        .expect("relay termination mutex poisoned");
    if guard.is_none() {
        *guard = Some(value);
    }
}

fn ws_io_error(kind: io::ErrorKind, message: &'static str) -> io::Error {
    io::Error::new(kind, message)
}

#[derive(Clone)]
pub(crate) struct RelayTerminationHandle(Arc<Mutex<Option<WsTermination>>>);

impl RelayTerminationHandle {
    pub(crate) fn new() -> Self {
        Self(Arc::new(Mutex::new(None)))
    }

    fn current(&self) -> Option<WsTermination> {
        current_termination(&self.0)
    }

    pub(crate) fn current_error(&self) -> Option<RelayError> {
        self.current().map(relay_error_from_termination)
    }

    fn record(&self, value: WsTermination) {
        record_termination(&self.0, value);
    }
}

pub(crate) struct WsByteDuplex {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    read_tail: Vec<u8>,
    read_pos: usize,
    termination: RelayTerminationHandle,
}

impl WsByteDuplex {
    pub(crate) fn new(
        ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    ) -> (Self, RelayTerminationHandle) {
        let termination = RelayTerminationHandle::new();
        (
            Self {
                ws,
                read_tail: Vec::new(),
                read_pos: 0,
                termination: termination.clone(),
            },
            termination,
        )
    }

    fn copy_tail(&mut self, buf: &mut ReadBuf<'_>) -> bool {
        if self.read_pos >= self.read_tail.len() {
            self.read_tail.clear();
            self.read_pos = 0;
            return false;
        }

        let n = buf
            .remaining()
            .min(self.read_tail.len().saturating_sub(self.read_pos));
        if n == 0 {
            return true;
        }
        buf.put_slice(&self.read_tail[self.read_pos..self.read_pos + n]);
        self.read_pos += n;
        if self.read_pos == self.read_tail.len() {
            self.read_tail.clear();
            self.read_pos = 0;
        }
        true
    }
}

impl AsyncRead for WsByteDuplex {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.copy_tail(buf) {
            return Poll::Ready(Ok(()));
        }

        loop {
            match Stream::poll_next(Pin::new(&mut self.ws), cx) {
                Poll::Ready(Some(Ok(Message::Binary(bytes)))) => {
                    if bytes.is_empty() {
                        continue;
                    }
                    self.read_tail = bytes.to_vec();
                    self.read_pos = 0;
                    let _ = self.copy_tail(buf);
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => {
                    // tungstenite auto-queues the Pong; the next sink flush sends it.
                    #[expect(
                        clippy::needless_continue,
                        reason = "the explicit continue documents that control frames do not satisfy a pending byte read"
                    )]
                    continue;
                }
                Poll::Ready(Some(Ok(Message::Close(frame)))) => {
                    #[expect(
                        clippy::map_unwrap_or,
                        reason = "the copied close mapping keeps absent close-frame handling explicit"
                    )]
                    let code = frame
                        .map(|close| u16::from(close.code))
                        .unwrap_or_else(|| u16::from(CloseCode::Normal));
                    self.termination.record(WsTermination::Close(code));
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Ok(Message::Text(_) | Message::Frame(_)))) => {
                    self.termination.record(WsTermination::Abnormal);
                    return Poll::Ready(Err(ws_io_error(
                        io::ErrorKind::InvalidData,
                        "unexpected relay websocket message",
                    )));
                }
                Poll::Ready(Some(Err(_))) => {
                    self.termination.record(WsTermination::Abnormal);
                    return Poll::Ready(Err(ws_io_error(
                        io::ErrorKind::BrokenPipe,
                        "relay websocket read failed",
                    )));
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for WsByteDuplex {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let mut ws = Pin::new(&mut self.ws);
        match Sink::poll_ready(ws.as_mut(), cx) {
            Poll::Ready(Ok(())) => {
                let n = buf.len().min(MAX_WS_CHUNK_BYTES);
                let message = Message::Binary(buf[..n].to_vec().into());
                match Sink::start_send(ws, message) {
                    Ok(()) => Poll::Ready(Ok(n)),
                    Err(_) => Poll::Ready(Err(ws_io_error(
                        io::ErrorKind::BrokenPipe,
                        "relay websocket write failed",
                    ))),
                }
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(ws_io_error(
                io::ErrorKind::BrokenPipe,
                "relay websocket not ready",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Sink::poll_flush(Pin::new(&mut self.ws), cx).map(|result| {
            result
                .map_err(|_| ws_io_error(io::ErrorKind::BrokenPipe, "relay websocket flush failed"))
        })
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Sink::poll_close(Pin::new(&mut self.ws), cx).map(|result| {
            result
                .map_err(|_| ws_io_error(io::ErrorKind::BrokenPipe, "relay websocket close failed"))
        })
    }
}

/// Dial an authenticated relay WebSocket for an established device.
///
/// # Errors
///
/// Returns a typed relay rejection or a TLS, URL, timeout, or WebSocket error.
pub async fn dial_relay_ws(
    url: &str,
    device_token: &str,
    outer: Arc<ClientConfig>,
) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, TransportError> {
    let mut request = url
        .into_client_request()
        .map_err(|e| TransportError::Tls(format!("relay dial request: {e}")))?;
    let authorization = format!("Bearer {device_token}")
        .parse()
        .map_err(|_| TransportError::Tls("relay authorization header".into()))?;
    request.headers_mut().insert(AUTHORIZATION, authorization);

    let dial = connect_async_tls_with_config(request, None, true, Some(Connector::Rustls(outer)));
    match tokio::time::timeout(DIAL_TIMEOUT, dial).await {
        Err(_) => Err(TransportError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            "relay ws dial timed out",
        ))),
        Ok(Ok((ws, _response))) => Ok(ws),
        Ok(Err(WsError::Http(response))) => Err(TransportError::Relay(
            relay_error_from_upgrade_status(response.status().as_u16()),
        )),
        Ok(Err(e)) => Err(TransportError::Tls(format!("relay ws upgrade: {e}"))),
    }
}

fn build_pair_dial_request(url: &str, rk_hex: &str) -> Result<Request, TransportError> {
    let mut request = url
        .into_client_request()
        .map_err(|e| TransportError::Tls(format!("relay pair-dial request: {e}")))?;
    let key = HeaderValue::from_str(rk_hex)
        .map_err(|_| TransportError::Tls("relay pair key header".into()))?;
    request
        .headers_mut()
        .insert(HeaderName::from_static("sec-pair-key"), key);
    Ok(request)
}

/// Dial a relay WebSocket authorized by the one-shot relay pairing key.
///
/// # Errors
///
/// Returns a typed pair-window rejection or a TLS, URL, timeout, or WebSocket
/// error.
pub(crate) async fn dial_pair_relay_ws(
    url: &str,
    rk_hex: &str,
    outer: Arc<ClientConfig>,
) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, TransportError> {
    let request = build_pair_dial_request(url, rk_hex)?;
    let dial = connect_async_tls_with_config(request, None, true, Some(Connector::Rustls(outer)));
    match tokio::time::timeout(DIAL_TIMEOUT, dial).await {
        Err(_) => Err(TransportError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            "relay ws dial timed out",
        ))),
        Ok(Ok((ws, _response))) => Ok(ws),
        Ok(Err(WsError::Http(response))) => Err(TransportError::Relay(
            relay_error_from_pair_upgrade_status(response.status().as_u16()),
        )),
        Ok(Err(e)) => Err(TransportError::Tls(format!("relay ws upgrade: {e}"))),
    }
}

/// Send one HTTP request over an already-established relay WebSocket.
///
/// # Errors
///
/// Returns an inner TLS, mux, HTTP, timeout, or typed relay error.
pub async fn request_once_over_ws(
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    inner_config: Arc<ClientConfig>,
    handshake_timeout: Duration,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<HttpResponse, TransportError> {
    request_once_over_ws_inner(
        ws,
        inner_config,
        handshake_timeout,
        method,
        path,
        headers,
        body,
    )
    .await
    .map(|(response, _peer_leaf)| response)
}

pub(crate) struct RelayCarrier {
    pub(crate) stream: TlsStream<WsByteDuplex>,
    pub(crate) termination: RelayTerminationHandle,
}

pub(crate) async fn dial_relay_carrier(
    inner_config: Arc<ClientConfig>,
    relay_origin: &str,
    instance_id: &str,
    device_token: &str,
) -> Result<RelayCarrier, TransportError> {
    let url = spl_core::relay::dial_url(relay_origin, instance_id)
        .map_err(|e| TransportError::PairLink(format!("relay origin: {e}")))?;
    let ws = dial_relay_ws(&url, device_token, outer_config()).await?;
    let (duplex, termination) = WsByteDuplex::new(ws);
    let connector = TlsConnector::from(inner_config);
    let tls = match tokio::time::timeout(
        RELAY_HANDSHAKE_TIMEOUT,
        connector.connect(pinned_server_name(), duplex),
    )
    .await
    {
        Err(_) => return Err(TransportError::Relay(RelayError::Stalled)),
        Ok(Ok(tls)) => tls,
        Ok(Err(e)) => {
            if let Some(error) = termination.current_error() {
                return Err(TransportError::Relay(error));
            }
            return Err(TransportError::Tls(format!("inner relay handshake: {e}")));
        }
    };

    Ok(RelayCarrier {
        stream: tls,
        termination,
    })
}

async fn request_once_over_ws_inner(
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    inner_config: Arc<ClientConfig>,
    handshake_timeout: Duration,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<(HttpResponse, Option<CertificateDer<'static>>), TransportError> {
    let (duplex, termination) = WsByteDuplex::new(ws);
    match request_once_over_stream_with_peer_leaf(
        duplex,
        inner_config,
        handshake_timeout,
        method,
        path,
        headers,
        body,
    )
    .await
    {
        Ok(result) => Ok(result),
        Err(error) => {
            if let Some(value) = termination.current() {
                Err(TransportError::Relay(relay_error_from_termination(value)))
            } else {
                Err(error)
            }
        }
    }
}

pub(crate) async fn request_once_over_stream_with_peer_leaf<S>(
    io: S,
    inner_config: Arc<ClientConfig>,
    handshake_timeout: Duration,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<(HttpResponse, Option<CertificateDer<'static>>), TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let connector = TlsConnector::from(inner_config);
    let tls = match tokio::time::timeout(
        handshake_timeout,
        connector.connect(pinned_server_name(), io),
    )
    .await
    {
        Err(_) => return Err(TransportError::Relay(RelayError::Stalled)),
        Ok(Ok(tls)) => tls,
        Ok(Err(e)) => return Err(TransportError::Tls(format!("inner relay handshake: {e}"))),
    };
    let peer_leaf = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .cloned();

    run_request_over_stream(tls, method, path, headers, body)
        .await
        .map(|response| (response, peer_leaf))
}

#[expect(
    clippy::too_many_arguments,
    reason = "the relay request entry point mirrors the explicit TLS, routing, authorization, and HTTP inputs"
)]
/// Send one HTTP request through a newly dialed authenticated relay carrier.
///
/// # Errors
///
/// Returns a relay-origin, relay-upgrade, inner TLS, mux, or HTTP error.
pub async fn request_once_relay(
    inner_config: Arc<ClientConfig>,
    relay_origin: &str,
    instance_id: &str,
    device_token: &str,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<HttpResponse, TransportError> {
    let url = spl_core::relay::dial_url(relay_origin, instance_id)
        .map_err(|e| TransportError::PairLink(format!("relay origin: {e}")))?;
    let ws = dial_relay_ws(&url, device_token, outer_config()).await?;
    request_once_over_ws(
        ws,
        inner_config,
        RELAY_HANDSHAKE_TIMEOUT,
        method,
        path,
        headers,
        body,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_pair_dial_request_sets_pair_key_without_authorization() {
        let rk_hex = "e34481a4cde647ba9c9fb29a59e18271";
        let request =
            build_pair_dial_request("wss://link.solstone.app/session/pair-dial", rk_hex).unwrap();

        assert!(request.uri().query().is_none());
        assert_eq!(
            request.headers().get("sec-pair-key").unwrap(),
            HeaderValue::from_str(rk_hex).unwrap()
        );
        assert!(request.headers().get(AUTHORIZATION).is_none());
    }

    #[test]
    fn pair_upgrade_401_maps_to_pair_window_closed() {
        assert_eq!(
            relay_error_from_pair_upgrade_status(401),
            RelayError::PairWindowClosed
        );
    }
}
