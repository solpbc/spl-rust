// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Hand-rolled loopback proxy for the paired journal dashboard.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use spl_core::bridge::{
    self, BOOTSTRAP_ROUTE, BridgeNames, FailureCategory, RejectReason, RequestHead,
};
use spl_core::mux::StreamItem;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::client::DialedCarrier;
use crate::journal_bridge_carrier::MuxCarrier;
use crate::{TransportError, transport_error_code};

const MAX_HEAD_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
const READ_BUF_BYTES: usize = 4096;

/// Consumer seam used by the journal bridge to authenticate and open carriers.
///
/// Implementations must add the consumer's complete authentication-header set.
/// Two prior mobile 401 regressions were missing-header bugs, so the bridge must
/// not selectively omit one of the consumer's redundant authentication forms.
pub trait CarrierOpener: Send + Sync + 'static {
    /// Add consumer authentication to the already-filtered upstream headers.
    ///
    /// # Errors
    ///
    /// Returns a transport error when required consumer authentication is absent.
    fn proxy_headers(
        &self,
        upstream_headers: &[(String, String)],
    ) -> Result<Vec<(String, String)>, TransportError>;

    /// Open a direct-or-relay carrier and return it opaquely to the bridge.
    fn dial_carrier(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<DialedCarrier, TransportError>> + Send + '_>>;
}

/// Consumer-owned inputs used to start one loopback journal bridge.
pub struct JournalBridgeConfig {
    /// Header policy and carrier dialer for the paired consumer identity.
    pub opener: Arc<dyn CarrierOpener>,
    /// Product-selected cookie and header names used by bridge transforms.
    pub bridge_names: BridgeNames,
    /// Direct endpoint hosts accepted when rewriting journal redirects.
    pub endpoint_hosts: Vec<String>,
}

/// Running loopback journal bridge and its shutdown controls.
pub struct JournalBridgeHandle {
    port: u16,
    capability: String,
    contacted: Arc<AtomicBool>,
    shutdown: oneshot::Sender<()>,
    join: JoinHandle<()>,
}

impl JournalBridgeHandle {
    /// Return the bound loopback TCP port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Whether the loopback listener has accepted at least one TCP connection.
    /// Write-once observation flag (set at accept, before HTTP parse).
    pub fn contacted(&self) -> bool {
        self.contacted.load(Ordering::Relaxed)
    }

    /// Return the one-use bootstrap URL carrying the local capability.
    pub fn bootstrap_url(&self) -> String {
        format!(
            "http://127.0.0.1:{}{}?cap={}",
            self.port, BOOTSTRAP_ROUTE, self.capability
        )
    }

    /// Request shutdown without waiting for the bridge task to exit.
    pub fn begin_shutdown(self) {
        let _ = self.shutdown.send(());
    }

    /// Request shutdown and wait for the bridge task to exit.
    pub async fn shutdown_and_wait(self) {
        let _ = self.shutdown.send(());
        let _ = self.join.await;
    }
}

#[derive(Debug)]
/// Failure while constructing a loopback journal bridge.
pub enum BridgeStartError {
    /// Secure capability generation failed.
    Capability(TransportError),
    /// The loopback listener could not bind or report its address.
    Bind(std::io::Error),
}

/// Start a bridge bound to an ephemeral IPv4 loopback port.
///
/// # Errors
///
/// Returns [`BridgeStartError::Capability`] if secure capability generation
/// fails, or [`BridgeStartError::Bind`] for loopback listener failures.
pub async fn start(config: JournalBridgeConfig) -> Result<JournalBridgeHandle, BridgeStartError> {
    let JournalBridgeConfig {
        opener,
        bridge_names,
        endpoint_hosts,
    } = config;
    let mut journal_hosts = Vec::with_capacity(endpoint_hosts.len() + 1);
    // No `spl.local` occurrence exists in the vendored `.proto-ref/` mirror;
    // preserve the source's conventional transport host inline for this lift.
    journal_hosts.push("spl.local".to_string());
    journal_hosts.extend(endpoint_hosts);
    let carrier = Arc::new(MuxCarrier::new(opener));

    let capability = mint_capability()?;
    let listener = match TcpListener::bind(("127.0.0.1", 0)).await {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!(
                target: "journal_bridge",
                category = FailureCategory::LocalBind.token(),
                error_kind = ?error.kind()
            );
            return Err(BridgeStartError::Bind(error));
        }
    };
    let port = listener
        .local_addr()
        .map_err(BridgeStartError::Bind)?
        .port();
    let loopback_origin = Arc::new(format!("http://127.0.0.1:{port}"));
    let capability = Arc::new(capability);
    let journal_hosts = Arc::new(journal_hosts);
    let bridge_names = Arc::new(bridge_names);
    let (shutdown, shutdown_rx) = oneshot::channel();

    let contacted = Arc::new(AtomicBool::new(false));
    let join = tokio::spawn(accept_loop(
        listener,
        shutdown_rx,
        carrier,
        capability.clone(),
        port,
        journal_hosts,
        loopback_origin,
        bridge_names,
        contacted.clone(),
    ));

    Ok(JournalBridgeHandle {
        port,
        capability: (*capability).clone(),
        contacted,
        shutdown,
        join,
    })
}

fn mint_capability() -> Result<String, BridgeStartError> {
    let mut bytes = [0u8; 32];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut bytes)
        .map_err(|error| {
            BridgeStartError::Capability(TransportError::Crypto(format!(
                "journal bridge capability rng: {error:?}"
            )))
        })?;
    Ok(hex_encode(&bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[expect(
    clippy::too_many_arguments,
    reason = "the accept task owns the independently shared listener, carrier, authorization, rewrite, and lifecycle values"
)]
async fn accept_loop(
    listener: TcpListener,
    mut shutdown: oneshot::Receiver<()>,
    carrier: Arc<MuxCarrier>,
    capability: Arc<String>,
    port: u16,
    journal_hosts: Arc<Vec<String>>,
    loopback_origin: Arc<String>,
    bridge_names: Arc<BridgeNames>,
    contacted: Arc<AtomicBool>,
) {
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                carrier.shutdown().await;
                break;
            }
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else {
                    continue;
                };
                contacted.store(true, Ordering::Relaxed);
                tokio::spawn(handle_conn(
                    stream,
                    carrier.clone(),
                    capability.clone(),
                    port,
                    journal_hosts.clone(),
                    loopback_origin.clone(),
                    bridge_names.clone(),
                ));
            }
        }
    }
}

async fn handle_conn(
    mut stream: TcpStream,
    carrier: Arc<MuxCarrier>,
    capability: Arc<String>,
    port: u16,
    journal_hosts: Arc<Vec<String>>,
    loopback_origin: Arc<String>,
    bridge_names: Arc<BridgeNames>,
) {
    let Some((head_bytes, body)) = read_request(&mut stream).await else {
        return;
    };
    let Some(request_head) = bridge::parse_request_head(&head_bytes) else {
        write_local(&mut stream, 400, b"bad request", "text/plain").await;
        return;
    };
    let route = if request_head.path() == BOOTSTRAP_ROUTE {
        "bootstrap"
    } else {
        "upstream"
    };
    tracing::info!(
        target: "journal_bridge",
        method = request_head.method.as_str(),
        route,
        "local request"
    );

    if request_head.path() == BOOTSTRAP_ROUTE {
        handle_bootstrap(&mut stream, &request_head, &capability, port, &bridge_names).await;
        return;
    }

    if let Err(reason) =
        bridge::authorize(&request_head, capability.as_bytes(), port, &bridge_names)
    {
        log_capability_reject(reason);
        let status = if reason == RejectReason::BadMethod {
            405
        } else {
            403
        };
        write_local(&mut stream, status, b"forbidden", "text/plain").await;
        return;
    }

    let upstream_headers = bridge::upstream_request_headers(&request_head, &bridge_names);
    if request_head.method == "GET" && request_head.path() == "/sse/events" {
        forward_sse(
            &mut stream,
            carrier,
            &request_head,
            &upstream_headers,
            &journal_hosts,
            &loopback_origin,
            &bridge_names,
        )
        .await;
    } else {
        forward_buffered(
            &mut stream,
            carrier,
            &request_head,
            &upstream_headers,
            &body,
            &journal_hosts,
            &loopback_origin,
            &bridge_names,
        )
        .await;
    }
}

async fn handle_bootstrap(
    stream: &mut TcpStream,
    request_head: &RequestHead,
    capability: &str,
    port: u16,
    bridge_names: &BridgeNames,
) {
    let expected_host = format!("127.0.0.1:{port}");
    if request_head.host() != Some(expected_host.as_str()) {
        log_capability_reject(RejectReason::BadHost);
        write_local(stream, 403, b"forbidden", "text/plain").await;
        return;
    }
    if request_head.method != "GET" {
        log_capability_reject(RejectReason::BadMethod);
        write_local(stream, 405, b"forbidden", "text/plain").await;
        return;
    }
    if request_head.has_caller_auth(bridge_names) {
        log_capability_reject(RejectReason::CallerAuth);
        write_local(stream, 403, b"forbidden", "text/plain").await;
        return;
    }

    #[expect(
        clippy::map_unwrap_or,
        reason = "the copied bootstrap check keeps absence and comparison failure visibly equivalent"
    )]
    let cap_ok = bridge::bootstrap_cap(&request_head.target)
        .map(|presented| bridge::ct_eq(presented.as_bytes(), capability.as_bytes()))
        .unwrap_or(false);
    if !cap_ok {
        log_capability_reject(RejectReason::BadCapability);
        write_local(stream, 403, b"forbidden", "text/plain").await;
        return;
    }

    let response = format!(
        "HTTP/1.1 302 Found\r\nSet-Cookie: {}={capability}; {}\r\nLocation: /\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        bridge_names.capability_cookie_name,
        bridge::bootstrap_cookie_attributes()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

#[expect(
    clippy::too_many_arguments,
    reason = "buffered forwarding keeps request, body, authorization names, and response rewrite inputs explicit"
)]
async fn forward_buffered(
    stream: &mut TcpStream,
    carrier: Arc<MuxCarrier>,
    request_head: &RequestHead,
    upstream_headers: &[(String, String)],
    body: &[u8],
    journal_hosts: &[String],
    loopback_origin: &str,
    bridge_names: &BridgeNames,
) {
    let mut rx = match carrier
        .open_stream(
            &request_head.method,
            &request_head.target,
            upstream_headers,
            body,
        )
        .await
    {
        Ok(rx) => rx,
        Err(error) => {
            log_upstream_open_error(&error);
            write_local(stream, 502, b"journal unreachable", "text/plain").await;
            return;
        }
    };

    let mut response_head = None;
    let mut response_body = Vec::new();
    while let Some(item) = rx.recv().await {
        match item {
            StreamItem::Head(head) => {
                if matches!(head.status, 401 | 403) {
                    tracing::warn!(
                        target: "journal_bridge",
                        category = FailureCategory::UpstreamCredential.token(),
                        status = head.status
                    );
                }
                response_head = Some(head);
            }
            StreamItem::Body(bytes) => response_body.extend_from_slice(&bytes),
            StreamItem::End(_) => break,
        }
    }

    let Some(head) = response_head else {
        tracing::warn!(
            target: "journal_bridge",
            category = FailureCategory::UpstreamUnreachable.token(),
            code = "io"
        );
        write_local(stream, 502, b"journal unreachable", "text/plain").await;
        return;
    };

    let headers =
        bridge::response_headers(&head.headers, journal_hosts, loopback_origin, bridge_names);
    let body = if request_head.method == "HEAD" {
        &[][..]
    } else {
        response_body.as_slice()
    };
    let content_length = if request_head.method == "HEAD" {
        upstream_content_length(&head.headers).unwrap_or(body.len())
    } else {
        body.len()
    };
    if write_upstream_response(stream, head.status, &headers, body, Some(content_length))
        .await
        .is_err()
    {
        rx.cancel();
    }
}

async fn forward_sse(
    stream: &mut TcpStream,
    carrier: Arc<MuxCarrier>,
    request_head: &RequestHead,
    upstream_headers: &[(String, String)],
    journal_hosts: &[String],
    loopback_origin: &str,
    bridge_names: &BridgeNames,
) {
    let mut rx = match carrier
        .open_stream("GET", &request_head.target, upstream_headers, b"")
        .await
    {
        Ok(rx) => rx,
        Err(error) => {
            log_upstream_open_error(&error);
            write_local(stream, 502, b"journal unreachable", "text/plain").await;
            return;
        }
    };

    let mut head_written = false;
    while let Some(item) = rx.recv().await {
        match item {
            StreamItem::Head(head) => {
                if matches!(head.status, 401 | 403) {
                    tracing::warn!(
                        target: "journal_bridge",
                        category = FailureCategory::UpstreamCredential.token(),
                        status = head.status
                    );
                }
                let headers = bridge::response_headers(
                    &head.headers,
                    journal_hosts,
                    loopback_origin,
                    bridge_names,
                );
                if write_stream_head(stream, head.status, &headers)
                    .await
                    .is_err()
                {
                    rx.cancel();
                    return;
                }
                head_written = true;
            }
            StreamItem::Body(bytes) => {
                if !head_written {
                    break;
                }
                if stream.write_all(&bytes).await.is_err() || stream.flush().await.is_err() {
                    rx.cancel();
                    return;
                }
            }
            StreamItem::End(_) => break,
        }
    }

    if !head_written {
        tracing::warn!(
            target: "journal_bridge",
            category = FailureCategory::UpstreamUnreachable.token(),
            code = "io"
        );
        write_local(stream, 502, b"journal unreachable", "text/plain").await;
        return;
    }
    let _ = stream.shutdown().await;
}

fn log_upstream_open_error(error: &TransportError) {
    let category = if matches!(error, TransportError::NotPaired) {
        FailureCategory::UpstreamCredential
    } else {
        FailureCategory::UpstreamUnreachable
    };
    tracing::warn!(
        target: "journal_bridge",
        category = category.token(),
        code = %transport_error_code(error)
    );
}

async fn read_request(stream: &mut TcpStream) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut received = Vec::new();
    let mut buf = [0u8; READ_BUF_BYTES];
    let split = loop {
        let n = stream.read(&mut buf).await.ok()?;
        if n == 0 {
            return None;
        }
        received.extend_from_slice(&buf[..n]);
        if let Some(split) = find_header_end(&received) {
            break split;
        }
        if received.len() > MAX_HEAD_BYTES {
            return None;
        }
    };

    let body_start = split + 4;
    let head = received[..body_start].to_vec();
    let content_length = parse_content_length(&head)?;
    if content_length > MAX_BODY_BYTES {
        return None;
    }
    let mut body = received[body_start..].to_vec();
    if body.len() > content_length {
        body.truncate(content_length);
    }
    while body.len() < content_length {
        let remaining = content_length - body.len();
        let n = stream
            .read(&mut buf[..remaining.min(READ_BUF_BYTES)])
            .await
            .ok()?;
        if n == 0 {
            return None;
        }
        body.extend_from_slice(&buf[..n]);
    }
    Some((head, body))
}

fn parse_content_length(head: &[u8]) -> Option<usize> {
    let text = String::from_utf8_lossy(head);
    for line in text.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("content-length") {
            return value.trim().parse::<usize>().ok();
        }
    }
    Some(0)
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

async fn write_local(stream: &mut TcpStream, status: u16, body: &[u8], content_type: &str) {
    let response = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reason_phrase(status),
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.write_all(body).await;
    let _ = stream.shutdown().await;
}

async fn write_upstream_response(
    stream: &mut TcpStream,
    status: u16,
    headers: &[(String, String)],
    body: &[u8],
    content_length: Option<usize>,
) -> std::io::Result<()> {
    let mut response = format!("HTTP/1.1 {status} {}\r\n", reason_phrase(status));
    for (name, value) in headers {
        response.push_str(name);
        response.push_str(": ");
        response.push_str(value);
        response.push_str("\r\n");
    }
    if let Some(content_length) = content_length {
        response.push_str("content-length: ");
        response.push_str(&content_length.to_string());
        response.push_str("\r\n");
    }
    response.push_str("connection: close\r\n\r\n");
    stream.write_all(response.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.shutdown().await
}

fn upstream_content_length(headers: &[(String, String)]) -> Option<usize> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse::<usize>().ok())
}

async fn write_stream_head(
    stream: &mut TcpStream,
    status: u16,
    headers: &[(String, String)],
) -> std::io::Result<()> {
    let mut response = format!("HTTP/1.1 {status} {}\r\n", reason_phrase(status));
    for (name, value) in headers {
        response.push_str(name);
        response.push_str(": ");
        response.push_str(value);
        response.push_str("\r\n");
    }
    response.push_str("connection: close\r\n\r\n");
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        410 => "Gone",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

fn log_capability_reject(reason: RejectReason) {
    tracing::warn!(
        target: "journal_bridge",
        category = FailureCategory::LocalCapabilityReject.token(),
        reason = reason.token()
    );
}
