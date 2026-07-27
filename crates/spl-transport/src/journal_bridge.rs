// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Hand-rolled configurable loopback proxy for consumer HTTP traffic.
//!
//! The default policy preserves the paired journal dashboard behavior:
//! ephemeral port, capability gate, streaming `GET /sse/events`, the existing
//! request-header allow-list, and an 8 MiB request-body limit. Disabling the
//! capability gate permits every method, while exact loopback `Host` validation
//! and bridge-reserved header stripping remain mandatory.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};

use spl_core::bridge::{
    self, BOOTSTRAP_ROUTE, BridgeNames, FailureCategory, RejectReason, RequestHead,
    RequestHeaderPolicy,
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
const READ_BUF_BYTES: usize = 4096;

const DEFAULT_REQUEST_HEADERS: &[&str] = &[
    "accept",
    "accept-language",
    "content-type",
    "cache-control",
    "if-none-match",
    "if-modified-since",
    "range",
    "user-agent",
];

/// Whether local requests must present a bridge capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityGate {
    /// Mint a capability and require it on forwarded requests.
    Enabled,
    /// Do not mint or compare a capability.
    Disabled,
}

/// Complete response returned locally without opening an upstream stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalResponse {
    /// HTTP response status.
    pub status: u16,
    /// HTTP response content type.
    pub content_type: String,
    /// Complete response body.
    pub body: Vec<u8>,
}

/// Owned point-in-time status for one journal bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalBridgeStatus {
    /// Whether the loopback listener task has not exited.
    pub listener_active: bool,
    /// Whether the listener has accepted at least one TCP connection.
    pub contacted: bool,
    /// Whether the current persistent carrier is live.
    pub carrier_live: bool,
    /// Accepted connection tasks that have not completed.
    pub active_requests: usize,
}

pub(crate) type SharedStatus = Arc<Mutex<StatusRecord>>;

pub(crate) struct StatusRecord {
    pub(crate) snapshot: JournalBridgeStatus,
    pub(crate) current_carrier: Option<Arc<()>>,
}

pub(crate) fn lock_status(status: &SharedStatus) -> MutexGuard<'_, StatusRecord> {
    match status.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

pub(crate) fn new_status() -> SharedStatus {
    Arc::new(Mutex::new(StatusRecord {
        snapshot: JournalBridgeStatus {
            listener_active: false,
            contacted: false,
            carrier_live: false,
            active_requests: 0,
        },
        current_carrier: None,
    }))
}

fn status_snapshot(status: &SharedStatus) -> JournalBridgeStatus {
    lock_status(status).snapshot
}

struct ListenerActiveGuard {
    status: SharedStatus,
}

impl ListenerActiveGuard {
    fn new(status: SharedStatus) -> Self {
        lock_status(&status).snapshot.listener_active = true;
        Self { status }
    }
}

impl Drop for ListenerActiveGuard {
    fn drop(&mut self) {
        lock_status(&self.status).snapshot.listener_active = false;
    }
}

struct ActiveRequestGuard {
    status: SharedStatus,
}

impl ActiveRequestGuard {
    fn new(status: SharedStatus) -> Self {
        let mut record = lock_status(&status);
        record.snapshot.contacted = true;
        record.snapshot.active_requests = record.snapshot.active_requests.saturating_add(1);
        drop(record);
        Self { status }
    }
}

impl Drop for ActiveRequestGuard {
    fn drop(&mut self) {
        let mut record = lock_status(&self.status);
        record.snapshot.active_requests = record.snapshot.active_requests.saturating_sub(1);
    }
}

/// Consumer-selected behavior for one loopback bridge.
#[derive(Clone)]
#[expect(
    clippy::type_complexity,
    reason = "the two public policy hooks keep their complete synchronous per-request signatures visible"
)]
pub struct BridgePolicy {
    /// IPv4 loopback port to bind, or zero for an ephemeral port.
    pub port: u16,
    /// Whether requests require a minted capability.
    pub capability_gate: CapabilityGate,
    /// Predicate selecting responses that are delivered incrementally.
    /// Selected requests forward their real method and body; the default
    /// bodyless `GET /sse/events` is unchanged, while a GET with a body forwards it.
    pub stream_response: Arc<dyn Fn(&RequestHead) -> bool + Send + Sync>,
    /// Optionally answer an authorized request without opening an upstream
    /// stream. The hook receives one coherent owned-status view by reference.
    pub local_response:
        Arc<dyn Fn(&RequestHead, &JournalBridgeStatus) -> Option<LocalResponse> + Send + Sync>,
    /// Produce attribution headers from the unfiltered authorized request.
    ///
    /// The bridge never promotes a caller-supplied header on its own: every
    /// attribution header reaching upstream was produced by consumer code that
    /// saw the request. Fields with invalid names or CR, LF, or NUL in their
    /// values are dropped. Cookies are dropped, and reserved header names can
    /// never be attributed.
    ///
    /// This hook does not authenticate the caller or bind attribution to a
    /// caller identity. Consumer code that copies a caller header verbatim
    /// reopens forgery, and this crate cannot prevent that.
    pub attribution_headers: Arc<dyn Fn(&RequestHead) -> Vec<(String, String)> + Send + Sync>,
    /// Policy for forwarding non-cookie request headers.
    pub request_headers: RequestHeaderPolicy,
    /// Maximum request body accepted from a local client.
    pub max_request_body_bytes: usize,
}

impl Default for BridgePolicy {
    fn default() -> Self {
        Self {
            port: 0,
            capability_gate: CapabilityGate::Enabled,
            stream_response: Arc::new(|head| head.method == "GET" && head.path() == "/sse/events"),
            local_response: Arc::new(|_, _| None),
            attribution_headers: Arc::new(|_| Vec::new()),
            request_headers: RequestHeaderPolicy::Allow(
                DEFAULT_REQUEST_HEADERS
                    .iter()
                    .map(|name| (*name).to_string())
                    .collect(),
            ),
            max_request_body_bytes: 8 * 1024 * 1024,
        }
    }
}

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
    /// Listener, authorization, streaming, header, and request-size behavior.
    pub policy: BridgePolicy,
}

/// Running loopback journal bridge and its shutdown controls.
pub struct JournalBridgeHandle {
    port: u16,
    capability: CapabilityState,
    status: SharedStatus,
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
        self.status().contacted
    }

    /// Return one coherent owned bridge-status snapshot.
    pub fn status(&self) -> JournalBridgeStatus {
        status_snapshot(&self.status)
    }

    /// Return the bootstrap URL when capability authorization is enabled.
    pub fn bootstrap_url(&self) -> Option<String> {
        self.capability.value().map(|capability| {
            format!(
                "http://127.0.0.1:{}{}?cap={capability}",
                self.port, BOOTSTRAP_ROUTE
            )
        })
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

#[derive(Clone)]
enum CapabilityState {
    Enabled(Arc<String>),
    Disabled,
}

impl CapabilityState {
    fn value(&self) -> Option<&str> {
        match self {
            Self::Enabled(capability) => Some(capability),
            Self::Disabled => None,
        }
    }

    fn bootstrap_capability(&self, path: &str) -> Option<&str> {
        if path == BOOTSTRAP_ROUTE {
            self.value()
        } else {
            None
        }
    }
}

#[expect(
    clippy::type_complexity,
    reason = "the runtime retains the public policy hook signatures without adapter types"
)]
struct BridgeRuntime {
    carrier: Arc<MuxCarrier>,
    status: SharedStatus,
    capability: CapabilityState,
    port: u16,
    journal_hosts: Vec<String>,
    loopback_origin: String,
    bridge_names: BridgeNames,
    stream_response: Arc<dyn Fn(&RequestHead) -> bool + Send + Sync>,
    local_response:
        Arc<dyn Fn(&RequestHead, &JournalBridgeStatus) -> Option<LocalResponse> + Send + Sync>,
    attribution_headers: Arc<dyn Fn(&RequestHead) -> Vec<(String, String)> + Send + Sync>,
    request_headers: RequestHeaderPolicy,
    max_request_body_bytes: usize,
}

#[derive(Debug)]
/// Failure while constructing a loopback journal bridge.
pub enum BridgeStartError {
    /// Secure capability generation failed.
    Capability(TransportError),
    /// The loopback listener could not bind or report its address.
    Bind(std::io::Error),
}

/// Start a bridge bound to the configured IPv4 loopback port.
///
/// # Errors
///
/// Returns [`BridgeStartError::Capability`] if secure capability generation
/// fails while the gate is enabled, or [`BridgeStartError::Bind`] for loopback
/// listener failures.
pub async fn start(config: JournalBridgeConfig) -> Result<JournalBridgeHandle, BridgeStartError> {
    let JournalBridgeConfig {
        opener,
        bridge_names,
        endpoint_hosts,
        policy,
    } = config;
    let BridgePolicy {
        port: requested_port,
        capability_gate,
        stream_response,
        local_response,
        attribution_headers,
        request_headers,
        max_request_body_bytes,
    } = policy;
    let mut journal_hosts = Vec::with_capacity(endpoint_hosts.len() + 1);
    // No `spl.local` occurrence exists in the vendored `.proto-ref/` mirror;
    // it remains the conventional hostname for transport redirect rewriting.
    journal_hosts.push("spl.local".to_string());
    journal_hosts.extend(endpoint_hosts);
    let status = new_status();
    let carrier = Arc::new(MuxCarrier::new(opener, status.clone()));

    let capability = match capability_gate {
        CapabilityGate::Enabled => CapabilityState::Enabled(Arc::new(mint_capability()?)),
        CapabilityGate::Disabled => CapabilityState::Disabled,
    };
    let listener = match TcpListener::bind(("127.0.0.1", requested_port)).await {
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
    let runtime = Arc::new(BridgeRuntime {
        carrier,
        status: status.clone(),
        capability: capability.clone(),
        port,
        journal_hosts,
        loopback_origin: format!("http://127.0.0.1:{port}"),
        bridge_names,
        stream_response,
        local_response,
        attribution_headers,
        request_headers,
        max_request_body_bytes,
    });
    let (shutdown, shutdown_rx) = oneshot::channel();

    let listener_guard = ListenerActiveGuard::new(status.clone());
    let join = tokio::spawn(accept_loop(listener, shutdown_rx, runtime, listener_guard));

    Ok(JournalBridgeHandle {
        port,
        capability,
        status,
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

async fn accept_loop(
    listener: TcpListener,
    mut shutdown: oneshot::Receiver<()>,
    runtime: Arc<BridgeRuntime>,
    _listener_guard: ListenerActiveGuard,
) {
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                runtime.carrier.shutdown().await;
                break;
            }
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else {
                    continue;
                };
                let request_guard = ActiveRequestGuard::new(runtime.status.clone());
                tokio::spawn(handle_conn(stream, runtime.clone(), request_guard));
            }
        }
    }
}

async fn handle_conn(
    mut stream: TcpStream,
    runtime: Arc<BridgeRuntime>,
    _request_guard: ActiveRequestGuard,
) {
    let Some((head_bytes, body)) = read_request(&mut stream, runtime.max_request_body_bytes).await
    else {
        return;
    };
    let Some(request_head) = bridge::parse_request_head(&head_bytes) else {
        write_local(&mut stream, 400, b"bad request", "text/plain").await;
        return;
    };
    let bootstrap_capability = runtime.capability.bootstrap_capability(request_head.path());

    if let Some(capability) = bootstrap_capability {
        log_local_request(&request_head, "bootstrap");
        handle_bootstrap(
            &mut stream,
            &request_head,
            capability,
            runtime.port,
            &runtime.bridge_names,
        )
        .await;
        return;
    }

    let authorization = match &runtime.capability {
        CapabilityState::Enabled(capability) => bridge::authorize(
            &request_head,
            capability.as_bytes(),
            runtime.port,
            &runtime.bridge_names,
        ),
        CapabilityState::Disabled => {
            // A gate-off host failure deliberately retains the
            // local_capability_reject category below for diagnostic stability.
            bridge::check_loopback_host(&request_head, runtime.port)
        }
    };
    if let Err(reason) = authorization {
        log_capability_reject(reason);
        let status = if reason == RejectReason::BadMethod {
            405
        } else {
            403
        };
        write_local(&mut stream, status, b"forbidden", "text/plain").await;
        return;
    }

    let snapshot = status_snapshot(&runtime.status);
    if let Some(response) = (runtime.local_response)(&request_head, &snapshot) {
        log_local_request(&request_head, "local");
        let content_type = safe_content_type(&response.content_type);
        write_local(&mut stream, response.status, &response.body, content_type).await;
        return;
    }

    log_local_request(&request_head, "upstream");
    let mut upstream_headers = bridge::upstream_request_headers(
        &request_head,
        &runtime.bridge_names,
        &runtime.request_headers,
    );
    let attribution_headers = filtered_attribution_headers(
        &request_head,
        &runtime.bridge_names,
        (runtime.attribution_headers)(&request_head),
    );
    for (name, _) in &attribution_headers {
        upstream_headers.retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
    }
    upstream_headers.extend(attribution_headers);
    if (runtime.stream_response)(&request_head) {
        forward_streaming(
            &mut stream,
            &runtime,
            &request_head,
            &upstream_headers,
            &body,
        )
        .await;
    } else {
        forward_buffered(
            &mut stream,
            &runtime,
            &request_head,
            &upstream_headers,
            &body,
        )
        .await;
    }
}

fn filtered_attribution_headers(
    request_head: &RequestHead,
    bridge_names: &BridgeNames,
    headers: Vec<(String, String)>,
) -> Vec<(String, String)> {
    let headers = headers
        .into_iter()
        .filter(|(name, value)| valid_attribution_header(name, value))
        .filter(|(name, _)| !name.eq_ignore_ascii_case("cookie"))
        .collect();
    let attribution = RequestHead {
        method: request_head.method.clone(),
        target: request_head.target.clone(),
        headers,
    };
    bridge::upstream_request_headers(&attribution, bridge_names, &RequestHeaderPolicy::ForwardAll)
}

fn valid_attribution_header(name: &str, value: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
        && !value.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0))
}

async fn handle_bootstrap(
    stream: &mut TcpStream,
    request_head: &RequestHead,
    capability: &str,
    port: u16,
    bridge_names: &BridgeNames,
) {
    if bridge::check_loopback_host(request_head, port).is_err() {
        log_capability_reject(RejectReason::BadHost);
        write_local(stream, 403, b"forbidden", "text/plain").await;
        return;
    }
    if request_head.method != "GET" {
        log_capability_reject(RejectReason::BadMethod);
        write_local(stream, 405, b"forbidden", "text/plain").await;
        return;
    }
    if bridge::check_caller_auth(request_head, bridge_names).is_err() {
        log_capability_reject(RejectReason::CallerAuth);
        write_local(stream, 403, b"forbidden", "text/plain").await;
        return;
    }

    #[expect(
        clippy::map_unwrap_or,
        reason = "the mapped capability comparison keeps absence and mismatch visibly equivalent"
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

async fn forward_buffered(
    stream: &mut TcpStream,
    runtime: &BridgeRuntime,
    request_head: &RequestHead,
    upstream_headers: &[(String, String)],
    body: &[u8],
) {
    let mut rx = match runtime
        .carrier
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

    let headers = bridge::response_headers(
        &head.headers,
        &runtime.journal_hosts,
        &runtime.loopback_origin,
        &runtime.bridge_names,
    );
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

async fn forward_streaming(
    stream: &mut TcpStream,
    runtime: &BridgeRuntime,
    request_head: &RequestHead,
    upstream_headers: &[(String, String)],
    body: &[u8],
) {
    let mut rx = match runtime
        .carrier
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
                    &runtime.journal_hosts,
                    &runtime.loopback_origin,
                    &runtime.bridge_names,
                );
                let content_length = (request_head.method == "HEAD")
                    .then(|| upstream_content_length(&head.headers).unwrap_or(0));
                if write_stream_head(stream, head.status, &headers, content_length)
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
                if request_head.method == "HEAD" {
                    continue;
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

async fn read_request(
    stream: &mut TcpStream,
    max_request_body_bytes: usize,
) -> Option<(Vec<u8>, Vec<u8>)> {
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
    if content_length > max_request_body_bytes {
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

fn log_local_request(request_head: &RequestHead, route: &'static str) {
    tracing::info!(
        target: "journal_bridge",
        method = request_head.method.as_str(),
        route,
        "local request"
    );
}

fn safe_content_type(content_type: &str) -> &str {
    if content_type.contains(['\r', '\n']) {
        "application/octet-stream"
    } else {
        content_type
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_policy_default_matches_current_bridge() {
        // This exhaustive pattern is the guard: adding any field, including a
        // bind address, makes the test fail to compile until reviewed.
        let BridgePolicy {
            port,
            capability_gate,
            stream_response,
            local_response,
            attribution_headers,
            request_headers,
            max_request_body_bytes,
        } = BridgePolicy::default();

        assert_eq!(port, 0);
        assert_eq!(capability_gate, CapabilityGate::Enabled);
        assert_eq!(
            request_headers,
            RequestHeaderPolicy::Allow(vec![
                "accept".to_string(),
                "accept-language".to_string(),
                "content-type".to_string(),
                "cache-control".to_string(),
                "if-none-match".to_string(),
                "if-modified-since".to_string(),
                "range".to_string(),
                "user-agent".to_string(),
            ])
        );
        assert_eq!(max_request_body_bytes, 8 * 1024 * 1024);

        let request = |method: &str, target: &str| RequestHead {
            method: method.to_string(),
            target: target.to_string(),
            headers: Vec::new(),
        };
        assert!(stream_response(&request("GET", "/sse/events")));
        assert!(!stream_response(&request("HEAD", "/sse/events")));
        assert!(!stream_response(&request("GET", "/other")));
        let status = JournalBridgeStatus {
            listener_active: true,
            contacted: true,
            carrier_live: false,
            active_requests: 1,
        };
        assert!(local_response(&request("GET", "/other"), &status).is_none());
        assert!(attribution_headers(&request("GET", "/other")).is_empty());
        assert_eq!(
            safe_content_type("text/plain\r\nx-injected: value"),
            "application/octet-stream"
        );
    }
}
