// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Hand-rolled configurable loopback proxy for consumer HTTP traffic.
//!
//! The default policy preserves the paired journal dashboard behavior:
//! ephemeral port, capability gate, streaming `GET /sse/events`, the existing
//! request-header allow-list, and an 8 MiB request-body limit. Disabling the
//! capability gate permits every method, while exact loopback `Host` validation
//! and bridge-reserved header stripping remain mandatory.
//!
//! Requests use known-length framing: at most one valid `Content-Length` (absent
//! means no body) and no `Transfer-Encoding`. Request bodies are streamed through
//! a fixed-size stage; carrier credit and bounded queues propagate backpressure to
//! the local socket. Once any request bytes are accepted by a carrier they are
//! never replayed. Application code owns retry and the associated idempotency
//! policy.
//!
//! Limitations: request bodies stream incrementally within a fixed per-stream
//! memory bound. Buffered upstream-response paths remain buffered, and
//! `connection::request_once` remains caller-buffered. Ordinary short bodies,
//! disconnects, and early responses are cancelled; fully saturated internal
//! queues rely on reserved capacity rather than an exhaustive scheduling contract.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};

use spl_core::bridge::{
    self, BOOTSTRAP_ROUTE, BridgeNames, FailureCategory, RejectReason, RequestFramingError,
    RequestHead, RequestHeaderPolicy,
};
use spl_core::mux::{StreamEnd, StreamItem};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, Interest};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};

use crate::client::DialedCarrier;
use crate::journal_bridge_carrier::{BodyTx, MuxCarrier, OpenedStream};
use crate::{TransportError, transport_error_code};

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
    join: JoinHandle<JournalBridgeStatus>,
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

    /// Request shutdown, wait for every accepted request task, and return the
    /// final quiescent status.
    pub async fn shutdown_and_wait(self) -> JournalBridgeStatus {
        let Self {
            status,
            shutdown,
            join,
            ..
        } = self;
        let _ = shutdown.send(());
        match join.await {
            Ok(snapshot) => snapshot,
            Err(_) => status_snapshot(&status),
        }
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
    let (connection_shutdown, connection_shutdown_rx) = watch::channel(false);

    let listener_guard = ListenerActiveGuard::new(status.clone());
    let join = tokio::spawn(accept_loop(
        listener,
        shutdown_rx,
        connection_shutdown,
        connection_shutdown_rx,
        runtime,
        listener_guard,
    ));

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
    connection_shutdown: watch::Sender<bool>,
    connection_shutdown_rx: watch::Receiver<bool>,
    runtime: Arc<BridgeRuntime>,
    listener_guard: ListenerActiveGuard,
) -> JournalBridgeStatus {
    let mut requests = JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                break;
            }
            Some(_) = requests.join_next(), if !requests.is_empty() => {}
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else {
                    continue;
                };
                let request_guard = ActiveRequestGuard::new(runtime.status.clone());
                requests.spawn(handle_conn(
                    stream,
                    runtime.clone(),
                    request_guard,
                    connection_shutdown_rx.clone(),
                ));
            }
        }
    }
    drop(listener);
    let _ = connection_shutdown.send(true);
    runtime.carrier.shutdown().await;
    while requests.join_next().await.is_some() {}
    drop(listener_guard);
    let snapshot = status_snapshot(&runtime.status);
    if snapshot.active_requests != 0 {
        tracing::error!(
            target: "journal_bridge",
            category = FailureCategory::UpstreamUnreachable.token(),
            code = "shutdown_not_quiescent",
            active_requests = snapshot.active_requests
        );
    }
    snapshot
}

async fn handle_conn(
    mut stream: TcpStream,
    runtime: Arc<BridgeRuntime>,
    _request_guard: ActiveRequestGuard,
    mut shutdown: watch::Receiver<bool>,
) {
    let Some(validated) = until_shutdown(
        &mut shutdown,
        read_validated_request_head(&mut stream, runtime.max_request_body_bytes),
    )
    .await
    else {
        return;
    };
    let Some(validated) = validated else {
        return;
    };
    let declared_body_len = validated.declared_body_len;
    let request_head = validated.head;
    let body_prefix = validated.body_prefix;
    let bootstrap_capability = runtime.capability.bootstrap_capability(request_head.path());

    if let Some(capability) = bootstrap_capability {
        log_local_request(&request_head, "bootstrap");
        let _ = until_shutdown(
            &mut shutdown,
            handle_bootstrap(
                &mut stream,
                &request_head,
                capability,
                runtime.port,
                &runtime.bridge_names,
            ),
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
        let _ = until_shutdown(
            &mut shutdown,
            write_local(&mut stream, status, b"forbidden", "text/plain"),
        )
        .await;
        return;
    }

    let snapshot = status_snapshot(&runtime.status);
    if let Some(response) = (runtime.local_response)(&request_head, &snapshot) {
        log_local_request(&request_head, "local");
        let content_type = safe_content_type(&response.content_type);
        let _ = until_shutdown(
            &mut shutdown,
            write_local(&mut stream, response.status, &response.body, content_type),
        )
        .await;
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
    let response_mode = if (runtime.stream_response)(&request_head) {
        ResponseMode::Streaming
    } else {
        ResponseMode::Buffered
    };
    let request = UpstreamRequest {
        head: &request_head,
        headers: &upstream_headers,
        body_prefix,
        declared_body_len,
        response_mode,
    };
    forward_upstream(stream, &runtime, request, &mut shutdown).await;
}

async fn until_shutdown<F>(shutdown: &mut watch::Receiver<bool>, future: F) -> Option<F::Output>
where
    F: Future,
{
    if *shutdown.borrow() {
        return None;
    }
    tokio::select! {
        biased;
        _ = shutdown.changed() => None,
        output = future => Some(output),
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

#[derive(Clone, Copy)]
enum ResponseMode {
    Buffered,
    Streaming,
}

struct LocalBodyUpload {
    sender: Option<BodyTx>,
    prefix: Vec<u8>,
    prefix_offset: usize,
    read_bytes: usize,
    declared_body_len: usize,
}

impl LocalBodyUpload {
    fn new(sender: BodyTx, mut prefix: Vec<u8>, declared_body_len: usize) -> Self {
        prefix.truncate(declared_body_len);
        let mut upload = Self {
            sender: Some(sender),
            prefix,
            prefix_offset: 0,
            read_bytes: 0,
            declared_body_len,
        };
        if declared_body_len == 0 {
            upload.sender.take();
        }
        upload
    }

    fn is_active(&self) -> bool {
        self.sender.is_some()
    }

    fn stop(&mut self) {
        self.sender.take();
    }

    async fn advance(&mut self, read: &mut OwnedReadHalf) -> Result<BodyAdvance, BodyAdvanceError> {
        let remaining = self.declared_body_len - self.read_bytes;
        if remaining == 0 {
            self.stop();
            return Ok(BodyAdvance::Complete);
        }
        let Some(sender) = self.sender.as_ref() else {
            return Ok(BodyAdvance::Complete);
        };

        if self.prefix_offset < self.prefix.len() {
            let count = (self.prefix.len() - self.prefix_offset).min(remaining);
            let reservation = sender
                .reserve(count)
                .await
                .map_err(BodyAdvanceError::Pipe)?;
            let bytes = self.prefix[self.prefix_offset..self.prefix_offset + count].to_vec();
            sender
                .send_reserved(reservation, bytes)
                .await
                .map_err(BodyAdvanceError::Pipe)?;
            self.prefix_offset += count;
            self.read_bytes += count;
        } else {
            let count = remaining.min(READ_BUF_BYTES);
            let reservation = reserve_or_closed(sender, read, count).await?;
            let Some(reservation) = reservation else {
                self.stop();
                return Ok(BodyAdvance::Short);
            };
            let mut bytes = vec![0u8; reservation.capacity()];
            let count = read
                .read(&mut bytes)
                .await
                .map_err(|_| BodyAdvanceError::Io)?;
            if count == 0 {
                self.stop();
                return Ok(BodyAdvance::Short);
            }
            bytes.truncate(count);
            sender
                .send_reserved(reservation, bytes)
                .await
                .map_err(BodyAdvanceError::Pipe)?;
            self.read_bytes += count;
        }

        if self.read_bytes == self.declared_body_len {
            self.stop();
            Ok(BodyAdvance::Complete)
        } else {
            Ok(BodyAdvance::Progress)
        }
    }
}

async fn reserve_or_closed(
    sender: &BodyTx,
    read: &OwnedReadHalf,
    bytes: usize,
) -> Result<Option<crate::journal_bridge_carrier::BodyReservation>, BodyAdvanceError> {
    let reservation = sender.reserve(bytes);
    tokio::pin!(reservation);
    tokio::select! {
        result = &mut reservation => result
            .map(Some)
            .map_err(BodyAdvanceError::Pipe),
        result = read.ready(Interest::READABLE) => {
            let ready = result.map_err(|_| BodyAdvanceError::Io)?;
            if ready.is_read_closed() {
                Ok(None)
            } else {
                reservation
                    .await
                    .map(Some)
                    .map_err(BodyAdvanceError::Pipe)
            }
        }
    }
}

enum BodyAdvance {
    Progress,
    Complete,
    Short,
}

enum BodyAdvanceError {
    Io,
    Pipe(TransportError),
}

enum DriverInput {
    Body(Result<BodyAdvance, BodyAdvanceError>),
    Upstream(Option<StreamItem>),
    Shutdown,
}

enum ResponseControl {
    Continue,
    Complete,
    Incomplete,
    Handled,
}

struct ResponseForwarder<'a> {
    write: OwnedWriteHalf,
    runtime: &'a BridgeRuntime,
    request_head: &'a RequestHead,
    mode: ResponseMode,
    head: Option<spl_core::mux::HttpHead>,
    body: Vec<u8>,
    head_written: bool,
}

impl<'a> ResponseForwarder<'a> {
    fn new(
        write: OwnedWriteHalf,
        runtime: &'a BridgeRuntime,
        request_head: &'a RequestHead,
        mode: ResponseMode,
    ) -> Self {
        Self {
            write,
            runtime,
            request_head,
            mode,
            head: None,
            body: Vec::new(),
            head_written: false,
        }
    }

    async fn handle(
        &mut self,
        item: StreamItem,
        rx: &mut crate::journal_bridge_carrier::StreamRx,
        upload: &mut LocalBodyUpload,
        shutdown: &mut watch::Receiver<bool>,
    ) -> ResponseControl {
        match item {
            StreamItem::Head(head) => self.handle_head(head, rx, upload, shutdown).await,
            StreamItem::Body(bytes) => self.handle_body(&bytes, rx, shutdown).await,
            StreamItem::End(StreamEnd::Close) => ResponseControl::Complete,
            StreamItem::End(StreamEnd::Reset(_) | StreamEnd::Eof) => ResponseControl::Incomplete,
        }
    }

    async fn handle_head(
        &mut self,
        head: spl_core::mux::HttpHead,
        rx: &mut crate::journal_bridge_carrier::StreamRx,
        upload: &mut LocalBodyUpload,
        shutdown: &mut watch::Receiver<bool>,
    ) -> ResponseControl {
        if matches!(head.status, 401 | 403) {
            tracing::warn!(
                target: "journal_bridge",
                category = FailureCategory::UpstreamCredential.token(),
                status = head.status
            );
        }
        if rx.early_final_status().is_some() {
            upload.stop();
            if (200..300).contains(&head.status) {
                log_upstream_io_failure();
                let _ = until_shutdown(
                    shutdown,
                    write_local(&mut self.write, 502, b"journal unreachable", "text/plain"),
                )
                .await;
            } else {
                let _ = until_shutdown(
                    shutdown,
                    write_early_failure(&mut self.write, self.runtime, self.request_head, &head),
                )
                .await;
            }
            return ResponseControl::Handled;
        }
        if matches!(self.mode, ResponseMode::Buffered) {
            self.head = Some(head);
            return ResponseControl::Continue;
        }

        let headers = bridge::response_headers(
            &head.headers,
            &self.runtime.journal_hosts,
            &self.runtime.loopback_origin,
            &self.runtime.bridge_names,
        );
        let content_length = (self.request_head.method == "HEAD")
            .then(|| upstream_content_length(&head.headers).unwrap_or(0));
        let write_result = until_shutdown(
            shutdown,
            write_stream_head(&mut self.write, head.status, &headers, content_length),
        )
        .await;
        if !matches!(write_result, Some(Ok(()))) {
            rx.cancel();
            return ResponseControl::Handled;
        }
        self.head_written = true;
        ResponseControl::Continue
    }

    async fn handle_body(
        &mut self,
        bytes: &[u8],
        rx: &mut crate::journal_bridge_carrier::StreamRx,
        shutdown: &mut watch::Receiver<bool>,
    ) -> ResponseControl {
        if matches!(self.mode, ResponseMode::Buffered) {
            self.body.extend_from_slice(bytes);
            return ResponseControl::Continue;
        }
        if !self.head_written {
            return ResponseControl::Complete;
        }
        if self.request_head.method == "HEAD" {
            return ResponseControl::Continue;
        }
        let write_result = until_shutdown(shutdown, async {
            self.write.write_all(bytes).await?;
            self.write.flush().await
        })
        .await;
        if !matches!(write_result, Some(Ok(()))) {
            rx.cancel();
            return ResponseControl::Handled;
        }
        ResponseControl::Continue
    }

    async fn finish(
        mut self,
        rx: &mut crate::journal_bridge_carrier::StreamRx,
        shutdown: &mut watch::Receiver<bool>,
    ) {
        if matches!(self.mode, ResponseMode::Streaming) {
            if self.head_written {
                let _ = until_shutdown(shutdown, self.write.shutdown()).await;
            } else {
                log_upstream_io_failure();
                let _ = until_shutdown(
                    shutdown,
                    write_local(&mut self.write, 502, b"journal unreachable", "text/plain"),
                )
                .await;
            }
            return;
        }

        let Some(head) = self.head else {
            log_upstream_io_failure();
            let _ = until_shutdown(
                shutdown,
                write_local(&mut self.write, 502, b"journal unreachable", "text/plain"),
            )
            .await;
            return;
        };
        if self.request_head.method != "HEAD"
            && upstream_content_length(&head.headers)
                .is_some_and(|declared| declared != self.body.len())
        {
            log_upstream_io_failure();
            let _ = until_shutdown(
                shutdown,
                write_local(&mut self.write, 502, b"journal unreachable", "text/plain"),
            )
            .await;
            return;
        }
        let headers = bridge::response_headers(
            &head.headers,
            &self.runtime.journal_hosts,
            &self.runtime.loopback_origin,
            &self.runtime.bridge_names,
        );
        let body = if self.request_head.method == "HEAD" {
            &[][..]
        } else {
            self.body.as_slice()
        };
        let content_length = if self.request_head.method == "HEAD" {
            upstream_content_length(&head.headers).unwrap_or(body.len())
        } else {
            body.len()
        };
        let write_result = until_shutdown(
            shutdown,
            write_upstream_response(
                &mut self.write,
                head.status,
                &headers,
                body,
                Some(content_length),
            ),
        )
        .await;
        if !matches!(write_result, Some(Ok(()))) {
            rx.cancel();
        }
    }

    async fn fail(
        mut self,
        rx: &mut crate::journal_bridge_carrier::StreamRx,
        shutdown: &mut watch::Receiver<bool>,
    ) {
        log_upstream_io_failure();
        rx.cancel();
        if matches!(self.mode, ResponseMode::Streaming) && self.head_written {
            let _ = until_shutdown(shutdown, self.write.shutdown()).await;
        } else {
            let _ = until_shutdown(
                shutdown,
                write_local(&mut self.write, 502, b"journal unreachable", "text/plain"),
            )
            .await;
        }
    }
}

struct UpstreamRequest<'a> {
    head: &'a RequestHead,
    headers: &'a [(String, String)],
    body_prefix: Vec<u8>,
    declared_body_len: usize,
    response_mode: ResponseMode,
}

async fn forward_upstream(
    stream: TcpStream,
    runtime: &BridgeRuntime,
    request: UpstreamRequest<'_>,
    shutdown: &mut watch::Receiver<bool>,
) {
    let opened = until_shutdown(
        shutdown,
        runtime.carrier.open_stream(
            &request.head.method,
            &request.head.target,
            request.headers,
            request.declared_body_len,
        ),
    )
    .await;
    let opened = match opened {
        None => return,
        Some(Ok(opened)) => opened,
        Some(Err(error)) => {
            log_upstream_open_error(&error);
            let mut stream = stream;
            let _ = until_shutdown(
                shutdown,
                write_local(&mut stream, 502, b"journal unreachable", "text/plain"),
            )
            .await;
            return;
        }
    };
    let OpenedStream {
        body,
        response: mut rx,
    } = opened;
    let (mut read, write) = stream.into_split();
    let mut upload = LocalBodyUpload::new(body, request.body_prefix, request.declared_body_len);
    let mut forwarder = ResponseForwarder::new(write, runtime, request.head, request.response_mode);
    let completed = loop {
        let input = if upload.is_active() {
            tokio::select! {
                biased;
                _ = shutdown.changed() => DriverInput::Shutdown,
                item = rx.recv() => DriverInput::Upstream(item),
                result = upload.advance(&mut read) => DriverInput::Body(result),
            }
        } else {
            tokio::select! {
                biased;
                _ = shutdown.changed() => DriverInput::Shutdown,
                item = rx.recv() => DriverInput::Upstream(item),
            }
        };

        let item = match input {
            DriverInput::Shutdown => {
                upload.stop();
                rx.cancel();
                return;
            }
            DriverInput::Body(Ok(BodyAdvance::Progress | BodyAdvance::Complete)) => continue,
            DriverInput::Body(Ok(BodyAdvance::Short)) => {
                rx.cancel();
                let _ = until_shutdown(
                    shutdown,
                    write_local(&mut forwarder.write, 400, b"bad request", "text/plain"),
                )
                .await;
                return;
            }
            DriverInput::Body(Err(BodyAdvanceError::Io)) => {
                rx.cancel();
                return;
            }
            DriverInput::Body(Err(BodyAdvanceError::Pipe(error))) => {
                log_upstream_open_error(&error);
                upload.stop();
                continue;
            }
            DriverInput::Upstream(item) => item,
        };
        let Some(item) = item else {
            break false;
        };
        match forwarder.handle(item, &mut rx, &mut upload, shutdown).await {
            ResponseControl::Continue => {}
            ResponseControl::Complete => break true,
            ResponseControl::Incomplete => break false,
            ResponseControl::Handled => return,
        }
    };
    upload.stop();
    if completed {
        forwarder.finish(&mut rx, shutdown).await;
    } else {
        forwarder.fail(&mut rx, shutdown).await;
    }
}

async fn write_early_failure(
    write: &mut OwnedWriteHalf,
    runtime: &BridgeRuntime,
    request_head: &RequestHead,
    head: &spl_core::mux::HttpHead,
) {
    let headers = bridge::response_headers(
        &head.headers,
        &runtime.journal_hosts,
        &runtime.loopback_origin,
        &runtime.bridge_names,
    );
    let content_length = if request_head.method == "HEAD" {
        upstream_content_length(&head.headers).unwrap_or(0)
    } else {
        0
    };
    let _ = write_upstream_response(write, head.status, &headers, &[], Some(content_length)).await;
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

fn log_upstream_io_failure() {
    tracing::warn!(
        target: "journal_bridge",
        category = FailureCategory::UpstreamUnreachable.token(),
        code = "io"
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestReadError {
    Io,
    Invalid,
}

struct ValidatedLocalRequestHead {
    head: RequestHead,
    declared_body_len: usize,
    body_prefix: Vec<u8>,
}

async fn read_validated_request_head(
    stream: &mut TcpStream,
    max_request_body_bytes: usize,
) -> Option<ValidatedLocalRequestHead> {
    let (head_bytes, body_prefix) = match read_request_head(stream).await {
        Ok(request) => request,
        Err(RequestReadError::Invalid) => {
            write_local(stream, 400, b"bad request", "text/plain").await;
            return None;
        }
        Err(RequestReadError::Io) => return None,
    };
    let validated = match bridge::parse_request_head(&head_bytes) {
        Ok(validated) => validated,
        Err(error) => {
            let status = framing_error_status(error);
            let body = if status == 417 {
                b"expectation failed".as_slice()
            } else {
                b"bad request".as_slice()
            };
            write_local(stream, status, body, "text/plain").await;
            return None;
        }
    };
    if validated.content_length > max_request_body_bytes {
        write_local(stream, 413, b"payload too large", "text/plain").await;
        return None;
    }
    Some(ValidatedLocalRequestHead {
        head: validated.head,
        declared_body_len: validated.content_length,
        body_prefix,
    })
}

async fn read_request_head(stream: &mut TcpStream) -> Result<(Vec<u8>, Vec<u8>), RequestReadError> {
    let mut received = Vec::new();
    let mut buf = [0u8; READ_BUF_BYTES];
    loop {
        let remaining = bridge::MAX_REQUEST_HEAD_BYTES - received.len();
        if remaining == 0 {
            return Err(RequestReadError::Invalid);
        }
        let read_bound = remaining.min(READ_BUF_BYTES);
        let n = stream
            .read(&mut buf[..read_bound])
            .await
            .map_err(|_| RequestReadError::Io)?;
        if n == 0 {
            return Err(RequestReadError::Invalid);
        }
        received.extend_from_slice(&buf[..n]);
        if let Some(split) = find_header_end(&received) {
            let body_start = split + 4;
            let body = received[body_start..].to_vec();
            received.truncate(body_start);
            return Ok((received, body));
        }
    }
}

fn framing_error_status(error: RequestFramingError) -> u16 {
    match error {
        RequestFramingError::HeadTooLarge
        | RequestFramingError::MissingTerminator
        | RequestFramingError::InvalidEncoding
        | RequestFramingError::InvalidRequestLine
        | RequestFramingError::InvalidHeader
        | RequestFramingError::TransferEncoding
        | RequestFramingError::DuplicateContentLength
        | RequestFramingError::InvalidContentLength => 400,
        RequestFramingError::Expectation => 417,
    }
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

async fn write_local<W>(stream: &mut W, status: u16, body: &[u8], content_type: &str)
where
    W: AsyncWrite + Unpin,
{
    let response = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reason_phrase(status),
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.write_all(body).await;
    let _ = stream.shutdown().await;
}

async fn write_upstream_response<W>(
    stream: &mut W,
    status: u16,
    headers: &[(String, String)],
    body: &[u8],
    content_length: Option<usize>,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
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

async fn write_stream_head<W>(
    stream: &mut W,
    status: u16,
    headers: &[(String, String)],
    content_length: Option<usize>,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
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
        413 => "Payload Too Large",
        417 => "Expectation Failed",
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
