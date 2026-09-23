// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Hand-rolled configurable loopback proxy for consumer HTTP traffic.
//!
//! The default policy preserves the paired journal dashboard behavior:
//! ephemeral port, capability gate, streaming `GET /sse/events`, and an 8 MiB
//! request-body limit. The capability and the exact loopback `Host` are the
//! whole admission check: a caller holding the capability is the consumer's own
//! code, so every method and every header the bridge does not reserve is
//! forwarded. Disabling the capability gate leaves only the `Host` check, and
//! bridge-reserved header stripping applies either way.
//!
//! Requests use known-length framing: at most one valid `Content-Length` (absent
//! means no body) and no `Transfer-Encoding`. Request bodies are streamed through
//! a fixed-size stage; carrier credit and bounded queues propagate backpressure to
//! the local socket. Once any request bytes are accepted by a carrier they are
//! never replayed. Application code owns retry and the associated idempotency
//! policy.
//!
//! A streamed response whose upstream declared a body length keeps that length,
//! so a caller can tell a body that ended early from a complete one; a streamed
//! body with no declared length, such as `GET /sse/events`, stays delimited by
//! the connection close. A failed dial is always a local `502`; the bridge's
//! status says whether the journal was reached and how it refused.
//!
//! Limitations: request bodies stream incrementally within a fixed per-stream
//! memory bound. Buffered upstream-response paths remain buffered, and
//! `connection::request_once` remains caller-buffered. Ordinary short bodies,
//! disconnects, and early responses are cancelled; fully saturated internal
//! queues rely on reserved capacity rather than an exhaustive scheduling contract.

use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};

use spl_core::bridge::{
    self, BOOTSTRAP_ROUTE, BridgeNames, FailureCategory, RejectReason, RequestFramingError,
    RequestHead,
};
use spl_core::mux::{StreamEnd, StreamItem};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, Interest};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};

use crate::client::DialedCarrier;
use crate::handshake::RefusalTracker;
use crate::journal_bridge_carrier::{BodyTx, MuxCarrier, OpenedStream};
use crate::{TransportError, transport_error_code};

const READ_BUF_BYTES: usize = 4096;

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
///
/// The bridge's local HTTP answer to a failed dial is always `502`. These
/// fields carry what that answer cannot: whether the journal was reached, and
/// how it refused. They implement the client half of the SPL session
/// protocol's handshake-refusal rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalBridgeStatus {
    /// Whether the loopback listener task has not exited.
    pub listener_active: bool,
    /// Whether the listener has accepted at least one TCP connection.
    pub contacted: bool,
    /// Whether the current persistent carrier is live.
    pub carrier_live: bool,
    /// Why the bridge stopped dialing, if it has. Latched once and never
    /// cleared; only access denied (49) and an exhausted refusal bound latch.
    /// Certificate unknown (46) never latches.
    pub terminal_reason: Option<JournalBridgeTerminalReason>,
    /// How the most recent carrier attempt failed, if the journal has not
    /// accepted a carrier since. Cleared when the journal accepts one.
    pub last_failure: Option<JournalBridgeFailure>,
    /// Refusals counted toward [`JournalBridgeTerminalReason::RefusalsExhausted`]
    /// since the journal last accepted a carrier. See [`REFUSAL_LIMIT`].
    pub refusals: u32,
    /// Accepted connection tasks that have not completed.
    pub active_requests: usize,
}

/// Why a journal bridge stopped dialing; latched once and never cleared.
pub type JournalBridgeTerminalReason = HandshakeStop;

/// How one attempt to reach the journal failed.
pub type JournalBridgeFailure = HandshakeFailure;

pub use crate::handshake::{HandshakeFailure, HandshakeStop, REFUSAL_LIMIT, REFUSAL_SPACING};

const STATUS_EVENT_CAPACITY: usize = 64;

pub(crate) struct StatusState {
    record: Mutex<StatusRecord>,
    events: broadcast::Sender<JournalBridgeStatus>,
}

pub(crate) type SharedStatus = Arc<StatusState>;

pub(crate) struct StatusRecord {
    pub(crate) snapshot: JournalBridgeStatus,
    pub(crate) current_carrier: Option<Arc<()>>,
    refusals: RefusalTracker,
    /// The newest carrier attempt; outcomes of older attempts are ignored.
    attempt: u64,
}

impl StatusRecord {
    fn publish_refusals(&mut self) {
        self.snapshot.terminal_reason = self.refusals.stop();
        self.snapshot.last_failure = self.refusals.last_failure();
        self.snapshot.refusals = self.refusals.refusals();
    }
}

pub(crate) struct StatusGuard<'a> {
    guard: MutexGuard<'a, StatusRecord>,
    events: &'a broadcast::Sender<JournalBridgeStatus>,
    initial: JournalBridgeStatus,
}

impl Deref for StatusGuard<'_> {
    type Target = StatusRecord;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl DerefMut for StatusGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

impl Drop for StatusGuard<'_> {
    fn drop(&mut self) {
        if self.guard.snapshot != self.initial {
            let _ = self.events.send(self.guard.snapshot);
        }
    }
}

pub(crate) fn lock_status(status: &SharedStatus) -> StatusGuard<'_> {
    let guard = match status.record.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let initial = guard.snapshot;
    StatusGuard {
        guard,
        events: &status.events,
        initial,
    }
}

pub(crate) fn new_status() -> SharedStatus {
    let snapshot = JournalBridgeStatus {
        listener_active: false,
        contacted: false,
        carrier_live: false,
        terminal_reason: None,
        last_failure: None,
        refusals: 0,
        active_requests: 0,
    };
    let (events, _) = broadcast::channel(STATUS_EVENT_CAPACITY);
    Arc::new(StatusState {
        record: Mutex::new(StatusRecord {
            snapshot,
            current_carrier: None,
            refusals: RefusalTracker::new(),
            attempt: 0,
        }),
        events,
    })
}

/// Stop the bridge for access denied, whether or not the attempt was resolved.
pub(crate) fn latch_tls_access_denied(status: &SharedStatus) {
    let mut record = lock_status(status);
    record.refusals.deny();
    record.publish_refusals();
}

/// Start a carrier attempt; its outcome counts only while no newer attempt has started.
pub(crate) fn begin_carrier_attempt(status: &SharedStatus) -> u64 {
    let mut record = lock_status(status);
    record.attempt = record.attempt.wrapping_add(1);
    record.attempt
}

/// Record that the journal accepted a carrier: only this clears the refusal count.
pub(crate) fn record_carrier_accepted(status: &SharedStatus, attempt: u64) {
    let mut record = lock_status(status);
    if record.attempt != attempt {
        return;
    }
    record.refusals.accepted();
    record.publish_refusals();
}

/// Record how one carrier attempt failed.
pub(crate) fn record_carrier_failure(
    status: &SharedStatus,
    attempt: u64,
    failure: HandshakeFailure,
) {
    let mut record = lock_status(status);
    if record.attempt != attempt {
        return;
    }
    record.refusals.failed(failure);
    record.publish_refusals();
}

fn status_snapshot(status: &SharedStatus) -> JournalBridgeStatus {
    lock_status(status).snapshot
}

fn status_subscription(status: &SharedStatus) -> JournalBridgeStatusSubscription {
    let record = lock_status(status);
    let receiver = status.events.subscribe();
    JournalBridgeStatusSubscription {
        initial: record.snapshot,
        receiver,
    }
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

/// Ordered status stream for one bridge.
///
/// The initial snapshot and receiver are captured under the same status lock.
/// A slow consumer receives an explicit [`broadcast::error::RecvError::Lagged`]
/// instead of silently missing a carrier transition.
pub struct JournalBridgeStatusSubscription {
    initial: JournalBridgeStatus,
    receiver: broadcast::Receiver<JournalBridgeStatus>,
}

impl JournalBridgeStatusSubscription {
    /// Status at the instant the subscription was created.
    pub fn initial(&self) -> JournalBridgeStatus {
        self.initial
    }

    /// Receive the next ordered status transition.
    ///
    /// # Errors
    ///
    /// Returns `Closed` after the bridge drops its sender, or `Lagged` with the
    /// exact number of skipped transitions when the bounded receiver falls behind.
    pub async fn recv(&mut self) -> Result<JournalBridgeStatus, broadcast::error::RecvError> {
        self.receiver.recv().await
    }
}

/// Cloneable read access to one bridge's status, for code that does not own
/// the bridge handle.
#[derive(Clone)]
pub struct JournalBridgeStatusReader {
    status: SharedStatus,
}

impl JournalBridgeStatusReader {
    /// Return one coherent owned bridge-status snapshot.
    pub fn status(&self) -> JournalBridgeStatus {
        status_snapshot(&self.status)
    }

    /// Subscribe to ordered status transitions without a snapshot/subscription race.
    pub fn subscribe(&self) -> JournalBridgeStatusSubscription {
        status_subscription(&self.status)
    }
}

impl JournalBridgeHandle {
    /// Return cloneable read access to this bridge's status.
    pub fn status_reader(&self) -> JournalBridgeStatusReader {
        JournalBridgeStatusReader {
            status: self.status.clone(),
        }
    }

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

    /// Subscribe to ordered status transitions without a snapshot/subscription race.
    pub fn subscribe_status(&self) -> JournalBridgeStatusSubscription {
        status_subscription(&self.status)
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
        let _ = until_shutdown(
            &mut shutdown,
            write_local(&mut stream, 403, b"forbidden", "text/plain"),
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
    let mut upstream_headers =
        bridge::upstream_request_headers(&request_head, &runtime.bridge_names);
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
    bridge::upstream_request_headers(&attribution, bridge_names)
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
    /// Body length a streamed response declared to the local caller.
    declared_len: Option<usize>,
    /// Body bytes a streamed response with a declared length has received.
    received_len: usize,
    /// The final declared byte, written only once the journal ends the stream
    /// cleanly, so an early or overlong end always leaves the body short.
    held_last: Option<u8>,
    /// The head of a streamed response that declared an empty body, written
    /// only once the journal ends the stream, so an unexpected body can still
    /// become a local 502.
    deferred_head: Option<(u16, Vec<(String, String)>)>,
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
            declared_len: None,
            received_len: 0,
            held_last: None,
            deferred_head: None,
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
        // A finite streamed body keeps the length the journal declared, so a
        // caller can tell a body that ended early from a complete one. A body
        // with no declared length, such as an event stream, stays delimited by
        // the connection close. `response_headers` has already removed the
        // upstream field, so this is the only length header written.
        let content_length = if self.request_head.method == "HEAD" {
            Some(upstream_content_length(&head.headers).unwrap_or(0))
        } else if status_permits_body(head.status) && !has_transfer_encoding(&head.headers) {
            upstream_content_length(&head.headers)
        } else {
            None
        };
        if self.request_head.method != "HEAD" {
            self.declared_len = content_length;
            if content_length == Some(0) {
                self.deferred_head = Some((head.status, headers));
                return ResponseControl::Continue;
            }
        }
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
        if self.deferred_head.is_some() {
            // A body after an empty declaration: the head is still unwritten,
            // so this becomes a local 502.
            return if bytes.is_empty() {
                ResponseControl::Continue
            } else {
                ResponseControl::Incomplete
            };
        }
        if !self.head_written {
            return ResponseControl::Complete;
        }
        if self.request_head.method == "HEAD" {
            return ResponseControl::Continue;
        }
        let mut writable = bytes;
        if let Some(declared) = self.declared_len {
            let received = self.received_len.saturating_add(bytes.len());
            if received > declared {
                // More body than the journal declared. Never write past the
                // declared length, and never write the held final byte, so
                // the caller sees the body as incomplete.
                log_upstream_io_failure();
                rx.cancel();
                let _ = until_shutdown(shutdown, self.write.shutdown()).await;
                return ResponseControl::Handled;
            }
            self.received_len = received;
            if received == declared
                && let Some((&last, rest)) = bytes.split_last()
            {
                self.held_last = Some(last);
                writable = rest;
            }
        }
        if writable.is_empty() {
            return ResponseControl::Continue;
        }
        let write_result = until_shutdown(shutdown, async {
            self.write.write_all(writable).await?;
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
            if let Some((status, headers)) = self.deferred_head.take() {
                let _ = until_shutdown(shutdown, async {
                    write_stream_head(&mut self.write, status, &headers, Some(0)).await?;
                    self.write.shutdown().await
                })
                .await;
            } else if self.head_written {
                let complete = self
                    .declared_len
                    .is_none_or(|declared| declared == self.received_len);
                if complete {
                    if let Some(last) = self.held_last.take() {
                        let _ = until_shutdown(shutdown, async {
                            self.write.write_all(&[last]).await?;
                            self.write.flush().await
                        })
                        .await;
                    }
                } else {
                    // The journal closed the stream before its declared length.
                    // The declared length already makes this visible to the caller.
                    log_upstream_io_failure();
                }
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

/// Whether the upstream framed its body with a transfer coding, which takes
/// precedence over any length it also declared.
fn has_transfer_encoding(headers: &[(String, String)]) -> bool {
    headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("transfer-encoding"))
}

/// Whether a response with this status can carry a body, and so a length.
fn status_permits_body(status: u16) -> bool {
    !matches!(status, 100..=199 | 204 | 304)
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
            max_request_body_bytes,
        } = BridgePolicy::default();

        assert_eq!(port, 0);
        assert_eq!(capability_gate, CapabilityGate::Enabled);
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
            terminal_reason: None,
            last_failure: None,
            refusals: 0,
            active_requests: 1,
        };
        assert!(local_response(&request("GET", "/other"), &status).is_none());
        assert!(attribution_headers(&request("GET", "/other")).is_empty());
        assert_eq!(
            safe_content_type("text/plain\r\nx-injected: value"),
            "application/octet-stream"
        );
    }

    // Falsified by publishing the tracker without its stop: a latched refusal never reaches the
    // status a consumer reads.
    #[test]
    fn status_publishes_the_refusal_state() {
        let status = new_status();
        let first = begin_carrier_attempt(&status);
        record_carrier_failure(&status, first, HandshakeFailure::TlsRefused);
        let snapshot = status_snapshot(&status);
        assert_eq!(snapshot.last_failure, Some(HandshakeFailure::TlsRefused));
        assert_eq!(snapshot.refusals, 1);
        assert_eq!(snapshot.terminal_reason, None);

        record_carrier_failure(&status, first, HandshakeFailure::TlsCertificateUnknown);
        assert_eq!(
            status_snapshot(&status).last_failure,
            Some(HandshakeFailure::TlsCertificateUnknown)
        );
        assert_eq!(status_snapshot(&status).refusals, 1);

        record_carrier_accepted(&status, first);
        let snapshot = status_snapshot(&status);
        assert_eq!((snapshot.last_failure, snapshot.refusals), (None, 0));

        latch_tls_access_denied(&status);
        record_carrier_accepted(&status, first);
        assert_eq!(
            status_snapshot(&status).terminal_reason,
            Some(JournalBridgeTerminalReason::TlsAccessDenied)
        );
    }

    // Falsified by recording every outcome: a superseded carrier's late failure would overwrite
    // the newer carrier's accepted state.
    #[test]
    fn a_superseded_attempt_cannot_overwrite_a_newer_one() {
        let status = new_status();
        let old = begin_carrier_attempt(&status);
        let new = begin_carrier_attempt(&status);
        record_carrier_accepted(&status, new);
        record_carrier_failure(&status, old, HandshakeFailure::TlsRefused);
        record_carrier_failure(&status, old, HandshakeFailure::Unreachable);
        let snapshot = status_snapshot(&status);
        assert_eq!((snapshot.last_failure, snapshot.refusals), (None, 0));

        record_carrier_failure(&status, new, HandshakeFailure::TlsRefused);
        assert_eq!(status_snapshot(&status).refusals, 1);
        record_carrier_accepted(&status, old);
        assert_eq!(status_snapshot(&status).refusals, 1);
    }

    #[tokio::test]
    async fn status_reader_sees_the_same_status_as_its_bridge() {
        let status = new_status();
        let reader = JournalBridgeStatusReader {
            status: status.clone(),
        };
        let mut subscription = reader.subscribe();
        let attempt = begin_carrier_attempt(&status);
        record_carrier_failure(&status, attempt, HandshakeFailure::TlsAccessDenied);
        assert_eq!(
            reader.status().terminal_reason,
            Some(JournalBridgeTerminalReason::TlsAccessDenied)
        );
        assert_eq!(
            subscription.recv().await.unwrap().terminal_reason,
            Some(JournalBridgeTerminalReason::TlsAccessDenied)
        );
    }

    #[tokio::test]
    async fn status_subscription_preserves_transient_carrier_edges_in_order() {
        let status = new_status();
        let mut subscription = status_subscription(&status);
        assert!(!subscription.initial().carrier_live);

        lock_status(&status).snapshot.carrier_live = true;
        lock_status(&status).snapshot.carrier_live = false;
        lock_status(&status).snapshot.carrier_live = true;

        assert!(subscription.recv().await.unwrap().carrier_live);
        assert!(!subscription.recv().await.unwrap().carrier_live);
        assert!(subscription.recv().await.unwrap().carrier_live);
    }
}
