// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Home-owned relay attachment and per-stream loopback forwarding.

use std::fmt;
use std::future::Future;
use std::io;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::StreamExt;
use spl_core::relay::{ListenControl, listen_url, parse_listen_control, tunnel_url};
use spl_home::{HomeConfig, HomeConnection, HomeStream, ResetReason};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep, timeout};
use tokio_tungstenite::tungstenite::Message;

use crate::relay::{RELAY_HANDSHAKE_TIMEOUT, WsByteDuplex};
use crate::{RelayError, TransportError};

/// A service credential that cannot be formatted or compared.
///
/// ```compile_fail
/// let token = spl_transport::home_relay::ServiceToken::new("secret".into());
/// let _ = format!("{:?}", token);
/// ```
///
/// ```compile_fail
/// let token = spl_transport::home_relay::ServiceToken::new("secret".into());
/// let _ = format!("{}", token);
/// ```
pub struct ServiceToken(String);

impl ServiceToken {
    /// Wrap a service credential for authenticated relay requests.
    #[must_use]
    pub const fn new(value: String) -> Self {
        Self(value)
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for ServiceToken {
    fn drop(&mut self) {
        let mut bytes = std::mem::take(&mut self.0).into_bytes();
        bytes.fill(0);
    }
}

/// Supplies normalized reconnect jitter samples in the inclusive 0.0 through 1.0 range.
pub trait RelayJitter: Send + Sync {
    /// Return one normalized sample for a reconnect delay.
    fn sample(&self) -> f64;
}

/// Owner-visible home relay state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayHealthState {
    /// A listen connection is being established.
    Connecting,
    /// The listen WebSocket is established.
    Connected,
    /// A disconnected listen WebSocket is waiting to reconnect.
    Reconnecting,
}

/// A classified tunnel failure without journal-facing reason strings.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RelayTunnelFailure {
    /// The relay reported no matching mobile tunnel.
    HomeMissingMobile,
    /// The relay rejected the service credential.
    ServiceTokenRejected,
    /// The relay rejected the tunnel with another HTTP status.
    RelayTunnelRejected {
        /// Relay HTTP status.
        status: u16,
    },
    /// No usable relay tunnel transport was established.
    RelayTunnelUnreachable,
    /// The configured local application listener could not be reached.
    LocalPrivateListenerUnreachable,
}

/// The relay-attachment phase in which a tunnel failure occurred.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayTunnelPhase {
    /// Opening the home tunnel WebSocket.
    Dial,
    /// Reading the non-consuming TLS record prefix.
    Prefix,
    /// Terminating inner TLS and accepting its mux carrier.
    InnerHandshake,
    /// Connecting to or pumping the local application socket.
    LocalSocket,
}

impl RelayTunnelFailure {
    /// Return the relay rejection status when one was observed.
    #[must_use]
    pub const fn status(self) -> Option<u16> {
        match self {
            Self::RelayTunnelRejected { status } => Some(status),
            Self::HomeMissingMobile
            | Self::ServiceTokenRejected
            | Self::RelayTunnelUnreachable
            | Self::LocalPrivateListenerUnreachable => None,
        }
    }
}

impl fmt::Debug for RelayTunnelFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HomeMissingMobile => formatter.write_str("HomeMissingMobile"),
            Self::ServiceTokenRejected => formatter.write_str("ServiceTokenRejected"),
            Self::RelayTunnelRejected { status } => formatter
                .debug_struct("RelayTunnelRejected")
                .field("status", status)
                .finish(),
            Self::RelayTunnelUnreachable => formatter.write_str("RelayTunnelUnreachable"),
            Self::LocalPrivateListenerUnreachable => {
                formatter.write_str("LocalPrivateListenerUnreachable")
            }
        }
    }
}

/// Typed owner-visible relay health snapshot.
#[derive(Clone, PartialEq, Eq)]
pub struct RelayHealth {
    state: RelayHealthState,
    listen_generation: u64,
    last_successful_tunnel_at_ms: Option<u64>,
    last_failure: Option<RelayTunnelFailure>,
    last_failure_at_ms: Option<u64>,
    admission_saturated_count: u64,
}

impl RelayHealth {
    fn new() -> Self {
        Self {
            state: RelayHealthState::Connecting,
            listen_generation: 0,
            last_successful_tunnel_at_ms: None,
            last_failure: None,
            last_failure_at_ms: None,
            admission_saturated_count: 0,
        }
    }

    /// Return the current listen state.
    #[must_use]
    pub const fn state(&self) -> RelayHealthState {
        self.state
    }
    /// Return the number of started listen attempts.
    #[must_use]
    pub const fn listen_generation(&self) -> u64 {
        self.listen_generation
    }
    /// Return the timestamp recorded for the most recent successful tunnel.
    #[must_use]
    pub const fn last_successful_tunnel_at_ms(&self) -> Option<u64> {
        self.last_successful_tunnel_at_ms
    }
    /// Return the most recent typed tunnel failure.
    #[must_use]
    pub const fn last_failure(&self) -> Option<RelayTunnelFailure> {
        self.last_failure
    }
    /// Return the timestamp recorded for the most recent tunnel failure.
    #[must_use]
    pub const fn last_failure_at_ms(&self) -> Option<u64> {
        self.last_failure_at_ms
    }
    /// Return the cumulative admission saturation count.
    #[must_use]
    pub const fn admission_saturated_count(&self) -> u64 {
        self.admission_saturated_count
    }
}

impl fmt::Debug for RelayHealth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayHealth")
            .field("state", &self.state)
            .field("listen_generation", &self.listen_generation)
            .field(
                "last_successful_tunnel_at_ms",
                &self.last_successful_tunnel_at_ms,
            )
            .field("last_failure", &self.last_failure)
            .field("last_failure_at_ms", &self.last_failure_at_ms)
            .field("admission_saturated_count", &self.admission_saturated_count)
            .finish()
    }
}

/// A typed event emitted by the home relay client.
pub enum RelayEvent {
    /// A listen connection attempt started.
    Connecting,
    /// The listen WebSocket connected.
    Connected,
    /// The listen WebSocket disconnected.
    Disconnected,
    /// Relay configuration prevented opening a listen connection.
    ConfigurationFailure,
    /// Prefix admission was saturated.
    AdmissionSaturated {
        /// Cumulative number of admission refusals.
        count: u64,
    },
    /// A tunnel did not begin with a TLS `ClientHello` record.
    TunnelUnknownPrefix,
    /// The relay offered a tunnel.
    TunnelPaired {
        /// Relay-assigned opaque tunnel identifier.
        tunnel_id: String,
    },
    /// Tunnel processing ended.
    TunnelClosed {
        /// Relay-assigned opaque tunnel identifier.
        tunnel_id: String,
    },
    /// Tunnel processing failed in a classified attachment phase.
    TunnelFailure {
        /// Phase that failed.
        phase: RelayTunnelPhase,
        /// Secret-free failure classification.
        failure: RelayTunnelFailure,
    },
    /// Relay health changed.
    Health(RelayHealth),
}

impl fmt::Debug for RelayEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connecting => formatter.write_str("Connecting"),
            Self::Connected => formatter.write_str("Connected"),
            Self::Disconnected => formatter.write_str("Disconnected"),
            Self::ConfigurationFailure => formatter.write_str("ConfigurationFailure"),
            Self::AdmissionSaturated { count } => formatter
                .debug_struct("AdmissionSaturated")
                .field("count", count)
                .finish(),
            Self::TunnelUnknownPrefix => formatter.write_str("TunnelUnknownPrefix"),
            Self::TunnelPaired { tunnel_id } => formatter
                .debug_struct("TunnelPaired")
                .field("tunnel_id", &RedactedId(tunnel_id))
                .finish(),
            Self::TunnelClosed { tunnel_id } => formatter
                .debug_struct("TunnelClosed")
                .field("tunnel_id", &RedactedId(tunnel_id))
                .finish(),
            Self::TunnelFailure { phase, failure } => formatter
                .debug_struct("TunnelFailure")
                .field("phase", phase)
                .field("failure", failure)
                .finish(),
            Self::Health(health) => formatter.debug_tuple("Health").field(health).finish(),
        }
    }
}

struct RedactedId<'a>(&'a str);

impl fmt::Debug for RedactedId<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = self.0.len();
        formatter.write_str("[REDACTED]")
    }
}

/// Receives typed, secret-free home relay events.
pub trait RelayEventSink: Send + Sync {
    /// Receive one typed relay event.
    fn emit(&self, event: RelayEvent);
}

/// Configuration for one home relay attachment client.
pub struct HomeRelayClientConfig {
    /// Relay HTTP or HTTPS origin.
    pub relay_origin: String,
    /// Service credential used only in authenticated request headers.
    pub service_token: ServiceToken,
    /// Inner TLS and mux listener configuration.
    pub home_config: HomeConfig,
    /// Local application port on literal IPv4 loopback.
    pub app_port: u16,
    /// Absolute limit for collecting the non-consuming four-byte TLS prefix.
    pub dispatch_read_deadline: Duration,
    /// Operator policy cap for concurrently prefix-peeking tunnels.
    ///
    /// This required, non-zero value is home-operator policy; the protocol has
    /// no default or clause for it.
    pub admission_ceiling: NonZeroUsize,
    /// Consumer-supplied jitter source for deterministic testability.
    pub jitter: Arc<dyn RelayJitter>,
    /// Consumer-owned receiver of typed relay events.
    pub events: Arc<dyn RelayEventSink>,
}

/// A relay client whose active tunnel work can be stopped separately from its listen task.
pub trait RelayStop {
    /// Error returned by stop.
    type Error: std::error::Error + Send + Sync + 'static;
    /// Stop active tunnel work without closing the externally supervised listen task.
    ///
    /// # Errors
    ///
    /// Returns the implementation's classified stop error.
    fn stop(&mut self) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;
}

/// Schedules a reconnect delay from the current base and injected jitter sample.
///
/// Protocol: `.proto-ref/session.md`, lines 319-325.
///
/// Returns `None` when `jitter` is not finite or falls outside 0.0 through 1.0.
pub fn schedule_reconnect(current_base: Duration, jitter: f64) -> Option<(Duration, Duration)> {
    if !jitter.is_finite() || !(0.0..=1.0).contains(&jitter) {
        return None;
    }
    let base = current_base.clamp(Duration::from_secs(1), Duration::from_mins(1));
    #[expect(
        clippy::cast_precision_loss,
        clippy::cast_sign_loss,
        reason = "the bounded one-minute reconnect base keeps rounded jittered nanoseconds below u64"
    )]
    let delay =
        Duration::from_nanos(((base.as_nanos() as f64) * (0.75 + jitter * 0.5)).round() as u64);
    Some((base.saturating_mul(2).min(Duration::from_mins(1)), delay))
}

fn base_after_connection(current_base: Duration, established_for: Duration) -> Duration {
    if established_for >= Duration::from_mins(1) {
        Duration::ZERO
    } else {
        current_base
    }
}

struct Admission {
    ceiling: usize,
    count: Mutex<(usize, u64)>,
}
impl Admission {
    fn acquire(&self) -> bool {
        let mut state = self
            .count
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.0 < self.ceiling {
            state.0 += 1;
            true
        } else {
            state.1 = state.1.saturating_add(1);
            false
        }
    }
    fn release(&self) {
        let mut state = self
            .count
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.0 = state.0.saturating_sub(1);
    }
    fn saturated(&self) -> u64 {
        self.count
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .1
    }
}

/// Home-side relay attachment client.
#[derive(Clone)]
pub struct HomeRelayClient {
    inner: Arc<Inner>,
}
struct Inner {
    relay_origin: String,
    token: Arc<ServiceToken>,
    home: HomeConfig,
    app_port: u16,
    deadline: Duration,
    admission: Admission,
    jitter: Arc<dyn RelayJitter>,
    events: Arc<dyn RelayEventSink>,
    health: Mutex<RelayHealth>,
    tunnel_tasks: Mutex<TunnelTasks>,
    accepting_tunnels: AtomicBool,
}

struct TunnelTasks {
    tasks: Vec<JoinHandle<()>>,
    stopping: bool,
    stopped: bool,
    waiters: Vec<tokio::sync::oneshot::Sender<()>>,
}

impl HomeRelayClient {
    /// Construct a home relay attachment client.
    #[must_use]
    pub fn new(config: HomeRelayClientConfig) -> Self {
        Self {
            inner: Arc::new(Inner {
                relay_origin: config.relay_origin,
                token: Arc::new(config.service_token),
                home: config.home_config,
                app_port: config.app_port,
                deadline: config.dispatch_read_deadline,
                admission: Admission {
                    ceiling: config.admission_ceiling.get(),
                    count: Mutex::new((0, 0)),
                },
                jitter: config.jitter,
                events: config.events,
                health: Mutex::new(RelayHealth::new()),
                tunnel_tasks: Mutex::new(TunnelTasks {
                    tasks: Vec::new(),
                    stopping: false,
                    stopped: false,
                    waiters: Vec::new(),
                }),
                accepting_tunnels: AtomicBool::new(true),
            }),
        }
    }

    /// Run the listen connection and reconnect after transport failure.
    ///
    /// # Errors
    ///
    /// Returns a class-only relay error for terminal relay configuration or an
    /// invalid injected jitter sample.
    pub async fn run(&self) -> Result<(), TransportError> {
        let mut base = Duration::ZERO;
        loop {
            self.emit(RelayEvent::Connecting);
            let started = Instant::now();
            let error = self.run_once().await;
            self.emit(RelayEvent::Disconnected);
            if matches!(
                error,
                TransportError::Relay(RelayError::HomeRelayConfiguration)
            ) {
                self.emit(RelayEvent::ConfigurationFailure);
                return Err(error);
            }
            self.record_reconnecting();
            base = base_after_connection(base, started.elapsed());
            let (next, delay) = schedule_reconnect(base, self.inner.jitter.sample())
                .ok_or(TransportError::Relay(RelayError::Abnormal))?;
            base = next;
            sleep(delay).await;
        }
    }

    /// Stop and await all tunnel work without closing the supervised listen task.
    pub async fn stop(&self) {
        enum StopAction {
            Leader(Vec<JoinHandle<()>>),
            Follower(tokio::sync::oneshot::Receiver<()>),
            Stopped,
        }

        let action = {
            let mut tunnel_tasks = self
                .inner
                .tunnel_tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if tunnel_tasks.stopped {
                StopAction::Stopped
            } else if tunnel_tasks.stopping {
                let (sender, receiver) = tokio::sync::oneshot::channel();
                tunnel_tasks.waiters.push(sender);
                StopAction::Follower(receiver)
            } else {
                tunnel_tasks.stopping = true;
                self.inner.accepting_tunnels.store(false, Ordering::Release);
                StopAction::Leader(std::mem::take(&mut tunnel_tasks.tasks))
            }
        };
        match action {
            StopAction::Stopped => {}
            StopAction::Follower(receiver) => {
                let _ = receiver.await;
            }
            StopAction::Leader(tasks) => {
                for task in &tasks {
                    task.abort();
                }
                for task in tasks {
                    let _ = task.await;
                }
                let waiters = {
                    let mut tunnel_tasks = self
                        .inner
                        .tunnel_tasks
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    tunnel_tasks.stopping = false;
                    tunnel_tasks.stopped = true;
                    std::mem::take(&mut tunnel_tasks.waiters)
                };
                for waiter in waiters {
                    let _ = waiter.send(());
                }
                self.emit(RelayEvent::Disconnected);
            }
        }
    }

    async fn run_once(&self) -> TransportError {
        let Ok(url) = listen_url(&self.inner.relay_origin) else {
            return TransportError::Relay(RelayError::HomeRelayConfiguration);
        };
        let mut ws = match dial_home_ws(&url, &self.inner.token).await {
            Ok(ws) => ws,
            Err(error) => return error,
        };
        self.record_connected();
        self.emit(RelayEvent::Connected);
        while let Some(message) = ws.next().await {
            match message {
                Err(_) => return TransportError::Relay(RelayError::HomeListenConnection),
                Ok(message) => match message {
                    Message::Text(text) => {
                        if let ListenControl::Incoming { tunnel_id } = parse_listen_control(&text) {
                            if !self.inner.accepting_tunnels.load(Ordering::Acquire) {
                                self.emit(RelayEvent::TunnelClosed { tunnel_id });
                                continue;
                            }
                            let client = self.clone();
                            let task_tunnel_id = tunnel_id.clone();
                            if self.spawn_tunnel_task(async move {
                                client.handle_tunnel(task_tunnel_id).await;
                            }) {
                                self.emit(RelayEvent::TunnelPaired { tunnel_id });
                            } else {
                                self.emit(RelayEvent::TunnelClosed { tunnel_id });
                            }
                        }
                    }
                    Message::Binary(_)
                    | Message::Ping(_)
                    | Message::Pong(_)
                    | Message::Frame(_) => {}
                    Message::Close(_) => {
                        return TransportError::Relay(RelayError::HomeListenConnection);
                    }
                },
            }
        }
        TransportError::Relay(RelayError::HomeListenConnection)
    }

    async fn handle_tunnel(&self, tunnel_id: String) {
        let failure = self.handle_tunnel_inner(&tunnel_id).await.err();
        if let Some(failure) = failure {
            self.record_tunnel_failure(failure.phase, failure.failure);
        }
        self.emit(RelayEvent::TunnelClosed { tunnel_id });
    }

    async fn handle_tunnel_inner(&self, tunnel_id: &str) -> Result<(), TunnelProcessingFailure> {
        let url = tunnel_url(&self.inner.relay_origin, tunnel_id).map_err(|_| {
            TunnelProcessingFailure::dial(RelayTunnelFailure::RelayTunnelUnreachable)
        })?;
        let ws = dial_home_ws(&url, &self.inner.token)
            .await
            .map_err(|error| TunnelProcessingFailure::dial(classify_dial(&error)))?;
        if !self.inner.admission.acquire() {
            self.record_saturation(self.inner.admission.saturated());
            return Ok(());
        }
        let io = match guard_tls_prefix(PrefixIo::new(WsByteDuplex::new(ws).0), self.inner.deadline)
            .await
        {
            Ok(PrefixGuard::Tls(io)) => io,
            Ok(PrefixGuard::Unknown) => {
                self.inner.admission.release();
                self.emit(RelayEvent::TunnelUnknownPrefix);
                return Ok(());
            }
            Err(failure) => {
                self.inner.admission.release();
                return Err(TunnelProcessingFailure::prefix(failure));
            }
        };
        self.inner.admission.release();
        let mut connection = timeout(
            RELAY_HANDSHAKE_TIMEOUT,
            HomeConnection::accept(io, self.inner.home.clone()),
        )
        .await
        .map_err(|_| TunnelProcessingFailure::inner(RelayTunnelFailure::RelayTunnelUnreachable))?
        .map_err(|_| TunnelProcessingFailure::inner(RelayTunnelFailure::RelayTunnelUnreachable))?;
        self.record_success();
        while let Ok(stream) = connection.accept_stream().await {
            let client = self.clone();
            if !self.spawn_tunnel_task(async move {
                if let Err(failure) = pipe_stream(stream, client.inner.app_port).await {
                    client.record_tunnel_failure(RelayTunnelPhase::LocalSocket, failure);
                }
            }) {
                break;
            }
        }
        Ok(())
    }

    fn emit(&self, event: RelayEvent) {
        self.inner.events.emit(event);
    }
    fn spawn_tunnel_task<F>(&self, task: F) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let mut tunnel_tasks = self
            .inner
            .tunnel_tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tunnel_tasks.tasks.retain(|task| !task.is_finished());
        if tunnel_tasks.stopped || !self.inner.accepting_tunnels.load(Ordering::Acquire) {
            return false;
        }
        tunnel_tasks.tasks.push(tokio::spawn(task));
        true
    }
    fn record_success(&self) {
        self.update_health(|health| {
            health.last_successful_tunnel_at_ms = Some(timestamp_ms());
            health.last_failure = None;
        });
    }
    fn record_connected(&self) {
        self.update_health(|health| {
            health.state = RelayHealthState::Connected;
            health.listen_generation = health.listen_generation.saturating_add(1);
        });
    }
    fn record_reconnecting(&self) {
        self.update_health(|health| health.state = RelayHealthState::Reconnecting);
    }
    fn record_saturation(&self, count: u64) {
        self.emit(RelayEvent::AdmissionSaturated { count });
        self.update_health(|health| {
            health.admission_saturated_count = health.admission_saturated_count.max(count);
        });
    }
    fn record_failure(&self, failure: RelayTunnelFailure) {
        let saturated = self.inner.admission.saturated();
        self.update_health(|health| {
            health.last_failure = Some(failure);
            health.last_failure_at_ms = Some(timestamp_ms());
            health.admission_saturated_count = health.admission_saturated_count.max(saturated);
        });
    }
    fn record_tunnel_failure(&self, phase: RelayTunnelPhase, failure: RelayTunnelFailure) {
        self.record_failure(failure);
        self.emit(RelayEvent::TunnelFailure { phase, failure });
    }
    fn update_health(&self, update: impl FnOnce(&mut RelayHealth)) {
        let snapshot = {
            let mut health = self
                .inner
                .health
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            update(&mut health);
            health.clone()
        };
        self.emit(RelayEvent::Health(snapshot));
    }
}

/// Read wall-clock time for the owner-visible durable record, not monotonic ordering.
fn timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or_default()
}

struct TunnelProcessingFailure {
    phase: RelayTunnelPhase,
    failure: RelayTunnelFailure,
}

impl TunnelProcessingFailure {
    const fn dial(failure: RelayTunnelFailure) -> Self {
        Self {
            phase: RelayTunnelPhase::Dial,
            failure,
        }
    }

    const fn prefix(failure: RelayTunnelFailure) -> Self {
        Self {
            phase: RelayTunnelPhase::Prefix,
            failure,
        }
    }

    const fn inner(failure: RelayTunnelFailure) -> Self {
        Self {
            phase: RelayTunnelPhase::InnerHandshake,
            failure,
        }
    }
}

impl RelayStop for HomeRelayClient {
    type Error = std::convert::Infallible;
    #[expect(
        clippy::manual_async_fn,
        reason = "the public RelayStop seam deliberately preserves its impl-Future signature"
    )]
    fn stop(&mut self) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        async move {
            HomeRelayClient::stop(self).await;
            Ok(())
        }
    }
}

fn classify_dial(error: &TransportError) -> RelayTunnelFailure {
    match error {
        TransportError::Relay(RelayError::HomeTunnelRejected(status)) => match *status {
            404 => RelayTunnelFailure::HomeMissingMobile,
            401 | 403 => RelayTunnelFailure::ServiceTokenRejected,
            status => RelayTunnelFailure::RelayTunnelRejected { status },
        },
        _ => RelayTunnelFailure::RelayTunnelUnreachable,
    }
}

async fn dial_home_ws(
    url: &str,
    token: &ServiceToken,
) -> Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
    TransportError,
> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;
    use tokio_tungstenite::{Connector, connect_async_tls_with_config};
    let mut request = url
        .into_client_request()
        .map_err(|_| TransportError::Relay(RelayError::HomeListenConnection))?;
    let authorization = format!("Bearer {}", token.as_str())
        .parse()
        .map_err(|_| TransportError::Relay(RelayError::HomeListenConnection))?;
    request.headers_mut().insert(AUTHORIZATION, authorization);
    match timeout(
        Duration::from_secs(10),
        connect_async_tls_with_config(
            request,
            None,
            true,
            Some(Connector::Rustls(crate::relay::outer_config())),
        ),
    )
    .await
    {
        Ok(Ok((ws, _))) => Ok(ws),
        Ok(Err(tokio_tungstenite::tungstenite::Error::Http(response))) => Err(
            TransportError::Relay(RelayError::HomeTunnelRejected(response.status().as_u16())),
        ),
        Ok(Err(_)) | Err(_) => Err(TransportError::Relay(RelayError::HomeListenConnection)),
    }
}

struct PrefixIo<I> {
    inner: I,
    prefix: [u8; 4],
    prefix_len: usize,
    position: usize,
}

enum PrefixGuard<I> {
    Tls(PrefixIo<I>),
    Unknown,
}

async fn guard_tls_prefix<I>(
    mut io: PrefixIo<I>,
    deadline: Duration,
) -> Result<PrefixGuard<I>, RelayTunnelFailure>
where
    I: AsyncRead + Unpin,
{
    let mut prefix = [0_u8; 4];
    match timeout(deadline, io.read_exact(&mut prefix)).await {
        Ok(Ok(_)) if prefix[0] == 0x16 => {
            io.replay(prefix);
            Ok(PrefixGuard::Tls(io))
        }
        Ok(Ok(_)) => Ok(PrefixGuard::Unknown),
        Ok(Err(_)) | Err(_) => Err(RelayTunnelFailure::RelayTunnelUnreachable),
    }
}
impl<I> PrefixIo<I> {
    fn new(inner: I) -> Self {
        Self {
            inner,
            prefix: [0; 4],
            prefix_len: 0,
            position: 0,
        }
    }
    fn replay(&mut self, prefix: [u8; 4]) {
        self.prefix = prefix;
        self.prefix_len = prefix.len();
        self.position = 0;
    }
}
impl<I: AsyncRead + Unpin> AsyncRead for PrefixIo<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.position < self.prefix_len {
            let count = buf.remaining().min(self.prefix_len - self.position);
            buf.put_slice(&self.prefix[self.position..self.position + count]);
            self.position += count;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl<I: AsyncWrite + Unpin> AsyncWrite for PrefixIo<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn pipe_stream(stream: HomeStream, port: u16) -> Result<(), RelayTunnelFailure> {
    let Ok(mut socket) = TcpStream::connect(("127.0.0.1", port)).await else {
        let mut stream = stream;
        let _ = stream.reset(ResetReason::InternalError);
        return Err(RelayTunnelFailure::LocalPrivateListenerUnreachable);
    };
    pump_stream(stream, &mut socket).await
}

async fn pump_stream<S>(mut stream: HomeStream, socket: &mut S) -> Result<(), RelayTunnelFailure>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut tunnel_buf = vec![0_u8; 64 * 1024].into_boxed_slice();
    let mut socket_buf = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        tokio::select! {
            read = stream.read(&mut tunnel_buf) => match read {
                Ok(0) => { if socket.shutdown().await.is_err() { let _ = stream.reset(ResetReason::InternalError); return Err(RelayTunnelFailure::RelayTunnelUnreachable); } return Ok(()); }
                Ok(count) => if socket.write_all(&tunnel_buf[..count]).await.is_err() { let _ = stream.reset(ResetReason::InternalError); return Err(RelayTunnelFailure::RelayTunnelUnreachable); },
                Err(_) => return Ok(()),
            },
            read = socket.read(&mut socket_buf) => match read {
                Ok(0) => { let _ = stream.shutdown().await; return Ok(()); }
                Ok(count) => if stream.write_all(&socket_buf[..count]).await.is_err() { return Ok(()); },
                Err(_) => { let _ = stream.reset(ResetReason::InternalError); return Err(RelayTunnelFailure::RelayTunnelUnreachable); },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::SinkExt;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::Barrier;
    use std::sync::Mutex;
    use std::task::{Context, Poll};

    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
    };
    use rustls::RootCertStore;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::server::danger::ClientCertVerifier;
    use spl_core::ca::sha256;
    use spl_core::frame::{FLAG_CLOSE, FLAG_DATA, FLAG_OPEN, FLAG_WINDOW, Frame, FrameDecoder};
    use spl_core::mux::INITIAL_WINDOW;
    use spl_home::{MAX_STAGED_WRITE_BYTES_PER_STREAM, MuxLimits};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsConnector;

    struct TlsFixture {
        ca: CertificateDer<'static>,
        server_chain: Vec<CertificateDer<'static>>,
        server_key: PrivateKeyDer<'static>,
        client_chain: Vec<CertificateDer<'static>>,
        client_key: PrivateKeyDer<'static>,
    }

    fn tls_fixture() -> TlsFixture {
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let ca_der = CertificateDer::from(ca.der().to_vec());

        let server_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut server_params = CertificateParams::new(vec!["spl.local".to_owned()]).unwrap();
        server_params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        let server = server_params.signed_by(&server_key, &ca, &ca_key).unwrap();

        let client_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut client_params = CertificateParams::new(vec!["relay-test".to_owned()]).unwrap();
        client_params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);
        let client = client_params.signed_by(&client_key, &ca, &ca_key).unwrap();
        TlsFixture {
            ca: ca_der.clone(),
            server_chain: vec![CertificateDer::from(server.der().to_vec()), ca_der.clone()],
            server_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
            client_chain: vec![CertificateDer::from(client.der().to_vec()), ca_der],
            client_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(client_key.serialize_der())),
        }
    }

    fn home_config(fixture: &TlsFixture) -> HomeConfig {
        let mut roots = RootCertStore::empty();
        roots.add(fixture.ca.clone()).unwrap();
        let verifier: Arc<dyn ClientCertVerifier> =
            rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .unwrap();
        HomeConfig {
            certificate_chain: fixture.server_chain.clone(),
            private_key: fixture.server_key.clone_key(),
            client_cert_verifier: verifier,
            mux_limits: MuxLimits::default(),
        }
    }

    struct CapturedEvents(Mutex<Vec<RelayEvent>>);

    impl RelayEventSink for CapturedEvents {
        fn emit(&self, event: RelayEvent) {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(event);
        }
    }

    struct FixedJitter;

    impl RelayJitter for FixedJitter {
        fn sample(&self) -> f64 {
            0.5
        }
    }

    fn test_client(relay_origin: String, events: Arc<CapturedEvents>) -> HomeRelayClient {
        let fixture = tls_fixture();
        HomeRelayClient::new(HomeRelayClientConfig {
            relay_origin,
            service_token: ServiceToken::new("test-service-token".into()),
            home_config: home_config(&fixture),
            app_port: 1,
            dispatch_read_deadline: Duration::from_millis(20),
            admission_ceiling: NonZeroUsize::new(1).unwrap(),
            jitter: Arc::new(FixedJitter),
            events,
        })
    }

    fn health_snapshots(events: &CapturedEvents) -> Vec<RelayHealth> {
        events
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter_map(|event| match event {
                RelayEvent::Health(health) => Some(health.clone()),
                _ => None,
            })
            .collect()
    }

    struct WriteFailingSocket;

    impl AsyncRead for WriteFailingSocket {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for WriteFailingSocket {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::Error::other("loopback write failed")))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn prefix_guard_replays_every_byte_across_chunk_boundaries() {
        for chunks in [
            vec![b"\x16\x03\x01\x00payload".to_vec()],
            vec![
                b"\x16".to_vec(),
                b"\x03".to_vec(),
                b"\x01".to_vec(),
                b"\x00".to_vec(),
                b"payload".to_vec(),
            ],
            vec![
                b"\x16\x03".to_vec(),
                b"\x01\x00pay".to_vec(),
                b"load".to_vec(),
            ],
        ] {
            let (mut writer, reader) = tokio::io::duplex(64);
            let writer = tokio::spawn(async move {
                for chunk in chunks {
                    writer.write_all(&chunk).await.unwrap();
                }
                writer.shutdown().await.unwrap();
            });
            let mut guarded = PrefixIo::new(reader);
            let mut prefix = [0_u8; 4];
            tokio::time::timeout(Duration::from_secs(1), guarded.read_exact(&mut prefix))
                .await
                .expect("prefix guard must receive four bytes")
                .unwrap();
            assert_eq!(prefix, [0x16, 0x03, 0x01, 0x00]);
            guarded.replay(prefix);
            let mut replayed = [0_u8; 11];
            tokio::time::timeout(Duration::from_secs(1), guarded.read_exact(&mut replayed))
                .await
                .expect("prefix replay must not stall")
                .unwrap();
            assert_eq!(&replayed, b"\x16\x03\x01\x00payload");
            writer.await.unwrap();
        }
    }

    #[tokio::test]
    async fn stalled_prefix_does_not_emit_unknown_prefix() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let relay_origin = format!("http://{}", listener.local_addr().unwrap());
        let relay = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tunnel = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let _ = tunnel.next().await;
        });
        let events = Arc::new(CapturedEvents(Mutex::new(Vec::new())));
        let client = test_client(relay_origin, events.clone());
        client.handle_tunnel("stalled-prefix".into()).await;
        relay.await.unwrap();
        let events = events
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, RelayEvent::TunnelUnknownPrefix)),
            "a stalled prefix must not emit TunnelUnknownPrefix"
        );
        assert!(
            events.iter().any(|event| matches!(
                event,
                RelayEvent::Health(RelayHealth {
                    last_failure: Some(RelayTunnelFailure::RelayTunnelUnreachable),
                    ..
                })
            )),
            "a stalled prefix must emit a transport failure through health"
        );
        assert!(
            events.iter().any(|event| matches!(
                event,
                RelayEvent::TunnelFailure {
                    phase: RelayTunnelPhase::Prefix,
                    failure: RelayTunnelFailure::RelayTunnelUnreachable,
                }
            )),
            "a stalled prefix must identify the prefix phase"
        );
    }

    #[tokio::test]
    async fn pipe_forwards_a_mux_stream_to_loopback_and_closes_it() {
        let app = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let app_port = app.local_addr().unwrap().port();
        let app_task = tokio::spawn(async move {
            let (mut socket, _) = tokio::time::timeout(Duration::from_secs(1), app.accept())
                .await
                .expect("pipe must dial the local app")
                .unwrap();
            let mut request = [0_u8; 5];
            socket.read_exact(&mut request).await.unwrap();
            assert_eq!(request, *b"hello");
            socket.write_all(b"world").await.unwrap();
            socket.shutdown().await.unwrap();
        });
        let fixture = tls_fixture();
        let (mobile_io, home_io) = tokio::io::duplex(2 * 1024 * 1024);
        let home = tokio::spawn(HomeConnection::accept(home_io, home_config(&fixture)));
        let client_config = crate::tls::mtls_config(
            &sha256(fixture.ca.as_ref())[..16],
            fixture.client_chain,
            fixture.client_key,
        )
        .unwrap();
        let mut mobile = TlsConnector::from(Arc::new(client_config))
            .connect(ServerName::try_from("spl.local").unwrap(), mobile_io)
            .await
            .unwrap();
        let mut home = home.await.unwrap().unwrap();
        mobile
            .write_all(
                &Frame::new(1, FLAG_OPEN | FLAG_DATA, b"hello".to_vec())
                    .encode()
                    .unwrap(),
            )
            .await
            .unwrap();
        mobile.flush().await.unwrap();
        let stream = tokio::time::timeout(Duration::from_secs(1), home.accept_stream())
            .await
            .expect("mux driver must accept the opened stream")
            .unwrap();
        let pipe = tokio::spawn(pipe_stream(stream, app_port));
        let mut decoder = FrameDecoder::new();
        let mut bytes = [0_u8; 4096];
        let mut saw_reply = false;
        let mut saw_close = false;
        while !saw_reply || !saw_close {
            let count = tokio::time::timeout(Duration::from_secs(1), mobile.read(&mut bytes))
                .await
                .expect("pipe reply must not stall")
                .unwrap();
            decoder.feed(&bytes[..count]);
            for frame in decoder.drain().unwrap() {
                saw_reply |= frame.payload == b"world";
                saw_close |= frame.flags == FLAG_CLOSE;
            }
        }
        assert!(saw_reply, "mobile must receive the loopback response");
        assert!(
            saw_close,
            "mobile must observe stream close after app teardown"
        );
        assert!(pipe.await.unwrap().is_ok());
        app_task.await.unwrap();
    }

    #[tokio::test]
    async fn post_connect_socket_error_is_not_listener_unreachable() {
        let fixture = tls_fixture();
        let (mobile_io, home_io) = tokio::io::duplex(2 * 1024 * 1024);
        let home = tokio::spawn(HomeConnection::accept(home_io, home_config(&fixture)));
        let client_config = crate::tls::mtls_config(
            &sha256(fixture.ca.as_ref())[..16],
            fixture.client_chain,
            fixture.client_key,
        )
        .unwrap();
        let mut mobile = TlsConnector::from(Arc::new(client_config))
            .connect(ServerName::try_from("spl.local").unwrap(), mobile_io)
            .await
            .unwrap();
        let mut home = home.await.unwrap().unwrap();
        mobile
            .write_all(
                &Frame::new(1, FLAG_OPEN | FLAG_DATA, b"hello".to_vec())
                    .encode()
                    .unwrap(),
            )
            .await
            .unwrap();
        mobile.flush().await.unwrap();
        let stream = tokio::time::timeout(Duration::from_secs(1), home.accept_stream())
            .await
            .expect("mux driver must accept the opened stream")
            .unwrap();
        let mut socket = WriteFailingSocket;
        assert_eq!(
            pump_stream(stream, &mut socket).await,
            Err(RelayTunnelFailure::RelayTunnelUnreachable),
            "a post-connect socket error must not claim the listener was unreachable"
        );
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "the staging test keeps the producer, mobile drain, and credit assertions in one ordered exchange"
    )]
    async fn pipe_backpressures_at_the_stream_staging_bound_then_wakes() {
        let fixture = tls_fixture();
        let (mobile_io, home_io) = tokio::io::duplex(4096);
        let home = tokio::spawn(HomeConnection::accept(home_io, home_config(&fixture)));
        let client_config = crate::tls::mtls_config(
            &sha256(fixture.ca.as_ref())[..16],
            fixture.client_chain,
            fixture.client_key,
        )
        .unwrap();
        let mut mobile = TlsConnector::from(Arc::new(client_config))
            .connect(ServerName::try_from("spl.local").unwrap(), mobile_io)
            .await
            .unwrap();
        let mut home = home.await.unwrap().unwrap();
        mobile
            .write_all(&Frame::new(1, FLAG_OPEN, Vec::new()).encode().unwrap())
            .await
            .unwrap();
        mobile.flush().await.unwrap();
        let stream = tokio::time::timeout(Duration::from_secs(1), home.accept_stream())
            .await
            .expect("mux driver must accept the opened stream")
            .unwrap();
        let payload = vec![0x5a; 16 * MAX_STAGED_WRITE_BYTES_PER_STREAM + 1];
        let app_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let app_port = app_listener.local_addr().unwrap().port();
        let (started_sender, started_receiver) = tokio::sync::oneshot::channel();
        let mut app = tokio::spawn(async move {
            let (mut socket, _) = app_listener.accept().await.unwrap();
            started_sender.send(()).unwrap();
            socket.write_all(&payload).await
        });
        let pump = tokio::spawn(pipe_stream(stream, app_port));
        started_receiver.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut app)
                .await
                .is_err(),
            "new pipe must backpressure once per-stream staging is full"
        );

        let mut decoder = FrameDecoder::new();
        let mut bytes = [0_u8; 16 * 1024];
        let mut received = 0;
        while received < INITIAL_WINDOW {
            let count = tokio::time::timeout(Duration::from_secs(1), mobile.read(&mut bytes))
                .await
                .expect("mobile must be able to drain staged bytes")
                .unwrap();
            decoder.feed(&bytes[..count]);
            for frame in decoder.drain().unwrap() {
                if frame.flags & FLAG_DATA != 0 {
                    received += frame.payload.len();
                }
            }
        }
        assert_eq!(
            received, INITIAL_WINDOW,
            "pipe must stop at the configured per-stream staging bound"
        );
        mobile
            .write_all(
                &Frame::new(
                    1,
                    FLAG_WINDOW,
                    (INITIAL_WINDOW as u32).to_be_bytes().to_vec(),
                )
                .encode()
                .unwrap(),
            )
            .await
            .unwrap();
        mobile.flush().await.unwrap();
        let mut next_window_at = 2 * INITIAL_WINDOW;
        while !app.is_finished() {
            let count = tokio::time::timeout(Duration::from_secs(1), mobile.read(&mut bytes))
                .await
                .expect("window credit must wake the pipe")
                .unwrap();
            decoder.feed(&bytes[..count]);
            for frame in decoder.drain().unwrap() {
                if frame.flags & FLAG_DATA != 0 {
                    received += frame.payload.len();
                }
            }
            while received >= next_window_at {
                mobile
                    .write_all(
                        &Frame::new(
                            1,
                            FLAG_WINDOW,
                            (INITIAL_WINDOW as u32).to_be_bytes().to_vec(),
                        )
                        .encode()
                        .unwrap(),
                    )
                    .await
                    .unwrap();
                mobile.flush().await.unwrap();
                next_window_at += INITIAL_WINDOW;
            }
        }
        app.await.unwrap().unwrap();
        pump.abort();
    }

    #[test]
    fn debug_never_contains_payload_or_nonce_markers() {
        let payload = "SPL-RELAY-PAYLOAD-MARKER";
        let nonce = "SPL-RELAY-PING-NONCE-MARKER";
        let events = [
            RelayEvent::Connecting,
            RelayEvent::Connected,
            RelayEvent::Disconnected,
            RelayEvent::ConfigurationFailure,
            RelayEvent::AdmissionSaturated { count: 1 },
            RelayEvent::TunnelUnknownPrefix,
            RelayEvent::TunnelPaired {
                tunnel_id: payload.into(),
            },
            RelayEvent::TunnelClosed {
                tunnel_id: nonce.into(),
            },
            RelayEvent::TunnelFailure {
                phase: RelayTunnelPhase::Prefix,
                failure: RelayTunnelFailure::RelayTunnelUnreachable,
            },
            RelayEvent::Health(RelayHealth::new()),
        ];
        for event in events {
            let rendered = format!("{event:?}");
            assert!(
                !rendered.contains(payload),
                "event Debug leaked payload bytes"
            );
            assert!(!rendered.contains(nonce), "event Debug leaked PING nonce");
        }
        let health = RelayHealth::new();
        let failure = RelayTunnelFailure::RelayTunnelRejected { status: 500 };
        assert!(!format!("{health:?}").contains(payload));
        assert!(!format!("{health:?}").contains(nonce));
        assert!(!format!("{failure:?}").contains(payload));
        assert!(!format!("{failure:?}").contains(nonce));
    }
    #[test]
    fn schedule_requires_stability_before_reset() {
        assert_eq!(
            schedule_reconnect(Duration::ZERO, 0.5),
            Some((Duration::from_secs(2), Duration::from_secs(1)))
        );
        assert_eq!(
            schedule_reconnect(Duration::from_mins(1), 0.0),
            Some((Duration::from_mins(1), Duration::from_secs(45)))
        );
        assert_eq!(
            schedule_reconnect(Duration::from_secs(2), 1.0),
            Some((Duration::from_secs(4), Duration::from_millis(2500)))
        );
        assert_eq!(
            schedule_reconnect(Duration::from_mins(1), 0.5),
            Some((Duration::from_mins(1), Duration::from_mins(1)))
        );
        assert_eq!(
            base_after_connection(Duration::from_secs(8), Duration::from_secs(59)),
            Duration::from_secs(8),
            "connection establishment alone must not reset backoff"
        );
        assert_eq!(
            base_after_connection(Duration::from_secs(8), Duration::from_mins(1)),
            Duration::ZERO,
            "60 seconds of stable establishment resets backoff"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[expect(
        clippy::too_many_lines,
        reason = "the race test keeps registration, live admission, and concurrent-stop ordering in one scenario"
    )]
    async fn stop_racing_tunnel_admission_never_leaves_work_unregistered() {
        struct BlockOnDrop {
            entered: Option<tokio::sync::oneshot::Sender<()>>,
            barrier: Arc<Barrier>,
        }

        impl Drop for BlockOnDrop {
            fn drop(&mut self) {
                if let Some(sender) = self.entered.take() {
                    let _ = sender.send(());
                }
                self.barrier.wait();
            }
        }

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let relay_origin = format!("http://{}", listener.local_addr().unwrap());
        let (accepted_sender, accepted_receiver) = tokio::sync::oneshot::channel();
        let relay = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tunnel = tokio_tungstenite::accept_async(tcp).await.unwrap();
            accepted_sender.send(()).unwrap();
            let _ = tunnel.next().await;
        });
        let events = Arc::new(CapturedEvents(Mutex::new(Vec::new())));
        let client = test_client(relay_origin, events);
        let registration = client
            .inner
            .tunnel_tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (started_sender, mut started_receiver) = tokio::sync::oneshot::channel();
        let spawner = tokio::task::spawn_blocking({
            let client = client.clone();
            move || {
                let handler = client.clone();
                assert!(client.spawn_tunnel_task(async move {
                    started_sender.send(()).unwrap();
                    handler.handle_tunnel("in-flight".into()).await;
                }));
            }
        });
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            matches!(
                started_receiver.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty)
            ),
            "a tunnel must not start before its registration lock is released"
        );
        drop(registration);
        spawner.await.unwrap();
        started_receiver
            .await
            .expect("registered tunnel admission must start");
        accepted_receiver
            .await
            .expect("in-flight admission must open the relay tunnel");
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let admitted = client
                    .inner
                    .admission
                    .count
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .0;
                if admitted == 1 {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("tunnel admission must be in flight before stop");

        let barrier = Arc::new(Barrier::new(2));
        let (drop_sender, drop_receiver) = tokio::sync::oneshot::channel();
        assert!(client.spawn_tunnel_task({
            let barrier = barrier.clone();
            async move {
                let _block = BlockOnDrop {
                    entered: Some(drop_sender),
                    barrier,
                };
                std::future::pending::<()>().await;
            }
        }));
        let first_stop = tokio::spawn({
            let client = client.clone();
            async move { client.stop().await }
        });
        drop_receiver
            .await
            .expect("first stop must reach a tracked task before returning");
        let second_stop = tokio::spawn({
            let client = client.clone();
            async move { client.stop().await }
        });
        tokio::task::yield_now().await;
        assert!(
            !second_stop.is_finished(),
            "a concurrent stop must wait for the first stop's tracked work"
        );
        barrier.wait();
        first_stop.await.unwrap();
        second_stop.await.unwrap();
        assert!(
            client
                .inner
                .tunnel_tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .tasks
                .is_empty(),
            "stop must return only after in-flight tunnel work is gone"
        );
        relay.await.unwrap();
    }

    #[tokio::test]
    async fn invalid_relay_origin_is_terminal_and_emitted() {
        let events = Arc::new(CapturedEvents(Mutex::new(Vec::new())));
        let client = test_client("ftp://invalid-relay".into(), events.clone());
        let result = tokio::time::timeout(Duration::from_millis(100), client.run())
            .await
            .expect("invalid relay origin must not enter reconnect backoff");
        assert!(matches!(
            result,
            Err(TransportError::Relay(RelayError::HomeRelayConfiguration))
        ));
        assert!(
            events
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .any(|event| matches!(event, RelayEvent::ConfigurationFailure)),
            "terminal configuration failure must be emitted through the event port"
        );
    }

    async fn assert_listen_termination_reconnects(send_close: bool) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let relay_origin = format!("http://{}", listener.local_addr().unwrap());
        let (terminated_sender, terminated_receiver) = tokio::sync::oneshot::channel();
        let relay = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut listen = tokio_tungstenite::accept_async(tcp).await.unwrap();
            if send_close {
                listen.send(Message::Close(None)).await.unwrap();
            }
            drop(listen);
            terminated_sender.send(()).unwrap();
            let _ = tokio::time::timeout(Duration::from_secs(3), listener.accept())
                .await
                .expect("listen termination must trigger a reconnect attempt")
                .unwrap();
        });
        let events = Arc::new(CapturedEvents(Mutex::new(Vec::new())));
        let client = test_client(relay_origin, events);
        let running = tokio::spawn({
            let client = client.clone();
            async move { client.run().await }
        });
        terminated_receiver
            .await
            .expect("relay must terminate the listen socket");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !running.is_finished(),
            "listen termination must enter reconnect backoff instead of returning"
        );
        relay.await.unwrap();
        running.abort();
    }

    #[tokio::test]
    async fn listen_close_frame_reconnects_with_backoff() {
        assert_listen_termination_reconnects(true).await;
    }

    #[tokio::test]
    async fn listen_eof_reconnects_with_backoff() {
        assert_listen_termination_reconnects(false).await;
    }

    #[tokio::test]
    async fn listen_failure_publishes_reconnecting_health() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let relay_origin = format!("http://{}", listener.local_addr().unwrap());
        let relay = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = tcp.read(&mut request).await.unwrap();
            tcp.write_all(
                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        });
        let events = Arc::new(CapturedEvents(Mutex::new(Vec::new())));
        let client = test_client(relay_origin, events.clone());
        let running = tokio::spawn({
            let client = client.clone();
            async move { client.run().await }
        });
        relay.await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if health_snapshots(&events)
                    .iter()
                    .any(|health| health.state() == RelayHealthState::Reconnecting)
                {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("listen loss must publish reconnecting health before backoff");
        running.abort();
    }

    #[tokio::test]
    async fn health_records_real_ordered_timestamps() {
        let events = Arc::new(CapturedEvents(Mutex::new(Vec::new())));
        let client = test_client("http://127.0.0.1:1".into(), events.clone());
        client.record_failure(RelayTunnelFailure::RelayTunnelUnreachable);
        tokio::time::sleep(Duration::from_millis(1)).await;
        client.record_success();
        let health = health_snapshots(&events)
            .pop()
            .expect("health changes must be emitted");
        let failure_at = health
            .last_failure_at_ms()
            .expect("failure timestamp must be recorded");
        let success_at = health
            .last_successful_tunnel_at_ms()
            .expect("success timestamp must be recorded");
        assert_ne!(
            failure_at, 0,
            "failure timestamp must be a real clock value"
        );
        assert_ne!(
            success_at, 0,
            "success timestamp must be a real clock value"
        );
        assert!(
            success_at >= failure_at,
            "success timestamp must not precede the recorded failure"
        );
    }

    #[test]
    fn saturation_health_count_never_regresses() {
        let events = Arc::new(CapturedEvents(Mutex::new(Vec::new())));
        let client = test_client("http://127.0.0.1:1".into(), events.clone());
        client.record_saturation(2);
        client.record_saturation(1);
        assert_eq!(
            health_snapshots(&events)
                .last()
                .expect("saturation must emit a health snapshot")
                .admission_saturated_count(),
            2,
            "a lower saturation observation must not overwrite a newer count"
        );
    }
}
