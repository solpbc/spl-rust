// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Direct-or-relay carrier dialing for a paired SPL credential.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::connection::dial_tls;
use crate::credential::Credential;
use crate::observe::{
    note_dial_attempt, note_direct_success, note_relay_success, note_selected_path,
};
use crate::relay::{RelayTerminationHandle, dial_relay_carrier};
use crate::relay_token::{RefreshOutcome, refresh_device_token};
use crate::{RelayError, TransportError, prefer_refusal, tls};

/// Relay transient retry count. Mirrors the LAN connection/handshake retry bound.
const RELAY_MAX_TRANSIENT_ATTEMPTS: usize = 5;

/// Relay permission returned by a [`RelayFence`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayPermit {
    /// Relay communication is currently permitted.
    Allow,
    /// Relay communication is temporarily or administratively disabled.
    Disabled,
    /// The incarnation is retired or obsolete; relay communication is permanently disallowed for this client.
    Retired,
}

/// Object-safe gate synchronizing relay access and durable token commit against consumer lifecycle.
///
/// Consumers serialize revoke/disable/retire operations against [`with_publication`](RelayFence::with_publication),
/// ensuring the library's permit check, transactional durable commit, and live mutex assignment execute as a
/// single atomic critical section.
pub trait RelayFence: Send + Sync + 'static {
    /// Evaluate whether relay communication is permitted for `incarnation`.
    fn permit(&self, incarnation: u64) -> RelayPermit;
    /// Consumer serializes revoke/disable/retire against this section.
    fn with_publication(&self, body: &mut dyn FnMut());
}

/// Outcome of a durable consumer token transaction commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenCommit {
    /// Token was durably committed at the specified generation sequence.
    Committed {
        /// The monotonically increasing generation number assigned by the transaction.
        generation: u64,
    },
    /// Token update was rejected or unchanged; existing state remains valid.
    Unchanged,
    /// Token commit outcome is unknown/indeterminate; live token must not update and relay becomes ineligible.
    Indeterminate,
}

/// Context provided to [`TokenTransaction::commit`].
#[derive(Debug)]
pub struct TokenCommitContext<'a> {
    /// The newly acquired token to commit.
    pub token: &'a str,
    /// Unix timestamp (seconds) when the token expires.
    pub expires_at: i64,
    /// The token being replaced.
    pub previous_token: &'a str,
    /// The incarnation sequence number of the client.
    pub incarnation: u64,
}

/// Consumer-provided transaction interface for durable token storage.
pub trait TokenTransaction: Send + Sync + 'static {
    /// Commit a newly refreshed token.
    ///
    /// The transaction must return one of three honest outcomes:
    /// - [`TokenCommit::Committed`]: The token was written to durable storage; the client will subsequently update its in-memory live token and proceed.
    /// - [`TokenCommit::Unchanged`]: The update was rejected or considered stale by durable storage; the previous token remains in place and refresh reports publication rejection.
    /// - [`TokenCommit::Indeterminate`]: Storage state could not be confirmed (e.g. timeout or storage fault); the client leaves its live token unchanged and marks itself relay-ineligible to prevent unauthenticated network loops.
    fn commit(&self, ctx: TokenCommitContext<'_>) -> TokenCommit;
}

/// Token publication and lifecycle configuration for [`TransportClient`].
///
/// Dispatches durable token commits through an owned background task that survives
/// cancellation or dropping of calling request futures.
#[derive(Clone)]
pub struct TokenPublication {
    /// The transactional commit implementation.
    pub transaction: Arc<dyn TokenTransaction>,
    /// Optional fence synchronizing relay access against consumer lifecycle.
    pub fence: Option<Arc<dyn RelayFence>>,
    /// Monotonic incarnation number for the client instance.
    pub incarnation: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RefreshAction {
    Redial,
    Terminal,
    Transient,
    Rejected,
    Indeterminate,
    FenceDenied(RelayPermit),
}

/// Errors returned when opening a direct-or-relay carrier.
#[derive(Debug, thiserror::Error)]
pub enum CarrierOpenError {
    /// Relay communication is disabled by the local fence.
    #[error("relay communication is disabled by local fence")]
    RelayDisabled,
    /// Relay communication was retired by the local fence.
    #[error("relay communication was retired by local fence")]
    RelayRetired,
    /// Refreshed token publication was rejected by durable storage.
    #[error("refreshed token publication was rejected by storage")]
    PublicationRejected,
    /// Refreshed token publication outcome is indeterminate; live token was not updated.
    #[error("refreshed token publication outcome is indeterminate")]
    PublicationIndeterminate,
    /// An underlying transport error occurred.
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
}

pub(crate) fn relay_fence_permit(
    publication: Option<&TokenPublication>,
) -> Result<(), RelayPermit> {
    let Some(publ) = publication else {
        return Ok(());
    };
    let Some(fence) = &publ.fence else {
        return Ok(());
    };
    let permit = fence.permit(publ.incarnation);
    if permit != RelayPermit::Allow {
        return Err(permit);
    }
    Ok(())
}

fn map_fence_permit(permit: RelayPermit) -> CarrierOpenError {
    match permit {
        RelayPermit::Disabled => CarrierOpenError::RelayDisabled,
        RelayPermit::Retired => CarrierOpenError::RelayRetired,
        RelayPermit::Allow => unreachable!("allow is not a fence rejection"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CarrierPolicy {
    Legacy,
    Fenced,
}

pub(crate) trait CarrierIo: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> CarrierIo for T {}

/// An established SPL carrier returned opaquely to a bridge opener.
///
/// Consumers receive this value from [`TransportClient::dial_carrier`] and
/// forward it through `CarrierOpener`; only this crate can inspect its stream or
/// kind.
pub struct DialedCarrier {
    stream: Box<dyn CarrierIo>,
    kind: CarrierKind,
}

impl DialedCarrier {
    pub(crate) fn into_parts(self) -> (Box<dyn CarrierIo>, CarrierKind) {
        (self.stream, self.kind)
    }

    #[cfg(test)]
    pub(crate) fn from_test_parts(stream: Box<dyn CarrierIo>, kind: CarrierKind) -> Self {
        Self { stream, kind }
    }
}

#[derive(Clone)]
pub(crate) enum CarrierKind {
    Lan,
    Relay { termination: RelayTerminationHandle },
}

/// Best-effort callback invoked after a refreshed relay token becomes live.
///
/// The callback owns persistence and must absorb its own failures. It is called
/// after the refresh single-flight mutex has been released.
pub type TokenPersistHook = Arc<dyn Fn(&str, i64) + Send + Sync + 'static>;

/// SPL transport client for direct and relay carrier establishment.
pub struct TransportClient {
    pub(crate) credential: Credential,
    pub(crate) config: Arc<ClientConfig>,
    /// Live relay device token.
    pub(crate) device_token: Option<Arc<tokio::sync::Mutex<String>>>,
    pub(crate) refresh_lock: Arc<tokio::sync::Mutex<()>>,
    pub(crate) token_persist: Option<TokenPersistHook>,
    pub(crate) publication: Option<TokenPublication>,
    pub(crate) relay_ineligible: Arc<AtomicBool>,
    /// Peers that answered where the paired journal was expected but are not
    /// it, one per address (`None` for the relay).
    pub(crate) unknown_journals: Arc<std::sync::Mutex<Vec<crate::UnknownJournal>>>,
}

impl TransportClient {
    /// Peers that answered where the paired journal was expected but are not
    /// it: a different journal holding a saved address, or this journal after
    /// its CA changed. One entry per address, in the order first seen. An
    /// address's entry stays until a later dial to that same address reaches
    /// the paired journal, even while another address or the relay works, so
    /// an owner can be told.
    #[must_use]
    pub fn unknown_journals(&self) -> Vec<crate::UnknownJournal> {
        self.unknown_journals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Record one dial's outcome at `address` (`None` for the relay) for
    /// [`Self::unknown_journals`].
    pub(crate) fn note_dial(&self, address: Option<&str>, result: Result<(), &TransportError>) {
        let mut sightings = self
            .unknown_journals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match result {
            Err(TransportError::UnknownJournal(unknown)) => {
                match sightings
                    .iter_mut()
                    .find(|seen| seen.address == unknown.address)
                {
                    Some(seen) => seen.clone_from(unknown),
                    None => sightings.push(unknown.clone()),
                }
            }
            Ok(()) => sightings.retain(|seen| seen.address.as_deref() != address),
            Err(_) => {}
        }
    }

    /// Build the transport client and its mutual-TLS configuration.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Pairing`] when a relay credential has no LAN
    /// endpoints, or a TLS/crypto error when certificate material is invalid.
    pub fn new(
        credential: Credential,
        token_persist: Option<TokenPersistHook>,
    ) -> Result<Self, TransportError> {
        if credential.relay_origin.is_some() && credential.endpoints.is_empty() {
            return Err(TransportError::Pairing(
                "relay credential has no LAN endpoints".into(),
            ));
        }
        Self::build(credential, token_persist, None)
    }

    /// Build a transport client for a credential that deliberately has only a
    /// relay origin and device token.
    ///
    /// Use [`TransportClient::new`] when the credential carries LAN endpoints.
    /// This client never dials LAN because an empty endpoint list is required, so
    /// [`TransportClient::dial_carrier`] proceeds directly to relay fallback
    /// without a direct-network delay.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Pairing`] when the credential carries LAN
    /// endpoints or lacks a relay origin or device token. Returns a TLS or crypto
    /// error when the certificate, private key, or fingerprint pin is invalid.
    pub fn new_relay_only(
        credential: Credential,
        token_persist: Option<TokenPersistHook>,
    ) -> Result<Self, TransportError> {
        if !credential.endpoints.is_empty() {
            return Err(TransportError::Pairing(
                "relay-only credential has LAN endpoints; use TransportClient::new for a credential with LAN endpoints"
                    .into(),
            ));
        }
        if !matches!(
            credential.relay_origin.as_deref(),
            Some(origin) if !origin.is_empty()
        ) {
            return Err(TransportError::Pairing(
                "relay-only credential has no relay origin".into(),
            ));
        }
        if !matches!(
            credential.device_token.as_deref(),
            Some(token) if !token.is_empty()
        ) {
            return Err(TransportError::Pairing(
                "relay-only credential has no device token".into(),
            ));
        }
        Self::build(credential, token_persist, None)
    }

    /// Build a transport client with a transactional publication interface and optional fence.
    ///
    /// # Sequencing and Cancellation
    ///
    /// Token refreshes execute durable commits before live in-memory assignment.
    /// Publication is dispatched to an owned `spawn_blocking` task that runs to completion
    /// even if the calling request future is cancelled or dropped.
    ///
    /// # Failure Outcomes
    ///
    /// - [`TokenCommit::Committed`]: Durable storage accepted the token; in-memory state is updated and redial proceeds.
    /// - [`TokenCommit::Unchanged`]: Durable storage rejected the update; live state is kept and [`crate::request::RequestError::PublicationRejected`] is returned.
    /// - [`TokenCommit::Indeterminate`]: Commit state is unknown; live state is kept and this client is latched as relay-ineligible, returning [`crate::request::RequestError::PublicationIndeterminate`].
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Pairing`] when a relay credential has no LAN
    /// endpoints, or a TLS/crypto error when certificate material is invalid.
    pub fn new_with_publication(
        credential: Credential,
        publication: TokenPublication,
    ) -> Result<Self, TransportError> {
        if credential.relay_origin.is_some() && credential.endpoints.is_empty() {
            return Err(TransportError::Pairing(
                "relay credential has no LAN endpoints".into(),
            ));
        }
        Self::build(credential, None, Some(publication))
    }

    /// Build a relay-only transport client with a transactional publication interface and optional fence.
    ///
    /// # Sequencing and Cancellation
    ///
    /// Token refreshes execute durable commits before live in-memory assignment.
    /// Publication is dispatched to an owned `spawn_blocking` task that runs to completion
    /// even if the calling request future is cancelled or dropped.
    ///
    /// # Failure Outcomes
    ///
    /// - [`TokenCommit::Committed`]: Durable storage accepted the token; in-memory state is updated and redial proceeds.
    /// - [`TokenCommit::Unchanged`]: Durable storage rejected the update; live state is kept and [`crate::request::RequestError::PublicationRejected`] is returned.
    /// - [`TokenCommit::Indeterminate`]: Commit state is unknown; live state is kept and this client is latched as relay-ineligible, returning [`crate::request::RequestError::PublicationIndeterminate`].
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Pairing`] when the credential carries LAN
    /// endpoints or lacks a relay origin or device token. Returns a TLS or crypto
    /// error when the certificate, private key, or fingerprint pin is invalid.
    pub fn new_relay_only_with_publication(
        credential: Credential,
        publication: TokenPublication,
    ) -> Result<Self, TransportError> {
        if !credential.endpoints.is_empty() {
            return Err(TransportError::Pairing(
                "relay-only credential has LAN endpoints; use TransportClient::new for a credential with LAN endpoints"
                    .into(),
            ));
        }
        if !matches!(
            credential.relay_origin.as_deref(),
            Some(origin) if !origin.is_empty()
        ) {
            return Err(TransportError::Pairing(
                "relay-only credential has no relay origin".into(),
            ));
        }
        if !matches!(
            credential.device_token.as_deref(),
            Some(token) if !token.is_empty()
        ) {
            return Err(TransportError::Pairing(
                "relay-only credential has no device token".into(),
            ));
        }
        Self::build(credential, None, Some(publication))
    }

    #[doc(hidden)]
    pub fn live_token_mutex_for_test(&self) -> Option<Arc<tokio::sync::Mutex<String>>> {
        self.device_token.clone()
    }

    fn build(
        credential: Credential,
        token_persist: Option<TokenPersistHook>,
        publication: Option<TokenPublication>,
    ) -> Result<Self, TransportError> {
        let device_token = credential
            .device_token
            .clone()
            .map(|t| Arc::new(tokio::sync::Mutex::new(t)));
        let chain = tls::parse_certs(&credential.client_cert_pem)?;
        let key = tls::parse_private_key(&credential.client_key_pem)?;
        let config = Arc::new(tls::mtls_config(&credential.ca_fp_prefix, chain, key)?);
        Ok(Self {
            credential,
            config,
            device_token,
            refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
            token_persist,
            publication,
            relay_ineligible: Arc::new(AtomicBool::new(false)),
            unknown_journals: Arc::default(),
        })
    }

    /// Establish a persistent carrier, preferring direct LAN endpoints and
    /// falling back to the relay only after transient direct failures.
    ///
    /// Note: `dial_carrier` does not consult the local [`RelayFence`]; use
    /// [`TransportClient::open_carrier`] or [`TransportClient::request`] for
    /// fence-coordinated access.
    ///
    /// Direct connection and handshake failures retain a bounded linear retry
    /// before relay fallback. A TLS alert received while dialing is not the
    /// journal's verdict (it checks the client certificate after this dial
    /// completes) and is retried like any handshake failure. A peer whose
    /// certificate is not the paired journal's is reported as
    /// [`TransportError::UnknownJournal`] unless another endpoint gives a more
    /// specific answer, and is kept in [`Self::unknown_journals`]. The journal's
    /// own verdict on this device arrives on the carrier, after this returns.
    ///
    /// # Errors
    ///
    /// Returns the last direct transport error when relay fallback is
    /// unavailable, or the terminal relay error after bounded relay attempts.
    #[expect(
        clippy::large_futures,
        reason = "the carrier dialing future keeps its established stack layout; callers in tests pin the size"
    )]
    pub async fn dial_carrier(&self) -> Result<DialedCarrier, TransportError> {
        match self.establish_carrier(None, CarrierPolicy::Legacy).await {
            Ok(carrier) => Ok(carrier),
            Err(CarrierOpenError::Transport(err)) => Err(err),
            Err(
                CarrierOpenError::RelayDisabled
                | CarrierOpenError::RelayRetired
                | CarrierOpenError::PublicationRejected
                | CarrierOpenError::PublicationIndeterminate,
            ) => unreachable!("legacy carrier policy never produces classified error variants"),
        }
    }

    /// Open a direct-or-relay carrier using local fence coordination,
    /// publication hooks, and an optional operation observer.
    ///
    /// # Errors
    ///
    /// Returns [`CarrierOpenError`] detailing transport, fence rejection,
    /// or publication failure.
    #[expect(
        clippy::large_futures,
        reason = "the carrier dialing future keeps its established stack layout; callers in tests pin the size"
    )]
    pub async fn open_carrier(
        &self,
        observer: Option<&crate::observe::OperationObserver>,
    ) -> Result<DialedCarrier, CarrierOpenError> {
        self.establish_carrier(observer, CarrierPolicy::Fenced)
            .await
    }

    pub(crate) async fn establish_carrier(
        &self,
        observer: Option<&crate::observe::OperationObserver>,
        policy: CarrierPolicy,
    ) -> Result<DialedCarrier, CarrierOpenError> {
        const MAX_ATTEMPTS: usize = 5;
        let mut last_err: Option<TransportError> = None;
        for attempt in 0..MAX_ATTEMPTS {
            for endpoint in &self.credential.endpoints {
                note_dial_attempt(observer);
                let dialed = dial_tls(self.config.clone(), &endpoint.host, endpoint.port).await;
                self.note_dial(
                    Some(&crate::endpoint_address(&endpoint.host, endpoint.port)),
                    dialed.as_ref().map(|_| ()),
                );
                match dialed {
                    Ok(stream) => {
                        note_direct_success(observer);
                        note_selected_path(observer, crate::request::SelectedPath::Direct);
                        return Ok(DialedCarrier {
                            stream: Box::new(stream),
                            kind: CarrierKind::Lan,
                        });
                    }
                    Err(error) => last_err = Some(prefer_refusal(last_err.take(), error)),
                }
            }
            match &last_err {
                Some(
                    TransportError::Tls(_)
                    | TransportError::UnknownJournal(_)
                    | TransportError::Io(_),
                ) => {
                    tokio::time::sleep(Duration::from_millis(250 * (attempt as u64 + 1))).await;
                }
                _ => break,
            }
        }

        let lan_err = last_err.unwrap_or(TransportError::NoEndpoint);
        let lan_unreachable = matches!(
            lan_err,
            TransportError::Tls(_)
                | TransportError::UnknownJournal(_)
                | TransportError::Io(_)
                | TransportError::NoEndpoint
        );
        if !lan_unreachable {
            return Err(CarrierOpenError::Transport(lan_err));
        }

        if self.relay_ineligible.load(Ordering::SeqCst) {
            if policy == CarrierPolicy::Fenced {
                return Err(CarrierOpenError::PublicationIndeterminate);
            }
            return Err(CarrierOpenError::Transport(lan_err));
        }

        if self.relay_eligible() {
            if policy == CarrierPolicy::Fenced {
                relay_fence_permit(self.publication.as_ref()).map_err(map_fence_permit)?;
            }

            #[expect(
                clippy::large_futures,
                reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
            )]
            let relay = self.dial_carrier_over_relay(observer, policy).await;
            return relay;
        }
        Err(CarrierOpenError::Transport(lan_err))
    }

    pub(crate) fn relay_eligible(&self) -> bool {
        self.credential.relay_origin.is_some()
            && self.device_token.is_some()
            && !self.relay_ineligible.load(Ordering::Acquire)
    }

    #[expect(
        clippy::expect_used,
        reason = "relay eligibility proves the live token mutex is present before this helper is called"
    )]
    pub(crate) async fn current_token(&self) -> String {
        self.device_token
            .as_ref()
            .expect("live device token present for relay dial")
            .lock()
            .await
            .clone()
    }

    fn persist_token(&self, token: &str, expires_at: i64) {
        if let Some(persist) = &self.token_persist {
            persist(token, expires_at);
        }
    }

    pub(crate) async fn refresh_if_current(&self, origin: &str, expected: &str) -> RefreshAction {
        let Some(token_mutex) = &self.device_token else {
            return RefreshAction::Terminal;
        };
        let refresh_guard = self.refresh_lock.clone().lock_owned().await;
        {
            let guard = token_mutex.lock().await;
            if guard.as_str() != expected {
                return RefreshAction::Redial;
            }
        }
        #[expect(
            clippy::large_futures,
            reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
        )]
        let refresh = refresh_device_token(origin, expected).await;
        match refresh {
            RefreshOutcome::Refreshed {
                device_token,
                expires_at,
            } => {
                if let Some(pub_cfg) = &self.publication {
                    let pub_cfg = pub_cfg.clone();
                    let old_token = expected.to_string();
                    let new_token = device_token.clone();
                    let mutex_clone = token_mutex.clone();
                    let ineligible_flag = self.relay_ineligible.clone();
                    let blocking_task = tokio::task::spawn_blocking(move || {
                        let _guard = refresh_guard;
                        let mut action = RefreshAction::Terminal;
                        let fence = pub_cfg.fence.as_deref();
                        let mut publish = || {
                            if let Some(f) = fence {
                                let permit = f.permit(pub_cfg.incarnation);
                                if permit != RelayPermit::Allow {
                                    action = RefreshAction::FenceDenied(permit);
                                    return;
                                }
                            }
                            let ctx = TokenCommitContext {
                                token: &new_token,
                                expires_at,
                                previous_token: &old_token,
                                incarnation: pub_cfg.incarnation,
                            };
                            let commit = pub_cfg.transaction.commit(ctx);
                            match commit {
                                TokenCommit::Unchanged => {
                                    action = RefreshAction::Rejected;
                                }
                                TokenCommit::Indeterminate => {
                                    ineligible_flag.store(true, Ordering::Release);
                                    action = RefreshAction::Indeterminate;
                                }
                                TokenCommit::Committed { .. } => {
                                    let mut g = mutex_clone.blocking_lock();
                                    (*g).clone_from(&new_token);
                                    action = RefreshAction::Redial;
                                }
                            }
                        };
                        if let Some(f) = fence {
                            f.with_publication(&mut publish);
                        } else {
                            publish();
                        }
                        action
                    });
                    blocking_task.await.unwrap_or(RefreshAction::Indeterminate)
                } else {
                    let mut guard = token_mutex.lock().await;
                    #[expect(
                        clippy::assigning_clones,
                        reason = "the refreshed token must remain available for the persistence callback after replacing the live token"
                    )]
                    {
                        *guard = device_token.clone();
                    }
                    drop(guard);
                    self.persist_token(&device_token, expires_at);
                    drop(refresh_guard);
                    RefreshAction::Redial
                }
            }
            RefreshOutcome::ReconnectNeeded => RefreshAction::Terminal,
            RefreshOutcome::TransientError => RefreshAction::Transient,
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the relay carrier dial loop coordinates proactive refresh, loop fence checks, observer recording, and transient retry backoff"
    )]
    async fn dial_carrier_over_relay(
        &self,
        observer: Option<&crate::observe::OperationObserver>,
        policy: CarrierPolicy,
    ) -> Result<DialedCarrier, CarrierOpenError> {
        let origin = self
            .credential
            .relay_origin
            .as_deref()
            .ok_or(CarrierOpenError::Transport(TransportError::NoEndpoint))?;
        let instance_id = &self.credential.instance_id;
        let current = self.current_token().await;
        if token_should_refresh(&current, now_secs()) {
            #[expect(
                clippy::large_futures,
                reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
            )]
            let refresh = self.refresh_if_current(origin, &current).await;
            match policy {
                CarrierPolicy::Legacy => {
                    if matches!(refresh, RefreshAction::Terminal) {
                        return Err(CarrierOpenError::Transport(TransportError::Relay(
                            RelayError::Unauthorized,
                        )));
                    }
                }
                CarrierPolicy::Fenced => match refresh {
                    RefreshAction::Redial | RefreshAction::Transient => {}
                    RefreshAction::Terminal => {
                        return Err(CarrierOpenError::Transport(TransportError::Relay(
                            RelayError::Unauthorized,
                        )));
                    }
                    RefreshAction::Rejected => {
                        return Err(CarrierOpenError::PublicationRejected);
                    }
                    RefreshAction::Indeterminate => {
                        return Err(CarrierOpenError::PublicationIndeterminate);
                    }
                    RefreshAction::FenceDenied(permit) => {
                        return Err(map_fence_permit(permit));
                    }
                },
            }
        }

        let mut reactive_refreshed = false;
        let mut transient_attempt = 0usize;
        loop {
            if policy == CarrierPolicy::Fenced {
                relay_fence_permit(self.publication.as_ref()).map_err(map_fence_permit)?;
            }

            note_dial_attempt(observer);

            let token = self.current_token().await;
            let dialed = dial_relay_carrier(self.config.clone(), origin, instance_id, &token).await;
            self.note_dial(None, dialed.as_ref().map(|_| ()));
            match dialed {
                Ok(carrier) => {
                    note_relay_success(observer);
                    note_selected_path(observer, crate::request::SelectedPath::Relay);
                    return Ok(DialedCarrier {
                        stream: Box::new(carrier.stream),
                        kind: CarrierKind::Relay {
                            termination: carrier.termination,
                        },
                    });
                }
                Err(TransportError::Relay(RelayError::Unauthorized)) => {
                    if reactive_refreshed {
                        return Err(CarrierOpenError::Transport(TransportError::Relay(
                            RelayError::Unauthorized,
                        )));
                    }
                    reactive_refreshed = true;
                    #[expect(
                        clippy::large_futures,
                        reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
                    )]
                    let refresh = self.refresh_if_current(origin, &token).await;
                    match policy {
                        CarrierPolicy::Legacy => match refresh {
                            RefreshAction::Redial => {}
                            RefreshAction::Terminal
                            | RefreshAction::Transient
                            | RefreshAction::Rejected
                            | RefreshAction::Indeterminate
                            | RefreshAction::FenceDenied(_) => {
                                return Err(CarrierOpenError::Transport(TransportError::Relay(
                                    RelayError::Unauthorized,
                                )));
                            }
                        },
                        CarrierPolicy::Fenced => match refresh {
                            RefreshAction::Redial => {}
                            RefreshAction::Terminal | RefreshAction::Transient => {
                                return Err(CarrierOpenError::Transport(TransportError::Relay(
                                    RelayError::Unauthorized,
                                )));
                            }
                            RefreshAction::Rejected => {
                                return Err(CarrierOpenError::PublicationRejected);
                            }
                            RefreshAction::Indeterminate => {
                                return Err(CarrierOpenError::PublicationIndeterminate);
                            }
                            RefreshAction::FenceDenied(permit) => {
                                return Err(map_fence_permit(permit));
                            }
                        },
                    }
                }
                Err(error) if relay_fault_is_transient_err(&error) => {
                    transient_attempt += 1;
                    if transient_attempt >= RELAY_MAX_TRANSIENT_ATTEMPTS {
                        return Err(CarrierOpenError::Transport(error));
                    }
                    tokio::time::sleep(Duration::from_millis(250 * transient_attempt as u64)).await;
                }
                Err(error) => return Err(CarrierOpenError::Transport(error)),
            }
        }
    }
}

fn token_should_refresh(token: &str, now_secs: i64) -> bool {
    #[expect(
        clippy::map_unwrap_or,
        reason = "the copied token predicate keeps the optional decode and false fallback explicit"
    )]
    spl_core::jwt::decode_unverified_claims(token)
        .map(|claims| spl_core::jwt::should_refresh(&claims, now_secs))
        .unwrap_or(false)
}

pub(crate) fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            #[expect(
                clippy::cast_possible_wrap,
                reason = "the source transport preserves its signed Unix-time representation"
            )]
            let seconds = duration.as_secs() as i64;
            seconds
        })
}

pub(crate) fn relay_fault_is_transient_err(error: &TransportError) -> bool {
    matches!(error, TransportError::Relay(relay) if relay.is_transient())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio_rustls::TlsAcceptor;

    use crate::credential::EndpointAddr;

    fn test_client(endpoints: Vec<EndpointAddr>) -> TransportClient {
        test_client_inner(endpoints, None, None)
    }

    fn test_client_with_relay(
        endpoints: Vec<EndpointAddr>,
        relay_origin: String,
        token: String,
    ) -> TransportClient {
        test_client_inner(endpoints, Some(relay_origin), Some(token))
    }

    fn test_client_inner(
        endpoints: Vec<EndpointAddr>,
        relay_origin: Option<String>,
        token: Option<String>,
    ) -> TransportClient {
        TransportClient {
            credential: Credential {
                client_key_pem: String::new(),
                client_cert_pem: String::new(),
                ca_chain_pem: Vec::new(),
                ca_fp_prefix: Vec::new(),
                instance_id: "test-instance".into(),
                home_label: "Test".into(),
                endpoints,
                home_attestation: None,
                local_endpoints: None,
                relay_origin,
                device_token: token.clone(),
                device_token_expires_at: None,
            },
            config: Arc::new(tls::trust_all_pairing_config().unwrap()),
            device_token: token.map(|t| Arc::new(tokio::sync::Mutex::new(t))),
            refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
            token_persist: None,
            publication: None,
            relay_ineligible: Arc::new(AtomicBool::new(false)),
            unknown_journals: Arc::default(),
        }
    }

    async fn scripted_alert_listener(
        description: u8,
    ) -> (EndpointAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let endpoint = EndpointAddr {
            host: "127.0.0.1".into(),
            port: listener.local_addr().unwrap().port(),
        };
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut header = [0u8; 5];
            stream.read_exact(&mut header).await.unwrap();
            let mut hello = vec![0u8; u16::from_be_bytes([header[3], header[4]]) as usize];
            stream.read_exact(&mut hello).await.unwrap();
            stream
                .write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, description])
                .await
                .unwrap();
            stream.flush().await.unwrap();
        });
        (endpoint, task)
    }

    async fn healthy_tls_listener() -> (EndpointAddr, oneshot::Receiver<()>) {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let certificate = CertificateParams::new(vec!["spl.local".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(certificate.der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let endpoint = EndpointAddr {
            host: "127.0.0.1".into(),
            port: listener.local_addr().unwrap().port(),
        };
        let (accepted_tx, accepted_rx) = oneshot::channel();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            TlsAcceptor::from(Arc::new(config))
                .accept(stream)
                .await
                .unwrap();
            let _ = accepted_tx.send(());
        });
        (endpoint, accepted_rx)
    }

    #[test]
    fn relay_fault_is_transient_truth_table() {
        for err in [
            RelayError::HomeOffline,
            RelayError::Abnormal,
            RelayError::Overflow,
            RelayError::Stalled,
        ] {
            assert!(err.is_transient(), "{err:?} should retry");
        }
        for err in [
            RelayError::Unauthorized,
            RelayError::Unpaid,
            RelayError::UnknownInstance,
            RelayError::PairWindowClosed,
            RelayError::UpgradeRejected,
            RelayError::HomeListenConnection,
            RelayError::HomeRelayConfiguration,
            RelayError::HomeTunnelRejected(503),
        ] {
            assert!(!err.is_transient(), "{err:?} should stop");
        }
    }

    // A TLS 1.3 journal checks the client certificate after the client's handshake completes, so
    // an alert received while dialing comes from a peer that has not proven it is the journal and
    // is never its verdict. This covers only that such an alert does not end the dial: the healthy
    // second endpoint is still reached. `a_dial_time_alert_is_an_unclassified_tls_error` covers
    // its classification.
    #[tokio::test]
    async fn dial_time_alerts_are_not_verdicts() {
        for description in [49, 46, 80, 200] {
            let (first, first_task) = scripted_alert_listener(description).await;
            let (second, accepted) = healthy_tls_listener().await;
            let client = test_client(vec![first, second]);

            let carrier = client.dial_carrier().await.unwrap();
            drop(carrier);
            first_task.await.unwrap();
            accepted.await.unwrap();
        }
    }

    // A peer whose certificate does not chain to the pinned CA, such as a journal that
    // regenerated its CA or another journal at a saved address, is named with its address and
    // journal ID. Falsified by leaving pin failures as a generic `Tls(String)`.
    #[tokio::test]
    async fn a_peer_that_is_not_the_journal_is_an_unknown_journal() {
        let (endpoint, _accepted) = healthy_tls_listener().await;
        let config = Arc::new(tls::pairing_config(&[0xAA; 16]).unwrap());
        match crate::connection::dial_tls(config, &endpoint.host, endpoint.port).await {
            Err(TransportError::UnknownJournal(unknown)) => {
                assert_eq!(
                    unknown.address,
                    Some(format!("127.0.0.1:{}", endpoint.port))
                );
                assert!(unknown.jid.is_some());
            }
            Err(other) => panic!("expected an unknown journal, got {other:?}"),
            Ok(_) => panic!("expected an unknown journal, got a connection"),
        }
    }

    // Falsified by classifying dial-time alerts: a peer that has not authenticated could then
    // unpair the device (49) or advance its refusal count.
    #[tokio::test]
    async fn a_dial_time_alert_is_an_unclassified_tls_error() {
        for description in [49, 46, 80, 48, 200] {
            let (endpoint, task) = scripted_alert_listener(description).await;
            let config = Arc::new(tls::trust_all_pairing_config().unwrap());
            assert!(
                matches!(
                    crate::connection::dial_tls(config, &endpoint.host, endpoint.port).await,
                    Err(TransportError::Tls(_))
                ),
                "alert {description}"
            );
            task.await.unwrap();
        }
    }

    fn test_ca() -> (rcgen::Certificate, KeyPair) {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages.push(rcgen::KeyUsagePurpose::KeyCertSign);
        params
            .key_usages
            .push(rcgen::KeyUsagePurpose::DigitalSignature);
        (params.self_signed(&key).unwrap(), key)
    }

    /// A server leaf signed by `ca`, valid now unless `expired`.
    fn test_leaf(
        ca: &rcgen::Certificate,
        ca_key: &KeyPair,
        expired: bool,
    ) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(vec!["spl.local".into()]).unwrap();
        params
            .extended_key_usages
            .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
        if expired {
            params.not_before = rcgen::date_time_ymd(2001, 1, 1);
            params.not_after = rcgen::date_time_ymd(2002, 1, 1);
        }
        let leaf = params.signed_by(&key, ca, ca_key).unwrap();
        (
            CertificateDer::from(leaf.der().to_vec()),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
    }

    /// A listener presenting `chain` once.
    async fn chain_listener(
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> EndpointAddr {
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let endpoint = EndpointAddr {
            host: "127.0.0.1".into(),
            port: listener.local_addr().unwrap().port(),
        };
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = TlsAcceptor::from(Arc::new(config)).accept(stream).await;
        });
        endpoint
    }

    // The paired journal's own certificate outside its dates (or a client clock that is off) is a
    // failure to connect, not another journal. Falsified by attributing every failed binding to
    // another peer: the owner is told a different journal holds their journal's address.
    #[tokio::test]
    async fn the_paired_journals_expired_certificate_is_not_an_unknown_journal() {
        let (ca, ca_key) = test_ca();
        let ca_der = CertificateDer::from(ca.der().to_vec());
        let pin = spl_core::ca::sha256(ca_der.as_ref())[..16].to_vec();
        let (leaf, key) = test_leaf(&ca, &ca_key, true);
        let endpoint = chain_listener(vec![leaf, ca_der.clone()], key).await;
        let mut client = test_client(vec![endpoint.clone()]);
        client.config = Arc::new(tls::pairing_config(&pin).unwrap());
        let dialed =
            crate::connection::dial_tls(client.config.clone(), &endpoint.host, endpoint.port).await;
        client.note_dial(
            Some(&crate::endpoint_address(&endpoint.host, endpoint.port)),
            dialed.as_ref().map(|_| ()),
        );
        assert!(
            matches!(dialed, Err(TransportError::Tls(_))),
            "{:?}",
            dialed.err()
        );
        assert_eq!(client.unknown_journals(), Vec::new());

        // The same CA with a certificate it never signed is not the paired journal.
        let (other, other_key) = test_ca();
        let (foreign_leaf, foreign_key) = test_leaf(&other, &other_key, false);
        let endpoint = chain_listener(vec![foreign_leaf, ca_der], foreign_key).await;
        let config = Arc::new(tls::pairing_config(&pin).unwrap());
        match crate::connection::dial_tls(config, &endpoint.host, endpoint.port).await {
            Err(TransportError::UnknownJournal(unknown)) => assert_eq!(unknown.jid, None),
            Err(other) => panic!("expected an unknown journal, got {other:?}"),
            Ok(_) => panic!("expected an unknown journal, got a connection"),
        }
    }

    // Falsified by reading the peer's identity from its leaf rather than its CA: the reported
    // journal ID is not the one the relay and pairing use.
    #[tokio::test]
    async fn an_unknown_journal_is_named_by_its_ca() {
        let (ca, ca_key) = test_ca();
        let ca_der = CertificateDer::from(ca.der().to_vec());
        let expected = spl_core::relay_window::jid_from_spki(
            &spl_core::ca::extract_spki_der(ca_der.as_ref()).unwrap(),
        )
        .unwrap();
        let (leaf, key) = test_leaf(&ca, &ca_key, false);
        let endpoint = chain_listener(vec![leaf, ca_der], key).await;
        let config = Arc::new(tls::pairing_config(&[0xAA; 16]).unwrap());
        match crate::connection::dial_tls(config, &endpoint.host, endpoint.port).await {
            Err(TransportError::UnknownJournal(unknown)) => {
                assert_eq!(unknown.jid, Some(expected));
            }
            Err(other) => panic!("expected an unknown journal, got {other:?}"),
            Ok(_) => panic!("expected an unknown journal, got a connection"),
        }
    }

    // Falsified by keeping only the last endpoint's error: the closed second endpoint hides the
    // first endpoint's unknown journal and the dial reports an outage.
    #[tokio::test]
    async fn an_unknown_journal_is_not_hidden_by_a_later_unreachable_endpoint() {
        let (refusing, _accepted) = healthy_tls_listener().await;
        let closed = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let closed_endpoint = EndpointAddr {
            host: "127.0.0.1".into(),
            port: closed.local_addr().unwrap().port(),
        };
        drop(closed);
        let mut client = test_client(vec![refusing, closed_endpoint]);
        client.config = Arc::new(tls::pairing_config(&[0xAA; 16]).unwrap());

        assert!(matches!(
            client.dial_carrier().await,
            Err(TransportError::UnknownJournal(_))
        ));
        assert_eq!(client.unknown_journals().len(), 1);
    }

    #[tokio::test]
    async fn a_closed_endpoint_is_not_a_refusal() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let config = Arc::new(tls::trust_all_pairing_config().unwrap());
        assert!(matches!(
            crate::connection::dial_tls(config, "127.0.0.1", port).await,
            Err(TransportError::Io(_))
        ));
    }

    // Falsified by trusting dial-time 49 or 46: the client stops before the relay is tried.
    #[tokio::test]
    async fn a_dial_time_alert_does_not_keep_the_client_off_the_relay() {
        for description in [49, 46] {
            let (first, first_task) = scripted_alert_listener(description).await;
            let relay = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let relay_origin = format!("http://{}", relay.local_addr().unwrap());
            let (relay_accept_tx, relay_accept_rx) = oneshot::channel();
            let relay_task = tokio::spawn(async move {
                let (stream, _) = relay.accept().await.unwrap();
                drop(stream);
                let _ = relay_accept_tx.send(());
            });
            let client = test_client_with_relay(vec![first], relay_origin, "test-token".into());

            let result = client.dial_carrier().await;
            assert!(
                !matches!(
                    result,
                    Err(TransportError::TlsAccessDenied | TransportError::TlsCertificateUnknown)
                ),
                "alert {description}"
            );
            first_task.await.unwrap();
            tokio::time::timeout(Duration::from_secs(10), relay_accept_rx)
                .await
                .expect("relay reached")
                .unwrap();
            relay_task.abort();
        }
    }

    // The fenced path does not end on a dial-time alert either; classification is covered above.
    #[tokio::test]
    async fn open_carrier_dial_time_alerts_are_not_verdicts() {
        for description in [49, 46, 80, 200] {
            let (first, first_task) = scripted_alert_listener(description).await;
            let (second, accepted) = healthy_tls_listener().await;
            let client = test_client(vec![first, second]);

            let carrier = client.open_carrier(None).await.unwrap();
            drop(carrier);
            first_task.await.unwrap();
            accepted.await.unwrap();
        }
    }
}
