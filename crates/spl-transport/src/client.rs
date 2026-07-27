// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Direct-or-relay carrier dialing for a paired SPL credential.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::connection::dial_tls;
use crate::credential::Credential;
use crate::relay::{RelayTerminationHandle, dial_relay_carrier};
use crate::relay_token::{RefreshOutcome, refresh_device_token};
use crate::{RelayError, TransportError, tls};

/// Relay transient retry count. Mirrors the LAN connection/handshake retry bound.
const RELAY_MAX_TRANSIENT_ATTEMPTS: usize = 5;

enum RefreshAction {
    Redial,
    Terminal,
    Transient,
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
}

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
    credential: Credential,
    config: Arc<ClientConfig>,
    /// Live relay device token; the mutex is the refresh single-flight gate.
    device_token: Option<tokio::sync::Mutex<String>>,
    token_persist: Option<TokenPersistHook>,
}

impl TransportClient {
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
        Self::build(credential, token_persist)
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
        Self::build(credential, token_persist)
    }

    fn build(
        credential: Credential,
        token_persist: Option<TokenPersistHook>,
    ) -> Result<Self, TransportError> {
        let device_token = credential.device_token.clone().map(tokio::sync::Mutex::new);
        let chain = tls::parse_certs(&credential.client_cert_pem)?;
        let key = tls::parse_private_key(&credential.client_key_pem)?;
        let config = Arc::new(tls::mtls_config(&credential.ca_fp_prefix, chain, key)?);
        Ok(Self {
            credential,
            config,
            device_token,
            token_persist,
        })
    }

    /// Establish a persistent carrier, preferring direct LAN endpoints and
    /// falling back to the relay only after transient direct failures.
    ///
    /// A newly paired fingerprint can take a moment to reach every journal
    /// worker because the listener fans out across `SO_REUSEPORT` processes.
    /// Direct connection and handshake failures therefore retain the bounded
    /// linear retry before relay fallback.
    ///
    /// # Errors
    ///
    /// Returns the last direct transport error when relay fallback is
    /// unavailable, or the terminal relay error after bounded relay attempts.
    pub async fn dial_carrier(&self) -> Result<DialedCarrier, TransportError> {
        const MAX_ATTEMPTS: usize = 5;
        let mut last_err: Option<TransportError> = None;
        for attempt in 0..MAX_ATTEMPTS {
            for endpoint in &self.credential.endpoints {
                match dial_tls(self.config.clone(), &endpoint.host, endpoint.port).await {
                    Ok(stream) => {
                        return Ok(DialedCarrier {
                            stream: Box::new(stream),
                            kind: CarrierKind::Lan,
                        });
                    }
                    Err(error) => last_err = Some(error),
                }
            }
            match &last_err {
                Some(TransportError::Tls(_) | TransportError::Io(_)) => {
                    tokio::time::sleep(Duration::from_millis(250 * (attempt as u64 + 1))).await;
                }
                _ => break,
            }
        }

        let lan_err = last_err.unwrap_or(TransportError::NoEndpoint);
        let lan_unreachable = matches!(
            lan_err,
            TransportError::Tls(_) | TransportError::Io(_) | TransportError::NoEndpoint
        );
        if lan_unreachable && self.relay_eligible() {
            #[expect(
                clippy::large_futures,
                reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
            )]
            let relay = self.dial_carrier_over_relay().await;
            return relay;
        }
        Err(lan_err)
    }

    fn relay_eligible(&self) -> bool {
        self.credential.relay_origin.is_some() && self.device_token.is_some()
    }

    #[expect(
        clippy::expect_used,
        reason = "relay eligibility proves the live token mutex is present before this helper is called"
    )]
    async fn current_token(&self) -> String {
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

    async fn refresh_if_current(&self, origin: &str, expected: &str) -> RefreshAction {
        let Some(token) = &self.device_token else {
            return RefreshAction::Terminal;
        };
        let mut guard = token.lock().await;
        if guard.as_str() != expected {
            return RefreshAction::Redial;
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
                #[expect(
                    clippy::assigning_clones,
                    reason = "the refreshed token must remain available for the persistence callback after replacing the live token"
                )]
                {
                    *guard = device_token.clone();
                }
                drop(guard);
                self.persist_token(&device_token, expires_at);
                RefreshAction::Redial
            }
            RefreshOutcome::ReconnectNeeded => RefreshAction::Terminal,
            RefreshOutcome::TransientError => RefreshAction::Transient,
        }
    }

    async fn dial_carrier_over_relay(&self) -> Result<DialedCarrier, TransportError> {
        let origin = self
            .credential
            .relay_origin
            .as_deref()
            .ok_or(TransportError::NoEndpoint)?;
        let instance_id = &self.credential.instance_id;
        let current = self.current_token().await;
        let proactive_refresh = if token_should_refresh(&current, now_secs()) {
            #[expect(
                clippy::large_futures,
                reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
            )]
            let refresh = self.refresh_if_current(origin, &current).await;
            matches!(refresh, RefreshAction::Terminal)
        } else {
            false
        };
        if proactive_refresh {
            return Err(TransportError::Relay(RelayError::Unauthorized));
        }

        let mut reactive_refreshed = false;
        let mut transient_attempt = 0usize;
        loop {
            let token = self.current_token().await;
            match dial_relay_carrier(self.config.clone(), origin, instance_id, &token).await {
                Ok(carrier) => {
                    return Ok(DialedCarrier {
                        stream: Box::new(carrier.stream),
                        kind: CarrierKind::Relay {
                            termination: carrier.termination,
                        },
                    });
                }
                Err(TransportError::Relay(RelayError::Unauthorized)) => {
                    if reactive_refreshed {
                        return Err(TransportError::Relay(RelayError::Unauthorized));
                    }
                    reactive_refreshed = true;
                    #[expect(
                        clippy::large_futures,
                        reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
                    )]
                    let refresh = self.refresh_if_current(origin, &token).await;
                    match refresh {
                        #[expect(
                            clippy::needless_continue,
                            reason = "the explicit redial branch documents that refreshed credentials restart the relay dial loop"
                        )]
                        RefreshAction::Redial => continue,
                        RefreshAction::Terminal | RefreshAction::Transient => {
                            return Err(TransportError::Relay(RelayError::Unauthorized));
                        }
                    }
                }
                Err(error) if relay_fault_is_transient_err(&error) => {
                    transient_attempt += 1;
                    if transient_attempt >= RELAY_MAX_TRANSIENT_ATTEMPTS {
                        return Err(error);
                    }
                    tokio::time::sleep(Duration::from_millis(250 * transient_attempt as u64)).await;
                }
                Err(error) => return Err(error),
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

fn now_secs() -> i64 {
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

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "relay errors are matched by reference consistently with TransportError inspection"
)]
fn relay_fault_is_transient(error: &RelayError) -> bool {
    matches!(
        error,
        RelayError::HomeOffline | RelayError::Abnormal | RelayError::Overflow | RelayError::Stalled
    )
}

fn relay_fault_is_transient_err(error: &TransportError) -> bool {
    matches!(error, TransportError::Relay(relay) if relay_fault_is_transient(relay))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_fault_is_transient_truth_table() {
        for err in [
            RelayError::HomeOffline,
            RelayError::Abnormal,
            RelayError::Overflow,
            RelayError::Stalled,
        ] {
            assert!(relay_fault_is_transient(&err), "{err:?} should retry");
        }
        for err in [
            RelayError::Unauthorized,
            RelayError::Unpaid,
            RelayError::UnknownInstance,
            RelayError::UpgradeRejected,
        ] {
            assert!(!relay_fault_is_transient(&err), "{err:?} should stop");
        }
    }
}
