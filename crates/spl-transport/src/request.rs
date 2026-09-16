// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Production one-request interface for direct and relay transports.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use spl_core::http::HttpResponse;
use spl_core::jwt;
use spl_core::mux::MAX_ASSEMBLED_BYTES;

use crate::client::{
    RefreshAction, RelayPermit, TransportClient, now_secs, relay_fault_is_transient_err,
};
use crate::connection::{RefusalNaming, dial_tls, run_request_over_stream_with_options};
use crate::observe::{
    OperationObserver, note_dial_attempt, note_direct_success, note_relay_success,
    note_selected_path,
};
use crate::relay::dial_relay_carrier;
use crate::{RelayError, TransportError, prefer_refusal};

const MAX_ATTEMPTS: usize = 5;
const RELAY_MAX_TRANSIENT_ATTEMPTS: usize = 5;

/// Replay policy for the request method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReplayPolicy {
    /// If the first request frame has started sending, never retry on direct or fall back to relay.
    #[default]
    ForbidAfterWrite,
    /// Replay is safe even after partial write.
    ReplaySafe,
}

/// The transport path that successfully completed the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectedPath {
    /// Request succeeded over direct LAN mutual-TLS connection.
    Direct,
    /// Request succeeded over WebSocket relay tunnel.
    Relay,
}

/// Options configuring a single request attempt.
#[derive(Debug, Clone)]
pub struct RequestOptions<'a> {
    /// Maximum response body size in bytes before assembly fails with [`spl_core::mux::MuxError::CapExceeded`].
    pub response_cap: usize,
    /// Whether the request may be retried or fallen back to relay after bytes have been written to the wire.
    pub replay: ReplayPolicy,
    /// Optional operation observer.
    pub observer: Option<&'a OperationObserver>,
}

impl Default for RequestOptions<'_> {
    fn default() -> Self {
        Self {
            response_cap: MAX_ASSEMBLED_BYTES,
            replay: ReplayPolicy::ForbidAfterWrite,
            observer: None,
        }
    }
}

/// Successful outcome of a single request.
#[derive(Debug)]
pub struct RequestOutcome {
    /// Assembled HTTP response from the peer.
    pub response: HttpResponse,
    /// The transport path that handled the request.
    pub path: SelectedPath,
    /// Total dial/retry attempts made during the operation.
    pub attempts: u32,
}

/// Errors produced by a single request attempt.
#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    /// An underlying transport or protocol error occurred.
    ///
    /// Remote 401 Unauthorized from the relay is reported here as
    /// `RequestError::Transport(TransportError::Relay(RelayError::Unauthorized))`.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// Request failed after write was initiated and cannot be safely replayed under [`ReplayPolicy::ForbidAfterWrite`].
    ///
    /// A journal's refusal other than access denied or certificate unknown
    /// arrives here once the request was written; see
    /// [`RequestError::transport_error`].
    #[error("request failed after write was initiated and cannot be safely replayed: {0}")]
    ReplayUnsafe(TransportError),
    /// Local relay fence disabled. This is a local lifecycle gate denial, never a remote unauthorized error.
    #[error("local relay fence disabled")]
    RelayDisabled,
    /// Local relay fence retired or stale incarnation. This is a local lifecycle gate denial, never a remote unauthorized error.
    #[error("local relay fence retired or stale incarnation")]
    RelayRetired,
    /// Token publication rejected by durable storage ([`crate::client::TokenCommit::Unchanged`]).
    #[error("token publication rejected")]
    PublicationRejected,
    /// Token publication indeterminate ([`crate::client::TokenCommit::Indeterminate`]); client is marked relay-ineligible.
    #[error("token publication indeterminate; client relay-ineligible")]
    PublicationIndeterminate,
}

/// A relay that closed the tunnel keeps precedence over a TLS refusal read
/// through it, as on the carrier path.
fn relay_close_first(error: TransportError, relay: Option<RelayError>) -> TransportError {
    match (&error, relay) {
        (
            TransportError::TlsAccessDenied
            | TransportError::TlsCertificateUnknown
            | TransportError::TlsRefused,
            Some(relay),
        ) => TransportError::Relay(relay),
        _ => error,
    }
}

impl RequestError {
    /// The transport error behind this request error, whether or not the
    /// request is safe to replay.
    ///
    /// Classify refusals from this, not from [`RequestError::Transport`] alone:
    /// under [`ReplayPolicy::ForbidAfterWrite`] a counted refusal arrives as
    /// [`RequestError::ReplayUnsafe`], and a tracker fed only the other variant
    /// never reaches its limit.
    #[must_use]
    pub fn transport_error(&self) -> Option<&TransportError> {
        match self {
            Self::Transport(error) | Self::ReplayUnsafe(error) => Some(error),
            Self::RelayDisabled
            | Self::RelayRetired
            | Self::PublicationRejected
            | Self::PublicationIndeterminate => None,
        }
    }
}

/// End the request on an over-cap response or on the journal's refusal of this
/// device; hand any other error back to the caller.
///
/// Every endpoint and the relay reach the same journal, so its refusal is the
/// answer. Access denied (49) and certificate unknown (46) come only from the
/// journal's check of this device's certificate, before it reads anything, so
/// they are never a replay hazard. Any other refusal alert proves nothing about
/// whether the journal read the request (a corrupted record after it ran the
/// request also ends in one), so after a write it keeps the replay guarantee.
fn end_on_refusal(
    error: TransportError,
    write_started: bool,
) -> Result<TransportError, RequestError> {
    match error {
        TransportError::TlsRefused if write_started => Err(RequestError::ReplayUnsafe(error)),
        TransportError::Mux(spl_core::mux::MuxError::CapExceeded)
        | TransportError::TlsAccessDenied
        | TransportError::TlsCertificateUnknown
        | TransportError::TlsRefused => Err(RequestError::Transport(error)),
        other => Ok(other),
    }
}

fn check_fence(publication: Option<&crate::client::TokenPublication>) -> Result<(), RequestError> {
    match crate::client::relay_fence_permit(publication) {
        Ok(()) | Err(RelayPermit::Allow) => Ok(()),
        Err(RelayPermit::Disabled) => Err(RequestError::RelayDisabled),
        Err(RelayPermit::Retired) => Err(RequestError::RelayRetired),
    }
}

impl TransportClient {
    /// Send a single HTTP request over direct LAN or relay with response bounding,
    /// observation, and write-initiated replay protection.
    ///
    /// # Errors
    ///
    /// Returns [`RequestError::ReplayUnsafe`] if an error occurs after request-frame
    /// transmission has begun under [`ReplayPolicy::ForbidAfterWrite`]. Returns
    /// [`RequestError::RelayDisabled`] or [`RequestError::RelayRetired`] if the local
    /// fence prevents relay access, or [`RequestError::Transport`] for network, TLS,
    /// HTTP, or mux failures. A journal's refusal of this device is
    /// [`TransportError::TlsAccessDenied`], [`TransportError::TlsCertificateUnknown`]
    /// or [`TransportError::TlsRefused`]; the last arrives as
    /// [`RequestError::ReplayUnsafe`] once the request was written under
    /// [`ReplayPolicy::ForbidAfterWrite`]. Use [`RequestError::transport_error`] to
    /// classify either.
    #[expect(
        clippy::too_many_lines,
        reason = "request handles LAN iteration, fallback, fence checks, and relay retry in one coherent method"
    )]
    pub async fn request(
        &self,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: &[u8],
        options: RequestOptions<'_>,
    ) -> Result<RequestOutcome, RequestError> {
        let mut attempts = 0u32;
        let mut last_lan_err = None;

        // 1. Direct LAN iteration
        for attempt in 0..MAX_ATTEMPTS {
            for endpoint in &self.credential.endpoints {
                attempts += 1;
                note_dial_attempt(options.observer);

                let dialed = dial_tls(self.config.clone(), &endpoint.host, endpoint.port).await;
                self.note_dial(
                    Some(&crate::endpoint_address(&endpoint.host, endpoint.port)),
                    dialed.as_ref().map(|_| ()),
                );
                match dialed {
                    Err(error) => {
                        last_lan_err = Some(prefer_refusal(last_lan_err.take(), error));
                    }
                    Ok(stream) => {
                        let write_initiated = AtomicBool::new(false);
                        match run_request_over_stream_with_options(
                            stream,
                            method,
                            path,
                            headers,
                            body,
                            options.response_cap,
                            options.observer,
                            &write_initiated,
                            RefusalNaming::BeforeFirstData,
                        )
                        .await
                        {
                            Ok(response) => {
                                note_direct_success(options.observer);
                                note_selected_path(options.observer, SelectedPath::Direct);
                                return Ok(RequestOutcome {
                                    response,
                                    path: SelectedPath::Direct,
                                    attempts,
                                });
                            }
                            Err(error) => {
                                let write_started = write_initiated.load(Ordering::Acquire)
                                    && options.replay == ReplayPolicy::ForbidAfterWrite;
                                let error = end_on_refusal(error, write_started)?;
                                if write_started {
                                    return Err(RequestError::ReplayUnsafe(error));
                                }
                                last_lan_err = Some(prefer_refusal(last_lan_err.take(), error));
                            }
                        }
                    }
                }
            }

            match &last_lan_err {
                Some(
                    TransportError::Tls(_)
                    | TransportError::UnknownJournal(_)
                    | TransportError::Io(_),
                ) => {
                    if attempt + 1 < MAX_ATTEMPTS {
                        tokio::time::sleep(Duration::from_millis(250 * (attempt as u64 + 1))).await;
                    }
                }
                _ => break,
            }
        }

        let lan_err = last_lan_err.unwrap_or(TransportError::NoEndpoint);
        let lan_unreachable = matches!(
            lan_err,
            TransportError::Tls(_)
                | TransportError::UnknownJournal(_)
                | TransportError::Io(_)
                | TransportError::NoEndpoint
        );
        if !lan_unreachable {
            return Err(RequestError::Transport(lan_err));
        }

        // 2. Relay fallback
        if self.relay_ineligible.load(Ordering::SeqCst) {
            return Err(RequestError::PublicationIndeterminate);
        }
        if !self.relay_eligible() {
            return Err(RequestError::Transport(lan_err));
        }

        let origin = self
            .credential
            .relay_origin
            .as_deref()
            .ok_or(TransportError::NoEndpoint)?;
        let instance_id = &self.credential.instance_id;

        let current = self.current_token().await;
        let proactive_refresh_needed = if let Some(claims) = jwt::decode_unverified_claims(&current)
        {
            jwt::should_refresh(&claims, now_secs())
        } else {
            false
        };

        if proactive_refresh_needed {
            match Box::pin(self.refresh_if_current(origin, &current)).await {
                RefreshAction::Redial | RefreshAction::Transient => {}
                RefreshAction::Terminal => {
                    return Err(RequestError::Transport(TransportError::Relay(
                        RelayError::Unauthorized,
                    )));
                }
                RefreshAction::Rejected => {
                    return Err(RequestError::PublicationRejected);
                }
                RefreshAction::Indeterminate => {
                    return Err(RequestError::PublicationIndeterminate);
                }
                RefreshAction::FenceDenied(permit) => match permit {
                    RelayPermit::Disabled => return Err(RequestError::RelayDisabled),
                    RelayPermit::Retired => return Err(RequestError::RelayRetired),
                    RelayPermit::Allow => {}
                },
            }
        }

        let mut reactive_refreshed = false;
        let mut transient_attempt = 0usize;

        loop {
            check_fence(self.publication.as_ref())?;

            let token = self.current_token().await;
            attempts += 1;
            note_dial_attempt(options.observer);

            let dialed = dial_relay_carrier(self.config.clone(), origin, instance_id, &token).await;
            self.note_dial(None, dialed.as_ref().map(|_| ()));
            match dialed {
                Ok(carrier) => {
                    let write_initiated = AtomicBool::new(false);
                    let termination = carrier.termination;
                    match run_request_over_stream_with_options(
                        carrier.stream,
                        method,
                        path,
                        headers,
                        body,
                        options.response_cap,
                        options.observer,
                        &write_initiated,
                        RefusalNaming::BeforeFirstData,
                    )
                    .await
                    {
                        Ok(response) => {
                            note_relay_success(options.observer);
                            note_selected_path(options.observer, SelectedPath::Relay);
                            return Ok(RequestOutcome {
                                response,
                                path: SelectedPath::Relay,
                                attempts,
                            });
                        }
                        Err(error) => {
                            let error = relay_close_first(error, termination.current_error());
                            let write_started = write_initiated.load(Ordering::Acquire)
                                && options.replay == ReplayPolicy::ForbidAfterWrite;
                            let error = end_on_refusal(error, write_started)?;
                            if write_started {
                                return Err(RequestError::ReplayUnsafe(error));
                            }
                            if relay_fault_is_transient_err(&error)
                                || (matches!(error, TransportError::Io(_))
                                    && options.replay == ReplayPolicy::ReplaySafe)
                            {
                                transient_attempt += 1;
                                if transient_attempt >= RELAY_MAX_TRANSIENT_ATTEMPTS {
                                    return Err(RequestError::Transport(error));
                                }
                                tokio::time::sleep(Duration::from_millis(
                                    250 * transient_attempt as u64,
                                ))
                                .await;
                            } else {
                                return Err(RequestError::Transport(error));
                            }
                        }
                    }
                }
                Err(TransportError::Relay(RelayError::Unauthorized)) => {
                    if reactive_refreshed {
                        return Err(RequestError::Transport(TransportError::Relay(
                            RelayError::Unauthorized,
                        )));
                    }
                    reactive_refreshed = true;
                    match Box::pin(self.refresh_if_current(origin, &token)).await {
                        RefreshAction::Redial => {}
                        RefreshAction::Terminal | RefreshAction::Transient => {
                            return Err(RequestError::Transport(TransportError::Relay(
                                RelayError::Unauthorized,
                            )));
                        }
                        RefreshAction::Rejected => {
                            return Err(RequestError::PublicationRejected);
                        }
                        RefreshAction::Indeterminate => {
                            return Err(RequestError::PublicationIndeterminate);
                        }
                        RefreshAction::FenceDenied(permit) => match permit {
                            RelayPermit::Disabled => return Err(RequestError::RelayDisabled),
                            RelayPermit::Retired => return Err(RequestError::RelayRetired),
                            RelayPermit::Allow => {}
                        },
                    }
                }
                Err(error) if relay_fault_is_transient_err(&error) => {
                    transient_attempt += 1;
                    if transient_attempt >= RELAY_MAX_TRANSIENT_ATTEMPTS {
                        return Err(RequestError::Transport(error));
                    }
                    tokio::time::sleep(Duration::from_millis(250 * transient_attempt as u64)).await;
                }
                Err(error) => {
                    return Err(RequestError::Transport(error));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_error_reads_through_either_variant() {
        assert!(matches!(
            RequestError::Transport(TransportError::TlsRefused).transport_error(),
            Some(TransportError::TlsRefused)
        ));
        assert!(matches!(
            RequestError::ReplayUnsafe(TransportError::TlsRefused).transport_error(),
            Some(TransportError::TlsRefused)
        ));
        assert!(RequestError::RelayDisabled.transport_error().is_none());
    }

    // Falsified by naming the refusal first: a relay that closed the tunnel would be reported as
    // the journal refusing this device.
    #[test]
    fn a_recorded_relay_close_precedes_a_refusal_read_through_it() {
        for refusal in [
            TransportError::TlsAccessDenied,
            TransportError::TlsCertificateUnknown,
            TransportError::TlsRefused,
        ] {
            assert!(matches!(
                relay_close_first(refusal, Some(RelayError::Unauthorized)),
                TransportError::Relay(RelayError::Unauthorized)
            ));
        }
        assert!(matches!(
            relay_close_first(TransportError::TlsRefused, None),
            TransportError::TlsRefused
        ));
        assert!(matches!(
            relay_close_first(
                TransportError::Io(std::io::Error::from(std::io::ErrorKind::BrokenPipe)),
                Some(RelayError::Abnormal)
            ),
            TransportError::Io(_)
        ));
    }
}
