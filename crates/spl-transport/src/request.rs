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
use crate::connection::{dial_tls, run_request_over_stream_with_options};
use crate::observe::{OperationObserver, note_dial_attempt, note_selected_path};
use crate::relay::dial_relay_carrier;
use crate::{RelayError, TransportError};

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

fn check_fence(publication: Option<&crate::client::TokenPublication>) -> Result<(), RequestError> {
    if let Some(pub_cfg) = publication
        && let Some(fence) = &pub_cfg.fence
    {
        match fence.permit(pub_cfg.incarnation) {
            RelayPermit::Allow => {}
            RelayPermit::Disabled => return Err(RequestError::RelayDisabled),
            RelayPermit::Retired => return Err(RequestError::RelayRetired),
        }
    }
    Ok(())
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
    /// HTTP, or mux failures.
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

                match dial_tls(self.config.clone(), &endpoint.host, endpoint.port).await {
                    Err(error) => match error {
                        TransportError::TlsAccessDenied | TransportError::TlsCertificateUnknown => {
                            return Err(RequestError::Transport(error));
                        }
                        _ => {
                            last_lan_err = Some(error);
                        }
                    },
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
                        )
                        .await
                        {
                            Ok(response) => {
                                note_selected_path(options.observer, SelectedPath::Direct);
                                return Ok(RequestOutcome {
                                    response,
                                    path: SelectedPath::Direct,
                                    attempts,
                                });
                            }
                            Err(error) => {
                                if matches!(
                                    error,
                                    TransportError::Mux(spl_core::mux::MuxError::CapExceeded)
                                        | TransportError::TlsAccessDenied
                                        | TransportError::TlsCertificateUnknown
                                ) {
                                    return Err(RequestError::Transport(error));
                                }
                                if write_initiated.load(Ordering::Acquire)
                                    && options.replay == ReplayPolicy::ForbidAfterWrite
                                {
                                    return Err(RequestError::ReplayUnsafe(error));
                                }
                                last_lan_err = Some(error);
                            }
                        }
                    }
                }
            }

            match &last_lan_err {
                Some(TransportError::Tls(_) | TransportError::Io(_)) => {
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
            TransportError::Tls(_) | TransportError::Io(_) | TransportError::NoEndpoint
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

            match dial_relay_carrier(self.config.clone(), origin, instance_id, &token).await {
                Ok(carrier) => {
                    let write_initiated = AtomicBool::new(false);
                    match run_request_over_stream_with_options(
                        carrier.stream,
                        method,
                        path,
                        headers,
                        body,
                        options.response_cap,
                        options.observer,
                        &write_initiated,
                    )
                    .await
                    {
                        Ok(response) => {
                            note_selected_path(options.observer, SelectedPath::Relay);
                            return Ok(RequestOutcome {
                                response,
                                path: SelectedPath::Relay,
                                attempts,
                            });
                        }
                        Err(error) => {
                            if matches!(
                                error,
                                TransportError::Mux(spl_core::mux::MuxError::CapExceeded)
                            ) {
                                return Err(RequestError::Transport(error));
                            }
                            if write_initiated.load(Ordering::Acquire)
                                && options.replay == ReplayPolicy::ForbidAfterWrite
                            {
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
