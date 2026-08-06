// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! SPL client transport — the I/O tier over [`spl_core`]'s pure wire.
//!
//! This crate owns the sockets: the CA-fingerprint-pinned mutual-TLS dial to a
//! journal on the local network, the WebSocket relay dial when no direct path
//! exists, the mux carrier that multiplexes many logical streams over one
//! connection, and the local loopback proxy that carries application HTTP into
//! the tunnel.
//!
//! Trust is **CA-fingerprint pinning**, not a system trust store: a presented
//! chain is accepted only if some certificate in it matches the pinned prefix
//! carried by the pair-link, *and* the handshake signature verifies against the
//! leaf the peer actually presented. The two together defeat a relay that echoes
//! a real chain but terminates TLS with its own key.
//!
//! `rustls` is cross-platform, so this crate is host-testable everywhere — a
//! consumer's platform does not change the transport, only what it stores
//! credentials in.
//!
//! # Not in scope
//!
//! Credential *storage* is the consuming product's job: an OS keystore, a
//! DPAPI-sealed blob, or a permission-guarded file are all product decisions.
//! Service lifecycles, retry supervision policy, and application wire types
//! (observer ingest, linked-system provisioning) likewise belong to the consumer.
//!
//! # Public seams
//!
//! [`client::TransportClient`] owns direct-or-relay carrier establishment,
//! including explicit relay-only construction, and accepts an optional
//! [`client::TokenPersistHook`] for consumer-owned, best-effort relay-token
//! persistence. [`relay_pairing::enroll_device`] exposes relay enrollment when
//! the consumer has a fresh pairing-window attestation.
//! [`journal_bridge::CarrierOpener`] combines that transport with consumer
//! authentication without exposing the carrier implementation.
//! [`journal_bridge::BridgePolicy`] selects the loopback port, capability gate,
//! response streaming, authorized local responses, attribution headers, request
//! header forwarding, and request-body limit. [`journal_bridge::JournalBridgeHandle`]
//! returns an owned coherent status snapshot. The bridge always owns exact
//! loopback `Host` validation and reserved-header stripping. Bridge requests allow
//! at most one valid `Content-Length` (absent means no body) and reject
//! `Transfer-Encoding`; their bodies stream through bounded queues that apply
//! carrier backpressure to the local socket. A request is not replayed after the
//! carrier starts consuming it.
//! Credential storage, retry and idempotency policy, and service lifetime remain
//! consumer-owned. Response buffering remains selected by the response path.

#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    expect(
        clippy::collapsible_if,
        clippy::expect_used,
        clippy::large_futures,
        clippy::match_wildcard_for_single_variants,
        clippy::panic,
        clippy::semicolon_if_nothing_returned,
        clippy::similar_names,
        clippy::unwrap_used,
        reason = "copied transport tests use direct fixture assertions while production paths remain fallible"
    )
)]

pub mod client;
pub mod connection;
pub mod credential;
pub mod home_relay;
pub mod journal_bridge;
mod journal_bridge_carrier;
pub mod pairing;
pub mod relay;
pub(crate) mod relay_http;
pub mod relay_pairing;
pub mod relay_token;
pub(crate) mod spki_pin;
pub mod tls;

use std::fmt;
use std::io;

use rustls::{AlertDescription, Error as RustlsError};
use spl_core::http::HttpError;
use spl_core::mux::MuxError;
use thiserror::Error;

/// Typed relay upgrade and close outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayError {
    /// Upgrade HTTP 503; retryable.
    HomeOffline,
    /// Upgrade HTTP 401 or close 4401; refresh may recover it.
    Unauthorized,
    /// Upgrade HTTP 402 or close 4402; terminal.
    Unpaid,
    /// Upgrade HTTP 404; terminal.
    UnknownInstance,
    /// Pair-dial HTTP 401; the journal pairing window is closed or expired.
    PairWindowClosed,
    /// Close 1009; retryable.
    Overflow,
    /// Close 1006/1012 or abnormal drop; retryable by reconnecting.
    Abnormal,
    /// Any other unexpected upgrade HTTP status; terminal.
    UpgradeRejected,
    /// Inner-handshake or first-byte timeout; retryable.
    Stalled,
    /// A home listen WebSocket could not be established or remained open.
    HomeListenConnection,
    /// The configured home relay origin cannot form a WebSocket URL.
    HomeRelayConfiguration,
    /// A home tunnel WebSocket was rejected with this HTTP status.
    HomeTunnelRejected(u16),
}

impl fmt::Display for RelayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::HomeOffline => "home offline",
            Self::Unauthorized => "unauthorized",
            Self::Unpaid => "unpaid",
            Self::UnknownInstance => "unknown instance",
            Self::PairWindowClosed => {
                "the pairing window is closed or expired — regenerate the link on your journal"
            }
            Self::Overflow => "overflow",
            Self::Abnormal => "abnormal close",
            Self::UpgradeRejected => "upgrade rejected",
            Self::Stalled => "stalled",
            Self::HomeListenConnection => "home listen connection failed",
            Self::HomeRelayConfiguration => "invalid home relay configuration",
            Self::HomeTunnelRejected(_) => "home tunnel rejected",
        };
        formatter.write_str(message)
    }
}

/// Relay control-plane operation rejected by the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayControlEndpoint {
    /// Device enrollment after relay pairing.
    EnrollDevice,
    /// Existing device-token refresh.
    TokenRefresh,
}

impl RelayControlEndpoint {
    fn code(self) -> &'static str {
        match self {
            Self::EnrollDevice => "enroll_device",
            Self::TokenRefresh => "refresh",
        }
    }
}

impl fmt::Display for RelayControlEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

/// Errors from SPL connection, TLS, relay, pairing, and HTTP transport.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Socket or stream I/O failed.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// TLS configuration or handshake failed.
    #[error("tls error: {0}")]
    Tls(String),
    /// The peer rejected the TLS session with access denied.
    #[error("tls access denied")]
    TlsAccessDenied,
    /// Cryptographic material or verification failed.
    #[error("crypto error: {0}")]
    Crypto(String),
    /// SPL multiplexer framing failed.
    #[error("mux error: {0}")]
    Mux(#[from] MuxError),
    /// HTTP-over-SPL parsing failed.
    #[error("http error: {0}")]
    Http(#[from] HttpError),
    /// JSON serialization or deserialization failed.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    /// Pair-link parsing or admission failed.
    #[error("pair-link error: {0}")]
    PairLink(String),
    /// Pairing ceremony validation failed.
    #[error("pairing failed: {0}")]
    Pairing(String),
    /// The application endpoint rejected a request.
    #[error("server rejected request: HTTP {status} {body}")]
    Rejected {
        /// HTTP response status.
        status: u16,
        /// Sanitized rejection-body metadata retained for presentation; never contains raw peer response text.
        body: String,
    },
    /// Relay data-plane failure.
    #[error("relay error: {0}")]
    Relay(RelayError),
    /// Relay control-plane request was rejected.
    #[error("relay control {endpoint} rejected request: HTTP {status}")]
    RelayControlRejected {
        /// Control operation that was rejected.
        endpoint: RelayControlEndpoint,
        /// HTTP response status.
        status: u16,
    },
    /// No direct or relay endpoint is available.
    #[error("no reachable journal endpoint")]
    NoEndpoint,
    /// Consumer authentication has not been configured.
    #[error("not paired")]
    NotPaired,
    /// Local offset lookup failed.
    ///
    /// Consumers construct this variant; it is not raised inside this crate.
    #[error("local offset lookup failed")]
    LocalOffset,
}

/// Classify a received TLS access-denied alert without retaining peer-controlled detail.
pub(crate) fn received_access_denied(error: &io::Error) -> Option<TransportError> {
    matches!(
        error
            .get_ref()
            .and_then(|source| source.downcast_ref::<RustlsError>()),
        Some(RustlsError::AlertReceived(AlertDescription::AccessDenied))
    )
    .then_some(TransportError::TlsAccessDenied)
}

/// Return a stable, secret-free diagnostic code for a transport error.
pub fn transport_error_code(error: &TransportError) -> String {
    match error {
        TransportError::Io(_) => "io".to_string(),
        TransportError::Tls(_) => "tls".to_string(),
        TransportError::TlsAccessDenied => "tls_access_denied".to_string(),
        TransportError::Crypto(_) => "crypto".to_string(),
        TransportError::Mux(_) => "mux".to_string(),
        TransportError::Http(_) => "http".to_string(),
        TransportError::Json(_) => "json".to_string(),
        TransportError::PairLink(_) => "pair_link".to_string(),
        TransportError::Pairing(_) => "pairing".to_string(),
        TransportError::Rejected { status, body: _ } => format!("http_{status}"),
        TransportError::Relay(relay) => match relay {
            RelayError::HomeOffline => "relay_home_offline",
            RelayError::Unauthorized => "relay_unauthorized",
            RelayError::Unpaid => "relay_unpaid",
            RelayError::UnknownInstance => "relay_unknown_instance",
            RelayError::PairWindowClosed => "relay_pair_window_closed",
            RelayError::Overflow => "relay_overflow",
            RelayError::Abnormal => "relay_abnormal",
            RelayError::UpgradeRejected => "relay_upgrade_rejected",
            RelayError::Stalled => "relay_stalled",
            RelayError::HomeListenConnection => "relay_home_listen_connection",
            RelayError::HomeRelayConfiguration => "relay_home_configuration",
            RelayError::HomeTunnelRejected(status) => {
                return format!("relay_home_tunnel_http_{status}");
            }
        }
        .to_string(),
        TransportError::RelayControlRejected { endpoint, status } => {
            format!("relay_{}_http_{status}", endpoint.code())
        }
        TransportError::NoEndpoint => "no_endpoint".to_string(),
        TransportError::NotPaired => "not_paired".to_string(),
        TransportError::LocalOffset => "local_offset".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_error_code_maps_every_variant_without_inner_detail() {
        let json_error = serde_json::from_str::<serde_json::Value>("{").unwrap_err();
        let cases = [
            (
                TransportError::Io(std::io::Error::other("C:\\Users\\me\\seg.mp4")),
                "io",
            ),
            (TransportError::Tls("10.0.0.5:7657".into()), "tls"),
            (TransportError::TlsAccessDenied, "tls_access_denied"),
            (TransportError::Crypto("fingerprint abc".into()), "crypto"),
            (TransportError::Mux(MuxError::Incomplete), "mux"),
            (
                TransportError::Http(HttpError::BadStatusLine("HTTP/1.1 SECRET".into())),
                "http",
            ),
            (TransportError::Json(json_error), "json"),
            (TransportError::PairLink("token=abc".into()), "pair_link"),
            (TransportError::Pairing("sha256:abc".into()), "pairing"),
            (
                TransportError::Rejected {
                    status: 503,
                    body: "SECRET https://x/y?token=abc C:\\Users\\me\\seg.mp4".into(),
                },
                "http_503",
            ),
            (
                TransportError::Relay(RelayError::HomeOffline),
                "relay_home_offline",
            ),
            (
                TransportError::Relay(RelayError::Unauthorized),
                "relay_unauthorized",
            ),
            (TransportError::Relay(RelayError::Unpaid), "relay_unpaid"),
            (
                TransportError::Relay(RelayError::UnknownInstance),
                "relay_unknown_instance",
            ),
            (
                TransportError::Relay(RelayError::PairWindowClosed),
                "relay_pair_window_closed",
            ),
            (
                TransportError::Relay(RelayError::Overflow),
                "relay_overflow",
            ),
            (
                TransportError::Relay(RelayError::Abnormal),
                "relay_abnormal",
            ),
            (
                TransportError::Relay(RelayError::UpgradeRejected),
                "relay_upgrade_rejected",
            ),
            (TransportError::Relay(RelayError::Stalled), "relay_stalled"),
            (
                TransportError::Relay(RelayError::HomeListenConnection),
                "relay_home_listen_connection",
            ),
            (
                TransportError::Relay(RelayError::HomeRelayConfiguration),
                "relay_home_configuration",
            ),
            (
                TransportError::Relay(RelayError::HomeTunnelRejected(503)),
                "relay_home_tunnel_http_503",
            ),
            (
                TransportError::RelayControlRejected {
                    endpoint: RelayControlEndpoint::EnrollDevice,
                    status: 409,
                },
                "relay_enroll_device_http_409",
            ),
            (
                TransportError::RelayControlRejected {
                    endpoint: RelayControlEndpoint::TokenRefresh,
                    status: 404,
                },
                "relay_refresh_http_404",
            ),
            (TransportError::NoEndpoint, "no_endpoint"),
            (TransportError::NotPaired, "not_paired"),
            (TransportError::LocalOffset, "local_offset"),
        ];

        for (error, expected) in cases {
            let code = transport_error_code(&error);
            assert_eq!(code, expected);
            assert!(!code.contains("SECRET"));
            assert!(!code.contains("token"));
            assert!(!code.contains("Users"));
            assert!(!code.contains("https://"));
            assert!(!code.contains("sha256:"));
            assert!(!code.contains("10.0.0.5"));
        }
    }
}
