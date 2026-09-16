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
//! Trust uses a pinned home CA. The verifier checks the CA's self-signature,
//! validates the peer leaf's signature against that CA, and verifies the TLS
//! handshake signature against the leaf. Inner connections require TLS 1.3.
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
//! persistence. Transactional consumers configure [`client::TokenPublication`]
//! via [`client::TransportClient::new_with_publication`] or
//! [`client::TransportClient::new_relay_only_with_publication`], executing
//! durable commits before live assignment inside an owned background task.
//! [`client::RelayFence`] gates relay communication locally against consumer
//! lifecycle (`Disabled`/`Retired`), distinctly from remote `RelayError::Unauthorized`.
//! [`client::TransportClient::open_carrier`] provides fence-coordinated,
//! observer-capable persistent-carrier establishment for lifecycle-fenced consumers
//! and journal-bridge adapters. Note that [`client::TransportClient::dial_carrier`]
//! remains frozen and does not enforce the local fence or attach an observer.
//!
//! [`client::TransportClient::request`] provides one-request execution over direct
//! LAN or relay fallback with write-initiated replay protection ([`request::ReplayPolicy`]),
//! response byte limits ([`request::RequestOptions`]), operation observation
//! ([`observe::OperationObserver`]), and classified outcomes ([`request::RequestOutcome`]
//! or [`request::RequestError`]).
//!
//! [`relay_pairing::enroll_device`] exposes relay enrollment when the consumer has
//! a fresh pairing-window attestation.
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
pub mod handshake;
pub mod home_relay;
pub mod journal_bridge;
mod journal_bridge_carrier;
pub mod observe;
pub mod pairing;
pub mod relay;
pub(crate) mod relay_http;
pub use relay_http::{same_relay_origin, validate_relay_origin};
pub mod relay_pairing;
pub mod relay_token;
pub mod request;
pub(crate) mod spki_pin;
pub mod tls;

pub use client::{
    CarrierOpenError, DialedCarrier, RelayFence, RelayPermit, TokenCommit, TokenCommitContext,
    TokenPersistHook, TokenPublication, TokenTransaction, TransportClient,
};
pub use observe::{OperationObserver, OperationSnapshot};
pub use pairing::{
    DirectPairPrepareFuture, DirectPairSendFuture, DirectPairingSeam, PreparedDirectPairConnection,
    pair, pair_from_link, pair_from_link_observed, pair_observed, pair_with_seam,
    pair_with_seam_observed,
};
pub use relay_pairing::{
    PairingMaterial, pair_over_carrier, pair_over_relay, pair_over_relay_observed,
};
pub use request::{ReplayPolicy, RequestError, RequestOptions, RequestOutcome, SelectedPath};

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

impl RelayError {
    /// Whether retrying the relay data-plane operation can recover without
    /// changing credentials or configuration.
    #[must_use]
    pub const fn is_transient(self) -> bool {
        matches!(
            self,
            Self::HomeOffline | Self::Overflow | Self::Abnormal | Self::Stalled
        )
    }
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

/// A peer that answered where the paired journal was expected, but is not it.
///
/// Seen while dialing, before any request: the peer presented a certificate
/// that does not chain to the paired journal's CA. A journal whose CA changed
/// has a new journal ID, so this is how both "a different journal holds this
/// address" and "this journal was reset" look to a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownJournal {
    /// The direct endpoint (`host:port`) that answered, or `None` when the
    /// peer answered through the relay.
    pub address: Option<String>,
    /// The journal ID the peer presented: the ID of the self-signed P-256
    /// certificate in its chain, as a journal's CA is. This is what the peer
    /// claims, not a proven identity, because any peer can present another
    /// journal's public CA certificate. Show it to the owner; never decide
    /// anything on it. `None` when the peer presented no such certificate, or
    /// presented the paired journal's CA without a certificate that CA signed.
    pub jid: Option<String>,
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
    /// The peer rejected the TLS session with certificate unknown.
    #[error("tls certificate unknown")]
    TlsCertificateUnknown,
    /// The journal refused the TLS session with an alert other than access
    /// denied or certificate unknown.
    #[error("tls refused")]
    TlsRefused,
    /// A peer that is not the paired journal answered while dialing.
    #[error("unknown journal")]
    UnknownJournal(UnknownJournal),
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

/// A direct endpoint as `host:port`, bracketing an IPv6 host.
pub(crate) fn endpoint_address(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Classify a TLS failure seen while dialing, without retaining peer-controlled detail.
///
/// A TLS 1.3 journal checks the client certificate only after the client's side
/// of the handshake is complete, so its verdict never arrives while dialing. A
/// received alert at this point comes from a peer that has not authenticated
/// and is not trusted. A peer whose certificate the pin check found is not the
/// paired journal's is an [`TransportError::UnknownJournal`] at `address`
/// (`None` through the relay). Any other certificate failure is left
/// unclassified.
pub(crate) fn classify_dial_refusal(
    error: &io::Error,
    address: Option<&str>,
) -> Option<TransportError> {
    let Some(RustlsError::InvalidCertificate(rustls::CertificateError::Other(other))) = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<RustlsError>())
    else {
        return None;
    };
    let mismatch = other.0.downcast_ref::<tls::JournalIdentityMismatch>()?;
    Some(TransportError::UnknownJournal(UnknownJournal {
        address: address.map(str::to_owned),
        jid: mismatch.jid.clone(),
    }))
}

/// Keep the more informative of two failed direct-dial errors, so the order of
/// a credential's endpoints cannot hide anything: a journal's own answer
/// outranks its refusal, a refusal outranks a peer that is not the journal, and
/// that outranks a failure to reach an endpoint at all. On a tie the later
/// error wins.
pub(crate) fn prefer_refusal(
    previous: Option<TransportError>,
    next: TransportError,
) -> TransportError {
    fn rank(error: &TransportError) -> u8 {
        match error {
            TransportError::Io(_) | TransportError::Tls(_) | TransportError::NoEndpoint => 0,
            TransportError::UnknownJournal(_) => 1,
            TransportError::TlsRefused => 2,
            _ => 3,
        }
    }
    match previous {
        Some(previous) if rank(&previous) > rank(&next) => previous,
        _ => next,
    }
}

/// Classify a TLS refusal on an authenticated connection, without retaining
/// peer-controlled detail.
///
/// Call this only once the handshake has completed and before the peer has
/// sent any application data: that is when a journal's verdict on the client
/// certificate arrives. Access denied (49) and certificate unknown (46) have
/// their own variants. Any other received alert is a
/// [`TransportError::TlsRefused`]. Everything else, including a plain socket
/// error, a timeout, or a peer that does not speak TLS, is not a refusal and
/// returns `None`.
pub(crate) fn classify_tls_refusal(error: &io::Error) -> Option<TransportError> {
    match error
        .get_ref()
        .and_then(|source| source.downcast_ref::<RustlsError>())
    {
        Some(RustlsError::AlertReceived(AlertDescription::AccessDenied)) => {
            Some(TransportError::TlsAccessDenied)
        }
        Some(RustlsError::AlertReceived(AlertDescription::CertificateUnknown)) => {
            Some(TransportError::TlsCertificateUnknown)
        }
        Some(RustlsError::AlertReceived(_)) => Some(TransportError::TlsRefused),
        _ => None,
    }
}

/// Return a stable, secret-free diagnostic code for a transport error.
pub fn transport_error_code(error: &TransportError) -> String {
    match error {
        TransportError::Io(_) => "io".to_string(),
        TransportError::Tls(_) => "tls".to_string(),
        TransportError::TlsAccessDenied => "tls_access_denied".to_string(),
        TransportError::TlsCertificateUnknown => "tls_certificate_unknown".to_string(),
        TransportError::TlsRefused => "tls_refused".to_string(),
        TransportError::UnknownJournal(_) => "unknown_journal".to_string(),
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
    fn unknown_journal_code_carries_neither_address_nor_journal_id() {
        let code = transport_error_code(&TransportError::UnknownJournal(UnknownJournal {
            address: Some("10.0.0.5:7657".into()),
            jid: Some("jSECRET".into()),
        }));
        assert_eq!(code, "unknown_journal");
    }

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
            (
                TransportError::TlsCertificateUnknown,
                "tls_certificate_unknown",
            ),
            (TransportError::TlsRefused, "tls_refused"),
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

    fn tls_io_error(source: RustlsError) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, source)
    }

    // Falsified by narrowing the refusal arm to recognized codes: 80 and an unassigned code
    // then read as "not a refusal", which is the retry-forever defect session.md § 7 forbids.
    #[test]
    fn classify_tls_refusal_names_49_and_46_and_folds_every_other_refusal() {
        assert!(matches!(
            classify_tls_refusal(&tls_io_error(RustlsError::AlertReceived(
                AlertDescription::AccessDenied
            ))),
            Some(TransportError::TlsAccessDenied)
        ));
        assert!(matches!(
            classify_tls_refusal(&tls_io_error(RustlsError::AlertReceived(
                AlertDescription::CertificateUnknown
            ))),
            Some(TransportError::TlsCertificateUnknown)
        ));
        for description in [
            AlertDescription::InternalError,
            AlertDescription::UnknownCA,
            AlertDescription::BadCertificate,
            AlertDescription::Unknown(200),
        ] {
            assert!(matches!(
                classify_tls_refusal(&tls_io_error(RustlsError::AlertReceived(description))),
                Some(TransportError::TlsRefused)
            ));
        }
        // The journal's certificate was checked while dialing; it is not a refusal.
        assert!(
            classify_tls_refusal(&tls_io_error(RustlsError::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer
            )))
            .is_none()
        );
    }

    // Falsified by keeping only the last endpoint's error: a refusal followed by an unreachable
    // endpoint would be reported as unreachable and never counted.
    #[test]
    fn a_refusal_outranks_a_later_unreachable_endpoint() {
        let unreachable = || TransportError::Io(io::Error::from(io::ErrorKind::ConnectionRefused));
        assert!(matches!(
            prefer_refusal(Some(TransportError::TlsRefused), unreachable()),
            TransportError::TlsRefused
        ));
        assert!(matches!(
            prefer_refusal(Some(unreachable()), TransportError::TlsRefused),
            TransportError::TlsRefused
        ));
        assert!(matches!(
            prefer_refusal(None, unreachable()),
            TransportError::Io(_)
        ));
        assert!(matches!(
            prefer_refusal(Some(TransportError::Tls("x".into())), unreachable()),
            TransportError::Io(_)
        ));
        // What a journal that accepted the handshake said is never hidden by a refusal elsewhere,
        // whichever endpoint came first.
        assert!(matches!(
            prefer_refusal(
                Some(TransportError::TlsRefused),
                TransportError::Mux(spl_core::mux::MuxError::Incomplete)
            ),
            TransportError::Mux(_)
        ));
        assert!(matches!(
            prefer_refusal(
                Some(TransportError::Mux(spl_core::mux::MuxError::Incomplete)),
                TransportError::TlsRefused
            ),
            TransportError::Mux(_)
        ));
        assert!(matches!(
            prefer_refusal(Some(TransportError::TlsRefused), TransportError::TlsRefused),
            TransportError::TlsRefused
        ));
    }

    // Falsified by ranking an unknown journal with unreachable endpoints: a stale address that
    // now holds another journal would be reported as offline, and the owner never told.
    #[test]
    fn an_unknown_journal_outranks_unreachable_and_yields_to_a_refusal() {
        let unreachable = || TransportError::Io(io::Error::from(io::ErrorKind::ConnectionRefused));
        let unknown = || {
            TransportError::UnknownJournal(UnknownJournal {
                address: Some("10.0.0.5:7657".into()),
                jid: None,
            })
        };
        for (previous, next) in [
            (Some(unknown()), unreachable()),
            (Some(unreachable()), unknown()),
        ] {
            assert!(matches!(
                prefer_refusal(previous, next),
                TransportError::UnknownJournal(_)
            ));
        }
        for (previous, next) in [
            (Some(unknown()), TransportError::TlsRefused),
            (Some(TransportError::TlsRefused), unknown()),
        ] {
            assert!(matches!(
                prefer_refusal(previous, next),
                TransportError::TlsRefused
            ));
        }
    }

    // Falsified by trusting a dial-time alert: an unauthenticated peer could unpair the device.
    #[test]
    fn classify_dial_refusal_trusts_only_the_certificate_check() {
        for description in [
            AlertDescription::AccessDenied,
            AlertDescription::CertificateUnknown,
            AlertDescription::InternalError,
            AlertDescription::Unknown(200),
        ] {
            assert!(
                classify_dial_refusal(
                    &tls_io_error(RustlsError::AlertReceived(description)),
                    Some("10.0.0.5:7657")
                )
                .is_none()
            );
        }
        assert!(
            classify_dial_refusal(
                &io::Error::from(io::ErrorKind::ConnectionReset),
                Some("10.0.0.5:7657")
            )
            .is_none()
        );
    }

    // Falsified by dropping the identity the verifier carried, or the address: the owner could
    // not be shown which peer answered or where.
    #[test]
    fn classify_dial_refusal_names_the_peer_that_is_not_the_journal() {
        let mismatch = |jid: Option<&str>| {
            tls_io_error(RustlsError::InvalidCertificate(
                rustls::CertificateError::Other(rustls::OtherError(std::sync::Arc::new(
                    tls::JournalIdentityMismatch {
                        jid: jid.map(str::to_owned),
                    },
                ))),
            ))
        };
        assert_eq!(
            classify_dial_refusal(&mismatch(Some("jOTHER")), Some("10.0.0.5:7657")).map(|error| {
                match error {
                    TransportError::UnknownJournal(unknown) => Some(unknown),
                    _ => None,
                }
            }),
            Some(Some(UnknownJournal {
                address: Some("10.0.0.5:7657".into()),
                jid: Some("jOTHER".into()),
            }))
        );
        assert!(matches!(
            classify_dial_refusal(&mismatch(None), None),
            Some(TransportError::UnknownJournal(UnknownJournal {
                address: None,
                jid: None
            }))
        ));
        // A certificate failure the pin check did not attribute to another peer, such as the
        // paired journal's own certificate outside its dates, is not an unknown journal.
        for other in [
            rustls::CertificateError::UnknownIssuer,
            rustls::CertificateError::Expired,
            rustls::CertificateError::Other(rustls::OtherError(std::sync::Arc::new(
                io::Error::other("unrelated"),
            ))),
        ] {
            assert!(
                classify_dial_refusal(
                    &tls_io_error(RustlsError::InvalidCertificate(other)),
                    Some("10.0.0.5:7657")
                )
                .is_none()
            );
        }
    }

    #[test]
    fn endpoint_address_brackets_only_a_bare_ipv6_host() {
        assert_eq!(endpoint_address("10.0.0.5", 7657), "10.0.0.5:7657");
        assert_eq!(
            endpoint_address("journal.local", 7657),
            "journal.local:7657"
        );
        assert_eq!(endpoint_address("fe80::1", 7657), "[fe80::1]:7657");
        assert_eq!(endpoint_address("[fe80::1]", 7657), "[fe80::1]:7657");
    }

    #[test]
    fn classify_tls_refusal_leaves_transport_failures_unclassified() {
        assert!(classify_tls_refusal(&tls_io_error(RustlsError::DecryptError)).is_none());
        assert!(
            classify_tls_refusal(&tls_io_error(RustlsError::InvalidMessage(
                rustls::InvalidMessage::InvalidContentType
            )))
            .is_none()
        );
        assert!(classify_tls_refusal(&io::Error::from(io::ErrorKind::UnexpectedEof)).is_none());
        assert!(classify_tls_refusal(&io::Error::from(io::ErrorKind::ConnectionReset)).is_none());
    }
}
