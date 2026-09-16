// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Compile-time assertion that `TransportError` and `RelayError` have closed variant sets.
//!
//! If a variant is added or removed from either enum, this fixture will fail to compile
//! because of non-exhaustive matching.

use spl_transport::{CarrierOpenError, RelayError, TransportError};

#[allow(dead_code)]
fn match_carrier_open_error_exhaustively(err: &CarrierOpenError) -> &'static str {
    match err {
        CarrierOpenError::Transport(_) => "transport",
        CarrierOpenError::RelayDisabled => "relay_disabled",
        CarrierOpenError::RelayRetired => "relay_retired",
        CarrierOpenError::PublicationRejected => "publication_rejected",
        CarrierOpenError::PublicationIndeterminate => "publication_indeterminate",
    }
}

#[allow(dead_code)]
fn match_transport_error_exhaustively(err: &TransportError) -> &'static str {
    match err {
        TransportError::Io(_) => "io",
        TransportError::Tls(_) => "tls",
        TransportError::TlsAccessDenied => "tls_access_denied",
        TransportError::TlsCertificateUnknown => "tls_certificate_unknown",
        TransportError::TlsRefused => "tls_refused",
        TransportError::UnknownJournal(_) => "unknown_journal",
        TransportError::Crypto(_) => "crypto",
        TransportError::Mux(_) => "mux",
        TransportError::Http(_) => "http",
        TransportError::Json(_) => "json",
        TransportError::PairLink(_) => "pair_link",
        TransportError::Pairing(_) => "pairing",
        TransportError::Rejected { .. } => "rejected",
        TransportError::Relay(_) => "relay",
        TransportError::RelayControlRejected { .. } => "relay_control_rejected",
        TransportError::NoEndpoint => "no_endpoint",
        TransportError::NotPaired => "not_paired",
        TransportError::LocalOffset => "local_offset",
    }
}

#[allow(dead_code)]
fn match_relay_error_exhaustively(err: RelayError) -> &'static str {
    match err {
        RelayError::HomeOffline => "home_offline",
        RelayError::Unauthorized => "unauthorized",
        RelayError::Unpaid => "unpaid",
        RelayError::UnknownInstance => "unknown_instance",
        RelayError::PairWindowClosed => "pair_window_closed",
        RelayError::Overflow => "overflow",
        RelayError::Abnormal => "abnormal",
        RelayError::UpgradeRejected => "upgrade_rejected",
        RelayError::Stalled => "stalled",
        RelayError::HomeListenConnection => "home_listen_connection",
        RelayError::HomeRelayConfiguration => "home_relay_configuration",
        RelayError::HomeTunnelRejected(_) => "home_tunnel_rejected",
    }
}

#[test]
fn error_variants_compile_check() {
    // Assert that the functions exist and are callable.
    let _ = match_relay_error_exhaustively(RelayError::HomeOffline);
}
