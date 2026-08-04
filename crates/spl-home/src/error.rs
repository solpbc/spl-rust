// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Secret-safe listener errors and peer-refusal classifications.

use spl_core::frame::{FrameError, FrameViolation};
use thiserror::Error;

/// Errors returned by the home-side SPL implementation.
#[derive(Debug, PartialEq, Eq, Error)]
pub enum HomeError {
    /// A TLS handshake failed without retaining peer-controlled diagnostics.
    #[error("TLS failure")]
    Tls,
    /// TLS configuration was rejected without retaining key or certificate data.
    #[error("TLS configuration failure")]
    TlsConfig,
    /// Mux configuration is invalid.
    #[error("invalid mux configuration: {0}")]
    Config(#[from] ConfigError),
    /// Shared framing encoding or decoding failed.
    #[error("frame error: {0}")]
    Frame(#[from] FrameError),
    /// A local operation or peer frame was refused with a classified reason.
    #[error("refusal: {0}")]
    Refused(Refusal),
    /// The carrier ended before a complete protocol exchange finished.
    #[error("peer went away")]
    PeerGone,
    /// No further listener-owned even stream id exists.
    #[error("listener stream identifiers exhausted")]
    StreamIdExhausted,
    /// The requested stream is already closed or unknown locally.
    #[error("stream is closed")]
    Closed,
}

/// Invalid mux-limit combinations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ConfigError {
    /// The configured concurrent-stream cap is zero.
    #[error("concurrent stream cap must be nonzero")]
    ZeroConcurrentStreamCap,
    /// The decoder cannot hold one legal maximum-size frame.
    #[error("decoder buffer is below one legal maximum-size frame")]
    DecoderBelowMaximumFrame,
}

/// Header-only classification of a refused operation or peer frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusal {
    /// Stable reason class for the refusal.
    pub class: RefusalClass,
    /// Rejected peer-frame header metadata, when a peer frame caused it.
    pub violation: Option<FrameViolation>,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.violation {
            Some(violation) => write!(
                formatter,
                "{} (stream {}, flags {:#x}, length {})",
                self.class, violation.stream_id, violation.flags, violation.length
            ),
            None => self.class.fmt(formatter),
        }
    }
}

/// Stable classes used to select SPL reset reasons without retaining payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalClass {
    /// The peer violated framing or stream lifecycle rules.
    Protocol,
    /// The peer exceeded the configured concurrent-stream cap.
    StreamLimit,
    /// The peer exceeded advertised flow-control credit.
    FlowControl,
    /// Local stream accounting or state failed independently of peer payload.
    Internal,
}

impl std::fmt::Display for RefusalClass {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::Protocol => "protocol",
            Self::StreamLimit => "stream limit",
            Self::FlowControl => "flow control",
            Self::Internal => "internal",
        };
        formatter.write_str(text)
    }
}
