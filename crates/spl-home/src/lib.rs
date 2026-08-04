// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! SPL home-side framing acceptance.
//!
//! This crate owns the listener role of the SPL mux protocol. Its pure
//! acceptor is independent of sockets, clocks, HTTP, authorization policy, and
//! TLS configuration so protocol behavior can be tested by feeding wire bytes.
//! Its Tokio/rustls driver exposes listener-owned stream handles without owning
//! an application listener socket.
//! Inbound stream bytes are bounded by the configured stream cap times the
//! protocol's 1 MiB receive window, plus the independent decoder ceiling and
//! [`MAX_STAGED_WRITE_BYTES_PER_STREAM`] of outbound staging per live stream.

#![forbid(unsafe_code)]

mod config;
mod connection;
mod error;
mod mux;

/// Listener mux configuration and protocol-mandated default limits.
pub use config::{
    DEFAULT_DECODER_BUFFER_BYTES, DEFAULT_MAX_CONCURRENT_STREAMS, HomeConfig,
    MAX_STAGED_WRITE_BYTES_PER_STREAM, MuxLimits,
};
/// Tokio listener connection and per-stream I/O handles.
pub use connection::{HomeConnection, HomeStream};
/// Error and refusal types returned by the home-side mux.
pub use error::{ConfigError, HomeError, Refusal, RefusalClass};
/// Pure listener-side frame dispatch and stream lifecycle types.
pub use mux::{MuxAcceptor, MuxEvent, MuxOutput, ResetReason};
