// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! The pure SPL (solstone private link) wire protocol.
//!
//! This crate owns everything about the wire that can be decided without doing
//! any I/O: parsing a pair-link, deciding whether a direct candidate address may
//! be dialed, encoding and decoding mux frames, framing HTTP over the mux,
//! pinning a CA fingerprint, and the pair-window / journal-identity key
//! derivations.
//!
//! There is deliberately **no I/O and no platform dependency here**, so the whole
//! wire contract is unit-testable on any host. Sockets, TLS, and the WebSocket
//! carrier live in the sibling `spl-transport` crate.
//!
//! # Authority
//!
//! The wire is specified by the [`proto/` documents in solpbc/spl][proto], and
//! those documents — together with the conformance-vector corpus generated from
//! them — are authoritative over this code. When this crate and the protocol
//! disagree, the protocol is right. Never invent wire behavior here; raise the
//! gap against the protocol instead.
//!
//! [proto]: https://github.com/solpbc/spl/tree/main/proto
//!
//! # Scope
//!
//! This crate is the *client* side of SPL, shared across every Rust consumer.
//! Application layers built on top of it — observer registration and segment
//! ingest, linked-system credential provisioning, service lifecycles — belong to
//! the consuming product, not here.

#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    expect(
        clippy::byte_char_slices,
        clippy::format_push_string,
        clippy::needless_pass_by_value,
        clippy::panic,
        clippy::similar_names,
        clippy::unreadable_literal,
        clippy::unwrap_used,
        reason = "copied wire tests favor direct fixtures and assertions over production error handling"
    )
)]

pub mod bridge;
pub mod ca;
pub mod crockford;
pub mod frame;
pub mod http;
pub mod jwt;
pub mod mux;
pub mod pairlink;
pub mod relay;
pub mod relay_window;

/// Default TCP port for direct-network pairing endpoints.
pub const DEFAULT_DIRECT_PORT: u16 = 7657;

/// HTTP path for the nonce-authorized direct pairing request.
///
/// Protocol: [`.proto-ref/pairing.md`, “mobile posts the CSR to the pair URL”](../../../.proto-ref/pairing.md#5-mobile-posts-the-csr-to-the-pair-url).
pub const PAIR_PATH: &str = "/app/network/pair";
