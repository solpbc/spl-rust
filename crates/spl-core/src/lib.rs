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
