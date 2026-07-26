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

#![forbid(unsafe_code)]
