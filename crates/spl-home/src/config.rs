// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Listener mux limits and their protocol-derived defaults.

use std::sync::Arc;

use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::danger::ClientCertVerifier;
use spl_core::frame::{HEADER_LEN, MAX_PAYLOAD};
use spl_core::mux::INITIAL_WINDOW;

use crate::ConfigError;

/// v1's default cap of 256 concurrent streams per direction.
///
/// Protocol: `.proto-ref/framing.md`, “concurrent stream cap”, lines 114-118.
pub const DEFAULT_MAX_CONCURRENT_STREAMS: usize = 256;
/// Bytes required to retain one complete maximum-size legal frame.
///
/// Protocol: `.proto-ref/framing.md`, “frame layout”, lines 29-36.
pub const DEFAULT_DECODER_BUFFER_BYTES: usize = 16_777_223;
/// Maximum bytes the Tokio driver stages for one live stream before applying
/// local write backpressure.
///
/// This matches the protocol's 1 MiB initial receive window, so each stream's
/// outbound staging has a fixed, documented bound.
pub const MAX_STAGED_WRITE_BYTES_PER_STREAM: usize = INITIAL_WINDOW;

/// Per-connection listener limits for the pure mux state machine.
///
/// Inbound stream data is bounded by each stream's protocol-mandated
/// 1 MiB receive window times [`Self::max_concurrent_streams`]. The separate
/// decoder ceiling limits unframed carrier bytes. The Tokio driver additionally
/// caps outbound staging at [`MAX_STAGED_WRITE_BYTES_PER_STREAM`] per stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MuxLimits {
    /// Maximum concurrently open peer-originated streams.
    pub max_concurrent_streams: usize,
    /// Maximum undecoded carrier bytes retained by the frame decoder.
    pub decoder_buffer_bytes: usize,
}

impl MuxLimits {
    /// Validate the independently configurable limits.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when a cap is zero or the decoder cannot
    /// hold one legal maximum-size frame.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_concurrent_streams == 0 {
            return Err(ConfigError::ZeroConcurrentStreamCap);
        }
        if self.decoder_buffer_bytes < HEADER_LEN + MAX_PAYLOAD {
            return Err(ConfigError::DecoderBelowMaximumFrame);
        }
        Ok(())
    }
}

impl Default for MuxLimits {
    fn default() -> Self {
        Self {
            max_concurrent_streams: DEFAULT_MAX_CONCURRENT_STREAMS,
            decoder_buffer_bytes: DEFAULT_DECODER_BUFFER_BYTES,
        }
    }
}

/// TLS and mux configuration supplied by the embedding home application.
pub struct HomeConfig {
    /// Certificate chain presented by the listener during the inner TLS handshake.
    pub certificate_chain: Vec<CertificateDer<'static>>,
    /// Private key corresponding to the first certificate in the chain.
    pub private_key: PrivateKeyDer<'static>,
    /// Application-owned policy for authenticating the dialing client's certificate.
    pub client_cert_verifier: Arc<dyn ClientCertVerifier>,
    /// Per-connection framing and memory limits.
    pub mux_limits: MuxLimits,
}

impl HomeConfig {
    /// Build a TLS-1.3-only server configuration using the caller's verifier.
    ///
    /// # Errors
    ///
    /// Returns [`HomeError::TlsConfig`](crate::HomeError::TlsConfig) if rustls
    /// rejects the selected provider, protocol version, certificate chain, or key.
    pub fn server_config(&self) -> Result<ServerConfig, crate::HomeError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| crate::HomeError::TlsConfig)?
            .with_client_cert_verifier(self.client_cert_verifier.clone())
            .with_single_cert(self.certificate_chain.clone(), self.private_key.clone_key())
            .map_err(|_| crate::HomeError::TlsConfig)
    }
}
