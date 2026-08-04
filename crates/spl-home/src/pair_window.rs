// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Anonymous, single-use pairing-window admission.

use std::fmt;
use std::time::Instant;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;

use crate::config::build_server_config;
use crate::{HomeConnection, HomeError, MuxLimits, PairWindowRefusal};

/// The eight-byte home pairing nonce used to derive a relay rendezvous key.
pub struct PairSecret([u8; 8]);

impl From<[u8; 8]> for PairSecret {
    fn from(value: [u8; 8]) -> Self {
        Self(value)
    }
}

impl fmt::Debug for PairSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairSecret([REDACTED; 8])")
    }
}

impl Drop for PairSecret {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Lowercase hexadecimal relay rendezvous key.
///
/// This intentionally implements no [`std::fmt::Display`], so logging a relay
/// key is not one formatting placeholder away.
#[derive(Clone)]
pub struct RelayKeyHex(String);

impl RelayKeyHex {
    /// Return the lowercase ASCII key suitable for the `Sec-Pair-Key` header.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RelayKeyHex {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RelayKeyHex([REDACTED; 32])")
    }
}

/// TLS and mux material used by an anonymous pairing window.
pub struct PairWindowConfig {
    /// Certificate chain presented by the home, in leaf-first order.
    pub certificate_chain: Vec<CertificateDer<'static>>,
    /// Private key matching the first certificate in `certificate_chain`.
    pub private_key: PrivateKeyDer<'static>,
    /// The CA whose SPKI prefix appears in the pair link and whose certificate
    /// the journal returns in the pairing response `ca_chain`.
    pub ca_certificate: CertificateDer<'static>,
    /// Per-connection framing and memory limits.
    pub mux_limits: MuxLimits,
}

impl fmt::Debug for PairWindowConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairWindowConfig")
            .field("certificate_chain", &"[REDACTED]")
            .field("private_key", &"[REDACTED]")
            .field("ca_certificate", &"[REDACTED]")
            .field("mux_limits", &self.mux_limits)
            .finish()
    }
}

impl PairWindowConfig {
    fn server_config(&self) -> Result<rustls::ServerConfig, HomeError> {
        // Protocol: `.proto-ref/pair-window.md`, lines 87-89: the pair-dial
        // side remains anonymous and is gated by the inner CA fingerprint/S.
        build_server_config(
            self.certificate_chain.clone(),
            self.private_key.clone_key(),
            WebPkiClientVerifier::no_client_auth(),
        )
    }
}

/// One short-lived, single-use anonymous pairing admission window.
pub struct PairWindow {
    relay_key: RelayKeyHex,
    expires_at: Instant,
    consumed: bool,
    config: PairWindowConfig,
    instance_id: String,
}

impl fmt::Debug for PairWindow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairWindow")
            .field("relay_key", &self.relay_key)
            .field("expires_at", &self.expires_at)
            .field("consumed", &self.consumed)
            .field("config", &self.config)
            .field("instance_id", &self.instance_id)
            .finish()
    }
}

impl PairWindow {
    /// Open a pairing window from a caller-supplied home nonce and expiry.
    ///
    /// The nonce is deterministically transformed into a lowercase relay key;
    /// this crate does not generate pairing nonces.
    ///
    /// # Errors
    ///
    /// Returns [`HomeError::PairWindowCaIdentity`] when the configured CA does
    /// not contain a valid P-256 SPKI from which to derive an instance identity.
    pub fn open(
        mut secret: PairSecret,
        expires_at: Instant,
        config: PairWindowConfig,
    ) -> Result<Self, HomeError> {
        let spki = spl_core::ca::extract_spki_der(config.ca_certificate.as_ref())
            .map_err(|_| HomeError::PairWindowCaIdentity)?;
        let instance_id = spl_core::relay_window::jid_from_spki(&spki)
            .map_err(|_| HomeError::PairWindowCaIdentity)?;
        let relay_key = RelayKeyHex(hex_lower(&spl_core::relay_window::derive_rk(&secret.0)));
        secret.0.fill(0);
        Ok(Self {
            relay_key,
            expires_at,
            consumed: false,
            config,
            instance_id,
        })
    }

    /// Return the relay-registration key in lowercase hexadecimal form.
    pub fn relay_key_hex(&self) -> RelayKeyHex {
        self.relay_key.clone()
    }

    /// Return the CA-derived identity returned by a conforming pairing ceremony.
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// Admit an anonymous pair-dial carrier.
    ///
    /// Only exactly 32 lowercase ASCII hexadecimal characters can match.
    /// Uppercase hexadecimal is rejected. Relay key, expiry, and consumption
    /// are checked before the TLS handshake writes any carrier bytes.
    ///
    /// Protocol: `.proto-ref/pair-window.md`, line 83 requires one use with
    /// the first dial winning; line 91 requires consume-on-success-only with
    /// rollback after a failed admission.
    ///
    /// Refusals happen before the handshake so carrier bytes cannot distinguish
    /// local refusal causes, preserving the oracle-safety requirement in line 85.
    ///
    /// # Errors
    ///
    /// Returns a distinct [`PairWindowRefusal`] before I/O for a wrong key,
    /// expired window, or consumed window. Returns a TLS or mux error when an
    /// otherwise admitted carrier cannot complete setup.
    pub async fn admit<S>(
        &mut self,
        io: S,
        presented_rk: &str,
        now: Instant,
    ) -> Result<HomeConnection, HomeError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        if !relay_key_matches(presented_rk, &self.relay_key) {
            return Err(HomeError::PairWindowRefused(
                PairWindowRefusal::WrongRelayKey,
            ));
        }
        if now >= self.expires_at {
            return Err(HomeError::PairWindowRefused(PairWindowRefusal::Expired));
        }
        if self.consumed {
            return Err(HomeError::PairWindowRefused(PairWindowRefusal::Consumed));
        }

        let connection = HomeConnection::accept_with_server_config(
            io,
            self.config.server_config()?,
            self.config.mux_limits,
        )
        .await?;
        self.consumed = true;
        Ok(connection)
    }
}

fn relay_key_matches(presented: &str, expected: &RelayKeyHex) -> bool {
    let presented = presented.as_bytes();
    let expected = expected.0.as_bytes();
    let mut difference = presented.len() ^ expected.len();
    for (index, expected) in expected.iter().enumerate() {
        let received = presented.get(index).copied().unwrap_or(0);
        difference |= usize::from(received ^ *expected);
    }
    difference == 0
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
