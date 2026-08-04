// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Relay pair-window derivations.
//!
//! `jid_from_spki` is the relay-pairing journal-identity integrity check. It can
//! be promoted later if direct pairing needs the same journal identity.

use hkdf::Hkdf;
use p256::pkcs8::der::Decode;
use p256::pkcs8::{EncodePublicKey, SubjectPublicKeyInfoRef};
use sha2::Sha256;
use thiserror::Error;

use crate::pairlink;

/// Errors produced while deriving a journal identity.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum JidError {
    /// The supplied SPKI does not name an EC P-256 key.
    #[error("journal CA SPKI is not P-256")]
    NotP256,
    /// The supplied P-256 SPKI contains an invalid public point.
    #[error("journal CA SPKI contains an invalid P-256 public point")]
    InvalidPoint,
    /// The supplied SPKI is not well-formed DER.
    #[error("journal CA SPKI is malformed")]
    MalformedSpki,
}

/// Derive the 16-byte relay rendezvous key from a pair-window secret.
pub fn derive_rk(s: &[u8; 8]) -> [u8; 16] {
    hkdf16(s, None, b"spl-pair-window-v1")
}

/// Derive the stable UUID-form journal identity from a P-256 SPKI DER key.
///
/// # Errors
///
/// Parses `spki_der`, validates a P-256 public key, and derives from its
/// canonical SPKI DER serialization, normalizing a compressed point.
///
/// Returns [`JidError`] when the input must be refused; its variants are
/// diagnostic only.
pub fn jid_from_spki(spki_der: &[u8]) -> Result<String, JidError> {
    let spki = SubjectPublicKeyInfoRef::from_der(spki_der).map_err(|_| JidError::MalformedSpki)?;
    if spki.subject_public_key.as_bytes().is_none() {
        return Err(JidError::MalformedSpki);
    }

    let public_key = match p256::PublicKey::try_from(&spki) {
        Ok(public_key) => public_key,
        Err(p256::pkcs8::spki::Error::OidUnknown { .. }) => return Err(JidError::NotP256),
        Err(_) => return Err(JidError::InvalidPoint),
    };

    Ok(jid_from_public_key(&public_key))
}

#[expect(
    clippy::expect_used,
    reason = "a validated P-256 public key always has a fixed valid SPKI DER encoding"
)]
fn jid_from_public_key(public_key: &p256::PublicKey) -> String {
    let canonical_der = public_key
        .to_public_key_der()
        .expect("validated P-256 public key encodes as DER");
    let mut raw = hkdf16(
        canonical_der.as_bytes(),
        Some(b"solstone/journal/v1"),
        b"solstone/jid/uuidv8/v1",
    );
    raw[6] = (raw[6] & 0x0f) | 0x80;
    raw[8] = (raw[8] & 0x3f) | 0x80;
    pairlink::uuid_string(&raw)
}

#[expect(
    clippy::expect_used,
    reason = "HKDF-SHA256 always permits the fixed 16-byte output length"
)]
fn hkdf16(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> [u8; 16] {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut out = [0u8; 16];
    hk.expand(info, &mut out)
        .expect("HKDF-SHA256 supports 16-byte output");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_lower(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        assert_eq!(s.len() % 2, 0);
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn derive_rk_matches_conformance_vector() {
        let s = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        assert_eq!(
            hex_lower(&derive_rk(&s)),
            "e34481a4cde647ba9c9fb29a59e18271"
        );
    }

    #[test]
    fn jid_from_spki_matches_conformance_vector() {
        let spki_der = hex_decode(
            "3059301306072a8648ce3d020106082a8648ce3d03010703420004798953e7e8134fdf3c139f63d3fbccc252a28b6ca5059e618374a81231240f3fc83267aec725e18b66176c3685d1257201a67033819585a22a296350159ae70b",
        );
        assert_eq!(
            jid_from_spki(&spki_der).unwrap(),
            "3dc481a5-f430-862b-b5f8-5c47a3df5efb"
        );
    }

    #[test]
    fn jid_from_spki_fails_closed_on_malformed_spki() {
        assert_eq!(jid_from_spki(b"not der"), Err(JidError::MalformedSpki));
    }

    #[test]
    fn jid_from_spki_refuses_malformed_spki_encodings() {
        // Protocol: `.proto-ref/identity.md`, “An implementation MUST refuse any input
        // that is not a canonical P-256 `SubjectPublicKeyInfo`”.
        let spki_der = hex_decode(
            "3059301306072a8648ce3d020106082a8648ce3d03010703420004798953e7e8134fdf3c139f63d3fbccc252a28b6ca5059e618374a81231240f3fc83267aec725e18b66176c3685d1257201a67033819585a22a296350159ae70b",
        );
        let mut trailing = spki_der.clone();
        trailing.push(0);
        let mut non_minimal_length = vec![0x30, 0x81, 0x59];
        non_minimal_length.extend_from_slice(&spki_der[2..]);

        for malformed in [
            b"not der".as_slice(),
            trailing.as_slice(),
            non_minimal_length.as_slice(),
        ] {
            assert_eq!(jid_from_spki(malformed), Err(JidError::MalformedSpki));
        }
    }
}
