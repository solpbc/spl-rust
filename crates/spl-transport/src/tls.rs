// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! rustls client configs for SPL's framed-mTLS transport.
//!
//! Trust is CA-fingerprint pinning, not a system trust store. The peer leaf
//! must be signed by the pinned home CA, and TLS separately verifies possession
//! of the leaf private key. Hostname validation is intentionally replaced by
//! this private trust anchor because connections dial the home's raw addresses.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};

use crate::TransportError;

/// The fixed TLS server name. Hostname is not validated (CA-fp pin is the trust
/// anchor); this is a stable placeholder so SNI/name handling is deterministic.
pub(crate) const PINNED_SERVER_NAME: &str = "spl.local";

/// A rustls verifier that pins the journal CA fingerprint prefix and still
/// verifies the handshake signature against the presented leaf.
#[derive(Debug)]
pub(crate) struct CaFpPinVerifier {
    pub(crate) prefix: Vec<u8>,
    pub(crate) provider: Arc<CryptoProvider>,
}

#[derive(Debug)]
struct TrustAllPairingVerifier {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for CaFpPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let pinned_ca = std::iter::once(end_entity)
            .chain(intermediates.iter())
            .find(|cert| spl_core::ca::cert_matches_prefix(cert.as_ref(), &self.prefix))
            .ok_or_else(|| RustlsError::General("journal CA fingerprint pin mismatch".into()))?;
        crate::spki_pin::verify_ca_self_signed(pinned_ca)
            .and_then(|()| crate::spki_pin::verify_live_peer_binding(end_entity, pinned_ca))
            .map_err(|_| {
                RustlsError::General("journal certificate not signed by pinned CA".into())
            })?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl ServerCertVerifier for TrustAllPairingVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Client config for the **certless pairing** handshake: pins the CA-fp prefix,
/// presents no client certificate.
///
/// # Errors
///
/// Returns a TLS configuration error when rustls rejects the provider setup.
pub fn pairing_config(ca_fp_prefix: &[u8]) -> Result<ClientConfig, TransportError> {
    let provider = provider();
    let verifier = Arc::new(CaFpPinVerifier {
        prefix: ca_fp_prefix.to_vec(),
        provider: provider.clone(),
    });
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TransportError::Tls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(config)
}

/// Client config for relay pairing's inner TLS leg. It accepts any certificate
/// chain during the handshake so the ceremony can surface the live peer leaf,
/// but it still verifies the TLS handshake signature against that leaf through
/// ring. Safe only when followed immediately by the relay live-peer SPKI binding;
/// never use this for an established session.
///
/// # Errors
///
/// Returns a TLS configuration error when rustls rejects the provider setup.
pub(crate) fn trust_all_pairing_config() -> Result<ClientConfig, TransportError> {
    let provider = provider();
    let verifier = Arc::new(TrustAllPairingVerifier {
        provider: provider.clone(),
    });
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TransportError::Tls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(config)
}

/// Client config for the **established mTLS** session: pins the same CA-fp
/// prefix and presents the client cert + key minted during pairing.
///
/// # Errors
///
/// Returns a TLS configuration error when the provider, certificate chain, or
/// private key is invalid.
pub fn mtls_config(
    ca_fp_prefix: &[u8],
    client_cert_chain: Vec<CertificateDer<'static>>,
    client_key: PrivateKeyDer<'static>,
) -> Result<ClientConfig, TransportError> {
    let provider = provider();
    let verifier = Arc::new(CaFpPinVerifier {
        prefix: ca_fp_prefix.to_vec(),
        provider: provider.clone(),
    });
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TransportError::Tls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(client_cert_chain, client_key)
        .map_err(|e| TransportError::Tls(e.to_string()))?;
    Ok(config)
}

/// Parse PEM certificate text into rustls DER certs. Uses the PEM parser in
/// `rustls-pki-types` directly (the maintained replacement for `rustls-pemfile`).
///
/// # Errors
///
/// Returns a TLS error when any certificate PEM block is invalid.
pub fn parse_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>, TransportError> {
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TransportError::Tls(format!("bad certificate PEM: {e}")))
}

/// Parse a PKCS#8 (or other) private key PEM into a rustls key.
///
/// # Errors
///
/// Returns a TLS error when the private-key PEM is invalid.
pub(crate) fn parse_private_key(pem: &str) -> Result<PrivateKeyDer<'static>, TransportError> {
    PrivateKeyDer::from_pem_slice(pem.as_bytes())
        .map_err(|e| TransportError::Tls(format!("bad private key PEM: {e}")))
}

/// The pinned [`ServerName`] used for every dial.
///
/// # Panics
///
/// Panics only if the compile-time pinned DNS name becomes invalid.
#[expect(
    clippy::expect_used,
    reason = "the compile-time spl.local constant is a valid DNS name by construction"
)]
pub(crate) fn pinned_server_name() -> ServerName<'static> {
    ServerName::try_from(PINNED_SERVER_NAME).expect("spl.local is a valid DNS name")
}
