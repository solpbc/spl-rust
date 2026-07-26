// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Relay live-peer SPKI binding checks.

use rustls::pki_types::{CertificateDer, SubjectPublicKeyInfoDer, UnixTime};

use crate::TransportError;

pub(crate) fn verify_live_peer_binding(
    peer_leaf: &CertificateDer<'_>,
    pinned_ca: &CertificateDer<'_>,
) -> Result<(), TransportError> {
    let anchor = webpki::anchor_from_trusted_cert(pinned_ca)
        .map_err(|_| TransportError::Pairing("relay peer leaf not signed by pinned ca".into()))?;
    let leaf = webpki::EndEntityCert::try_from(peer_leaf)
        .map_err(|_| TransportError::Pairing("relay peer leaf not signed by pinned ca".into()))?;
    leaf.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &[anchor],
        &[],
        UnixTime::now(),
        webpki::KeyUsage::server_auth(),
        None,
        None,
    )
    .map_err(|_| TransportError::Pairing("relay peer leaf not signed by pinned ca".into()))?;
    Ok(())
}

pub(crate) fn verify_ca_self_signed(pinned_ca: &CertificateDer<'_>) -> Result<(), TransportError> {
    let (tbs, signature) = spl_core::ca::extract_tbs_and_signature(pinned_ca.as_ref())
        .map_err(|_| TransportError::Pairing("relay ca not self signed".into()))?;
    let spki = spl_core::ca::extract_spki_der(pinned_ca.as_ref())
        .map_err(|_| TransportError::Pairing("relay ca not self signed".into()))?;
    let spki_der = SubjectPublicKeyInfoDer::from(spki.as_slice());
    let rpk = webpki::RawPublicKeyEntity::try_from(&spki_der)
        .map_err(|_| TransportError::Pairing("relay ca not self signed".into()))?;

    for alg in webpki::ALL_VERIFICATION_ALGS {
        if rpk.verify_signature(*alg, &tbs, &signature).is_ok() {
            return Ok(());
        }
    }
    Err(TransportError::Pairing("relay ca not self signed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
    };
    use rustls::pki_types::CertificateDer;

    struct TestCa {
        cert: rcgen::Certificate,
        key: KeyPair,
    }

    fn ca() -> TestCa {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        params.key_usages.push(KeyUsagePurpose::CrlSign);
        let cert = params.self_signed(&key).unwrap();
        TestCa { cert, key }
    }

    fn leaf_signed_by(ca: &TestCa) -> CertificateDer<'static> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(vec!["spl.local".to_string()]).unwrap();
        params.is_ca = IsCa::NoCa;
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        let cert = params.signed_by(&key, &ca.cert, &ca.key).unwrap();
        CertificateDer::from(cert.der().to_vec())
    }

    fn cert_der(ca: &TestCa) -> CertificateDer<'static> {
        CertificateDer::from(ca.cert.der().to_vec())
    }

    #[test]
    fn live_peer_leaf_signed_by_self_signed_ca_verifies() {
        let ca = ca();
        let leaf = leaf_signed_by(&ca);
        verify_live_peer_binding(&leaf, &cert_der(&ca)).unwrap();
        verify_ca_self_signed(&cert_der(&ca)).unwrap();
    }

    #[test]
    fn live_peer_leaf_signed_by_unrelated_ca_rejects() {
        let pinned = ca();
        let unrelated = ca();
        let leaf = leaf_signed_by(&unrelated);
        assert!(verify_live_peer_binding(&leaf, &cert_der(&pinned)).is_err());
    }

    #[test]
    fn non_self_signed_ca_rejects() {
        let issuer = ca();
        let not_self_signed = leaf_signed_by(&issuer);
        assert!(verify_ca_self_signed(&not_self_signed).is_err());
    }
}
