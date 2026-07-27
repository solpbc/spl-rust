// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Relay-form pairing ceremony.

use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use serde::Deserialize;
use serde_json::json;
use spl_core::pairlink::RelayPairLink;
use spl_core::{PAIR_PATH, PairResponse, ca};

use crate::credential::{Credential, endpoint_addrs_from_local_endpoints, generate_csr};
use crate::pairing::{
    build_pair_request, summarize_rejection_body, verify_client_cert_key_binding,
};
use crate::{RelayControlEndpoint, TransportError, relay, relay_http, spki_pin, tls};

#[derive(Deserialize)]
struct EnrollResponse {
    device_token: String,
}

/// Complete the relay-form SPL pairing ceremony.
///
/// # Errors
///
/// Returns a relay, TLS, JSON, certificate-binding, enrollment, or credential
/// verification error when the ceremony cannot complete safely.
pub async fn pair_over_relay(
    link: &RelayPairLink,
    device_label: &str,
    additional_fields: &serde_json::Map<String, serde_json::Value>,
) -> Result<Credential, TransportError> {
    let rk = spl_core::relay_window::derive_rk(&link.s);
    let url = spl_core::relay::pair_dial_url(&link.relay_origin)
        .map_err(|e| TransportError::PairLink(format!("relay origin: {e}")))?;
    let ws = relay::dial_pair_relay_ws(&url, &hex_lower(&rk), relay::outer_config()).await?;

    let generated = generate_csr(device_label)?;
    let request = build_pair_request(generated.csr_pem, device_label, additional_fields)?;
    let body = serde_json::to_vec(&request)?;
    let headers = vec![("Content-Type".to_string(), "application/json".to_string())];
    let path = format!("{PAIR_PATH}?token={}", hex_lower(&link.s));
    let inner_config = Arc::new(tls::trust_all_pairing_config()?);
    let (response, peer_leaf) = relay::request_once_over_ws_with_peer_leaf(
        ws,
        inner_config,
        relay::RELAY_HANDSHAKE_TIMEOUT,
        "POST",
        &path,
        &headers,
        &body,
    )
    .await?;
    let peer_leaf =
        peer_leaf.ok_or_else(|| TransportError::Pairing("relay missing peer leaf".into()))?;
    if !response.is_success() {
        return Err(TransportError::Rejected {
            status: response.status,
            body: summarize_rejection_body(&response.body),
        });
    }

    let pair: PairResponse = serde_json::from_slice(&response.body)?;
    let ca_chain_der = parse_ca_chain(&pair.ca_chain)?;
    let pinned_ca = ca_chain_der
        .iter()
        .find(|cert| ca::spki_matches_prefix(cert.as_ref(), &link.ca_fp_spki))
        .cloned()
        .ok_or_else(|| TransportError::Pairing("relay pinned ca not found".into()))?;
    spki_pin::verify_live_peer_binding(&peer_leaf, &pinned_ca)?;
    spki_pin::verify_ca_self_signed(&pinned_ca)?;

    let spki = ca::extract_spki_der(pinned_ca.as_ref())
        .map_err(|_| TransportError::Pairing("relay ca spki".into()))?;
    let expected = spl_core::relay_window::jid_from_spki(&spki)
        .map_err(|_| TransportError::Pairing("relay ca not p-256".into()))?;
    if pair.instance_id != expected {
        return Err(TransportError::Pairing("relay instance mismatch".into()));
    }

    let client_cert_der = tls::parse_certs(&pair.client_cert)?
        .into_iter()
        .next()
        .ok_or_else(|| TransportError::Pairing("relay response missing client cert".into()))?;
    let computed = format!("sha256:{}", ca::sha256_hex(client_cert_der.as_ref()));
    if pair.fingerprint != computed {
        return Err(TransportError::Pairing(
            "relay client cert fingerprint mismatch".into(),
        ));
    }
    verify_client_cert_key_binding(client_cert_der.as_ref(), &generated.public_key_spki_der)?;

    let home_attestation = pair
        .home_attestation
        .as_deref()
        .ok_or_else(|| TransportError::Pairing("relay response missing home attestation".into()))?;
    #[expect(
        clippy::large_futures,
        reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
    )]
    let device_token =
        enroll_device(&link.relay_origin, &pair.instance_id, home_attestation).await?;
    let device_token_expires_at =
        spl_core::jwt::decode_unverified_claims(&device_token).map(|c| c.exp);
    let ca_fp_prefix = ca::sha256(pinned_ca.as_ref())[..16].to_vec();
    let endpoints = endpoint_addrs_from_local_endpoints(pair.local_endpoints.as_ref());

    Ok(Credential {
        client_key_pem: generated.key_pem,
        client_cert_pem: pair.client_cert,
        ca_chain_pem: pair.ca_chain,
        ca_fp_prefix,
        instance_id: pair.instance_id,
        home_label: pair.home_label,
        endpoints,
        home_attestation: pair.home_attestation,
        local_endpoints: pair.local_endpoints,
        relay_origin: Some(link.relay_origin.clone()),
        device_token: Some(device_token),
        device_token_expires_at,
    })
}

/// Exchange a fresh home attestation for a relay device token.
///
/// The caller must obtain `home_attestation` from a current pairing ceremony.
/// The relay requires its JWT lifetime to be no more than five minutes, so the
/// copy stored on [`Credential`] is not a restart-survivable enrollment input.
/// Once that pairing window has elapsed, a device that receives
/// [`crate::relay_token::RefreshOutcome::ReconnectNeeded`] after restarting
/// requires a new pairing ceremony. This crate forwards the attestation without
/// parsing, signature verification, or a local expiry check.
///
/// # Errors
///
/// Returns [`TransportError::RelayControlRejected`] with
/// [`RelayControlEndpoint::EnrollDevice`] when the relay rejects a stale or
/// otherwise invalid attestation. Returns an I/O, TLS, JSON, or pairing error
/// when the request fails or a successful response is malformed.
pub async fn enroll_device(
    relay_origin: &str,
    instance_id: &str,
    home_attestation: &str,
) -> Result<String, TransportError> {
    let body = serde_json::to_vec(&json!({
        "instance_id": instance_id,
        "home_attestation": home_attestation,
    }))?;
    #[expect(
        clippy::large_futures,
        reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
    )]
    let response = relay_http::relay_https_post_json(relay_origin, "/enroll/device", &body).await?;
    if !response.is_success() {
        return Err(TransportError::RelayControlRejected {
            endpoint: RelayControlEndpoint::EnrollDevice,
            status: response.status,
        });
    }
    let parsed: EnrollResponse = serde_json::from_slice(&response.body)
        .map_err(|_| TransportError::Pairing("relay enroll response malformed".into()))?;
    if parsed.device_token.is_empty() {
        return Err(TransportError::Pairing(
            "relay enroll response malformed".into(),
        ));
    }
    Ok(parsed.device_token)
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        #[expect(
            clippy::format_push_string,
            reason = "the copied short fixed-width hex formatter keeps its allocation behavior unchanged"
        )]
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn parse_ca_chain(chain: &[String]) -> Result<Vec<CertificateDer<'static>>, TransportError> {
    let mut out = Vec::new();
    for pem in chain {
        out.extend(tls::parse_certs(pem)?);
    }
    if out.is_empty() {
        Err(TransportError::Pairing(
            "relay response missing ca chain".into(),
        ))
    } else {
        Ok(out)
    }
}
