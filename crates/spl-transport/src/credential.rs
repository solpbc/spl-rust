// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Pairing credentials and certificate-signing request generation.
//!
//! Persistence, secret protection, and platform keystores belong to consumers.

use rcgen::{CertificateParams, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use serde::{Deserialize, Serialize};
use spl_core::pairlink::Endpoint;

use crate::TransportError;

/// A dialable journal endpoint in serializable form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointAddr {
    /// DNS name or IP address to dial.
    pub host: String,
    /// TCP port to dial.
    pub port: u16,
}

impl From<&Endpoint> for EndpointAddr {
    fn from(endpoint: &Endpoint) -> Self {
        Self {
            host: endpoint.host.clone(),
            port: endpoint.port,
        }
    }
}

/// Signed pairing identity and the addresses used to reach its journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    /// PEM-encoded private key matching the client certificate.
    pub client_key_pem: String,
    /// PEM-encoded client certificate signed during pairing.
    pub client_cert_pem: String,
    /// PEM-encoded CA chain trusted for journal sessions.
    pub ca_chain_pem: Vec<String>,
    /// Required prefix of the paired CA certificate fingerprint.
    pub ca_fp_prefix: Vec<u8>,
    /// Stable identifier of the paired journal instance.
    pub instance_id: String,
    /// Human-facing label of the paired journal.
    pub home_label: String,
    /// Direct-network endpoints learned during pairing.
    pub endpoints: Vec<EndpointAddr>,
    /// Short-lived home attestation returned by the pairing ceremony, when supplied.
    #[serde(default)]
    pub home_attestation: Option<String>,
    /// Journal-advertised LAN endpoints in their extensible response shape.
    #[serde(default)]
    pub local_endpoints: Option<serde_json::Value>,
    /// Relay control and WebSocket origin, when relay service is configured.
    #[serde(default)]
    pub relay_origin: Option<String>,
    /// Current relay device token, when relay service is configured.
    #[serde(default)]
    pub device_token: Option<String>,
    /// Relay device-token expiry as Unix seconds, when known.
    #[serde(default)]
    pub device_token_expires_at: Option<i64>,
}

pub(crate) struct GeneratedKey {
    pub(crate) key_pem: String,
    pub(crate) csr_pem: String,
    pub(crate) public_key_spki_der: Vec<u8>,
}

pub(crate) fn endpoint_addrs_from_local_endpoints(
    value: Option<&serde_json::Value>,
) -> Vec<EndpointAddr> {
    // Relay pair-response local_endpoints are {ip, port, scope}; scope is kept
    // server-side for now and intentionally not persisted by this crate.
    let Some(serde_json::Value::Array(entries)) = value else {
        return Vec::new();
    };

    entries
        .iter()
        .filter_map(|entry| {
            let object = entry.as_object()?;
            let host = object.get("ip")?.as_str()?;
            let port = object.get("port")?.as_u64()?;
            let port = u16::try_from(port).ok()?;
            if port == 0 {
                return None;
            }
            Some(EndpointAddr {
                host: host.to_string(),
                port,
            })
        })
        .collect()
}

pub(crate) fn generate_csr(device_label: &str) -> Result<GeneratedKey, TransportError> {
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|error| TransportError::Crypto(format!("keygen: {error}")))?;
    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|error| TransportError::Crypto(format!("csr params: {error}")))?;
    params
        .distinguished_name
        .push(DnType::CommonName, truncate_cn_label(device_label));
    let csr = params
        .serialize_request(&key_pair)
        .map_err(|error| TransportError::Crypto(format!("csr serialize: {error}")))?;
    let csr_pem = csr
        .pem()
        .map_err(|error| TransportError::Crypto(format!("csr pem: {error}")))?;
    Ok(GeneratedKey {
        key_pem: key_pair.serialize_pem(),
        csr_pem,
        public_key_spki_der: key_pair.public_key_der(),
    })
}

fn truncate_cn_label(device_label: &str) -> &str {
    let mut end = device_label.len().min(64);
    while !device_label.is_char_boundary(end) {
        end -= 1;
    }
    &device_label[..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateSigningRequestParams, DnValue};

    #[test]
    fn generated_csr_carries_matching_public_key_spki_der() {
        let g = generate_csr("solstone-windows-test").unwrap();
        assert!(g.csr_pem.contains("BEGIN CERTIFICATE REQUEST"));
        assert!(g.key_pem.contains("BEGIN PRIVATE KEY"));
        let key = KeyPair::from_pem(&g.key_pem).unwrap();
        assert_eq!(g.public_key_spki_der, key.public_key_der());
    }

    #[test]
    fn generated_csr_truncates_common_name_to_64_bytes_at_utf8_boundary() {
        for (label, expected) in [
            ("a".repeat(80), "a".repeat(64)),
            (format!("{}é-tail", "a".repeat(63)), "a".repeat(63)),
        ] {
            let generated = generate_csr(&label).unwrap();
            let parsed = CertificateSigningRequestParams::from_pem(&generated.csr_pem).unwrap();
            let Some(DnValue::Utf8String(common_name)) =
                parsed.params.distinguished_name.get(&DnType::CommonName)
            else {
                panic!("generated CSR common name is not a UTF-8 string");
            };
            assert_eq!(
                common_name, &expected,
                "CSR common name exceeds the 64-byte bound"
            );
        }
    }

    #[test]
    fn local_endpoints_helper_maps_valid_entries_and_skips_invalid() {
        let value = serde_json::json!([
            {"ip": "10.0.0.2", "port": 7657, "scope": "lan"},
            {"ip": "10.0.0.3", "port": 0, "scope": "lan"},
            {"ip": "10.0.0.4", "port": 70000, "scope": "lan"},
            {"ip": 42, "port": 7657},
            {"host": "10.0.0.5", "port": 7657},
            "bad"
        ]);
        assert_eq!(
            endpoint_addrs_from_local_endpoints(Some(&value)),
            vec![EndpointAddr {
                host: "10.0.0.2".into(),
                port: 7657
            }]
        );
        assert!(endpoint_addrs_from_local_endpoints(None).is_empty());
        assert!(
            endpoint_addrs_from_local_endpoints(Some(&serde_json::json!({"ip": "10.0.0.2"})))
                .is_empty()
        );
    }

    fn credential() -> Credential {
        Credential {
            client_key_pem: "KEY".into(),
            client_cert_pem: "CERT".into(),
            ca_chain_pem: vec!["CA".into()],
            ca_fp_prefix: vec![1, 2, 3, 4],
            instance_id: "instance".into(),
            home_label: "Home".into(),
            endpoints: vec![EndpointAddr {
                host: "127.0.0.1".into(),
                port: 7657,
            }],
            home_attestation: Some("home-attestation".into()),
            local_endpoints: Some(serde_json::json!([
                {"ip": "127.0.0.1", "port": 7657, "scope": "lan"}
            ])),
            relay_origin: Some("https://relay.example".into()),
            device_token: Some("device-token".into()),
            device_token_expires_at: Some(1_800_000_000),
        }
    }

    #[test]
    fn optional_fields_round_trip_directly_through_credential() {
        let encoded = serde_json::to_vec(&credential()).unwrap();
        let decoded: Credential = serde_json::from_slice(&encoded).unwrap();

        assert_eq!(
            decoded.relay_origin.as_deref(),
            Some("https://relay.example")
        );
        assert_eq!(decoded.device_token.as_deref(), Some("device-token"));
        assert_eq!(decoded.device_token_expires_at, Some(1_800_000_000));
        assert_eq!(
            decoded.home_attestation.as_deref(),
            Some("home-attestation")
        );
        assert_eq!(
            decoded.local_endpoints,
            Some(serde_json::json!([
                {"ip": "127.0.0.1", "port": 7657, "scope": "lan"}
            ]))
        );
    }

    #[test]
    fn legacy_credential_defaults_relay_fields_when_omitted() {
        let encoded = serde_json::json!({
            "client_key_pem": "KEY",
            "client_cert_pem": "CERT",
            "ca_chain_pem": ["CA"],
            "ca_fp_prefix": [1, 2, 3, 4],
            "instance_id": "instance",
            "home_label": "Home",
            "endpoints": [{"host": "127.0.0.1", "port": 7657}]
        });

        let decoded: Credential = serde_json::from_value(encoded).unwrap();

        assert_eq!(decoded.relay_origin, None);
        assert_eq!(decoded.device_token, None);
        assert_eq!(decoded.device_token_expires_at, None);
        assert_eq!(decoded.home_attestation, None);
        assert_eq!(decoded.local_endpoints, None);
    }
}
