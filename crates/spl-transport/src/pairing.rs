// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! The pairing handshake.
//!
//! Over a certless, CA-fp-pinned TLS connection, POST a freshly-minted CSR to
//! `/app/network/pair?token=<nonce>`; the journal signs it and returns the client
//! cert + CA chain + its identity. We verify the returned `fingerprint` equals
//! `sha256:<hex>` of the signed client cert (the integrity check the Android/iOS
//! clients also do) before trusting the credential. One key/CSR and request body
//! are generated per ceremony; consumer-defined additional fields are flattened
//! into that request without changing the generated CSR or device label.
//! Candidates are prepared in order, but only a pre-write preparation failure
//! advances to the next candidate: the first prepared connection receives the
//! sole request and its outcome is terminal.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use rustls::ClientConfig;
use spl_core::http::HttpResponse;
use spl_core::pairlink::{self, Endpoint, ParsedPairLink};
use spl_core::{PAIR_PATH, PairRequest, PairResponse, ca};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use crate::connection::{dial_tls, run_request_over_stream};
use crate::credential::{Credential, EndpointAddr, GeneratedKey, generate_csr};
use crate::relay_pairing;
use crate::{TransportError, tls};

/// Boxed future returned while preparing a direct-pairing connection.
pub type DirectPairPrepareFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<Box<dyn PreparedDirectPairConnection>, TransportError>>
            + Send
            + 'a,
    >,
>;

/// Boxed future returned while sending the one direct-pairing request.
pub type DirectPairSendFuture<'a> =
    Pin<Box<dyn Future<Output = Result<HttpResponse, TransportError>> + Send + 'a>>;

/// Consumer-implementable seam for preparing a direct-pairing transport.
pub trait DirectPairingSeam: Send + Sync {
    /// Prepare a connection to `endpoint` without writing the pairing request.
    fn prepare<'a>(
        &'a self,
        config: Arc<ClientConfig>,
        endpoint: &'a Endpoint,
    ) -> DirectPairPrepareFuture<'a>;
}

/// A prepared direct-pairing connection that has not yet sent its sole request.
pub trait PreparedDirectPairConnection: Send {
    /// Send the pairing request and return its HTTP response.
    fn send<'a>(
        self: Box<Self>,
        method: &'a str,
        path: &'a str,
        headers: &'a [(String, String)],
        body: &'a [u8],
    ) -> DirectPairSendFuture<'a>;
}

struct RealDirectPairingSeam;

struct TlsPreparedDirectPairConnection {
    stream: TlsStream<TcpStream>,
}

impl DirectPairingSeam for RealDirectPairingSeam {
    fn prepare<'a>(
        &'a self,
        config: Arc<ClientConfig>,
        endpoint: &'a Endpoint,
    ) -> DirectPairPrepareFuture<'a> {
        Box::pin(async move {
            let stream = dial_tls(config, &endpoint.host, endpoint.port).await?;
            Ok(Box::new(TlsPreparedDirectPairConnection { stream })
                as Box<dyn PreparedDirectPairConnection>)
        })
    }
}

impl PreparedDirectPairConnection for TlsPreparedDirectPairConnection {
    fn send<'a>(
        self: Box<Self>,
        method: &'a str,
        path: &'a str,
        headers: &'a [(String, String)],
        body: &'a [u8],
    ) -> DirectPairSendFuture<'a> {
        Box::pin(
            async move { run_request_over_stream(self.stream, method, path, headers, body).await },
        )
    }
}

/// Pair against the given candidate endpoints using the one-shot `nonce_hex` and
/// the pinned `ca_fp_prefix`. Returns the signed [`Credential`] on success.
/// Direct-address allow-listing and duplicate coalescing are pair-link parser
/// policy; this lower-level function uses endpoints exactly as supplied.
///
/// # Errors
///
/// Returns an endpoint, TLS, I/O, HTTP, JSON, or pairing-verification error if
/// the ceremony cannot produce a verified credential.
pub async fn pair(
    endpoints: &[Endpoint],
    nonce_hex: &str,
    ca_fp_prefix: &[u8],
    device_label: &str,
    additional_fields: &serde_json::Map<String, serde_json::Value>,
) -> Result<Credential, TransportError> {
    pair_with_seam(
        endpoints,
        nonce_hex,
        ca_fp_prefix,
        device_label,
        Arc::new(RealDirectPairingSeam),
        additional_fields,
    )
    .await
}

/// Pair through a consumer-supplied direct transport while keeping key generation internal.
///
/// # Errors
///
/// Returns an endpoint, TLS, I/O, HTTP, JSON, or pairing-verification error if
/// the ceremony cannot produce a verified credential.
///
/// # Panics
///
/// Does not panic: the non-empty endpoint guard and exhaustive candidate loop
/// guarantee a preparation error is recorded before the invariant assertion.
pub async fn pair_with_seam(
    endpoints: &[Endpoint],
    nonce_hex: &str,
    ca_fp_prefix: &[u8],
    device_label: &str,
    seam: Arc<dyn DirectPairingSeam>,
    additional_fields: &serde_json::Map<String, serde_json::Value>,
) -> Result<Credential, TransportError> {
    if endpoints.is_empty() {
        return Err(TransportError::NoEndpoint);
    }
    let config = Arc::new(tls::pairing_config(ca_fp_prefix)?);
    let path = format!("{PAIR_PATH}?token={nonce_hex}");
    let generated = generate_csr(device_label)?;
    let request = build_pair_request(generated.csr_pem.clone(), device_label, additional_fields)?;
    let body = serde_json::to_vec(&request)?;
    let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

    let mut last_err: Option<TransportError> = None;
    for endpoint in endpoints {
        match seam.prepare(config.clone(), endpoint).await {
            Ok(connection) => {
                let response = connection.send("POST", &path, &headers, &body).await?;
                return credential_from_direct_pair_response(
                    response,
                    generated,
                    ca_fp_prefix,
                    endpoints,
                );
            }
            Err(e) => last_err = Some(e),
        }
    }
    #[expect(
        clippy::expect_used,
        reason = "the non-empty endpoint guard and exhaustive loop prove that a preparation error was recorded"
    )]
    let last_err = last_err.expect("a non-empty endpoint list always records a preparation error");
    Err(last_err)
}

/// Parse a `https://go.solstone.app/p#…` pair-link and pair against it.
///
/// # Errors
///
/// Returns a pair-link parsing error or any direct/relay pairing error.
pub async fn pair_from_link(
    link: &str,
    device_label: &str,
    additional_fields: &serde_json::Map<String, serde_json::Value>,
) -> Result<Credential, TransportError> {
    #[expect(
        clippy::large_futures,
        reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
    )]
    let result = pair_from_link_with_seam(
        link,
        device_label,
        Arc::new(RealDirectPairingSeam),
        additional_fields,
    )
    .await;
    result
}

async fn pair_from_link_with_seam(
    link: &str,
    device_label: &str,
    seam: Arc<dyn DirectPairingSeam>,
    additional_fields: &serde_json::Map<String, serde_json::Value>,
) -> Result<Credential, TransportError> {
    let parsed = pairlink::parse(link).map_err(|e| TransportError::PairLink(e.to_string()))?;
    match parsed {
        ParsedPairLink::Direct(pl) => {
            pair_with_seam(
                &pl.candidates,
                &pl.nonce_hex,
                &pl.ca_fp_prefix,
                device_label,
                seam,
                additional_fields,
            )
            .await
        }
        ParsedPairLink::Relay(rl) => {
            #[expect(
                clippy::large_futures,
                reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
            )]
            let result = relay_pairing::pair_over_relay(&rl, device_label, additional_fields).await;
            result
        }
    }
}

pub(crate) fn build_pair_request(
    csr: String,
    device_label: &str,
    additional_fields: &serde_json::Map<String, serde_json::Value>,
) -> Result<PairRequest, TransportError> {
    for reserved in ["csr", "device_label"] {
        if additional_fields.contains_key(reserved) {
            return Err(TransportError::Pairing(format!(
                "additional pair field collides with reserved field {reserved:?}"
            )));
        }
    }
    Ok(PairRequest {
        csr,
        device_label: device_label.to_string(),
        additional_fields: additional_fields.clone(),
    })
}

pub(crate) fn summarize_rejection_body(body: &[u8]) -> String {
    let digest = ca::sha256_hex(body);
    format!(
        "rejection-body bytes={} sha256={}",
        body.len(),
        &digest[..12]
    )
}

pub(crate) fn verify_client_cert_key_binding(
    cert_der: &[u8],
    generated_public_key_spki_der: &[u8],
) -> Result<(), TransportError> {
    let cert_spki = ca::extract_spki_der(cert_der).map_err(|_| {
        TransportError::Pairing("client certificate public key is malformed".into())
    })?;
    if cert_spki != generated_public_key_spki_der {
        return Err(TransportError::Pairing(
            "client certificate public key does not match generated key".into(),
        ));
    }
    Ok(())
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "the pairing response is consumed into the resulting credential after verification"
)]
fn credential_from_direct_pair_response(
    response: HttpResponse,
    generated: GeneratedKey,
    ca_fp_prefix: &[u8],
    all_endpoints: &[Endpoint],
) -> Result<Credential, TransportError> {
    if !response.is_success() {
        return Err(TransportError::Rejected {
            status: response.status,
            body: summarize_rejection_body(&response.body),
        });
    }

    let pair: PairResponse = serde_json::from_slice(&response.body)?;
    let cert_der = tls::parse_certs(&pair.client_cert)?
        .into_iter()
        .next()
        .ok_or_else(|| TransportError::Pairing("pair response carried no client cert".into()))?;
    let computed = format!("sha256:{}", ca::sha256_hex(cert_der.as_ref()));
    if pair.fingerprint != computed {
        return Err(TransportError::Pairing(format!(
            "client cert fingerprint mismatch (journal: {}, computed: {})",
            pair.fingerprint, computed
        )));
    }
    verify_client_cert_key_binding(cert_der.as_ref(), &generated.public_key_spki_der)?;

    Ok(Credential {
        client_key_pem: generated.key_pem,
        client_cert_pem: pair.client_cert,
        ca_chain_pem: pair.ca_chain,
        ca_fp_prefix: ca_fp_prefix.to_vec(),
        instance_id: pair.instance_id,
        home_label: pair.home_label,
        endpoints: all_endpoints.iter().map(EndpointAddr::from).collect(),
        home_attestation: pair.home_attestation,
        local_endpoints: pair.local_endpoints,
        relay_origin: None,
        device_token: None,
        device_token_expires_at: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::VecDeque;
    use std::io;
    use std::sync::Mutex;

    use rcgen::{
        BasicConstraints, CertificateParams, CertificateSigningRequestParams, IsCa, KeyPair,
        KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
    };
    use spl_core::mux::MuxError;

    type SendScript =
        Box<dyn FnOnce(&[u8]) -> Result<HttpResponse, TransportError> + Send + 'static>;

    #[derive(Debug, Default)]
    struct PairingCounters {
        prepare_attempts: Vec<Endpoint>,
        request_bodies: Vec<Vec<u8>>,
    }

    struct FakeDirectPairingSeam {
        prepare_results: Mutex<VecDeque<Result<(), TransportError>>>,
        send_script: Arc<Mutex<Option<SendScript>>>,
        counters: Arc<Mutex<PairingCounters>>,
    }

    impl FakeDirectPairingSeam {
        fn new(
            prepare_results: Vec<Result<(), TransportError>>,
            send_script: SendScript,
        ) -> Arc<Self> {
            Arc::new(Self {
                prepare_results: Mutex::new(VecDeque::from(prepare_results)),
                send_script: Arc::new(Mutex::new(Some(send_script))),
                counters: Arc::new(Mutex::new(PairingCounters::default())),
            })
        }

        fn counters(&self) -> Arc<Mutex<PairingCounters>> {
            self.counters.clone()
        }
    }

    impl DirectPairingSeam for FakeDirectPairingSeam {
        fn prepare<'a>(
            &'a self,
            _config: Arc<ClientConfig>,
            endpoint: &'a Endpoint,
        ) -> DirectPairPrepareFuture<'a> {
            self.counters
                .lock()
                .unwrap()
                .prepare_attempts
                .push(endpoint.clone());
            let result = self
                .prepare_results
                .lock()
                .unwrap()
                .pop_front()
                .expect("scripted prepare result");
            let send_script = self.send_script.clone();
            let counters = self.counters.clone();
            Box::pin(async move {
                result?;
                Ok(Box::new(FakePreparedDirectPairConnection {
                    send_script,
                    counters,
                }) as Box<dyn PreparedDirectPairConnection>)
            })
        }
    }

    struct FakePreparedDirectPairConnection {
        send_script: Arc<Mutex<Option<SendScript>>>,
        counters: Arc<Mutex<PairingCounters>>,
    }

    impl PreparedDirectPairConnection for FakePreparedDirectPairConnection {
        fn send<'a>(
            self: Box<Self>,
            _method: &'a str,
            _path: &'a str,
            _headers: &'a [(String, String)],
            body: &'a [u8],
        ) -> DirectPairSendFuture<'a> {
            self.counters
                .lock()
                .unwrap()
                .request_bodies
                .push(body.to_vec());
            let script = self
                .send_script
                .lock()
                .unwrap()
                .take()
                .expect("one scripted request write");
            let result = script(body);
            Box::pin(async move { result })
        }
    }

    #[derive(Clone, Copy)]
    enum TestCertificateMode {
        SubmittedCsr,
        UnrelatedKey,
    }

    fn pair_response(request_body: &[u8], mode: TestCertificateMode) -> PairResponse {
        let request: PairRequest = serde_json::from_slice(request_body).unwrap();
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        ca_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let client_cert = match mode {
            TestCertificateMode::SubmittedCsr => {
                CertificateSigningRequestParams::from_pem(&request.csr)
                    .unwrap()
                    .signed_by(&ca_cert, &ca_key)
                    .unwrap()
            }
            TestCertificateMode::UnrelatedKey => {
                let unrelated_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
                CertificateParams::new(Vec::<String>::new())
                    .unwrap()
                    .signed_by(&unrelated_key, &ca_cert, &ca_key)
                    .unwrap()
            }
        };
        PairResponse {
            client_cert: client_cert.pem(),
            ca_chain: vec![ca_cert.pem()],
            instance_id: "test-instance".into(),
            home_label: "Home".into(),
            fingerprint: format!("sha256:{}", ca::sha256_hex(client_cert.der())),
            home_attestation: None,
            local_endpoints: None,
        }
    }

    fn http_response(status: u16, body: Vec<u8>) -> HttpResponse {
        HttpResponse {
            status,
            headers: Vec::new(),
            body,
        }
    }

    fn fixed_send(result: Result<HttpResponse, TransportError>) -> SendScript {
        Box::new(move |_| result)
    }

    fn successful_send() -> SendScript {
        Box::new(|request_body| {
            Ok(http_response(
                200,
                serde_json::to_vec(&pair_response(
                    request_body,
                    TestCertificateMode::SubmittedCsr,
                ))
                .unwrap(),
            ))
        })
    }

    fn endpoint(host: &str, port: u16) -> Endpoint {
        Endpoint {
            host: host.into(),
            port,
        }
    }

    fn test_endpoints() -> Vec<Endpoint> {
        vec![
            endpoint("10.0.0.1", 7657),
            endpoint("192.168.0.2", 7657),
            endpoint("100.64.0.3", 7657),
        ]
    }

    fn direct_v05_link(addresses: &[[u8; 4]]) -> String {
        let mut blob = vec![0x05, 0x01, addresses.len() as u8];
        blob.extend_from_slice(&7657u16.to_be_bytes());
        for address in addresses {
            blob.extend_from_slice(address);
        }
        blob.extend_from_slice(&[0x11; 16]);
        blob.extend_from_slice(&[0x22; 16]);
        format!(
            "https://go.solstone.app/p#{}",
            spl_core::crockford::encode(&blob)
        )
    }

    fn prepare_error(message: &'static str) -> TransportError {
        TransportError::Io(io::Error::other(message))
    }

    #[test]
    fn additional_pair_fields_reject_reserved_wire_keys() {
        for reserved in ["csr", "device_label"] {
            let mut additional_fields = serde_json::Map::new();
            additional_fields.insert(reserved.into(), serde_json::Value::Null);
            let error = build_pair_request("CSR".into(), "device", &additional_fields).unwrap_err();
            assert!(matches!(
                error,
                TransportError::Pairing(message)
                    if message == format!(
                        "additional pair field collides with reserved field {reserved:?}"
                    )
            ));
        }
    }

    #[tokio::test]
    async fn direct_pair_link_refusal_has_zero_prepare_and_write_counts() {
        let seam = FakeDirectPairingSeam::new(vec![], successful_send());
        let counters = seam.counters();
        let link = direct_v05_link(&[[10, 0, 0, 1], [192, 0, 2, 42]]);
        let additional_fields = serde_json::Map::new();

        let error = pair_from_link_with_seam(&link, "test-device", seam, &additional_fields)
            .await
            .unwrap_err();

        assert!(matches!(error, TransportError::PairLink(_)));
        let counters = counters.lock().unwrap();
        assert!(counters.prepare_attempts.is_empty());
        assert!(counters.request_bodies.is_empty());
    }

    #[tokio::test]
    async fn direct_pairing_generates_one_material_and_prepares_in_candidate_order() {
        let seam = FakeDirectPairingSeam::new(
            vec![
                Err(prepare_error("first unavailable")),
                Err(prepare_error("second unavailable")),
                Ok(()),
            ],
            successful_send(),
        );
        let counters = seam.counters();
        let endpoints = test_endpoints();
        let additional_fields = serde_json::Map::new();

        let credential = pair_with_seam(
            &endpoints,
            "00112233445566778899aabbccddeeff",
            &[0x22; 16],
            "test-device",
            seam,
            &additional_fields,
        )
        .await
        .unwrap();

        assert_eq!(credential.endpoints.len(), 3);
        let counters = counters.lock().unwrap();
        assert_eq!(counters.prepare_attempts, endpoints);
        assert_eq!(counters.request_bodies.len(), 1);
        let request: PairRequest = serde_json::from_slice(&counters.request_bodies[0]).unwrap();
        assert_eq!(request.device_label, "test-device");
        assert_eq!(request.csr.matches("BEGIN CERTIFICATE REQUEST").count(), 1);
        CertificateSigningRequestParams::from_pem(&request.csr).unwrap();
    }

    #[tokio::test]
    async fn direct_pairing_all_prepare_failures_return_last_error_without_writing() {
        let seam = FakeDirectPairingSeam::new(
            vec![
                Err(prepare_error("first unavailable")),
                Err(prepare_error("second unavailable")),
                Err(TransportError::Tls("last handshake failed".into())),
            ],
            successful_send(),
        );
        let counters = seam.counters();
        let endpoints = test_endpoints();
        let additional_fields = serde_json::Map::new();

        let error = pair_with_seam(
            &endpoints,
            "00112233445566778899aabbccddeeff",
            &[0x22; 16],
            "test-device",
            seam,
            &additional_fields,
        )
        .await
        .unwrap_err();

        assert!(matches!(
            error,
            TransportError::Tls(message) if message == "last handshake failed"
        ));
        let counters = counters.lock().unwrap();
        assert_eq!(counters.prepare_attempts, endpoints);
        assert!(counters.request_bodies.is_empty());
    }

    #[tokio::test]
    async fn parser_coalesced_candidates_are_each_prepared_at_most_once() {
        let seam = FakeDirectPairingSeam::new(
            vec![
                Err(prepare_error("first unavailable")),
                Err(prepare_error("second unavailable")),
            ],
            successful_send(),
        );
        let counters = seam.counters();
        let link = direct_v05_link(&[[10, 0, 0, 1], [192, 168, 0, 2], [10, 0, 0, 1]]);
        let additional_fields = serde_json::Map::new();

        let error = pair_from_link_with_seam(&link, "test-device", seam, &additional_fields)
            .await
            .unwrap_err();

        assert!(matches!(error, TransportError::Io(_)));
        let counters = counters.lock().unwrap();
        assert_eq!(
            counters.prepare_attempts,
            vec![endpoint("10.0.0.1", 7657), endpoint("192.168.0.2", 7657),]
        );
        assert!(counters.request_bodies.is_empty());
    }

    #[derive(Clone, Copy, Debug)]
    enum TerminalFailureKind {
        ImmediateWrite,
        PartialWrite,
        ResponseTimeout,
        ResponseReset,
        ResponseClose,
        Http400,
        Http403,
        Http500,
        MalformedJson,
        NoClientCertificate,
        FingerprintMismatch,
        DifferentKeyCertificate,
        MalformedCertificate,
        CredentialConstruction,
    }

    enum ExpectedFailure {
        Io(io::ErrorKind, &'static str),
        Mux(MuxError),
        Rejected(u16),
        Json,
        TlsPrefix(&'static str),
        PairingExact(&'static str),
        PairingPrefix(&'static str),
    }

    fn terminal_failure_script(kind: TerminalFailureKind) -> (SendScript, ExpectedFailure) {
        match kind {
            // The seam observes a send failure, not TCP byte progress. Distinct
            // errors keep immediate and partial writes independently attributable
            // without claiming the fake can see how many bytes reached the peer.
            TerminalFailureKind::ImmediateWrite => (
                fixed_send(Err(TransportError::Io(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "immediate write failed",
                )))),
                ExpectedFailure::Io(io::ErrorKind::BrokenPipe, "immediate write failed"),
            ),
            TerminalFailureKind::PartialWrite => (
                fixed_send(Err(TransportError::Io(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "partial write failed",
                )))),
                ExpectedFailure::Io(io::ErrorKind::WriteZero, "partial write failed"),
            ),
            TerminalFailureKind::ResponseTimeout => (
                fixed_send(Err(TransportError::Io(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "response timed out",
                )))),
                ExpectedFailure::Io(io::ErrorKind::TimedOut, "response timed out"),
            ),
            TerminalFailureKind::ResponseReset => (
                fixed_send(Err(TransportError::Mux(MuxError::StreamReset))),
                ExpectedFailure::Mux(MuxError::StreamReset),
            ),
            TerminalFailureKind::ResponseClose => (
                fixed_send(Err(TransportError::Mux(MuxError::Incomplete))),
                ExpectedFailure::Mux(MuxError::Incomplete),
            ),
            TerminalFailureKind::Http400 => (
                fixed_send(Ok(http_response(400, b"bad request".to_vec()))),
                ExpectedFailure::Rejected(400),
            ),
            TerminalFailureKind::Http403 => (
                fixed_send(Ok(http_response(403, b"forbidden".to_vec()))),
                ExpectedFailure::Rejected(403),
            ),
            TerminalFailureKind::Http500 => (
                fixed_send(Ok(http_response(500, b"server error".to_vec()))),
                ExpectedFailure::Rejected(500),
            ),
            TerminalFailureKind::MalformedJson => (
                fixed_send(Ok(http_response(200, b"{".to_vec()))),
                ExpectedFailure::Json,
            ),
            TerminalFailureKind::NoClientCertificate => (
                Box::new(|request_body| {
                    let mut response =
                        pair_response(request_body, TestCertificateMode::SubmittedCsr);
                    response.client_cert.clear();
                    Ok(http_response(200, serde_json::to_vec(&response).unwrap()))
                }),
                ExpectedFailure::PairingExact("pair response carried no client cert"),
            ),
            TerminalFailureKind::FingerprintMismatch => (
                Box::new(|request_body| {
                    let mut response =
                        pair_response(request_body, TestCertificateMode::SubmittedCsr);
                    response.fingerprint = "sha256:not-the-client-cert".into();
                    Ok(http_response(200, serde_json::to_vec(&response).unwrap()))
                }),
                ExpectedFailure::PairingPrefix("client cert fingerprint mismatch"),
            ),
            TerminalFailureKind::DifferentKeyCertificate => (
                Box::new(|request_body| {
                    let response = pair_response(request_body, TestCertificateMode::UnrelatedKey);
                    Ok(http_response(200, serde_json::to_vec(&response).unwrap()))
                }),
                ExpectedFailure::PairingExact(
                    "client certificate public key does not match generated key",
                ),
            ),
            TerminalFailureKind::MalformedCertificate => (
                Box::new(|request_body| {
                    let mut response =
                        pair_response(request_body, TestCertificateMode::SubmittedCsr);
                    response.client_cert =
                        "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n".into();
                    response.fingerprint = format!("sha256:{}", ca::sha256_hex(&[0]));
                    Ok(http_response(200, serde_json::to_vec(&response).unwrap()))
                }),
                ExpectedFailure::PairingExact("client certificate public key is malformed"),
            ),
            TerminalFailureKind::CredentialConstruction => (
                Box::new(|request_body| {
                    let mut response =
                        pair_response(request_body, TestCertificateMode::SubmittedCsr);
                    response.client_cert =
                        "-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n".into();
                    Ok(http_response(200, serde_json::to_vec(&response).unwrap()))
                }),
                ExpectedFailure::TlsPrefix("bad certificate PEM:"),
            ),
        }
    }

    fn assert_expected_failure(error: TransportError, expected: ExpectedFailure) {
        match (error, expected) {
            (TransportError::Io(error), ExpectedFailure::Io(kind, message)) => {
                assert_eq!(error.kind(), kind);
                assert_eq!(error.to_string(), message);
            }
            (TransportError::Mux(actual), ExpectedFailure::Mux(expected)) => {
                assert_eq!(actual, expected);
            }
            (TransportError::Rejected { status, .. }, ExpectedFailure::Rejected(expected)) => {
                assert_eq!(status, expected)
            }
            (TransportError::Json(_), ExpectedFailure::Json) => {}
            (TransportError::Tls(actual), ExpectedFailure::TlsPrefix(expected)) => {
                assert!(
                    actual.starts_with(expected),
                    "unexpected TLS error: {actual}"
                );
            }
            (TransportError::Pairing(actual), ExpectedFailure::PairingExact(expected)) => {
                assert_eq!(actual, expected);
            }
            (TransportError::Pairing(actual), ExpectedFailure::PairingPrefix(expected)) => {
                assert!(
                    actual.starts_with(expected),
                    "unexpected pairing error: {actual}"
                );
            }
            (actual, _) => panic!("unexpected terminal error: {actual:?}"),
        }
    }

    #[tokio::test]
    async fn direct_pairing_first_write_is_terminal_for_every_failure_shape() {
        for kind in [
            TerminalFailureKind::ImmediateWrite,
            TerminalFailureKind::PartialWrite,
            TerminalFailureKind::ResponseTimeout,
            TerminalFailureKind::ResponseReset,
            TerminalFailureKind::ResponseClose,
            TerminalFailureKind::Http400,
            TerminalFailureKind::Http403,
            TerminalFailureKind::Http500,
            TerminalFailureKind::MalformedJson,
            TerminalFailureKind::NoClientCertificate,
            TerminalFailureKind::FingerprintMismatch,
            TerminalFailureKind::DifferentKeyCertificate,
            TerminalFailureKind::MalformedCertificate,
            TerminalFailureKind::CredentialConstruction,
        ] {
            let (send_script, expected) = terminal_failure_script(kind);
            let seam = FakeDirectPairingSeam::new(vec![Ok(())], send_script);
            let counters = seam.counters();
            let additional_fields = serde_json::Map::new();
            let error = pair_with_seam(
                &test_endpoints(),
                "00112233445566778899aabbccddeeff",
                &[0x22; 16],
                "test-device",
                seam,
                &additional_fields,
            )
            .await
            .unwrap_err();

            assert_expected_failure(error, expected);
            let counters = counters.lock().unwrap();
            assert_eq!(
                counters.prepare_attempts.len(),
                1,
                "later endpoint prepared after {kind:?}"
            );
            assert_eq!(
                counters.request_bodies.len(),
                1,
                "extra request written after {kind:?}"
            );
        }
    }

    #[tokio::test]
    async fn direct_pairing_rejection_preserves_status_and_displays_only_body_summary() {
        let nonce = "00112233445566778899aabbccddeeff";
        let csr = "-----BEGIN CERTIFICATE REQUEST-----";
        let ca_fp_prefix = [0x22; 16];
        let ca_fp = "22222222222222222222222222222222";
        let fragment = "PAIRLINK-FRAGMENT-SENTINEL";
        let request_url =
            "https://10.0.0.1:7657/app/network/pair?token=00112233445566778899aabbccddeeff";
        let mut raw_body = format!(
            "reflected nonce={nonce} csr={csr} ca={ca_fp} fragment={fragment} url={request_url}"
        )
        .into_bytes();
        raw_body.push(0xff);
        assert_ne!(String::from_utf8_lossy(&raw_body).len(), raw_body.len());
        let expected_digest = ca::sha256_hex(&raw_body);
        let expected_display = format!(
            "server rejected request: HTTP 403 rejection-body bytes={} sha256={}",
            raw_body.len(),
            &expected_digest[..12]
        );

        let seam =
            FakeDirectPairingSeam::new(vec![Ok(())], fixed_send(Ok(http_response(403, raw_body))));
        let additional_fields = serde_json::Map::new();
        let error = pair_with_seam(
            &test_endpoints(),
            nonce,
            &ca_fp_prefix,
            "test-device",
            seam,
            &additional_fields,
        )
        .await
        .unwrap_err();

        assert_eq!(crate::transport_error_code(&error), "http_403");
        let display = error.to_string();
        assert_eq!(display, expected_display);
        for sentinel in [nonce, csr, ca_fp, fragment, request_url, "?token="] {
            assert!(
                !display.contains(sentinel),
                "rejection display reflected {sentinel}"
            );
        }
        assert!(matches!(
            error,
            TransportError::Rejected { status: 403, .. }
        ));
    }
}
