// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "the copied integration tests use unwraps and expect messages to keep harness failures at their exact setup or assertion site"
)]

//! End-to-end transport round-trip against a real in-process rustls peer.
//!
//! Stands up a tokio-rustls TLS server presenting a self-signed cert, then dials
//! it with the production `request_once` path: real TCP, real TLS 1.3 handshake,
//! real CA-fingerprint pinning + leaf-signature verification, real spl framing,
//! real HTTP-over-PL. Nothing is mocked — only the journal application logic is
//! replaced by a fixed echo. This is the deterministic, host-runnable proxy for
//! the live cross-repo gate.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error, ServerConfig, SignatureScheme,
};
use spl_core::bridge::BridgeNames;
use spl_core::frame::{
    FLAG_CLOSE, FLAG_DATA, FLAG_RESET, FLAG_WINDOW, Frame, FrameDecoder, RESET_CANCEL,
};
use spl_core::http::HttpResponse;
use spl_core::mux::INITIAL_WINDOW;
use spl_core::pairlink::Endpoint;
use spl_transport::TransportError;
use spl_transport::client::{DialedCarrier, TransportClient};
use spl_transport::connection::request_once;
use spl_transport::credential::{Credential, EndpointAddr};
use spl_transport::journal_bridge::{
    self, BridgePolicy, CapabilityGate, CarrierOpener, JournalBridgeConfig,
};
use spl_transport::pairing::{
    DirectPairPrepareFuture, DirectPairSendFuture, DirectPairingSeam, PreparedDirectPairConnection,
};
use spl_transport::tls::pairing_config;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

const TEST_CAP_COOKIE_NAME: &str = "test-journal-cap";
const TEST_OBSERVER_HEADER_NAME: &str = "x-test-observer";
const TEST_PROTOCOL_HEADER_NAME: &str = "x-test-protocol";
const TEST_OBSERVER_KEY: &str = "test-handle";

// Synthetic pairing values preserve the source fixture's asserted values while
// keeping this crate independent of the consumer contract bundle.
const PAIR_EXAMPLE_NONCE: &str = "5f0d8c8b9f1e48b0a5f80b98f3d5e9b0";
const PAIR_EXAMPLE_DEVICE_LABEL: &str = "Jer iPhone";
const PAIR_EXAMPLE_INSTANCE_ID: &str = "4d1f3d57-4f39-4930-b8f8-5e6f2a84d51a";
const PAIR_EXAMPLE_HOME_LABEL: &str = "home";
const PAIR_EXAMPLE_HOME_ATTESTATION: &str = "eyJhbGciOi...";

fn self_signed() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let params = CertificateParams::new(vec!["spl.local".to_string()]).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    (cert_der, key_der)
}

fn server_config(cert: CertificateDer<'static>, key: PrivateKeyDer<'static>) -> ServerConfig {
    ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap()
}

#[derive(Debug)]
struct RejectVerifier(CertificateError);

impl ClientCertVerifier for RejectVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        Err(Error::InvalidCertificate(self.0.clone()))
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::InvalidCertificate(
            CertificateError::ApplicationVerificationFailure,
        ))
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::InvalidCertificate(
            CertificateError::ApplicationVerificationFailure,
        ))
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ECDSA_NISTP256_SHA256]
    }
}

/// A journal-like server that accepts every client certificate and counts its checks.
#[derive(Debug)]
struct CountingAcceptVerifier(Arc<AtomicUsize>);

impl ClientCertVerifier for CountingAcceptVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ECDSA_NISTP256_SHA256]
    }
}

// A resumed TLS session skips the journal's check of the device certificate, so a journal could
// neither refuse an unpaired device nor say why. Falsified by leaving client session resumption
// on: the second session resumes against a server that allows it, unchecked.
#[tokio::test]
async fn every_mtls_session_is_a_full_handshake_the_journal_checks() {
    let (cert, key) = self_signed();
    let pin = spl_core::ca::sha256(cert.as_ref())[..16].to_vec();
    let checks = Arc::new(AtomicUsize::new(0));
    let server = Arc::new(
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(Arc::new(CountingAcceptVerifier(checks.clone())))
            .with_single_cert(vec![cert], key)
            .unwrap(),
    );
    let client_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let client_cert = CertificateParams::new(vec!["transport.test".to_string()])
        .unwrap()
        .self_signed(&client_key)
        .unwrap();
    let client = Arc::new(
        spl_transport::tls::mtls_config(
            &pin,
            vec![CertificateDer::from(client_cert.der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(client_key.serialize_der())),
        )
        .unwrap(),
    );

    let mut kinds = Vec::new();
    for _ in 0..2 {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let acceptor = TlsAcceptor::from(server.clone());
        let session = tokio::spawn(async move {
            let mut tls = acceptor.accept(server_io).await.unwrap();
            let kind = tls.get_ref().1.handshake_kind();
            tls.write_all(b"x").await.unwrap();
            tls.flush().await.unwrap();
            let mut byte = [0_u8; 1];
            let _ = tls.read(&mut byte).await;
            kind
        });
        let mut tls = tokio_rustls::TlsConnector::from(client.clone())
            .connect(
                rustls::pki_types::ServerName::try_from("spl.local").unwrap(),
                client_io,
            )
            .await
            .unwrap();
        // Reading processes the session tickets the server sends after the handshake.
        let mut byte = [0_u8; 1];
        tls.read_exact(&mut byte).await.unwrap();
        tls.write_all(b"y").await.unwrap();
        tls.flush().await.unwrap();
        drop(tls);
        kinds.push(session.await.unwrap());
    }
    assert_eq!(kinds, vec![Some(rustls::HandshakeKind::Full); 2]);
    assert_eq!(checks.load(Ordering::SeqCst), 2);
}

fn rejecting_server_config(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> ServerConfig {
    refusing_server_config(cert, key, CertificateError::ApplicationVerificationFailure)
}

/// A journal-like server that finishes its side of TLS 1.3 and then refuses the
/// client certificate, so the alert reaches the client after its handshake.
/// rustls sends 49 for `ApplicationVerificationFailure`, 46 for `Other`, and
/// 48 for `UnknownIssuer`.
fn refusing_server_config(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    error: CertificateError,
) -> ServerConfig {
    ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(Arc::new(RejectVerifier(error)))
        .with_single_cert(vec![cert], key)
        .unwrap()
}

/// A server-side refusal, the status it should record, and the error it should surface.
type RefusalClass = (
    CertificateError,
    Option<journal_bridge::JournalBridgeFailure>,
    fn(&TransportError) -> bool,
);

fn refusal_classes() -> [RefusalClass; 3] {
    [
        (
            CertificateError::ApplicationVerificationFailure,
            Some(journal_bridge::JournalBridgeFailure::TlsAccessDenied),
            |error| matches!(error, TransportError::TlsAccessDenied),
        ),
        (
            CertificateError::Other(rustls::OtherError(Arc::new(std::io::Error::other(
                "pairing records unreadable",
            )))),
            Some(journal_bridge::JournalBridgeFailure::TlsCertificateUnknown),
            |error| matches!(error, TransportError::TlsCertificateUnknown),
        ),
        (
            CertificateError::UnknownIssuer,
            Some(journal_bridge::JournalBridgeFailure::TlsRefused),
            |error| matches!(error, TransportError::TlsRefused),
        ),
    ]
}

fn transport_credential(pin: Vec<u8>, port: u16) -> Credential {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let params = CertificateParams::new(vec!["transport.test".to_string()]).unwrap();
    let cert = params.self_signed(&key).unwrap();
    Credential {
        client_key_pem: key.serialize_pem(),
        client_cert_pem: cert.pem(),
        ca_chain_pem: vec![cert.pem()],
        ca_fp_prefix: pin,
        instance_id: "test-instance".into(),
        home_label: "Home".into(),
        endpoints: vec![EndpointAddr {
            host: "127.0.0.1".into(),
            port,
        }],
        home_attestation: None,
        local_endpoints: None,
        relay_origin: None,
        device_token: None,
        device_token_expires_at: None,
    }
}

fn request_body(request: &[u8]) -> serde_json::Value {
    let request = String::from_utf8_lossy(request);
    let (_, body) = request.split_once("\r\n\r\n").unwrap();
    serde_json::from_str(body).unwrap()
}

fn pair_capture_matches(request: &[u8], nonce: &str, label: &str) -> bool {
    let text = String::from_utf8_lossy(request);
    let body = request_body(request);
    text.starts_with(&format!(
        "POST /app/network/pair?token={nonce} HTTP/1.1\r\n"
    )) && text.contains("Content-Type: application/json\r\n")
        && !text.contains(TEST_OBSERVER_HEADER_NAME)
        && !text.contains("Authorization:")
        && !text.contains(TEST_PROTOCOL_HEADER_NAME)
        && body["device_label"] == label
        && body["csr"]
            .as_str()
            .is_some_and(|csr| csr.contains("BEGIN CERTIFICATE REQUEST"))
        && body.get("nonce").is_none()
        && body.get("sender_instance_id").is_none()
}

async fn read_framed_request(
    tls: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> (u32, Vec<u8>) {
    let mut decoder = FrameDecoder::new();
    let mut request = Vec::new();
    let mut stream_id = 1u32;
    let mut closed = false;
    let mut buf = [0u8; 4096];
    while !closed {
        let n = tls.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        decoder.feed(&buf[..n]);
        for frame in decoder.drain().unwrap() {
            stream_id = frame.stream_id;
            if frame.flags & FLAG_DATA != 0 {
                request.extend_from_slice(&frame.payload);
            }
            if frame.flags & FLAG_CLOSE != 0 {
                closed = true;
            }
        }
    }
    (stream_id, request)
}

/// Accept one TLS connection, read the framed HTTP request, and frame back a
/// fixed `{"status":"ok"}` response on the same stream. Returns the request body
/// it received so the test can assert the wire bytes.
async fn serve_one_response(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    status: &str,
    body: &'static [u8],
) -> Vec<u8> {
    serve_one_response_with_content_length(listener, acceptor, status, body, body.len()).await
}

async fn serve_one_response_with_content_length(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    status: &str,
    body: &'static [u8],
    content_length: usize,
) -> Vec<u8> {
    serve_one_response_with_header(listener, acceptor, status, body, content_length, None).await
}

async fn serve_one_response_with_header(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    status: &str,
    body: &'static [u8],
    content_length: usize,
    extra_header: Option<&str>,
) -> Vec<u8> {
    let (tcp, _) = listener.accept().await.unwrap();
    let mut tls = acceptor.accept(tcp).await.unwrap();

    let (stream_id, request) = read_framed_request(&mut tls).await;

    let extra_header = extra_header
        .map(|header| format!("{header}\r\n"))
        .unwrap_or_default();
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {content_length}\r\n{extra_header}\r\n{}",
        String::from_utf8_lossy(body)
    );
    let frame = Frame::new(stream_id, FLAG_DATA | FLAG_CLOSE, response.into_bytes());
    tls.write_all(&frame.encode().unwrap()).await.unwrap();
    tls.flush().await.unwrap();
    let _ = tls.shutdown().await;
    request
}

async fn serve_one(listener: TcpListener, acceptor: TlsAcceptor) -> Vec<u8> {
    serve_one_response(listener, acceptor, "200 OK", b"{\"status\":\"ok\"}").await
}

#[derive(Clone, Copy)]
enum PairCertificateMode {
    SubmittedCsr,
    UnrelatedKey,
}

fn pair_response_body(
    pair_request: &spl_core::PairRequest,
    signing_cert: &rcgen::Certificate,
    signing_key: &KeyPair,
    mode: PairCertificateMode,
) -> Vec<u8> {
    let client_cert = match mode {
        PairCertificateMode::SubmittedCsr => {
            CertificateSigningRequestParams::from_pem(&pair_request.csr)
                .unwrap()
                .signed_by(signing_cert, signing_key)
                .unwrap()
        }
        PairCertificateMode::UnrelatedKey => {
            let unrelated_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
            CertificateParams::new(Vec::<String>::new())
                .unwrap()
                .signed_by(&unrelated_key, signing_cert, signing_key)
                .unwrap()
        }
    };
    serde_json::to_vec(&serde_json::json!({
        "client_cert": client_cert.pem(),
        "ca_chain": [signing_cert.pem()],
        "instance_id": PAIR_EXAMPLE_INSTANCE_ID,
        "home_label": PAIR_EXAMPLE_HOME_LABEL,
        "fingerprint": format!("sha256:{}", spl_core::ca::sha256_hex(client_cert.der())),
        "home_attestation": PAIR_EXAMPLE_HOME_ATTESTATION,
        "local_endpoints": [{
            "ip": "192.168.1.10",
            "port": 7657,
            "scope": "lan",
        }],
    }))
    .unwrap()
}

async fn serve_one_pair_response_counted(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    signing_cert: rcgen::Certificate,
    signing_key: KeyPair,
    mode: PairCertificateMode,
    accepts: Option<Arc<AtomicUsize>>,
) -> Vec<u8> {
    let (tcp, _) = listener.accept().await.unwrap();
    if let Some(ref c) = accepts {
        c.fetch_add(1, Ordering::SeqCst);
    }
    let mut tls = acceptor.accept(tcp).await.unwrap();
    let (stream_id, request) = read_framed_request(&mut tls).await;
    let pair_request: spl_core::PairRequest =
        serde_json::from_value(request_body(&request)).unwrap();
    let response_body = pair_response_body(&pair_request, &signing_cert, &signing_key, mode);
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        response_body.len(),
        String::from_utf8_lossy(&response_body)
    );
    let frame = Frame::new(stream_id, FLAG_DATA | FLAG_CLOSE, response.into_bytes());
    tls.write_all(&frame.encode().unwrap()).await.unwrap();
    tls.flush().await.unwrap();
    let _ = tls.shutdown().await;
    request
}

async fn serve_one_pair_response(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    signing_cert: rcgen::Certificate,
    signing_key: KeyPair,
    mode: PairCertificateMode,
) -> Vec<u8> {
    serve_one_pair_response_counted(listener, acceptor, signing_cert, signing_key, mode, None).await
}

async fn serve_one_custom_pair_response_counted(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    status: &str,
    response_body: Vec<u8>,
    accepts: Option<Arc<AtomicUsize>>,
) -> Vec<u8> {
    let (tcp, _) = listener.accept().await.unwrap();
    if let Some(ref c) = accepts {
        c.fetch_add(1, Ordering::SeqCst);
    }
    let mut tls = acceptor.accept(tcp).await.unwrap();
    let (stream_id, request) = read_framed_request(&mut tls).await;
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        response_body.len(),
        String::from_utf8_lossy(&response_body)
    );
    let frame = Frame::new(stream_id, FLAG_DATA | FLAG_CLOSE, response.into_bytes());
    tls.write_all(&frame.encode().unwrap()).await.unwrap();
    tls.flush().await.unwrap();
    let _ = tls.shutdown().await;
    request
}

struct ConsumerDirectPairingSeam;

impl DirectPairingSeam for ConsumerDirectPairingSeam {
    fn prepare<'a>(
        &'a self,
        _config: Arc<ClientConfig>,
        _endpoint: &'a Endpoint,
    ) -> DirectPairPrepareFuture<'a> {
        Box::pin(async {
            Ok(Box::new(ConsumerPreparedDirectPairConnection)
                as Box<dyn PreparedDirectPairConnection>)
        })
    }
}

struct ConsumerPreparedDirectPairConnection;

impl PreparedDirectPairConnection for ConsumerPreparedDirectPairConnection {
    fn send<'a>(
        self: Box<Self>,
        _method: &'a str,
        _path: &'a str,
        _headers: &'a [(String, String)],
        body: &'a [u8],
    ) -> DirectPairSendFuture<'a> {
        let response = (|| {
            let pair_request: spl_core::PairRequest = serde_json::from_slice(body)?;
            let signing_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
            let mut signing_params = CertificateParams::new(Vec::<String>::new()).unwrap();
            signing_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            signing_params
                .key_usages
                .push(KeyUsagePurpose::DigitalSignature);
            signing_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
            let signing_cert = signing_params.self_signed(&signing_key).unwrap();
            Ok(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: pair_response_body(
                    &pair_request,
                    &signing_cert,
                    &signing_key,
                    PairCertificateMode::SubmittedCsr,
                ),
            })
        })();
        Box::pin(async move { response })
    }
}

#[derive(Clone, Copy)]
enum SseMode {
    Close,
    EofBeforeHead,
    EofAfterHeadAndPartialBody,
    Authority(&'static [u8]),
}

async fn write_response_frame(
    tls: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    stream_id: u32,
    flags: u8,
    payload: &[u8],
) {
    let frame = Frame::new(stream_id, flags, payload.to_vec());
    tls.write_all(&frame.encode().unwrap()).await.unwrap();
    tls.flush().await.unwrap();
}

async fn serve_sse_stream(listener: TcpListener, acceptor: TlsAcceptor, mode: SseMode) -> Vec<u8> {
    let (tcp, _) = listener.accept().await.unwrap();
    let mut tls = acceptor.accept(tcp).await.unwrap();
    let (stream_id, request) = read_framed_request(&mut tls).await;

    if matches!(mode, SseMode::EofBeforeHead) {
        return request;
    }

    write_response_frame(
        &mut tls,
        stream_id,
        FLAG_DATA,
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n",
    )
    .await;
    if matches!(mode, SseMode::EofAfterHeadAndPartialBody) {
        write_response_frame(&mut tls, stream_id, FLAG_DATA, b"data: partial").await;
        return request;
    }
    if let SseMode::Authority(body) = mode {
        write_response_frame(&mut tls, stream_id, FLAG_DATA, body).await;
        write_response_frame(&mut tls, stream_id, FLAG_CLOSE, b"").await;
        let _ = tls.shutdown().await;
        return request;
    }
    write_response_frame(&mut tls, stream_id, FLAG_DATA, b"data: 1\n\n").await;
    write_response_frame(&mut tls, stream_id, FLAG_DATA, b"data: 2\n\n").await;
    write_response_frame(&mut tls, stream_id, FLAG_CLOSE, b"").await;

    let _ = tls.shutdown().await;
    request
}

struct TestOpener {
    client: Arc<TransportClient>,
}

impl CarrierOpener for TestOpener {
    fn proxy_headers(
        &self,
        upstream_headers: &[(String, String)],
    ) -> Result<Vec<(String, String)>, TransportError> {
        let mut headers = upstream_headers.to_vec();
        headers.push((TEST_OBSERVER_HEADER_NAME.into(), TEST_OBSERVER_KEY.into()));
        headers.push((
            "Authorization".into(),
            format!("Bearer {TEST_OBSERVER_KEY}"),
        ));
        headers.push((TEST_PROTOCOL_HEADER_NAME.into(), "2".into()));
        Ok(headers)
    }

    fn dial_carrier(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<DialedCarrier, TransportError>> + Send + '_>> {
        Box::pin(self.client.dial_carrier())
    }
}

fn neutral_bridge_names() -> BridgeNames {
    BridgeNames {
        capability_cookie_name: TEST_CAP_COOKIE_NAME.into(),
        upstream_cookie_prefix: "test_j_".into(),
        observer_header_name: TEST_OBSERVER_HEADER_NAME.into(),
        protocol_version_header_name: TEST_PROTOCOL_HEADER_NAME.into(),
    }
}

async fn start_bridge(credential: Credential) -> journal_bridge::JournalBridgeHandle {
    start_bridge_with_policy(credential, BridgePolicy::default()).await
}

async fn start_bridge_with_policy(
    credential: Credential,
    policy: BridgePolicy,
) -> journal_bridge::JournalBridgeHandle {
    let endpoint_hosts = credential
        .endpoints
        .iter()
        .map(|endpoint| endpoint.host.clone())
        .collect();
    let client = Arc::new(TransportClient::new(credential, None).unwrap());
    journal_bridge::start(JournalBridgeConfig {
        opener: Arc::new(TestOpener { client }),
        bridge_names: neutral_bridge_names(),
        endpoint_hosts,
        policy,
    })
    .await
    .unwrap()
}

fn capability_from(handle: &journal_bridge::JournalBridgeHandle) -> String {
    handle
        .bootstrap_url()
        .expect("default bridge has capability")
        .split_once("cap=")
        .map(|(_, cap)| cap.to_string())
        .unwrap()
}

async fn start_bridge_with_response(
    status: &'static str,
    body: &'static [u8],
) -> (journal_bridge::JournalBridgeHandle, JoinHandle<Vec<u8>>) {
    let (cert, key) = self_signed();
    let pin = spl_core::ca::sha256(cert.as_ref())[..16].to_vec();
    let acceptor = TlsAcceptor::from(Arc::new(server_config(cert, key)));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(serve_one_response(listener, acceptor, status, body));
    let handle = start_bridge(transport_credential(pin, upstream_port)).await;
    (handle, server)
}

async fn start_bridge_with_response_content_length(
    status: &'static str,
    body: &'static [u8],
    content_length: usize,
) -> (journal_bridge::JournalBridgeHandle, JoinHandle<Vec<u8>>) {
    let (cert, key) = self_signed();
    let pin = spl_core::ca::sha256(cert.as_ref())[..16].to_vec();
    let acceptor = TlsAcceptor::from(Arc::new(server_config(cert, key)));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(serve_one_response_with_content_length(
        listener,
        acceptor,
        status,
        body,
        content_length,
    ));
    let handle = start_bridge(transport_credential(pin, upstream_port)).await;
    (handle, server)
}

async fn start_bridge_with_sse(
    mode: SseMode,
) -> (journal_bridge::JournalBridgeHandle, JoinHandle<Vec<u8>>) {
    let (cert, key) = self_signed();
    let pin = spl_core::ca::sha256(cert.as_ref())[..16].to_vec();
    let acceptor = TlsAcceptor::from(Arc::new(server_config(cert, key)));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(serve_sse_stream(listener, acceptor, mode));
    let handle = start_bridge(transport_credential(pin, upstream_port)).await;
    (handle, server)
}

async fn start_bridge_with_counting_upstream() -> (
    journal_bridge::JournalBridgeHandle,
    Arc<AtomicUsize>,
    JoinHandle<()>,
) {
    let (cert, key) = self_signed();
    let pin = spl_core::ca::sha256(cert.as_ref())[..16].to_vec();
    let _acceptor = TlsAcceptor::from(Arc::new(server_config(cert, key)));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = listener.local_addr().unwrap().port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let task = tokio::spawn({
        let accepts = accepts.clone();
        async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    break;
                };
                accepts.fetch_add(1, Ordering::SeqCst);
                drop(tcp);
            }
        }
    });
    let handle = start_bridge(transport_credential(pin, upstream_port)).await;
    (handle, accepts, task)
}

struct PersistentRequest {
    carrier_index: usize,
    stream_id: u32,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
struct PersistentFrameEvent {
    carrier_index: usize,
    stream_id: u32,
    flags: u8,
    payload_len: usize,
    cumulative_data: usize,
}

enum PersistentWrite {
    Frame(Vec<u8>),
    CloseCarrier,
}

struct PersistentBridgeServer {
    accepts: Arc<AtomicUsize>,
    requests: mpsc::Receiver<PersistentRequest>,
    frames: mpsc::UnboundedReceiver<PersistentFrameEvent>,
    carrier_closes: mpsc::UnboundedReceiver<usize>,
    writes: mpsc::UnboundedSender<PersistentWrite>,
    task: JoinHandle<()>,
}

impl PersistentBridgeServer {
    async fn next_request(&mut self) -> PersistentRequest {
        tokio::time::timeout(std::time::Duration::from_secs(3), self.requests.recv())
            .await
            .expect("timed out waiting for upstream mux request")
            .expect("persistent upstream closed before request")
    }

    async fn next_frame(&mut self) -> PersistentFrameEvent {
        tokio::time::timeout(std::time::Duration::from_secs(3), self.frames.recv())
            .await
            .expect("timed out waiting for upstream mux frame")
            .expect("persistent upstream closed before frame")
    }

    async fn next_carrier_close(&mut self) -> usize {
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            self.carrier_closes.recv(),
        )
        .await
        .expect("timed out waiting for upstream carrier close")
        .expect("persistent upstream stopped before carrier close")
    }

    async fn await_cumulative(&mut self, stream_id: u32, bytes: usize) -> PersistentFrameEvent {
        loop {
            let event = self.next_frame().await;
            if event.stream_id == stream_id && event.cumulative_data >= bytes {
                return event;
            }
        }
    }

    fn send_window(&self, stream_id: u32, bytes: u32) {
        self.send_frame(stream_id, FLAG_WINDOW, &bytes.to_be_bytes());
    }

    fn send_http(&self, stream_id: u32, status: &str, body: &[u8]) {
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            String::from_utf8_lossy(body)
        );
        self.send_frame(stream_id, FLAG_DATA | FLAG_CLOSE, response.as_bytes());
    }

    fn send_sse_head(&self, stream_id: u32) {
        self.send_stream_head(
            stream_id,
            "200 OK",
            &[("Content-Type", "text/event-stream")],
        );
    }

    fn send_stream_head(&self, stream_id: u32, status: &str, headers: &[(&str, &str)]) {
        let mut response = format!("HTTP/1.1 {status}\r\n");
        for (name, value) in headers {
            response.push_str(name);
            response.push_str(": ");
            response.push_str(value);
            response.push_str("\r\n");
        }
        response.push_str("\r\n");
        self.send_frame(stream_id, FLAG_DATA, response.as_bytes());
    }

    fn send_body(&self, stream_id: u32, body: &[u8]) {
        self.send_frame(stream_id, FLAG_DATA, body);
    }

    fn close_stream(&self, stream_id: u32) {
        self.send_frame(stream_id, FLAG_CLOSE, b"");
    }

    fn reset_stream(&self, stream_id: u32) {
        self.send_frame(stream_id, FLAG_RESET, &[RESET_CANCEL]);
    }

    fn send_frame(&self, stream_id: u32, flags: u8, payload: &[u8]) {
        let frame = Frame::new(stream_id, flags, payload.to_vec())
            .encode()
            .unwrap();
        self.writes.send(PersistentWrite::Frame(frame)).unwrap();
    }

    fn close_current_carrier(&self) {
        self.writes.send(PersistentWrite::CloseCarrier).unwrap();
    }

    fn accepted_carriers(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }

    fn abort(self) {
        self.task.abort();
    }
}

async fn start_bridge_with_persistent_server()
-> (journal_bridge::JournalBridgeHandle, PersistentBridgeServer) {
    start_bridge_with_persistent_server_policy(BridgePolicy::default()).await
}

async fn handle_persistent_carrier(
    tls: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    carrier_index: usize,
    request_tx: &mpsc::Sender<PersistentRequest>,
    frame_tx: &mpsc::UnboundedSender<PersistentFrameEvent>,
    write_rx: &mut mpsc::UnboundedReceiver<PersistentWrite>,
) -> bool {
    let (mut read, mut write) = tokio::io::split(tls);
    let mut decoder = FrameDecoder::new();
    let mut requests: HashMap<u32, Vec<u8>> = HashMap::new();
    let mut cumulative_data: HashMap<u32, usize> = HashMap::new();
    let mut buf = [0u8; 4096];
    loop {
        tokio::select! {
            read_result = read.read(&mut buf) => {
                let Ok(n) = read_result else {
                    return true;
                };
                if n == 0 {
                    return true;
                }
                decoder.feed(&buf[..n]);
                for frame in decoder.drain().unwrap() {
                    let cumulative = if frame.flags & FLAG_DATA != 0 {
                        let total = cumulative_data.entry(frame.stream_id).or_default();
                        *total += frame.payload.len();
                        *total
                    } else {
                        cumulative_data
                            .get(&frame.stream_id)
                            .copied()
                            .unwrap_or_default()
                    };
                    frame_tx
                        .send(PersistentFrameEvent {
                            carrier_index,
                            stream_id: frame.stream_id,
                            flags: frame.flags,
                            payload_len: frame.payload.len(),
                            cumulative_data: cumulative,
                        })
                        .unwrap();
                    if let Some(pong) = frame.control_pong() {
                        let bytes = pong.encode().unwrap();
                        write.write_all(&bytes).await.unwrap();
                        write.flush().await.unwrap();
                        continue;
                    }
                    if frame.flags & FLAG_DATA != 0 {
                        requests
                            .entry(frame.stream_id)
                            .or_default()
                            .extend_from_slice(&frame.payload);
                    }
                    if frame.flags & FLAG_CLOSE != 0 {
                        let bytes = requests.remove(&frame.stream_id).unwrap_or_default();
                        cumulative_data.remove(&frame.stream_id);
                        request_tx
                            .send(PersistentRequest {
                                carrier_index,
                                stream_id: frame.stream_id,
                                bytes,
                            })
                            .await
                            .unwrap();
                    }
                }
            }
            write_command = write_rx.recv() => {
                match write_command {
                    Some(PersistentWrite::Frame(bytes)) => {
                        if write.write_all(&bytes).await.is_err()
                            || write.flush().await.is_err()
                        {
                            return true;
                        }
                    }
                    Some(PersistentWrite::CloseCarrier) => {
                        let _ = write.shutdown().await;
                        return true;
                    }
                    None => return false,
                }
            }
        }
    }
}

async fn start_bridge_with_persistent_server_policy(
    policy: BridgePolicy,
) -> (journal_bridge::JournalBridgeHandle, PersistentBridgeServer) {
    let (cert, key) = self_signed();
    let pin = spl_core::ca::sha256(cert.as_ref())[..16].to_vec();
    let acceptor = TlsAcceptor::from(Arc::new(server_config(cert, key)));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = listener.local_addr().unwrap().port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let (request_tx, request_rx) = mpsc::channel(16);
    let (frame_tx, frame_rx) = mpsc::unbounded_channel();
    let (carrier_close_tx, carrier_close_rx) = mpsc::unbounded_channel();
    let (write_tx, mut write_rx) = mpsc::unbounded_channel::<PersistentWrite>();
    let task = tokio::spawn({
        let accepts = accepts.clone();
        async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    break;
                };
                let carrier_index = accepts.fetch_add(1, Ordering::SeqCst) + 1;
                let tls = acceptor.accept(tcp).await.unwrap();
                let keep_serving = handle_persistent_carrier(
                    tls,
                    carrier_index,
                    &request_tx,
                    &frame_tx,
                    &mut write_rx,
                )
                .await;
                carrier_close_tx.send(carrier_index).unwrap();
                if !keep_serving {
                    return;
                }
            }
        }
    });
    let handle = start_bridge_with_policy(transport_credential(pin, upstream_port), policy).await;
    (
        handle,
        PersistentBridgeServer {
            accepts,
            requests: request_rx,
            frames: frame_rx,
            carrier_closes: carrier_close_rx,
            writes: write_tx,
            task,
        },
    )
}

async fn raw_bridge_request(
    port: u16,
    method: &str,
    target: &str,
    host: Option<String>,
    cookie: Option<String>,
    extra_headers: &[(&str, &str)],
    body: &[u8],
) -> Vec<u8> {
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    write_bridge_request(
        &mut stream,
        method,
        target,
        host,
        cookie,
        extra_headers,
        body,
    )
    .await;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    response
}

async fn raw_bridge_bytes(port: u16, request: &[u8]) -> Vec<u8> {
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    stream.write_all(request).await.unwrap();
    stream.flush().await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    response
}

// The coordinator latches before fanout closes the response stream, so reading this first 502
// establishes that the terminal reason is already observable. Restoring generic read-error
// conversion leaves no terminal reason and lets the second request reach this listener. This peer
// uses real rustls TLS 1.3 client-auth rejection.
#[tokio::test]
async fn journal_bridge_latches_real_received_access_denied() {
    let (cert, key) = self_signed();
    let pin = spl_core::ca::sha256(cert.as_ref())[..16].to_vec();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (second_accept_tx, mut second_accept_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let acceptor = TlsAcceptor::from(Arc::new(rejecting_server_config(cert, key)));
        let (first, _) = listener.accept().await.unwrap();
        assert!(acceptor.accept(first).await.is_err());
        let (second, _) = listener.accept().await.unwrap();
        drop(second);
        let _ = second_accept_tx.send(());
    });
    let handle = start_bridge(transport_credential(pin, port)).await;
    let capability = capability_from(&handle);
    let cookie = Some(format!("{TEST_CAP_COOKIE_NAME}={capability}"));
    let host = Some(loopback_host(handle.port()));

    let first = raw_bridge_request(
        handle.port(),
        "GET",
        "/healthz",
        host.clone(),
        cookie.clone(),
        &[],
        b"",
    )
    .await;
    assert_eq!(response_status(&first), 502);
    assert_eq!(
        handle.status().terminal_reason,
        Some(journal_bridge::JournalBridgeTerminalReason::TlsAccessDenied)
    );

    let second = raw_bridge_request(handle.port(), "GET", "/healthz", host, cookie, &[], b"").await;
    assert_eq!(response_status(&second), 502);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut second_accept_rx)
            .await
            .is_err()
    );
    handle.shutdown_and_wait().await;
    server.abort();
}

// Protocol: `.proto-ref/session.md` § 7. The journal refuses after the client's TLS 1.3
// handshake completes. Falsified by leaving post-dial reads unclassified: every class records
// the journal as unreachable, so neither the unpaired stop nor the catch-all can fire.
#[tokio::test]
async fn journal_bridge_records_each_real_post_handshake_refusal() {
    for (error, expected, _) in refusal_classes() {
        let (cert, key) = self_signed();
        let pin = spl_core::ca::sha256(cert.as_ref())[..16].to_vec();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let acceptor = TlsAcceptor::from(Arc::new(refusing_server_config(cert, key, error)));
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let _ = acceptor.accept(stream).await;
            }
        });
        let handle = start_bridge(transport_credential(pin, port)).await;
        let capability = capability_from(&handle);
        let cookie = Some(format!("{TEST_CAP_COOKIE_NAME}={capability}"));
        let host = Some(loopback_host(handle.port()));

        let response =
            raw_bridge_request(handle.port(), "GET", "/healthz", host, cookie, &[], b"").await;
        assert_eq!(response_status(&response), 502, "{expected:?}");
        let status = handle.status();
        assert_eq!(status.last_failure, expected);
        let (refusals, terminal) = match expected {
            Some(journal_bridge::JournalBridgeFailure::TlsAccessDenied) => (
                0,
                Some(journal_bridge::JournalBridgeTerminalReason::TlsAccessDenied),
            ),
            Some(journal_bridge::JournalBridgeFailure::TlsRefused) => (1, None),
            _ => (0, None),
        };
        assert_eq!(status.refusals, refusals, "{expected:?}");
        assert_eq!(status.terminal_reason, terminal, "{expected:?}");
        handle.shutdown_and_wait().await;
        server.abort();
    }
}

// Protocol: `.proto-ref/session.md` § 7. Every endpoint and the relay reach the same journal, so a
// refusal over the direct path is the answer. Falsified by trying another endpoint or the relay
// after a direct refusal: their own failure is returned, so the refusal never counts.
#[tokio::test]
#[expect(
    clippy::large_futures,
    reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
)]
async fn transport_client_request_returns_a_direct_refusal_without_trying_the_relay() {
    let (cert, key) = self_signed();
    let pin = spl_core::ca::sha256(cert.as_ref())[..16].to_vec();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let acceptor = TlsAcceptor::from(Arc::new(refusing_server_config(
            cert,
            key,
            CertificateError::UnknownIssuer,
        )));
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = acceptor.accept(stream).await;
        }
    });
    let relay = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_origin = format!("http://{}", relay.local_addr().unwrap());
    let relay_dials = Arc::new(AtomicUsize::new(0));
    let counted = relay_dials.clone();
    let relay_task = tokio::spawn(async move {
        loop {
            let (stream, _) = relay.accept().await.unwrap();
            counted.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });
    let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second_port = second.local_addr().unwrap().port();
    let second_dials = Arc::new(AtomicUsize::new(0));
    let second_counted = second_dials.clone();
    let second_task = tokio::spawn(async move {
        loop {
            let (stream, _) = second.accept().await.unwrap();
            second_counted.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });
    let mut credential = transport_credential(pin, port);
    credential.endpoints.push(EndpointAddr {
        host: "127.0.0.1".into(),
        port: second_port,
    });
    credential.relay_origin = Some(relay_origin);
    credential.device_token = Some("relay-token".into());
    let client = TransportClient::new(credential, None).unwrap();

    for (replay, replay_unsafe) in [
        (spl_transport::ReplayPolicy::ForbidAfterWrite, true),
        (spl_transport::ReplayPolicy::ReplaySafe, false),
    ] {
        let options = spl_transport::RequestOptions {
            replay,
            ..spl_transport::RequestOptions::default()
        };
        let err = client
            .request("GET", "/healthz", &[], b"", options)
            .await
            .unwrap_err();
        // The refusal proves nothing about whether the request was read, so a request that must
        // not be replayed says so.
        assert!(
            match &err {
                spl_transport::RequestError::ReplayUnsafe(TransportError::TlsRefused) => {
                    replay_unsafe
                }
                spl_transport::RequestError::Transport(TransportError::TlsRefused) => {
                    !replay_unsafe
                }
                _ => false,
            },
            "{replay:?}: {err:?}"
        );
    }
    assert_eq!(second_dials.load(Ordering::SeqCst), 0);
    assert_eq!(relay_dials.load(Ordering::SeqCst), 0);
    server.abort();
    second_task.abort();
    relay_task.abort();
}

// A peer at the saved address that is not the paired journal is neither a refusal nor a stop.
// Falsified by classifying an unknown journal as a refusal: the count advances.
#[tokio::test]
async fn journal_bridge_records_an_unknown_journal_without_counting_it() {
    let (paired, _) = self_signed();
    let pin = spl_core::ca::sha256(paired.as_ref())[..16].to_vec();
    let (cert, key) = self_signed();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let acceptor = TlsAcceptor::from(Arc::new(server_config(cert, key)));
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = acceptor.accept(stream).await;
        }
    });
    let handle = start_bridge(transport_credential(pin, port)).await;
    let capability = capability_from(&handle);
    let cookie = Some(format!("{TEST_CAP_COOKIE_NAME}={capability}"));
    let host = Some(loopback_host(handle.port()));

    let response =
        raw_bridge_request(handle.port(), "GET", "/healthz", host, cookie, &[], b"").await;
    assert_eq!(response_status(&response), 502);
    let status = handle.status();
    assert_eq!(
        status.last_failure,
        Some(journal_bridge::JournalBridgeFailure::UnknownJournal)
    );
    assert_eq!(status.refusals, 0);
    assert_eq!(status.terminal_reason, None);
    handle.shutdown_and_wait().await;
    server.abort();
}

// Falsified by leaving post-dial request errors as plain I/O: a consumer that makes its own
// requests cannot tell a refusal from an outage.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[expect(
    clippy::large_futures,
    reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
)]
async fn transport_client_request_names_real_post_handshake_refusals() {
    // A journal that refuses resets the connection, so an upload's write can fail before the
    // refusal is read. Falsified by dropping the verdict read: the bodies report plain I/O.
    for (error, expected, matches_expected) in refusal_classes()
        .into_iter()
        .flat_map(|class| [0, 4 * 1024, 64 * 1024, 900 * 1024].map(|len| (class.clone(), len)))
        .map(|((error, expected, matches_expected), len)| {
            ((error, len), expected, matches_expected)
        })
    {
        let (error, body_len) = error;
        let (cert, key) = self_signed();
        let pin = spl_core::ca::sha256(cert.as_ref())[..16].to_vec();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let acceptor = TlsAcceptor::from(Arc::new(refusing_server_config(cert, key, error)));
            let (stream, _) = listener.accept().await.unwrap();
            let _ = acceptor.accept(stream).await;
        });
        let client = TransportClient::new(transport_credential(pin, port), None).unwrap();
        let options = spl_transport::RequestOptions {
            response_cap: 1024 * 1024,
            replay: spl_transport::ReplayPolicy::ForbidAfterWrite,
            observer: None,
        };

        let body = vec![0x5a; body_len];
        let method = if body.is_empty() { "GET" } else { "POST" };
        let err = client
            .request(method, "/healthz", &[], &body, options)
            .await
            .unwrap_err();
        // Access denied and certificate unknown come before the journal reads anything, so they
        // are never a replay hazard. Any other refusal keeps the replay guarantee once written.
        let transport = match (&err, expected) {
            (
                spl_transport::RequestError::ReplayUnsafe(error),
                Some(journal_bridge::JournalBridgeFailure::TlsRefused),
            )
            | (
                spl_transport::RequestError::Transport(error),
                Some(
                    journal_bridge::JournalBridgeFailure::TlsAccessDenied
                    | journal_bridge::JournalBridgeFailure::TlsCertificateUnknown,
                ),
            ) => Some(error),
            _ => None,
        };
        assert!(
            transport.is_some_and(matches_expected),
            "{expected:?} with a {body_len}-byte body: {err:?}"
        );
        server.await.unwrap();
    }
}

async fn partial_body_bridge_request(
    port: u16,
    target: &str,
    content_type: &str,
    body: Arc<Vec<u8>>,
    write_sizes: &[usize],
) -> Vec<u8> {
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let head = format!(
        "POST {target} HTTP/1.1\r\nHost: {}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
        loopback_host(port),
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    let mut offset = 0usize;
    let mut size_index = 0usize;
    while offset < body.len() {
        let size = write_sizes[size_index % write_sizes.len()];
        let end = (offset + size).min(body.len());
        stream.write_all(&body[offset..end]).await.unwrap();
        stream.flush().await.unwrap();
        offset = end;
        size_index += 1;
        tokio::task::yield_now().await;
    }
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    response
}

async fn write_bridge_request(
    stream: &mut tokio::net::TcpStream,
    method: &str,
    target: &str,
    host: Option<String>,
    cookie: Option<String>,
    extra_headers: &[(&str, &str)],
    body: &[u8],
) {
    let mut request = format!("{method} {target} HTTP/1.1\r\n");
    if let Some(host) = host {
        request.push_str("Host: ");
        request.push_str(&host);
        request.push_str("\r\n");
    }
    if let Some(cookie) = cookie {
        request.push_str("Cookie: ");
        request.push_str(&cookie);
        request.push_str("\r\n");
    }
    for (name, value) in extra_headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    if !body.is_empty() {
        request.push_str("Content-Length: ");
        request.push_str(&body.len().to_string());
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    if !body.is_empty() {
        stream.write_all(body).await.unwrap();
    }
    stream.flush().await.unwrap();
}

struct PartialBridgeResponse {
    stream: tokio::net::TcpStream,
    received: Vec<u8>,
}

async fn partial_bridge_request(
    port: u16,
    method: &str,
    target: &str,
    host: Option<String>,
    body: &[u8],
    first_marker: &[u8],
) -> PartialBridgeResponse {
    const RESPONSE_BOUND: usize = 64 * 1024;

    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    write_bridge_request(&mut stream, method, target, host, None, &[], body).await;

    let mut received = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let head_arrived = received.windows(4).any(|window| window == b"\r\n\r\n");
            let marker_arrived = received
                .windows(first_marker.len())
                .any(|window| window == first_marker);
            if head_arrived && marker_arrived {
                break;
            }
            assert!(
                received.len() < RESPONSE_BOUND,
                "partial response exceeded read bound"
            );
            let mut buf = [0u8; 256];
            let remaining = RESPONSE_BOUND - received.len();
            let read_bound = remaining.min(buf.len());
            let read = stream.read(&mut buf[..read_bound]).await.unwrap();
            assert!(read > 0, "response closed before first streamed chunk");
            received.extend_from_slice(&buf[..read]);
        }
    })
    .await
    .expect("timed out waiting for first streamed response chunk");

    PartialBridgeResponse { stream, received }
}

fn loopback_host(port: u16) -> String {
    format!("127.0.0.1:{port}")
}

fn cap_cookie(cap: &str) -> String {
    format!("{TEST_CAP_COOKIE_NAME}={cap}")
}

fn response_text(response: &[u8]) -> String {
    String::from_utf8_lossy(response).into_owned()
}

fn response_status(response: &[u8]) -> u16 {
    response_text(response)
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

fn response_body(response: &[u8]) -> String {
    let text = response_text(response);
    text.split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap()
}

fn response_head(response: &[u8]) -> String {
    let text = response_text(response);
    text.split_once("\r\n\r\n")
        .map(|(head, _)| head.to_ascii_lowercase())
        .unwrap()
}

#[derive(Clone)]
struct CapturingSubscriber {
    lines: Arc<Mutex<Vec<String>>>,
}

impl tracing::Subscriber for CapturingSubscriber {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target() == "journal_bridge"
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        if !self.enabled(event.metadata()) {
            return;
        }
        let mut visitor = LogVisitor::default();
        event.record(&mut visitor);
        self.lines.lock().unwrap().push(visitor.line);
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

#[derive(Default)]
struct LogVisitor {
    line: String,
}

impl LogVisitor {
    fn field(&mut self, name: &str, value: impl std::fmt::Display) {
        if !self.line.is_empty() {
            self.line.push(' ');
        }
        self.line.push_str(name);
        self.line.push('=');
        self.line.push_str(&value.to_string());
    }
}

impl tracing::field::Visit for LogVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.field(field.name(), format!("{value:?}"));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.field(field.name(), value);
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.field(field.name(), value);
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.field(field.name(), value);
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.field(field.name(), value);
    }
}

#[tokio::test]
async fn round_trips_request_over_real_tls_and_framing() {
    let (cert, key) = self_signed();
    let pin = spl_core::ca::sha256(cert.as_ref())[..16].to_vec();
    let acceptor = TlsAcceptor::from(Arc::new(server_config(cert, key)));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(serve_one(listener, acceptor));

    let config = Arc::new(pairing_config(&pin).unwrap());
    let request_body = b"{\"csr\":\"PEM\",\"device_label\":\"win\"}";
    let response = request_once(
        config,
        "127.0.0.1",
        port,
        "POST",
        "/app/network/pair?token=abc123",
        &[("Content-Type".to_string(), "application/json".to_string())],
        request_body,
    )
    .await
    .expect("request should succeed against the pinned peer");

    assert_eq!(response.status, 200);
    assert_eq!(response.body_text(), "{\"status\":\"ok\"}");

    // The server received exactly the HTTP request our transport framed.
    let received = server.await.unwrap();
    let received_text = String::from_utf8_lossy(&received);
    assert!(received_text.starts_with("POST /app/network/pair?token=abc123 HTTP/1.1\r\n"));
    assert!(received_text.contains("host: spl.local\r\n"));
    assert!(received_text.contains("Content-Type: application/json\r\n"));
    assert!(received_text.ends_with("{\"csr\":\"PEM\",\"device_label\":\"win\"}"));
}

#[tokio::test]
async fn observer_contract_authority_direct_pairing_uses_real_crypto_and_request_path() {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    ca_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    let signing_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let signing_cert = ca_params.self_signed(&signing_key).unwrap();

    let (server_cert, server_key) = self_signed();
    let server_pin = spl_core::ca::sha256(server_cert.as_ref())[..16].to_vec();
    let acceptor = TlsAcceptor::from(Arc::new(server_config(server_cert, server_key)));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(serve_one_pair_response(
        listener,
        acceptor,
        signing_cert,
        signing_key,
        PairCertificateMode::SubmittedCsr,
    ));
    let nonce = PAIR_EXAMPLE_NONCE;
    let label = PAIR_EXAMPLE_DEVICE_LABEL;
    let endpoints = [spl_core::pairlink::Endpoint {
        host: "127.0.0.1".to_owned(),
        port,
    }];

    let credential = spl_transport::pairing::pair(
        &endpoints,
        nonce,
        &server_pin,
        label,
        &serde_json::Map::new(),
    )
    .await
    .unwrap();
    assert_eq!(credential.instance_id, PAIR_EXAMPLE_INSTANCE_ID);
    assert_eq!(credential.home_label, PAIR_EXAMPLE_HOME_LABEL);
    assert_eq!(
        credential.home_attestation.as_deref(),
        Some(PAIR_EXAMPLE_HOME_ATTESTATION)
    );
    assert_eq!(
        credential.local_endpoints,
        Some(serde_json::json!([{
            "ip": "192.168.1.10",
            "port": 7657,
            "scope": "lan",
        }]))
    );
    assert!(credential.client_cert_pem.contains("BEGIN CERTIFICATE"));
    let credential_key = KeyPair::from_pem(&credential.client_key_pem).unwrap();
    let credential_leaf = spl_transport::tls::parse_certs(&credential.client_cert_pem)
        .unwrap()
        .remove(0);
    assert_eq!(
        credential_key.public_key_der(),
        spl_core::ca::extract_spki_der(credential_leaf.as_ref()).unwrap()
    );
    let request = server.await.unwrap();
    assert!(pair_capture_matches(&request, nonce, label));
    let body_json = request_body(&request);
    let mut keys: Vec<String> = body_json.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(keys, vec!["csr".to_string(), "device_label".to_string()]);
    let mutated = String::from_utf8(request.clone()).unwrap().replacen(
        &format!("token={nonce}"),
        "token=wrong",
        1,
    );
    assert!(!pair_capture_matches(mutated.as_bytes(), nonce, label));
}

#[tokio::test]
async fn linked_system_pair_additional_fields_reach_direct_wire() {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    ca_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    let signing_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let signing_cert = ca_params.self_signed(&signing_key).unwrap();

    let (server_cert, server_key) = self_signed();
    let server_pin = spl_core::ca::sha256(server_cert.as_ref())[..16].to_vec();
    let acceptor = TlsAcceptor::from(Arc::new(server_config(server_cert, server_key)));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(serve_one_pair_response(
        listener,
        acceptor,
        signing_cert,
        signing_key,
        PairCertificateMode::SubmittedCsr,
    ));
    let endpoints = [Endpoint {
        host: "127.0.0.1".to_owned(),
        port,
    }];
    let device_label = "d".repeat(80);
    let mut additional_fields = serde_json::Map::new();
    additional_fields.insert(
        "sender_instance_id".into(),
        serde_json::json!("consumer-instance"),
    );

    spl_transport::pairing::pair(
        &endpoints,
        PAIR_EXAMPLE_NONCE,
        &server_pin,
        &device_label,
        &additional_fields,
    )
    .await
    .unwrap();

    let request = server.await.unwrap();
    let body = request_body(&request);
    assert_eq!(
        body["sender_instance_id"],
        serde_json::json!("consumer-instance")
    );
    assert_eq!(body["device_label"], device_label);
    assert!(
        body["csr"]
            .as_str()
            .is_some_and(|csr| csr.contains("BEGIN CERTIFICATE REQUEST"))
    );
}

#[tokio::test]
async fn linked_system_can_implement_public_direct_pairing_seam() {
    let endpoints = [Endpoint {
        host: "consumer-transport.invalid".into(),
        port: 7657,
    }];

    let credential = spl_transport::pairing::pair_with_seam(
        &endpoints,
        PAIR_EXAMPLE_NONCE,
        &[0x22; 16],
        PAIR_EXAMPLE_DEVICE_LABEL,
        Arc::new(ConsumerDirectPairingSeam),
        &serde_json::Map::new(),
    )
    .await
    .unwrap();

    assert_eq!(credential.instance_id, PAIR_EXAMPLE_INSTANCE_ID);
    assert!(credential.client_cert_pem.contains("BEGIN CERTIFICATE"));
}

#[tokio::test]
async fn direct_pairing_key_mismatch_is_terminal_after_first_written_request() {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    ca_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    let signing_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let signing_cert = ca_params.self_signed(&signing_key).unwrap();

    let (server_cert, server_key) = self_signed();
    let server_pin = spl_core::ca::sha256(server_cert.as_ref())[..16].to_vec();
    let acceptor = TlsAcceptor::from(Arc::new(server_config(server_cert, server_key)));
    let first_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let first_port = first_listener.local_addr().unwrap().port();
    let first_server = tokio::spawn(serve_one_pair_response(
        first_listener,
        acceptor,
        signing_cert,
        signing_key,
        PairCertificateMode::UnrelatedKey,
    ));

    let later_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let later_port = later_listener.local_addr().unwrap().port();
    let later_accepts = Arc::new(AtomicUsize::new(0));
    let later_server = tokio::spawn({
        let later_accepts = later_accepts.clone();
        async move {
            if let Ok(Ok((tcp, _))) = tokio::time::timeout(
                std::time::Duration::from_millis(250),
                later_listener.accept(),
            )
            .await
            {
                later_accepts.fetch_add(1, Ordering::SeqCst);
                drop(tcp);
            }
        }
    });
    let endpoints = [
        spl_core::pairlink::Endpoint {
            host: "127.0.0.1".into(),
            port: first_port,
        },
        spl_core::pairlink::Endpoint {
            host: "127.0.0.1".into(),
            port: later_port,
        },
    ];

    let error = spl_transport::pairing::pair(
        &endpoints,
        "00112233445566778899aabbccddeeff",
        &server_pin,
        "win-test",
        &serde_json::Map::new(),
    )
    .await
    .unwrap_err();

    assert!(matches!(
        error,
        TransportError::Pairing(message)
            if message == "client certificate public key does not match generated key"
    ));
    let request = first_server.await.unwrap();
    assert!(
        String::from_utf8_lossy(&request)
            .starts_with("POST /app/network/pair?token=00112233445566778899aabbccddeeff HTTP/1.1")
    );
    later_server.await.unwrap();
    assert_eq!(later_accepts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
#[expect(
    clippy::uninlined_format_args,
    reason = "the copied cookie assertion keeps its format arguments aligned with the exact expected header bytes"
)]
async fn journal_bridge_bootstrap_sets_cookie_and_rejects_wrong_cap() {
    let (handle, _accepts, upstream) = start_bridge_with_counting_upstream().await;
    let port = handle.port();
    let cap = capability_from(&handle);

    let ok = raw_bridge_request(
        port,
        "GET",
        &format!("{}?cap={cap}", spl_core::bridge::BOOTSTRAP_ROUTE),
        Some(loopback_host(port)),
        None,
        &[],
        b"",
    )
    .await;
    let ok_text = response_text(&ok);
    assert_eq!(response_status(&ok), 302);
    assert!(ok_text.contains(&format!(
        "Set-Cookie: {}={cap}; Path=/; HttpOnly; SameSite=Strict",
        TEST_CAP_COOKIE_NAME
    )));
    assert!(ok_text.contains("Location: /\r\n"));

    let bad = raw_bridge_request(
        port,
        "GET",
        &format!("{}?cap=wrong", spl_core::bridge::BOOTSTRAP_ROUTE),
        Some(loopback_host(port)),
        None,
        &[],
        b"",
    )
    .await;
    assert_eq!(response_status(&bad), 403);
    assert!(!response_text(&bad).contains("Set-Cookie:"));

    let wrong_method = raw_bridge_request(
        port,
        "POST",
        &format!("{}?cap={cap}", spl_core::bridge::BOOTSTRAP_ROUTE),
        Some(loopback_host(port)),
        None,
        &[],
        b"",
    )
    .await;
    assert_eq!(response_status(&wrong_method), 405);
    assert!(!response_text(&wrong_method).contains("Set-Cookie:"));

    // An Authorization header is the caller's own business; the bootstrap
    // still answers on the capability alone.
    let with_authorization = raw_bridge_request(
        port,
        "GET",
        &format!("{}?cap={cap}", spl_core::bridge::BOOTSTRAP_ROUTE),
        Some(loopback_host(port)),
        None,
        &[("Authorization", "Bearer caller")],
        b"",
    )
    .await;
    assert_eq!(response_status(&with_authorization), 302);
    assert!(response_text(&with_authorization).contains("Set-Cookie:"));

    handle.shutdown_and_wait().await;
    upstream.abort();
}

#[tokio::test]
async fn journal_bridge_authority_rejects_before_upstream() {
    let (handle, accepts, upstream) = start_bridge_with_counting_upstream().await;
    let port = handle.port();
    let cap = capability_from(&handle);

    let cases = [
        (
            "GET",
            "/journal",
            Some(loopback_host(port)),
            None,
            vec![],
            403,
        ),
        (
            "GET",
            "/journal",
            Some(loopback_host(port)),
            Some(cap_cookie("wrong")),
            vec![],
            403,
        ),
        (
            "GET",
            "/journal",
            Some(loopback_host(port + 1)),
            Some(cap_cookie(&cap)),
            vec![],
            403,
        ),
    ];

    for (method, target, host, cookie, headers, expected) in cases {
        let response = raw_bridge_request(port, method, target, host, cookie, &headers, b"").await;
        assert_eq!(response_status(&response), expected);
    }

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(accepts.load(Ordering::SeqCst), 0);
    handle.shutdown_and_wait().await;
    upstream.abort();
}

#[tokio::test]
async fn journal_bridge_forwards_any_method_and_header_once_the_capability_matches() {
    // The capability is the whole boundary: a caller holding it is the
    // consumer's own code, so the bridge forwards what it sends and lets the
    // journal decide. Reserved headers are still stripped, never refused.
    let (handle, mut server) =
        start_bridge_with_persistent_server_policy(BridgePolicy::default()).await;
    let port = handle.port();
    let cap = capability_from(&handle);
    for method in ["PUT", "DELETE", "PATCH", "OPTIONS"] {
        let cookie = cap_cookie(&cap);
        let host = loopback_host(port);
        let response = tokio::spawn(async move {
            raw_bridge_request(
                port,
                method,
                "/objects/7",
                Some(host),
                Some(cookie),
                &[
                    ("X-Custom", "kept"),
                    ("If-Match", "\"v1\""),
                    ("Authorization", "Bearer caller"),
                ],
                b"body",
            )
            .await
        });

        let request = server.next_request().await;
        let request_text = String::from_utf8_lossy(&request.bytes).to_lowercase();
        assert!(
            request_text.starts_with(&format!(
                "{} /objects/7 http/1.1\r\n",
                method.to_lowercase()
            )),
            "{method}: {request_text}"
        );
        assert!(request_text.contains("x-custom: kept\r\n"), "{method}");
        assert!(request_text.contains("if-match: \"v1\"\r\n"), "{method}");
        assert!(!request_text.contains("bearer caller"), "{method}");
        server.send_http(request.stream_id, "200 OK", b"done");

        let response = response.await.unwrap();
        assert_eq!(response_status(&response), 200, "{method}");
    }
    handle.shutdown_and_wait().await;
    server.abort();
}

#[tokio::test]
async fn journal_bridge_disabled_gate_forwards_without_cookie_and_allows_put() {
    let policy = BridgePolicy {
        capability_gate: CapabilityGate::Disabled,
        ..BridgePolicy::default()
    };
    let (handle, mut server) = start_bridge_with_persistent_server_policy(policy).await;
    assert_eq!(handle.bootstrap_url(), None);
    let port = handle.port();
    let response = tokio::spawn(raw_bridge_request(
        port,
        "PUT",
        "/objects/7",
        Some(loopback_host(port)),
        None,
        &[],
        b"replacement",
    ));

    let request = server.next_request().await;
    let request_text = String::from_utf8_lossy(&request.bytes);
    assert!(request_text.starts_with("PUT /objects/7 HTTP/1.1\r\n"));
    assert!(request_text.ends_with("\r\n\r\nreplacement"));
    server.send_http(request.stream_id, "200 OK", b"updated");

    let response = response.await.unwrap();
    assert_eq!(response_status(&response), 200);
    assert_eq!(response_body(&response), "updated");
    handle.shutdown_and_wait().await;
    server.abort();
}

#[tokio::test]
async fn journal_bridge_disabled_gate_forwards_bootstrap_path_upstream() {
    let policy = BridgePolicy {
        capability_gate: CapabilityGate::Disabled,
        ..BridgePolicy::default()
    };
    let (handle, mut server) = start_bridge_with_persistent_server_policy(policy).await;
    let port = handle.port();
    let target = format!("{}?cap=unused", spl_core::bridge::BOOTSTRAP_ROUTE);
    let host = loopback_host(port);
    let response = tokio::spawn(async move {
        raw_bridge_request(port, "GET", &target, Some(host), None, &[], b"").await
    });

    let request = server.next_request().await;
    assert!(
        String::from_utf8_lossy(&request.bytes).starts_with(&format!(
            "GET {}?cap=unused HTTP/1.1\r\n",
            spl_core::bridge::BOOTSTRAP_ROUTE
        ))
    );
    server.send_http(request.stream_id, "404 Not Found", b"upstream route");

    let response = response.await.unwrap();
    assert_eq!(response_status(&response), 404);
    assert_eq!(response_body(&response), "upstream route");
    handle.shutdown_and_wait().await;
    server.abort();
}

#[tokio::test]
async fn journal_bridge_disabled_gate_still_rejects_wrong_host() {
    let policy = BridgePolicy {
        capability_gate: CapabilityGate::Disabled,
        ..BridgePolicy::default()
    };
    let (handle, server) = start_bridge_with_persistent_server_policy(policy).await;
    let port = handle.port();

    let response = raw_bridge_request(
        port,
        "DELETE",
        "/objects/7",
        Some(loopback_host(port ^ 1)),
        None,
        &[],
        b"",
    )
    .await;

    assert_eq!(response_status(&response), 403);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(server.accepted_carriers(), 0);
    handle.shutdown_and_wait().await;
    server.abort();
}

#[tokio::test]
async fn journal_bridge_custom_request_body_bound_rejects_oversize_body() {
    const BODY_BOUND: usize = 3;
    const AT_BOUND_BODY: &[u8; BODY_BOUND] = b"fit";

    let policy = BridgePolicy {
        capability_gate: CapabilityGate::Disabled,
        max_request_body_bytes: BODY_BOUND,
        ..BridgePolicy::default()
    };
    let (handle, mut server) = start_bridge_with_persistent_server_policy(policy).await;
    let port = handle.port();

    let oversize_response = raw_bridge_request(
        port,
        "POST",
        "/objects",
        Some(loopback_host(port)),
        None,
        &[],
        b"four",
    )
    .await;

    assert_eq!(response_status(&oversize_response), 413);
    assert!(response_text(&oversize_response).starts_with("HTTP/1.1 413 Payload Too Large\r\n"));
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(server.accepted_carriers(), 0);

    let accepted_response = tokio::spawn(raw_bridge_request(
        port,
        "POST",
        "/objects",
        Some(loopback_host(port)),
        None,
        &[],
        AT_BOUND_BODY,
    ));
    let request = server.next_request().await;
    assert!(String::from_utf8_lossy(&request.bytes).ends_with("\r\n\r\nfit"));
    server.send_http(request.stream_id, "200 OK", b"accepted");

    let accepted_response = accepted_response.await.unwrap();
    assert_eq!(response_status(&accepted_response), 200);
    assert_eq!(response_body(&accepted_response), "accepted");
    handle.shutdown_and_wait().await;
    server.abort();
}

#[tokio::test]
async fn journal_bridge_rejects_invalid_request_framing_before_dial() {
    // Protocol: `.proto-ref/framing.md`, "stream lifecycle" — a stream exists
    // only after an OPEN frame, so locally rejected input must not reach one.
    let policy = BridgePolicy {
        capability_gate: CapabilityGate::Disabled,
        ..BridgePolicy::default()
    };
    let (handle, server) = start_bridge_with_persistent_server_policy(policy).await;
    let port = handle.port();
    let host = loopback_host(port);
    let cases = [
        (
            "matching duplicate content length",
            format!(
                "POST /objects HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\ncontent-length: 0\r\n\r\n"
            ),
        ),
        (
            "disagreeing duplicate content length",
            format!(
                "POST /objects HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\nContent-Length: 1\r\n\r\n"
            ),
        ),
        (
            "transfer encoding",
            format!("POST /objects HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\n\r\n"),
        ),
        (
            "invalid content length",
            format!("POST /objects HTTP/1.1\r\nHost: {host}\r\nContent-Length: +1\r\n\r\n"),
        ),
    ];

    for (label, request) in cases {
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            raw_bridge_bytes(port, request.as_bytes()),
        )
        .await
        .expect(label);
        assert_eq!(response_status(&response), 400, "{label}");
        assert_eq!(server.accepted_carriers(), 0, "{label}");
    }

    handle.shutdown_and_wait().await;
    server.abort();
}

#[tokio::test]
async fn journal_bridge_rejects_head_past_limit_before_dial() {
    // Protocol: `.proto-ref/framing.md`, "stream lifecycle" — local HTTP
    // validation precedes the first OPEN frame.
    let policy = BridgePolicy {
        capability_gate: CapabilityGate::Disabled,
        ..BridgePolicy::default()
    };
    let (handle, server) = start_bridge_with_persistent_server_policy(policy).await;
    let port = handle.port();
    let prefix = format!(
        "GET /objects HTTP/1.1\r\nHost: {}\r\nX-Pad: ",
        loopback_host(port)
    );
    let suffix = "\r\n\r\n";
    let padding_len = spl_core::bridge::MAX_REQUEST_HEAD_BYTES + 1 - prefix.len() - suffix.len();
    let request = format!("{prefix}{}{suffix}", "a".repeat(padding_len));
    assert_eq!(request.len(), spl_core::bridge::MAX_REQUEST_HEAD_BYTES + 1);

    let response = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        raw_bridge_bytes(port, request.as_bytes()),
    )
    .await
    .expect("oversized head did not receive a prompt local rejection");
    assert_eq!(response_status(&response), 400);
    assert_eq!(server.accepted_carriers(), 0);

    handle.shutdown_and_wait().await;
    server.abort();
}

#[tokio::test]
async fn journal_bridge_accepts_head_ending_at_limit() {
    // Protocol: `.proto-ref/framing.md`, "stream lifecycle" — accepted local
    // input reaches one OPEN stream, while the companion test pins rejection
    // one byte later.
    let policy = BridgePolicy {
        capability_gate: CapabilityGate::Disabled,
        ..BridgePolicy::default()
    };
    let (handle, mut server) = start_bridge_with_persistent_server_policy(policy).await;
    let port = handle.port();
    let prefix = format!(
        "GET /objects HTTP/1.1\r\nHost: {}\r\nX-Pad: ",
        loopback_host(port)
    );
    let suffix = "\r\n\r\n";
    let padding_len = spl_core::bridge::MAX_REQUEST_HEAD_BYTES - prefix.len() - suffix.len();
    let request = format!("{prefix}{}{suffix}", "a".repeat(padding_len));
    assert_eq!(request.len(), spl_core::bridge::MAX_REQUEST_HEAD_BYTES);

    let response = tokio::spawn(async move { raw_bridge_bytes(port, request.as_bytes()).await });
    let forwarded = server.next_request().await;
    server.send_http(forwarded.stream_id, "200 OK", b"accepted");
    let response = response.await.unwrap();

    assert_eq!(response_status(&response), 200);
    assert_eq!(server.accepted_carriers(), 1);

    handle.shutdown_and_wait().await;
    server.abort();
}

#[tokio::test]
async fn journal_bridge_rejects_expect_without_waiting_for_body_or_dialing() {
    // Protocol: `.proto-ref/framing.md`, "stream lifecycle" — rejection before
    // OPEN means no carrier stream is allocated.
    let policy = BridgePolicy {
        capability_gate: CapabilityGate::Disabled,
        ..BridgePolicy::default()
    };
    let (handle, server) = start_bridge_with_persistent_server_policy(policy).await;
    let port = handle.port();
    let request = format!(
        "POST /objects HTTP/1.1\r\nHost: {}\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n",
        loopback_host(port)
    );

    let response = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        raw_bridge_bytes(port, request.as_bytes()),
    )
    .await
    .expect("417 response must arrive before the client sends a body");
    assert_eq!(response_status(&response), 417);
    assert!(response_text(&response).starts_with("HTTP/1.1 417 Expectation Failed\r\n"));
    assert_eq!(server.accepted_carriers(), 0);

    handle.shutdown_and_wait().await;
    server.abort();
}

#[tokio::test]
async fn journal_bridge_forward_all_forwards_custom_and_strips_reserved_headers() {
    let policy = BridgePolicy {
        capability_gate: CapabilityGate::Disabled,
        ..BridgePolicy::default()
    };
    let (handle, mut server) = start_bridge_with_persistent_server_policy(policy).await;
    let port = handle.port();
    let response = tokio::spawn(raw_bridge_request(
        port,
        "PATCH",
        "/objects/7",
        Some(loopback_host(port)),
        None,
        &[
            ("X-Custom-Request", "forward me"),
            ("Authorization", "Bearer caller"),
            (TEST_OBSERVER_HEADER_NAME, "caller"),
            (TEST_PROTOCOL_HEADER_NAME, "caller"),
            ("Connection", "keep-alive"),
        ],
        b"patch",
    ));

    let request = server.next_request().await;
    let request_text = String::from_utf8_lossy(&request.bytes).to_ascii_lowercase();
    assert!(request_text.contains("x-custom-request: forward me\r\n"));
    assert_eq!(request_text.matches("authorization:").count(), 1);
    assert_eq!(
        request_text
            .matches(&format!("{TEST_OBSERVER_HEADER_NAME}:"))
            .count(),
        1
    );
    assert_eq!(
        request_text
            .matches(&format!("{TEST_PROTOCOL_HEADER_NAME}:"))
            .count(),
        1
    );
    assert_eq!(request_text.matches("host:").count(), 1);
    assert!(request_text.contains("host: spl.local\r\n"));
    assert_eq!(request_text.matches("content-length:").count(), 1);
    assert!(!request_text.contains("connection:"));
    server.send_http(request.stream_id, "204 No Content", b"");

    let response = response.await.unwrap();
    assert_eq!(response_status(&response), 204);
    handle.shutdown_and_wait().await;
    server.abort();
}

#[tokio::test]
async fn journal_bridge_attribution_uses_unfiltered_request() {
    let policy = BridgePolicy {
        capability_gate: CapabilityGate::Disabled,
        attribution_headers: Arc::new(|head| {
            let saw_context = head.headers.iter().any(|(name, value)| {
                name.eq_ignore_ascii_case("x-caller-context") && value == "present"
            });
            if saw_context {
                vec![("X-Upstream-Attribution".into(), "derived".into())]
            } else {
                Vec::new()
            }
        }),
        ..BridgePolicy::default()
    };
    let (handle, mut server) = start_bridge_with_persistent_server_policy(policy).await;
    let port = handle.port();
    let response = tokio::spawn(raw_bridge_request(
        port,
        "GET",
        "/journal",
        Some(loopback_host(port)),
        None,
        &[("X-Caller-Context", "present")],
        b"",
    ));

    let request = server.next_request().await;
    let request_text = String::from_utf8_lossy(&request.bytes).to_ascii_lowercase();
    assert!(request_text.contains("x-upstream-attribution: derived\r\n"));
    // The caller's own header is forwarded as sent; attribution is added beside it.
    assert!(request_text.contains("x-caller-context: present\r\n"));
    server.send_http(request.stream_id, "200 OK", b"attributed");

    let response = response.await.unwrap();
    assert_eq!(response_status(&response), 200);
    handle.shutdown_and_wait().await;
    server.abort();
}

#[tokio::test]
async fn journal_bridge_attribution_drops_spoofed_reserved_headers_and_cookies() {
    let policy = BridgePolicy {
        capability_gate: CapabilityGate::Disabled,
        attribution_headers: Arc::new(|_| {
            vec![
                ("X-Upstream-Attribution".into(), "derived".into()),
                ("Authorization".into(), "Bearer hook".into()),
                (TEST_OBSERVER_HEADER_NAME.into(), "hook".into()),
                (TEST_PROTOCOL_HEADER_NAME.into(), "hook".into()),
                ("Host".into(), "hook.invalid".into()),
                ("Connection".into(), "upgrade".into()),
                (
                    "Cookie".into(),
                    format!("{TEST_CAP_COOKIE_NAME}=hook-capability"),
                ),
                (
                    "X-Upstream-Attribution".into(),
                    "ok\r\nAuthorization: Bearer forged".into(),
                ),
                (
                    "X-Linefeed-Attribution".into(),
                    "ok\nX-Injected: yes".into(),
                ),
                ("X-Nul-Attribution".into(), "ok\0hidden".into()),
                ("Bad Name".into(), "v".into()),
                ("Bad\u{7f}Name".into(), "v".into()),
                ("Bäd-Name".into(), "v".into()),
            ]
        }),
        ..BridgePolicy::default()
    };
    let (handle, mut server) = start_bridge_with_persistent_server_policy(policy).await;
    let port = handle.port();
    let response = tokio::spawn(raw_bridge_request(
        port,
        "GET",
        "/journal",
        Some(loopback_host(port)),
        None,
        &[
            ("X-Upstream-Attribution", "forged"),
            ("Authorization", "Bearer caller"),
            (TEST_OBSERVER_HEADER_NAME, "caller"),
            (TEST_PROTOCOL_HEADER_NAME, "caller"),
            ("Connection", "keep-alive"),
            ("Cookie", "test-journal-cap=caller-capability"),
        ],
        b"",
    ));

    let request = server.next_request().await;
    let request_text = String::from_utf8_lossy(&request.bytes).to_ascii_lowercase();
    assert!(request_text.contains("x-upstream-attribution: derived\r\n"));
    assert!(!request_text.contains("x-upstream-attribution: forged\r\n"));
    assert_eq!(request_text.matches("authorization:").count(), 1);
    assert!(request_text.contains("authorization: bearer test-handle\r\n"));
    assert_eq!(
        request_text
            .matches(&format!("{TEST_OBSERVER_HEADER_NAME}:"))
            .count(),
        1
    );
    assert!(request_text.contains(&format!(
        "{TEST_OBSERVER_HEADER_NAME}: {TEST_OBSERVER_KEY}\r\n"
    )));
    assert_eq!(
        request_text
            .matches(&format!("{TEST_PROTOCOL_HEADER_NAME}:"))
            .count(),
        1
    );
    assert!(request_text.contains(&format!("{TEST_PROTOCOL_HEADER_NAME}: 2\r\n")));
    assert_eq!(request_text.matches("host:").count(), 1);
    assert!(request_text.contains("host: spl.local\r\n"));
    assert!(!request_text.contains("connection:"));
    assert!(!request_text.contains("cookie:"));
    assert!(!request_text.contains("hook-capability"));
    assert!(!request_text.contains("caller-capability"));
    assert!(!request_text.contains("x-injected:"));
    assert!(!request_text.contains("forged"));
    assert!(!request_text.contains("x-linefeed-attribution:"));
    assert!(!request_text.contains("x-nul-attribution:"));
    assert!(!request_text.contains("bad name:"));
    assert!(!request_text.contains("bad\u{7f}name:"));
    assert!(!request_text.contains("bäd-name:"));
    server.send_http(request.stream_id, "200 OK", b"safe");

    let response = response.await.unwrap();
    assert_eq!(response_status(&response), 200);
    handle.shutdown_and_wait().await;
    server.abort();
}

#[tokio::test]
async fn journal_bridge_default_policy_preserves_current_forwarding() {
    let (handle, mut server) =
        start_bridge_with_persistent_server_policy(BridgePolicy::default()).await;
    let port = handle.port();
    let capability = capability_from(&handle);
    let response = tokio::spawn(raw_bridge_request(
        port,
        "GET",
        "/ordinary",
        Some(loopback_host(port)),
        Some(cap_cookie(&capability)),
        &[("Accept", "text/plain"), ("X-Caller-Header", "caller")],
        b"",
    ));

    let request = server.next_request().await;
    assert_eq!(
        String::from_utf8_lossy(&request.bytes),
        concat!(
            "GET /ordinary HTTP/1.1\r\n",
            "host: spl.local\r\n",
            "accept: text/plain\r\n",
            "x-caller-header: caller\r\n",
            "x-test-observer: test-handle\r\n",
            "Authorization: Bearer test-handle\r\n",
            "x-test-protocol: 2\r\n",
            "content-length: 0\r\n",
            "\r\n",
        )
    );
    server.send_http(request.stream_id, "200 OK", b"unchanged");

    let response = response.await.unwrap();
    assert_eq!(response_status(&response), 200);
    assert_eq!(response_body(&response), "unchanged");
    handle.shutdown_and_wait().await;
    server.abort();
}

#[tokio::test]
async fn journal_bridge_status_tracks_current_carrier() {
    let (handle, mut server) = start_bridge_with_persistent_server().await;
    assert!(!handle.status().carrier_live);
    let port = handle.port();
    let capability = capability_from(&handle);

    let first = tokio::spawn(raw_bridge_request(
        port,
        "GET",
        "/first",
        Some(loopback_host(port)),
        Some(cap_cookie(&capability)),
        &[],
        b"",
    ));
    let first_request = server.next_request().await;
    assert!(handle.status().carrier_live);
    server.send_http(first_request.stream_id, "200 OK", b"first");
    assert_eq!(response_status(&first.await.unwrap()), 200);

    server.close_current_carrier();
    for _ in 0..200 {
        if !handle.status().carrier_live {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(!handle.status().carrier_live);

    let second = tokio::spawn(raw_bridge_request(
        port,
        "GET",
        "/second",
        Some(loopback_host(port)),
        Some(cap_cookie(&capability)),
        &[],
        b"",
    ));
    let second_request = server.next_request().await;
    assert!(handle.status().carrier_live);
    assert_eq!(server.accepted_carriers(), 2);
    server.send_http(second_request.stream_id, "200 OK", b"second");
    assert_eq!(response_status(&second.await.unwrap()), 200);

    handle.shutdown_and_wait().await;
    server.abort();
}

#[tokio::test]
async fn journal_bridge_buffered_pass_through_injects_auth_and_strips_local_headers() {
    let (handle, upstream) = start_bridge_with_response("200 OK", b"bridge ok").await;
    let port = handle.port();
    let cap = capability_from(&handle);

    let response = raw_bridge_request(
        port,
        "GET",
        "/journal",
        Some(loopback_host(port)),
        Some(cap_cookie(&cap)),
        &[("Accept", "text/html")],
        b"",
    )
    .await;

    assert_eq!(response_status(&response), 200);
    assert_eq!(response_body(&response), "bridge ok");
    let head = response_head(&response);
    assert!(head.contains("content-length: 9"));
    assert!(head.contains("connection: close"));

    let request = upstream.await.unwrap();
    let request = String::from_utf8_lossy(&request);
    assert!(request.contains("x-test-observer: test-handle\r\n"));
    assert!(request.contains("Authorization: Bearer test-handle\r\n"));
    assert!(request.contains("x-test-protocol: 2\r\n"));
    assert!(request.contains("accept: text/html\r\n"));
    let lower = request.to_ascii_lowercase();
    assert!(!lower.contains(TEST_CAP_COOKIE_NAME));
    assert!(!lower.contains("cookie:"));
    assert!(!lower.contains("host: 127.0.0.1"));

    handle.shutdown_and_wait().await;
}

#[tokio::test]
async fn journal_bridge_head_preserves_upstream_content_length_without_body() {
    let (handle, upstream) = start_bridge_with_response_content_length("200 OK", b"", 42).await;
    let port = handle.port();
    let cap = capability_from(&handle);

    let response = raw_bridge_request(
        port,
        "HEAD",
        "/journal",
        Some(loopback_host(port)),
        Some(cap_cookie(&cap)),
        &[],
        b"",
    )
    .await;

    assert_eq!(response_status(&response), 200);
    assert_eq!(response_body(&response), "");
    let head = response_head(&response);
    assert!(head.contains("content-length: 42"));
    assert!(head.contains("connection: close"));

    let request = upstream.await.unwrap();
    let request = String::from_utf8_lossy(&request);
    assert!(request.starts_with("HEAD /journal HTTP/1.1\r\n"));
    handle.shutdown_and_wait().await;
}

#[tokio::test]
async fn journal_bridge_forwards_journal_401_without_masking() {
    let (handle, upstream) = start_bridge_with_response("401 Unauthorized", b"auth").await;
    let port = handle.port();
    let cap = capability_from(&handle);

    let response = raw_bridge_request(
        port,
        "GET",
        "/journal",
        Some(loopback_host(port)),
        Some(cap_cookie(&cap)),
        &[],
        b"",
    )
    .await;

    assert_eq!(response_status(&response), 401);
    assert_eq!(response_body(&response), "auth");
    let _ = upstream.await.unwrap();
    handle.shutdown_and_wait().await;
}

#[tokio::test]
async fn journal_bridge_sse_streams_without_local_framing_headers() {
    let (handle, upstream) = start_bridge_with_sse(SseMode::Close).await;
    let port = handle.port();
    let cap = capability_from(&handle);

    let response = raw_bridge_request(
        port,
        "GET",
        "/sse/events",
        Some(loopback_host(port)),
        Some(cap_cookie(&cap)),
        &[],
        b"",
    )
    .await;

    assert_eq!(response_status(&response), 200);
    let head = response_head(&response);
    assert!(head.contains("content-type: text/event-stream"));
    assert!(head.contains("connection: close"));
    assert!(!head.contains("content-length"));
    assert!(!head.contains("transfer-encoding"));
    let body = response_body(&response);
    assert!(body.contains("data: 1\n\n"));
    assert!(body.contains("data: 2\n\n"));

    let _ = upstream.await.unwrap();
    handle.shutdown_and_wait().await;
}

#[tokio::test]
async fn journal_bridge_selected_stream_arrives_incrementally() {
    let policy = BridgePolicy {
        capability_gate: CapabilityGate::Disabled,
        stream_response: Arc::new(|head| head.path() == "/downloads/archive"),
        ..BridgePolicy::default()
    };
    let (handle, mut server) = start_bridge_with_persistent_server_policy(policy).await;
    let port = handle.port();
    let client = tokio::spawn(partial_bridge_request(
        port,
        "PUT",
        "/downloads/archive",
        Some(loopback_host(port)),
        b"upload request",
        b"first chunk",
    ));

    let request = server.next_request().await;
    let request_text = String::from_utf8_lossy(&request.bytes);
    assert!(request_text.starts_with("PUT /downloads/archive HTTP/1.1\r\n"));
    assert!(request_text.ends_with("\r\n\r\nupload request"));
    server.send_stream_head(
        request.stream_id,
        "200 OK",
        &[("Content-Type", "application/octet-stream")],
    );
    server.send_body(request.stream_id, b"first chunk");

    let mut partial = client.await.unwrap();
    assert!(response_body(&partial.received).contains("first chunk"));

    let mut probe = [0u8; 256];
    let early_second = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        partial.stream.read(&mut probe),
    )
    .await;
    assert!(
        early_second.is_err(),
        "second response chunk arrived before the upstream sent it"
    );

    server.send_body(request.stream_id, b"second chunk");
    server.close_stream(request.stream_id);
    let mut remaining = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        partial.stream.read_to_end(&mut remaining),
    )
    .await
    .expect("timed out waiting for streamed response close")
    .unwrap();
    partial.received.extend_from_slice(&remaining);
    assert_eq!(response_body(&partial.received), "first chunksecond chunk");

    handle.shutdown_and_wait().await;
    server.abort();
}

#[tokio::test]
async fn journal_bridge_selected_streaming_head_preserves_length_without_body() {
    let policy = BridgePolicy {
        capability_gate: CapabilityGate::Disabled,
        stream_response: Arc::new(|head| head.method == "HEAD"),
        ..BridgePolicy::default()
    };
    let (handle, mut server) = start_bridge_with_persistent_server_policy(policy).await;
    let port = handle.port();
    let response = tokio::spawn(raw_bridge_request(
        port,
        "HEAD",
        "/downloads/archive",
        Some(loopback_host(port)),
        None,
        &[],
        b"",
    ));

    let request = server.next_request().await;
    assert!(
        String::from_utf8_lossy(&request.bytes).starts_with("HEAD /downloads/archive HTTP/1.1\r\n")
    );
    server.send_stream_head(
        request.stream_id,
        "200 OK",
        &[
            ("Content-Type", "application/octet-stream"),
            ("Content-Length", "42"),
        ],
    );
    server.send_body(request.stream_id, b"not written locally");
    server.close_stream(request.stream_id);

    let response = response.await.unwrap();
    assert_eq!(response_status(&response), 200);
    assert_eq!(response_body(&response), "");
    assert!(response_head(&response).contains("content-length: 42"));
    handle.shutdown_and_wait().await;
    server.abort();
}

fn media_stream_policy() -> BridgePolicy {
    BridgePolicy {
        capability_gate: CapabilityGate::Disabled,
        stream_response: Arc::new(|head| head.path() == "/media/clip"),
        ..BridgePolicy::default()
    }
}

#[derive(Clone, Copy, Debug)]
enum StreamEnding {
    Close,
    Reset,
}

async fn streamed_media_response(
    headers: &[(&str, &str)],
    chunks: &[&[u8]],
    ending: StreamEnding,
) -> Vec<u8> {
    let (handle, mut server) =
        start_bridge_with_persistent_server_policy(media_stream_policy()).await;
    let port = handle.port();
    let client = tokio::spawn(raw_bridge_request(
        port,
        "GET",
        "/media/clip",
        Some(loopback_host(port)),
        None,
        &[],
        b"",
    ));
    let request = server.next_request().await;
    server.send_stream_head(request.stream_id, "200 OK", headers);
    for chunk in chunks {
        server.send_body(request.stream_id, chunk);
    }
    match ending {
        StreamEnding::Close => server.close_stream(request.stream_id),
        StreamEnding::Reset => server.reset_stream(request.stream_id),
    }
    let response = tokio::time::timeout(std::time::Duration::from_secs(5), client)
        .await
        .expect("streamed response did not end")
        .unwrap();
    handle.shutdown_and_wait().await;
    server.abort();
    response
}

fn declared_length(head: &str) -> Vec<usize> {
    head.lines()
        .filter_map(|line| line.strip_prefix("content-length:"))
        .map(|value| value.trim().parse().unwrap())
        .collect()
}

// Falsified by restoring the HEAD-only length: the complete body arrives with no length, so a
// short one could not be told apart from it.
#[tokio::test]
async fn journal_bridge_finite_stream_declares_the_upstream_length_once() {
    let response = streamed_media_response(
        &[("Content-Type", "audio/mp4"), ("Content-Length", "11")],
        &[b"hello ", b"world"],
        StreamEnding::Close,
    )
    .await;

    assert_eq!(response_status(&response), 200);
    let head = response_head(&response);
    assert_eq!(declared_length(&head), vec![11]);
    assert!(!head.contains("transfer-encoding"));
    assert_eq!(response_body(&response), "hello world");
}

// The defect: a truncated finite body reached the caller as a complete-looking response.
// Falsified by restoring the HEAD-only length: no length is declared for either ending.
#[tokio::test]
async fn journal_bridge_truncated_finite_stream_is_short_of_its_declared_length() {
    for ending in [StreamEnding::Close, StreamEnding::Reset] {
        let response = streamed_media_response(
            &[("Content-Type", "audio/mp4"), ("Content-Length", "64")],
            &[b"partial"],
            ending,
        )
        .await;

        assert_eq!(response_status(&response), 200, "{ending:?}");
        let head = response_head(&response);
        assert_eq!(declared_length(&head), vec![64], "{ending:?}");
        assert_eq!(response_body(&response), "partial", "{ending:?}");
    }
}

// Falsified by writing every upstream chunk: the caller would receive more than was declared.
#[tokio::test]
async fn journal_bridge_finite_stream_never_writes_past_its_declared_length() {
    let response = streamed_media_response(
        &[("Content-Type", "audio/mp4"), ("Content-Length", "5")],
        &[b"0123", b"456789"],
        StreamEnding::Close,
    )
    .await;

    let head = response_head(&response);
    assert_eq!(declared_length(&head), vec![5]);
    let body = response_body(&response);
    assert!(body.len() < 5, "wrote {body:?} past a 5-byte declaration");
    assert!("0123".starts_with(&body), "{body:?}");
}

// Falsified by writing the final declared byte before the journal ends the stream: a body that
// overflows exactly at its declared length reaches the caller looking complete.
#[tokio::test]
async fn journal_bridge_finite_stream_overflowing_at_its_length_still_ends_short() {
    let response = streamed_media_response(
        &[("Content-Type", "audio/mp4"), ("Content-Length", "5")],
        &[b"01234", b"5"],
        StreamEnding::Close,
    )
    .await;

    assert_eq!(declared_length(&response_head(&response)), vec![5]);
    let body = response_body(&response);
    assert!(body.len() < 5, "{body:?} looks complete");
    assert!("0123".starts_with(&body), "{body:?}");
}

// Falsified by writing the held final byte when the stream fails: a body that ends abnormally
// after its last declared byte reaches the caller looking complete.
#[tokio::test]
async fn journal_bridge_finite_stream_reset_after_its_length_still_ends_short() {
    let response = streamed_media_response(
        &[("Content-Type", "audio/mp4"), ("Content-Length", "5")],
        &[b"01234"],
        StreamEnding::Reset,
    )
    .await;

    assert_eq!(declared_length(&response_head(&response)), vec![5]);
    let body = response_body(&response);
    assert!(body.len() < 5, "{body:?} looks complete");
    assert!("0123".starts_with(&body), "{body:?}");
}

// Falsified by writing an empty body's head before the stream ends: a body that arrives anyway
// cannot be refused, and the caller reads a complete empty response.
#[tokio::test]
async fn journal_bridge_empty_declared_stream_with_a_body_is_a_local_502() {
    let response = streamed_media_response(
        &[("Content-Type", "audio/mp4"), ("Content-Length", "0")],
        &[b"unexpected"],
        StreamEnding::Close,
    )
    .await;
    assert_eq!(response_status(&response), 502);
    assert_eq!(response_body(&response), "journal unreachable");

    let response = streamed_media_response(
        &[("Content-Type", "audio/mp4"), ("Content-Length", "0")],
        &[],
        StreamEnding::Close,
    )
    .await;
    assert_eq!(response_status(&response), 200);
    assert_eq!(declared_length(&response_head(&response)), vec![0]);
    assert_eq!(response_body(&response), "");
}

// Falsified by forwarding a length beside a transfer coding: the de-chunked body would not match it.
#[tokio::test]
async fn journal_bridge_chunked_stream_declares_no_length() {
    let response = streamed_media_response(
        &[
            ("Content-Type", "application/octet-stream"),
            ("Transfer-Encoding", "chunked"),
            ("Content-Length", "64"),
        ],
        &[b"5\r\nhello\r\n0\r\n\r\n"],
        StreamEnding::Close,
    )
    .await;

    assert_eq!(response_status(&response), 200);
    let head = response_head(&response);
    assert!(declared_length(&head).is_empty(), "{head}");
    assert!(!head.contains("transfer-encoding"), "{head}");
    assert_eq!(response_body(&response), "hello");
}

#[tokio::test]
async fn journal_bridge_stream_without_a_declared_length_stays_close_delimited() {
    let response = streamed_media_response(
        &[("Content-Type", "application/octet-stream")],
        &[b"first ", b"second"],
        StreamEnding::Close,
    )
    .await;

    let head = response_head(&response);
    assert!(declared_length(&head).is_empty());
    assert!(head.contains("connection: close"));
    assert_eq!(response_body(&response), "first second");
}

#[tokio::test]
async fn journal_bridge_bodiless_stream_status_declares_no_length() {
    for status in ["304 Not Modified", "204 No Content"] {
        let (handle, mut server) =
            start_bridge_with_persistent_server_policy(media_stream_policy()).await;
        let port = handle.port();
        let client = tokio::spawn(raw_bridge_request(
            port,
            "GET",
            "/media/clip",
            Some(loopback_host(port)),
            None,
            &[("If-None-Match", "\"clip\"")],
            b"",
        ));
        let request = server.next_request().await;
        server.send_stream_head(
            request.stream_id,
            status,
            &[("ETag", "\"clip\""), ("Content-Length", "64")],
        );
        server.close_stream(request.stream_id);
        let response = client.await.unwrap();
        let code: u16 = status.split_whitespace().next().unwrap().parse().unwrap();
        assert_eq!(response_status(&response), code);
        assert!(
            declared_length(&response_head(&response)).is_empty(),
            "{status}"
        );
        handle.shutdown_and_wait().await;
        server.abort();
    }
}

#[tokio::test]
async fn journal_bridge_sse_fail_before_head_returns_502() {
    let (handle, upstream) = start_bridge_with_sse(SseMode::EofBeforeHead).await;
    let port = handle.port();
    let cap = capability_from(&handle);

    let response = raw_bridge_request(
        port,
        "GET",
        "/sse/events",
        Some(loopback_host(port)),
        Some(cap_cookie(&cap)),
        &[],
        b"",
    )
    .await;

    assert_eq!(response_status(&response), 502);
    assert!(!response_text(&response).starts_with("HTTP/1.1 200"));
    let _ = upstream.await.unwrap();
    handle.shutdown_and_wait().await;
}

#[tokio::test]
async fn journal_bridge_sse_fail_after_head_does_not_emit_502() {
    let (handle, upstream) = start_bridge_with_sse(SseMode::EofAfterHeadAndPartialBody).await;
    let port = handle.port();
    let cap = capability_from(&handle);

    let response = raw_bridge_request(
        port,
        "GET",
        "/sse/events",
        Some(loopback_host(port)),
        Some(cap_cookie(&cap)),
        &[],
        b"",
    )
    .await;

    let text = response_text(&response);
    assert_eq!(text.matches("HTTP/1.1").count(), 1);
    assert!(text.starts_with("HTTP/1.1 200"));
    assert!(response_body(&response).contains("data: partial"));
    assert!(!text.contains("502"));
    assert!(!text.contains("journal unreachable"));
    let _ = upstream.await.unwrap();
    handle.shutdown_and_wait().await;
}

#[tokio::test]
async fn root_sse_preserves_literal_data_and_heartbeat_bytes() {
    const ROOT_SSE_CASES: [&[u8]; 3] = [
        b"data: {\"event\":\"owner_message\",\"message\":\"What changed?\",\"tract\":\"chat\",\"ts\":1781803200000}\n\n",
        b"data: {\"event\":\"unknown\",\"extra\":\"value\",\"tract\":\"future\",\"ts\":0}\n\n",
        b": heartbeat\n\n",
    ];

    for expected in ROOT_SSE_CASES {
        let (handle, upstream) = start_bridge_with_sse(SseMode::Authority(expected)).await;
        let port = handle.port();
        let cap = capability_from(&handle);
        let response = raw_bridge_request(
            port,
            "GET",
            "/sse/events",
            Some(loopback_host(port)),
            Some(cap_cookie(&cap)),
            &[],
            b"",
        )
        .await;

        assert_eq!(response_status(&response), 200);
        assert_eq!(response_body(&response).as_bytes(), expected);
        let head = response_head(&response);
        assert!(head.contains("content-type: text/event-stream"));
        assert!(!head.contains("content-length"));
        assert!(!head.contains("transfer-encoding"));
        let request = upstream.await.unwrap();
        assert!(String::from_utf8_lossy(&request).starts_with("GET /sse/events HTTP/1.1\r\n"));
        handle.shutdown_and_wait().await;
    }
}

#[tokio::test]
async fn journal_bridge_reuses_one_carrier_for_sequential_requests() {
    let (handle, mut server) = start_bridge_with_persistent_server().await;
    let port = handle.port();
    let cap = capability_from(&handle);

    let first_cap = cap.clone();
    let first = tokio::spawn(async move {
        raw_bridge_request(
            port,
            "GET",
            "/first",
            Some(loopback_host(port)),
            Some(cap_cookie(&first_cap)),
            &[],
            b"",
        )
        .await
    });
    let first_request = server.next_request().await;
    assert!(String::from_utf8_lossy(&first_request.bytes).starts_with("GET /first HTTP/1.1\r\n"));
    server.send_http(first_request.stream_id, "200 OK", b"first");
    let first_response = first.await.unwrap();
    assert_eq!(response_status(&first_response), 200);
    assert_eq!(response_body(&first_response), "first");

    let second_cap = cap.clone();
    let second = tokio::spawn(async move {
        raw_bridge_request(
            port,
            "GET",
            "/second",
            Some(loopback_host(port)),
            Some(cap_cookie(&second_cap)),
            &[],
            b"",
        )
        .await
    });
    let second_request = server.next_request().await;
    assert!(String::from_utf8_lossy(&second_request.bytes).starts_with("GET /second HTTP/1.1\r\n"));
    server.send_http(second_request.stream_id, "200 OK", b"second");
    let second_response = second.await.unwrap();
    assert_eq!(response_status(&second_response), 200);
    assert_eq!(response_body(&second_response), "second");

    assert_eq!(server.accepted_carriers(), 1);
    handle.shutdown_and_wait().await;
    server.abort();
}

#[tokio::test]
#[expect(
    clippy::stable_sort_primitive,
    reason = "the copied two-element stream-id assertion preserves its established harness operation"
)]
async fn journal_bridge_first_load_concurrent_requests_coalesce_one_carrier() {
    let (handle, mut server) = start_bridge_with_persistent_server().await;
    let port = handle.port();
    let cap = capability_from(&handle);

    let first_cap = cap.clone();
    let first = tokio::spawn(async move {
        raw_bridge_request(
            port,
            "GET",
            "/first-load-a",
            Some(loopback_host(port)),
            Some(cap_cookie(&first_cap)),
            &[],
            b"",
        )
        .await
    });
    let second_cap = cap.clone();
    let second = tokio::spawn(async move {
        raw_bridge_request(
            port,
            "GET",
            "/first-load-b",
            Some(loopback_host(port)),
            Some(cap_cookie(&second_cap)),
            &[],
            b"",
        )
        .await
    });

    let req_a = server.next_request().await;
    let req_b = server.next_request().await;
    assert_eq!(req_a.carrier_index, 1);
    assert_eq!(req_b.carrier_index, 1);
    let mut stream_ids = [req_a.stream_id, req_b.stream_id];
    stream_ids.sort();
    assert_eq!(stream_ids, [1, 3]);
    server.send_http(req_a.stream_id, "200 OK", b"a");
    server.send_http(req_b.stream_id, "200 OK", b"b");

    assert_eq!(response_status(&first.await.unwrap()), 200);
    assert_eq!(response_status(&second.await.unwrap()), 200);
    assert_eq!(server.accepted_carriers(), 1);

    handle.shutdown_and_wait().await;
    server.abort();
}

#[tokio::test]
async fn journal_bridge_two_handles_use_separate_caps_and_carriers() {
    let (handle1, mut server1) = start_bridge_with_persistent_server().await;
    let (handle2, mut server2) = start_bridge_with_persistent_server().await;
    let port1 = handle1.port();
    let port2 = handle2.port();
    let cap1 = capability_from(&handle1);
    let cap2 = capability_from(&handle2);
    assert_ne!(cap1, cap2);

    let cap1_for_request = cap1.clone();
    let one = tokio::spawn(async move {
        raw_bridge_request(
            port1,
            "GET",
            "/one",
            Some(loopback_host(port1)),
            Some(cap_cookie(&cap1_for_request)),
            &[],
            b"",
        )
        .await
    });
    let cap2_for_request = cap2.clone();
    let two = tokio::spawn(async move {
        raw_bridge_request(
            port2,
            "GET",
            "/two",
            Some(loopback_host(port2)),
            Some(cap_cookie(&cap2_for_request)),
            &[],
            b"",
        )
        .await
    });

    let req1 = server1.next_request().await;
    let req2 = server2.next_request().await;
    assert!(String::from_utf8_lossy(&req1.bytes).starts_with("GET /one HTTP/1.1\r\n"));
    assert!(String::from_utf8_lossy(&req2.bytes).starts_with("GET /two HTTP/1.1\r\n"));
    server1.send_http(req1.stream_id, "200 OK", b"one");
    server2.send_http(req2.stream_id, "200 OK", b"two");

    assert_eq!(response_body(&one.await.unwrap()), "one");
    assert_eq!(response_body(&two.await.unwrap()), "two");
    assert_eq!(server1.accepted_carriers(), 1);
    assert_eq!(server2.accepted_carriers(), 1);

    handle1.shutdown_and_wait().await;
    handle2.shutdown_and_wait().await;
    server1.abort();
    server2.abort();
}

#[tokio::test]
async fn journal_bridge_interleaves_streams_to_correct_clients_on_one_carrier() {
    let (handle, mut server) = start_bridge_with_persistent_server().await;
    let port = handle.port();
    let cap = capability_from(&handle);

    let first_cap = cap.clone();
    let first = tokio::spawn(async move {
        raw_bridge_request(
            port,
            "GET",
            "/first",
            Some(loopback_host(port)),
            Some(cap_cookie(&first_cap)),
            &[],
            b"",
        )
        .await
    });
    let second_cap = cap.clone();
    let second = tokio::spawn(async move {
        raw_bridge_request(
            port,
            "GET",
            "/second",
            Some(loopback_host(port)),
            Some(cap_cookie(&second_cap)),
            &[],
            b"",
        )
        .await
    });

    let req_a = server.next_request().await;
    let req_b = server.next_request().await;
    let text_a = String::from_utf8_lossy(&req_a.bytes);
    let (first_req, second_req) = if text_a.starts_with("GET /first ") {
        (req_a, req_b)
    } else {
        (req_b, req_a)
    };
    assert!(String::from_utf8_lossy(&first_req.bytes).starts_with("GET /first HTTP/1.1\r\n"));
    assert!(String::from_utf8_lossy(&second_req.bytes).starts_with("GET /second HTTP/1.1\r\n"));

    server.send_http(second_req.stream_id, "200 OK", b"second");
    server.send_http(first_req.stream_id, "200 OK", b"first");

    let first_response = first.await.unwrap();
    let second_response = second.await.unwrap();
    assert_eq!(response_body(&first_response), "first");
    assert_eq!(response_body(&second_response), "second");
    assert_eq!(server.accepted_carriers(), 1);

    handle.shutdown_and_wait().await;
    server.abort();
}

#[tokio::test]
async fn journal_bridge_reset_isolates_one_stream_on_shared_carrier() {
    let (handle, mut server) = start_bridge_with_persistent_server().await;
    let port = handle.port();
    let cap = capability_from(&handle);

    let reset_cap = cap.clone();
    let reset_client = tokio::spawn(async move {
        raw_bridge_request(
            port,
            "GET",
            "/reset-me",
            Some(loopback_host(port)),
            Some(cap_cookie(&reset_cap)),
            &[],
            b"",
        )
        .await
    });
    let ok_cap = cap.clone();
    let ok_client = tokio::spawn(async move {
        raw_bridge_request(
            port,
            "GET",
            "/still-ok",
            Some(loopback_host(port)),
            Some(cap_cookie(&ok_cap)),
            &[],
            b"",
        )
        .await
    });

    let req_a = server.next_request().await;
    let req_b = server.next_request().await;
    let text_a = String::from_utf8_lossy(&req_a.bytes);
    let (reset_req, ok_req) = if text_a.starts_with("GET /reset-me ") {
        (req_a, req_b)
    } else {
        (req_b, req_a)
    };
    assert!(String::from_utf8_lossy(&reset_req.bytes).starts_with("GET /reset-me HTTP/1.1\r\n"));
    assert!(String::from_utf8_lossy(&ok_req.bytes).starts_with("GET /still-ok HTTP/1.1\r\n"));

    server.send_stream_head(
        reset_req.stream_id,
        "200 OK",
        &[("Content-Type", "text/plain"), ("Content-Length", "64")],
    );
    server.send_body(reset_req.stream_id, b"partial");
    server.reset_stream(reset_req.stream_id);
    server.send_http(ok_req.stream_id, "200 OK", b"survived");

    let reset_response = reset_client.await.unwrap();
    let ok_response = ok_client.await.unwrap();
    assert_eq!(response_status(&reset_response), 502);
    assert_eq!(response_status(&ok_response), 200);
    assert_eq!(response_body(&ok_response), "survived");
    assert_eq!(server.accepted_carriers(), 1);

    handle.shutdown_and_wait().await;
    server.abort();
}

#[tokio::test]
async fn journal_bridge_rejects_normal_close_before_declared_content_length() {
    let (handle, mut server) = start_bridge_with_persistent_server().await;
    let port = handle.port();
    let cap = capability_from(&handle);

    let client = tokio::spawn(async move {
        raw_bridge_request(
            port,
            "GET",
            "/truncated",
            Some(loopback_host(port)),
            Some(cap_cookie(&cap)),
            &[],
            b"",
        )
        .await
    });
    let request = server.next_request().await;
    server.send_stream_head(
        request.stream_id,
        "200 OK",
        &[("Content-Type", "text/plain"), ("Content-Length", "64")],
    );
    server.send_body(request.stream_id, b"partial");
    server.close_stream(request.stream_id);

    let response = client.await.unwrap();
    assert_eq!(response_status(&response), 502);
    assert_eq!(response_body(&response), "journal unreachable");

    handle.shutdown_and_wait().await;
    server.abort();
}

#[tokio::test]
async fn journal_bridge_sse_does_not_block_second_get_on_same_carrier() {
    let (handle, mut server) = start_bridge_with_persistent_server().await;
    let port = handle.port();
    let cap = capability_from(&handle);

    let sse_cap = cap.clone();
    let sse = tokio::spawn(async move {
        raw_bridge_request(
            port,
            "GET",
            "/sse/events",
            Some(loopback_host(port)),
            Some(cap_cookie(&sse_cap)),
            &[],
            b"",
        )
        .await
    });
    let sse_request = server.next_request().await;
    assert!(
        String::from_utf8_lossy(&sse_request.bytes).starts_with("GET /sse/events HTTP/1.1\r\n")
    );
    server.send_sse_head(sse_request.stream_id);
    server.send_body(sse_request.stream_id, b"data: 1\n\n");

    let get_cap = cap.clone();
    let get = tokio::spawn(async move {
        raw_bridge_request(
            port,
            "GET",
            "/journal",
            Some(loopback_host(port)),
            Some(cap_cookie(&get_cap)),
            &[],
            b"",
        )
        .await
    });
    let get_request = server.next_request().await;
    assert!(String::from_utf8_lossy(&get_request.bytes).starts_with("GET /journal HTTP/1.1\r\n"));
    server.send_http(get_request.stream_id, "200 OK", b"ok while sse open");

    let get_response = tokio::time::timeout(std::time::Duration::from_millis(500), get)
        .await
        .expect("second GET should not wait for SSE to close")
        .unwrap();
    assert_eq!(response_status(&get_response), 200);
    assert_eq!(response_body(&get_response), "ok while sse open");

    server.send_body(sse_request.stream_id, b"data: 2\n\n");
    server.close_stream(sse_request.stream_id);
    let sse_response = tokio::time::timeout(std::time::Duration::from_secs(1), sse)
        .await
        .expect("SSE should close after upstream close")
        .unwrap();
    assert_eq!(response_status(&sse_response), 200);
    let sse_body = response_body(&sse_response);
    assert!(sse_body.contains("data: 1\n\n"));
    assert!(sse_body.contains("data: 2\n\n"));
    assert_eq!(server.accepted_carriers(), 1);

    handle.shutdown_and_wait().await;
    server.abort();
}

#[tokio::test]
async fn journal_bridge_shutdown_closes_active_carrier_and_streams() {
    let (handle, mut server) = start_bridge_with_persistent_server().await;
    let port = handle.port();
    let cap = capability_from(&handle);

    let mut local = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let request = format!(
        "GET /sse/events HTTP/1.1\r\nHost: {}\r\nCookie: {}\r\n\r\n",
        loopback_host(port),
        cap_cookie(&cap)
    );
    local.write_all(request.as_bytes()).await.unwrap();
    local.flush().await.unwrap();

    let sse_request = server.next_request().await;
    server.send_sse_head(sse_request.stream_id);
    server.send_body(sse_request.stream_id, b"data: one\n\n");

    let mut sse_response = Vec::new();
    let mut buf = [0u8; 256];
    while !response_text(&sse_response).contains("data: one\n\n") {
        let n = tokio::time::timeout(std::time::Duration::from_secs(1), local.read(&mut buf))
            .await
            .expect("SSE bytes should arrive before shutdown")
            .unwrap();
        assert!(n > 0, "SSE closed before first body item");
        sse_response.extend_from_slice(&buf[..n]);
    }

    handle.shutdown_and_wait().await;
    let mut tail = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        local.read_to_end(&mut tail),
    )
    .await
    .expect("shutdown should close active SSE")
    .unwrap();
    sse_response.extend_from_slice(&tail);
    assert_eq!(response_status(&sse_response), 200);
    assert!(response_body(&sse_response).contains("data: one\n\n"));
    assert!(
        tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_err()
    );
    server.abort();
}

#[tokio::test]
async fn journal_bridge_carrier_death_redials_without_replaying_failed_stream() {
    let (handle, mut server) = start_bridge_with_persistent_server().await;
    let mut status_events = handle.subscribe_status();
    let port = handle.port();
    let cap = capability_from(&handle);

    let ok_cap = cap.clone();
    let ok = tokio::spawn(async move {
        raw_bridge_request(
            port,
            "GET",
            "/ok",
            Some(loopback_host(port)),
            Some(cap_cookie(&ok_cap)),
            &[],
            b"",
        )
        .await
    });
    let ok_request = server.next_request().await;
    assert_eq!(ok_request.carrier_index, 1);
    assert!(String::from_utf8_lossy(&ok_request.bytes).starts_with("GET /ok HTTP/1.1\r\n"));
    server.send_http(ok_request.stream_id, "200 OK", b"ok");
    assert_eq!(response_body(&ok.await.unwrap()), "ok");
    while !status_events.recv().await.unwrap().carrier_live {}

    let dying_cap = cap.clone();
    let dying = tokio::spawn(async move {
        raw_bridge_request(
            port,
            "GET",
            "/dies",
            Some(loopback_host(port)),
            Some(cap_cookie(&dying_cap)),
            &[],
            b"",
        )
        .await
    });
    let dying_request = server.next_request().await;
    assert_eq!(dying_request.carrier_index, 1);
    assert!(String::from_utf8_lossy(&dying_request.bytes).starts_with("GET /dies HTTP/1.1\r\n"));
    server.close_current_carrier();
    let dying_response = tokio::time::timeout(std::time::Duration::from_secs(1), dying)
        .await
        .expect("dead carrier should fail in-flight local request")
        .unwrap();
    assert_eq!(response_status(&dying_response), 502);
    while status_events.recv().await.unwrap().carrier_live {}

    let after_cap = cap.clone();
    let after = tokio::spawn(async move {
        raw_bridge_request(
            port,
            "GET",
            "/after",
            Some(loopback_host(port)),
            Some(cap_cookie(&after_cap)),
            &[],
            b"",
        )
        .await
    });
    let after_request = server.next_request().await;
    assert_eq!(after_request.carrier_index, 2);
    assert!(String::from_utf8_lossy(&after_request.bytes).starts_with("GET /after HTTP/1.1\r\n"));
    assert!(
        !String::from_utf8_lossy(&after_request.bytes).starts_with("GET /dies HTTP/1.1\r\n"),
        "failed in-flight request must not be replayed on the new carrier"
    );
    server.send_http(after_request.stream_id, "200 OK", b"after");
    assert_eq!(response_body(&after.await.unwrap()), "after");
    while !status_events.recv().await.unwrap().carrier_live {}
    assert_eq!(server.accepted_carriers(), 2);

    handle.shutdown_and_wait().await;
    server.abort();
}

#[tokio::test]
async fn journal_bridge_binds_loopback_and_serves_on_reported_port() {
    let (handle, _accepts, upstream) = start_bridge_with_counting_upstream().await;
    let port = handle.port();
    let cap = capability_from(&handle);

    let response = raw_bridge_request(
        port,
        "GET",
        &format!("{}?cap={cap}", spl_core::bridge::BOOTSTRAP_ROUTE),
        Some(loopback_host(port)),
        None,
        &[],
        b"",
    )
    .await;

    assert_eq!(response_status(&response), 302);
    handle.shutdown_and_wait().await;
    upstream.abort();
}

#[tokio::test]
async fn journal_bridge_shutdown_frees_port() {
    let (handle, _accepts, upstream) = start_bridge_with_counting_upstream().await;
    let port = handle.port();

    handle.shutdown_and_wait().await;
    assert!(
        tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_err()
    );
    upstream.abort();
}

#[tokio::test]
async fn journal_bridge_logs_redacted_failure_categories_only() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_port = listener.local_addr().unwrap().port();
    drop(listener);
    let credential = transport_credential(vec![0; 16], closed_port);
    let lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let subscriber = CapturingSubscriber {
        lines: lines.clone(),
    };
    tracing::dispatcher::set_global_default(tracing::Dispatch::new(subscriber))
        .expect("install journal bridge log capture subscriber");
    let handle = start_bridge(credential).await;
    let port = handle.port();
    let cap = capability_from(&handle);

    let _ = raw_bridge_request(
        port,
        "GET",
        "/secret/path?token=owner-secret",
        Some(loopback_host(port)),
        Some(cap_cookie("wrong-capability")),
        &[],
        b"body-secret",
    )
    .await;
    let _ = raw_bridge_request(
        port,
        "GET",
        "/journal?query=owner-secret",
        Some(loopback_host(port)),
        Some(cap_cookie(&cap)),
        &[],
        b"",
    )
    .await;

    handle.shutdown_and_wait().await;
    let logs = lines.lock().unwrap().join("\n");
    assert!(logs.contains("category=local_capability_reject"));
    assert!(logs.contains("reason=bad_capability"));
    assert!(logs.contains("category=upstream_unreachable"));
    assert!(logs.contains("code=io"));
    assert!(!logs.contains(&cap));
    assert!(!logs.contains("wrong-capability"));
    assert!(!logs.contains(TEST_CAP_COOKIE_NAME));
    assert!(!logs.contains("/secret/path"));
    assert!(!logs.contains("owner-secret"));
    assert!(!logs.contains("body-secret"));
}

#[tokio::test]
async fn journal_bridge_streams_partial_multipart_body_byte_exactly() {
    // Protocol: `.proto-ref/framing.md`, "fragmentation" — application writes
    // do not map 1:1 to frames, while "ordering guarantees" requires strict
    // FIFO within one stream.
    const TARGET: &str = "/uploads/multipart";
    const CONTENT_TYPE: &str = "multipart/form-data; boundary=test-boundary";
    let policy = BridgePolicy {
        capability_gate: CapabilityGate::Disabled,
        ..BridgePolicy::default()
    };
    let (handle, mut server) = start_bridge_with_persistent_server_policy(policy).await;
    let body = Arc::new(
        (0..INITIAL_WINDOW + 257_131)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>(),
    );
    let body_for_client = body.clone();
    let port = handle.port();
    let client = tokio::spawn(async move {
        partial_body_bridge_request(
            port,
            TARGET,
            CONTENT_TYPE,
            body_for_client,
            &[1, 31, 4093, 65_519, 777],
        )
        .await
    });

    let first = server.next_frame().await;
    assert_eq!(first.carrier_index, 1);
    assert_ne!(first.flags & FLAG_DATA, 0);
    assert!(first.payload_len > 0);
    let stream_id = first.stream_id;
    let mut event = first;
    let mut granted_at = 0usize;
    loop {
        if event.stream_id == stream_id
            && event.flags & FLAG_DATA != 0
            && event.cumulative_data.saturating_sub(granted_at) >= INITIAL_WINDOW / 2
        {
            let grant = event.cumulative_data - granted_at;
            server.send_window(stream_id, u32::try_from(grant).unwrap());
            granted_at = event.cumulative_data;
        }
        if event.stream_id == stream_id && event.flags & FLAG_CLOSE != 0 {
            break;
        }
        event = server.next_frame().await;
    }

    let request = server.next_request().await;
    assert_eq!(request.carrier_index, 1);
    assert_eq!(request.stream_id, stream_id);
    let split = request
        .bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap()
        + 4;
    let expected_head = spl_core::http::build_request_head(
        "POST",
        TARGET,
        &[
            ("content-type".into(), CONTENT_TYPE.into()),
            (TEST_OBSERVER_HEADER_NAME.into(), TEST_OBSERVER_KEY.into()),
            (
                "Authorization".into(),
                format!("Bearer {TEST_OBSERVER_KEY}"),
            ),
            (TEST_PROTOCOL_HEADER_NAME.into(), "2".into()),
        ],
        body.len(),
    );
    assert_eq!(&request.bytes[..split], expected_head);
    assert_eq!(&request.bytes[split..], body.as_slice());

    server.send_http(stream_id, "200 OK", b"stored");
    let response = client.await.unwrap();
    assert_eq!(response_status(&response), 200);
    assert_eq!(response_body(&response), "stored");
    assert_eq!(server.accepted_carriers(), 1);

    let status = handle.shutdown_and_wait().await;
    assert_eq!(status.active_requests, 0);
    server.abort();
}

#[tokio::test]
async fn journal_bridge_small_request_completes_during_large_upload() {
    // Protocol: `.proto-ref/framing.md`, "ordering guarantees" — "emit at most
    // one frame per stream before scheduling another stream — round-robin, not
    // greedy."
    const LARGE_TARGET: &str = "/uploads/large";
    let policy = BridgePolicy {
        capability_gate: CapabilityGate::Disabled,
        ..BridgePolicy::default()
    };
    let (handle, mut server) = start_bridge_with_persistent_server_policy(policy).await;
    let port = handle.port();
    let large_body = Arc::new(vec![b'L'; INITIAL_WINDOW * 2 + 333_333]);
    let large_for_client = large_body.clone();
    let large_client = tokio::spawn(async move {
        partial_body_bridge_request(
            port,
            LARGE_TARGET,
            "application/octet-stream",
            large_for_client,
            &[16_381, 7777, 65_521],
        )
        .await
    });

    let first = server.next_frame().await;
    let large_stream_id = first.stream_id;
    assert_ne!(first.flags & spl_core::frame::FLAG_OPEN, 0);
    server.send_window(large_stream_id, u32::try_from(INITIAL_WINDOW / 2).unwrap());

    let small_client = tokio::spawn(raw_bridge_request(
        port,
        "GET",
        "/small",
        Some(loopback_host(port)),
        None,
        &[],
        b"",
    ));
    let small_request = server.next_request().await;
    assert_ne!(small_request.stream_id, large_stream_id);
    assert_eq!(small_request.carrier_index, first.carrier_index);
    assert!(String::from_utf8_lossy(&small_request.bytes).starts_with("GET /small HTTP/1.1\r\n"));
    server.send_http(small_request.stream_id, "200 OK", b"small-first");
    let small_response = tokio::time::timeout(std::time::Duration::from_secs(1), small_client)
        .await
        .expect("small request should finish while the large upload remains open")
        .unwrap();
    assert_eq!(response_status(&small_response), 200);
    assert_eq!(response_body(&small_response), "small-first");
    assert!(
        server.requests.try_recv().is_err(),
        "large upload must still be open when the small response completes"
    );

    server.send_window(large_stream_id, u32::try_from(large_body.len()).unwrap());
    let large_request = server.next_request().await;
    assert_eq!(large_request.stream_id, large_stream_id);
    assert!(large_request.bytes.ends_with(large_body.as_slice()));
    server.send_http(large_stream_id, "200 OK", b"large-done");
    let large_response = tokio::time::timeout(std::time::Duration::from_secs(3), large_client)
        .await
        .expect("large request should finish after further credit")
        .unwrap();
    assert_eq!(response_status(&large_response), 200);
    assert_eq!(response_body(&large_response), "large-done");
    assert_eq!(server.accepted_carriers(), 1);

    let status = handle.shutdown_and_wait().await;
    assert_eq!(status.active_requests, 0);
    server.abort();
}

#[tokio::test]
async fn journal_bridge_shutdown_waits_for_head_and_credit_blocked_requests() {
    // Protocol: `.proto-ref/framing.md`, "flow control and backpressure" — a
    // sender with zero credit MUST NOT send DATA.
    let policy = BridgePolicy {
        capability_gate: CapabilityGate::Disabled,
        ..BridgePolicy::default()
    };
    let (handle, mut server) = start_bridge_with_persistent_server_policy(policy).await;
    let port = handle.port();

    let mut head_waiter = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    head_waiter
        .write_all(
            format!(
                "GET /waiting-head HTTP/1.1\r\nHost: {}\r\n",
                loopback_host(port)
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    head_waiter.flush().await.unwrap();

    let mut upload = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let declared = INITIAL_WINDOW * 2;
    upload
        .write_all(
            format!(
                "POST /waiting-credit HTTP/1.1\r\nHost: {}\r\nContent-Length: {declared}\r\n\r\n",
                loopback_host(port)
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let upload_writer = tokio::spawn(async move {
        let result = upload.write_all(&vec![b'Q'; declared]).await;
        (upload, result)
    });

    let first = server.next_frame().await;
    let upload_stream_id = first.stream_id;
    let last = server
        .await_cumulative(upload_stream_id, INITIAL_WINDOW)
        .await;
    assert_eq!(last.cumulative_data, INITIAL_WINDOW);
    assert_eq!(handle.status().active_requests, 2);

    let final_status = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        handle.shutdown_and_wait(),
    )
    .await
    .expect("shutdown should wake head and credit-blocked requests");
    assert_eq!(final_status.active_requests, 0);
    assert!(!final_status.listener_active);
    assert!(!final_status.carrier_live);

    let mut head_tail = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        head_waiter.read_to_end(&mut head_tail),
    )
    .await
    .expect("head-blocked local socket should close")
    .unwrap();
    assert!(head_tail.is_empty());

    let (mut upload, _) = upload_writer.await.unwrap();
    let mut upload_tail = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        upload.read_to_end(&mut upload_tail),
    )
    .await
    .expect("credit-blocked local socket should close")
    .unwrap();
    assert!(upload_tail.is_empty());
    assert_eq!(server.next_carrier_close().await, 1);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), server.frames.recv())
            .await
            .is_err(),
        "no stream activity may continue after shutdown returns"
    );
    server.abort();
}

#[tokio::test]
async fn journal_bridge_local_disconnect_stops_inflight_upload() {
    // Protocol: `.proto-ref/framing.md`, "stream lifecycle" — RESET fully
    // closes the stream, including both request and response directions.
    let policy = BridgePolicy {
        capability_gate: CapabilityGate::Disabled,
        ..BridgePolicy::default()
    };
    let (handle, mut server) = start_bridge_with_persistent_server_policy(policy).await;
    let port = handle.port();
    let mut local = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let declared = INITIAL_WINDOW * 2;
    local
        .write_all(
            format!(
                "POST /cancel-response HTTP/1.1\r\nHost: {}\r\nContent-Length: {declared}\r\n\r\n",
                loopback_host(port)
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    local.write_all(&vec![b'C'; 64 * 1024]).await.unwrap();
    local.flush().await.unwrap();

    let first = server.next_frame().await;
    let stream_id = first.stream_id;
    drop(local);

    let stopped_at = loop {
        let event = server.next_frame().await;
        if event.stream_id == stream_id && event.flags & FLAG_RESET != 0 {
            break event.cumulative_data;
        }
    };
    assert!(stopped_at < declared);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), server.frames.recv())
            .await
            .is_err(),
        "request body consumption must stop after local cancellation"
    );

    let status = handle.shutdown_and_wait().await;
    assert_eq!(status.active_requests, 0);
    server.abort();
}

async fn early_final_response(
    server: &mut PersistentBridgeServer,
    port: u16,
    target: &'static str,
    upstream_status: &'static str,
) -> (u32, Vec<u8>) {
    let client = tokio::spawn(async move {
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let declared = INITIAL_WINDOW;
        let head = format!(
            "POST {target} HTTP/1.1\r\nHost: {}\r\nContent-Length: {declared}\r\n\r\n",
            loopback_host(port)
        );
        stream.write_all(head.as_bytes()).await.unwrap();
        stream.write_all(&vec![b'P'; 32 * 1024]).await.unwrap();
        stream.flush().await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        response
    });
    let first = server.next_frame().await;
    let stream_id = first.stream_id;
    assert!(first.cumulative_data < INITIAL_WINDOW);
    server.send_http(stream_id, upstream_status, b"early");
    let response = tokio::time::timeout(std::time::Duration::from_secs(1), client)
        .await
        .expect("early final response should terminate the local request")
        .unwrap();
    loop {
        let event = server.next_frame().await;
        if event.stream_id == stream_id && event.flags & FLAG_RESET != 0 {
            assert_eq!(event.payload_len, 1);
            break;
        }
    }
    (stream_id, response)
}

#[tokio::test]
async fn journal_bridge_maps_early_final_responses_and_resets_once() {
    // Protocol: `.proto-ref/framing.md`, "stream lifecycle" — either side's
    // RESET fully closes the stream; late terminal frames must not create a
    // second termination.
    let policy = BridgePolicy {
        capability_gate: CapabilityGate::Disabled,
        ..BridgePolicy::default()
    };
    let (handle, mut server) = start_bridge_with_persistent_server_policy(policy).await;
    let port = handle.port();

    let (failed_stream, failure) =
        early_final_response(&mut server, port, "/early-failure", "409 Conflict").await;
    assert_eq!(response_status(&failure), 409);
    let (success_stream, success) =
        early_final_response(&mut server, port, "/early-success", "200 OK").await;
    assert_eq!(response_status(&success), 502);

    let mut reset_counts = HashMap::from([(failed_stream, 1usize), (success_stream, 1usize)]);
    while let Ok(event) = server.frames.try_recv() {
        if event.flags & FLAG_RESET != 0 {
            *reset_counts.entry(event.stream_id).or_default() += 1;
        }
    }
    assert_eq!(reset_counts.get(&failed_stream), Some(&1));
    assert_eq!(reset_counts.get(&success_stream), Some(&1));

    let status = handle.shutdown_and_wait().await;
    assert_eq!(status.active_requests, 0);
    server.abort();
}

/// A flow-control-enforcing peer, byte-identical in policy to the journal's
/// `convey/secure_listener/mux.py`: it advertises a 1 MiB recv window, **RESETs**
/// the stream if a DATA frame would overrun the un-granted window, and grants a
/// `WINDOW` frame once 50% is consumed. A client that blasted the whole body
/// up front (the old non-windowed path) would overrun and get RESET here; only a
/// correctly-paced [`WindowedUpload`] completes. Returns the assembled request.
async fn serve_one_with_flow_control(listener: TcpListener, acceptor: TlsAcceptor) -> Vec<u8> {
    let (tcp, _) = listener.accept().await.unwrap();
    let mut tls = acceptor.accept(tcp).await.unwrap();

    let mut decoder = FrameDecoder::new();
    let mut request = Vec::new();
    let mut stream_id = 1u32;
    let mut closed = false;
    #[expect(
        clippy::cast_possible_wrap,
        reason = "the protocol window constant is fixed well within i64"
    )]
    let mut recv_credit: i64 = INITIAL_WINDOW as i64;
    let mut unacked: i64 = 0;
    let mut buf = [0u8; 16 * 1024];
    while !closed {
        let n = tls.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        decoder.feed(&buf[..n]);
        for frame in decoder.drain().unwrap() {
            stream_id = frame.stream_id;
            if frame.flags & FLAG_DATA != 0 {
                #[expect(
                    clippy::cast_possible_wrap,
                    reason = "the bounded test frame payload is well within i64"
                )]
                let len = frame.payload.len() as i64;
                if len > recv_credit {
                    // Window overrun — exactly what the journal refuses. Prove the
                    // client never does this by RESETing if it ever happens.
                    let reset = Frame::new(stream_id, FLAG_RESET, vec![0x03]); // protocol error
                    tls.write_all(&reset.encode().unwrap()).await.unwrap();
                    tls.flush().await.unwrap();
                    return request; // request stays short → test assertion fails loudly
                }
                recv_credit -= len;
                unacked += len;
                request.extend_from_slice(&frame.payload);
                // Replenish at 50% consumed, granting back exactly what we drained.
                #[expect(
                    clippy::cast_possible_wrap,
                    reason = "the protocol window constant is fixed well within i64"
                )]
                if unacked >= (INITIAL_WINDOW as i64) / 2 {
                    #[expect(
                        clippy::cast_sign_loss,
                        reason = "the preceding nonnegative threshold guarantees this grant fits the protocol's u32 window"
                    )]
                    let grant = unacked as u32;
                    recv_credit += unacked;
                    unacked = 0;
                    let window = Frame::new(stream_id, FLAG_WINDOW, grant.to_be_bytes().to_vec());
                    tls.write_all(&window.encode().unwrap()).await.unwrap();
                    tls.flush().await.unwrap();
                }
            }
            if frame.flags & FLAG_CLOSE != 0 {
                closed = true;
            }
        }
    }

    let body = b"{\"status\":\"accepted\"}";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        String::from_utf8_lossy(body)
    );
    let frame = Frame::new(stream_id, FLAG_DATA | FLAG_CLOSE, response.into_bytes());
    tls.write_all(&frame.encode().unwrap()).await.unwrap();
    tls.flush().await.unwrap();
    let _ = tls.shutdown().await;
    request
}

#[tokio::test]
async fn streams_multi_mib_body_under_window_flow_control() {
    let (cert, key) = self_signed();
    let pin = spl_core::ca::sha256(cert.as_ref())[..16].to_vec();
    let acceptor = TlsAcceptor::from(Arc::new(server_config(cert, key)));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(serve_one_with_flow_control(listener, acceptor));

    // ~2.5 MiB body — well past the 1 MiB initial window, so the upload only
    // completes if the client paces to WINDOW grants (an encoded screen segment
    // is ~37.5 MB; this is the same path at test scale).
    let big_body = vec![0x7Cu8; INITIAL_WINDOW * 2 + INITIAL_WINDOW / 2 + 123];
    let config = Arc::new(pairing_config(&pin).unwrap());
    let response = request_once(
        config,
        "127.0.0.1",
        port,
        "POST",
        "/app/observer/ingest",
        &[(
            "Content-Type".to_string(),
            "application/octet-stream".to_string(),
        )],
        &big_body,
    )
    .await
    .expect("a >1 MiB body must stream to completion under flow control");

    assert_eq!(response.status, 200);
    assert_eq!(response.body_text(), "{\"status\":\"accepted\"}");

    // The server received the entire framed request, body intact and in order.
    let received = server.await.unwrap();
    assert!(
        received.len() > INITIAL_WINDOW * 2,
        "server should have received the whole multi-MiB request, got {} bytes",
        received.len()
    );
    let received_text = String::from_utf8_lossy(&received[..received.len().min(256)]);
    assert!(received_text.starts_with("POST /app/observer/ingest HTTP/1.1\r\n"));
    assert!(received.ends_with(&big_body));
}

#[tokio::test]
async fn wrong_pin_fails_the_handshake() {
    let (cert, key) = self_signed();
    let acceptor = TlsAcceptor::from(Arc::new(server_config(cert, key)));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    // Server task may error when the client aborts the handshake; ignore it.
    let _server = tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            let _ = acceptor.accept(tcp).await;
        }
    });

    // Pin a fingerprint that does not match the server cert.
    let wrong_pin = vec![0xFFu8; 16];
    let config = Arc::new(pairing_config(&wrong_pin).unwrap());
    let result = request_once(config, "127.0.0.1", port, "GET", "/healthz", &[], b"").await;
    assert!(result.is_err(), "a wrong CA-fp pin must fail the handshake");
}

#[tokio::test]
#[expect(
    clippy::large_futures,
    reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
)]
async fn transport_client_request_direct_with_observer() {
    let (cert, key) = self_signed();
    let pin = spl_core::ca::sha256(cert.as_ref())[..16].to_vec();
    let acceptor = TlsAcceptor::from(Arc::new(server_config(cert, key)));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = tokio::spawn(async move { serve_one(listener, acceptor).await });

    let cred = transport_credential(pin, port);
    let client = TransportClient::new(cred, None).unwrap();
    let obs = spl_transport::OperationObserver::new();
    let options = spl_transport::RequestOptions {
        response_cap: 1024 * 1024,
        replay: spl_transport::ReplayPolicy::ForbidAfterWrite,
        observer: Some(&obs),
    };

    let outcome = client
        .request("GET", "/healthz", &[], b"", options)
        .await
        .unwrap();

    assert_eq!(outcome.response.status, 200);
    assert_eq!(outcome.path, spl_transport::SelectedPath::Direct);
    assert_eq!(outcome.attempts, 1);
    assert_eq!(obs.dial_attempts(), 1);
    assert_eq!(obs.direct_successes(), 1);
    assert_eq!(obs.relay_successes(), 0);
    assert_eq!(
        obs.selected_path(),
        Some(spl_transport::SelectedPath::Direct)
    );
    assert!(obs.request_bytes_sent() > 0);
    assert!(obs.close_completed());
    assert!(!obs.legacy_enrollment_possible());
    assert_eq!(obs.enrollment_events(), 0);
    assert_eq!(
        obs.snapshot(),
        spl_transport::OperationSnapshot {
            dial_attempts: 1,
            direct_successes: 1,
            relay_successes: 0,
            request_bytes_sent: obs.request_bytes_sent(),
            close_completed: true,
            selected_path: Some(spl_transport::SelectedPath::Direct),
            enrollment_events: 0,
            legacy_enrollment_possible: false,
        }
    );

    server.await.unwrap();
}

#[tokio::test]
#[expect(
    clippy::large_futures,
    reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
)]
async fn transport_client_request_response_cap_enforced() {
    let (cert, key) = self_signed();
    let pin = spl_core::ca::sha256(cert.as_ref())[..16].to_vec();
    let acceptor = TlsAcceptor::from(Arc::new(server_config(cert, key)));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = tokio::spawn(async move {
        serve_one_response(listener, acceptor, "200 OK", b"01234567890123456789").await
    });

    let cred = transport_credential(pin, port);
    let client = TransportClient::new(cred, None).unwrap();
    let options = spl_transport::RequestOptions {
        response_cap: 80,
        replay: spl_transport::ReplayPolicy::ForbidAfterWrite,
        observer: None,
    };

    let err = client
        .request("GET", "/healthz", &[], b"", options)
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        spl_transport::RequestError::Transport(TransportError::Mux(
            spl_core::mux::MuxError::CapExceeded,
        ))
    ));

    server.await.unwrap();
}

#[tokio::test]
#[expect(
    clippy::large_futures,
    reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
)]
async fn transport_client_request_replay_unsafe_after_partial_write() {
    let (cert, key) = self_signed();
    let pin = spl_core::ca::sha256(cert.as_ref())[..16].to_vec();
    let acceptor = TlsAcceptor::from(Arc::new(server_config(cert, key)));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.unwrap();
        let mut buf = [0u8; 1024];
        let _ = tls.read(&mut buf).await.unwrap();
        // Drop TLS stream abruptly after reading request
        drop(tls);
    });

    let cred = transport_credential(pin, port);
    let client = TransportClient::new(cred, None).unwrap();
    let options = spl_transport::RequestOptions {
        response_cap: 1024 * 1024,
        replay: spl_transport::ReplayPolicy::ForbidAfterWrite,
        observer: None,
    };

    let err = client
        .request("POST", "/test", &[], b"hello world", options)
        .await
        .unwrap_err();

    assert!(matches!(err, spl_transport::RequestError::ReplayUnsafe(_)));

    server.await.unwrap();
}

/// The journal ID a client reports for a peer presenting `cert`.
fn jid_of(cert: &CertificateDer<'_>) -> String {
    spl_core::relay_window::jid_from_spki(&spl_core::ca::extract_spki_der(cert.as_ref()).unwrap())
        .unwrap()
}

/// A TLS server whose certificate does not match the pin in the credential, accepting every
/// connection until aborted. Returns its port and journal ID.
async fn impostor_listener() -> (u16, String, tokio::task::JoinHandle<()>) {
    let (cert, key) = self_signed();
    let jid = jid_of(&cert);
    let acceptor = TlsAcceptor::from(Arc::new(server_config(cert, key)));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = acceptor.accept(stream).await;
        }
    });
    (port, jid, task)
}

// A peer at a saved address that is not the paired journal is named, with where it answered and
// which journal it claims to be. Falsified by keeping only the last endpoint's error on the
// request path (the closed second endpoint hides the sighting and the request reports an
// outage), or by dropping the peer's address or journal ID.
#[tokio::test]
#[expect(
    clippy::large_futures,
    reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
)]
async fn transport_client_request_does_not_let_a_closed_endpoint_hide_an_unknown_journal() {
    let (pinned, _) = self_signed();
    let pin = spl_core::ca::sha256(pinned.as_ref())[..16].to_vec();
    let (impostor_port, impostor_jid, impostor) = impostor_listener().await;
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_port = closed.local_addr().unwrap().port();
    drop(closed);
    let mut credential = transport_credential(pin, impostor_port);
    credential.endpoints.push(EndpointAddr {
        host: "127.0.0.1".into(),
        port: closed_port,
    });
    let client = TransportClient::new(credential, None).unwrap();
    let expected = spl_transport::UnknownJournal {
        address: Some(format!("127.0.0.1:{impostor_port}")),
        jid: Some(impostor_jid),
    };

    let err = client
        .request(
            "GET",
            "/healthz",
            &[],
            b"",
            spl_transport::RequestOptions::default(),
        )
        .await
        .unwrap_err();
    let reported = match &err {
        spl_transport::RequestError::Transport(TransportError::UnknownJournal(unknown)) => {
            Some(unknown.clone())
        }
        _ => None,
    };
    assert_eq!(reported, Some(expected.clone()), "{err:?}");
    assert_eq!(client.unknown_journals(), vec![expected]);
    impostor.abort();
}

/// A TLS listener at one fixed address whose certificate can be swapped between connections.
async fn swappable_listener(
    config: ServerConfig,
) -> (
    u16,
    Arc<Mutex<Arc<ServerConfig>>>,
    tokio::task::JoinHandle<()>,
) {
    let current = Arc::new(Mutex::new(Arc::new(config)));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let serving = current.clone();
    let task = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let config = serving.lock().unwrap().clone();
            let _ = TlsAcceptor::from(config).accept(stream).await;
        }
    });
    (port, current, task)
}

// The owner stays told while another address works, and the sighting clears once that address
// holds the paired journal again. Falsified by keeping one sighting for the whole client (the
// working second address clears it on every dial) or by never clearing it.
#[tokio::test]
#[expect(
    clippy::large_futures,
    reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
)]
async fn an_unknown_journal_is_kept_per_address_until_that_address_reaches_the_journal() {
    let (cert, key) = self_signed();
    let pin = spl_core::ca::sha256(cert.as_ref())[..16].to_vec();
    let (other_cert, other_key) = self_signed();
    let other_jid = jid_of(&other_cert);
    let (swap_port, swap, swap_task) =
        swappable_listener(server_config(other_cert, other_key)).await;
    let (journal_port, journal_task) = {
        let acceptor = TlsAcceptor::from(Arc::new(server_config(cert.clone(), key.clone_key())));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let _ = acceptor.accept(stream).await;
            }
        });
        (port, task)
    };
    let mut credential = transport_credential(pin, swap_port);
    credential.endpoints.push(EndpointAddr {
        host: "127.0.0.1".into(),
        port: journal_port,
    });
    let client = TransportClient::new(credential, None).unwrap();
    let sighting = spl_transport::UnknownJournal {
        address: Some(format!("127.0.0.1:{swap_port}")),
        jid: Some(other_jid),
    };

    for _ in 0..2 {
        drop(
            client
                .dial_carrier()
                .await
                .expect("the second address holds the journal"),
        );
        assert_eq!(client.unknown_journals(), vec![sighting.clone()]);
    }

    *swap.lock().unwrap() = Arc::new(server_config(cert, key));
    drop(
        client
            .dial_carrier()
            .await
            .expect("the first address holds the journal again"),
    );
    assert_eq!(client.unknown_journals(), Vec::new());

    swap_task.abort();
    journal_task.abort();
}

// Falsified by letting an unknown journal outrank the real journal's answer on another endpoint,
// in either order: the answer is hidden and the request is replayed.
#[tokio::test]
#[expect(
    clippy::large_futures,
    reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
)]
async fn transport_client_request_keeps_the_real_journals_answer_over_an_unknown_journal() {
    for journal_first in [false, true] {
        let (cert, key) = self_signed();
        let pin = spl_core::ca::sha256(cert.as_ref())[..16].to_vec();
        let (impostor_port, _, impostor) = impostor_listener().await;
        let journal = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let journal_port = journal.local_addr().unwrap().port();
        let handled = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let journal_handled = handled.clone();
        let journal_task = tokio::spawn(async move {
            let acceptor = TlsAcceptor::from(Arc::new(server_config(cert, key)));
            loop {
                let (stream, _) = journal.accept().await.unwrap();
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    continue;
                };
                journal_handled.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut buf = [0u8; 4096];
                let _ = tls.read(&mut buf).await;
                // Not a valid frame: the journal answered, and its answer is a protocol error.
                let _ = tls.write_all(&[0xff; 32]).await;
                let _ = tls.flush().await;
            }
        });
        let journal_endpoint = EndpointAddr {
            host: "127.0.0.1".into(),
            port: journal_port,
        };
        let impostor_endpoint = EndpointAddr {
            host: "127.0.0.1".into(),
            port: impostor_port,
        };
        let mut credential = transport_credential(pin, impostor_port);
        credential.endpoints = if journal_first {
            vec![journal_endpoint, impostor_endpoint]
        } else {
            vec![impostor_endpoint, journal_endpoint]
        };
        let client = TransportClient::new(credential, None).unwrap();
        let options = spl_transport::RequestOptions {
            replay: spl_transport::ReplayPolicy::ReplaySafe,
            ..spl_transport::RequestOptions::default()
        };

        let err = client
            .request("GET", "/healthz", &[], b"", options)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                spl_transport::RequestError::Transport(TransportError::Mux(_))
            ),
            "journal first: {journal_first}: {err:?}"
        );
        assert_eq!(
            client.unknown_journals().len(),
            1,
            "journal first: {journal_first}"
        );
        assert_eq!(
            handled.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "journal first: {journal_first}"
        );
        impostor.abort();
        journal_task.abort();
    }
}

// A TLS 1.3 journal's verdict on the client certificate arrives after the dial, so an alert read
// during the dial is not trusted. Falsified by classifying dial-time alerts: the request stops on
// the first attempt with a terminal refusal.
#[tokio::test]
#[expect(
    clippy::large_futures,
    reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
)]
async fn transport_client_request_dial_time_alert_is_not_a_verdict() {
    for description in [49, 46] {
        let (cert, _) = self_signed();
        let pin = spl_core::ca::sha256(cert.as_ref())[..16].to_vec();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut header = [0u8; 5];
            stream.read_exact(&mut header).await.unwrap();
            let mut hello = vec![0u8; u16::from_be_bytes([header[3], header[4]]) as usize];
            stream.read_exact(&mut hello).await.unwrap();
            stream
                .write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, description])
                .await
                .unwrap();
            stream.flush().await.unwrap();
        });

        let obs = spl_transport::OperationObserver::new();
        let cred = transport_credential(pin, port);
        let client = TransportClient::new(cred, None).unwrap();
        let options = spl_transport::RequestOptions {
            response_cap: 1024 * 1024,
            replay: spl_transport::ReplayPolicy::ForbidAfterWrite,
            observer: Some(&obs),
        };

        let err = client
            .request("GET", "/healthz", &[], b"", options)
            .await
            .unwrap_err();

        assert!(
            !matches!(
                err,
                spl_transport::RequestError::Transport(
                    TransportError::TlsAccessDenied | TransportError::TlsCertificateUnknown
                )
            ),
            "alert {description}: {err:?}"
        );
        assert!(obs.dial_attempts() > 1, "alert {description}");

        server.await.unwrap();
    }
}

#[tokio::test]
#[expect(
    clippy::large_futures,
    reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
)]
async fn transport_client_request_replay_safe_retries_on_backup_endpoint() {
    let (cert, key) = self_signed();
    let pin = spl_core::ca::sha256(cert.as_ref())[..16].to_vec();
    let acceptor = TlsAcceptor::from(Arc::new(server_config(cert, key)));

    // First listener accepts, reads partial request, then drops stream
    let listener1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port1 = listener1.local_addr().unwrap().port();
    let acceptor1 = acceptor.clone();
    let server1 = tokio::spawn(async move {
        let (tcp, _) = listener1.accept().await.unwrap();
        let mut tls = acceptor1.accept(tcp).await.unwrap();
        let mut buf = [0u8; 1024];
        let _ = tls.read(&mut buf).await.unwrap();
        drop(tls);
    });

    // Second listener serves valid response
    let listener2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port2 = listener2.local_addr().unwrap().port();
    let server2 = tokio::spawn(async move {
        serve_one(listener2, acceptor).await;
    });

    let mut cred = transport_credential(pin, port1);
    cred.endpoints = vec![
        EndpointAddr {
            host: "127.0.0.1".into(),
            port: port1,
        },
        EndpointAddr {
            host: "127.0.0.1".into(),
            port: port2,
        },
    ];

    let client = TransportClient::new(cred, None).unwrap();
    let obs = spl_transport::OperationObserver::new();
    let options = spl_transport::RequestOptions {
        response_cap: 1024 * 1024,
        replay: spl_transport::ReplayPolicy::ReplaySafe,
        observer: Some(&obs),
    };

    let outcome = client
        .request("POST", "/test", &[], b"hello", options)
        .await
        .unwrap();

    assert_eq!(outcome.response.status, 200);
    assert_eq!(outcome.path, spl_transport::SelectedPath::Direct);
    assert_eq!(outcome.attempts, 2);
    assert_eq!(obs.dial_attempts(), 2);

    server1.await.unwrap();
    server2.await.unwrap();
}

#[tokio::test]
#[expect(
    clippy::large_futures,
    reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
)]
async fn transport_client_request_exact_response_cap_succeeds() {
    let (cert, key) = self_signed();
    let pin = spl_core::ca::sha256(cert.as_ref())[..16].to_vec();
    let acceptor = TlsAcceptor::from(Arc::new(server_config(cert, key)));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = tokio::spawn(async move {
        serve_one_response(listener, acceptor, "200 OK", b"0123456789").await
    });

    let cred = transport_credential(pin, port);
    let client = TransportClient::new(cred, None).unwrap();
    let options = spl_transport::RequestOptions {
        response_cap: 81,
        replay: spl_transport::ReplayPolicy::ForbidAfterWrite,
        observer: None,
    };

    let outcome = client
        .request("GET", "/healthz", &[], b"", options)
        .await
        .unwrap();

    assert_eq!(outcome.response.status, 200);
    assert_eq!(outcome.response.body, b"0123456789");
    server.await.unwrap();
}

#[tokio::test]
#[expect(
    clippy::large_futures,
    reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
)]
async fn transport_client_request_early_413_path_selected_and_close_not_completed() {
    let (cert, key) = self_signed();
    let pin = spl_core::ca::sha256(cert.as_ref())[..16].to_vec();
    let acceptor = TlsAcceptor::from(Arc::new(server_config(cert, key)));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.unwrap();
        let mut buf = [0u8; 1024];
        let n = tls.read(&mut buf).await.unwrap();
        assert!(n > 9);
        let resp = b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n";
        let frame = Frame::new(1, FLAG_DATA | FLAG_CLOSE, resp.to_vec());
        tls.write_all(&frame.encode().unwrap()).await.unwrap();
        tls.flush().await.unwrap();
        let _ = tls.shutdown().await;
    });

    let cred = transport_credential(pin, port);
    let client = TransportClient::new(cred, None).unwrap();
    let obs = spl_transport::OperationObserver::new();
    let options = spl_transport::RequestOptions {
        response_cap: 1024 * 1024,
        replay: spl_transport::ReplayPolicy::ForbidAfterWrite,
        observer: Some(&obs),
    };

    let big_body = vec![b'a'; 2 * 1024 * 1024];
    let outcome = client
        .request("POST", "/upload", &[], &big_body, options)
        .await
        .unwrap();

    assert_eq!(outcome.response.status, 413);
    assert_eq!(outcome.path, spl_transport::SelectedPath::Direct);
    assert_eq!(obs.direct_successes(), 1);
    assert_eq!(
        obs.selected_path(),
        Some(spl_transport::SelectedPath::Direct)
    );
    assert!(!obs.close_completed());

    server.await.unwrap();
}

#[tokio::test]
#[expect(
    clippy::large_futures,
    reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
)]
async fn transport_client_request_http_404_and_500_select_path() {
    let (cert, key) = self_signed();
    let pin = spl_core::ca::sha256(cert.as_ref())[..16].to_vec();
    let acceptor = TlsAcceptor::from(Arc::new(server_config(cert, key)));

    let listener_404 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port_404 = listener_404.local_addr().unwrap().port();
    let acceptor_404 = acceptor.clone();
    let server_404 = tokio::spawn(async move {
        serve_one_response(listener_404, acceptor_404, "404 Not Found", b"not found").await;
    });

    let cred_404 = transport_credential(pin.clone(), port_404);
    let client_404 = TransportClient::new(cred_404, None).unwrap();
    let obs_404 = spl_transport::OperationObserver::new();
    let options_404 = spl_transport::RequestOptions {
        response_cap: 1024 * 1024,
        replay: spl_transport::ReplayPolicy::ForbidAfterWrite,
        observer: Some(&obs_404),
    };
    let outcome_404 = client_404
        .request("GET", "/missing", &[], b"", options_404)
        .await
        .unwrap();
    assert_eq!(outcome_404.response.status, 404);
    assert_eq!(outcome_404.path, spl_transport::SelectedPath::Direct);
    assert_eq!(obs_404.direct_successes(), 1);
    assert_eq!(
        obs_404.selected_path(),
        Some(spl_transport::SelectedPath::Direct)
    );
    server_404.await.unwrap();

    let listener_500 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port_500 = listener_500.local_addr().unwrap().port();
    let server_500 = tokio::spawn(async move {
        serve_one_response(
            listener_500,
            acceptor,
            "500 Internal Server Error",
            b"server error",
        )
        .await;
    });

    let cred_500 = transport_credential(pin, port_500);
    let client_500 = TransportClient::new(cred_500, None).unwrap();
    let obs_500 = spl_transport::OperationObserver::new();
    let options_500 = spl_transport::RequestOptions {
        response_cap: 1024 * 1024,
        replay: spl_transport::ReplayPolicy::ForbidAfterWrite,
        observer: Some(&obs_500),
    };
    let outcome_500 = client_500
        .request("GET", "/error", &[], b"", options_500)
        .await
        .unwrap();
    assert_eq!(outcome_500.response.status, 500);
    assert_eq!(outcome_500.path, spl_transport::SelectedPath::Direct);
    assert_eq!(obs_500.direct_successes(), 1);
    assert_eq!(
        obs_500.selected_path(),
        Some(spl_transport::SelectedPath::Direct)
    );
    server_500.await.unwrap();
}

#[tokio::test]
async fn direct_pair_observed_multiple_candidates_records_attempts_and_path() {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    ca_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    let signing_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let signing_cert = ca_params.self_signed(&signing_key).unwrap();

    let (server_cert, server_key) = self_signed();
    let server_pin = spl_core::ca::sha256(server_cert.as_ref())[..16].to_vec();
    let acceptor = TlsAcceptor::from(Arc::new(server_config(server_cert, server_key)));

    // Closed port for first candidate
    let unused_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_port = unused_listener.local_addr().unwrap().port();
    drop(unused_listener);

    // Second candidate is valid
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let valid_port = listener.local_addr().unwrap().port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let accepts_clone = accepts.clone();
    let server = tokio::spawn(serve_one_pair_response_counted(
        listener,
        acceptor,
        signing_cert,
        signing_key,
        PairCertificateMode::SubmittedCsr,
        Some(accepts_clone),
    ));

    let nonce = PAIR_EXAMPLE_NONCE;
    let label = PAIR_EXAMPLE_DEVICE_LABEL;
    let endpoints = [
        spl_core::pairlink::Endpoint {
            host: "127.0.0.1".to_owned(),
            port: closed_port,
        },
        spl_core::pairlink::Endpoint {
            host: "127.0.0.1".to_owned(),
            port: valid_port,
        },
    ];

    let obs = spl_transport::OperationObserver::new();
    let credential = spl_transport::pairing::pair_observed(
        &endpoints,
        nonce,
        &server_pin,
        label,
        &serde_json::Map::new(),
        Some(&obs),
    )
    .await
    .unwrap();

    assert_eq!(credential.instance_id, PAIR_EXAMPLE_INSTANCE_ID);
    assert_eq!(accepts.load(Ordering::SeqCst), 1);
    assert_eq!(obs.dial_attempts(), 2);
    assert_eq!(obs.direct_successes(), 1);
    assert_eq!(obs.relay_successes(), 0);
    assert_eq!(
        obs.selected_path(),
        Some(spl_transport::SelectedPath::Direct)
    );
    assert_eq!(obs.request_bytes_sent(), 0);
    assert!(!obs.legacy_enrollment_possible());
    assert_eq!(
        obs.snapshot(),
        spl_transport::OperationSnapshot {
            dial_attempts: 2,
            direct_successes: 1,
            relay_successes: 0,
            request_bytes_sent: 0,
            close_completed: false,
            selected_path: Some(spl_transport::SelectedPath::Direct),
            enrollment_events: 0,
            legacy_enrollment_possible: false,
        }
    );

    server.await.unwrap();
}

#[tokio::test]
async fn direct_pair_observed_non_2xx_sets_success_not_path() {
    let (server_cert, server_key) = self_signed();
    let server_pin = spl_core::ca::sha256(server_cert.as_ref())[..16].to_vec();
    let acceptor = TlsAcceptor::from(Arc::new(server_config(server_cert, server_key)));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let accepts = Arc::new(AtomicUsize::new(0));
    let accepts_clone = accepts.clone();
    let server = tokio::spawn(serve_one_custom_pair_response_counted(
        listener,
        acceptor,
        "403 Forbidden",
        b"{\"error\":\"forbidden\"}".to_vec(),
        Some(accepts_clone),
    ));

    let nonce = PAIR_EXAMPLE_NONCE;
    let label = PAIR_EXAMPLE_DEVICE_LABEL;
    let endpoints = [spl_core::pairlink::Endpoint {
        host: "127.0.0.1".to_owned(),
        port,
    }];

    let obs = spl_transport::OperationObserver::new();
    let result = spl_transport::pairing::pair_observed(
        &endpoints,
        nonce,
        &server_pin,
        label,
        &serde_json::Map::new(),
        Some(&obs),
    )
    .await;

    assert!(result.is_err());
    assert_eq!(accepts.load(Ordering::SeqCst), 1);
    assert_eq!(obs.dial_attempts(), 1);
    assert_eq!(obs.direct_successes(), 1);
    assert_eq!(obs.relay_successes(), 0);
    assert_eq!(obs.selected_path(), None);
    assert!(!obs.legacy_enrollment_possible());

    server.await.unwrap();
}

#[tokio::test]
async fn direct_pair_observed_malformed_body_sets_success_not_path() {
    let (server_cert, server_key) = self_signed();
    let server_pin = spl_core::ca::sha256(server_cert.as_ref())[..16].to_vec();
    let acceptor = TlsAcceptor::from(Arc::new(server_config(server_cert, server_key)));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let accepts = Arc::new(AtomicUsize::new(0));
    let accepts_clone = accepts.clone();
    let server = tokio::spawn(serve_one_custom_pair_response_counted(
        listener,
        acceptor,
        "200 OK",
        b"not-json-content".to_vec(),
        Some(accepts_clone),
    ));

    let nonce = PAIR_EXAMPLE_NONCE;
    let label = PAIR_EXAMPLE_DEVICE_LABEL;
    let endpoints = [spl_core::pairlink::Endpoint {
        host: "127.0.0.1".to_owned(),
        port,
    }];

    let obs = spl_transport::OperationObserver::new();
    let result = spl_transport::pairing::pair_observed(
        &endpoints,
        nonce,
        &server_pin,
        label,
        &serde_json::Map::new(),
        Some(&obs),
    )
    .await;

    assert!(result.is_err());
    assert_eq!(accepts.load(Ordering::SeqCst), 1);
    assert_eq!(obs.dial_attempts(), 1);
    assert_eq!(obs.direct_successes(), 1);
    assert_eq!(obs.relay_successes(), 0);
    assert_eq!(obs.selected_path(), None);

    server.await.unwrap();
}

#[tokio::test]
async fn direct_pair_observed_unrelated_key_sets_success_not_path() {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    ca_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    let signing_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let signing_cert = ca_params.self_signed(&signing_key).unwrap();

    let (server_cert, server_key) = self_signed();
    let server_pin = spl_core::ca::sha256(server_cert.as_ref())[..16].to_vec();
    let acceptor = TlsAcceptor::from(Arc::new(server_config(server_cert, server_key)));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let accepts = Arc::new(AtomicUsize::new(0));
    let accepts_clone = accepts.clone();
    let server = tokio::spawn(serve_one_pair_response_counted(
        listener,
        acceptor,
        signing_cert,
        signing_key,
        PairCertificateMode::UnrelatedKey,
        Some(accepts_clone),
    ));

    let nonce = PAIR_EXAMPLE_NONCE;
    let label = PAIR_EXAMPLE_DEVICE_LABEL;
    let endpoints = [spl_core::pairlink::Endpoint {
        host: "127.0.0.1".to_owned(),
        port,
    }];

    let obs = spl_transport::OperationObserver::new();
    let result = spl_transport::pairing::pair_observed(
        &endpoints,
        nonce,
        &server_pin,
        label,
        &serde_json::Map::new(),
        Some(&obs),
    )
    .await;

    assert!(result.is_err());
    assert_eq!(accepts.load(Ordering::SeqCst), 1);
    assert_eq!(obs.dial_attempts(), 1);
    assert_eq!(obs.direct_successes(), 1);
    assert_eq!(obs.relay_successes(), 0);
    assert_eq!(obs.selected_path(), None);

    server.await.unwrap();
}

#[tokio::test]
#[expect(
    clippy::large_futures,
    reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
)]
async fn transport_client_request_failure_after_tls_accept_sets_no_success_and_path_none() {
    let (cert, key) = self_signed();
    let pin = spl_core::ca::sha256(cert.as_ref())[..16].to_vec();
    let acceptor = TlsAcceptor::from(Arc::new(server_config(cert, key)));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let accepts = Arc::new(AtomicUsize::new(0));
    let accepts_clone = accepts.clone();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        accepts_clone.fetch_add(1, Ordering::SeqCst);
        let mut tls = acceptor.accept(tcp).await.unwrap();
        let mut buf = [0u8; 128];
        let _ = tls.read(&mut buf).await;
        // Drop and shutdown TLS without sending HTTP response frames
        let _ = tls.shutdown().await;
    });

    let cred = transport_credential(pin, port);
    let client = TransportClient::new(cred, None).unwrap();
    let obs = spl_transport::OperationObserver::new();
    let options = spl_transport::RequestOptions {
        response_cap: 1024 * 1024,
        replay: spl_transport::ReplayPolicy::ForbidAfterWrite,
        observer: Some(&obs),
    };

    let result = client
        .request("POST", "/test", &[], b"payload", options)
        .await;
    assert!(result.is_err());
    assert_eq!(accepts.load(Ordering::SeqCst), 1);
    assert_eq!(obs.direct_successes(), 0);
    assert_eq!(obs.selected_path(), None);

    server.await.unwrap();
}
