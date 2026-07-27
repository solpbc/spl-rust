// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

#![expect(
    clippy::unwrap_used,
    reason = "the copied integration test uses unwraps to keep harness failures at their exact setup or assertion site"
)]

//! Relay pairing ceremony integration coverage over loopback TLS and WebSocket peers.

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use futures_util::{SinkExt, StreamExt};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, ExtendedKeyUsagePurpose,
    IsCa, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::json;
use spl_core::PairRequest;
use spl_core::frame::{FLAG_CLOSE, FLAG_DATA, Frame, FrameDecoder};
use spl_core::pairlink::RelayPairLink;
use spl_transport::client::TransportClient;
use spl_transport::credential::EndpointAddr;
use spl_transport::relay_pairing::{enroll_device, pair_over_relay};
use spl_transport::relay_token::{RefreshOutcome, refresh_device_token};
use spl_transport::{RelayControlEndpoint, TransportError, transport_error_code};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{WebSocketStream, accept_async};

const PAIR_SECRET: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
const PAIR_SECRET_HEX: &str = "0123456789abcdef";
// Exemplar request values from `.proto-ref/pairing.md` §5.
const PAIR_EXAMPLE_NONCE: &str = "5f0d8c8b9f1e48b0a5f80b98f3d5e9b0";
const PAIR_EXAMPLE_DEVICE_LABEL: &str = "Jer iPhone";
const CURRENT_TOKEN: &str = "e30.eyJpYXQiOjEwMCwiZXhwIjoyMDB9.sig";
const NEW_TOKEN: &str = "e30.eyJpYXQiOjMwMCwiZXhwIjo0MDB9.sig";
const ENROLL_TOKEN: &str = "e30.eyJpYXQiOjEwMCwiZXhwIjo5OTk5OTk5OTk5fQ.sig";

struct TestCa {
    cert: rcgen::Certificate,
    key: KeyPair,
}

impl TestCa {
    fn new() -> Self {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        params.key_usages.push(KeyUsagePurpose::CrlSign);
        let cert = params.self_signed(&key).unwrap();
        Self { cert, key }
    }

    fn spki_pin(&self) -> Vec<u8> {
        let spki = spl_core::ca::extract_spki_der(self.cert.der()).unwrap();
        spl_core::ca::sha256(&spki)[..16].to_vec()
    }

    fn cert_der_pin(&self) -> Vec<u8> {
        spl_core::ca::sha256(self.cert.der())[..16].to_vec()
    }
}

fn leaf_config(signer: &TestCa) -> ServerConfig {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(vec!["spl.local".to_string()]).unwrap();
    params.is_ca = IsCa::NoCa;
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    let cert = params.signed_by(&key, &signer.cert, &signer.key).unwrap();
    ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![
                CertificateDer::from(cert.der().to_vec()),
                CertificateDer::from(signer.cert.der().to_vec()),
            ],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap()
}

#[derive(Clone)]
enum HomeMode {
    Ok,
    NoLocalEndpoints,
    Reject { status: u16, body: &'static [u8] },
    MissingHomeAttestation,
    UnrelatedClientKey,
}

struct MockState {
    json_ca: Arc<TestCa>,
    tls_signer: Arc<TestCa>,
    home_mode: HomeMode,
    pair_instance_id: Mutex<Option<String>>,
    enroll_status: Mutex<Option<u16>>,
    enroll_hits: AtomicUsize,
    refresh_status: Mutex<Option<u16>>,
    refresh_hits: AtomicUsize,
    session_dials: AtomicUsize,
    dial_target: Mutex<Option<String>>,
    dial_authorization: Mutex<Option<String>>,
    expected_pair_token: Mutex<String>,
    pair_request: Mutex<Option<PairRequest>>,
}

impl MockState {
    fn normal() -> Self {
        let ca = Arc::new(TestCa::new());
        Self {
            json_ca: ca,
            tls_signer: Arc::new(TestCa::new()),
            home_mode: HomeMode::Ok,
            pair_instance_id: Mutex::new(None),
            enroll_status: Mutex::new(None),
            enroll_hits: AtomicUsize::new(0),
            refresh_status: Mutex::new(None),
            refresh_hits: AtomicUsize::new(0),
            session_dials: AtomicUsize::new(0),
            dial_target: Mutex::new(None),
            dial_authorization: Mutex::new(None),
            expected_pair_token: Mutex::new(PAIR_SECRET_HEX.to_owned()),
            pair_request: Mutex::new(None),
        }
    }

    fn with_same_tls_ca(mut self) -> Self {
        self.tls_signer = self.json_ca.clone();
        self
    }
}

fn relay_link(origin: String, ca_fp_spki: Vec<u8>) -> RelayPairLink {
    RelayPairLink {
        s: PAIR_SECRET,
        ca_fp_spki,
        relay_origin: origin,
    }
}

fn jid_for_ca(ca: &TestCa) -> String {
    let spki = spl_core::ca::extract_spki_der(ca.cert.der()).unwrap();
    spl_core::relay_window::jid_from_spki(&spki).unwrap()
}

async fn spawn_mock_relay(state: Arc<MockState>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let state = state.clone();
            tokio::spawn(async move {
                let _ = handle_connection(tcp, state).await;
            });
        }
    });
    origin
}

async fn handle_connection(tcp: TcpStream, state: Arc<MockState>) -> io::Result<()> {
    let mut peek = [0u8; 512];
    let n = tcp.peek(&mut peek).await?;
    if String::from_utf8_lossy(&peek[..n]).starts_with("GET ") {
        handle_ws(tcp, state).await
    } else {
        handle_http(tcp, state).await
    }
}

async fn handle_ws(tcp: TcpStream, state: Arc<MockState>) -> io::Result<()> {
    let mut peek = [0u8; 1024];
    let n = tcp.peek(&mut peek).await?;
    let request = String::from_utf8_lossy(&peek[..n]);
    let target = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_string();
    let authorization = request.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("authorization")
            .then(|| value.trim().to_string())
    });
    let ws = accept_async(tcp).await.map_err(io::Error::other)?;
    let (relay_side, home_side) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        let _ = pump_ws(ws, relay_side).await;
    });
    if target.starts_with("/session/dial?") {
        state.session_dials.fetch_add(1, Ordering::SeqCst);
        *state.dial_target.lock().unwrap() = Some(target);
        *state.dial_authorization.lock().unwrap() = authorization;
        serve_home_carrier(home_side, state).await
    } else {
        serve_home_pair(home_side, state).await
    }
}

async fn pump_ws(ws: WebSocketStream<TcpStream>, relay_side: DuplexStream) -> io::Result<()> {
    let (mut ws_sink, mut ws_stream) = ws.split();
    let (mut relay_read, mut relay_write) = tokio::io::split(relay_side);

    let to_inner = async move {
        while let Some(message) = ws_stream.next().await {
            match message.map_err(io::Error::other)? {
                Message::Binary(bytes) => {
                    relay_write.write_all(&bytes).await?;
                    relay_write.flush().await?;
                }
                Message::Close(_) => {
                    let _ = relay_write.shutdown().await;
                    return Ok(());
                }
                Message::Ping(_) | Message::Pong(_) => {}
                Message::Text(_) | Message::Frame(_) => {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "bad ws message"));
                }
            }
        }
        Ok(())
    };

    let to_ws = async move {
        let mut buf = [0u8; 4096];
        loop {
            let n = relay_read.read(&mut buf).await?;
            if n == 0 {
                let _ = ws_sink.close().await;
                return Ok(());
            }
            ws_sink
                .send(Message::Binary(buf[..n].to_vec().into()))
                .await
                .map_err(io::Error::other)?;
        }
    };

    tokio::select! {
        result = to_inner => result,
        result = to_ws => result,
    }
}

async fn handle_http(mut tcp: TcpStream, state: Arc<MockState>) -> io::Result<()> {
    let raw = read_http_request(&mut tcp).await?;
    let text = String::from_utf8_lossy(&raw);
    let path = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");

    if path == "/enroll/device" {
        state.enroll_hits.fetch_add(1, Ordering::SeqCst);
        let status = *state.enroll_status.lock().unwrap();
        match status {
            Some(status) => write_json(&mut tcp, status, json!({"error":"rejected"})).await?,
            None => write_json(&mut tcp, 200, json!({"device_token":ENROLL_TOKEN})).await?,
        }
    } else if path == "/token/refresh" {
        state.refresh_hits.fetch_add(1, Ordering::SeqCst);
        let status = *state.refresh_status.lock().unwrap();
        match status {
            Some(401) => write_json(&mut tcp, 401, json!({"reason":"expired"})).await?,
            Some(status) => write_json(&mut tcp, status, json!({"error":"rejected"})).await?,
            None => write_json(&mut tcp, 200, json!({"device_token":NEW_TOKEN})).await?,
        }
    } else {
        write_json(&mut tcp, 404, json!({"error":"not_found"})).await?;
    }
    let _ = tcp.shutdown().await;
    Ok(())
}

async fn read_http_request<S>(stream: &mut S) -> io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Ok(raw);
        }
        raw.extend_from_slice(&buf[..n]);
        if request_complete(&raw) {
            return Ok(raw);
        }
    }
}

fn request_complete(raw: &[u8]) -> bool {
    let Some(split) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let head = String::from_utf8_lossy(&raw[..split]);
    let len = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    raw.len() >= split + 4 + len
}

async fn write_json<S>(stream: &mut S, status: u16, body: serde_json::Value) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let body = body.to_string();
    let reason = if status == 200 { "OK" } else { "ERR" };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

async fn serve_home_pair(stream: DuplexStream, state: Arc<MockState>) -> io::Result<()> {
    let acceptor = TlsAcceptor::from(Arc::new(leaf_config(state.tls_signer.as_ref())));
    let mut tls = acceptor.accept(stream).await.map_err(io::Error::other)?;
    let request = read_pl_request(&mut tls).await?;

    if let HomeMode::Reject { status, body } = &state.home_mode {
        write_pl_response_bytes(&mut tls, *status, body).await?;
        return Ok(());
    }

    let request_text = String::from_utf8_lossy(&request);
    let expected_pair_token = state.expected_pair_token.lock().unwrap().clone();
    assert!(request_text.starts_with(&format!(
        "POST /app/network/pair?token={expected_pair_token} "
    )));
    let body = request
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|split| &request[split + 4..])
        .unwrap();
    let pair_request: PairRequest = serde_json::from_slice(body).unwrap();
    *state.pair_request.lock().unwrap() = Some(pair_request.clone());
    let client_cert = if matches!(state.home_mode, HomeMode::UnrelatedClientKey) {
        let unrelated_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        CertificateParams::new(Vec::<String>::new())
            .unwrap()
            .signed_by(&unrelated_key, &state.json_ca.cert, &state.json_ca.key)
            .unwrap()
    } else {
        CertificateSigningRequestParams::from_pem(&pair_request.csr)
            .unwrap()
            .signed_by(&state.json_ca.cert, &state.json_ca.key)
            .unwrap()
    };
    let fingerprint = format!("sha256:{}", spl_core::ca::sha256_hex(client_cert.der()));

    let instance_id = state
        .pair_instance_id
        .lock()
        .unwrap()
        .clone()
        .unwrap_or_else(|| jid_for_ca(state.json_ca.as_ref()));
    let mut response = json!({
        "client_cert": client_cert.pem(),
        "ca_chain": [state.json_ca.cert.pem()],
        "instance_id": instance_id,
        "home_label": "Home",
        "fingerprint": fingerprint
    });
    if !matches!(state.home_mode, HomeMode::NoLocalEndpoints) {
        response["local_endpoints"] = json!([{"ip":"10.0.0.2","port":7657,"scope":"lan"}]);
    }
    if !matches!(state.home_mode, HomeMode::MissingHomeAttestation) {
        response["home_attestation"] = json!("attestation");
    }
    write_pl_response(&mut tls, 200, response).await
}

async fn serve_home_carrier(stream: DuplexStream, state: Arc<MockState>) -> io::Result<()> {
    let acceptor = TlsAcceptor::from(Arc::new(leaf_config(state.tls_signer.as_ref())));
    let mut tls = acceptor.accept(stream).await.map_err(io::Error::other)?;
    let mut buf = [0u8; 4096];
    while tls.read(&mut buf).await? != 0 {}
    Ok(())
}

async fn read_pl_request<S>(tls: &mut S) -> io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut decoder = FrameDecoder::new();
    let mut request = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = tls.read(&mut buf).await?;
        if n == 0 {
            return Ok(request);
        }
        decoder.feed(&buf[..n]);
        for frame in decoder.drain().unwrap() {
            if frame.flags & FLAG_DATA != 0 {
                request.extend_from_slice(&frame.payload);
            }
            if frame.flags & FLAG_CLOSE != 0 {
                return Ok(request);
            }
        }
    }
}

async fn write_pl_response<S>(tls: &mut S, status: u16, body: serde_json::Value) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let body = body.to_string();
    write_pl_response_bytes(tls, status, body.as_bytes()).await
}

async fn write_pl_response_bytes<S>(tls: &mut S, status: u16, body: &[u8]) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let status_text = if status == 200 { "OK" } else { "ERR" };
    let response_head = format!(
        "HTTP/1.1 {status} {status_text}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
        body.len()
    );
    let mut response = response_head.into_bytes();
    response.extend_from_slice(body);
    let frame = Frame::new(1, FLAG_DATA | FLAG_CLOSE, response);
    tls.write_all(&frame.encode().unwrap()).await?;
    tls.flush().await?;
    let _ = tls.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn relay_pairing_full_ceremony_populates_credential() {
    let state = Arc::new(MockState::normal().with_same_tls_ca());
    let origin = spawn_mock_relay(state.clone()).await;
    let link = relay_link(origin.clone(), state.json_ca.spki_pin());

    #[expect(
        clippy::large_futures,
        reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
    )]
    let credential = pair_over_relay(&link, "win-test", &serde_json::Map::new())
        .await
        .unwrap();

    assert_eq!(credential.relay_origin.as_deref(), Some(origin.as_str()));
    assert_eq!(credential.instance_id, jid_for_ca(state.json_ca.as_ref()));
    assert_eq!(credential.device_token.as_deref(), Some(ENROLL_TOKEN));
    assert_eq!(credential.device_token_expires_at, Some(9_999_999_999));
    assert!(credential.client_key_pem.contains("BEGIN PRIVATE KEY"));
    assert!(credential.client_cert_pem.contains("BEGIN CERTIFICATE"));
    assert_eq!(credential.ca_chain_pem.len(), 1);
    assert_eq!(credential.ca_fp_prefix, state.json_ca.cert_der_pin());
    assert_eq!(
        credential.endpoints,
        vec![EndpointAddr {
            host: "10.0.0.2".into(),
            port: 7657
        }]
    );
    assert_eq!(credential.home_attestation.as_deref(), Some("attestation"));
    assert_eq!(
        credential.local_endpoints,
        Some(json!([{"ip":"10.0.0.2","port":7657,"scope":"lan"}]))
    );
}

#[tokio::test]
async fn relay_enrollment_builds_relay_only_persistent_carrier_through_public_api() {
    let mut mock = MockState::normal().with_same_tls_ca();
    mock.home_mode = HomeMode::NoLocalEndpoints;
    let state = Arc::new(mock);
    let origin = spawn_mock_relay(state.clone()).await;
    let link = relay_link(origin.clone(), state.json_ca.spki_pin());

    #[expect(
        clippy::large_futures,
        reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
    )]
    let mut credential = pair_over_relay(&link, "resident-test", &serde_json::Map::new())
        .await
        .unwrap();
    assert!(credential.endpoints.is_empty());

    #[expect(
        clippy::large_futures,
        reason = "the public enrollment future keeps the transport harness stack layout visible at its assertion site"
    )]
    let token = enroll_device(
        &origin,
        &credential.instance_id,
        credential.home_attestation.as_deref().unwrap(),
    )
    .await
    .unwrap();
    credential.device_token_expires_at =
        spl_core::jwt::decode_unverified_claims(&token).map(|claims| claims.exp);
    credential.device_token = Some(token.clone());

    let client = TransportClient::new_relay_only(credential, None).unwrap();
    #[expect(
        clippy::large_futures,
        reason = "the public carrier dial keeps the transport harness stack layout visible at its assertion site"
    )]
    let carrier = client.dial_carrier().await.unwrap();

    assert_eq!(state.enroll_hits.load(Ordering::SeqCst), 2);
    assert_eq!(state.session_dials.load(Ordering::SeqCst), 1);
    assert_eq!(
        state.dial_authorization.lock().unwrap().as_deref(),
        Some(format!("Bearer {token}").as_str())
    );
    assert!(
        state
            .dial_target
            .lock()
            .unwrap()
            .as_deref()
            .is_some_and(|target| target.contains(&credential_instance_query(&state)))
    );
    drop(carrier);
}

fn credential_instance_query(state: &MockState) -> String {
    format!("instance={}", jid_for_ca(state.json_ca.as_ref()))
}

#[tokio::test]
async fn observer_contract_authority_relay_pairing_uses_real_ceremony() {
    let nonce = PAIR_EXAMPLE_NONCE;
    let mut secret = [0u8; 8];
    for (index, byte) in secret.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&nonce[index * 2..index * 2 + 2], 16).unwrap();
    }
    let state = Arc::new(MockState::normal().with_same_tls_ca());
    *state.expected_pair_token.lock().unwrap() = nonce[..16].to_owned();
    let origin = spawn_mock_relay(state.clone()).await;
    let link = RelayPairLink {
        s: secret,
        ca_fp_spki: state.json_ca.spki_pin(),
        relay_origin: origin,
    };
    let device_label = PAIR_EXAMPLE_DEVICE_LABEL;

    #[expect(
        clippy::large_futures,
        reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
    )]
    let credential = pair_over_relay(&link, device_label, &serde_json::Map::new())
        .await
        .unwrap();
    let captured = state.pair_request.lock().unwrap().clone().unwrap();
    assert_eq!(captured.device_label, device_label);
    assert!(captured.csr.contains("BEGIN CERTIFICATE REQUEST"));
    assert!(credential.client_cert_pem.contains("BEGIN CERTIFICATE"));
    assert_eq!(credential.home_label, "Home");
}

#[tokio::test]
async fn observer_contract_authority_pair_from_link_dispatches_relay_ceremony() {
    let nonce = PAIR_EXAMPLE_NONCE;
    let mut secret = [0u8; 8];
    for (index, byte) in secret.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&nonce[index * 2..index * 2 + 2], 16).unwrap();
    }
    let state = Arc::new(MockState::normal().with_same_tls_ca());
    *state.expected_pair_token.lock().unwrap() = nonce[..16].to_owned();
    let origin = spawn_mock_relay(state.clone()).await;
    let origin_bytes = origin.as_bytes();
    let mut blob = vec![0x06];
    blob.extend_from_slice(&secret);
    blob.push(0x01);
    blob.extend_from_slice(&state.json_ca.spki_pin());
    blob.push(u8::try_from(origin_bytes.len()).unwrap());
    blob.extend_from_slice(origin_bytes);
    let link = format!(
        "https://go.solstone.app/p#{}",
        spl_core::crockford::encode(&blob)
    );
    let device_label = PAIR_EXAMPLE_DEVICE_LABEL;

    #[expect(
        clippy::large_futures,
        reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
    )]
    let credential =
        spl_transport::pairing::pair_from_link(&link, device_label, &serde_json::Map::new())
            .await
            .unwrap();
    assert_eq!(
        state
            .pair_request
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .device_label,
        device_label
    );
    assert!(credential.client_cert_pem.contains("BEGIN CERTIFICATE"));
}

#[tokio::test]
async fn linked_system_pair_from_link_forwards_additional_fields_over_relay() {
    let nonce = PAIR_EXAMPLE_NONCE;
    let mut secret = [0u8; 8];
    for (index, byte) in secret.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&nonce[index * 2..index * 2 + 2], 16).unwrap();
    }
    let state = Arc::new(MockState::normal().with_same_tls_ca());
    *state.expected_pair_token.lock().unwrap() = nonce[..16].to_owned();
    let origin = spawn_mock_relay(state.clone()).await;
    let origin_bytes = origin.as_bytes();
    let mut blob = vec![0x06];
    blob.extend_from_slice(&secret);
    blob.push(0x01);
    blob.extend_from_slice(&state.json_ca.spki_pin());
    blob.push(u8::try_from(origin_bytes.len()).unwrap());
    blob.extend_from_slice(origin_bytes);
    let link = format!(
        "https://go.solstone.app/p#{}",
        spl_core::crockford::encode(&blob)
    );
    let device_label = "r".repeat(80);
    let mut additional_fields = serde_json::Map::new();
    additional_fields.insert("sender_instance_id".into(), json!("consumer-instance"));

    #[expect(
        clippy::large_futures,
        reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
    )]
    let credential =
        spl_transport::pairing::pair_from_link(&link, &device_label, &additional_fields)
            .await
            .unwrap();

    let captured = state.pair_request.lock().unwrap().clone().unwrap();
    assert_eq!(
        captured.additional_fields["sender_instance_id"],
        json!("consumer-instance")
    );
    assert_eq!(captured.device_label, device_label);
    assert!(credential.client_cert_pem.contains("BEGIN CERTIFICATE"));
}

#[tokio::test]
async fn relay_pairing_rejects_jid_mismatch_before_enroll() {
    let state = Arc::new(MockState::normal().with_same_tls_ca());
    *state.pair_instance_id.lock().unwrap() =
        Some("00000000-0000-8000-8000-000000000001".to_string());
    let origin = spawn_mock_relay(state.clone()).await;
    let link = relay_link(origin, state.json_ca.spki_pin());

    #[expect(
        clippy::large_futures,
        reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
    )]
    let err = pair_over_relay(&link, "win-test", &serde_json::Map::new())
        .await
        .unwrap_err();
    assert!(matches!(err, TransportError::Pairing(_)));
}

#[tokio::test]
async fn relay_pairing_rejects_anti_pin_theater_leaf() {
    let state = Arc::new(MockState::normal());
    let origin = spawn_mock_relay(state.clone()).await;
    let link = relay_link(origin, state.json_ca.spki_pin());

    #[expect(
        clippy::large_futures,
        reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
    )]
    let err = pair_over_relay(&link, "win-test", &serde_json::Map::new())
        .await
        .unwrap_err();
    assert!(matches!(err, TransportError::Pairing(_)));
}

#[tokio::test]
async fn relay_pairing_rejects_wrong_spki_before_enroll() {
    let state = Arc::new(MockState::normal().with_same_tls_ca());
    let origin = spawn_mock_relay(state.clone()).await;
    let link = relay_link(origin, vec![0u8; 16]);

    #[expect(
        clippy::large_futures,
        reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
    )]
    let err = pair_over_relay(&link, "win-test", &serde_json::Map::new())
        .await
        .unwrap_err();
    assert!(matches!(err, TransportError::Pairing(_)));
}

#[tokio::test]
async fn relay_pairing_inner_410_maps_to_http_410() {
    let mut state = MockState::normal().with_same_tls_ca();
    state.home_mode = HomeMode::Reject {
        status: 410,
        body: br#"{"error":"gone"}"#,
    };
    let state = Arc::new(state);
    let origin = spawn_mock_relay(state.clone()).await;
    let link = relay_link(origin, state.json_ca.spki_pin());

    #[expect(
        clippy::large_futures,
        reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
    )]
    let err = pair_over_relay(&link, "win-test", &serde_json::Map::new())
        .await
        .unwrap_err();
    assert!(matches!(err, TransportError::Rejected { status: 410, .. }));
    assert_eq!(transport_error_code(&err), "http_410");
}

#[tokio::test]
async fn relay_pairing_rejection_displays_only_body_summary() {
    const SENTINEL: &str = "RELAY-PAIR-REJECTION-SENTINEL token=0123456789abcdef private=response";
    let mut state = MockState::normal().with_same_tls_ca();
    state.home_mode = HomeMode::Reject {
        status: 403,
        body: SENTINEL.as_bytes(),
    };
    let state = Arc::new(state);
    let origin = spawn_mock_relay(state.clone()).await;
    let link = relay_link(origin, state.json_ca.spki_pin());
    let expected_digest = spl_core::ca::sha256_hex(SENTINEL.as_bytes());
    let expected_display = format!(
        "server rejected request: HTTP 403 rejection-body bytes={} sha256={}",
        SENTINEL.len(),
        &expected_digest[..12]
    );

    #[expect(
        clippy::large_futures,
        reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
    )]
    let err = pair_over_relay(&link, "win-test", &serde_json::Map::new())
        .await
        .unwrap_err();

    assert_eq!(err.to_string(), expected_display);
    assert!(
        !err.to_string().contains(SENTINEL),
        "relay rejection display reflected sentinel"
    );
}

#[tokio::test]
async fn relay_pairing_rejects_client_certificate_for_unrelated_key() {
    let mut state = MockState::normal().with_same_tls_ca();
    state.home_mode = HomeMode::UnrelatedClientKey;
    let state = Arc::new(state);
    let origin = spawn_mock_relay(state.clone()).await;
    let link = relay_link(origin, state.json_ca.spki_pin());

    #[expect(
        clippy::large_futures,
        reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
    )]
    let result = pair_over_relay(&link, "win-test", &serde_json::Map::new()).await;

    assert!(
        matches!(
            result,
            Err(TransportError::Pairing(message))
                if message == "client certificate public key does not match generated key"
        ),
        "relay pairing accepted a client certificate for an unrelated key"
    );
}

#[tokio::test]
async fn relay_pairing_rejects_missing_home_attestation() {
    let mut state = MockState::normal().with_same_tls_ca();
    state.home_mode = HomeMode::MissingHomeAttestation;
    let state = Arc::new(state);
    let origin = spawn_mock_relay(state.clone()).await;
    let link = relay_link(origin, state.json_ca.spki_pin());

    #[expect(
        clippy::large_futures,
        reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
    )]
    let err = pair_over_relay(&link, "win-test", &serde_json::Map::new())
        .await
        .unwrap_err();
    assert!(matches!(err, TransportError::Pairing(_)));
}

#[tokio::test]
async fn relay_pairing_enroll_statuses_are_control_rejections() {
    for status in [409, 401, 403, 404] {
        let state = Arc::new(MockState::normal().with_same_tls_ca());
        *state.enroll_status.lock().unwrap() = Some(status);
        let origin = spawn_mock_relay(state.clone()).await;
        let link = relay_link(origin, state.json_ca.spki_pin());

        #[expect(
            clippy::large_futures,
            reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
        )]
        let err = pair_over_relay(&link, "win-test", &serde_json::Map::new())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            TransportError::RelayControlRejected {
                endpoint: RelayControlEndpoint::EnrollDevice,
                status: actual
            } if actual == status
        ));
        let code = transport_error_code(&err);
        assert_eq!(code, format!("relay_enroll_device_http_{status}"));
        assert!(!code.contains("attestation"));
    }
}

#[tokio::test]
#[expect(
    clippy::large_futures,
    reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
)]
async fn forced_refresh_reconnect_statuses() {
    for status in [401, 403, 404] {
        let state = Arc::new(MockState::normal().with_same_tls_ca());
        *state.refresh_status.lock().unwrap() = Some(status);
        let origin = spawn_mock_relay(state).await;
        assert_eq!(
            refresh_device_token(&origin, CURRENT_TOKEN).await,
            RefreshOutcome::ReconnectNeeded
        );
    }
}
