// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

#![expect(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "the copied integration tests use explicit panics and unwraps to keep harness failures at their exact setup or assertion site"
)]

//! End-to-end SPL relay carrier tests over a real loopback WebSocket relay.
//!
//! The loopback relay intentionally uses `ws://127.0.0.1` rather than WSS, so it
//! does not exercise the production outer `WebPKI` leg. It is otherwise a dumb
//! opaque pump: WS binary frames are bridged to an in-memory byte stream whose
//! far side runs the same pinned inner TLS + PL framing server used by the LAN
//! round-trip tests.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::danger::ClientCertVerifier;
use rustls::{ClientConfig, ServerConfig};
use serde_json::json;
use spl_core::bridge::BridgeNames;
use spl_core::frame::{
    FLAG_CLOSE, FLAG_DATA, FLAG_OPEN, FLAG_RESET, FLAG_WINDOW, Frame, FrameDecoder,
    RESET_FLOW_CONTROL_ERROR,
};
use spl_core::http::HttpResponse;
use spl_core::mux::INITIAL_WINDOW;
use spl_home::{HomeConfig, MuxLimits};
use spl_transport::client::{DialedCarrier, TokenPersistHook, TransportClient};
use spl_transport::credential::{Credential, EndpointAddr};
use spl_transport::home_relay::{
    HomeRelayClient, HomeRelayClientConfig, RelayEvent, RelayEventSink, RelayJitter, ServiceToken,
};
use spl_transport::journal_bridge::{self, BridgePolicy, CarrierOpener, JournalBridgeConfig};
use spl_transport::relay::{dial_relay_ws, request_once_over_ws, request_once_relay};
use spl_transport::tls::{mtls_config, pairing_config};
use spl_transport::{RelayError, TransportError, transport_error_code};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::{WebSocketStream, accept_async, accept_hdr_async};

const RELAY_TOKEN: &str = "test-device-token";
const INSTANCE_ID: &str = "12345678-1234-5678-1234-567812345678";
const CARRIER_READ_BUF_BYTES: usize = 64 * 1024;
const LARGE_WS_FRAME_BYTES: usize = 256 * 1024;
const LARGE_RESPONSE_BYTES: usize = 512 * 1024 + 137;
const TEST_CAP_COOKIE_NAME: &str = "test-journal-cap";
const TEST_OBSERVER_HEADER_NAME: &str = "x-test-observer";

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

struct HomeTlsFixture {
    ca: CertificateDer<'static>,
    server_chain: Vec<CertificateDer<'static>>,
    server_key: PrivateKeyDer<'static>,
    client_chain: Vec<CertificateDer<'static>>,
    client_key: PrivateKeyDer<'static>,
}

fn home_tls_fixture() -> HomeTlsFixture {
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let ca_der = CertificateDer::from(ca.der().to_vec());

    let server_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut server_params = CertificateParams::new(vec!["spl.local".to_owned()]).unwrap();
    server_params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    let server = server_params.signed_by(&server_key, &ca, &ca_key).unwrap();

    let client_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut client_params = CertificateParams::new(vec!["relay-test".to_owned()]).unwrap();
    client_params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);
    let client = client_params.signed_by(&client_key, &ca, &ca_key).unwrap();
    HomeTlsFixture {
        ca: ca_der.clone(),
        server_chain: vec![CertificateDer::from(server.der().to_vec()), ca_der.clone()],
        server_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
        client_chain: vec![CertificateDer::from(client.der().to_vec()), ca_der],
        client_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(client_key.serialize_der())),
    }
}

fn home_config(fixture: &HomeTlsFixture) -> HomeConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(fixture.ca.clone()).unwrap();
    let verifier: Arc<dyn ClientCertVerifier> =
        rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();
    HomeConfig {
        certificate_chain: fixture.server_chain.clone(),
        private_key: fixture.server_key.clone_key(),
        client_cert_verifier: verifier,
        mux_limits: MuxLimits::default(),
    }
}

struct FixedRelayJitter;

impl RelayJitter for FixedRelayJitter {
    fn sample(&self) -> f64 {
        0.5
    }
}

struct TestRelayEvents;

impl RelayEventSink for TestRelayEvents {
    fn emit(&self, _event: RelayEvent) {}
}

struct DisconnectEvents(AtomicUsize);

impl RelayEventSink for DisconnectEvents {
    fn emit(&self, event: RelayEvent) {
        if matches!(event, RelayEvent::Disconnected) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
}

fn client_config(pin: &[u8]) -> Arc<ClientConfig> {
    Arc::new(pairing_config(pin).unwrap())
}

fn unused_outer_config() -> Arc<ClientConfig> {
    client_config(&[0xAA; 16])
}

fn epoch_secs() -> i64 {
    #[expect(
        clippy::cast_possible_wrap,
        clippy::map_unwrap_or,
        reason = "the copied test clock intentionally falls back to zero and uses the process lifetime's representable epoch range"
    )]
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn base64url_no_pad(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut index = 0;
    while index + 3 <= input.len() {
        let chunk = ((input[index] as u32) << 16)
            | ((input[index + 1] as u32) << 8)
            | input[index + 2] as u32;
        out.push(TABLE[((chunk >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((chunk >> 12) & 0x3F) as usize] as char);
        out.push(TABLE[((chunk >> 6) & 0x3F) as usize] as char);
        out.push(TABLE[(chunk & 0x3F) as usize] as char);
        index += 3;
    }
    match input.len() - index {
        1 => {
            let chunk = (input[index] as u32) << 16;
            out.push(TABLE[((chunk >> 18) & 0x3F) as usize] as char);
            out.push(TABLE[((chunk >> 12) & 0x3F) as usize] as char);
        }
        2 => {
            let chunk = ((input[index] as u32) << 16) | ((input[index + 1] as u32) << 8);
            out.push(TABLE[((chunk >> 18) & 0x3F) as usize] as char);
            out.push(TABLE[((chunk >> 12) & 0x3F) as usize] as char);
            out.push(TABLE[((chunk >> 6) & 0x3F) as usize] as char);
        }
        _ => {}
    }
    out
}

fn mint_jwt(iat: i64, exp: i64) -> String {
    let payload = format!(r#"{{"iat":{iat},"exp":{exp}}}"#);
    format!(
        "{}.{}.sig",
        base64url_no_pad(b"{}"),
        base64url_no_pad(payload.as_bytes())
    )
}

fn relay_credential(
    pin: Vec<u8>,
    lan_port: u16,
    relay_origin: String,
    token: String,
) -> Credential {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let params = CertificateParams::new(vec!["transport.test".to_string()]).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let expires_at = spl_core::jwt::decode_unverified_claims(&token).map(|claims| claims.exp);
    Credential {
        client_key_pem: key.serialize_pem(),
        client_cert_pem: cert.pem(),
        ca_chain_pem: vec![cert.pem()],
        ca_fp_prefix: pin,
        instance_id: INSTANCE_ID.into(),
        home_label: "Home".into(),
        endpoints: vec![EndpointAddr {
            host: "127.0.0.1".into(),
            port: lan_port,
        }],
        home_attestation: None,
        local_endpoints: None,
        relay_origin: Some(relay_origin),
        device_token: Some(token),
        device_token_expires_at: expires_at,
    }
}

fn transport_client(
    credential: Credential,
    token_persist: Option<TokenPersistHook>,
) -> TransportClient {
    TransportClient::new(credential, token_persist).unwrap()
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
        headers.push(("x-test-observer".into(), "test-key".into()));
        headers.push(("x-test-protocol".into(), "2".into()));
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
        observer_header_name: "x-test-observer".into(),
        protocol_version_header_name: "x-test-protocol".into(),
    }
}

async fn start_relay_bridge(
    credential: Credential,
    token_persist: Option<TokenPersistHook>,
) -> journal_bridge::JournalBridgeHandle {
    let client = Arc::new(transport_client(credential, token_persist));
    journal_bridge::start(JournalBridgeConfig {
        opener: Arc::new(TestOpener { client }),
        bridge_names: neutral_bridge_names(),
        endpoint_hosts: vec!["127.0.0.1".into()],
        policy: BridgePolicy::default(),
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

fn loopback_host(port: u16) -> String {
    format!("127.0.0.1:{port}")
}

fn cap_cookie(cap: &str) -> String {
    format!("{TEST_CAP_COOKIE_NAME}={cap}")
}

async fn raw_bridge_request(port: u16, target: &str, cap: &str) -> Vec<u8> {
    raw_bridge_request_with_method(port, "GET", target, cap, &[]).await
}

async fn raw_bridge_request_with_method(
    port: u16,
    method: &str,
    target: &str,
    cap: &str,
    body: &[u8],
) -> Vec<u8> {
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let request = format!(
        "{method} {target} HTTP/1.1\r\nHost: {}\r\nCookie: {}\r\nContent-Length: {}\r\n\r\n",
        loopback_host(port),
        cap_cookie(cap),
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    stream.flush().await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    response
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
    response_text(response)
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
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

async fn pump_ws(
    ws: WebSocketStream<TcpStream>,
    relay_side: DuplexStream,
    capture_first_inbound: Option<Arc<Mutex<Vec<u8>>>>,
) -> io::Result<()> {
    let (mut ws_sink, mut ws_stream) = ws.split();
    let (mut relay_read, mut relay_write) = tokio::io::split(relay_side);

    let to_inner = async move {
        while let Some(message) = ws_stream.next().await {
            match message.map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "relay websocket receive failed")
            })? {
                Message::Binary(bytes) => {
                    if let Some(capture) = &capture_first_inbound {
                        let mut guard = capture.lock().unwrap();
                        if guard.is_empty() {
                            guard.extend_from_slice(&bytes);
                        }
                    }
                    relay_write.write_all(&bytes).await?;
                    relay_write.flush().await?;
                }
                Message::Close(_) => {
                    let _ = relay_write.shutdown().await;
                    return Ok(());
                }
                Message::Ping(_) | Message::Pong(_) => {}
                Message::Text(_) | Message::Frame(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "relay tunnel received non-binary message",
                    ));
                }
            }
        }
        Ok(())
    };

    let to_ws = async move {
        let mut buf = [0u8; 512];
        loop {
            let n = relay_read.read(&mut buf).await?;
            if n == 0 {
                let _ = ws_sink.close().await;
                return Ok(());
            }
            ws_sink
                .send(Message::Binary(buf[..n].to_vec().into()))
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "relay websocket send failed")
                })?;
        }
    };

    tokio::select! {
        result = to_inner => result,
        result = to_ws => result,
    }
}

async fn pump_ws_large_response_frames(
    ws: WebSocketStream<TcpStream>,
    relay_side: DuplexStream,
    large_response_mode: Arc<AtomicBool>,
    sent_frame_sizes: Arc<Mutex<Vec<usize>>>,
) -> io::Result<()> {
    let (mut ws_sink, mut ws_stream) = ws.split();
    let (mut relay_read, mut relay_write) = tokio::io::split(relay_side);

    let to_inner = async move {
        while let Some(message) = ws_stream.next().await {
            match message.map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "relay websocket receive failed")
            })? {
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
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "relay tunnel received non-binary message",
                    ));
                }
            }
        }
        Ok(())
    };

    let to_ws = async move {
        let mut buf = vec![0u8; LARGE_WS_FRAME_BYTES];
        let mut pending = Vec::new();
        loop {
            let n = relay_read.read(&mut buf).await?;
            if n == 0 {
                if !pending.is_empty() {
                    let frame = std::mem::take(&mut pending);
                    sent_frame_sizes.lock().unwrap().push(frame.len());
                    ws_sink
                        .send(Message::Binary(frame.into()))
                        .await
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::BrokenPipe, "relay websocket send failed")
                        })?;
                }
                let _ = ws_sink.close().await;
                return Ok(());
            }

            if !large_response_mode.load(Ordering::SeqCst) {
                ws_sink
                    .send(Message::Binary(buf[..n].to_vec().into()))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "relay websocket send failed")
                    })?;
                continue;
            }

            pending.extend_from_slice(&buf[..n]);
            if pending.len() >= LARGE_WS_FRAME_BYTES {
                let frame = std::mem::take(&mut pending);
                sent_frame_sizes.lock().unwrap().push(frame.len());
                ws_sink
                    .send(Message::Binary(frame.into()))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "relay websocket send failed")
                    })?;
            }
        }
    };

    tokio::select! {
        result = to_inner => result,
        result = to_ws => result,
    }
}

async fn accept_relay_stream(
    listener: TcpListener,
    capture_first_inbound: Option<Arc<Mutex<Vec<u8>>>>,
    duplex_capacity: usize,
) -> DuplexStream {
    let (tcp, _) = listener.accept().await.unwrap();
    let ws = accept_async(tcp).await.unwrap();
    let (relay_side, server_side) = tokio::io::duplex(duplex_capacity);
    tokio::spawn(async move {
        let _ = pump_ws(ws, relay_side, capture_first_inbound).await;
    });
    server_side
}

async fn accept_relay_stream_large_response_frames(
    listener: TcpListener,
    large_response_mode: Arc<AtomicBool>,
    sent_frame_sizes: Arc<Mutex<Vec<usize>>>,
) -> DuplexStream {
    let (tcp, _) = listener.accept().await.unwrap();
    let ws = accept_async(tcp).await.unwrap();
    let (relay_side, server_side) = tokio::io::duplex(LARGE_RESPONSE_BYTES);
    tokio::spawn(async move {
        let _ =
            pump_ws_large_response_frames(ws, relay_side, large_response_mode, sent_frame_sizes)
                .await;
    });
    server_side
}

async fn serve_stream_response<S>(
    stream: S,
    acceptor: TlsAcceptor,
    status: &'static str,
    body: &'static [u8],
) -> Vec<u8>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut tls = acceptor.accept(stream).await.unwrap();

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
                #[expect(
                    clippy::cast_possible_wrap,
                    reason = "the bounded test frame payload is well within i64"
                )]
                let len = frame.payload.len() as i64;
                if len > recv_credit {
                    let reset = Frame::new(stream_id, FLAG_RESET, vec![RESET_FLOW_CONTROL_ERROR]);
                    tls.write_all(&reset.encode().unwrap()).await.unwrap();
                    tls.flush().await.unwrap();
                    return request;
                }
                recv_credit -= len;
                unacked += len;
                request.extend_from_slice(&frame.payload);
                #[expect(
                    clippy::cast_possible_wrap,
                    reason = "the protocol window constant is fixed well within i64"
                )]
                if unacked >= (INITIAL_WINDOW as i64) / 2 {
                    #[expect(
                        clippy::cast_sign_loss,
                        reason = "the nonnegative threshold keeps the grant within the protocol's u32 window"
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

    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        String::from_utf8_lossy(body)
    );
    let frame = Frame::new(stream_id, FLAG_DATA | FLAG_CLOSE, response.into_bytes());
    tls.write_all(&frame.encode().unwrap()).await.unwrap();
    tls.flush().await.unwrap();
    let _ = tls.shutdown().await;
    request
}

async fn serve_stream_large_response<S>(
    stream: S,
    acceptor: TlsAcceptor,
    body: Vec<u8>,
    large_response_mode: Arc<AtomicBool>,
) -> Vec<u8>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut tls = acceptor.accept(stream).await.unwrap();

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

    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(&body);
    let frame = Frame::new(stream_id, FLAG_DATA | FLAG_CLOSE, response);
    large_response_mode.store(true, Ordering::SeqCst);
    tls.write_all(&frame.encode().unwrap()).await.unwrap();
    tls.flush().await.unwrap();
    let _ = tls.shutdown().await;
    request
}

async fn serve_stream_with_flow_control<S>(stream: S, acceptor: TlsAcceptor) -> Vec<u8>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut tls = acceptor.accept(stream).await.unwrap();

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
                    let reset = Frame::new(stream_id, FLAG_RESET, vec![RESET_FLOW_CONTROL_ERROR]);
                    tls.write_all(&reset.encode().unwrap()).await.unwrap();
                    tls.flush().await.unwrap();
                    return request;
                }
                recv_credit -= len;
                unacked += len;
                request.extend_from_slice(&frame.payload);
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

async fn spawn_response_relay(
    acceptor: TlsAcceptor,
    status: &'static str,
    body: &'static [u8],
    capture_first_inbound: Option<Arc<Mutex<Vec<u8>>>>,
    duplex_capacity: usize,
) -> (String, JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let stream = accept_relay_stream(listener, capture_first_inbound, duplex_capacity).await;
        serve_stream_response(stream, acceptor, status, body).await
    });
    (origin, task)
}

async fn spawn_flow_relay(acceptor: TlsAcceptor) -> (String, JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    #[expect(
        clippy::large_futures,
        reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
    )]
    let task = tokio::spawn(async move {
        let stream = accept_relay_stream(listener, None, 1024).await;
        serve_stream_with_flow_control(stream, acceptor).await
    });
    (origin, task)
}

async fn spawn_large_response_relay(
    acceptor: TlsAcceptor,
    body: Vec<u8>,
) -> (String, JoinHandle<Vec<u8>>, Arc<Mutex<Vec<usize>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let large_response_mode = Arc::new(AtomicBool::new(false));
    let sent_frame_sizes = Arc::new(Mutex::new(Vec::new()));
    let task = tokio::spawn({
        let large_response_mode = large_response_mode.clone();
        let sent_frame_sizes = sent_frame_sizes.clone();
        async move {
            let stream = accept_relay_stream_large_response_frames(
                listener,
                large_response_mode.clone(),
                sent_frame_sizes,
            )
            .await;
            serve_stream_large_response(stream, acceptor, body, large_response_mode).await
        }
    });
    (origin, task, sent_frame_sizes)
}

fn tls_pair_with_pin() -> (Vec<u8>, TlsAcceptor) {
    let (cert, key) = self_signed();
    let pin = spl_core::ca::sha256(cert.as_ref())[..16].to_vec();
    let acceptor = TlsAcceptor::from(Arc::new(server_config(cert, key)));
    (pin, acceptor)
}

fn tls_pair() -> (Arc<ClientConfig>, TlsAcceptor) {
    let (pin, acceptor) = tls_pair_with_pin();
    (client_config(&pin), acceptor)
}

fn assert_relay_error<T>(result: Result<T, TransportError>, expected: RelayError) {
    match result {
        Err(TransportError::Relay(actual)) => assert_eq!(actual, expected),
        Err(other) => panic!("expected relay error {expected:?}, got {other:?}"),
        Ok(_) => panic!("expected relay error {expected:?}, got success"),
    }
}

#[derive(Clone, Copy)]
enum CombinedWsMode {
    AcceptAny,
    FreshOnly,
    AlwaysUnauthorized,
    Close(u16),
    UpgradeReject(u16),
    InnerAlert(u8),
}

struct CombinedRelayState {
    acceptor: TlsAcceptor,
    mode: CombinedWsMode,
    fresh_token: String,
    tcp_accepts: AtomicUsize,
    ws_dials: AtomicUsize,
    refreshes: AtomicUsize,
    auth_headers: Mutex<Vec<String>>,
    inner_requests: Mutex<Vec<Vec<u8>>>,
}

struct CombinedRelay {
    origin: String,
    state: Arc<CombinedRelayState>,
    task: JoinHandle<()>,
}

impl CombinedRelay {
    fn abort(&self) {
        self.task.abort();
    }
}

async fn spawn_combined_relay(
    acceptor: TlsAcceptor,
    mode: CombinedWsMode,
    fresh_token: String,
) -> CombinedRelay {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let state = Arc::new(CombinedRelayState {
        acceptor,
        mode,
        fresh_token,
        tcp_accepts: AtomicUsize::new(0),
        ws_dials: AtomicUsize::new(0),
        refreshes: AtomicUsize::new(0),
        auth_headers: Mutex::new(Vec::new()),
        inner_requests: Mutex::new(Vec::new()),
    });
    let task = tokio::spawn({
        let state = state.clone();
        async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    break;
                };
                state.tcp_accepts.fetch_add(1, Ordering::SeqCst);
                let state = state.clone();
                tokio::spawn(async move {
                    let _ = handle_combined_connection(tcp, state).await;
                });
            }
        }
    });
    CombinedRelay {
        origin,
        state,
        task,
    }
}

async fn handle_combined_connection(
    tcp: TcpStream,
    state: Arc<CombinedRelayState>,
) -> io::Result<()> {
    let mut peek = [0u8; 512];
    let n = tcp.peek(&mut peek).await?;
    if String::from_utf8_lossy(&peek[..n]).starts_with("GET ") {
        handle_combined_ws(tcp, state).await
    } else {
        handle_combined_http(tcp, state).await
    }
}

#[expect(
    clippy::result_large_err,
    reason = "the copied relay harness must return tungstenite's full upgrade rejection response"
)]
#[expect(
    clippy::too_many_lines,
    reason = "the copied combined relay handler keeps the upgrade and close-mode harness in one readable state machine"
)]
async fn handle_combined_ws(tcp: TcpStream, state: Arc<CombinedRelayState>) -> io::Result<()> {
    let seen_auth = Arc::new(Mutex::new(String::new()));
    let seen_auth_for_cb = seen_auth.clone();
    let state_for_cb = state.clone();
    let mode = state.mode;
    #[expect(
        clippy::assigning_clones,
        reason = "the harness intentionally retains one authorization value and records a second owned copy"
    )]
    let result = accept_hdr_async(tcp, move |request: &Request, response: Response| {
        state_for_cb.ws_dials.fetch_add(1, Ordering::SeqCst);
        #[expect(
            clippy::map_unwrap_or,
            reason = "the copied relay harness keeps the optional query test explicit"
        )]
        let path_ok = request.uri().path() == "/session/dial"
            && request
                .uri()
                .query()
                .map(|query| query.contains(INSTANCE_ID))
                .unwrap_or(false);
        let auth = request
            .headers()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_string();
        *seen_auth_for_cb.lock().unwrap() = auth.clone();
        state_for_cb.auth_headers.lock().unwrap().push(auth);
        if !path_ok {
            let response: ErrorResponse = tokio_tungstenite::tungstenite::http::Response::builder()
                .status(400)
                .body(Some("bad path".to_string()))
                .unwrap();
            return Err(response);
        }
        if let CombinedWsMode::UpgradeReject(status) = mode {
            let response: ErrorResponse = tokio_tungstenite::tungstenite::http::Response::builder()
                .status(status)
                .body(Some("rejected".to_string()))
                .unwrap();
            return Err(response);
        }
        Ok(response)
    })
    .await;

    #[expect(
        clippy::manual_let_else,
        reason = "the copied match keeps the successful WebSocket binding beside the early-return harness path"
    )]
    let mut ws = match result {
        Ok(ws) => ws,
        Err(_) => return Ok(()),
    };
    match mode {
        CombinedWsMode::AcceptAny | CombinedWsMode::InnerAlert(_) => {}
        CombinedWsMode::FreshOnly => {
            let expected = format!("Bearer {}", state.fresh_token);
            if *seen_auth.lock().unwrap() != expected {
                ws.send(Message::Close(Some(CloseFrame {
                    code: CloseCode::from(4401),
                    reason: "".into(),
                })))
                .await
                .map_err(io::Error::other)?;
                return Ok(());
            }
        }
        CombinedWsMode::AlwaysUnauthorized => {
            ws.send(Message::Close(Some(CloseFrame {
                code: CloseCode::from(4401),
                reason: "".into(),
            })))
            .await
            .map_err(io::Error::other)?;
            return Ok(());
        }
        CombinedWsMode::Close(code) => {
            ws.send(Message::Close(Some(CloseFrame {
                code: CloseCode::from(code),
                reason: "".into(),
            })))
            .await
            .map_err(io::Error::other)?;
            return Ok(());
        }
        CombinedWsMode::UpgradeReject(_) => return Ok(()),
    }

    let (relay_side, server_side) = tokio::io::duplex(4096);
    tokio::spawn(async move {
        let _ = pump_ws(ws, relay_side, None).await;
    });
    if let CombinedWsMode::InnerAlert(description) = mode {
        let mut server_side = server_side;
        let mut header = [0u8; 5];
        server_side.read_exact(&mut header).await?;
        let mut hello = vec![0u8; u16::from_be_bytes([header[3], header[4]]) as usize];
        server_side.read_exact(&mut hello).await?;
        server_side
            .write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, description])
            .await?;
        server_side.flush().await?;
        return Ok(());
    }
    let request = serve_stream_response(
        server_side,
        state.acceptor.clone(),
        "200 OK",
        b"{\"status\":\"ok\"}",
    )
    .await;
    state.inner_requests.lock().unwrap().push(request);
    Ok(())
}

async fn handle_combined_http(
    mut tcp: TcpStream,
    state: Arc<CombinedRelayState>,
) -> io::Result<()> {
    let raw = read_http_request(&mut tcp).await?;
    let text = String::from_utf8_lossy(&raw);
    let path = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");
    if path == "/token/refresh" {
        state.refreshes.fetch_add(1, Ordering::SeqCst);
        write_json(
            &mut tcp,
            200,
            json!({
                "device_token": state.fresh_token,
            }),
        )
        .await?;
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
    let Some(split) = raw.windows(4).position(|window| window == b"\r\n\r\n") else {
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

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn deterministic_bytes(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| ((i.wrapping_mul(31) + (i / 7)) % 251) as u8)
        .collect()
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the cycle assertion keeps the relay, mobile, and loopback milestones in one ordered test"
)]
#[expect(
    clippy::result_large_err,
    reason = "the WebSocket upgrade callbacks use tungstenite's required full rejection response type"
)]
async fn home_relay_attachment_forwards_bytes_and_observes_stream_close() {
    let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_origin = format!("http://{}", relay_listener.local_addr().unwrap());
    let app_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let app_port = app_listener.local_addr().unwrap().port();
    let (app_received_sender, app_received_receiver) = tokio::sync::oneshot::channel();
    let (close_sender, close_receiver) = tokio::sync::oneshot::channel();
    let app = tokio::spawn(async move {
        let (mut socket, _) = tokio::time::timeout(Duration::from_secs(1), app_listener.accept())
            .await
            .expect("relay pipe must dial the app")
            .unwrap();
        let mut request = [0_u8; 5];
        socket.read_exact(&mut request).await.unwrap();
        assert_eq!(request, *b"hello");
        app_received_sender.send(()).unwrap();
        socket.write_all(b"world").await.unwrap();
        close_receiver
            .await
            .expect("test must request app teardown after observing reply");
        socket.shutdown().await.unwrap();
    });
    let (mobile_sender, mobile_receiver) = tokio::sync::oneshot::channel();
    let relay = tokio::spawn(async move {
        let (listen_tcp, _) = relay_listener.accept().await.unwrap();
        let mut listen = accept_hdr_async(listen_tcp, |request: &Request, response: Response| {
            assert_eq!(request.uri().path(), "/session/listen");
            assert_eq!(
                request.headers().get("authorization").unwrap(),
                "Bearer test-service-token"
            );
            Ok(response)
        })
        .await
        .unwrap();
        listen
            .send(Message::Text(
                r#"{"type":"incoming","tunnel_id":"test-tunnel"}"#.into(),
            ))
            .await
            .unwrap();
        let (tunnel_tcp, _) = relay_listener.accept().await.unwrap();
        let tunnel = accept_hdr_async(tunnel_tcp, |request: &Request, response: Response| {
            assert_eq!(request.uri().path(), "/tunnel/test-tunnel");
            assert_eq!(
                request.headers().get("authorization").unwrap(),
                "Bearer test-service-token"
            );
            Ok(response)
        })
        .await
        .unwrap();
        let (relay_side, mobile_side) = tokio::io::duplex(2 * 1024 * 1024);
        mobile_sender.send(mobile_side).unwrap();
        let _ = pump_ws(tunnel, relay_side, None).await;
        let _ = listen.next().await;
    });
    let fixture = home_tls_fixture();
    let client = HomeRelayClient::new(HomeRelayClientConfig {
        relay_origin,
        service_token: ServiceToken::new("test-service-token".into()),
        home_config: home_config(&fixture),
        app_port,
        dispatch_read_deadline: Duration::from_secs(1),
        admission_ceiling: std::num::NonZeroUsize::new(1).unwrap(),
        jitter: Arc::new(FixedRelayJitter),
        events: Arc::new(TestRelayEvents),
    });
    let running = tokio::spawn({
        let client = client.clone();
        async move { client.run().await }
    });
    let mobile_io = tokio::time::timeout(Duration::from_secs(1), mobile_receiver)
        .await
        .expect("home must open the signaled tunnel")
        .unwrap();
    let config = mtls_config(
        &spl_core::ca::sha256(fixture.ca.as_ref())[..16],
        fixture.client_chain,
        fixture.client_key,
    )
    .unwrap();
    let mut mobile = TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("spl.local").unwrap(), mobile_io)
        .await
        .unwrap();
    mobile
        .write_all(
            &Frame::new(1, FLAG_OPEN | FLAG_DATA, b"hello".to_vec())
                .encode()
                .unwrap(),
        )
        .await
        .unwrap();
    mobile.flush().await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), app_received_receiver)
        .await
        .expect("tunnel bytes must reach the loopback app")
        .unwrap();
    let mut decoder = FrameDecoder::new();
    let mut buffer = [0_u8; 4096];
    let mut saw_reply = false;
    while !saw_reply {
        let count = tokio::time::timeout(Duration::from_secs(1), mobile.read(&mut buffer))
            .await
            .expect("full relay cycle must not stall")
            .unwrap();
        decoder.feed(&buffer[..count]);
        for frame in decoder.drain().unwrap() {
            saw_reply |= frame.payload == b"world";
        }
    }
    assert!(
        saw_reply,
        "mobile must receive loopback reply through relay"
    );
    close_sender.send(()).unwrap();
    let saw_close = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let count = mobile.read(&mut buffer).await.unwrap();
            decoder.feed(&buffer[..count]);
            if decoder
                .drain()
                .unwrap()
                .into_iter()
                .any(|frame| frame.flags == FLAG_CLOSE)
            {
                return;
            }
        }
    })
    .await
    .is_ok();
    assert!(
        saw_close,
        "mobile must observe stream close after app teardown"
    );
    app.await.unwrap();
    client.stop().await;
    running.abort();
    relay.abort();
}

#[tokio::test]
async fn stopped_home_relay_ignores_incoming_without_opening_a_tunnel() {
    let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_origin = format!("http://{}", relay_listener.local_addr().unwrap());
    let relay = tokio::spawn(async move {
        let (listen_tcp, _) = relay_listener.accept().await.unwrap();
        let mut listen = accept_async(listen_tcp).await.unwrap();
        listen
            .send(Message::Text(
                r#"{"type":"incoming","tunnel_id":"after-stop"}"#.into(),
            ))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_millis(150), relay_listener.accept())
            .await
            .is_err()
    });
    let fixture = home_tls_fixture();
    let events = Arc::new(DisconnectEvents(AtomicUsize::new(0)));
    let client = HomeRelayClient::new(HomeRelayClientConfig {
        relay_origin,
        service_token: ServiceToken::new("test-service-token".into()),
        home_config: home_config(&fixture),
        app_port: 1,
        dispatch_read_deadline: Duration::from_secs(1),
        admission_ceiling: std::num::NonZeroUsize::new(1).unwrap(),
        jitter: Arc::new(FixedRelayJitter),
        events: events.clone(),
    });
    client.stop().await;
    assert_eq!(
        events.0.load(Ordering::SeqCst),
        1,
        "stop must announce the typed disconnect transition"
    );
    let running = tokio::spawn({
        let client = client.clone();
        async move { client.run().await }
    });
    assert!(relay.await.unwrap(), "stop must prevent the tunnel dial");
    running.abort();
}

#[expect(
    clippy::result_large_err,
    reason = "the copied relay harness must construct tungstenite's full upgrade rejection response"
)]
fn reject_upgrade(status: u16) -> impl Fn(&Request, Response) -> Result<Response, ErrorResponse> {
    move |_request: &Request, _response: Response| {
        let response: ErrorResponse = tokio_tungstenite::tungstenite::http::Response::builder()
            .status(status)
            .body(Some("rejected".to_string()))
            .unwrap();
        Err(response)
    }
}

#[tokio::test]
async fn relay_round_trips_small_body() {
    let (config, acceptor) = tls_pair();
    let (origin, server) =
        spawn_response_relay(acceptor, "200 OK", b"{\"status\":\"ok\"}", None, 4096).await;

    let response = request_once_relay(
        config,
        &origin,
        "inst-small",
        RELAY_TOKEN,
        "POST",
        "/app/observer/register",
        &[("Content-Type".to_string(), "application/json".to_string())],
        b"{\"device\":\"win\"}",
    )
    .await
    .expect("relay request should round-trip");

    assert_eq!(response.status, 200);
    assert_eq!(response.body_text(), "{\"status\":\"ok\"}");
    let received = server.await.unwrap();
    let received_text = String::from_utf8_lossy(&received);
    assert!(received_text.starts_with("POST /app/observer/register HTTP/1.1\r\n"));
    assert!(received_text.ends_with("{\"device\":\"win\"}"));
}

#[tokio::test]
async fn relay_streams_multi_mib_body_under_flow_control() {
    let (config, acceptor) = tls_pair();
    let (origin, server) = spawn_flow_relay(acceptor).await;
    let big_body = vec![0x7Cu8; INITIAL_WINDOW * 2 + INITIAL_WINDOW / 2 + 123];

    let response = request_once_relay(
        config,
        &origin,
        "inst-flow",
        RELAY_TOKEN,
        "POST",
        "/app/observer/ingest",
        &[(
            "Content-Type".to_string(),
            "application/octet-stream".to_string(),
        )],
        &big_body,
    )
    .await
    .expect("relay must preserve the windowed upload over partial byte reads");

    assert_eq!(response.status, 200);
    assert_eq!(response.body_text(), "{\"status\":\"accepted\"}");
    let received = server.await.unwrap();
    assert!(
        received.len() > INITIAL_WINDOW * 2,
        "server should receive the whole multi-MiB request, got {} bytes",
        received.len()
    );
    assert!(received.ends_with(&big_body));
}

#[tokio::test]
async fn relay_reassembles_large_response_across_partial_frames() {
    let (config, acceptor) = tls_pair();
    let expected_body = deterministic_bytes(LARGE_RESPONSE_BYTES);
    let (origin, server, sent_frame_sizes) =
        spawn_large_response_relay(acceptor, expected_body.clone()).await;

    let response = request_once_relay(
        config,
        &origin,
        "inst-large-response",
        RELAY_TOKEN,
        "GET",
        "/app/observer/large-response",
        &[],
        b"",
    )
    .await
    .expect("large relay response should round-trip");

    assert_eq!(response.status, 200);
    assert_eq!(response.body, expected_body);
    assert!(
        sent_frame_sizes
            .lock()
            .unwrap()
            .iter()
            .any(|size| *size > CARRIER_READ_BUF_BYTES),
        "test must deliver at least one inbound WS frame larger than the carrier read buffer"
    );
    let received = server.await.unwrap();
    let received_text = String::from_utf8_lossy(&received);
    assert!(received_text.starts_with("GET /app/observer/large-response HTTP/1.1\r\n"));
}

#[tokio::test]
async fn relay_is_blind_to_inner_http_and_tokens() {
    let (config, acceptor) = tls_pair();
    let captured = Arc::new(Mutex::new(Vec::new()));
    let instance_id = "instance-blind";
    let token = "blind-token-secret";
    let (origin, server) = spawn_response_relay(
        acceptor,
        "200 OK",
        b"{\"status\":\"ok\"}",
        Some(captured.clone()),
        4096,
    )
    .await;

    let response = request_once_relay(
        config,
        &origin,
        instance_id,
        token,
        "POST",
        "/app/observer/register",
        &[(TEST_OBSERVER_HEADER_NAME.into(), "observer-key".into())],
        b"{\"device\":\"win\"}",
    )
    .await
    .expect("relay request should round-trip");
    assert_eq!(response.status, 200);
    let _ = server.await.unwrap();

    let captured = captured.lock().unwrap().clone();
    assert!(captured.len() > 6, "expected a captured TLS record");
    assert_eq!(
        captured[0], 0x16,
        "first WS binary payload is a TLS handshake record"
    );
    assert_eq!(
        captured[5], 0x01,
        "first TLS handshake message is ClientHello"
    );
    assert!(!contains_bytes(&captured, b"POST"));
    assert!(!contains_bytes(&captured, token.as_bytes()));
    assert!(!contains_bytes(
        &captured,
        TEST_OBSERVER_HEADER_NAME.as_bytes()
    ));
    assert!(!contains_bytes(&captured, instance_id.as_bytes()));
}

#[tokio::test]
async fn relay_wrong_inner_pin_stays_tls_error() {
    let (cert, key) = self_signed();
    let acceptor = TlsAcceptor::from(Arc::new(server_config(cert, key)));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let _server = tokio::spawn(async move {
        let stream = accept_relay_stream(listener, None, 4096).await;
        let _ = acceptor.accept(stream).await;
    });

    let wrong_pin = vec![0xFFu8; 16];
    let result = request_once_relay(
        client_config(&wrong_pin),
        &origin,
        "inst-wrong-pin",
        RELAY_TOKEN,
        "GET",
        "/healthz",
        &[],
        b"",
    )
    .await;

    match result {
        Err(TransportError::Tls(_)) => {}
        Err(TransportError::Relay(err)) => panic!("wrong pin must not map to relay error: {err:?}"),
        Err(other) => panic!("wrong pin should surface as TLS, got {other:?}"),
        Ok(response) => panic!("wrong pin unexpectedly succeeded: {response:?}"),
    }
}

#[tokio::test]
async fn relay_upgrade_reject_maps_http_statuses() {
    for (status, expected) in [
        (503, RelayError::HomeOffline),
        (402, RelayError::Unpaid),
        (401, RelayError::Unauthorized),
        (404, RelayError::UnknownInstance),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "ws://{}/session/dial?instance=inst",
            listener.local_addr().unwrap()
        );
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let _ = accept_hdr_async(tcp, reject_upgrade(status)).await;
        });

        let result = dial_relay_ws(&url, RELAY_TOKEN, unused_outer_config()).await;
        assert_relay_error(result, expected);
        server.await.unwrap();
    }
}

#[tokio::test]
async fn relay_post_upgrade_close_maps_codes() {
    for (code, expected) in [
        (4401, RelayError::Unauthorized),
        (4402, RelayError::Unpaid),
        (1009, RelayError::Overflow),
        (1012, RelayError::Abnormal),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "ws://{}/session/dial?instance=inst",
            listener.local_addr().unwrap()
        );
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = accept_async(tcp).await.unwrap();
            ws.send(Message::Close(Some(CloseFrame {
                code: CloseCode::from(code),
                reason: "".into(),
            })))
            .await
            .unwrap();
        });

        let ws = dial_relay_ws(&url, RELAY_TOKEN, unused_outer_config())
            .await
            .unwrap();
        let result = request_once_over_ws(
            ws,
            client_config(&[0xAA; 16]),
            Duration::from_secs(5),
            "GET",
            "/healthz",
            &[],
            b"",
        )
        .await;
        assert_relay_error(result, expected);
        server.await.unwrap();
    }
}

#[tokio::test]
async fn relay_abnormal_drop_maps_to_abnormal() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "ws://{}/session/dial?instance=inst",
        listener.local_addr().unwrap()
    );
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let ws = accept_async(tcp).await.unwrap();
        drop(ws);
    });

    let ws = dial_relay_ws(&url, RELAY_TOKEN, unused_outer_config())
        .await
        .unwrap();
    let result = request_once_over_ws(
        ws,
        client_config(&[0xAA; 16]),
        Duration::from_secs(5),
        "GET",
        "/healthz",
        &[],
        b"",
    )
    .await;

    assert_relay_error(result, RelayError::Abnormal);
    server.await.unwrap();
}

#[tokio::test]
async fn relay_inner_handshake_stall_maps_to_stalled() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "ws://{}/session/dial?instance=inst",
        listener.local_addr().unwrap()
    );
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut ws = accept_async(tcp).await.unwrap();
        let _ = ws.next().await;
        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    let ws = dial_relay_ws(&url, RELAY_TOKEN, unused_outer_config())
        .await
        .unwrap();
    let result = request_once_over_ws(
        ws,
        client_config(&[0xAA; 16]),
        Duration::from_millis(200),
        "GET",
        "/healthz",
        &[],
        b"",
    )
    .await;

    assert_relay_error(result, RelayError::Stalled);
    server.abort();
}

#[tokio::test]
async fn relay_inner_app_503_returns_http_response_not_home_offline() {
    let (config, acceptor) = tls_pair();
    let (origin, server) = spawn_response_relay(
        acceptor,
        "503 Service Unavailable",
        b"{\"error\":\"busy\"}",
        None,
        4096,
    )
    .await;

    let response: HttpResponse = request_once_relay(
        config,
        &origin,
        "inst-inner-503",
        RELAY_TOKEN,
        "GET",
        "/app/observer/ingest",
        &[],
        b"",
    )
    .await
    .expect("inner app 503 stays an HTTP response inside the tunnel");

    assert_eq!(response.status, 503);
    assert!(!response.is_success());
    assert_eq!(response.body_text(), "{\"error\":\"busy\"}");
    let _ = server.await.unwrap();
}

#[tokio::test]
async fn relay_fallbacks_after_lan_unreachable() {
    let (pin, acceptor) = tls_pair_with_pin();
    let now = epoch_secs();
    let token = mint_jwt(now, now + 10_000);
    let relay = spawn_combined_relay(acceptor, CombinedWsMode::AcceptAny, token.clone()).await;
    let credential = relay_credential(pin, 9, relay.origin.clone(), token);
    let handle = start_relay_bridge(credential, None).await;
    let cap = capability_from(&handle);

    let _response = raw_bridge_request_with_method(
        handle.port(),
        "POST",
        "/app/observer/ingest/event",
        &cap,
        b"{}",
    )
    .await;

    {
        let requests = relay.state.inner_requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let request_text = String::from_utf8_lossy(&requests[0]);
        assert!(request_text.starts_with("POST /app/observer/ingest/event HTTP/1.1\r\n"));
    }
    handle.shutdown_and_wait().await;
    relay.abort();
}

// Falsified by restoring generic inner-handshake formatting: this result becomes Tls(_) rather
// than the terminal variant even though the relay delivers a real TLS access-denied alert.
#[tokio::test]
async fn relay_inner_access_denied_is_terminal() {
    let (pin, acceptor) = tls_pair_with_pin();
    let now = epoch_secs();
    let token = mint_jwt(now, now + 10_000);
    let relay = spawn_combined_relay(acceptor, CombinedWsMode::InnerAlert(49), token.clone()).await;
    let client = transport_client(relay_credential(pin, 9, relay.origin.clone(), token), None);

    assert!(matches!(
        Box::pin(client.dial_carrier()).await,
        Err(TransportError::TlsAccessDenied)
    ));
    assert_eq!(relay.state.ws_dials.load(Ordering::SeqCst), 1);
    relay.abort();
}

// AC2(a). Protocol: `.proto-ref/session.md`, lines 179-183, 189-193. Falsified by
// restoring generic inner-handshake formatting: this result becomes Tls(_) rather
// than TlsCertificateUnknown even though the relay delivers a real TLS 46 alert.
#[tokio::test]
async fn relay_inner_certificate_unknown_is_typed() {
    let (pin, acceptor) = tls_pair_with_pin();
    let now = epoch_secs();
    let token = mint_jwt(now, now + 10_000);
    let relay = spawn_combined_relay(acceptor, CombinedWsMode::InnerAlert(46), token.clone()).await;
    let client = transport_client(relay_credential(pin, 9, relay.origin.clone(), token), None);

    assert!(matches!(
        Box::pin(client.dial_carrier()).await,
        Err(TransportError::TlsCertificateUnknown)
    ));
    assert_eq!(relay.state.ws_dials.load(Ordering::SeqCst), 1);
    relay.abort();
}

// Falsified by broadening the inner classifier to every alert description: this result becomes
// a named terminal variant instead of preserving the existing generic TLS error.
#[tokio::test]
async fn relay_inner_unclassified_alert_stays_tls() {
    for description in [80, 200] {
        let (pin, acceptor) = tls_pair_with_pin();
        let now = epoch_secs();
        let token = mint_jwt(now, now + 10_000);
        let relay = spawn_combined_relay(
            acceptor,
            CombinedWsMode::InnerAlert(description),
            token.clone(),
        )
        .await;
        let client = transport_client(relay_credential(pin, 9, relay.origin.clone(), token), None);

        assert!(
            matches!(
                Box::pin(client.dial_carrier()).await,
                Err(TransportError::Tls(_))
            ),
            "description {description} must stay a generic TLS error"
        );
        assert_eq!(relay.state.ws_dials.load(Ordering::SeqCst), 1);
        relay.abort();
    }
}

#[tokio::test]
async fn relay_bridge_streams_body_beyond_initial_window_byte_exactly() {
    // Protocol: `.proto-ref/framing.md`, "relationship to the relay" — the
    // relay is an opaque pump and framing flow control remains between the two
    // TLS endpoints.
    const TARGET: &str = "/app/observer/ingest/large";
    let (pin, acceptor) = tls_pair_with_pin();
    let now = epoch_secs();
    let token = mint_jwt(now, now + 10_000);
    let relay = spawn_combined_relay(acceptor, CombinedWsMode::AcceptAny, token.clone()).await;
    let credential = relay_credential(pin, 9, relay.origin.clone(), token);
    let handle = start_relay_bridge(credential, None).await;
    let cap = capability_from(&handle);
    let body = (0..INITIAL_WINDOW + 193_771)
        .map(|index| (index % 239) as u8)
        .collect::<Vec<_>>();

    let response = raw_bridge_request_with_method(handle.port(), "POST", TARGET, &cap, &body).await;
    assert_eq!(response_status(&response), 200);
    assert_eq!(response_body(&response), "{\"status\":\"ok\"}");

    {
        let requests = relay.state.inner_requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        let split = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap()
            + 4;
        let expected_head = spl_core::http::build_request_head(
            "POST",
            TARGET,
            &[
                ("x-test-observer".into(), "test-key".into()),
                ("x-test-protocol".into(), "2".into()),
            ],
            body.len(),
        );
        assert_eq!(&request[..split], expected_head);
        assert_eq!(&request[split..], body);
    }

    let status = handle.shutdown_and_wait().await;
    assert_eq!(status.active_requests, 0);
    relay.abort();
}

#[tokio::test]
async fn relay_credential_without_lan_endpoints_rejected_at_new() {
    let (pin, _acceptor) = tls_pair_with_pin();
    let mut credential =
        relay_credential(pin, 7657, "http://127.0.0.1:1".into(), mint_jwt(100, 200));
    credential.endpoints.clear();

    match TransportClient::new(credential, None) {
        Err(TransportError::Pairing(message)) => {
            assert_eq!(message, "relay credential has no LAN endpoints");
        }
        Err(other) => panic!("expected Pairing error, got {other:?}"),
        Ok(_) => panic!("relay credential without LAN endpoints should fail"),
    }
}

#[tokio::test]
async fn relay_only_constructor_rejects_lan_endpoints_and_missing_relay_inputs() {
    let (pin, _acceptor) = tls_pair_with_pin();
    let token = mint_jwt(100, 200);

    let with_lan = relay_credential(
        pin.clone(),
        7657,
        "http://127.0.0.1:1".into(),
        token.clone(),
    );
    assert!(matches!(
        TransportClient::new_relay_only(with_lan, None),
        Err(TransportError::Pairing(message))
            if message
                == "relay-only credential has LAN endpoints; use TransportClient::new for a credential with LAN endpoints"
    ));

    let mut without_origin = relay_credential(
        pin.clone(),
        7657,
        "http://127.0.0.1:1".into(),
        token.clone(),
    );
    without_origin.endpoints.clear();
    without_origin.relay_origin = None;
    assert!(matches!(
        TransportClient::new_relay_only(without_origin, None),
        Err(TransportError::Pairing(message))
            if message == "relay-only credential has no relay origin"
    ));

    let mut without_token = relay_credential(pin, 7657, "http://127.0.0.1:1".into(), token);
    without_token.endpoints.clear();
    without_token.device_token = None;
    assert!(matches!(
        TransportClient::new_relay_only(without_token, None),
        Err(TransportError::Pairing(message))
            if message == "relay-only credential has no device token"
    ));
}

#[tokio::test]
async fn relay_proactive_refresh_before_first_dial() {
    let (pin, acceptor) = tls_pair_with_pin();
    let now = epoch_secs();
    let old_token = mint_jwt(100, 200);
    let fresh_token = mint_jwt(now, now + 10_000);
    let relay =
        spawn_combined_relay(acceptor, CombinedWsMode::FreshOnly, fresh_token.clone()).await;
    let client = transport_client(
        relay_credential(pin, 9, relay.origin.clone(), old_token),
        None,
    );

    #[expect(
        clippy::large_futures,
        reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
    )]
    let _carrier = client.dial_carrier().await.unwrap();

    assert_eq!(relay.state.refreshes.load(Ordering::SeqCst), 1);
    assert_eq!(relay.state.ws_dials.load(Ordering::SeqCst), 1);
    assert_eq!(
        relay.state.auth_headers.lock().unwrap().as_slice(),
        [format!("Bearer {fresh_token}")]
    );
    relay.abort();
}

#[tokio::test]
async fn relay_unauthorized_refreshes_and_redials_once() {
    let (pin, acceptor) = tls_pair_with_pin();
    let now = epoch_secs();
    let old_token = mint_jwt(now, now + 10_000);
    let fresh_token = mint_jwt(now, now + 20_000);
    let relay =
        spawn_combined_relay(acceptor, CombinedWsMode::FreshOnly, fresh_token.clone()).await;
    let client = transport_client(
        relay_credential(pin, 9, relay.origin.clone(), old_token),
        None,
    );

    #[expect(
        clippy::large_futures,
        reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
    )]
    let _carrier = client.dial_carrier().await.unwrap();

    assert_eq!(relay.state.ws_dials.load(Ordering::SeqCst), 2);
    assert_eq!(relay.state.refreshes.load(Ordering::SeqCst), 1);
    assert_eq!(
        relay.state.auth_headers.lock().unwrap().last().cloned(),
        Some(format!("Bearer {fresh_token}"))
    );
    relay.abort();
}

#[tokio::test]
async fn relay_bridge_carrier_refreshes_on_4401_then_succeeds() {
    let (pin, acceptor) = tls_pair_with_pin();
    let now = epoch_secs();
    let old_token = mint_jwt(now, now + 10_000);
    let fresh_token = mint_jwt(now, now + 20_000);
    let relay =
        spawn_combined_relay(acceptor, CombinedWsMode::FreshOnly, fresh_token.clone()).await;
    let credential = relay_credential(pin, 9, relay.origin.clone(), old_token);
    let handle = start_relay_bridge(credential, None).await;
    let cap = capability_from(&handle);

    let response = raw_bridge_request(handle.port(), "/journal", &cap).await;

    assert_eq!(response_status(&response), 200);
    assert_eq!(response_body(&response), "{\"status\":\"ok\"}");
    assert_eq!(relay.state.ws_dials.load(Ordering::SeqCst), 2);
    assert_eq!(relay.state.refreshes.load(Ordering::SeqCst), 1);
    assert_eq!(
        relay.state.auth_headers.lock().unwrap().last().cloned(),
        Some(format!("Bearer {fresh_token}"))
    );
    {
        let requests = relay.state.inner_requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(String::from_utf8_lossy(&requests[0]).starts_with("GET /journal HTTP/1.1\r\n"));
    }

    handle.shutdown_and_wait().await;
    relay.abort();
}

#[tokio::test]
async fn relay_bridge_initial_dial_failure_returns_502_and_next_request_redials() {
    let (pin, acceptor) = tls_pair_with_pin();
    let now = epoch_secs();
    let old_token = mint_jwt(now, now + 10_000);
    let fresh_token = mint_jwt(now, now + 20_000);
    let relay = spawn_combined_relay(
        acceptor,
        CombinedWsMode::AlwaysUnauthorized,
        fresh_token.clone(),
    )
    .await;
    let lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let subscriber = CapturingSubscriber {
        lines: lines.clone(),
    };
    let _ = tracing::dispatcher::set_global_default(tracing::Dispatch::new(subscriber));
    let credential = relay_credential(pin, 9, relay.origin.clone(), old_token.clone());
    let handle = start_relay_bridge(credential, None).await;
    let cap = capability_from(&handle);

    let first = raw_bridge_request(handle.port(), "/fail", &cap).await;
    assert_eq!(response_status(&first), 502);
    let first_dials = relay.state.ws_dials.load(Ordering::SeqCst);
    assert!(first_dials >= 2);

    let second = raw_bridge_request(handle.port(), "/fail-again", &cap).await;
    assert_eq!(response_status(&second), 502);
    assert!(
        relay.state.ws_dials.load(Ordering::SeqCst) > first_dials,
        "failed relay carrier must not be cached as live"
    );

    handle.shutdown_and_wait().await;
    let logs = lines.lock().unwrap().join("\n");
    assert!(logs.contains("category=upstream_unreachable"));
    assert!(logs.contains("code=relay_unauthorized"));
    assert!(!logs.contains(&old_token));
    assert!(!logs.contains(&fresh_token));
    assert!(!logs.contains(&relay.origin));
    relay.abort();
}

// Multi-stream-over-relay does not get a separate live harness here: after
// `dial_carrier` returns, LAN and relay both feed the same transport-agnostic
// `MuxCarrier` coordinator. The duplex and persistent-TLS tests cover that mux
// behavior; these relay tests cover the relay-specific dial and refresh branch.

#[tokio::test]
#[expect(
    clippy::large_futures,
    reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
)]
async fn relay_unauthorized_persists_after_refresh_is_terminal_no_storm() {
    let (pin, acceptor) = tls_pair_with_pin();
    let now = epoch_secs();
    let old_token = mint_jwt(now, now + 10_000);
    let fresh_token = mint_jwt(now, now + 20_000);
    let relay =
        spawn_combined_relay(acceptor, CombinedWsMode::AlwaysUnauthorized, fresh_token).await;
    let client = transport_client(
        relay_credential(pin, 9, relay.origin.clone(), old_token),
        None,
    );

    assert_relay_error(client.dial_carrier().await, RelayError::Unauthorized);
    assert_eq!(relay.state.ws_dials.load(Ordering::SeqCst), 2);
    assert_eq!(relay.state.refreshes.load(Ordering::SeqCst), 1);
    relay.abort();
}

#[tokio::test]
async fn relay_refresh_persists_token_for_restart() {
    let (pin, acceptor) = tls_pair_with_pin();
    let now = epoch_secs();
    let old_token = mint_jwt(now, now + 10_000);
    let fresh_token = mint_jwt(now, now + 20_000);
    let relay =
        spawn_combined_relay(acceptor, CombinedWsMode::FreshOnly, fresh_token.clone()).await;
    let credential = relay_credential(pin, 9, relay.origin.clone(), old_token);
    let persisted = Arc::new(Mutex::new(credential.clone()));
    let persisted_for_hook = persisted.clone();
    let hook: TokenPersistHook = Arc::new(move |token, expires_at| {
        let mut credential = persisted_for_hook.lock().unwrap();
        credential.device_token = Some(token.to_string());
        credential.device_token_expires_at = Some(expires_at);
    });
    let client = transport_client(credential, Some(hook));

    #[expect(
        clippy::large_futures,
        reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
    )]
    let first_carrier = client.dial_carrier().await.unwrap();

    let persisted_credential = persisted.lock().unwrap().clone();
    assert_eq!(
        persisted_credential.device_token.as_deref(),
        Some(fresh_token.as_str())
    );
    assert_eq!(
        persisted_credential.device_token_expires_at,
        Some(now + 20_000)
    );
    assert_eq!(relay.state.refreshes.load(Ordering::SeqCst), 1);

    drop(first_carrier);
    let restarted = transport_client(persisted_credential, None);
    #[expect(
        clippy::large_futures,
        reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
    )]
    let _restarted_carrier = restarted.dial_carrier().await.unwrap();
    assert_eq!(relay.state.refreshes.load(Ordering::SeqCst), 1);
    relay.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[expect(
    clippy::large_futures,
    reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
)]
async fn relay_refresh_single_flight_across_concurrent_dials() {
    let (pin, acceptor) = tls_pair_with_pin();
    let now = epoch_secs();
    let old_token = mint_jwt(now, now + 10_000);
    let fresh_token = mint_jwt(now, now + 20_000);
    let relay =
        spawn_combined_relay(acceptor, CombinedWsMode::FreshOnly, fresh_token.clone()).await;
    let client = Arc::new(transport_client(
        relay_credential(pin, 9, relay.origin.clone(), old_token),
        None,
    ));

    let mut tasks = Vec::new();
    for _ in 0..3 {
        let client = client.clone();
        tasks.push(tokio::spawn(async move { client.dial_carrier().await }));
    }
    for task in tasks {
        task.await.unwrap().unwrap();
    }

    assert_eq!(relay.state.refreshes.load(Ordering::SeqCst), 1);
    assert_eq!(
        relay
            .state
            .auth_headers
            .lock()
            .unwrap()
            .iter()
            .filter(|auth| *auth == &format!("Bearer {fresh_token}"))
            .count(),
        3
    );
    relay.abort();
}

#[tokio::test]
#[expect(
    clippy::large_futures,
    reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
)]
async fn relay_unpaid_is_terminal_bounded() {
    let (pin, acceptor) = tls_pair_with_pin();
    let now = epoch_secs();
    let token = mint_jwt(now, now + 10_000);
    let relay = spawn_combined_relay(acceptor, CombinedWsMode::Close(4402), token.clone()).await;
    let client = transport_client(relay_credential(pin, 9, relay.origin.clone(), token), None);

    assert_relay_error(client.dial_carrier().await, RelayError::Unpaid);
    assert_eq!(relay.state.ws_dials.load(Ordering::SeqCst), 1);
    assert_eq!(relay.state.refreshes.load(Ordering::SeqCst), 0);
    relay.abort();
}

#[tokio::test]
async fn relay_reasons_map_verbatim_and_redacted() {
    for (mode, expected) in [
        (CombinedWsMode::Close(4402), "relay_unpaid"),
        (CombinedWsMode::UpgradeReject(503), "relay_home_offline"),
    ] {
        let (pin, acceptor) = tls_pair_with_pin();
        let now = epoch_secs();
        let token = mint_jwt(now, now + 10_000);
        let relay = spawn_combined_relay(acceptor, mode, token.clone()).await;
        let client = transport_client(
            relay_credential(pin, 9, relay.origin.clone(), token.clone()),
            None,
        );

        #[expect(
            clippy::large_futures,
            clippy::manual_let_else,
            reason = "the copied transport future and explicit success/failure match preserve the established harness shape"
        )]
        let err = match client.dial_carrier().await {
            Err(error) => error,
            Ok(_) => panic!("expected relay failure"),
        };
        let code = transport_error_code(&err);

        assert_eq!(code, expected);
        assert!(!code.contains(&token));
        assert!(!code.contains(&relay.origin));
        assert!(!code.contains("https://"));
        assert!(!code.contains(INSTANCE_ID));
        relay.abort();
    }
}
