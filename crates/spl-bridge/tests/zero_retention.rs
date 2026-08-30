// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! End-to-end retention boundaries for public bridge listener traffic.

#![expect(
    clippy::unwrap_used,
    reason = "integration fixtures use controlled local certificates, sockets, and paths"
)]

use std::collections::HashMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use serde::Serialize;
use serde::de::DeserializeOwned;
use spl_bridge::pop_auth::{
    Challenge, ChallengeResponse, FixtureTokenVerifier, PopAuthenticator, RegistrationRequest,
    RenewalIdentity,
};
use spl_bridge::registry::Registry;
use spl_bridge::{
    DEFAULT_ADMISSION_DEADLINE, run_client_listener, run_control_listener, server_tls_config,
};
use spl_core::frame::{FLAG_OPEN, FrameDecoder};
use spl_home::{MuxAcceptor, MuxEvent, MuxLimits};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

const HOSTNAME: &str = "aaaqeaye.solstone.me";
const RESERVED_CONTROL_SNI: &str = "bridge.solstone.me";
const INSTANCE_ID: &str = "8488ae64-b592-80a3-97c6-490e995daa85";
const BRIDGE_ID: &str = "mcp-bridge-zero-retention";

fn registry_authenticator() -> PopAuthenticator {
    let verifier = FixtureTokenVerifier::new(
        HashMap::from([(String::from("fixture"), SigningKey::from_bytes(&[7; 32]))]),
        String::from(BRIDGE_ID),
    );
    PopAuthenticator::new(Arc::new(verifier), String::from(BRIDGE_ID))
}

fn registry_identity(hostname: &str) -> RenewalIdentity {
    RenewalIdentity::new(
        String::from(hostname),
        String::from(INSTANCE_ID),
        SigningKey::from_bytes(&[19; 32]).verifying_key(),
    )
}

#[derive(Clone)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

struct LogWriter(LogBuffer);

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuffer {
    type Writer = LogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        LogWriter(self.clone())
    }
}

impl Write for LogWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn fragmented_reserved_client_hello_and_pipelined_tail_reach_control_unchanged() {
    let control_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_address = control_listener.local_addr().unwrap();
    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_address = client_listener.local_addr().unwrap();
    let client_task = tokio::spawn(run_client_listener(
        client_listener,
        Registry::default(),
        control_address,
        Duration::from_secs(1),
    ));

    let hello = fragment_client_hello(&client_hello(RESERVED_CONTROL_SNI), 0x51a7_2c3d);
    let tail = b"pipelined-tail-must-arrive-without-a-proxy-prefix".to_vec();
    let mut expected = hello.clone();
    expected.extend_from_slice(&tail);
    let captured = tokio::spawn(async move {
        let (mut stream, _) = control_listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        bytes
    });

    let mut client = TcpStream::connect(client_address).await.unwrap();
    client.write_all(&expected).await.unwrap();
    client.shutdown().await.unwrap();
    assert_eq!(captured.await.unwrap(), expected);
    client_task.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn reserved_name_bypasses_a_maliciously_seeded_registry_entry() {
    let registry = Registry::default();
    let (carrier, mut malicious_journal) = tokio::io::duplex(1024);
    registry
        .register(
            String::from(RESERVED_CONTROL_SNI),
            carrier,
            registry_authenticator(),
            registry_identity(RESERVED_CONTROL_SNI),
            u64::MAX,
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap();
    let mut control_open = [0u8; 8];
    malicious_journal
        .read_exact(&mut control_open)
        .await
        .unwrap();
    let mut decoder = FrameDecoder::new();
    decoder.feed(&control_open);
    let frame = decoder.next_frame().unwrap().unwrap();
    assert_eq!(frame.stream_id, 1);
    assert_eq!(frame.flags, FLAG_OPEN);

    let control_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_address = control_listener.local_addr().unwrap();
    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_address = client_listener.local_addr().unwrap();
    let client_task = tokio::spawn(run_client_listener(
        client_listener,
        registry,
        control_address,
        Duration::from_secs(1),
    ));

    let expected = client_hello(RESERVED_CONTROL_SNI);
    let captured = tokio::spawn(async move {
        let (mut stream, _) = control_listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        bytes
    });
    let mut client = TcpStream::connect(client_address).await.unwrap();
    client.write_all(&expected).await.unwrap();
    client.shutdown().await.unwrap();
    assert_eq!(captured.await.unwrap(), expected);
    let mut byte = [0u8; 1];
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            malicious_journal.read(&mut byte)
        )
        .await
        .is_err(),
        "reserved-name traffic must not open a stream on the seeded journal"
    );
    client_task.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn reserved_sni_completes_real_pop_registration_through_the_public_listener() {
    let fixture_key = SigningKey::from_bytes(&[7; 32]);
    let pop_key = SigningKey::from_bytes(&[19; 32]);
    let verifier = FixtureTokenVerifier::new(
        HashMap::from([(String::from("fixture"), fixture_key)]),
        String::from(BRIDGE_ID),
    );
    let registry = Registry::default();
    let (public_address, certificate, control_task, client_task) = start_bridge(
        registry.clone(),
        verifier.clone(),
        DEFAULT_ADMISSION_DEADLINE,
    )
    .await;
    let token = mint_token(&verifier, &pop_key, HOSTNAME);
    let journal = connect_and_authenticate(public_address, certificate, token, pop_key).await;
    wait_for_registration(&registry).await;
    drop(journal);
    control_task.abort();
    client_task.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn listener_splice_keeps_payload_out_of_logs_and_scratch_files() {
    let logs = LogBuffer(Arc::new(Mutex::new(Vec::new())));
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_writer(logs.clone())
        .finish();
    let _subscriber = tracing::subscriber::set_default(subscriber);

    let scratch = scratch_directory();
    std::fs::create_dir_all(&scratch).unwrap();

    let fixture_key = SigningKey::from_bytes(&[7; 32]);
    let pop_key = SigningKey::from_bytes(&[19; 32]);
    let verifier = FixtureTokenVerifier::new(
        HashMap::from([(String::from("fixture"), fixture_key)]),
        String::from(BRIDGE_ID),
    );
    let authenticator = PopAuthenticator::new(Arc::new(verifier.clone()), String::from(BRIDGE_ID));
    let registry = Registry::default();
    let (certificate, private_key) = certificate_fixture();
    let tls_config = Arc::new(server_tls_config(vec![certificate.clone()], private_key).unwrap());

    let control_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_address = control_listener.local_addr().unwrap();
    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_address = client_listener.local_addr().unwrap();
    let control_task = tokio::spawn(run_control_listener(
        control_listener,
        tls_config,
        registry.clone(),
        authenticator,
        DEFAULT_ADMISSION_DEADLINE,
    ));
    let client_task = tokio::spawn(run_client_listener(
        client_listener,
        registry.clone(),
        control_address,
        Duration::from_secs(1),
    ));

    let issued_at = u64::try_from(unix_seconds()).unwrap();
    let token = verifier
        .mint(
            "fixture",
            INSTANCE_ID,
            HOSTNAME,
            issued_at,
            issued_at + 600,
            &pop_key.verifying_key(),
        )
        .unwrap();
    let journal = connect_and_authenticate(
        control_address,
        certificate,
        token,
        SigningKey::from_bytes(&[19; 32]),
    )
    .await;
    wait_for_registration(&registry).await;

    let payload = distinctive_payload();
    let response = distinctive_response();
    let journal_task = tokio::spawn(journal_mux(journal, payload.clone(), response.clone()));
    let mut client = TcpStream::connect(client_address).await.unwrap();
    client.write_all(&client_hello(HOSTNAME)).await.unwrap();
    client.write_all(&payload).await.unwrap();
    client.flush().await.unwrap();
    let mut received = vec![0; response.len()];
    client.read_exact(&mut received).await.unwrap();
    assert_eq!(received, response);
    client.shutdown().await.unwrap();
    journal_task.await.unwrap();

    let captured = logs.0.lock().unwrap().clone();
    assert!(
        !captured
            .windows(HOSTNAME.len())
            .any(|window| window == HOSTNAME.as_bytes()),
        "hostname input must not be emitted into operational logs"
    );
    for protected in [&payload, &response] {
        assert!(
            !captured
                .windows(protected.len())
                .any(|window| window == protected.as_slice()),
            "payload bytes must never be emitted into logs"
        );
        let encoded = URL_SAFE_NO_PAD.encode(protected);
        assert!(
            !captured
                .windows(encoded.len())
                .any(|window| window == encoded.as_bytes()),
            "payload base64 must never be emitted into logs"
        );
    }
    assert_no_file_contains(&scratch, &payload);
    assert_no_file_contains(&scratch, &response);
    std::fs::remove_dir_all(&scratch).unwrap();

    control_task.abort();
    client_task.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn acceptance_criteria_3_and_5_admission_deadline_closes_stalled_peers_and_releases_nonce() {
    let fixture_key = SigningKey::from_bytes(&[7; 32]);
    let pop_key = SigningKey::from_bytes(&[19; 32]);
    let verifier = FixtureTokenVerifier::new(
        HashMap::from([(String::from("fixture"), fixture_key)]),
        String::from(BRIDGE_ID),
    );
    let registry = Registry::default();
    let (public_address, certificate, control_task, client_task) = start_bridge(
        registry.clone(),
        verifier.clone(),
        Duration::from_millis(200),
    )
    .await;

    let mut before_tls = TcpStream::connect(public_address).await.unwrap();
    assert_connection_closed(&mut before_tls).await;
    assert!(registry.lookup(HOSTNAME).await.is_none());

    let mut mid_tls = TcpStream::connect(public_address).await.unwrap();
    mid_tls
        .write_all(&[0x16, 0x03, 0x03, 0x00, 0x20, 0x01])
        .await
        .unwrap();
    mid_tls.flush().await.unwrap();
    assert_connection_closed(&mut mid_tls).await;
    assert!(registry.lookup(HOSTNAME).await.is_none());

    let token = mint_token(&verifier, &pop_key, HOSTNAME);
    let mut slow_proof = connect_control(public_address, certificate.clone()).await;
    write_message(
        &mut slow_proof,
        &RegistrationRequest {
            token: token.clone(),
            hostname: String::from(HOSTNAME),
        },
    )
    .await;
    let challenge: Challenge = read_message(&mut slow_proof).await;
    let response = challenge_response(&challenge, &pop_key);
    let response_bytes = serde_json::to_vec(&response).unwrap();
    slow_proof
        .write_u32(response_bytes.len().try_into().unwrap())
        .await
        .unwrap();
    slow_proof.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    let _ = slow_proof.write_all(&response_bytes[..1]).await;
    let _ = slow_proof.flush().await;

    let journal = connect_and_authenticate(
        public_address,
        certificate,
        token,
        SigningKey::from_bytes(&[19; 32]),
    )
    .await;
    wait_for_registration(&registry).await;
    assert_connection_closed(&mut slow_proof).await;
    drop(journal);
    control_task.abort();
    client_task.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn acceptance_criteria_11_and_12_use_verified_identity_and_fixed_admission_reasons() {
    let logs = LogBuffer(Arc::new(Mutex::new(Vec::new())));
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_writer(logs.clone())
        .finish();
    let _subscriber = tracing::subscriber::set_default(subscriber);

    let fixture_key = SigningKey::from_bytes(&[7; 32]);
    let pop_key = SigningKey::from_bytes(&[19; 32]);
    let verifier = FixtureTokenVerifier::new(
        HashMap::from([(String::from("fixture"), fixture_key)]),
        String::from(BRIDGE_ID),
    );
    let registry = Registry::default();
    let (public_address, certificate, control_task, client_task) = start_bridge(
        registry.clone(),
        verifier.clone(),
        Duration::from_millis(200),
    )
    .await;

    let rejected_token = String::from("token-must-not-appear-in-logs");
    let rejected_hostname = String::from("hostname-must-not-appear-in-logs.test");
    let mut token_rejection = connect_control(public_address, certificate.clone()).await;
    write_message(
        &mut token_rejection,
        &RegistrationRequest {
            token: rejected_token.clone(),
            hostname: rejected_hostname.clone(),
        },
    )
    .await;
    assert_connection_closed(&mut token_rejection).await;
    assert!(registry.lookup(&rejected_hostname).await.is_none());

    let claimed_hostname = String::from("claimed-hostname-must-not-appear-in-logs.test");
    let token = mint_token(&verifier, &pop_key, HOSTNAME);
    let mut mismatched_hostname = connect_control(public_address, certificate.clone()).await;
    write_message(
        &mut mismatched_hostname,
        &RegistrationRequest {
            token: token.clone(),
            hostname: claimed_hostname.clone(),
        },
    )
    .await;
    assert_connection_closed(&mut mismatched_hostname).await;
    assert!(registry.lookup(HOSTNAME).await.is_none());
    assert!(registry.lookup(&claimed_hostname).await.is_none());

    let framing_payload = b"framing-payload-must-not-appear-in-logs";
    let mut framing_rejection = connect_control(public_address, certificate.clone()).await;
    framing_rejection
        .write_u32(framing_payload.len().try_into().unwrap())
        .await
        .unwrap();
    framing_rejection.write_all(framing_payload).await.unwrap();
    framing_rejection.flush().await.unwrap();
    assert_connection_closed(&mut framing_rejection).await;

    let mut timeout_rejection = connect_control(public_address, certificate.clone()).await;
    assert_connection_closed(&mut timeout_rejection).await;

    let journal = connect_and_authenticate(
        public_address,
        certificate,
        token.clone(),
        SigningKey::from_bytes(&[19; 32]),
    )
    .await;
    wait_for_registration(&registry).await;
    drop(journal);

    let captured = wait_for_log_fragments(
        &logs,
        [
            "journal registration rejected: token rejection",
            "journal registration rejected: framing or proof rejection",
            "journal registration timed out",
        ],
    )
    .await;
    for protected in [
        rejected_token.as_bytes(),
        rejected_hostname.as_bytes(),
        claimed_hostname.as_bytes(),
        HOSTNAME.as_bytes(),
        token.as_bytes(),
        framing_payload.as_slice(),
    ] {
        assert!(
            !captured
                .windows(protected.len())
                .any(|window| window == protected),
            "admission logs must not include protected registration input"
        );
    }

    control_task.abort();
    client_task.abort();
}

async fn start_bridge(
    registry: Registry,
    verifier: FixtureTokenVerifier,
    admission_deadline: Duration,
) -> (
    std::net::SocketAddr,
    CertificateDer<'static>,
    tokio::task::JoinHandle<()>,
    tokio::task::JoinHandle<()>,
) {
    let (certificate, private_key) = certificate_fixture();
    let tls_config = Arc::new(server_tls_config(vec![certificate.clone()], private_key).unwrap());
    let control_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_address = control_listener.local_addr().unwrap();
    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_address = client_listener.local_addr().unwrap();
    let authenticator = PopAuthenticator::new(Arc::new(verifier), String::from(BRIDGE_ID));
    let task = tokio::spawn(run_control_listener(
        control_listener,
        tls_config,
        registry.clone(),
        authenticator,
        admission_deadline,
    ));
    let client_task = tokio::spawn(run_client_listener(
        client_listener,
        registry,
        control_address,
        admission_deadline,
    ));
    (client_address, certificate, task, client_task)
}

fn certificate_fixture() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let key = KeyPair::generate().unwrap();
    let params = CertificateParams::new(vec![String::from("bridge.solstone.me")]).unwrap();
    let certificate = params.self_signed(&key).unwrap();
    (
        CertificateDer::from(certificate.der().to_vec()),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
}

async fn connect_and_authenticate(
    address: std::net::SocketAddr,
    certificate: CertificateDer<'static>,
    token: String,
    pop_key: SigningKey,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let mut journal = connect_control(address, certificate).await;
    write_message(
        &mut journal,
        &RegistrationRequest {
            token,
            hostname: String::from(HOSTNAME),
        },
    )
    .await;
    let challenge: Challenge = read_message(&mut journal).await;
    write_message(&mut journal, &challenge_response(&challenge, &pop_key)).await;
    journal
}

async fn connect_control(
    address: std::net::SocketAddr,
    certificate: CertificateDer<'static>,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let mut roots = RootCertStore::empty();
    roots.add(certificate).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = ServerName::try_from("bridge.solstone.me")
        .unwrap()
        .to_owned();
    TlsConnector::from(Arc::new(config))
        .connect(server_name, TcpStream::connect(address).await.unwrap())
        .await
        .unwrap()
}

fn challenge_response(challenge: &Challenge, pop_key: &SigningKey) -> ChallengeResponse {
    let nonce: [u8; 16] = URL_SAFE_NO_PAD
        .decode(&challenge.nonce)
        .unwrap()
        .try_into()
        .unwrap();
    let mut signed = Vec::new();
    signed.extend_from_slice(&nonce);
    signed.extend_from_slice(challenge.bridge_id.as_bytes());
    signed.extend_from_slice(&challenge.timestamp.to_be_bytes());
    ChallengeResponse {
        signature: URL_SAFE_NO_PAD.encode(pop_key.sign(&signed).to_bytes()),
    }
}

fn mint_token(verifier: &FixtureTokenVerifier, pop_key: &SigningKey, hostname: &str) -> String {
    let issued_at = u64::try_from(unix_seconds()).unwrap();
    verifier
        .mint(
            "fixture",
            INSTANCE_ID,
            hostname,
            issued_at,
            issued_at + 600,
            &pop_key.verifying_key(),
        )
        .unwrap()
}

async fn assert_connection_closed<S>(carrier: &mut S)
where
    S: AsyncRead + Unpin,
{
    let mut byte = [0u8; 1];
    let result = tokio::time::timeout(Duration::from_secs(1), carrier.read(&mut byte))
        .await
        .unwrap();
    assert!(
        matches!(result, Ok(0) | Err(_)),
        "timed-out admission must close its carrier"
    );
}

async fn wait_for_log_fragments<const N: usize>(logs: &LogBuffer, fragments: [&str; N]) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let captured = logs.0.lock().unwrap().clone();
            if fragments.iter().all(|fragment| {
                captured
                    .windows(fragment.len())
                    .any(|window| window == fragment.as_bytes())
            }) {
                return captured;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap()
}

async fn write_message<S, T>(carrier: &mut S, message: &T)
where
    S: AsyncWrite + Unpin,
    T: Serialize,
{
    let bytes = serde_json::to_vec(message).unwrap();
    carrier
        .write_u32(bytes.len().try_into().unwrap())
        .await
        .unwrap();
    carrier.write_all(&bytes).await.unwrap();
    carrier.flush().await.unwrap();
}

async fn read_message<S, T>(carrier: &mut S) -> T
where
    S: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let length: usize = carrier.read_u32().await.unwrap().try_into().unwrap();
    let mut bytes = vec![0; length];
    carrier.read_exact(&mut bytes).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn wait_for_registration(registry: &Registry) {
    tokio::time::timeout(Duration::from_secs(1), async {
        while registry.lookup(HOSTNAME).await.is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

async fn journal_mux(
    mut journal: tokio_rustls::client::TlsStream<TcpStream>,
    payload: Vec<u8>,
    response: Vec<u8>,
) {
    let mut acceptor = MuxAcceptor::new(MuxLimits::default()).unwrap();
    let mut received = Vec::new();
    let mut stream_id = None;
    let mut sent_response = false;
    let mut bytes = [0; 16 * 1024];
    loop {
        let count = journal.read(&mut bytes).await.unwrap();
        if count == 0 {
            break;
        }
        let output = acceptor.feed(&bytes[..count]).unwrap();
        write_frames(&mut journal, &output.frames).await;
        let mut read_closed = false;
        for event in output.events {
            match event {
                MuxEvent::Opened { stream_id: opened } => stream_id = Some(opened),
                MuxEvent::Data {
                    stream_id: _,
                    bytes,
                } => {
                    received.extend_from_slice(&bytes);
                    if !sent_response
                        && received
                            .windows(payload.len())
                            .any(|window| window == payload.as_slice())
                    {
                        let output = acceptor
                            .try_send_data(stream_id.unwrap(), response.clone())
                            .unwrap()
                            .unwrap();
                        write_frames(&mut journal, &output.frames).await;
                        sent_response = true;
                    }
                }
                MuxEvent::ReadClosed { .. }
                | MuxEvent::Reset { .. }
                | MuxEvent::PeerGone { .. } => {
                    read_closed = true;
                }
            }
        }
        if read_closed {
            break;
        }
    }
    assert!(
        sent_response,
        "journal must observe the distinctive client payload before closing"
    );
}

async fn write_frames<S>(carrier: &mut S, frames: &[spl_core::frame::Frame])
where
    S: AsyncWrite + Unpin,
{
    for frame in frames {
        carrier.write_all(&frame.encode().unwrap()).await.unwrap();
    }
    carrier.flush().await.unwrap();
}

fn client_hello(hostname: &str) -> Vec<u8> {
    let mut names = Vec::new();
    names.push(0);
    push_u16(&mut names, hostname.len().try_into().unwrap());
    names.extend_from_slice(hostname.as_bytes());
    let mut server_name = Vec::new();
    push_u16(&mut server_name, names.len().try_into().unwrap());
    server_name.extend_from_slice(&names);
    let mut extensions = Vec::new();
    push_u16(&mut extensions, 0);
    push_u16(&mut extensions, server_name.len().try_into().unwrap());
    extensions.extend_from_slice(&server_name);

    let mut body = vec![0x03, 0x03];
    body.extend([0x55; 32]);
    body.push(0);
    push_u16(&mut body, 2);
    body.extend([0x13, 0x01]);
    body.extend([1, 0]);
    push_u16(&mut body, extensions.len().try_into().unwrap());
    body.extend_from_slice(&extensions);

    let mut handshake = vec![1];
    handshake.extend_from_slice(&[
        (body.len() >> 16).try_into().unwrap(),
        (body.len() >> 8).try_into().unwrap(),
        body.len().try_into().unwrap(),
    ]);
    handshake.extend_from_slice(&body);
    let mut record = vec![0x16, 0x03, 0x01];
    push_u16(&mut record, handshake.len().try_into().unwrap());
    record.extend_from_slice(&handshake);
    record
}

fn fragment_client_hello(hello: &[u8], seed: u32) -> Vec<u8> {
    let handshake = &hello[5..];
    let mut output = Vec::new();
    let mut position = 0;
    let mut state = seed;
    while position < handshake.len() {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let mut payload_length = 1 + usize::try_from((state >> 24) % 7).unwrap();
        if position < 4 {
            payload_length = [1, 2, 1][position.min(2)];
        }
        let end = (position + payload_length).min(handshake.len());
        output.extend([0x16, 0x03, 0x01]);
        push_u16(&mut output, (end - position).try_into().unwrap());
        output.extend_from_slice(&handshake[position..end]);
        position = end;
    }
    output
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn distinctive_payload() -> Vec<u8> {
    let mut payload = b"bridge-client-payload-must-not-be-retained-".to_vec();
    payload.extend((0u8..64).map(|index| index.wrapping_mul(29).wrapping_add(11)));
    payload
}

fn distinctive_response() -> Vec<u8> {
    let mut response = b"journal-response-must-not-be-retained-".to_vec();
    response.extend((0u8..64).map(|index| index.wrapping_mul(17).wrapping_add(3)));
    response
}

fn unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .try_into()
        .unwrap()
}

fn scratch_directory() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    Path::new("/var/tmp").join(format!(
        "spl-bridge-zero-retention-{}-{nanos}",
        std::process::id()
    ))
}

fn assert_no_file_contains(root: &Path, protected: &[u8]) {
    let mut paths = Vec::new();
    collect_files(root, &mut paths);
    for path in paths {
        let contents = std::fs::read(&path).unwrap();
        assert!(
            !contents
                .windows(protected.len())
                .any(|window| window == protected),
            "scratch file {} retained payload bytes",
            path.display()
        );
    }
}

fn collect_files(root: &Path, paths: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if entry.file_type().unwrap().is_dir() {
            collect_files(&path, paths);
        } else {
            paths.push(path);
        }
    }
}
