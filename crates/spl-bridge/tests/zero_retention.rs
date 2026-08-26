// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! End-to-end retention boundaries for public bridge listener traffic.

#![expect(
    clippy::unwrap_used,
    reason = "integration fixtures use controlled local certificates, sockets, and paths"
)]

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
};
use spl_bridge::registry::Registry;
use spl_bridge::{run_client_listener, run_control_listener, server_tls_config};
use spl_home::{MuxAcceptor, MuxEvent, MuxLimits};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

const HOSTNAME: &str = "journal-retention.test";
const POP_DOMAIN_SEPARATOR: &[u8] = b"spl-bridge-pop-v1\0";

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
    let verifier = FixtureTokenVerifier::new([(String::from("fixture"), fixture_key)]).unwrap();
    let authenticator = PopAuthenticator::new(Arc::new(verifier.clone()));
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
    ));
    let client_task = tokio::spawn(run_client_listener(
        client_listener,
        registry.clone(),
        Duration::from_secs(1),
    ));

    let token = verifier
        .mint(
            "fixture",
            HOSTNAME,
            unix_seconds(),
            unix_seconds() + 60,
            pop_key.verifying_key(),
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
        captured
            .windows(HOSTNAME.len())
            .any(|window| window == HOSTNAME.as_bytes()),
        "the operational log capture must contain routing metadata"
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

fn certificate_fixture() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let key = KeyPair::generate().unwrap();
    let params = CertificateParams::new(vec![String::from("bridge.test")]).unwrap();
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
    let mut roots = RootCertStore::empty();
    roots.add(certificate).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = ServerName::try_from("bridge.test").unwrap().to_owned();
    let mut journal = TlsConnector::from(Arc::new(config))
        .connect(server_name, TcpStream::connect(address).await.unwrap())
        .await
        .unwrap();
    write_message(
        &mut journal,
        &RegistrationRequest {
            token,
            hostname: String::from(HOSTNAME),
        },
    )
    .await;
    let challenge: Challenge = read_message(&mut journal).await;
    let nonce: [u8; 32] = URL_SAFE_NO_PAD
        .decode(challenge.nonce)
        .unwrap()
        .try_into()
        .unwrap();
    let timestamp = unix_seconds();
    let mut signed = Vec::new();
    signed.extend_from_slice(POP_DOMAIN_SEPARATOR);
    signed.extend_from_slice(&nonce);
    signed.extend_from_slice(&timestamp.to_be_bytes());
    let response = ChallengeResponse {
        timestamp,
        signature: URL_SAFE_NO_PAD.encode(pop_key.sign(&signed).to_bytes()),
    };
    write_message(&mut journal, &response).await;
    journal
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
