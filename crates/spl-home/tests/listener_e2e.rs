// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "integration fixtures use direct setup assertions at their exact failure site"
)]

//! Both-roles-in-one-process, multi-stream listener-side protocol coverage.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, ExtendedKeyUsagePurpose,
    IsCa, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    AlertDescription, CertificateError, DigitallySignedStruct, Error, RootCertStore,
    SignatureScheme,
};
use spl_core::PairRequest;
use spl_core::ca::sha256;
use spl_core::frame::{
    FLAG_CLOSE, FLAG_DATA, FLAG_OPEN, FLAG_PONG, FLAG_WINDOW, Frame, FrameDecoder, FrameDialer,
    RECOMMENDED_CHUNK, RESET_CANCEL,
};
use spl_core::mux::INITIAL_WINDOW;
use spl_core::pairlink::RelayPairLink;
use spl_home::{
    HomeConfig, HomeConnection, MuxLimits, PairSecret, PairWindow, PairWindowConfig,
    PairWindowRefusal,
};
use spl_transport::TransportError;
use spl_transport::relay_pairing::pair_over_carrier;
use spl_transport::tls::mtls_config;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

struct Fixture {
    ca: CertificateDer<'static>,
    server_chain: Vec<CertificateDer<'static>>,
    server_key: PrivateKeyDer<'static>,
    client_chain: Vec<CertificateDer<'static>>,
    client_key: PrivateKeyDer<'static>,
}

fn fixture() -> Fixture {
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
    let mut client_params = CertificateParams::new(vec!["dialer.test".to_owned()]).unwrap();
    client_params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);
    let client = client_params.signed_by(&client_key, &ca, &ca_key).unwrap();

    Fixture {
        ca: ca_der.clone(),
        server_chain: vec![CertificateDer::from(server.der().to_vec()), ca_der.clone()],
        server_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
        client_chain: vec![CertificateDer::from(client.der().to_vec()), ca_der],
        client_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(client_key.serialize_der())),
    }
}

fn verifier(ca: CertificateDer<'static>) -> Arc<dyn ClientCertVerifier> {
    let mut roots = RootCertStore::empty();
    roots
        .add(ca)
        .expect("the test CA is a valid root certificate");
    rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .unwrap()
}

fn config(fixture: &Fixture, verifier: Arc<dyn ClientCertVerifier>) -> HomeConfig {
    HomeConfig {
        certificate_chain: fixture.server_chain.clone(),
        private_key: fixture.server_key.clone_key(),
        client_cert_verifier: verifier,
        mux_limits: MuxLimits::default(),
    }
}

fn client_config(fixture: &Fixture) -> rustls::ClientConfig {
    mtls_config(
        &sha256(fixture.ca.as_ref())[..16],
        fixture.client_chain.clone(),
        fixture.client_key.clone_key(),
    )
    .unwrap()
}

struct PairFixture {
    ca: CertificateDer<'static>,
    ca_cert: rcgen::Certificate,
    ca_key: KeyPair,
    server_chain: Vec<CertificateDer<'static>>,
    server_key: PrivateKeyDer<'static>,
}

fn pair_fixture() -> PairFixture {
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca = CertificateDer::from(ca_cert.der().to_vec());

    let server_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut server_params = CertificateParams::new(vec!["spl.local".to_owned()]).unwrap();
    server_params.is_ca = IsCa::NoCa;
    server_params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    let server = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .unwrap();

    PairFixture {
        ca: ca.clone(),
        ca_cert,
        ca_key,
        server_chain: vec![CertificateDer::from(server.der().to_vec()), ca],
        server_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
    }
}

fn pair_window_config(fixture: &PairFixture) -> PairWindowConfig {
    PairWindowConfig {
        certificate_chain: fixture.server_chain.clone(),
        private_key: fixture.server_key.clone_key(),
        ca_certificate: fixture.ca.clone(),
        mux_limits: MuxLimits::default(),
    }
}

fn pair_link(fixture: &PairFixture) -> RelayPairLink {
    let spki = spl_core::ca::extract_spki_der(fixture.ca.as_ref()).unwrap();
    RelayPairLink {
        s: [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
        ca_fp_spki: sha256(&spki)[..16].to_vec(),
        relay_origin: "https://relay.invalid".to_owned(),
    }
}

struct CountingIo<S> {
    inner: S,
    written: Arc<AtomicUsize>,
}

impl<S> CountingIo<S> {
    fn new(inner: S, written: Arc<AtomicUsize>) -> Self {
        Self { inner, written }
    }
}

impl<S> tokio::io::AsyncRead for CountingIo<S>
where
    S: tokio::io::AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        read_buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, read_buf)
    }
}

impl<S> tokio::io::AsyncWrite for CountingIo<S>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write(context, bytes) {
            Poll::Ready(Ok(count)) => {
                self.written.fetch_add(count, Ordering::SeqCst);
                Poll::Ready(Ok(count))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

async fn serve_pair_response(
    stream: &mut spl_home::HomeStream,
    fixture: &PairFixture,
    instance_id: &str,
) {
    let mut request = Vec::new();
    stream.read_to_end(&mut request).await.unwrap();
    let body_start = request
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap()
        + 4;
    let request: PairRequest = serde_json::from_slice(&request[body_start..]).unwrap();
    let client_cert = CertificateSigningRequestParams::from_pem(&request.csr)
        .unwrap()
        .signed_by(&fixture.ca_cert, &fixture.ca_key)
        .unwrap();
    let response = serde_json::json!({
        "client_cert": client_cert.pem(),
        "ca_chain": [fixture.ca_cert.pem()],
        "instance_id": instance_id,
        "home_label": "Home",
        "fingerprint": format!("sha256:{}", spl_core::ca::sha256_hex(client_cert.der())),
        "home_attestation": "attestation"
    });
    let body = response.to_string();
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await.unwrap();
    stream.shutdown().await.unwrap();
}

async fn complete_pair_ceremony(
    window: &mut PairWindow,
    fixture: &PairFixture,
    response_instance_id: &str,
) -> Result<(), TransportError> {
    let link = pair_link(fixture);
    let (dialer_io, home_io) = tokio::io::duplex(64 * 1024);
    let client = tokio::spawn(async move {
        pair_over_carrier(
            dialer_io,
            &link,
            "pair-window-test",
            &serde_json::Map::new(),
        )
        .await
    });
    let relay_key = window.relay_key_hex();
    let mut home = window
        .admit(home_io, relay_key.as_str(), Instant::now())
        .await
        .unwrap();
    let mut stream = home.accept_stream().await.unwrap();
    serve_pair_response(&mut stream, fixture, response_instance_id).await;
    client.await.unwrap().map(|_| ())
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "the test emits frame literals directly into the wire helper"
)]
fn wire(frame: Frame) -> Vec<u8> {
    frame.encode().unwrap()
}

async fn read_frames<S>(
    stream: &mut tokio_rustls::client::TlsStream<S>,
    decoder: &mut FrameDecoder,
) -> Vec<Frame>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut buffer = [0u8; 4096];
    let read = stream.read(&mut buffer).await.unwrap();
    decoder.feed(&buffer[..read]);
    decoder.drain().unwrap()
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one ordered exchange must keep its framing assertions together"
)]
async fn multi_stream_listener_flow_control_half_close_reset_and_ping_pong() {
    // Protocol framing.md:75-97, :120-129, :155-159, and :181-197.
    let fixture = fixture();
    let (dialer_io, home_io) = tokio::io::duplex(2 * 1024 * 1024);
    let home = tokio::spawn(HomeConnection::accept(
        home_io,
        config(&fixture, verifier(fixture.ca.clone())),
    ));
    let connector = TlsConnector::from(Arc::new(client_config(&fixture)));
    let mut dialer = connector
        .connect(ServerName::try_from("spl.local").unwrap(), dialer_io)
        .await
        .unwrap();
    let mut home = home.await.unwrap().unwrap();

    let mut ids = FrameDialer::default();
    let first = ids.allocate();
    let second = ids.allocate();
    let body = vec![0x5a; INITIAL_WINDOW + 2 * RECOMMENDED_CHUNK];
    let mut outbound = Vec::new();
    for (index, chunk) in body[..INITIAL_WINDOW].chunks(RECOMMENDED_CHUNK).enumerate() {
        let flags = if index == 0 {
            FLAG_OPEN | FLAG_DATA
        } else {
            FLAG_DATA
        };
        outbound.push(Frame::new(first, flags, chunk.to_vec()));
    }
    outbound.push(Frame::new(second, FLAG_OPEN, Vec::new()));
    outbound.push(Frame::control_ping([1, 2, 3, 4, 5, 6, 7, 8]));
    for frame in outbound {
        dialer.write_all(&wire(frame)).await.unwrap();
    }

    let mut first_stream = home.accept_stream().await.unwrap();
    let mut second_stream = home.accept_stream().await.unwrap();
    assert_eq!((first_stream.id(), second_stream.id()), (first, second));
    let mut consumed = vec![0; INITIAL_WINDOW / 2];
    first_stream.read_exact(&mut consumed).await.unwrap();
    assert_eq!(consumed, vec![0x5a; INITIAL_WINDOW / 2]);

    let mut decoder = FrameDecoder::new();
    let mut received = Vec::new();
    while !received
        .iter()
        .any(|frame: &Frame| frame.flags == FLAG_WINDOW)
        || !received
            .iter()
            .any(|frame: &Frame| frame.flags == FLAG_PONG)
    {
        received.extend(read_frames(&mut dialer, &mut decoder).await);
    }
    assert!(received.iter().any(|frame| {
        frame.stream_id == first
            && frame.flags == FLAG_WINDOW
            && frame.window_credit() == Some(524_288)
    }));
    assert!(received.iter().any(|frame| {
        frame.stream_id == 0
            && frame.flags == FLAG_PONG
            && frame.payload == vec![1, 2, 3, 4, 5, 6, 7, 8]
    }));

    let mut admitted_tail = vec![0; INITIAL_WINDOW / 2];
    first_stream.read_exact(&mut admitted_tail).await.unwrap();
    assert_eq!(admitted_tail, vec![0x5a; INITIAL_WINDOW / 2]);

    for chunk in body[INITIAL_WINDOW..].chunks(RECOMMENDED_CHUNK) {
        dialer
            .write_all(&wire(Frame::new(first, FLAG_DATA, chunk.to_vec())))
            .await
            .unwrap();
    }
    dialer
        .write_all(&wire(Frame::new(first, FLAG_CLOSE, Vec::new())))
        .await
        .unwrap();
    dialer
        .write_all(&wire(Frame::reset(second, RESET_CANCEL)))
        .await
        .unwrap();

    let mut remainder = vec![0; 2 * RECOMMENDED_CHUNK];
    first_stream.read_exact(&mut remainder).await.unwrap();
    assert_eq!(remainder, vec![0x5a; 2 * RECOMMENDED_CHUNK]);
    let mut eof_probe = [0u8; 1];
    assert_eq!(first_stream.read(&mut eof_probe).await.unwrap(), 0);
    let reset = second_stream.read(&mut eof_probe).await.unwrap_err();
    assert_eq!(reset.kind(), io::ErrorKind::ConnectionReset);

    // Protocol framing.md:155-159 and :191-197: queued listener DATA is
    // fragmented, but a PONG is written ahead of the next queued DATA frame.
    let listener_body = vec![0x33; 2 * RECOMMENDED_CHUNK + 7];
    first_stream.write_all(&listener_body).await.unwrap();
    tokio::task::yield_now().await;
    dialer
        .write_all(&wire(Frame::control_ping([9, 8, 7, 6, 5, 4, 3, 2])))
        .await
        .unwrap();
    let mut listener_frames = Vec::new();
    let mut listener_decoder = FrameDecoder::new();
    while listener_frames
        .iter()
        .filter(|frame: &&Frame| frame.stream_id == first && frame.flags == FLAG_DATA)
        .map(|frame| frame.payload.len())
        .sum::<usize>()
        < listener_body.len()
        || !listener_frames.iter().any(|frame: &Frame| {
            frame.stream_id == 0
                && frame.flags == FLAG_PONG
                && frame.payload == vec![9, 8, 7, 6, 5, 4, 3, 2]
        })
    {
        listener_frames.extend(read_frames(&mut dialer, &mut listener_decoder).await);
    }
    let data_indices: Vec<usize> = listener_frames
        .iter()
        .enumerate()
        .filter_map(|(index, frame)| {
            (frame.stream_id == first && frame.flags == FLAG_DATA).then_some(index)
        })
        .collect();
    let pong_index = listener_frames
        .iter()
        .position(|frame| frame.stream_id == 0 && frame.flags == FLAG_PONG)
        .unwrap();
    let reassembled: Vec<u8> = listener_frames
        .iter()
        .filter(|frame| frame.stream_id == first && frame.flags == FLAG_DATA)
        .flat_map(|frame| frame.payload.clone())
        .collect();
    assert_eq!(reassembled, listener_body);
    assert!(
        listener_frames
            .iter()
            .filter(|frame| frame.stream_id == first && frame.flags == FLAG_DATA)
            .all(|frame| frame.payload.len() <= RECOMMENDED_CHUNK)
    );
    assert!(data_indices.len() >= 2);
    assert!(pong_index < data_indices[1]);
}

#[derive(Debug)]
struct RejectVerifier;

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
        Err(Error::InvalidCertificate(
            CertificateError::ApplicationVerificationFailure,
        ))
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

#[tokio::test]
async fn rejected_client_certificate_surfaces_access_denied_to_dialer() {
    // TLS 1.3 client-auth rejection must remain observable as AccessDenied.
    let fixture = fixture();
    let (dialer_io, home_io) = tokio::io::duplex(64 * 1024);
    let home = tokio::spawn(HomeConnection::accept(
        home_io,
        config(&fixture, Arc::new(RejectVerifier)),
    ));
    let connector = TlsConnector::from(Arc::new(client_config(&fixture)));
    let mut dialer = connector
        .connect(ServerName::try_from("spl.local").unwrap(), dialer_io)
        .await
        .unwrap();
    let mut byte = [0u8; 1];
    let rejection = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        dialer.read(&mut byte),
    )
    .await;
    assert!(
        matches!(rejection, Ok(Err(_))),
        "rejected client authentication must yield a client I/O error"
    );
    let error = rejection.unwrap().unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        error
            .get_ref()
            .and_then(|error| error.downcast_ref::<Error>()),
        Some(&Error::AlertReceived(AlertDescription::AccessDenied))
    );
    assert!(matches!(home.await.unwrap(), Err(spl_home::HomeError::Tls)));
}

#[tokio::test]
async fn partial_frame_eof_ends_the_driver_as_peer_gone() {
    // Protocol framing.md:185 requires complete frames. Classifying carrier
    // EOF with partial local bytes as peer loss is local carrier policy.
    let fixture = fixture();
    let (dialer_io, home_io) = tokio::io::duplex(64 * 1024);
    let home = tokio::spawn(HomeConnection::accept(
        home_io,
        config(&fixture, verifier(fixture.ca.clone())),
    ));
    let connector = TlsConnector::from(Arc::new(client_config(&fixture)));
    let mut dialer = connector
        .connect(ServerName::try_from("spl.local").unwrap(), dialer_io)
        .await
        .unwrap();
    let mut home = home.await.unwrap().unwrap();
    dialer.write_all(&[0, 0, 0]).await.unwrap();
    drop(dialer);
    assert!(matches!(
        tokio::time::timeout(std::time::Duration::from_millis(100), home.accept_stream()).await,
        Ok(Err(spl_home::HomeError::PeerGone))
    ));
}

#[tokio::test]
async fn reset_discards_buffered_data_without_ending_other_streams() {
    // Protocol framing.md:75-97: RESET abandons a stream, not its carrier.
    let fixture = fixture();
    let (dialer_io, home_io) = tokio::io::duplex(64 * 1024);
    let home = tokio::spawn(HomeConnection::accept(
        home_io,
        config(&fixture, verifier(fixture.ca.clone())),
    ));
    let connector = TlsConnector::from(Arc::new(client_config(&fixture)));
    let mut dialer = connector
        .connect(ServerName::try_from("spl.local").unwrap(), dialer_io)
        .await
        .unwrap();
    let mut home = home.await.unwrap().unwrap();
    let mut ids = FrameDialer::default();
    let first = ids.allocate();
    let second = ids.allocate();
    dialer
        .write_all(&wire(Frame::new(
            first,
            FLAG_OPEN | FLAG_DATA,
            b"stale".to_vec(),
        )))
        .await
        .unwrap();
    dialer
        .write_all(&wire(Frame::new(second, FLAG_OPEN, Vec::new())))
        .await
        .unwrap();

    let mut first_stream = home.accept_stream().await.unwrap();
    let mut second_stream = home.accept_stream().await.unwrap();
    let mut admitted = [0u8; 1];
    first_stream.read_exact(&mut admitted).await.unwrap();
    assert_eq!(admitted, [b's']);

    dialer
        .write_all(&wire(Frame::reset(first, RESET_CANCEL)))
        .await
        .unwrap();
    dialer
        .write_all(&wire(Frame::new(second, FLAG_DATA, b"request".to_vec())))
        .await
        .unwrap();

    let mut request = [0u8; 7];
    second_stream.read_exact(&mut request).await.unwrap();
    assert_eq!(request, *b"request");
    let reset = first_stream.read(&mut admitted).await.unwrap_err();
    assert_eq!(reset.kind(), io::ErrorKind::ConnectionReset);

    second_stream.write_all(b"response").await.unwrap();
    let mut decoder = FrameDecoder::new();
    let mut frames = Vec::new();
    while !frames.iter().any(|frame: &Frame| {
        frame.stream_id == second && frame.flags == FLAG_DATA && frame.payload == b"response"
    }) {
        frames.extend(read_frames(&mut dialer, &mut decoder).await);
    }
}

#[tokio::test]
async fn pairing_window_completes_verified_ceremony_and_publishes_rk() {
    let fixture = pair_fixture();
    let now = Instant::now();
    let mut window = PairWindow::open(
        PairSecret::from([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]),
        now + Duration::from_mins(1),
        pair_window_config(&fixture),
    )
    .unwrap();
    assert_eq!(
        window.relay_key_hex().as_str(),
        "e34481a4cde647ba9c9fb29a59e18271"
    );
    let instance_id = window.instance_id().to_owned();
    complete_pair_ceremony(&mut window, &fixture, &instance_id)
        .await
        .unwrap();
}

#[tokio::test]
async fn pairing_window_failed_handshake_rolls_back_for_retry() {
    let fixture = pair_fixture();
    let now = Instant::now();
    let mut window = PairWindow::open(
        PairSecret::from([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]),
        now + Duration::from_mins(1),
        pair_window_config(&fixture),
    )
    .unwrap();
    let relay_key = window.relay_key_hex();
    let (dialer, failed_home_io) = tokio::io::duplex(64 * 1024);
    drop(dialer);
    let failed = window.admit(failed_home_io, relay_key.as_str(), now).await;
    assert!(matches!(failed, Err(spl_home::HomeError::Tls)));

    let instance_id = window.instance_id().to_owned();
    let link = pair_link(&fixture);
    let (dialer_io, home_io) = tokio::io::duplex(64 * 1024);
    let client = tokio::spawn(async move {
        pair_over_carrier(
            dialer_io,
            &link,
            "pair-window-test",
            &serde_json::Map::new(),
        )
        .await
    });
    let retry = window
        .admit(home_io, relay_key.as_str(), Instant::now())
        .await;
    assert!(
        retry.is_ok(),
        "a failed TLS handshake must not consume the pairing window"
    );
    let mut home = retry.unwrap();
    let mut stream = home.accept_stream().await.unwrap();
    serve_pair_response(&mut stream, &fixture, &instance_id).await;
    assert!(client.await.unwrap().is_ok());
}

#[tokio::test]
async fn pairing_window_client_rejects_non_jid_instance_id() {
    let fixture = pair_fixture();
    let now = Instant::now();
    let mut window = PairWindow::open(
        PairSecret::from([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]),
        now + Duration::from_mins(1),
        pair_window_config(&fixture),
    )
    .unwrap();
    let error = complete_pair_ceremony(&mut window, &fixture, "not-a-jid")
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        TransportError::Pairing(message) if message == "relay instance mismatch"
    ));
}

#[tokio::test]
async fn pairing_window_wrong_rk_writes_no_carrier_bytes() {
    let fixture = pair_fixture();
    let now = Instant::now();
    let mut window = PairWindow::open(
        PairSecret::from([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]),
        now + Duration::from_mins(1),
        pair_window_config(&fixture),
    )
    .unwrap();
    let (dialer, home_io) = tokio::io::duplex(64 * 1024);
    drop(dialer);
    let written = Arc::new(AtomicUsize::new(0));
    let result = window
        .admit(
            CountingIo::new(home_io, written.clone()),
            "00000000000000000000000000000000",
            now,
        )
        .await;
    assert!(matches!(
        result,
        Err(spl_home::HomeError::PairWindowRefused(
            PairWindowRefusal::WrongRelayKey
        ))
    ));
    assert_eq!(written.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn pairing_window_consumed_redial_writes_no_carrier_bytes() {
    let fixture = pair_fixture();
    let now = Instant::now();
    let mut window = PairWindow::open(
        PairSecret::from([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]),
        now + Duration::from_mins(1),
        pair_window_config(&fixture),
    )
    .unwrap();
    let instance_id = window.instance_id().to_owned();
    complete_pair_ceremony(&mut window, &fixture, &instance_id)
        .await
        .unwrap();

    let relay_key = window.relay_key_hex();
    let (dialer, home_io) = tokio::io::duplex(64 * 1024);
    drop(dialer);
    let written = Arc::new(AtomicUsize::new(0));
    let result = window
        .admit(
            CountingIo::new(home_io, written.clone()),
            relay_key.as_str(),
            Instant::now(),
        )
        .await;
    assert!(matches!(
        result,
        Err(spl_home::HomeError::PairWindowRefused(
            PairWindowRefusal::Consumed
        ))
    ));
    assert_eq!(written.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn pairing_window_expired_writes_no_carrier_bytes() {
    let fixture = pair_fixture();
    let now = Instant::now();
    let mut window = PairWindow::open(
        PairSecret::from([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]),
        now,
        pair_window_config(&fixture),
    )
    .unwrap();
    let relay_key = window.relay_key_hex();
    let (dialer, home_io) = tokio::io::duplex(64 * 1024);
    drop(dialer);
    let written = Arc::new(AtomicUsize::new(0));
    let result = window
        .admit(
            CountingIo::new(home_io, written.clone()),
            relay_key.as_str(),
            now,
        )
        .await;
    assert!(matches!(
        result,
        Err(spl_home::HomeError::PairWindowRefused(
            PairWindowRefusal::Expired
        ))
    ));
    assert_eq!(written.load(Ordering::SeqCst), 0);
}

#[test]
fn tls13_session_tickets_remain_enabled_by_default() {
    let fixture = fixture();
    let server = config(&fixture, verifier(fixture.ca.clone()))
        .server_config()
        .unwrap();
    assert_eq!(server.send_tls13_tickets, 2);
}
