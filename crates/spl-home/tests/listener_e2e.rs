// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "integration fixtures use direct setup assertions at their exact failure site"
)]

//! Both-roles-in-one-process, multi-stream listener-side protocol coverage.

use std::io;
use std::sync::Arc;

use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    AlertDescription, CertificateError, DigitallySignedStruct, Error, RootCertStore,
    SignatureScheme,
};
use spl_core::ca::sha256;
use spl_core::frame::{
    FLAG_CLOSE, FLAG_DATA, FLAG_OPEN, FLAG_PONG, FLAG_WINDOW, Frame, FrameDecoder, FrameDialer,
    RECOMMENDED_CHUNK, RESET_CANCEL,
};
use spl_core::mux::INITIAL_WINDOW;
use spl_home::{HomeConfig, HomeConnection, MuxLimits};
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
    // Protocol framing.md:29-36: EOF in a partial frame is carrier loss.
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

#[test]
fn tls13_session_tickets_remain_enabled_by_default() {
    let fixture = fixture();
    let server = config(&fixture, verifier(fixture.ca.clone()))
        .server_config()
        .unwrap();
    assert_eq!(server.send_tls13_tickets, 2);
}
