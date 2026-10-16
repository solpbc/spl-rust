// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! The caller owns the opt-in driver's actual future, I/O and task result.

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "controlled transport fixtures assert at the actual failure site"
)]

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{RootCertStore, server::danger::ClientCertVerifier};
use spl_core::ca::sha256;
use spl_core::frame::{
    FLAG_DATA, FLAG_OPEN, FLAG_PONG, FLAG_RESET, Frame, FrameDecoder, RESET_STREAM_LIMIT_EXCEEDED,
};
use spl_home::{CarrierClose, HomeConfig, HomeConnection, HomeError, MuxLimits};
use spl_transport::tls::mtls_config;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::sync::oneshot;
use tokio_rustls::{TlsConnector, client::TlsStream};

struct Fixture {
    ca: CertificateDer<'static>,
    server_chain: Vec<CertificateDer<'static>>,
    server_key: PrivateKeyDer<'static>,
    client_chain: Vec<CertificateDer<'static>>,
    client_key: PrivateKeyDer<'static>,
}

fn fixture() -> Fixture {
    let ca_key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca = params.self_signed(&ca_key).unwrap();
    let ca_der = CertificateDer::from(ca.der().to_vec());
    let server_key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["spl.local".to_owned()]).unwrap();
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    let server = params.signed_by(&server_key, &ca, &ca_key).unwrap();
    let client_key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["dialer.test".to_owned()]).unwrap();
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);
    let client = params.signed_by(&client_key, &ca, &ca_key).unwrap();
    Fixture {
        ca: ca_der.clone(),
        server_chain: vec![CertificateDer::from(server.der().to_vec()), ca_der.clone()],
        server_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
        client_chain: vec![CertificateDer::from(client.der().to_vec()), ca_der],
        client_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(client_key.serialize_der())),
    }
}

fn config(f: &Fixture, stream_cap: usize) -> HomeConfig {
    let mut roots = RootCertStore::empty();
    roots.add(f.ca.clone()).unwrap();
    let verifier: Arc<dyn ClientCertVerifier> =
        rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();
    HomeConfig {
        certificate_chain: f.server_chain.clone(),
        private_key: f.server_key.clone_key(),
        client_cert_verifier: verifier,
        mux_limits: MuxLimits {
            max_concurrent_streams: stream_cap,
            ..MuxLimits::default()
        },
    }
}

fn connector(f: &Fixture) -> TlsConnector {
    TlsConnector::from(Arc::new(
        mtls_config(
            &sha256(f.ca.as_ref())[..16],
            f.client_chain.clone(),
            f.client_key.clone_key(),
        )
        .unwrap(),
    ))
}

async fn bounded<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .unwrap()
}

struct PayloadGuard(Arc<AtomicBool>);
impl Drop for PayloadGuard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

struct HeldWrite {
    entered: Option<oneshot::Sender<()>>,
    release: oneshot::Receiver<()>,
}

#[derive(Default)]
struct Control {
    dropped: AtomicBool,
    read_polled: AtomicBool,
    write: Mutex<Option<HeldWrite>>,
    panic_write: Mutex<Option<PayloadGuard>>,
}

struct ControlledIo {
    inner: DuplexStream,
    control: Arc<Control>,
}
impl Drop for ControlledIo {
    fn drop(&mut self) {
        self.control.dropped.store(true, Ordering::SeqCst);
    }
}
impl AsyncRead for ControlledIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.control.read_polled.store(true, Ordering::SeqCst);
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for ControlledIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let payload = self.control.panic_write.lock().unwrap().take();
        if let Some(payload) = payload {
            std::panic::panic_any(payload);
        }
        {
            let mut held = self.control.write.lock().unwrap();
            if let Some(gate) = held.as_mut() {
                if let Some(entered) = gate.entered.take() {
                    entered.send(()).unwrap();
                }
                if Pin::new(&mut gate.release).poll(cx).is_pending() {
                    return Poll::Pending;
                }
                held.take();
            }
        }
        Pin::new(&mut self.inner).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn owned_pair(
    stream_cap: usize,
) -> (
    HomeConnection,
    impl Future<Output = ()> + Send + 'static,
    TlsStream<DuplexStream>,
    Arc<Control>,
) {
    let f = fixture();
    let (home, dialer) = tokio::io::duplex(64 * 1024);
    let control = Arc::new(Control::default());
    let home = ControlledIo {
        inner: home,
        control: control.clone(),
    };
    let connector = connector(&f);
    let (accepted, dialer) = Box::pin(bounded(async {
        tokio::join!(
            HomeConnection::accept_with_driver(home, config(&f, stream_cap)),
            connector.connect(ServerName::try_from("spl.local").unwrap(), dialer)
        )
    }))
    .await;
    let (connection, driver) = accepted.unwrap();
    (connection, driver, dialer.unwrap(), control)
}

fn wire(frame: &Frame) -> Vec<u8> {
    frame.encode().unwrap()
}
async fn frames(dialer: &mut TlsStream<DuplexStream>, decoder: &mut FrameDecoder) -> Vec<Frame> {
    let mut bytes = [0u8; 4096];
    loop {
        let n = bounded(dialer.read(&mut bytes)).await.unwrap();
        assert_ne!(n, 0, "carrier ended before expected frame");
        decoder.feed(&bytes[..n]);
        let frames = decoder.drain().unwrap();
        if !frames.is_empty() {
            return frames;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn owned_driver_preserves_real_mtls_mux_data_ping_and_configured_stream_cap() {
    let (mut home, driver, mut dialer, control) = Box::pin(owned_pair(1)).await;
    let task = tokio::spawn(driver);
    dialer
        .write_all(&wire(&Frame::new(
            1,
            FLAG_OPEN | FLAG_DATA,
            b"hello".to_vec(),
        )))
        .await
        .unwrap();
    let mut stream = bounded(home.accept_stream()).await.unwrap();
    let mut hello = [0u8; 5];
    bounded(stream.read_exact(&mut hello)).await.unwrap();
    assert_eq!(&hello, b"hello");
    dialer
        .write_all(&wire(&Frame::new(3, FLAG_OPEN, Vec::new())))
        .await
        .unwrap();
    dialer
        .write_all(&wire(&Frame::control_ping([7; 8])))
        .await
        .unwrap();
    let mut decoder = FrameDecoder::new();
    let mut received = Vec::new();
    while !received.iter().any(|f: &Frame| f.flags == FLAG_PONG)
        || !received
            .iter()
            .any(|f| f.stream_id == 3 && f.flags == FLAG_RESET)
    {
        received.extend(frames(&mut dialer, &mut decoder).await);
    }
    assert!(
        received
            .iter()
            .any(|f| f.flags == FLAG_PONG && f.payload == vec![7; 8])
    );
    assert!(received.iter().any(|f| f.stream_id == 3
        && f.flags == FLAG_RESET
        && f.payload == vec![RESET_STREAM_LIMIT_EXCEEDED]));
    stream.write_all(b"world").await.unwrap();
    let mut body = Vec::new();
    while body.len() < 5 {
        for f in frames(&mut dialer, &mut decoder).await {
            if f.stream_id == 1 && f.flags == FLAG_DATA {
                body.extend(f.payload);
            }
        }
    }
    assert_eq!(body, b"world");
    assert_eq!(home.refusals().stream_limit, 1);
    home.close().unwrap();
    bounded(task).await.unwrap();
    assert!(control.dropped.load(Ordering::SeqCst));
    assert_eq!(home.carrier_counts().close, CarrierClose::LocalClose);
}

#[tokio::test]
async fn dropping_unpolled_driver_releases_actual_carrier_without_hidden_task() {
    let (home, driver, _dialer, control) = Box::pin(owned_pair(1)).await;
    assert!(!control.dropped.load(Ordering::SeqCst));
    drop(home);
    assert!(!control.dropped.load(Ordering::SeqCst));
    drop(driver);
    assert!(
        control.dropped.load(Ordering::SeqCst),
        "dropping the unpolled actual driver synchronously releases its carrier"
    );
}

#[tokio::test]
async fn cancelling_pending_tls_acceptance_releases_actual_io_before_driver_exists() {
    let f = fixture();
    let (home, _dialer) = tokio::io::duplex(4096);
    let control = Arc::new(Control::default());
    let mut accept = Box::pin(HomeConnection::accept_with_driver(
        ControlledIo {
            inner: home,
            control: control.clone(),
        },
        config(&f, 1),
    ));
    assert!(
        accept
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    assert!(control.read_polled.load(Ordering::SeqCst));
    assert!(!control.dropped.load(Ordering::SeqCst));
    drop(accept);
    assert!(control.dropped.load(Ordering::SeqCst));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn real_held_pong_write_keeps_actual_join_pending_across_observer_cancellation() {
    let (home, driver, mut dialer, control) = Box::pin(owned_pair(1)).await;
    let (entered, write_entered) = oneshot::channel();
    let (release, released) = oneshot::channel();
    *control.write.lock().unwrap() = Some(HeldWrite {
        entered: Some(entered),
        release: released,
    });
    let mut task = tokio::spawn(driver);
    dialer
        .write_all(&wire(&Frame::control_ping([8; 8])))
        .await
        .unwrap();
    bounded(write_entered).await.unwrap();
    home.close().unwrap();
    let mut observer = Box::pin(&mut task);
    assert!(
        observer
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending(),
        "actual driver remains inside the entered response write"
    );
    drop(observer);
    assert!(!control.dropped.load(Ordering::SeqCst));
    release.send(()).unwrap();
    bounded(&mut task).await.unwrap();
    assert!(control.dropped.load(Ordering::SeqCst));
    assert_eq!(home.carrier_counts().close, CarrierClose::LocalClose);
    let mut decoder = FrameDecoder::new();
    let received = frames(&mut dialer, &mut decoder).await;
    assert!(
        received
            .iter()
            .any(|f| f.flags == FLAG_PONG && f.payload == vec![8; 8])
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn actual_driver_io_panic_reaches_caller_joinerror_with_opaque_payload_custody() {
    let (_home, driver, mut dialer, control) = Box::pin(owned_pair(1)).await;
    let dropped = Arc::new(AtomicBool::new(false));
    *control.panic_write.lock().unwrap() = Some(PayloadGuard(dropped.clone()));
    let task = tokio::spawn(driver);
    dialer
        .write_all(&wire(&Frame::control_ping([9; 8])))
        .await
        .unwrap();
    let error = bounded(task).await.unwrap_err();
    assert!(error.is_panic());
    assert!(control.dropped.load(Ordering::SeqCst));
    assert!(!dropped.load(Ordering::SeqCst));
    drop(error);
    assert!(dropped.load(Ordering::SeqCst));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn both_entrypoints_preserve_actual_wrong_ca_tls_refusal() {
    for owned in [false, true] {
        let f = fixture();
        let foreign = fixture();
        let (home, dialer) = tokio::io::duplex(64 * 1024);
        let control = Arc::new(Control::default());
        let home = ControlledIo {
            inner: home,
            control: control.clone(),
        };
        let connector = connector(&foreign);
        let server = async {
            if owned {
                HomeConnection::accept_with_driver(home, config(&f, 1))
                    .await
                    .map(|(connection, driver)| {
                        drop(driver);
                        connection
                    })
            } else {
                HomeConnection::accept(home, config(&f, 1)).await
            }
        };
        let (server, client) = bounded(async {
            tokio::join!(
                server,
                connector.connect(ServerName::try_from("spl.local").unwrap(), dialer)
            )
        })
        .await;
        assert!(matches!(server, Err(HomeError::Tls)));
        assert!(client.is_err());
        assert!(control.dropped.load(Ordering::SeqCst));
    }
}
