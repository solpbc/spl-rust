// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Acceptance criteria 5-8, 10: ACME TLS-ALPN-01 routing, loopback enforcement, and admission error isolation.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "integration tests use test sockets and synthetic ClientHellos"
)]

use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rcgen::{Certificate, CertificateParams, KeyPair, date_time_ymd};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use spl_bridge::registry::Registry;
use spl_bridge::sni::{ClientHelloRouting, DEFAULT_READ_DEADLINE, SniError, extract_sni};
use spl_bridge::{ControlConnector, TokioControlConnector, run_client_listener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(name: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = PathBuf::from(format!("/var/tmp/spl-bridge-test-{name}-{nanos}"));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn generate_ca() -> (CertificateDer<'static>, KeyPair, Certificate) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![String::from("Test Root CA")]).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let cert = params.self_signed(&key).unwrap();
    (CertificateDer::from(cert.der().to_vec()), key, cert)
}

fn generate_leaf(
    san: &str,
    ca_cert: &Certificate,
    ca_key: &KeyPair,
    start_year: i32,
    end_year: i32,
) -> (
    CertificateDer<'static>,
    PrivateKeyDer<'static>,
    Vec<u8>,
    Vec<u8>,
) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![String::from(san)]).unwrap();
    params.not_before = date_time_ymd(start_year, 1, 1);
    params.not_after = date_time_ymd(end_year, 1, 1);

    let cert = params.signed_by(&key, ca_cert, ca_key).unwrap();

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));

    let cert_pem = format!("{}\n{}", cert.pem(), ca_cert.pem()).into_bytes();
    let key_pem = key.serialize_pem().into_bytes();

    (cert_der, key_der, cert_pem, key_pem)
}

#[derive(Clone, Copy)]
struct PanicConnector;

impl ControlConnector for PanicConnector {
    async fn connect(&self, target: SocketAddr) -> io::Result<TcpStream> {
        unreachable!("unexpected connector dial to target: {target}");
    }
}

#[derive(Clone, Copy)]
struct FailingConnector;

impl ControlConnector for FailingConnector {
    async fn connect(&self, _target: SocketAddr) -> io::Result<TcpStream> {
        Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "failing connector",
        ))
    }
}

fn build_client_hello(sni: Option<&str>, alpn_protocols: &[&[u8]]) -> Vec<u8> {
    let mut extensions = Vec::new();

    if let Some(host) = sni {
        let mut sni_ext = Vec::new();
        let host_bytes = host.as_bytes();
        let list_len = (host_bytes.len() + 3) as u16;
        sni_ext.extend_from_slice(&list_len.to_be_bytes());
        sni_ext.push(0); // host_name type
        sni_ext.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(host_bytes);

        extensions.extend_from_slice(&0u16.to_be_bytes()); // extension type 0: server_name
        extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_ext);
    }

    if !alpn_protocols.is_empty() {
        let mut alpn_ext = Vec::new();
        let mut list = Vec::new();
        for proto in alpn_protocols {
            list.push(proto.len() as u8);
            list.extend_from_slice(proto);
        }
        alpn_ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
        alpn_ext.extend_from_slice(&list);

        extensions.extend_from_slice(&16u16.to_be_bytes()); // extension type 16: ALPN
        extensions.extend_from_slice(&(alpn_ext.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&alpn_ext);
    }

    let mut handshake = Vec::new();
    handshake.push(1); // ClientHello
    let mut client_hello_body = Vec::new();
    client_hello_body.extend_from_slice(&[0x03, 0x03]); // client version TLS 1.2
    client_hello_body.extend_from_slice(&[0u8; 32]); // random
    client_hello_body.push(0); // session id length
    client_hello_body.extend_from_slice(&2u16.to_be_bytes()); // cipher suites length
    client_hello_body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    client_hello_body.extend_from_slice(&[1, 0]); // compression methods
    client_hello_body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    client_hello_body.extend_from_slice(&extensions);

    let body_len = client_hello_body.len() as u32;
    handshake.push((body_len >> 16) as u8);
    handshake.push((body_len >> 8) as u8);
    handshake.push(body_len as u8);
    handshake.extend_from_slice(&client_hello_body);

    let mut record = Vec::new();
    record.push(0x16); // Handshake
    record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record version
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    record
}

async fn extract_sni_from_bytes(data: Vec<u8>) -> Result<ClientHelloRouting, SniError> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let write_task = tokio::spawn(async move {
        let mut client = TcpStream::connect(addr).await.unwrap();
        let _ = client.write_all(&data).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
    });
    let (server, _) = listener.accept().await.unwrap();
    let res = extract_sni(&server, DEFAULT_READ_DEADLINE).await;
    write_task.abort();
    res
}

fn assert_closed(res: &io::Result<usize>) {
    assert!(
        matches!(res, Ok(0)) || matches!(res, Err(e) if e.kind() == io::ErrorKind::ConnectionReset),
        "expected connection closed, got {res:?}"
    );
}

// Routing rule: ACME iff configured target AND SNI == "bridge.solstone.me" AND ALPN contains "acme-tls/1"
#[tokio::test]
async fn ac5_acme_routing_rules_and_panic_connectors() {
    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_listener.local_addr().unwrap();

    let control_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_addr = control_listener.local_addr().unwrap();

    let (_, shutdown_rx) = tokio::sync::watch::channel(false);

    // If reserved SNI has no ACME ALPN, ACME connector MUST NOT be dialed
    let client_task = tokio::spawn(run_client_listener(
        client_listener,
        Registry::default(),
        control_addr,
        Some("127.0.0.1:5001".parse().unwrap()),
        Duration::from_secs(1),
        TokioControlConnector,
        PanicConnector, // will panic if ACME is dialed
        shutdown_rx.clone(),
    ));

    // Send ClientHello with reserved SNI without ACME ALPN -> should dial control connector, not ACME
    let mut client = TcpStream::connect(client_addr).await.unwrap();
    let non_acme_hello = build_client_hello(Some("bridge.solstone.me"), &[b"http/1.1"]);
    client.write_all(&non_acme_hello).await.unwrap();

    // Accept on control listener
    let (mut control_stream, _) = control_listener.accept().await.unwrap();
    let mut buf = [0u8; 512];
    let n = control_stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], &non_acme_hello);
    drop(client);
    client_task.abort();

    // Owner SNI with acme-tls/1 must route to journal (or reject if unregistered), not dial ACME connector
    let client_listener2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_addr2 = client_listener2.local_addr().unwrap();

    let client_task2 = tokio::spawn(run_client_listener(
        client_listener2,
        Registry::default(),
        control_addr,
        Some("127.0.0.1:5001".parse().unwrap()),
        Duration::from_secs(1),
        PanicConnector, // control connector panic
        PanicConnector, // ACME connector panic
        shutdown_rx,
    ));

    let mut client2 = TcpStream::connect(client_addr2).await.unwrap();
    let owner_hello = build_client_hello(Some("aaaqeaye.solstone.me"), &[b"acme-tls/1"]);
    client2.write_all(&owner_hello).await.unwrap();

    // Unregistered owner journal closes client without dialing ACME or control
    let mut close_buf = [0u8; 1];
    let res = client2.read(&mut close_buf).await;
    assert_closed(&res);
    client_task2.abort();
}

#[tokio::test]
async fn ac6_binary_rejects_non_loopback_acme_target_before_bind() {
    let temp = TempDir::new("ac6-acme-target");
    let (_ca_der, ca_key, ca_cert) = generate_ca();

    let ca_pem_path = temp.path.join("ca.pem");
    fs::write(&ca_pem_path, ca_cert.pem().as_bytes()).unwrap();

    let (_, _, cert_pem, key_pem) =
        generate_leaf("bridge.solstone.me", &ca_cert, &ca_key, 2020, 2035);
    let cert_path = temp.path.join("cert.pem");
    let key_path = temp.path.join("key.pem");
    fs::write(&cert_path, &cert_pem).unwrap();
    fs::write(&key_path, &key_pem).unwrap();

    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap();
    drop(probe);

    let bridge_bin = env!("CARGO_BIN_EXE_spl-bridge");
    let output = Command::new(bridge_bin)
        .arg("--client-listen")
        .arg(port.to_string())
        .arg("--control-tls-cert")
        .arg(&cert_path)
        .arg("--control-tls-key")
        .arg(&key_path)
        .arg("--jwks-url")
        .arg("http://127.0.0.1:1/jwks")
        .arg("--bridge-id")
        .arg("bridge")
        .arg("--control-tls-roots")
        .arg(&ca_pem_path)
        .arg("--acme-tls-alpn-target")
        .arg("1.1.1.1:443")
        .output()
        .expect("failed to run spl-bridge");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("acme target address rejected: must be loopback"),
        "stderr must contain acme target rejected message: {stderr}"
    );
    assert!(
        !stderr.contains("listener started"),
        "must not start listeners"
    );

    // Port must still be bindable after exit
    let rebound = std::net::TcpListener::bind(port);
    assert!(
        rebound.is_ok(),
        "port {port} must remain free when rejected before bind"
    );
}

#[tokio::test]
async fn ac7_client_acme_forward_failure_with_erroring_connector() {
    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_listener.local_addr().unwrap();

    let (_, shutdown_rx) = tokio::sync::watch::channel(false);
    let client_task = tokio::spawn(run_client_listener(
        client_listener,
        Registry::default(),
        "127.0.0.1:1".parse().unwrap(),
        Some("127.0.0.1:5001".parse().unwrap()),
        Duration::from_secs(1),
        PanicConnector,
        FailingConnector,
        shutdown_rx,
    ));

    let payload = build_client_hello(Some("bridge.solstone.me"), &[b"acme-tls/1"]);
    let mut client = TcpStream::connect(client_addr).await.unwrap();
    client.write_all(&payload).await.unwrap();

    let mut buf = [0u8; 1];
    let res = client.read(&mut buf).await;
    assert_closed(&res);

    client_task.abort();
}

#[tokio::test]
async fn ac8_duplicate_sni_and_alpn_extensions_fail_closed() {
    let mut extensions = Vec::new();
    for host in ["host1.example.com", "host2.example.com"] {
        let mut sni_ext = Vec::new();
        let host_bytes = host.as_bytes();
        let list_len = (host_bytes.len() + 3) as u16;
        sni_ext.extend_from_slice(&list_len.to_be_bytes());
        sni_ext.push(0);
        sni_ext.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(host_bytes);

        extensions.extend_from_slice(&0u16.to_be_bytes());
        extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_ext);
    }

    let mut handshake = Vec::new();
    handshake.push(1);
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x13, 0x01]);
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let body_len = body.len() as u32;
    handshake.push((body_len >> 16) as u8);
    handshake.push((body_len >> 8) as u8);
    handshake.push(body_len as u8);
    handshake.extend_from_slice(&body);

    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    let res = extract_sni_from_bytes(record).await;
    assert!(res.is_err(), "Duplicate SNI extension must fail closed");

    let mut alpn_extensions = Vec::new();
    for proto in [b"http/1.1".as_slice(), b"acme-tls/1".as_slice()] {
        let mut alpn_ext = Vec::new();
        let mut list = Vec::new();
        list.push(proto.len() as u8);
        list.extend_from_slice(proto);
        alpn_ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
        alpn_ext.extend_from_slice(&list);

        alpn_extensions.extend_from_slice(&16u16.to_be_bytes());
        alpn_extensions.extend_from_slice(&(alpn_ext.len() as u16).to_be_bytes());
        alpn_extensions.extend_from_slice(&alpn_ext);
    }

    let mut handshake = Vec::new();
    handshake.push(1);
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x13, 0x01]);
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&(alpn_extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&alpn_extensions);

    let body_len = body.len() as u32;
    handshake.push((body_len >> 16) as u8);
    handshake.push((body_len >> 8) as u8);
    handshake.push(body_len as u8);
    handshake.extend_from_slice(&body);

    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    let res = extract_sni_from_bytes(record).await;
    assert!(res.is_err(), "Duplicate ALPN extension must fail closed");
}

#[tokio::test]
async fn ac10_admission_capacity_and_malformed_client_hello() {
    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_listener.local_addr().unwrap();

    let (_, shutdown_rx) = tokio::sync::watch::channel(false);
    let client_task = tokio::spawn(run_client_listener(
        client_listener,
        Registry::default(),
        "127.0.0.1:1".parse().unwrap(),
        None,
        Duration::from_millis(100),
        TokioControlConnector,
        TokioControlConnector,
        shutdown_rx,
    ));

    // 1. Malformed bytes (not TLS)
    let mut malformed_client = TcpStream::connect(client_addr).await.unwrap();
    malformed_client
        .write_all(b"not-a-tls-record")
        .await
        .unwrap();
    let mut buf = [0u8; 1];
    let res1 = malformed_client.read(&mut buf).await;
    assert_closed(&res1);

    // 2. Valid hello for not-a-hostname
    let bad_host_hello = build_client_hello(Some("invalid hostname!"), &[]);
    let mut bad_host_client = TcpStream::connect(client_addr).await.unwrap();
    bad_host_client.write_all(&bad_host_hello).await.unwrap();
    let res2 = bad_host_client.read(&mut buf).await;
    assert_closed(&res2);

    client_task.abort();
}
