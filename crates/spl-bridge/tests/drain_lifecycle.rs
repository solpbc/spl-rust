// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Acceptance criteria 8-9: Drain lifecycle, 30s timeout, SIGTERM/SIGINT, and accept backoff.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "integration tests use test sockets and local mock acceptors"
)]

use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rcgen::{Certificate, CertificateParams, KeyPair, date_time_ymd};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use spl_bridge::pop_auth::{FixtureTokenVerifier, PopAuthenticator};
use spl_bridge::registry::Registry;
use spl_bridge::{
    AcceptProvider, DEFAULT_ADMISSION_DEADLINE, TokioControlConnector, run_client_listener,
    run_control_listener, server_tls_config,
};
use tokio::io::AsyncWriteExt;
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

fn build_client_hello(sni: Option<&str>) -> Vec<u8> {
    let mut extensions = Vec::new();
    if let Some(host) = sni {
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
    let mut client_hello_body = Vec::new();
    client_hello_body.extend_from_slice(&[0x03, 0x03]);
    client_hello_body.extend_from_slice(&[0u8; 32]);
    client_hello_body.push(0);
    client_hello_body.extend_from_slice(&2u16.to_be_bytes());
    client_hello_body.extend_from_slice(&[0x13, 0x01]);
    client_hello_body.extend_from_slice(&[1, 0]);
    client_hello_body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    client_hello_body.extend_from_slice(&extensions);

    let body_len = client_hello_body.len() as u32;
    handshake.push((body_len >> 16) as u8);
    handshake.push((body_len >> 8) as u8);
    handshake.push(body_len as u8);
    handshake.extend_from_slice(&client_hello_body);

    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

#[tokio::test(start_paused = true)]
async fn ac8_paused_time_drain_budget_aborts_hanging_connections_at_30s() {
    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_listener.local_addr().unwrap();

    let control_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_addr = control_listener.local_addr().unwrap();

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let client_task = tokio::spawn(run_client_listener(
        client_listener,
        Registry::default(),
        control_addr,
        None,
        Duration::from_secs(5),
        TokioControlConnector,
        TokioControlConnector,
        shutdown_rx.clone(),
    ));

    let control_accept_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (_ca_der, ca_key, ca_cert) = generate_ca();
    let (_cert_der, _key_der, cert_pem, key_pem) =
        generate_leaf("bridge.solstone.me", &ca_cert, &ca_key, 2020, 2035);
    let tls_config = server_tls_config(
        spl_bridge::pem_certificate_chain(&cert_pem).unwrap(),
        spl_bridge::pem_private_key(&key_pem).unwrap(),
    )
    .unwrap();
    let verifier =
        FixtureTokenVerifier::new(std::collections::HashMap::new(), String::from("bridge"));
    let authenticator = PopAuthenticator::new(Arc::new(verifier), String::from("bridge"));

    let control_task = tokio::spawn(run_control_listener(
        control_accept_listener,
        Arc::new(tls_config),
        Registry::default(),
        authenticator,
        DEFAULT_ADMISSION_DEADLINE,
        shutdown_rx,
    ));

    // Connect a client with reserved hello -> connects to control listener and starts splice
    let mut client = TcpStream::connect(client_addr).await.unwrap();
    let hello = build_client_hello(Some("bridge.solstone.me"));
    client.write_all(&hello).await.unwrap();

    // Accept control side and hold it open
    let (_control_stream, _) = control_listener.accept().await.unwrap();

    // Signal shutdown and yield so listener enters drain
    shutdown_tx.send_replace(true);
    tokio::task::yield_now().await;

    // Advancing 29 seconds should NOT finish the client task yet
    tokio::time::advance(Duration::from_secs(29)).await;
    tokio::task::yield_now().await;
    assert!(!client_task.is_finished(), "29s must not finish drain");

    // Advancing 1 more second (total 30s = DRAIN_BUDGET) must complete the task
    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert!(
        client_task.is_finished(),
        "Client task must be finished after 30s DRAIN_BUDGET"
    );
    assert!(
        control_task.is_finished(),
        "Control task must be finished after drain"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ac8_spawned_binary_real_sigterm_and_sigint_clean_drain() {
    let temp = TempDir::new("ac8-signals");
    let (_ca_der, ca_key, ca_cert) = generate_ca();

    let ca_pem_path = temp.path.join("ca.pem");
    fs::write(&ca_pem_path, ca_cert.pem().as_bytes()).unwrap();

    let (_, _, cert_pem, key_pem) =
        generate_leaf("bridge.solstone.me", &ca_cert, &ca_key, 2020, 2035);
    let cert_path = temp.path.join("cert.pem");
    let key_path = temp.path.join("key.pem");
    fs::write(&cert_path, &cert_pem).unwrap();
    fs::write(&key_path, &key_pem).unwrap();

    let bridge_bin = env!("CARGO_BIN_EXE_spl-bridge");

    // Test SIGTERM
    {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap();
        drop(probe);

        let child = Command::new(bridge_bin)
            .arg("--client-listen")
            .arg(port.to_string())
            .arg("--control-tls-cert")
            .arg(&cert_path)
            .arg("--control-tls-key")
            .arg(&key_path)
            .arg("--jwks-url")
            .arg("https://127.0.0.1:1/jwks")
            .arg("--bridge-id")
            .arg("bridge")
            .arg("--control-tls-roots")
            .arg(&ca_pem_path)
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn bridge");
        let pid = child.id();

        for _ in 0..50 {
            if TcpStream::connect(port).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let _ = Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status();

        let output = child.wait_with_output().expect("wait failed");
        assert!(
            output.status.success(),
            "process must cleanly exit on SIGTERM"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("bridge shutdown signal received; starting drain"),
            "stderr must contain drain start message: {stderr}"
        );
    }

    // Test SIGINT
    {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap();
        drop(probe);

        let child = Command::new(bridge_bin)
            .arg("--client-listen")
            .arg(port.to_string())
            .arg("--control-tls-cert")
            .arg(&cert_path)
            .arg("--control-tls-key")
            .arg(&key_path)
            .arg("--jwks-url")
            .arg("https://127.0.0.1:1/jwks")
            .arg("--bridge-id")
            .arg("bridge")
            .arg("--control-tls-roots")
            .arg(&ca_pem_path)
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn bridge");
        let pid = child.id();

        for _ in 0..50 {
            if TcpStream::connect(port).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let _ = Command::new("kill")
            .args(["-INT", &pid.to_string()])
            .status();

        let output = child.wait_with_output().expect("wait failed");
        assert!(
            output.status.success(),
            "process must cleanly exit on SIGINT"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("bridge shutdown signal received; starting drain"),
            "stderr must contain drain start message: {stderr}"
        );
    }
}

struct BackoffTestingAcceptor {
    attempts: Arc<AtomicUsize>,
    succeed_on_attempt: Option<usize>,
}

impl AcceptProvider for BackoffTestingAcceptor {
    async fn accept(&mut self) -> io::Result<(TcpStream, SocketAddr)> {
        let count = self.attempts.fetch_add(1, Ordering::SeqCst) + 1;
        if Some(count) == self.succeed_on_attempt {
            // Success: connect a loopback pair
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let client = TcpStream::connect(addr).await?;
            let (server, peer) = listener.accept().await?;
            drop(client);
            Ok((server, peer))
        } else {
            Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "accept failed",
            ))
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "backoff progression and capped sleep test on both listeners"
)]
#[tokio::test(start_paused = true)]
async fn ac9_accept_backoff_progression_and_reset_on_success() {
    // Test on client listener
    let attempts = Arc::new(AtomicUsize::new(0));
    let acceptor = BackoffTestingAcceptor {
        attempts: Arc::clone(&attempts),
        succeed_on_attempt: Some(4), // succeeds on 4th attempt
    };

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let client_task = tokio::spawn(run_client_listener(
        acceptor,
        Registry::default(),
        "127.0.0.1:1".parse().unwrap(),
        None,
        Duration::from_secs(1),
        TokioControlConnector,
        TokioControlConnector,
        shutdown_rx,
    ));

    // Initial attempt at t=0
    tokio::task::yield_now().await;
    assert_eq!(attempts.load(Ordering::SeqCst), 1);

    // After 50ms -> attempt 2
    tokio::time::advance(Duration::from_millis(50)).await;
    tokio::task::yield_now().await;
    assert_eq!(attempts.load(Ordering::SeqCst), 2);

    // After 100ms -> attempt 3
    tokio::time::advance(Duration::from_millis(100)).await;
    tokio::task::yield_now().await;
    assert_eq!(attempts.load(Ordering::SeqCst), 3);

    // After 200ms -> attempt 4 (succeeds!)
    tokio::time::advance(Duration::from_millis(200)).await;
    tokio::task::yield_now().await;
    assert_eq!(attempts.load(Ordering::SeqCst), 4);

    // After success, next failure delay resets to 50ms -> attempt 5
    tokio::time::advance(Duration::from_millis(50)).await;
    tokio::task::yield_now().await;
    assert_eq!(attempts.load(Ordering::SeqCst), 5);

    // Progress through exponential backoff up to 5s cap:
    // 100ms -> attempt 6
    tokio::time::advance(Duration::from_millis(100)).await;
    tokio::task::yield_now().await;
    assert_eq!(attempts.load(Ordering::SeqCst), 6);

    // 200ms -> attempt 7
    tokio::time::advance(Duration::from_millis(200)).await;
    tokio::task::yield_now().await;
    assert_eq!(attempts.load(Ordering::SeqCst), 7);

    // 400ms -> attempt 8
    tokio::time::advance(Duration::from_millis(400)).await;
    tokio::task::yield_now().await;
    assert_eq!(attempts.load(Ordering::SeqCst), 8);

    // 800ms -> attempt 9
    tokio::time::advance(Duration::from_millis(800)).await;
    tokio::task::yield_now().await;
    assert_eq!(attempts.load(Ordering::SeqCst), 9);

    // 1600ms -> attempt 10
    tokio::time::advance(Duration::from_millis(1600)).await;
    tokio::task::yield_now().await;
    assert_eq!(attempts.load(Ordering::SeqCst), 10);

    // 3200ms -> attempt 11
    tokio::time::advance(Duration::from_millis(3200)).await;
    tokio::task::yield_now().await;
    assert_eq!(attempts.load(Ordering::SeqCst), 11);

    // 5000ms (capped) -> attempt 12
    tokio::time::advance(Duration::from_secs(5)).await;
    tokio::task::yield_now().await;
    assert_eq!(attempts.load(Ordering::SeqCst), 12);

    // It is now sleeping for the 5000ms cap before attempt 13.
    // Signal shutdown during the capped sleep, advancing 1ms must finish the task immediately.
    shutdown_tx.send_replace(true);
    tokio::time::advance(Duration::from_millis(1)).await;
    tokio::task::yield_now().await;
    assert!(client_task.is_finished());

    // Test on control listener
    let control_attempts = Arc::new(AtomicUsize::new(0));
    let control_acceptor = BackoffTestingAcceptor {
        attempts: Arc::clone(&control_attempts),
        succeed_on_attempt: None,
    };

    let (_ca_der, ca_key, ca_cert) = generate_ca();
    let (_cert_der, _key_der, cert_pem, key_pem) =
        generate_leaf("bridge.solstone.me", &ca_cert, &ca_key, 2020, 2035);
    let tls_config = server_tls_config(
        spl_bridge::pem_certificate_chain(&cert_pem).unwrap(),
        spl_bridge::pem_private_key(&key_pem).unwrap(),
    )
    .unwrap();

    let verifier =
        FixtureTokenVerifier::new(std::collections::HashMap::new(), String::from("bridge"));
    let authenticator = PopAuthenticator::new(Arc::new(verifier), String::from("bridge"));

    let (control_shutdown_tx, control_shutdown_rx) = tokio::sync::watch::channel(false);
    let control_task = tokio::spawn(run_control_listener(
        control_acceptor,
        Arc::new(tls_config),
        Registry::default(),
        authenticator,
        DEFAULT_ADMISSION_DEADLINE,
        control_shutdown_rx,
    ));

    // Initial attempt 1
    tokio::task::yield_now().await;
    assert_eq!(control_attempts.load(Ordering::SeqCst), 1);

    // 50ms -> attempt 2
    tokio::time::advance(Duration::from_millis(50)).await;
    tokio::task::yield_now().await;
    assert_eq!(control_attempts.load(Ordering::SeqCst), 2);

    // 100ms -> attempt 3
    tokio::time::advance(Duration::from_millis(100)).await;
    tokio::task::yield_now().await;
    assert_eq!(control_attempts.load(Ordering::SeqCst), 3);

    // 200ms -> attempt 4
    tokio::time::advance(Duration::from_millis(200)).await;
    tokio::task::yield_now().await;
    assert_eq!(control_attempts.load(Ordering::SeqCst), 4);

    // 400ms -> attempt 5
    tokio::time::advance(Duration::from_millis(400)).await;
    tokio::task::yield_now().await;
    assert_eq!(control_attempts.load(Ordering::SeqCst), 5);

    // 800ms -> attempt 6
    tokio::time::advance(Duration::from_millis(800)).await;
    tokio::task::yield_now().await;
    assert_eq!(control_attempts.load(Ordering::SeqCst), 6);

    // 1600ms -> attempt 7
    tokio::time::advance(Duration::from_millis(1600)).await;
    tokio::task::yield_now().await;
    assert_eq!(control_attempts.load(Ordering::SeqCst), 7);

    // 3200ms -> attempt 8
    tokio::time::advance(Duration::from_millis(3200)).await;
    tokio::task::yield_now().await;
    assert_eq!(control_attempts.load(Ordering::SeqCst), 8);

    // 5000ms (capped) -> attempt 9
    tokio::time::advance(Duration::from_secs(5)).await;
    tokio::task::yield_now().await;
    assert_eq!(control_attempts.load(Ordering::SeqCst), 9);

    // Now in 5s capped sleep before attempt 10: shutdown terminates immediately
    control_shutdown_tx.send_replace(true);
    tokio::time::advance(Duration::from_millis(1)).await;
    tokio::task::yield_now().await;
    assert!(control_task.is_finished());
}
