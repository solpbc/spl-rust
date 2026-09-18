// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Acceptance criteria 16: Atomic staged certificate activation, verification, rollback, and quarantine.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "integration tests verify CLI behavior against synthetic certificates and listeners"
)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rcgen::{Certificate, CertificateParams, KeyPair, date_time_ymd};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

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

async fn start_mock_tls_server(
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let certs = spl_bridge::pem_certificate_chain(&cert_pem).unwrap();
    let key = spl_bridge::pem_private_key(&key_pem).unwrap();

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();

    let acceptor = TlsAcceptor::from(Arc::new(config));

    let handle = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls_stream) = acceptor.accept(stream).await {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    let _ = tokio::io::AsyncWriteExt::shutdown(&mut tls_stream).await;
                }
            });
        }
    });

    (addr, handle)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ac16_activate_happy_path() {
    let temp = TempDir::new("activate-happy");
    let (_ca_der, ca_key, ca_cert) = generate_ca();

    let ca_pem_path = temp.path.join("ca.pem");
    fs::write(&ca_pem_path, ca_cert.pem().as_bytes()).unwrap();

    let (_leaf_der, _leaf_key, cert_pem, key_pem) =
        generate_leaf("bridge.solstone.me", &ca_cert, &ca_key, 2020, 2035);

    let issued_cert = temp.path.join("issued.crt");
    let issued_key = temp.path.join("issued.key");
    fs::write(&issued_cert, &cert_pem).unwrap();
    fs::write(&issued_key, &key_pem).unwrap();

    let generations_dir = temp.path.join("generations");

    let (verify_addr, server_handle) =
        start_mock_tls_server(cert_pem.clone(), key_pem.clone()).await;

    let activate_bin = env!("CARGO_BIN_EXE_spl-bridge-activate");
    let activate_cmd = activate_bin.to_string();
    let ca_pem_path_str = ca_pem_path.to_string_lossy().to_string();
    let issued_cert_str = issued_cert.to_string_lossy().to_string();
    let issued_key_str = issued_key.to_string_lossy().to_string();
    let gen_dir_str = generations_dir.to_string_lossy().to_string();
    let verify_addr_str = verify_addr.to_string();

    let status = tokio::task::spawn_blocking(move || {
        Command::new(activate_cmd)
            .arg("--issued-cert")
            .arg(issued_cert_str)
            .arg("--issued-key")
            .arg(issued_key_str)
            .arg("--generations-dir")
            .arg(gen_dir_str)
            .arg("--verify-addr")
            .arg(verify_addr_str)
            .arg("--reload-cmd")
            .arg("true")
            .arg("--control-tls-roots")
            .arg(ca_pem_path_str)
            .status()
            .expect("failed to run spl-bridge-activate")
    })
    .await
    .unwrap();

    assert!(status.success());
    let active_link = generations_dir.join("active");
    assert!(active_link.is_symlink());
    let active_target = fs::read_link(active_link).unwrap();
    assert!(active_target.exists());
    assert!(active_target.join("cert.pem").exists());
    assert!(active_target.join("key.pem").exists());

    server_handle.abort();
}

#[tokio::test]
async fn ac16_validation_failure_leaves_active_unchanged_and_no_pending() {
    let temp = TempDir::new("activate-val-fail");
    let (_ca_der, ca_key, ca_cert) = generate_ca();

    let ca_pem_path = temp.path.join("ca.pem");
    fs::write(&ca_pem_path, ca_cert.pem().as_bytes()).unwrap();

    // Gen 1 active
    let (_, _, gen1_cert_pem, gen1_key_pem) =
        generate_leaf("bridge.solstone.me", &ca_cert, &ca_key, 2020, 2035);
    let generations_dir = temp.path.join("generations");
    let gen1_dir = generations_dir.join("gen_1");
    fs::create_dir_all(&gen1_dir).unwrap();
    fs::write(gen1_dir.join("cert.pem"), &gen1_cert_pem).unwrap();
    fs::write(gen1_dir.join("key.pem"), &gen1_key_pem).unwrap();
    std::os::unix::fs::symlink(&gen1_dir, generations_dir.join("active")).unwrap();

    // Issued cert with wrong SAN
    let (_, _, bad_cert_pem, bad_key_pem) =
        generate_leaf("wrong.host.com", &ca_cert, &ca_key, 2020, 2035);
    let issued_cert = temp.path.join("issued.crt");
    let issued_key = temp.path.join("issued.key");
    fs::write(&issued_cert, &bad_cert_pem).unwrap();
    fs::write(&issued_key, &bad_key_pem).unwrap();

    let activate_bin = env!("CARGO_BIN_EXE_spl-bridge-activate");
    let output = Command::new(activate_bin)
        .arg("--issued-cert")
        .arg(&issued_cert)
        .arg("--issued-key")
        .arg(&issued_key)
        .arg("--generations-dir")
        .arg(&generations_dir)
        .arg("--verify-addr")
        .arg("127.0.0.1:443")
        .arg("--reload-cmd")
        .arg("true")
        .arg("--control-tls-roots")
        .arg(&ca_pem_path)
        .output()
        .expect("run activate");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("certificate validation failed"),
        "stderr must contain validation failure message: {stderr}"
    );

    // Active remains gen1
    let active_link = fs::read_link(generations_dir.join("active")).unwrap();
    assert_eq!(active_link, gen1_dir);
    // No pending created
    assert!(!generations_dir.join("pending").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ac16_verify_fail_rolls_back_and_stores_pending_and_retry_succeeds() {
    let temp = TempDir::new("activate-retry-pending");
    let (_ca_der, ca_key, ca_cert) = generate_ca();

    let ca_pem_path = temp.path.join("ca.pem");
    fs::write(&ca_pem_path, ca_cert.pem().as_bytes()).unwrap();

    // Gen 1: initial active
    let (_, _, gen1_cert_pem, gen1_key_pem) =
        generate_leaf("bridge.solstone.me", &ca_cert, &ca_key, 2020, 2035);
    let generations_dir = temp.path.join("generations");
    let gen1_dir = generations_dir.join("gen_1");
    fs::create_dir_all(&gen1_dir).unwrap();
    fs::write(gen1_dir.join("cert.pem"), &gen1_cert_pem).unwrap();
    fs::write(gen1_dir.join("key.pem"), &gen1_key_pem).unwrap();
    std::os::unix::fs::symlink(&gen1_dir, generations_dir.join("active")).unwrap();

    // Gen 2: issued pair
    let (_, _, gen2_cert_pem, gen2_key_pem) =
        generate_leaf("bridge.solstone.me", &ca_cert, &ca_key, 2020, 2035);
    let issued_cert = temp.path.join("issued.crt");
    let issued_key = temp.path.join("issued.key");
    fs::write(&issued_cert, &gen2_cert_pem).unwrap();
    fs::write(&issued_key, &gen2_key_pem).unwrap();

    // 1. Mock server serves gen1 so activate fails verify and rollbacks
    let (verify_addr, server1_handle) =
        start_mock_tls_server(gen1_cert_pem.clone(), gen1_key_pem.clone()).await;

    let activate_bin = env!("CARGO_BIN_EXE_spl-bridge-activate");
    let output1 = Command::new(activate_bin)
        .arg("--issued-cert")
        .arg(&issued_cert)
        .arg("--issued-key")
        .arg(&issued_key)
        .arg("--generations-dir")
        .arg(&generations_dir)
        .arg("--verify-addr")
        .arg(verify_addr.to_string())
        .arg("--reload-cmd")
        .arg("true")
        .arg("--control-tls-roots")
        .arg(&ca_pem_path)
        .output()
        .expect("run activate 1");

    assert!(!output1.status.success());
    let stderr1 = String::from_utf8_lossy(&output1.stderr);
    assert!(
        stderr1.contains("activation failed: reload or verify failed; rolled back"),
        "stderr must report rollback: {stderr1}"
    );

    // Active is gen1, pending points to gen2
    assert_eq!(
        fs::read_link(generations_dir.join("active")).unwrap(),
        gen1_dir
    );
    let pending_link = fs::read_link(generations_dir.join("pending")).unwrap();
    assert!(pending_link.exists());
    assert_ne!(pending_link, gen1_dir);

    server1_handle.abort();

    // 2. Mock server now serves gen2 -> retry-pending succeeds
    let (verify_addr2, server2_handle) =
        start_mock_tls_server(gen2_cert_pem.clone(), gen2_key_pem.clone()).await;

    let output2 = Command::new(activate_bin)
        .arg("--generations-dir")
        .arg(&generations_dir)
        .arg("--verify-addr")
        .arg(verify_addr2.to_string())
        .arg("--reload-cmd")
        .arg("true")
        .arg("--retry-pending")
        .arg("--control-tls-roots")
        .arg(&ca_pem_path)
        .output()
        .expect("run activate retry-pending");

    assert!(output2.status.success());
    // Active now points to gen2, pending removed
    assert_eq!(
        fs::read_link(generations_dir.join("active")).unwrap(),
        pending_link
    );
    assert!(!generations_dir.join("pending").exists());

    server2_handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ac16_hung_verify_aborts_at_timeout_and_retains_both_gens() {
    let temp = TempDir::new("activate-hung-verify");
    let (_ca_der, ca_key, ca_cert) = generate_ca();

    let ca_pem_path = temp.path.join("ca.pem");
    fs::write(&ca_pem_path, ca_cert.pem().as_bytes()).unwrap();

    // Gen 1 active
    let (_, _, gen1_cert_pem, gen1_key_pem) =
        generate_leaf("bridge.solstone.me", &ca_cert, &ca_key, 2020, 2035);
    let generations_dir = temp.path.join("generations");
    let gen1_dir = generations_dir.join("gen_1");
    fs::create_dir_all(&gen1_dir).unwrap();
    fs::write(gen1_dir.join("cert.pem"), &gen1_cert_pem).unwrap();
    fs::write(gen1_dir.join("key.pem"), &gen1_key_pem).unwrap();
    std::os::unix::fs::symlink(&gen1_dir, generations_dir.join("active")).unwrap();

    // Issued cert
    let (_, _, gen2_cert_pem, gen2_key_pem) =
        generate_leaf("bridge.solstone.me", &ca_cert, &ca_key, 2020, 2035);
    let issued_cert = temp.path.join("issued.crt");
    let issued_key = temp.path.join("issued.key");
    fs::write(&issued_cert, &gen2_cert_pem).unwrap();
    fs::write(&issued_key, &gen2_key_pem).unwrap();

    // Start a stalling server (accepts TCP connection but never completes TLS)
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let verify_addr = listener.local_addr().unwrap();
    let server_handle = tokio::spawn(async move {
        while let Ok((_stream, _)) = listener.accept().await {
            // Keep connection open without reading or writing
            tokio::time::sleep(Duration::from_mins(1)).await;
        }
    });

    let activate_bin = env!("CARGO_BIN_EXE_spl-bridge-activate");
    let start = Instant::now();
    let output = Command::new(activate_bin)
        .arg("--issued-cert")
        .arg(&issued_cert)
        .arg("--issued-key")
        .arg(&issued_key)
        .arg("--generations-dir")
        .arg(&generations_dir)
        .arg("--verify-addr")
        .arg(verify_addr.to_string())
        .arg("--reload-cmd")
        .arg("true")
        .arg("--control-tls-roots")
        .arg(&ca_pem_path)
        .output()
        .expect("run activate hung verify");

    let elapsed = start.elapsed();
    assert!(!output.status.success());
    // 10s verify timeout + rollback <= 30s overall timeout
    assert!(
        elapsed < Duration::from_secs(35),
        "Hung verify must exit <= 30s timeout, took {elapsed:?}"
    );

    // Active rolled back to gen 1
    assert_eq!(
        fs::read_link(generations_dir.join("active")).unwrap(),
        gen1_dir
    );
    // Both generations retained
    assert!(gen1_dir.exists());
    let pending_link = fs::read_link(generations_dir.join("pending")).unwrap();
    assert!(pending_link.exists());

    server_handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ac16_reload_cmd_fails_on_rollback() {
    let temp = TempDir::new("activate-rollback-fail");
    let (_ca_der, ca_key, ca_cert) = generate_ca();

    let ca_pem_path = temp.path.join("ca.pem");
    fs::write(&ca_pem_path, ca_cert.pem().as_bytes()).unwrap();

    let (_, _, gen1_cert_pem, gen1_key_pem) =
        generate_leaf("bridge.solstone.me", &ca_cert, &ca_key, 2020, 2035);
    let generations_dir = temp.path.join("generations");
    let gen1_dir = generations_dir.join("gen_1");
    fs::create_dir_all(&gen1_dir).unwrap();
    fs::write(gen1_dir.join("cert.pem"), &gen1_cert_pem).unwrap();
    fs::write(gen1_dir.join("key.pem"), &gen1_key_pem).unwrap();
    std::os::unix::fs::symlink(&gen1_dir, generations_dir.join("active")).unwrap();

    let (_, _, gen2_cert_pem, gen2_key_pem) =
        generate_leaf("bridge.solstone.me", &ca_cert, &ca_key, 2020, 2035);
    let issued_cert = temp.path.join("issued.crt");
    let issued_key = temp.path.join("issued.key");
    fs::write(&issued_cert, &gen2_cert_pem).unwrap();
    fs::write(&issued_key, &gen2_key_pem).unwrap();

    // Reload script: succeeds on 1st call, fails on 2nd call (rollback)
    let call_count_file = temp.path.join("reload_count");
    let reload_script = temp.path.join("reload.sh");
    let script_content = format!(
        r#"#!/usr/bin/env bash
COUNT_FILE="{}"
COUNT=0
if [ -f "$COUNT_FILE" ]; then
    COUNT=$(cat "$COUNT_FILE")
fi
COUNT=$((COUNT + 1))
echo "$COUNT" > "$COUNT_FILE"
if [ "$COUNT" -eq 1 ]; then
    exit 0
else
    exit 1
fi
"#,
        call_count_file.to_string_lossy()
    );
    fs::write(&reload_script, script_content).unwrap();
    fs::set_permissions(&reload_script, fs::Permissions::from_mode(0o755)).unwrap();

    // Mock server serves gen1 so verify fails
    let (verify_addr, server_handle) =
        start_mock_tls_server(gen1_cert_pem.clone(), gen1_key_pem.clone()).await;

    let activate_bin = env!("CARGO_BIN_EXE_spl-bridge-activate");
    let output = Command::new(activate_bin)
        .arg("--issued-cert")
        .arg(&issued_cert)
        .arg("--issued-key")
        .arg(&issued_key)
        .arg("--generations-dir")
        .arg(&generations_dir)
        .arg("--verify-addr")
        .arg(verify_addr.to_string())
        .arg("--reload-cmd")
        .arg(reload_script.to_string_lossy().to_string())
        .arg("--control-tls-roots")
        .arg(&ca_pem_path)
        .output()
        .expect("run activate");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("rollback activation failed"),
        "stderr must report rollback activation failed: {stderr}"
    );

    // Active link is rolled back to gen1 and both generations retained
    assert_eq!(
        fs::read_link(generations_dir.join("active")).unwrap(),
        gen1_dir
    );
    assert!(gen1_dir.exists());

    server_handle.abort();
}

#[tokio::test]
async fn ac16_retry_pending_quarantines_corrupt_cert() {
    let temp = TempDir::new("activate-quarantine");
    let generations_dir = temp.path.join("generations");
    fs::create_dir_all(&generations_dir).unwrap();

    let pending_dir = generations_dir.join("gen_corrupted");
    fs::create_dir_all(&pending_dir).unwrap();
    fs::write(pending_dir.join("cert.pem"), b"corrupted pem").unwrap();
    fs::write(pending_dir.join("key.pem"), b"corrupted key").unwrap();
    std::os::unix::fs::symlink(&pending_dir, generations_dir.join("pending")).unwrap();

    let activate_bin = env!("CARGO_BIN_EXE_spl-bridge-activate");
    let output = Command::new(activate_bin)
        .arg("--generations-dir")
        .arg(&generations_dir)
        .arg("--verify-addr")
        .arg("127.0.0.1:443")
        .arg("--reload-cmd")
        .arg("true")
        .arg("--retry-pending")
        .output()
        .expect("failed to run spl-bridge-activate");

    // Exit code 2 indicates quarantine
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("pending certificate quarantined: validation failed"),
        "stderr must report quarantine: {stderr}"
    );

    assert!(!generations_dir.join("pending").exists());
    let mut quarantined = false;
    for entry in fs::read_dir(&generations_dir).unwrap() {
        let name = entry.unwrap().file_name();
        if name.to_string_lossy().starts_with("quarantine_") {
            quarantined = true;
        }
    }
    assert!(quarantined, "Corrupt pending must be quarantined");
}
