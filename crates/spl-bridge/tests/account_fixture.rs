// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Locked account fixture coverage for MCP bridge tokens.

#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "the fixture test uses controlled local certificates, paths, and JSON"
)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rcgen::{CertificateParams, KeyPair};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::Value;
use spl_bridge::pop_auth::{ClockFn, JwksTimeouts, JwksTokenVerifier, PopError, TokenVerifier};
use spl_bridge::server_tls_config;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const FIXTURE_BYTES: usize = 2_203;
const FIXTURE_SHA256: &str = "6563b737522de561b62a00a93e5a083f5cfa56608bd45ea1bc388c0ee395c956";

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("bridge crate must be beneath the workspace root")
        .join("account/test-fixtures/mcp_bridge_v1.json")
}

#[test]
fn account_fixture_bytes_and_hash_are_locked() {
    let path = fixture_path();
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(bytes.len(), FIXTURE_BYTES);
    let output = Command::new("sha256sum").arg(path).output().unwrap();
    assert!(output.status.success());
    let digest = std::str::from_utf8(&output.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap();
    assert_eq!(digest, FIXTURE_SHA256);
}

#[tokio::test]
async fn account_fixture_token_verifies_against_its_jwks() {
    let fixture: Value = serde_json::from_slice(&std::fs::read(fixture_path()).unwrap()).unwrap();
    let token = fixture["response"]["body"]["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let jwks = serde_json::to_vec(&fixture["jwks"]["body"]).unwrap();
    let (url, roots, server) = serve_jwks(jwks).await;
    let seconds = Arc::new(AtomicU64::new(1_700_000_300));
    let clock: ClockFn = {
        let seconds = Arc::clone(&seconds);
        Arc::new(move || seconds.load(Ordering::SeqCst))
    };
    let verifier = JwksTokenVerifier::with_trust_store(
        &url,
        roots,
        JwksTimeouts::default(),
        String::from("mcp-bridge-fixture"),
        clock,
    )
    .unwrap();

    let claims = verifier.verify(&token).await.unwrap();
    assert_eq!(claims.instance_id(), "8488ae64-b592-80a3-97c6-490e995daa85");
    assert_eq!(claims.hostname(), "aaaqeaye.solstone.me");
    assert_eq!(claims.expires_at(), 1_700_000_600);
    server.await.unwrap();

    seconds.store(1_700_000_600, Ordering::SeqCst);
    assert!(matches!(
        verifier.verify(&token).await,
        Err(PopError::TokenRejected)
    ));
}

async fn serve_jwks(body: Vec<u8>) -> (String, RootCertStore, tokio::task::JoinHandle<()>) {
    let key = KeyPair::generate().unwrap();
    let params = CertificateParams::new(vec![String::from("localhost")]).unwrap();
    let certificate = params.self_signed(&key).unwrap();
    let certificate_der = CertificateDer::from(certificate.der().to_vec());
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let config = Arc::new(server_tls_config(vec![certificate_der.clone()], private_key).unwrap());
    let mut roots = RootCertStore::empty();
    roots.add(certificate_der).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = TlsAcceptor::from(config).accept(stream).await.unwrap();
        let mut request = [0u8; 1024];
        let _ = stream.read(&mut request).await.unwrap();
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        stream.write_all(&body).await.unwrap();
        stream.flush().await.unwrap();
    });
    (
        format!("https://localhost:{}/jwks", address.port()),
        roots,
        server,
    )
}
