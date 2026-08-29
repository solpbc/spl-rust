// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Single-flight JWKS fetch coverage using a local TLS origin.

#![expect(
    clippy::unwrap_used,
    reason = "the test fixture uses controlled local certificates and keys"
)]

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;
use rcgen::{CertificateParams, KeyPair};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::json;
use spl_bridge::pop_auth::{
    ClockFn, FixtureTokenVerifier, JwksTimeouts, JwksTokenVerifier, PopError, TokenVerifier,
};
use spl_bridge::server_tls_config;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Notify};
use tokio_rustls::TlsAcceptor;

const AUDIENCE: &str = "mcp-bridge-single-flight";
const INSTANCE_ID: &str = "8488ae64-b592-80a3-97c6-490e995daa85";
const HOSTNAME: &str = "aaaqeaye.solstone.me";
const NOW: u64 = 1_700_000_300;

#[derive(Clone)]
enum ResponseMode {
    Respond,
    Hold(Arc<Notify>),
    HoldThenClose(Arc<Notify>),
    Oversized,
}

struct ServerState {
    body: Vec<u8>,
    mode: ResponseMode,
}

struct JwksServer {
    url: String,
    roots: RootCertStore,
    state: Arc<Mutex<ServerState>>,
    requests: Arc<AtomicUsize>,
    accept_task: tokio::task::JoinHandle<()>,
}

impl JwksServer {
    async fn new(body: Vec<u8>) -> Self {
        let key = KeyPair::generate().unwrap();
        let params = CertificateParams::new(vec![String::from("localhost")]).unwrap();
        let certificate = params.self_signed(&key).unwrap();
        let certificate_der = CertificateDer::from(certificate.der().to_vec());
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let config =
            Arc::new(server_tls_config(vec![certificate_der.clone()], private_key).unwrap());
        let mut roots = RootCertStore::empty();
        roots.add(certificate_der).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(ServerState {
            body,
            mode: ResponseMode::Respond,
        }));
        let requests = Arc::new(AtomicUsize::new(0));
        let accept_task = {
            let state = Arc::clone(&state);
            let requests = Arc::clone(&requests);
            tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    let state = Arc::clone(&state);
                    let requests = Arc::clone(&requests);
                    let config = Arc::clone(&config);
                    tokio::spawn(async move {
                        serve_jwks_connection(stream, config, state, requests).await;
                    });
                }
            })
        };

        Self {
            url: format!("https://localhost:{}/jwks", address.port()),
            roots,
            state,
            requests,
            accept_task,
        }
    }

    async fn set_response(&self, body: Vec<u8>, mode: ResponseMode) {
        let mut state = self.state.lock().await;
        state.body = body;
        state.mode = mode;
    }

    async fn wait_for_requests(&self, expected: usize) {
        while self.requests.load(Ordering::SeqCst) < expected {
            tokio::task::yield_now().await;
        }
    }

    fn request_count(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

impl Drop for JwksServer {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

async fn serve_jwks_connection(
    stream: tokio::net::TcpStream,
    config: Arc<rustls::ServerConfig>,
    state: Arc<Mutex<ServerState>>,
    requests: Arc<AtomicUsize>,
) {
    let Ok(mut stream) = TlsAcceptor::from(config).accept(stream).await else {
        return;
    };
    let mut request = [0u8; 1024];
    let Ok(read) = stream.read(&mut request).await else {
        return;
    };
    if read == 0 {
        return;
    }
    requests.fetch_add(1, Ordering::SeqCst);

    let (body, mode) = {
        let state = state.lock().await;
        (state.body.clone(), state.mode.clone())
    };
    match mode {
        ResponseMode::Respond => write_jwks_response(&mut stream, &body).await,
        ResponseMode::Hold(gate) => {
            gate.notified().await;
            write_jwks_response(&mut stream, &body).await;
        }
        ResponseMode::HoldThenClose(gate) => {
            gate.notified().await;
        }
        ResponseMode::Oversized => {
            let _ = stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-length: 1048577\r\nconnection: close\r\n\r\n",
                )
                .await;
            let _ = stream.flush().await;
        }
    }
}

async fn write_jwks_response<S>(stream: &mut S, body: &[u8])
where
    S: AsyncWriteExt + Unpin,
{
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.write_all(body).await;
    let _ = stream.flush().await;
}

fn fixed_clock() -> ClockFn {
    Arc::new(|| NOW)
}

fn verifier(server: &JwksServer, timeouts: JwksTimeouts) -> JwksTokenVerifier {
    JwksTokenVerifier::with_trust_store(
        &server.url,
        server.roots.clone(),
        timeouts,
        String::from(AUDIENCE),
        fixed_clock(),
    )
    .unwrap()
}

fn token(kid: &str, seed: u8) -> String {
    let issuer = SigningKey::from_bytes(&[seed; 32]);
    let pop = SigningKey::from_bytes(&[201; 32]);
    let fixture = FixtureTokenVerifier::with_clock(
        HashMap::from([(kid.to_owned(), issuer)]),
        String::from(AUDIENCE),
        fixed_clock(),
    );
    fixture
        .mint(
            kid,
            INSTANCE_ID,
            HOSTNAME,
            NOW - 300,
            NOW + 300,
            &pop.verifying_key(),
        )
        .unwrap()
}

fn jwks_body(keys: &[(String, u8)]) -> Vec<u8> {
    let keys: Vec<_> = keys
        .iter()
        .map(|(kid, seed)| {
            let key = SigningKey::from_bytes(&[*seed; 32]);
            json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
                "kid": kid,
                "use": "sig",
                "alg": "EdDSA",
            })
        })
        .collect();
    serde_json::to_vec(&json!({"keys": keys})).unwrap()
}

fn keys(entries: &[(&str, u8)]) -> Vec<(String, u8)> {
    entries
        .iter()
        .map(|(kid, seed)| (String::from(*kid), *seed))
        .collect()
}

fn assert_key_unavailable(result: &Result<spl_bridge::pop_auth::VerifiedClaims, PopError>) {
    assert!(matches!(result, Err(PopError::JwksKeyUnavailable)));
}

fn assert_jwks_unavailable(result: &Result<spl_bridge::pop_auth::VerifiedClaims, PopError>) {
    assert!(matches!(result, Err(PopError::JwksUnavailable)));
}

#[tokio::test(start_paused = true)]
async fn single_flight_coalesces_misses_and_serves_cached_keys() {
    let gate = Arc::new(Notify::new());
    let server = JwksServer::new(jwks_body(&keys(&[("cached", 1)]))).await;
    server
        .set_response(
            jwks_body(&keys(&[("cached", 1)])),
            ResponseMode::Hold(Arc::clone(&gate)),
        )
        .await;
    let verifier = verifier(&server, JwksTimeouts::default());

    let mut misses = Vec::new();
    for seed in 2..=101 {
        let verifier = verifier.clone();
        let kid = format!("unknown-{seed}");
        misses.push(tokio::spawn(async move {
            verifier.verify(&token(&kid, seed)).await
        }));
    }
    server.wait_for_requests(1).await;
    gate.notify_one();
    for miss in misses {
        assert_key_unavailable(&miss.await.unwrap());
    }
    assert_eq!(server.request_count(), 1);

    for seed in 102..=106 {
        assert_key_unavailable(
            &verifier
                .verify(&token(&format!("staggered-{seed}"), seed))
                .await,
        );
    }
    assert_eq!(server.request_count(), 1);

    tokio::time::advance(Duration::from_secs(5)).await;
    let held_miss = Arc::new(Notify::new());
    server
        .set_response(
            jwks_body(&keys(&[("cached", 1)])),
            ResponseMode::Hold(Arc::clone(&held_miss)),
        )
        .await;
    let pending = {
        let verifier = verifier.clone();
        tokio::spawn(async move { verifier.verify(&token("second-miss", 107)).await })
    };
    server.wait_for_requests(2).await;

    let claims = verifier.verify(&token("cached", 1)).await.unwrap();
    assert_eq!(claims.instance_id(), INSTANCE_ID);
    assert_eq!(server.request_count(), 2);
    held_miss.notify_one();
    assert_key_unavailable(&pending.await.unwrap());
}

#[tokio::test(start_paused = true)]
async fn cancelled_initiator_does_not_abort_a_successful_fetch() {
    let gate = Arc::new(Notify::new());
    let server = JwksServer::new(jwks_body(&keys(&[("late-a", 2), ("late-b", 3)]))).await;
    server
        .set_response(
            jwks_body(&keys(&[("late-a", 2), ("late-b", 3)])),
            ResponseMode::Hold(Arc::clone(&gate)),
        )
        .await;
    let verifier = verifier(&server, JwksTimeouts::default());
    let initiator = {
        let verifier = verifier.clone();
        tokio::spawn(async move { verifier.verify(&token("dropped", 1)).await })
    };
    server.wait_for_requests(1).await;
    initiator.abort();
    assert!(initiator.await.is_err());

    let late_a = {
        let verifier = verifier.clone();
        tokio::spawn(async move { verifier.verify(&token("late-a", 2)).await })
    };
    let late_b = {
        let verifier = verifier.clone();
        tokio::spawn(async move { verifier.verify(&token("late-b", 3)).await })
    };
    tokio::task::yield_now().await;
    gate.notify_one();

    assert!(late_a.await.unwrap().is_ok());
    assert!(late_b.await.unwrap().is_ok());
    assert_eq!(server.request_count(), 1);
}

#[tokio::test(start_paused = true)]
async fn failed_fetch_is_shared_and_cooldown_rejects_without_retrying() {
    let gate = Arc::new(Notify::new());
    let server = JwksServer::new(jwks_body(&[])).await;
    server
        .set_response(Vec::new(), ResponseMode::HoldThenClose(Arc::clone(&gate)))
        .await;
    let verifier = verifier(&server, JwksTimeouts::default());
    let initiator = {
        let verifier = verifier.clone();
        tokio::spawn(async move { verifier.verify(&token("dropped", 1)).await })
    };
    server.wait_for_requests(1).await;
    initiator.abort();
    assert!(initiator.await.is_err());

    let leader = {
        let verifier = verifier.clone();
        tokio::spawn(async move { verifier.verify(&token("leader", 2)).await })
    };
    let waiter = {
        let verifier = verifier.clone();
        tokio::spawn(async move { verifier.verify(&token("waiter", 3)).await })
    };
    tokio::task::yield_now().await;
    gate.notify_one();
    assert_jwks_unavailable(&leader.await.unwrap());
    assert_jwks_unavailable(&waiter.await.unwrap());

    for seed in 4..=6 {
        assert_key_unavailable(
            &verifier
                .verify(&token(&format!("cooldown-{seed}"), seed))
                .await,
        );
    }
    assert_eq!(server.request_count(), 1);
}

#[tokio::test(start_paused = true)]
async fn rotation_and_cache_expiry_boundaries_are_exact_and_cache_is_bounded() {
    let server = JwksServer::new(jwks_body(&[])).await;
    let verifier = verifier(&server, JwksTimeouts::default());

    let initial = {
        let verifier = verifier.clone();
        tokio::spawn(async move { verifier.verify(&token("absent", 1)).await })
    };
    server.wait_for_requests(1).await;
    assert_key_unavailable(&initial.await.unwrap());
    assert_eq!(server.request_count(), 1);
    server
        .set_response(jwks_body(&keys(&[("rotated", 2)])), ResponseMode::Respond)
        .await;
    tokio::time::advance(Duration::from_millis(4_999)).await;
    assert_key_unavailable(&verifier.verify(&token("rotated", 2)).await);
    assert_eq!(server.request_count(), 1);

    tokio::time::advance(Duration::from_millis(1)).await;
    let mut rotated = Vec::new();
    for _ in 0..8 {
        let verifier = verifier.clone();
        rotated.push(tokio::spawn(async move {
            verifier.verify(&token("rotated", 2)).await
        }));
    }
    server.wait_for_requests(2).await;
    for verification in rotated {
        assert!(verification.await.unwrap().is_ok());
    }
    assert_eq!(server.request_count(), 2);

    tokio::time::advance(Duration::from_secs(100)).await;
    assert!(verifier.verify(&token("rotated", 2)).await.is_ok());
    assert_eq!(server.request_count(), 2);
    tokio::time::advance(Duration::from_millis(199_999)).await;
    assert!(verifier.verify(&token("rotated", 2)).await.is_ok());
    assert_eq!(server.request_count(), 2);
    tokio::time::advance(Duration::from_millis(1)).await;
    let expiry_miss = {
        let verifier = verifier.clone();
        tokio::spawn(async move { verifier.verify(&token("rotated", 2)).await })
    };
    server.wait_for_requests(3).await;
    assert!(expiry_miss.await.unwrap().is_ok());
    assert_eq!(server.request_count(), 3);

    let capacity_keys: Vec<_> = (3..=67)
        .map(|seed| (format!("capacity-{seed}"), seed))
        .collect();
    server
        .set_response(jwks_body(&capacity_keys), ResponseMode::Respond)
        .await;
    tokio::time::advance(Duration::from_secs(5)).await;
    let mut capacity = Vec::new();
    for (kid, seed) in capacity_keys.clone() {
        let verifier = verifier.clone();
        capacity.push(tokio::spawn(async move {
            verifier.verify(&token(&kid, seed)).await
        }));
    }
    server.wait_for_requests(4).await;
    let mut successes = 0;
    let mut misses = 0;
    for verification in capacity {
        match verification.await.unwrap() {
            Ok(_) => successes += 1,
            Err(PopError::JwksKeyUnavailable) => misses += 1,
            Err(error) => unreachable!("capacity fetch returned an unexpected error: {error}"),
        }
    }
    assert_eq!(successes, 64);
    assert_eq!(misses, 1);
    assert_eq!(server.request_count(), 4);
}

#[tokio::test]
async fn fetch_limits_and_error_categories_remain_bounded_and_nonreflective() {
    let oversized = JwksServer::new(jwks_body(&[])).await;
    oversized
        .set_response(Vec::new(), ResponseMode::Oversized)
        .await;
    let oversized_verifier = verifier(&oversized, JwksTimeouts::default());
    let Err(oversized_error) = oversized_verifier.verify(&token("kid-secret", 1)).await else {
        unreachable!("oversized JWKS response unexpectedly verified a token")
    };
    assert!(matches!(oversized_error, PopError::JwksUnavailable));

    let gate = Arc::new(Notify::new());
    let black_hole = JwksServer::new(jwks_body(&[])).await;
    black_hole
        .set_response(Vec::new(), ResponseMode::Hold(Arc::clone(&gate)))
        .await;
    let timeout_verifier = verifier(
        &black_hole,
        JwksTimeouts {
            connect: Duration::from_millis(50),
            fetch: Duration::from_millis(50),
        },
    );
    let started = tokio::time::Instant::now();
    let Err(timeout_error) = timeout_verifier.verify(&token("timeout-secret", 2)).await else {
        unreachable!("black-hole JWKS response unexpectedly verified a token")
    };
    assert!(matches!(timeout_error, PopError::JwksUnavailable));
    assert!(started.elapsed() < Duration::from_secs(1));
    gate.notify_one();

    let fixture = FixtureTokenVerifier::with_clock(
        HashMap::from([(String::from("fixture"), SigningKey::from_bytes(&[3; 32]))]),
        String::from(AUDIENCE),
        fixed_clock(),
    );
    let Err(rejected) = fixture.verify("token-secret").await else {
        unreachable!("malformed token unexpectedly verified")
    };
    let Err(cooldown) = oversized_verifier
        .verify(&token("cooldown-secret", 4))
        .await
    else {
        unreachable!("cooldown miss unexpectedly verified")
    };
    assert!(matches!(rejected, PopError::TokenRejected));
    assert!(matches!(cooldown, PopError::JwksKeyUnavailable));

    for error in [rejected, oversized_error, cooldown] {
        let display = error.to_string();
        let debug = format!("{error:?}");
        for secret in [
            "token-secret",
            "kid-secret",
            HOSTNAME,
            "home:subject-secret",
            "127.0.0.1:12345",
            AUDIENCE,
        ] {
            assert!(!display.contains(secret));
            assert!(!debug.contains(secret));
        }
    }
}
