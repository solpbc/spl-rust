// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! End-to-end coverage for bridge-controlled journal lease renewal.

#![expect(
    clippy::unwrap_used,
    reason = "the controlled mux fixture asserts exact renewal exchanges"
)]

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;
use spl_bridge::pop_auth::{FixtureTokenVerifier, PopAuthenticator, RenewalIdentity};
use spl_bridge::registry::Registry;
use spl_core::frame::Frame;
use spl_home::{MuxAcceptor, MuxEvent, MuxLimits};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::oneshot;

const BRIDGE_ID: &str = "bridge-lease-test";
const HOSTNAME: &str = "aaaqeaye.solstone.me";
const INSTANCE_ID: &str = "8488ae64-b592-80a3-97c6-490e995daa85";

#[tokio::test]
async fn acceptance_criterion_renewal_1_stream_one_reservation_precedes_public_stream_three() {
    let issuer = SigningKey::from_bytes(&[7; 32]);
    let pop = SigningKey::from_bytes(&[19; 32]);
    let verifier = FixtureTokenVerifier::new(
        HashMap::from([(String::from("fixture"), issuer)]),
        String::from(BRIDGE_ID),
    );
    let now = unix_seconds();
    let e1 = now + 120;
    let e2 = now + 600;
    let successor = verifier
        .mint(
            "fixture",
            INSTANCE_ID,
            HOSTNAME,
            now,
            e2,
            &pop.verifying_key(),
        )
        .unwrap();
    let authenticator = PopAuthenticator::new(Arc::new(verifier), String::from(BRIDGE_ID));
    let identity = RenewalIdentity::new(
        String::from(HOSTNAME),
        String::from(INSTANCE_ID),
        pop.verifying_key(),
    );
    let registry = Registry::default();
    let (carrier, peer) = tokio::io::duplex(128 * 1024);
    let (renewed_tx, renewed_rx) = oneshot::channel();
    let challenges = Arc::new(AtomicUsize::new(0));
    let peer_task = tokio::spawn(journal_peer(
        peer,
        pop,
        successor,
        renewed_tx,
        Arc::clone(&challenges),
    ));

    let journal = registry
        .register(
            String::from(HOSTNAME),
            carrier,
            authenticator,
            identity,
            e1,
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), renewed_rx)
        .await
        .unwrap()
        .unwrap();

    let public = journal.open_stream().await.unwrap();
    assert_eq!(public.id(), 3);
    assert_eq!(challenges.load(Ordering::Relaxed), 1);
    peer_task.abort();
}

#[tokio::test]
async fn acceptance_criterion_renewal_2_successor_e2_keeps_route_past_e1_then_retires_it() {
    let _subscriber = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_test_writer()
            .without_time()
            .finish(),
    );
    let issuer = SigningKey::from_bytes(&[7; 32]);
    let pop = SigningKey::from_bytes(&[23; 32]);
    let verifier = FixtureTokenVerifier::new(
        HashMap::from([(String::from("fixture"), issuer)]),
        String::from(BRIDGE_ID),
    );
    let now = unix_seconds();
    let e1 = now + 4;
    let e2 = now + 12;
    let successor = verifier
        .mint(
            "fixture",
            INSTANCE_ID,
            HOSTNAME,
            e2 - 700,
            e2,
            &pop.verifying_key(),
        )
        .unwrap();
    let authenticator = PopAuthenticator::new(Arc::new(verifier), String::from(BRIDGE_ID));
    let identity = RenewalIdentity::new(
        String::from(HOSTNAME),
        String::from(INSTANCE_ID),
        pop.verifying_key(),
    );
    let registry = Registry::default();
    let (carrier, peer) = tokio::io::duplex(128 * 1024);
    let (renewed_tx, renewed_rx) = oneshot::channel();
    let challenges = Arc::new(AtomicUsize::new(0));
    let peer_task = tokio::spawn(journal_peer(
        peer,
        pop,
        successor,
        renewed_tx,
        Arc::clone(&challenges),
    ));

    let journal = registry
        .register(
            String::from(HOSTNAME),
            carrier,
            authenticator,
            identity,
            e1,
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), renewed_rx)
        .await
        .unwrap()
        .unwrap();

    tokio::time::sleep(Duration::from_secs(5)).await;
    let stream = journal.open_stream().await;
    assert!(stream.is_ok(), "E2 must outlive E1: {:?}", stream.err());

    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if registry.lookup(HOSTNAME).await.is_none() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(challenges.load(Ordering::Relaxed), 1);
    peer_task.abort();
}

async fn journal_peer(
    mut peer: DuplexStream,
    pop: SigningKey,
    successor: String,
    renewed: oneshot::Sender<()>,
    challenges: Arc<AtomicUsize>,
) {
    let mut acceptor = MuxAcceptor::new(MuxLimits::default()).unwrap();
    let mut control_body = Vec::new();
    let mut renewed = Some(renewed);
    let mut bytes = [0u8; 16 * 1024];
    loop {
        let read = peer.read(&mut bytes).await.unwrap();
        if read == 0 {
            return;
        }
        let output = acceptor.feed(&bytes[..read]).unwrap();
        for event in output.events {
            if let MuxEvent::Data {
                stream_id: 1,
                bytes,
            } = event
            {
                control_body.extend_from_slice(&bytes);
                if let Some(response) = renewal_response(&control_body, &pop, &successor) {
                    challenges.fetch_add(1, Ordering::Relaxed);
                    if let Some(renewed) = renewed.take() {
                        let output = acceptor.try_send_data(1, response).unwrap().unwrap();
                        write_frames(&mut peer, &output.frames).await;
                        renewed.send(()).unwrap();
                    }
                }
            }
        }
        write_frames(&mut peer, &output.frames).await;
    }
}

fn renewal_response(body: &[u8], pop: &SigningKey, successor: &str) -> Option<Vec<u8>> {
    let prefix: [u8; 4] = body.get(..4)?.try_into().ok()?;
    let length = u32::from_be_bytes(prefix) as usize;
    let challenge: Value = serde_json::from_slice(body.get(4..4 + length)?).ok()?;
    let nonce: [u8; 16] = URL_SAFE_NO_PAD
        .decode(challenge.get("nonce")?.as_str()?)
        .ok()?
        .try_into()
        .ok()?;
    let bridge_id = challenge.get("bridge_id")?.as_str()?;
    let timestamp = challenge.get("timestamp")?.as_i64()?;
    let mut signed = Vec::with_capacity(16 + bridge_id.len() + 8);
    signed.extend_from_slice(&nonce);
    signed.extend_from_slice(bridge_id.as_bytes());
    signed.extend_from_slice(&timestamp.to_be_bytes());
    let response = serde_json::json!({
        "token": successor,
        "hostname": HOSTNAME,
        "signature": URL_SAFE_NO_PAD.encode(pop.sign(&signed).to_bytes()),
    });
    let body = serde_json::to_vec(&response).ok()?;
    let length = u32::try_from(body.len()).ok()?;
    let mut framed = length.to_be_bytes().to_vec();
    framed.extend_from_slice(&body);
    Some(framed)
}

async fn write_frames(peer: &mut DuplexStream, frames: &[Frame]) {
    for frame in frames {
        peer.write_all(&frame.encode().unwrap()).await.unwrap();
    }
    peer.flush().await.unwrap();
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
