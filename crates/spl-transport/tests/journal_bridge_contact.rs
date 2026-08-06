// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "the copied integration test uses direct assertions to identify failed harness steps"
)]

//! Loopback listener contact-state integration coverage.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use spl_core::bridge::BridgeNames;
use spl_transport::TransportError;
use spl_transport::client::DialedCarrier;
use spl_transport::journal_bridge::{
    self, BridgePolicy, CarrierOpener, JournalBridgeConfig, JournalBridgeStatus, LocalResponse,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct InertOpener;

impl CarrierOpener for InertOpener {
    fn proxy_headers(
        &self,
        upstream_headers: &[(String, String)],
    ) -> Result<Vec<(String, String)>, TransportError> {
        Ok(upstream_headers.to_vec())
    }

    fn dial_carrier(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<DialedCarrier, TransportError>> + Send + '_>> {
        Box::pin(async { Err(TransportError::NoEndpoint) })
    }
}

struct CountingOpener {
    dials: Arc<AtomicUsize>,
}

impl CarrierOpener for CountingOpener {
    fn proxy_headers(
        &self,
        upstream_headers: &[(String, String)],
    ) -> Result<Vec<(String, String)>, TransportError> {
        Ok(upstream_headers.to_vec())
    }

    fn dial_carrier(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<DialedCarrier, TransportError>> + Send + '_>> {
        self.dials.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(TransportError::NoEndpoint) })
    }
}

struct AccessDeniedOpener {
    dials: Arc<AtomicUsize>,
}

impl CarrierOpener for AccessDeniedOpener {
    fn proxy_headers(
        &self,
        upstream_headers: &[(String, String)],
    ) -> Result<Vec<(String, String)>, TransportError> {
        Ok(upstream_headers.to_vec())
    }

    fn dial_carrier(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<DialedCarrier, TransportError>> + Send + '_>> {
        self.dials.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(TransportError::TlsAccessDenied) })
    }
}

fn neutral_bridge_names() -> BridgeNames {
    BridgeNames {
        capability_cookie_name: "test-journal-cap".into(),
        upstream_cookie_prefix: "test_j_".into(),
        observer_header_name: "x-test-observer".into(),
        protocol_version_header_name: "x-test-protocol".into(),
    }
}

async fn raw_request(port: u16, target: &str, cookie: Option<&str>) -> Vec<u8> {
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect to bridge");
    let mut request = format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n");
    if let Some(cookie) = cookie {
        request.push_str("Cookie: ");
        request.push_str(cookie);
        request.push_str("\r\n");
    }
    request.push_str("Content-Length: 0\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write bridge request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read bridge response");
    response
}

fn response_status(response: &[u8]) -> u16 {
    String::from_utf8_lossy(response)
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse().ok())
        .expect("response status")
}

#[tokio::test]
async fn contacted_flips_on_first_accept_before_http_parse() {
    let handle = journal_bridge::start(JournalBridgeConfig {
        opener: Arc::new(InertOpener),
        bridge_names: neutral_bridge_names(),
        endpoint_hosts: vec!["127.0.0.1".into()],
        policy: BridgePolicy::default(),
    })
    .await
    .expect("bridge start");

    // Flag starts false before any connection.
    assert!(!handle.contacted(), "flag must start false");

    let port = handle.port();
    // Bare TCP connection that sends NO parseable HTTP request. The flag must
    // still flip, proving the seam is at accept (not after HTTP parse).
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect to bridge");

    // accept + flag store happen in the spawned accept_loop; bounded poll.
    let mut flipped = false;
    for _ in 0..200 {
        if handle.contacted() {
            flipped = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        flipped,
        "contacted() must flip true on the first accepted TCP connection"
    );

    drop(stream);
    handle.begin_shutdown();
}

#[tokio::test]
async fn journal_bridge_local_response_is_authorized_and_uses_coherent_status() {
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(None::<JournalBridgeStatus>));
    let calls_for_hook = calls.clone();
    let seen_for_hook = seen.clone();
    let policy = BridgePolicy {
        local_response: Arc::new(move |_head, status| {
            calls_for_hook.fetch_add(1, Ordering::SeqCst);
            *seen_for_hook.lock().unwrap() = Some(*status);
            Some(LocalResponse {
                status: 200,
                content_type: "application/json".into(),
                body: br#"{"status":"local"}"#.to_vec(),
            })
        }),
        ..BridgePolicy::default()
    };
    let dials = Arc::new(AtomicUsize::new(0));
    let handle = journal_bridge::start(JournalBridgeConfig {
        opener: Arc::new(CountingOpener {
            dials: dials.clone(),
        }),
        bridge_names: neutral_bridge_names(),
        endpoint_hosts: Vec::new(),
        policy,
    })
    .await
    .expect("bridge start");
    let port = handle.port();
    let capability = handle
        .bootstrap_url()
        .and_then(|url| url.split_once("cap=").map(|(_, value)| value.to_string()))
        .expect("default capability");

    let rejected = raw_request(port, "/_status", None).await;
    assert_eq!(response_status(&rejected), 403);
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let bootstrap = raw_request(
        port,
        &format!("{}?cap={capability}", spl_core::bridge::BOOTSTRAP_ROUTE),
        None,
    )
    .await;
    assert_eq!(response_status(&bootstrap), 302);
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let cookie = format!("test-journal-cap={capability}");
    let local = raw_request(port, "/_status", Some(&cookie)).await;
    assert_eq!(response_status(&local), 200);
    assert!(String::from_utf8_lossy(&local).contains("Content-Type: application/json\r\n"));
    assert!(local.ends_with(br#"{"status":"local"}"#));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(dials.load(Ordering::SeqCst), 0);

    let during = seen.lock().unwrap().expect("hook status");
    assert!(during.listener_active);
    assert!(during.contacted);
    assert!(!during.carrier_live);
    assert_eq!(during.active_requests, 1);

    for _ in 0..200 {
        if handle.status().active_requests == 0 {
            break;
        }
        tokio::task::yield_now().await;
    }
    let after = handle.status();
    assert!(after.listener_active);
    assert!(after.contacted);
    assert!(!after.carrier_live);
    assert_eq!(after.active_requests, 0);

    handle.shutdown_and_wait().await;
}

// Falsified by removing the get_or_dial latch-on-error branch: the second request increments
// the opener count to two instead of returning the existing local 502 without another dial.
#[tokio::test]
async fn access_denied_setup_latches_and_short_circuits_later_requests() {
    let dials = Arc::new(AtomicUsize::new(0));
    let handle = journal_bridge::start(JournalBridgeConfig {
        opener: Arc::new(AccessDeniedOpener {
            dials: dials.clone(),
        }),
        bridge_names: neutral_bridge_names(),
        endpoint_hosts: Vec::new(),
        policy: BridgePolicy::default(),
    })
    .await
    .expect("bridge start");
    let port = handle.port();
    let capability = handle
        .bootstrap_url()
        .and_then(|url| url.split_once("cap=").map(|(_, value)| value.to_string()))
        .expect("default capability");
    let cookie = format!("test-journal-cap={capability}");

    let first = raw_request(port, "/healthz", Some(&cookie)).await;
    assert_eq!(response_status(&first), 502);
    assert_eq!(dials.load(Ordering::SeqCst), 1);
    assert_eq!(
        handle.status().terminal_reason,
        Some(journal_bridge::JournalBridgeTerminalReason::TlsAccessDenied)
    );

    let second = raw_request(port, "/healthz", Some(&cookie)).await;
    assert_eq!(response_status(&second), 502);
    assert_eq!(dials.load(Ordering::SeqCst), 1);
    handle.shutdown_and_wait().await;
}

#[tokio::test]
async fn fixed_port_binds_only_ipv4_loopback() {
    let probe = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("reserve fixed port");
    let port = probe.local_addr().expect("probe address").port();
    drop(probe);

    let policy = BridgePolicy {
        port,
        ..BridgePolicy::default()
    };
    let handle = journal_bridge::start(JournalBridgeConfig {
        opener: Arc::new(InertOpener),
        bridge_names: neutral_bridge_names(),
        endpoint_hosts: vec!["127.0.0.1".into()],
        policy,
    })
    .await
    .expect("bridge start");

    assert_eq!(handle.port(), port);
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect to fixed bridge port");
    assert_eq!(
        stream.peer_addr().expect("bridge peer address"),
        std::net::SocketAddr::from(([127, 0, 0, 1], port))
    );

    drop(stream);
    handle.shutdown_and_wait().await;
}
