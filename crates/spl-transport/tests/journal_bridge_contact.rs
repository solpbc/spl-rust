// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

#![expect(
    clippy::expect_used,
    reason = "the copied integration test uses expect messages to identify failed harness steps"
)]

//! Loopback listener contact-state integration coverage.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use spl_core::bridge::BridgeNames;
use spl_transport::TransportError;
use spl_transport::client::DialedCarrier;
use spl_transport::journal_bridge::{self, CarrierOpener, JournalBridgeConfig};

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

fn neutral_bridge_names() -> BridgeNames {
    BridgeNames {
        capability_cookie_name: "test-journal-cap".into(),
        upstream_cookie_prefix: "test_j_".into(),
        observer_header_name: "x-test-observer".into(),
        protocol_version_header_name: "x-test-protocol".into(),
    }
}

#[tokio::test]
async fn contacted_flips_on_first_accept_before_http_parse() {
    let handle = journal_bridge::start(JournalBridgeConfig {
        opener: Arc::new(InertOpener),
        bridge_names: neutral_bridge_names(),
        endpoint_hosts: vec!["127.0.0.1".into()],
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
