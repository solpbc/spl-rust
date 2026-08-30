// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Coarse cleanup coverage for repeated public-bridge logical streams.

#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "the controlled in-memory mux fixture asserts at exact failure sites"
)]

use std::time::Duration;

use spl_bridge::registry::Registry;
use spl_home::{MuxAcceptor, MuxEvent, MuxLimits};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const STREAMS: usize = 256;

#[tokio::test]
async fn stream_churn_returns_registry_state_to_its_empty_baseline() {
    let registry = Registry::default();
    let (carrier, mut peer) = tokio::io::duplex(128 * 1024);
    let journal = registry
        .register(
            String::from("churn.test"),
            carrier,
            u64::MAX,
            tokio::time::Instant::now() + Duration::from_secs(10),
        )
        .await
        .unwrap();
    let mut acceptor = MuxAcceptor::new(MuxLimits::default()).unwrap();

    for _ in 0..STREAMS {
        let mut stream = journal.open_stream().await.unwrap();
        let output = feed_next(&mut peer, &mut acceptor).await;
        assert_eq!(
            output.events,
            vec![MuxEvent::Opened {
                stream_id: stream.id()
            }]
        );

        stream.shutdown().await.unwrap();
        let output = feed_next(&mut peer, &mut acceptor).await;
        assert_eq!(
            output.events,
            vec![MuxEvent::ReadClosed {
                stream_id: stream.id()
            }]
        );
        let output = acceptor.close_write(stream.id()).unwrap();
        write_frames(&mut peer, &output.frames).await;
        let mut byte = [0; 1];
        assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
    }

    drop(peer);
    tokio::time::timeout(Duration::from_secs(1), async {
        while registry.lookup("churn.test").await.is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

async fn feed_next(peer: &mut DuplexStream, acceptor: &mut MuxAcceptor) -> spl_home::MuxOutput {
    let mut bytes = vec![0; 64 * 1024];
    let count = tokio::time::timeout(Duration::from_secs(1), peer.read(&mut bytes))
        .await
        .expect("dialer must write a frame")
        .unwrap();
    assert_ne!(
        count, 0,
        "carrier must remain live while streams are closed"
    );
    acceptor.feed(&bytes[..count]).unwrap()
}

async fn write_frames(peer: &mut DuplexStream, frames: &[spl_core::frame::Frame]) {
    for frame in frames {
        peer.write_all(&frame.encode().unwrap()).await.unwrap();
    }
    peer.flush().await.unwrap();
}
