// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Interoperability coverage against the real home-side mux acceptor.

#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "interop tests assert controlled mux fixtures"
)]

use std::io;
use std::time::Duration;

use spl_bridge::frame_dialer::{FrameDialer, StreamEnd};
use spl_core::frame::{Frame, HEADER_LEN, MAX_PAYLOAD, RESET_CANCEL, RESET_STREAM_LIMIT_EXCEEDED};
use spl_core::mux::INITIAL_WINDOW;
use spl_home::{MuxAcceptor, MuxEvent, MuxLimits, MuxOutput, ResetReason};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::time::timeout;

const TEST_TIMEOUT: Duration = Duration::from_secs(1);

fn acceptor(limits: MuxLimits) -> MuxAcceptor {
    MuxAcceptor::new(limits).unwrap()
}

async fn feed_next(peer: &mut DuplexStream, acceptor: &mut MuxAcceptor) -> MuxOutput {
    let mut buffer = vec![0u8; 128 * 1024];
    let read = timeout(TEST_TIMEOUT, peer.read(&mut buffer))
        .await
        .expect("dialer must write a frame")
        .unwrap();
    assert_ne!(
        read, 0,
        "dialer carrier must remain open during the exchange"
    );
    acceptor.feed(&buffer[..read]).unwrap()
}

async fn write_frames(peer: &mut DuplexStream, frames: &[Frame]) {
    for frame in frames {
        peer.write_all(&frame.encode().unwrap()).await.unwrap();
    }
    peer.flush().await.unwrap();
}

async fn open_stream(
    dialer: &FrameDialer,
    peer: &mut DuplexStream,
    acceptor: &mut MuxAcceptor,
) -> spl_bridge::frame_dialer::DialerStream {
    let stream = dialer.open_stream().await.unwrap();
    let output = feed_next(peer, acceptor).await;
    assert_eq!(
        output.events,
        vec![MuxEvent::Opened {
            stream_id: stream.id()
        }]
    );
    stream
}

#[tokio::test]
async fn opens_and_transfers_ordered_bytes_in_both_directions() {
    let (carrier, mut peer) = tokio::io::duplex(2 * INITIAL_WINDOW);
    let dialer = FrameDialer::new(carrier);
    let mut acceptor = acceptor(MuxLimits::default());
    let mut stream = open_stream(&dialer, &mut peer, &mut acceptor).await;

    stream.write_all(b"client-to-journal").await.unwrap();
    stream.flush().await.unwrap();
    let output = feed_next(&mut peer, &mut acceptor).await;
    assert_eq!(
        output.events,
        vec![MuxEvent::Data {
            stream_id: stream.id(),
            bytes: b"client-to-journal".to_vec(),
        }]
    );

    let output = acceptor
        .try_send_data(stream.id(), b"journal-to-client".to_vec())
        .unwrap()
        .unwrap();
    write_frames(&mut peer, &output.frames).await;
    let mut received = [0u8; 17];
    stream.read_exact(&mut received).await.unwrap();
    assert_eq!(&received, b"journal-to-client");
}

#[tokio::test]
async fn send_window_pauses_then_resumes_after_a_grant() {
    let (carrier, mut peer) = tokio::io::duplex(2 * INITIAL_WINDOW);
    let dialer = FrameDialer::new(carrier);
    let mut acceptor = acceptor(MuxLimits::default());
    let mut stream = open_stream(&dialer, &mut peer, &mut acceptor).await;
    let stream_id = stream.id();
    let payload = vec![0x5au8; INITIAL_WINDOW + 19];

    let mut write = tokio::spawn(async move {
        stream.write_all(&payload).await.unwrap();
        stream
    });
    let mut received = 0;
    while received < INITIAL_WINDOW {
        let output = feed_next(&mut peer, &mut acceptor).await;
        received += output
            .events
            .iter()
            .filter_map(|event| match event {
                MuxEvent::Data {
                    stream_id: event_id,
                    bytes,
                } if *event_id == stream_id => Some(bytes.len()),
                _ => None,
            })
            .sum::<usize>();
    }
    assert_eq!(received, INITIAL_WINDOW);
    assert!(
        timeout(Duration::from_millis(100), &mut write)
            .await
            .is_err(),
        "write must pause when the initial window is exhausted"
    );

    let output = acceptor.consume(stream_id, INITIAL_WINDOW).unwrap();
    write_frames(&mut peer, &output.frames).await;
    let _stream = timeout(TEST_TIMEOUT, &mut write)
        .await
        .expect("WINDOW grant must resume the paused write")
        .unwrap();

    while received < INITIAL_WINDOW + 19 {
        let output = feed_next(&mut peer, &mut acceptor).await;
        received += output
            .events
            .iter()
            .filter_map(|event| match event {
                MuxEvent::Data {
                    stream_id: event_id,
                    bytes,
                } if *event_id == stream_id => Some(bytes.len()),
                _ => None,
            })
            .sum::<usize>();
    }
    assert_eq!(received, INITIAL_WINDOW + 19);
}

#[tokio::test]
async fn close_and_reset_end_the_dialer_read_side() {
    let (carrier, mut peer) = tokio::io::duplex(2 * INITIAL_WINDOW);
    let dialer = FrameDialer::new(carrier);
    let mut acceptor = acceptor(MuxLimits::default());

    let mut closed = open_stream(&dialer, &mut peer, &mut acceptor).await;
    closed.shutdown().await.unwrap();
    let output = feed_next(&mut peer, &mut acceptor).await;
    assert_eq!(
        output.events,
        vec![MuxEvent::ReadClosed {
            stream_id: closed.id()
        }]
    );
    let output = acceptor.close_write(closed.id()).unwrap();
    write_frames(&mut peer, &output.frames).await;
    let mut buffer = [0u8; 1];
    assert_eq!(closed.read(&mut buffer).await.unwrap(), 0);
    assert_eq!(closed.end(), Some(StreamEnd::Closed));

    let mut reset = open_stream(&dialer, &mut peer, &mut acceptor).await;
    let output = acceptor.reset(reset.id(), ResetReason::Cancel).unwrap();
    write_frames(&mut peer, &output.frames).await;
    let error = reset.read(&mut buffer).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    assert_eq!(
        reset.end(),
        Some(StreamEnd::Reset {
            reason: RESET_CANCEL
        })
    );
}

#[tokio::test]
async fn stream_limit_reset_closes_the_rejected_stream_immediately() {
    let (carrier, mut peer) = tokio::io::duplex(2 * INITIAL_WINDOW);
    let dialer = FrameDialer::new(carrier);
    let mut acceptor = acceptor(MuxLimits {
        max_concurrent_streams: 1,
        decoder_buffer_bytes: HEADER_LEN + MAX_PAYLOAD,
    });

    let _first = open_stream(&dialer, &mut peer, &mut acceptor).await;
    let mut rejected = dialer.open_stream().await.unwrap();
    let output = feed_next(&mut peer, &mut acceptor).await;
    assert_eq!(output.frames.len(), 1);
    assert_eq!(output.frames[0].payload, vec![RESET_STREAM_LIMIT_EXCEEDED]);
    write_frames(&mut peer, &output.frames).await;

    let mut buffer = [0u8; 1];
    let error = timeout(TEST_TIMEOUT, rejected.read(&mut buffer))
        .await
        .expect("peer reset must end the rejected stream")
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    assert_eq!(
        rejected.end(),
        Some(StreamEnd::Reset {
            reason: RESET_STREAM_LIMIT_EXCEEDED,
        })
    );
}
