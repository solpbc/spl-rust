// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! One PL request over a fresh framed-mTLS connection.
//!
//! Each one-shot request opens a TCP connection to the journal, completes the
//! TLS 1.3 handshake (CA-fp pinned via the supplied [`ClientConfig`]), opens one
//! dialer stream, and runs the **windowed** upload/response loop: it writes the
//! HTTP request as `OPEN|DATA…|CLOSE` frames but never sends more un-granted DATA
//! payload than the peer's advertised window ([`WindowedUpload`]), reading
//! inbound frames between bursts to pick up `WINDOW` grants (which unblock more
//! sending), answer control `PING`s with `PONG`s, and assemble the response.
//! Caller-owned request bodies remain completely buffered, but are fragmented on
//! the wire and paced beyond the 1 MiB initial window. Connection-per-request
//! keeps the mux trivially correct (no concurrent-stream bookkeeping); persistent
//! multiplexing belongs to this crate's journal bridge carrier.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use rustls::ClientConfig;
use spl_core::frame::{Frame, FrameDialer, RESET_FLOW_CONTROL_ERROR};
use spl_core::http::{self, HttpResponse};
use spl_core::mux::{MuxError, ResponseAssembler, WindowedUpload};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, client::TlsStream};

use crate::TransportError;
use crate::tls::pinned_server_name;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Upper bound on outbound writes. A stalled write means the peer is dead or no
/// longer draining; fail fast and leave retry policy to the caller.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Upper bound on a single inbound read while uploading/awaiting the response.
/// The journal returns upload credit as it consumes request DATA, and this client
/// returns response credit as it decodes DATA; a 60 s stall is therefore a dead
/// or wedged peer, not flow-control back-pressure. Fail fast and leave retry
/// policy to the caller.
#[expect(
    clippy::duration_suboptimal_units,
    reason = "the copied transport timeout remains expressed in protocol-facing seconds"
)]
const READ_TIMEOUT: Duration = Duration::from_secs(60);
const READ_BUF: usize = 64 * 1024;

/// Send one HTTP request over a fresh PL connection and return the response.
/// `headers` are the caller's extra headers (auth, content-type); framing-owned
/// headers are added by [`http::build_request_head`].
///
/// # Errors
///
/// Returns an I/O, TLS, mux, or HTTP error if any connection or request stage
/// fails.
pub async fn request_once(
    config: Arc<ClientConfig>,
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<HttpResponse, TransportError> {
    let tls = dial_tls(config, host, port).await?;
    run_request_over_stream(tls, method, path, headers, body).await
}

pub(crate) async fn dial_tls(
    config: Arc<ClientConfig>,
    host: &str,
    port: u16,
) -> Result<TlsStream<TcpStream>, TransportError> {
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port)))
        .await
        .map_err(|_| {
            TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("connect to {host}:{port} timed out"),
            ))
        })??;
    tcp.set_nodelay(true).ok();

    let connector = TlsConnector::from(config);
    connector
        .connect(pinned_server_name(), tcp)
        .await
        .map_err(|e| TransportError::Tls(format!("handshake to {host}:{port}: {e}")))
}

pub(crate) async fn run_request_over_stream<S>(
    mut stream: S,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<HttpResponse, TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut dialer = FrameDialer::default();
    let stream_id = dialer.allocate();
    let request_head = http::build_request_head(method, path, headers, body.len());
    let mut upload = WindowedUpload::new(stream_id, &request_head, body.len());
    let mut body_offset = 0;
    let mut assembler = ResponseAssembler::new(stream_id);

    let mut buf = vec![0u8; READ_BUF];
    loop {
        // Send everything the current window permits — unless the peer has
        // already responded and closed our stream (e.g. an early rejection),
        // in which case there is nothing more worth sending.
        if !assembler.is_closed() {
            let mut wrote = false;
            loop {
                let capacity = upload.body_capacity();
                if capacity > 0 && body_offset < body.len() {
                    let end = (body_offset + capacity).min(body.len());
                    upload.feed_body(&body[body_offset..end]).map_err(|error| {
                        TransportError::Io(io::Error::new(io::ErrorKind::InvalidInput, error))
                    })?;
                    body_offset = end;
                }
                let Some(frame) = upload
                    .poll_send()
                    .map_err(|e| TransportError::Mux(MuxError::Frame(e)))?
                else {
                    break;
                };
                write_all_with_timeout(
                    &mut stream,
                    &frame,
                    "PL write timed out sending request frame",
                )
                .await?;
                wrote = true;
            }
            if wrote {
                flush_with_timeout(&mut stream, "PL write timed out flushing request frames")
                    .await?;
            }
        }
        if assembler.is_closed() {
            break;
        }

        // Read inbound. WINDOW grants unblock more sending; PONGs keep the mux
        // alive; DATA/CLOSE/RESET drive the response assembler.
        let n = tokio::time::timeout(READ_TIMEOUT, stream.read(&mut buf))
            .await
            .map_err(|_| {
                TransportError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "PL read timed out awaiting response or window grant",
                ))
            })??;
        if n == 0 {
            break; // peer closed the connection
        }
        let out = assembler.feed(&buf[..n])?;
        for credit in out.window_grants {
            if upload.grant(credit).is_err() {
                let reset = Frame::reset(stream_id, RESET_FLOW_CONTROL_ERROR)
                    .encode()
                    .map_err(|error| TransportError::Mux(MuxError::Frame(error)))?;
                write_all_with_timeout(
                    &mut stream,
                    &reset,
                    "PL write timed out sending flow-control reset",
                )
                .await?;
                flush_with_timeout(
                    &mut stream,
                    "PL write timed out flushing flow-control reset",
                )
                .await?;
                return Err(TransportError::Mux(MuxError::FlowControl));
            }
        }
        let mut originated = false;
        for pong in out.pongs {
            write_all_with_timeout(&mut stream, &pong, "PL write timed out sending pong").await?;
            originated = true;
        }
        for frame in out.emit_frames {
            write_all_with_timeout(
                &mut stream,
                &frame,
                "PL write timed out sending originated frame",
            )
            .await?;
            originated = true;
        }
        if originated {
            flush_with_timeout(&mut stream, "PL write timed out flushing originated frames")
                .await?;
        }
        if let Some(error) = out.terminal_error {
            return Err(TransportError::Mux(error));
        }
    }
    // Best-effort clean close.
    let _ = stream.shutdown().await;

    Ok(assembler.into_response()?)
}

async fn write_all_with_timeout<S>(
    stream: &mut S,
    bytes: &[u8],
    message: &'static str,
) -> Result<(), TransportError>
where
    S: AsyncWrite + Unpin,
{
    tokio::time::timeout(WRITE_TIMEOUT, stream.write_all(bytes))
        .await
        .map_err(|_| TransportError::Io(io::Error::new(io::ErrorKind::TimedOut, message)))??;
    Ok(())
}

async fn flush_with_timeout<S>(stream: &mut S, message: &'static str) -> Result<(), TransportError>
where
    S: AsyncWrite + Unpin,
{
    tokio::time::timeout(WRITE_TIMEOUT, stream.flush())
        .await
        .map_err(|_| TransportError::Io(io::Error::new(io::ErrorKind::TimedOut, message)))??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use spl_core::frame::{
        FLAG_CLOSE, FLAG_DATA, FLAG_OPEN, Frame, FrameDecoder, RECOMMENDED_CHUNK,
    };
    use spl_core::mux::INITIAL_WINDOW;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{DuplexStream, ReadBuf};

    struct PendingWriteStream;

    impl AsyncRead for PendingWriteStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for PendingWriteStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    async fn next_frame(stream: &mut DuplexStream, decoder: &mut FrameDecoder) -> Frame {
        loop {
            if let Some(frame) = decoder.next_frame().unwrap() {
                return frame;
            }
            let mut buf = [0u8; 16 * 1024];
            let n = stream.read(&mut buf).await.unwrap();
            assert!(n > 0, "client closed before next frame");
            decoder.feed(&buf[..n]);
        }
    }

    async fn send_frame(stream: &mut DuplexStream, stream_id: u32, flags: u8, payload: &[u8]) {
        let frame = Frame::new(stream_id, flags, payload.to_vec())
            .encode()
            .unwrap();
        stream.write_all(&frame).await.unwrap();
        stream.flush().await.unwrap();
    }

    async fn read_request_close(stream: &mut DuplexStream, decoder: &mut FrameDecoder) -> u32 {
        loop {
            let frame = next_frame(stream, decoder).await;
            if frame.flags & FLAG_CLOSE != 0 {
                assert!(frame.stream_id != 0);
                return frame.stream_id;
            }
            assert!(frame.flags & (FLAG_OPEN | FLAG_DATA) != 0);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn pending_write_times_out_without_waiting() {
        let err = run_request_over_stream(PendingWriteStream, "POST", "/x", &[], b"body")
            .await
            .unwrap_err();

        match err {
            TransportError::Io(error) => assert_eq!(error.kind(), io::ErrorKind::TimedOut),
            other => panic!("expected timed out io error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn one_shot_response_over_initial_window_replenishes_peer_credit() {
        const BODY_BYTES: usize = 1_600_000;

        let (client, mut peer) = tokio::io::duplex(INITIAL_WINDOW * 2);
        let fake_peer = tokio::spawn(async move {
            let mut decoder = FrameDecoder::new();
            let stream_id = read_request_close(&mut peer, &mut decoder).await;

            let body = vec![b'x'; BODY_BYTES];
            let mut response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {BODY_BYTES}\r\n\r\n"
            )
            .into_bytes();
            response.extend_from_slice(&body);
            assert!(response.len() > INITIAL_WINDOW);

            let mut offset = 0usize;
            let mut send_credit = INITIAL_WINDOW;
            while offset < response.len() {
                if send_credit == 0 {
                    loop {
                        let frame = next_frame(&mut peer, &mut decoder).await;
                        if frame.stream_id == stream_id {
                            if let Some(grant) = frame.window_credit() {
                                send_credit += grant as usize;
                                break;
                            }
                        }
                    }
                }
                let count = (response.len() - offset)
                    .min(RECOMMENDED_CHUNK)
                    .min(send_credit);
                send_frame(
                    &mut peer,
                    stream_id,
                    FLAG_DATA,
                    &response[offset..offset + count],
                )
                .await;
                offset += count;
                send_credit -= count;
            }
            send_frame(&mut peer, stream_id, FLAG_CLOSE, &[]).await;
            let mut tail = [0u8; 64];
            while peer.read(&mut tail).await.unwrap() != 0 {}
        });

        let response = tokio::time::timeout(
            Duration::from_secs(1),
            run_request_over_stream(client, "GET", "/large", &[], b""),
        )
        .await
        .expect("one-shot response should complete after granting receive credit")
        .unwrap();

        assert_eq!(response.body, vec![b'x'; BODY_BYTES]);
        fake_peer.await.unwrap();
    }

    #[tokio::test]
    async fn one_shot_over_window_writes_one_flow_control_reset_before_error() {
        let (client, mut peer) = tokio::io::duplex(INITIAL_WINDOW * 2);
        let fake_peer = tokio::spawn(async move {
            let mut decoder = FrameDecoder::new();
            let stream_id = read_request_close(&mut peer, &mut decoder).await;
            let overrun = vec![b'x'; INITIAL_WINDOW + 19];
            send_frame(&mut peer, stream_id, FLAG_DATA, &overrun).await;

            let reset =
                tokio::time::timeout(Duration::from_secs(1), next_frame(&mut peer, &mut decoder))
                    .await
                    .expect("client should reset an over-window response");
            assert_eq!(reset.stream_id, stream_id);
            assert_eq!(reset.flags, spl_core::frame::FLAG_RESET);
            assert_eq!(
                reset.payload,
                vec![spl_core::frame::RESET_FLOW_CONTROL_ERROR]
            );
        });

        let error = tokio::time::timeout(
            Duration::from_secs(1),
            run_request_over_stream(client, "GET", "/over-window", &[], b""),
        )
        .await
        .expect("one-shot over-window response should fail promptly")
        .unwrap_err();
        match error {
            TransportError::Mux(error) => assert_eq!(format!("{error:?}"), "FlowControl"),
            other => panic!("expected mux flow-control error, got {other:?}"),
        }
        fake_peer.await.unwrap();
    }

    #[tokio::test]
    async fn one_shot_excess_send_credit_writes_flow_control_reset_before_error() {
        let (client, mut peer) = tokio::io::duplex(INITIAL_WINDOW * 2);
        let body = vec![b'x'; INITIAL_WINDOW + 257];
        let fake_peer = tokio::spawn(async move {
            let mut decoder = FrameDecoder::new();
            let mut stream_id = None;
            let mut data = 0usize;
            while data < INITIAL_WINDOW {
                let frame = next_frame(&mut peer, &mut decoder).await;
                if frame.flags & FLAG_DATA != 0 {
                    stream_id = Some(frame.stream_id);
                    data += frame.payload.len();
                }
            }
            assert_eq!(data, INITIAL_WINDOW);
            let stream_id = stream_id.unwrap();

            send_frame(
                &mut peer,
                stream_id,
                spl_core::frame::FLAG_WINDOW,
                &u32::MAX.to_be_bytes(),
            )
            .await;
            let reset =
                tokio::time::timeout(Duration::from_secs(1), next_frame(&mut peer, &mut decoder))
                    .await
                    .expect("client should reset excess send credit");
            assert_eq!(reset.stream_id, stream_id);
            assert_eq!(reset.flags, spl_core::frame::FLAG_RESET);
            assert_eq!(reset.payload, vec![RESET_FLOW_CONTROL_ERROR]);
        });

        let error = tokio::time::timeout(
            Duration::from_secs(1),
            run_request_over_stream(client, "POST", "/excess-credit", &[], &body),
        )
        .await
        .expect("excess send credit should fail promptly")
        .unwrap_err();
        assert!(matches!(error, TransportError::Mux(MuxError::FlowControl)));
        fake_peer.await.unwrap();
    }
}
