// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Liveness witness for one routed client connection, and the stand-in a
//! refused client is spliced to instead.
//!
//! A journal whose host has slept, lost its network, or frozen leaves its
//! carrier socket open with no FIN, so carrier EOF never arrives and the
//! registry keeps routing to it until its lease expires. [`FirstByteWitness`]
//! records whether the journal has produced any byte for a routed client so the
//! router can bound that wait instead of splicing into a black hole.
//!
//! [`UnansweredRoute`] behaves, from the client's side, like a journal stream
//! that never answers, so a label with no usable registration can be refused
//! in a way the client cannot tell apart from a sleeping journal.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Shared record of whether a routed journal stream has answered at all.
#[derive(Clone, Default)]
pub(crate) struct FirstByteFlag(Arc<AtomicBool>);

impl FirstByteFlag {
    pub(crate) fn observed(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    fn record(&self) {
        self.0.store(true, Ordering::Release);
    }
}

/// Wraps a journal stream and records its first delivered byte.
///
/// Reads and writes are otherwise passed through untouched: no payload byte is
/// copied, buffered, or inspected here.
pub(crate) struct FirstByteWitness<S> {
    inner: S,
    flag: FirstByteFlag,
}

impl<S> FirstByteWitness<S> {
    pub(crate) fn new(inner: S, flag: FirstByteFlag) -> Self {
        Self { inner, flag }
    }
}

impl<S> AsyncRead for FirstByteWitness<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(context, buffer);
        if matches!(polled, Poll::Ready(Ok(()))) && buffer.filled().len() > before {
            self.flag.record();
        }
        polled
    }
}

impl<S> AsyncWrite for FirstByteWitness<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, bytes)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

/// A journal stream that accepts a bounded number of bytes and never answers.
///
/// This mirrors what a routed client's splice meets when the journal host is
/// asleep: writes are accepted until the stream's initial send credit is spent,
/// after which they wait for a window grant that never comes; reads never
/// complete; flush and shutdown complete. Splicing a refused client to this
/// under the routed deadline makes the bridge read, stall, and close that
/// client exactly as it does a client of a sleeping journal. Accepted bytes are
/// discarded without being inspected or retained.
pub(crate) struct UnansweredRoute {
    remaining_credit: usize,
}

impl UnansweredRoute {
    /// Accept up to `send_credit` bytes before stalling every further write.
    pub(crate) fn new(send_credit: usize) -> Self {
        Self {
            remaining_credit: send_credit,
        }
    }
}

impl AsyncRead for UnansweredRoute {
    fn poll_read(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        _buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // The caller's deadline is the only thing that ends this wait.
        Poll::Pending
    }
}

impl AsyncWrite for UnansweredRoute {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // Like a journal stream's send credit: a write that does not fit in
        // what remains waits whole rather than being split.
        if bytes.len() > self.remaining_credit {
            return Poll::Pending;
        }
        self.remaining_credit -= bytes.len();
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "tests drive an in-memory duplex pair with known contents"
    )]

    use super::{FirstByteFlag, FirstByteWitness};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn a_silent_stream_never_records_a_first_byte() {
        let (peer, journal) = tokio::io::duplex(64);
        let flag = FirstByteFlag::default();
        let mut witness = FirstByteWitness::new(journal, flag.clone());
        let mut byte = [0_u8; 1];
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(50),
                witness.read(&mut byte),
            )
            .await
            .is_err()
        );
        assert!(!flag.observed());
        drop(peer);
    }

    #[tokio::test]
    async fn one_delivered_byte_records_the_witness() {
        let (mut peer, journal) = tokio::io::duplex(64);
        let flag = FirstByteFlag::default();
        let mut witness = FirstByteWitness::new(journal, flag.clone());
        peer.write_all(b"x").await.unwrap();
        let mut byte = [0_u8; 1];
        assert_eq!(witness.read(&mut byte).await.unwrap(), 1);
        assert!(flag.observed());
    }

    #[tokio::test]
    async fn an_eof_without_bytes_does_not_record_the_witness() {
        let (peer, journal) = tokio::io::duplex(64);
        let flag = FirstByteFlag::default();
        let mut witness = FirstByteWitness::new(journal, flag.clone());
        drop(peer);
        let mut byte = [0_u8; 1];
        assert_eq!(witness.read(&mut byte).await.unwrap(), 0);
        assert!(!flag.observed());
    }

    #[tokio::test]
    async fn writes_pass_through_untouched() {
        let (mut peer, journal) = tokio::io::duplex(64);
        let flag = FirstByteFlag::default();
        let mut witness = FirstByteWitness::new(journal, flag.clone());
        witness.write_all(b"proxy").await.unwrap();
        witness.flush().await.unwrap();
        let mut received = [0_u8; 5];
        peer.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"proxy");
        assert!(!flag.observed());
    }
}
