// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Tokio carrier driver for the pure listener mux.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::task::{Context, Poll};

use spl_core::frame::RECOMMENDED_CHUNK;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;

use crate::{HomeConfig, HomeError, MuxAcceptor, MuxEvent, MuxOutput, ResetReason};

const STREAM_LIVE: u8 = 0;
const STREAM_RESET: u8 = 1;
const STREAM_GONE: u8 = 2;

/// One accepted TLS carrier and its listener-owned streams.
pub struct HomeConnection {
    accepts: mpsc::UnboundedReceiver<HomeStream>,
    commands: mpsc::UnboundedSender<DriverCommand>,
}

/// A byte-stream handle for one peer-opened SPL logical stream.
pub struct HomeStream {
    id: u32,
    signals: mpsc::UnboundedReceiver<StreamSignal>,
    commands: mpsc::UnboundedSender<DriverCommand>,
    state: Arc<AtomicU8>,
    read_buffer: VecDeque<u8>,
    read_eof: bool,
    write_shutdown: bool,
}

enum DriverCommand {
    Write { stream_id: u32, bytes: Vec<u8> },
    Consumed { stream_id: u32, bytes: usize },
    Close { stream_id: u32 },
    Cancel { stream_id: u32 },
    Wake,
    CloseConnection,
}

enum StreamSignal {
    Data(Vec<u8>),
    ReadEof,
    Reset,
    Gone,
}

impl HomeConnection {
    /// Complete the inner TLS handshake over an arbitrary asynchronous carrier.
    ///
    /// # Errors
    ///
    /// Returns [`HomeError::Tls`] when the handshake fails, or configuration
    /// and I/O errors without retaining peer-controlled diagnostics.
    pub async fn accept<S>(io: S, config: HomeConfig) -> Result<Self, HomeError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let limits = config.mux_limits;
        let server = TlsAcceptor::from(Arc::new(config.server_config()?));
        let tls = server.accept(io).await.map_err(|_| HomeError::Tls)?;
        let acceptor = MuxAcceptor::new(limits)?;
        let (accept_tx, accept_rx) = mpsc::unbounded_channel();
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        tokio::spawn(run_driver(
            tls,
            acceptor,
            accept_tx,
            command_tx.clone(),
            command_rx,
        ));
        Ok(Self {
            accepts: accept_rx,
            commands: command_tx,
        })
    }

    /// Wait for the next peer-opened stream.
    ///
    /// # Errors
    ///
    /// Returns [`HomeError::PeerGone`] when the carrier driver has stopped.
    pub async fn accept_stream(&mut self) -> Result<HomeStream, HomeError> {
        self.accepts.recv().await.ok_or(HomeError::PeerGone)
    }

    /// Request orderly closure of the underlying carrier.
    ///
    /// # Errors
    ///
    /// Returns [`HomeError::Closed`] if the carrier driver already stopped.
    pub fn close(&self) -> Result<(), HomeError> {
        self.commands
            .send(DriverCommand::CloseConnection)
            .map_err(|_| HomeError::Closed)
    }
}

impl HomeStream {
    /// Return this logical stream's peer-owned identifier.
    pub fn id(&self) -> u32 {
        self.id
    }

    fn new(
        id: u32,
        signals: mpsc::UnboundedReceiver<StreamSignal>,
        commands: mpsc::UnboundedSender<DriverCommand>,
        state: Arc<AtomicU8>,
    ) -> Self {
        Self {
            id,
            signals,
            commands,
            state,
            read_buffer: VecDeque::new(),
            read_eof: false,
            write_shutdown: false,
        }
    }

    fn stream_error(&self) -> Option<io::Error> {
        match self.state.load(Ordering::Acquire) {
            STREAM_RESET => Some(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "stream reset",
            )),
            STREAM_GONE => Some(io::Error::new(io::ErrorKind::BrokenPipe, "carrier closed")),
            _ => None,
        }
    }

    fn read_error(&self) -> Option<io::Error> {
        match self.state.load(Ordering::Acquire) {
            STREAM_RESET => Some(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "stream reset",
            )),
            STREAM_GONE => Some(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "carrier closed",
            )),
            _ => None,
        }
    }
}

#[allow(
    clippy::match_same_arms,
    reason = "both channel closure and an explicit carrier-loss signal map to BrokenPipe"
)]
impl AsyncRead for HomeStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        read_buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.read_buffer.is_empty() {
                let count = read_buf.remaining().min(self.read_buffer.len());
                let bytes: Vec<u8> = self.read_buffer.drain(..count).collect();
                read_buf.put_slice(&bytes);
                if self
                    .commands
                    .send(DriverCommand::Consumed {
                        stream_id: self.id,
                        bytes: count,
                    })
                    .is_err()
                {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "carrier closed",
                    )));
                }
                return Poll::Ready(Ok(()));
            }
            if self.read_eof {
                return Poll::Ready(Ok(()));
            }
            if let Some(error) = self.read_error() {
                return Poll::Ready(Err(error));
            }
            match Pin::new(&mut self.signals).poll_recv(context) {
                Poll::Ready(Some(StreamSignal::Data(bytes))) => self.read_buffer.extend(bytes),
                Poll::Ready(Some(StreamSignal::ReadEof)) => self.read_eof = true,
                Poll::Ready(Some(StreamSignal::Reset)) => {
                    self.state.store(STREAM_RESET, Ordering::Release);
                }
                Poll::Ready(Some(StreamSignal::Gone)) => {
                    self.state.store(STREAM_GONE, Ordering::Release);
                }
                Poll::Ready(None) => {
                    self.state.store(STREAM_GONE, Ordering::Release);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for HomeStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Some(error) = this.stream_error() {
            return Poll::Ready(Err(error));
        }
        if this.write_shutdown {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stream writer closed",
            )));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        this.commands
            .send(DriverCommand::Write {
                stream_id: this.id,
                bytes: bytes.to_vec(),
            })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "carrier closed"))?;
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(error) = self.stream_error() {
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_shutdown {
            this.commands
                .send(DriverCommand::Close { stream_id: this.id })
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "carrier closed"))?;
            this.write_shutdown = true;
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for HomeStream {
    fn drop(&mut self) {
        if !self.write_shutdown {
            let _ = self
                .commands
                .send(DriverCommand::Cancel { stream_id: self.id });
        }
    }
}

async fn run_driver<S>(
    tls: tokio_rustls::server::TlsStream<S>,
    mut acceptor: MuxAcceptor,
    accepts: mpsc::UnboundedSender<HomeStream>,
    command_tx: mpsc::UnboundedSender<DriverCommand>,
    mut commands: mpsc::UnboundedReceiver<DriverCommand>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = tokio::io::split(tls);
    let mut streams = HashMap::new();
    let mut pending = HashMap::<u32, VecDeque<u8>>::new();
    let mut ready = VecDeque::new();
    let mut closing = HashSet::new();
    let mut buffer = [0u8; 8192];

    loop {
        tokio::select! {
            biased;
            read = reader.read(&mut buffer) => {
                let Ok(read) = read else { break; };
                if read == 0 {
                    let output = acceptor.finish_eof();
                    deliver_output(output, &mut streams, &accepts, &command_tx, &mut writer).await;
                    break;
                }
                let Ok(output) = acceptor.feed(&buffer[..read]) else { break; };
                if !deliver_output(output, &mut streams, &accepts, &command_tx, &mut writer).await {
                    break;
                }
            }
            command = commands.recv() => {
                let Some(command) = command else { break; };
                match command {
                    DriverCommand::Write { stream_id, bytes } => {
                        pending.entry(stream_id).or_default().extend(bytes);
                        if !ready.contains(&stream_id) { ready.push_back(stream_id); }
                    }
                    DriverCommand::Consumed { stream_id, bytes } => {
                        let Ok(output) = acceptor.consume(stream_id, bytes) else { break; };
                        if !deliver_output(output, &mut streams, &accepts, &command_tx, &mut writer).await { break; }
                    }
                    DriverCommand::Close { stream_id } => {
                        closing.insert(stream_id);
                        if !ready.contains(&stream_id) { ready.push_back(stream_id); }
                    }
                    DriverCommand::Cancel { stream_id } => {
                        pending.remove(&stream_id);
                        closing.remove(&stream_id);
                        if let Ok(output) = acceptor.reset(stream_id, ResetReason::Cancel)
                            && !deliver_output(output, &mut streams, &accepts, &command_tx, &mut writer).await { break; }
                    }
                    DriverCommand::Wake => {}
                    DriverCommand::CloseConnection => break,
                }
            }
        }
        if !flush_ready(
            &mut acceptor,
            &mut pending,
            &mut ready,
            &mut closing,
            &mut streams,
            &accepts,
            &command_tx,
            &mut writer,
        )
        .await
        {
            break;
        }
    }
    for (_, stream) in streams {
        stream.state.store(STREAM_GONE, Ordering::Release);
        let _ = stream.tx.send(StreamSignal::Gone);
    }
}

struct DriverStream {
    tx: mpsc::UnboundedSender<StreamSignal>,
    state: Arc<AtomicU8>,
}

#[allow(
    clippy::too_many_arguments,
    reason = "the driver state remains local to avoid a second mutable state container"
)]
async fn flush_ready<W>(
    acceptor: &mut MuxAcceptor,
    pending: &mut HashMap<u32, VecDeque<u8>>,
    ready: &mut VecDeque<u32>,
    closing: &mut HashSet<u32>,
    streams: &mut HashMap<u32, DriverStream>,
    accepts: &mpsc::UnboundedSender<HomeStream>,
    command_tx: &mpsc::UnboundedSender<DriverCommand>,
    writer: &mut W,
) -> bool
where
    W: AsyncWrite + Unpin,
{
    let rounds = ready.len();
    for _ in 0..rounds {
        let Some(stream_id) = ready.pop_front() else {
            break;
        };
        if !pending.contains_key(&stream_id) {
            if closing.remove(&stream_id) {
                let Ok(output) = acceptor.close_write(stream_id) else {
                    return false;
                };
                if !deliver_output(output, streams, accepts, command_tx, writer).await {
                    return false;
                }
            }
            continue;
        }
        let Some(queue) = pending.get_mut(&stream_id) else {
            return false;
        };
        let count = queue.len().min(RECOMMENDED_CHUNK);
        if count == 0 {
            pending.remove(&stream_id);
            if closing.remove(&stream_id) {
                let Ok(output) = acceptor.close_write(stream_id) else {
                    return false;
                };
                if !deliver_output(output, streams, accepts, command_tx, writer).await {
                    return false;
                }
            }
            continue;
        }
        let bytes: Vec<u8> = queue.drain(..count).collect();
        match acceptor.try_send_data(stream_id, bytes.clone()) {
            Ok(Some(output)) => {
                if !deliver_output(output, streams, accepts, command_tx, writer).await {
                    return false;
                }
                if queue.is_empty() {
                    pending.remove(&stream_id);
                }
                if pending.contains_key(&stream_id) {
                    ready.push_back(stream_id);
                }
                if !pending.contains_key(&stream_id) && closing.remove(&stream_id) {
                    let Ok(output) = acceptor.close_write(stream_id) else {
                        return false;
                    };
                    if !deliver_output(output, streams, accepts, command_tx, writer).await {
                        return false;
                    }
                }
            }
            Ok(None) => {
                queue.extend(bytes);
                ready.push_back(stream_id);
            }
            Err(_) => return false,
        }
    }
    if !ready.is_empty() {
        tokio::task::yield_now().await;
        if command_tx.send(DriverCommand::Wake).is_err() {
            return false;
        }
    }
    true
}

async fn deliver_output<W>(
    output: MuxOutput,
    streams: &mut HashMap<u32, DriverStream>,
    accepts: &mpsc::UnboundedSender<HomeStream>,
    command_tx: &mpsc::UnboundedSender<DriverCommand>,
    writer: &mut W,
) -> bool
where
    W: AsyncWrite + Unpin,
{
    for frame in output.frames {
        let Ok(bytes) = frame.encode() else {
            return false;
        };
        if writer.write_all(&bytes).await.is_err() {
            return false;
        }
    }
    for event in output.events {
        match event {
            MuxEvent::Opened { stream_id } => {
                let (tx, rx) = mpsc::unbounded_channel();
                let state = Arc::new(AtomicU8::new(STREAM_LIVE));
                streams.insert(
                    stream_id,
                    DriverStream {
                        tx,
                        state: state.clone(),
                    },
                );
                if accepts
                    .send(HomeStream::new(stream_id, rx, command_tx.clone(), state))
                    .is_err()
                {
                    return false;
                }
            }
            MuxEvent::Data { stream_id, bytes } => {
                if let Some(stream) = streams.get(&stream_id) {
                    let _ = stream.tx.send(StreamSignal::Data(bytes));
                }
            }
            MuxEvent::ReadClosed { stream_id } => {
                if let Some(stream) = streams.get(&stream_id) {
                    let _ = stream.tx.send(StreamSignal::ReadEof);
                }
            }
            MuxEvent::Reset { stream_id, .. } => {
                if let Some(stream) = streams.get(&stream_id) {
                    stream.state.store(STREAM_RESET, Ordering::Release);
                    let _ = stream.tx.send(StreamSignal::Reset);
                }
            }
            MuxEvent::PeerGone { .. } => {}
        }
    }
    true
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "driver tests use direct controlled fixture assertions"
    )]

    use super::*;
    use crate::MuxLimits;
    use spl_core::frame::{FLAG_DATA, Frame, FrameDecoder, RESET_CANCEL};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn acceptor_with_streams(ids: &[u32]) -> MuxAcceptor {
        let mut acceptor = MuxAcceptor::new(MuxLimits::default()).unwrap();
        for id in ids {
            acceptor
                .feed(
                    &Frame::new(*id, spl_core::frame::FLAG_OPEN, Vec::new())
                        .encode()
                        .unwrap(),
                )
                .unwrap();
        }
        acceptor
    }

    #[tokio::test]
    async fn shutdown_follows_queued_data_on_the_wire() {
        let mut acceptor = acceptor_with_streams(&[1]);
        let mut pending = HashMap::from([(1, VecDeque::from(vec![1, 2, 3]))]);
        let mut ready = VecDeque::from([1]);
        let mut closing = HashSet::from([1]);
        let mut streams = HashMap::new();
        let (accepts, _) = mpsc::unbounded_channel();
        let (commands, _) = mpsc::unbounded_channel();
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        assert!(
            flush_ready(
                &mut acceptor,
                &mut pending,
                &mut ready,
                &mut closing,
                &mut streams,
                &accepts,
                &commands,
                &mut writer,
            )
            .await
        );
        let mut wire = vec![0; 19];
        reader.read_exact(&mut wire).await.unwrap();
        let mut decoder = FrameDecoder::new();
        decoder.feed(&wire);
        let frames = decoder.drain().unwrap();
        assert_eq!(frames[0], Frame::new(1, FLAG_DATA, vec![1, 2, 3]));
        assert_eq!(
            frames[1],
            Frame::new(1, spl_core::frame::FLAG_CLOSE, Vec::new())
        );
    }

    #[tokio::test]
    async fn ready_streams_are_fifo_and_round_robin() {
        let mut acceptor = acceptor_with_streams(&[1, 3]);
        let mut pending = HashMap::from([
            (1, VecDeque::from(vec![1, 2])),
            (3, VecDeque::from(vec![3, 4])),
        ]);
        let mut ready = VecDeque::from([1, 3]);
        let mut closing = HashSet::new();
        let mut streams = HashMap::new();
        let (accepts, _) = mpsc::unbounded_channel();
        let (commands, _) = mpsc::unbounded_channel();
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        assert!(
            flush_ready(
                &mut acceptor,
                &mut pending,
                &mut ready,
                &mut closing,
                &mut streams,
                &accepts,
                &commands,
                &mut writer,
            )
            .await
        );
        let mut wire = vec![0; 20];
        reader.read_exact(&mut wire).await.unwrap();
        let mut decoder = FrameDecoder::new();
        decoder.feed(&wire);
        assert_eq!(
            decoder.drain().unwrap(),
            vec![
                Frame::new(1, FLAG_DATA, vec![1, 2]),
                Frame::new(3, FLAG_DATA, vec![3, 4]),
            ]
        );
    }

    #[tokio::test]
    async fn carrier_loss_maps_read_and_write_halves_to_distinct_io_kinds() {
        let (commands, _) = mpsc::unbounded_channel();
        let (_, signals) = mpsc::unbounded_channel();
        let state = Arc::new(AtomicU8::new(STREAM_GONE));
        let mut stream = HomeStream::new(1, signals, commands, state);
        let mut byte = [0u8; 1];
        assert_eq!(
            stream.read(&mut byte).await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(
            stream.write(&byte).await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    #[test]
    fn dropping_a_live_stream_requests_cancel_reset() {
        let (commands, mut receiver) = mpsc::unbounded_channel();
        let (_, signals) = mpsc::unbounded_channel();
        let state = Arc::new(AtomicU8::new(STREAM_LIVE));
        drop(HomeStream::new(7, signals, commands, state));
        assert!(matches!(
            receiver.try_recv(),
            Ok(DriverCommand::Cancel { stream_id: 7 })
        ));
        let mut acceptor = acceptor_with_streams(&[7]);
        let output = acceptor.reset(7, ResetReason::Cancel).unwrap();
        assert_eq!(output.frames, vec![Frame::reset(7, RESET_CANCEL)]);
    }
}
