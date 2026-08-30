// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Flow-controlled dialer streams over one SPL framing carrier.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use spl_core::frame::{
    FLAG_CLOSE, FLAG_DATA, FLAG_OPEN, FLAG_RESET, FLAG_WINDOW, Frame, FrameDecoder,
    FrameDialer as CoreFrameDialer, FrameError, RECOMMENDED_CHUNK, RESET_CANCEL,
    RESET_FLOW_CONTROL_ERROR, RESET_PROTOCOL_ERROR, flags_valid,
};
use spl_core::mux::{INITIAL_WINDOW, MuxError, RecvWindow};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
#[cfg(test)]
use tokio::sync::Notify;
use tokio::sync::{mpsc, oneshot, watch};

const MAX_SEND_CREDIT: usize = i32::MAX as usize;

/// A spawned SPL dialer connection that opens flow-controlled logical streams.
///
/// Construct it with [`FrameDialer::new`]. The connection owns the supplied
/// carrier in background tasks; clones may open additional streams concurrently.
#[derive(Clone)]
pub struct FrameDialer {
    commands: mpsc::UnboundedSender<Command>,
    connection: watch::Receiver<ConnectionState>,
    retired: Arc<AtomicBool>,
}

/// Whether the underlying carrier is still usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// The reader, writer, and coordinator are still running.
    Live,
    /// The peer reached EOF, carrier I/O failed, or the coordinator stopped.
    Gone,
}

/// The terminal read-side state of one dialer stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamEnd {
    /// The peer half-closed its writer normally.
    Closed,
    /// The peer or local flow-control handling reset the stream.
    Reset {
        /// The one-byte SPL reset reason.
        reason: u8,
    },
    /// The carrier ended before the peer closed this stream.
    ConnectionGone,
}

/// Errors returned by the dialer connection and its streams.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DialerError {
    /// The carrier coordinator is no longer running.
    #[error("dialer connection is closed")]
    ConnectionClosed,
    /// The dialer connection was retired before this open could queue its frame.
    #[error("dialer connection was retired")]
    Retired,
    /// The requested logical stream is no longer live.
    #[error("dialer stream is closed")]
    StreamClosed,
    /// The odd stream-id allocator reached a live identifier after wrapping.
    #[error("dialer stream identifiers are exhausted")]
    StreamIdExhausted,
    /// A peer WINDOW grant would exceed the protocol send-credit cap.
    #[error("peer WINDOW grant exceeds the send-credit cap")]
    SendCreditExceeded,
    /// A local receive-consumption report exceeded bytes previously delivered.
    #[error("stream receive consumption exceeded delivered bytes")]
    ReceiveConsumptionExceeded,
    /// Framing failed while encoding or decoding the carrier.
    #[error("frame error: {0}")]
    Frame(#[from] FrameError),
}

/// One logical bidirectional byte stream opened by a [`FrameDialer`].
///
/// `AsyncWrite` waits for the peer's WINDOW credit rather than treating normal
/// flow control as an error. `AsyncRead` returns EOF after peer CLOSE and a
/// connection-reset I/O error after peer RESET; inspect [`DialerStream::end`]
/// to obtain the terminal classification.
pub struct DialerStream {
    stream_id: u32,
    commands: mpsc::UnboundedSender<Command>,
    inbound: mpsc::UnboundedReceiver<InboundEvent>,
    read_buffer: VecDeque<u8>,
    end: Option<StreamEnd>,
    credit: watch::Receiver<bool>,
    credit_wait: Option<CreditWait>,
    pending_write: Option<PendingWrite>,
    pending_flush: Option<PendingFlush>,
    pending_shutdown: Option<PendingShutdown>,
    write_closed: bool,
    reset_on_drop: bool,
}

type CreditWait = Pin<Box<dyn Future<Output = bool> + Send>>;
type PendingWrite = Pin<Box<dyn Future<Output = Result<usize, DialerError>> + Send>>;
type PendingFlush = Pin<Box<dyn Future<Output = Result<(), DialerError>> + Send>>;
type PendingShutdown = Pin<Box<dyn Future<Output = Result<(), DialerError>> + Send>>;

struct ConnectionControl {
    state: watch::Sender<ConnectionState>,
    stop: watch::Sender<bool>,
    retired: Arc<AtomicBool>,
}

#[cfg(test)]
#[derive(Clone)]
pub(crate) struct OpenPause {
    reached: Arc<Notify>,
    release: Arc<Notify>,
}

#[cfg(test)]
impl OpenPause {
    pub(crate) fn new() -> Self {
        Self {
            reached: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
        }
    }

    pub(crate) async fn wait_until_open_is_paused(&self) {
        self.reached.notified().await;
    }

    pub(crate) fn release(&self) {
        self.release.notify_one();
    }

    async fn wait(&self) {
        self.reached.notify_one();
        self.release.notified().await;
    }
}

impl FrameDialer {
    /// Spawn a dialer connection over `carrier`.
    pub fn new<T>(carrier: T) -> Self
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::new_inner(
            carrier,
            #[cfg(test)]
            None,
        )
    }

    #[cfg(test)]
    pub(crate) fn new_with_open_pause<T>(carrier: T, pause: OpenPause) -> Self
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::new_inner(carrier, Some(pause))
    }

    fn new_inner<T>(carrier: T, #[cfg(test)] open_pause: Option<OpenPause>) -> Self
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (reader, writer) = tokio::io::split(carrier);
        let (commands, command_rx) = mpsc::unbounded_channel();
        let (reader_tx, reader_rx) = mpsc::unbounded_channel();
        let (writer_tx, writer_rx) = mpsc::unbounded_channel();
        let (open_tx, open_rx) = mpsc::unbounded_channel();
        let (state_tx, state_rx) = watch::channel(ConnectionState::Live);
        let (stop_tx, stop_rx) = watch::channel(false);
        let retired = Arc::new(AtomicBool::new(false));

        tokio::spawn(read_carrier(reader, reader_tx, stop_rx));
        tokio::spawn(write_carrier(writer, writer_rx, state_tx.clone()));
        let control = ConnectionControl {
            state: state_tx,
            stop: stop_tx,
            retired: Arc::clone(&retired),
        };
        tokio::spawn(run_connection(
            command_rx,
            open_rx,
            open_tx,
            reader_rx,
            writer_tx,
            control,
            #[cfg(test)]
            open_pause,
        ));

        Self {
            commands,
            connection: state_rx,
            retired,
        }
    }

    /// Allocate a new odd stream identifier, emit its OPEN frame, and return
    /// the corresponding byte-stream handle.
    ///
    /// # Errors
    ///
    /// Returns an error when the carrier is closed or stream-id allocation
    /// reaches a still-live identifier after wrapping.
    pub async fn open_stream(&self) -> Result<DialerStream, DialerError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(Command::Open { reply: reply_tx })
            .map_err(|_| DialerError::ConnectionClosed)?;
        let opened = reply_rx
            .await
            .map_err(|_| DialerError::ConnectionClosed)??;
        Ok(DialerStream {
            stream_id: opened.stream_id,
            commands: self.commands.clone(),
            inbound: opened.inbound,
            read_buffer: VecDeque::new(),
            end: None,
            credit: opened.credit,
            credit_wait: None,
            pending_write: None,
            pending_flush: None,
            pending_shutdown: None,
            write_closed: false,
            reset_on_drop: true,
        })
    }

    /// Return the current carrier state without waiting.
    pub fn connection_state(&self) -> ConnectionState {
        *self.connection.borrow()
    }

    /// Wait until the carrier has stopped, returning its final state.
    pub async fn wait_until_gone(&mut self) -> ConnectionState {
        while *self.connection.borrow_and_update() == ConnectionState::Live {
            if self.connection.changed().await.is_err() {
                break;
            }
        }
        *self.connection.borrow()
    }

    /// Stop the carrier coordinator and end every live logical stream.
    ///
    /// This is used when a newer journal registration replaces this connection.
    /// It waits until the coordinator has published [`ConnectionState::Gone`].
    pub async fn shutdown(&self) {
        let _ = self.commands.send(Command::Shutdown);
        let mut connection = self.connection.clone();
        while *connection.borrow_and_update() == ConnectionState::Live {
            if connection.changed().await.is_err() {
                break;
            }
        }
    }

    /// Send the shutdown command without waiting for the coordinator to stop.
    ///
    /// Used by registry cancellation-safety cleanup, which cannot `.await` inside `Drop`.
    pub(crate) fn signal_shutdown(&self) {
        let _ = self.commands.send(Command::Shutdown);
    }

    /// Mark this connection retired so a subsequent open is rejected before it queues a frame.
    pub(crate) fn retire(&self) {
        self.retired.store(true, Ordering::Release);
    }

    /// Return whether this connection has been retired.
    pub(crate) fn is_retired(&self) -> bool {
        self.retired.load(Ordering::Acquire)
    }
}

impl DialerStream {
    /// Return this stream's odd, dialer-owned SPL identifier.
    pub fn id(&self) -> u32 {
        self.stream_id
    }

    /// Return the terminal read-side condition once the stream has ended.
    pub fn end(&self) -> Option<StreamEnd> {
        self.end
    }
}

impl AsyncRead for DialerStream {
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
                let _ = self.commands.send(Command::Consumed {
                    stream_id: self.stream_id,
                    bytes: count,
                });
                return Poll::Ready(Ok(()));
            }

            if let Some(end) = self.end {
                return match end {
                    StreamEnd::Closed => Poll::Ready(Ok(())),
                    StreamEnd::Reset { .. } => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "dialer stream reset",
                    ))),
                    StreamEnd::ConnectionGone => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "dialer connection closed",
                    ))),
                };
            }

            match Pin::new(&mut self.inbound).poll_recv(context) {
                Poll::Ready(Some(InboundEvent::Data(bytes))) => {
                    self.read_buffer.extend(bytes);
                }
                Poll::Ready(Some(InboundEvent::End(end))) => {
                    self.end = Some(end);
                }
                Poll::Ready(None) => {
                    self.end = Some(StreamEnd::ConnectionGone);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for DialerStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "dialer stream write side is closed",
            )));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }

        loop {
            if let Some(pending) = self.pending_write.as_mut() {
                match pending.as_mut().poll(context) {
                    Poll::Ready(result) => {
                        self.pending_write = None;
                        return Poll::Ready(result.map_err(dialer_io_error));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }

            if !*self.credit.borrow_and_update() {
                if self.credit_wait.is_none() {
                    self.credit_wait = Some(wait_for_credit(self.credit.clone()));
                }
                let Some(wait) = self.credit_wait.as_mut() else {
                    return Poll::Pending;
                };
                match wait.as_mut().poll(context) {
                    Poll::Ready(true) => self.credit_wait = None,
                    Poll::Ready(false) => {
                        self.credit_wait = None;
                        return Poll::Ready(Err(dialer_io_error(DialerError::ConnectionClosed)));
                    }
                    Poll::Pending => return Poll::Pending,
                }
                continue;
            }

            let count = bytes.len().min(RECOMMENDED_CHUNK);
            let (reply_tx, reply_rx) = oneshot::channel();
            if self
                .commands
                .send(Command::Write {
                    stream_id: self.stream_id,
                    bytes: bytes[..count].to_vec(),
                    reply: reply_tx,
                })
                .is_err()
            {
                return Poll::Ready(Err(dialer_io_error(DialerError::ConnectionClosed)));
            }
            self.pending_write = Some(Box::pin(async move {
                reply_rx.await.map_err(|_| DialerError::ConnectionClosed)?
            }));
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(pending) = self.pending_flush.as_mut() {
            return match pending.as_mut().poll(context) {
                Poll::Ready(result) => {
                    self.pending_flush = None;
                    Poll::Ready(result.map_err(dialer_io_error))
                }
                Poll::Pending => Poll::Pending,
            };
        }

        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .commands
            .send(Command::Flush { reply: reply_tx })
            .is_err()
        {
            return Poll::Ready(Err(dialer_io_error(DialerError::ConnectionClosed)));
        }
        self.pending_flush = Some(Box::pin(async move {
            if reply_rx.await.unwrap_or(false) {
                Ok(())
            } else {
                Err(DialerError::ConnectionClosed)
            }
        }));
        self.poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_closed {
            return Poll::Ready(Ok(()));
        }
        if let Some(pending) = self.pending_shutdown.as_mut() {
            return match pending.as_mut().poll(context) {
                Poll::Ready(result) => {
                    self.pending_shutdown = None;
                    if result.is_ok() {
                        self.write_closed = true;
                        self.reset_on_drop = false;
                    }
                    Poll::Ready(result.map_err(dialer_io_error))
                }
                Poll::Pending => Poll::Pending,
            };
        }

        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .commands
            .send(Command::Close {
                stream_id: self.stream_id,
                reply: reply_tx,
            })
            .is_err()
        {
            return Poll::Ready(Err(dialer_io_error(DialerError::ConnectionClosed)));
        }
        self.pending_shutdown = Some(Box::pin(async move {
            if reply_rx.await.unwrap_or(false) {
                Ok(())
            } else {
                Err(DialerError::ConnectionClosed)
            }
        }));
        self.poll_shutdown(context)
    }
}

impl Drop for DialerStream {
    fn drop(&mut self) {
        if self.reset_on_drop {
            let _ = self.commands.send(Command::Reset {
                stream_id: self.stream_id,
                reason: RESET_CANCEL,
            });
        }
    }
}

fn dialer_io_error(error: DialerError) -> io::Error {
    let kind = match error {
        DialerError::StreamClosed | DialerError::ConnectionClosed => io::ErrorKind::BrokenPipe,
        _ => io::ErrorKind::InvalidData,
    };
    io::Error::new(kind, error)
}

fn wait_for_credit(mut receiver: watch::Receiver<bool>) -> CreditWait {
    Box::pin(async move {
        loop {
            if *receiver.borrow_and_update() {
                return true;
            }
            if receiver.changed().await.is_err() {
                return false;
            }
        }
    })
}

async fn wait_for_connection_gone(connection: &mut watch::Receiver<ConnectionState>) {
    while *connection.borrow_and_update() == ConnectionState::Live {
        if connection.changed().await.is_err() {
            break;
        }
    }
}

enum Command {
    Open {
        reply: oneshot::Sender<Result<OpenedStream, DialerError>>,
    },
    Write {
        stream_id: u32,
        bytes: Vec<u8>,
        reply: oneshot::Sender<Result<usize, DialerError>>,
    },
    Consumed {
        stream_id: u32,
        bytes: usize,
    },
    Close {
        stream_id: u32,
        reply: oneshot::Sender<bool>,
    },
    Reset {
        stream_id: u32,
        reason: u8,
    },
    Flush {
        reply: oneshot::Sender<bool>,
    },
    Shutdown,
}

enum ReaderEvent {
    Bytes(Vec<u8>),
    Gone,
}

enum WriterCommand {
    Frame(Vec<u8>),
    Flush(oneshot::Sender<bool>),
}

enum InboundEvent {
    Data(Vec<u8>),
    End(StreamEnd),
}

struct OpenedStream {
    stream_id: u32,
    inbound: mpsc::UnboundedReceiver<InboundEvent>,
    credit: watch::Receiver<bool>,
}

struct OpenFlush {
    opened: OpenedStream,
    reply: oneshot::Sender<Result<OpenedStream, DialerError>>,
    flushed: bool,
}

struct PendingWriteCommand {
    bytes: Vec<u8>,
    reply: oneshot::Sender<Result<usize, DialerError>>,
}

struct StreamSendState {
    send_credit: usize,
    credit: watch::Sender<bool>,
}

impl StreamSendState {
    fn new() -> (Self, watch::Receiver<bool>) {
        let (credit, receiver) = watch::channel(true);
        (
            Self {
                send_credit: INITIAL_WINDOW,
                credit,
            },
            receiver,
        )
    }

    fn debit(&mut self, bytes: usize) -> Result<(), DialerError> {
        if bytes > self.send_credit {
            return Err(DialerError::SendCreditExceeded);
        }
        self.send_credit -= bytes;
        self.credit.send_replace(self.send_credit != 0);
        Ok(())
    }

    fn grant(&mut self, credit: u32) -> Result<(), DialerError> {
        let next = self
            .send_credit
            .checked_add(credit as usize)
            .filter(|next| *next <= MAX_SEND_CREDIT)
            .ok_or(DialerError::SendCreditExceeded)?;
        self.send_credit = next;
        self.credit.send_replace(true);
        Ok(())
    }
}

struct StreamState {
    send: StreamSendState,
    receive: RecvWindow,
    received_unconsumed: usize,
    inbound: mpsc::UnboundedSender<InboundEvent>,
    pending_writes: VecDeque<PendingWriteCommand>,
    peer_closed: bool,
    local_closed: bool,
}

impl StreamState {
    fn new(inbound: mpsc::UnboundedSender<InboundEvent>) -> (Self, watch::Receiver<bool>) {
        let (send, credit) = StreamSendState::new();
        (
            Self {
                send,
                receive: RecvWindow::new(),
                received_unconsumed: 0,
                inbound,
                pending_writes: VecDeque::new(),
                peer_closed: false,
                local_closed: false,
            },
            credit,
        )
    }

    fn debit_received(&mut self, bytes: usize) -> Result<(), MuxError> {
        self.receive.debit(bytes)?;
        self.received_unconsumed = self
            .received_unconsumed
            .checked_add(bytes)
            .ok_or(MuxError::FlowControl)?;
        Ok(())
    }

    fn consume_received(&mut self, bytes: usize) -> Result<Option<u32>, DialerError> {
        if bytes > self.received_unconsumed {
            return Err(DialerError::ReceiveConsumptionExceeded);
        }
        self.received_unconsumed -= bytes;
        Ok(self.receive.consume(bytes as u64))
    }
}

struct Driver {
    ids: CoreFrameDialer,
    decoder: FrameDecoder,
    streams: HashMap<u32, StreamState>,
    writer: mpsc::UnboundedSender<WriterCommand>,
    retired: Arc<AtomicBool>,
}

impl Driver {
    fn new(writer: mpsc::UnboundedSender<WriterCommand>, retired: Arc<AtomicBool>) -> Self {
        Self {
            ids: CoreFrameDialer::default(),
            decoder: FrameDecoder::new(),
            streams: HashMap::new(),
            writer,
            retired,
        }
    }

    fn queue_frame(&self, frame: &Frame) -> Result<(), DialerError> {
        let encoded = frame.encode()?;
        self.writer
            .send(WriterCommand::Frame(encoded))
            .map_err(|_| DialerError::ConnectionClosed)
    }

    fn open(&mut self) -> Result<OpenedStream, DialerError> {
        if self.retired.load(Ordering::Acquire) {
            return Err(DialerError::Retired);
        }
        let stream_id = self.ids.allocate();
        if stream_id == 0 || self.streams.contains_key(&stream_id) {
            return Err(DialerError::StreamIdExhausted);
        }
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let (state, credit) = StreamState::new(inbound_tx);
        self.queue_frame(&Frame::new(stream_id, FLAG_OPEN, Vec::new()))?;
        self.streams.insert(stream_id, state);
        Ok(OpenedStream {
            stream_id,
            inbound: inbound_rx,
            credit,
        })
    }

    fn write(
        &mut self,
        stream_id: u32,
        bytes: Vec<u8>,
        reply: oneshot::Sender<Result<usize, DialerError>>,
    ) -> bool {
        let frame = {
            let Some(stream) = self.streams.get_mut(&stream_id) else {
                let _ = reply.send(Err(DialerError::StreamClosed));
                return true;
            };
            if stream.local_closed {
                let _ = reply.send(Err(DialerError::StreamClosed));
                return true;
            }
            if stream.send.debit(bytes.len()).is_err() {
                stream
                    .pending_writes
                    .push_back(PendingWriteCommand { bytes, reply });
                return true;
            }
            Frame::new(stream_id, FLAG_DATA, bytes)
        };
        let length = frame.payload.len();
        if let Ok(()) = self.queue_frame(&frame) {
            let _ = reply.send(Ok(length));
            true
        } else {
            let _ = reply.send(Err(DialerError::ConnectionClosed));
            false
        }
    }

    fn drain_pending_writes(&mut self, stream_id: u32) -> bool {
        loop {
            let next = {
                let Some(stream) = self.streams.get_mut(&stream_id) else {
                    return true;
                };
                let Some(pending) = stream.pending_writes.front() else {
                    return true;
                };
                if stream.send.debit(pending.bytes.len()).is_err() {
                    return true;
                }
                stream.pending_writes.pop_front()
            };
            let Some(pending) = next else {
                return true;
            };
            let length = pending.bytes.len();
            if let Ok(()) = self.queue_frame(&Frame::new(stream_id, FLAG_DATA, pending.bytes)) {
                let _ = pending.reply.send(Ok(length));
            } else {
                let _ = pending.reply.send(Err(DialerError::ConnectionClosed));
                return false;
            }
        }
    }

    fn consume(&mut self, stream_id: u32, bytes: usize) -> bool {
        let grant = match self.streams.get_mut(&stream_id) {
            Some(stream) => match stream.consume_received(bytes) {
                Ok(grant) => grant,
                Err(_) => return self.reset_stream(stream_id, RESET_PROTOCOL_ERROR),
            },
            None => return true,
        };
        match grant {
            Some(grant) => self.queue_frame(&Frame::window(stream_id, grant)).is_ok(),
            None => true,
        }
    }

    fn close(&mut self, stream_id: u32) -> bool {
        let remove = match self.streams.get_mut(&stream_id) {
            Some(stream) if !stream.local_closed => {
                stream.local_closed = true;
                stream.peer_closed
            }
            _ => return true,
        };
        if self
            .queue_frame(&Frame::new(stream_id, FLAG_CLOSE, Vec::new()))
            .is_err()
        {
            return false;
        }
        if remove {
            self.streams.remove(&stream_id);
        }
        true
    }

    fn reset_stream(&mut self, stream_id: u32, reason: u8) -> bool {
        let Some(stream) = self.streams.remove(&stream_id) else {
            return true;
        };
        let _ = stream
            .inbound
            .send(InboundEvent::End(StreamEnd::Reset { reason }));
        self.queue_frame(&Frame::reset(stream_id, reason)).is_ok()
    }

    fn receive(&mut self, frame: Frame) -> bool {
        if frame.stream_id == 0 {
            return match frame.control_pong() {
                Some(pong) => self.queue_frame(&pong).is_ok(),
                None => true,
            };
        }
        if !flags_valid(frame.flags) || frame.flags & FLAG_OPEN != 0 {
            return self.reset_stream(frame.stream_id, RESET_PROTOCOL_ERROR);
        }
        if frame.flags == FLAG_WINDOW {
            let Some(credit) = frame.window_credit() else {
                return self.reset_stream(frame.stream_id, RESET_PROTOCOL_ERROR);
            };
            let grant_ok = self
                .streams
                .get_mut(&frame.stream_id)
                .is_none_or(|stream| stream.send.grant(credit).is_ok());
            return if grant_ok {
                self.drain_pending_writes(frame.stream_id)
            } else {
                self.reset_stream(frame.stream_id, RESET_FLOW_CONTROL_ERROR)
            };
        }
        if frame.flags & FLAG_RESET != 0 {
            let reason = frame.payload.first().copied().unwrap_or(0xff);
            if let Some(stream) = self.streams.remove(&frame.stream_id) {
                let _ = stream
                    .inbound
                    .send(InboundEvent::End(StreamEnd::Reset { reason }));
            }
            return true;
        }
        if frame.flags & FLAG_DATA != 0 {
            let delivery = {
                let Some(stream) = self.streams.get_mut(&frame.stream_id) else {
                    return self.reset_stream(frame.stream_id, RESET_PROTOCOL_ERROR);
                };
                if stream.peer_closed || stream.debit_received(frame.payload.len()).is_err() {
                    return self.reset_stream(frame.stream_id, RESET_FLOW_CONTROL_ERROR);
                }
                stream
                    .inbound
                    .send(InboundEvent::Data(frame.payload))
                    .is_ok()
            };
            if !delivery {
                return self.reset_stream(frame.stream_id, RESET_CANCEL);
            }
        }
        if frame.flags & FLAG_CLOSE != 0 {
            let remove = match self.streams.get_mut(&frame.stream_id) {
                Some(stream) => {
                    stream.peer_closed = true;
                    let _ = stream.inbound.send(InboundEvent::End(StreamEnd::Closed));
                    stream.local_closed
                }
                None => return self.reset_stream(frame.stream_id, RESET_PROTOCOL_ERROR),
            };
            if remove {
                self.streams.remove(&frame.stream_id);
            }
        }
        true
    }

    fn read_bytes(&mut self, bytes: &[u8]) -> bool {
        self.decoder.feed(bytes);
        loop {
            match self.decoder.next_frame() {
                Ok(Some(frame)) => {
                    if !self.receive(frame) {
                        return false;
                    }
                }
                Ok(None) => return true,
                Err(_) => return false,
            }
        }
    }

    fn finish(&mut self) {
        for (_, stream) in self.streams.drain() {
            let _ = stream
                .inbound
                .send(InboundEvent::End(StreamEnd::ConnectionGone));
        }
    }
}

async fn read_carrier<R>(
    mut reader: R,
    events: mpsc::UnboundedSender<ReaderEvent>,
    mut stop: watch::Receiver<bool>,
) where
    R: AsyncRead + Unpin,
{
    let mut buffer = vec![0u8; RECOMMENDED_CHUNK];
    loop {
        let result = tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow_and_update() {
                    break;
                }
                continue;
            }
            result = reader.read(&mut buffer) => result,
        };
        match result {
            Ok(0) | Err(_) => {
                let _ = events.send(ReaderEvent::Gone);
                break;
            }
            Ok(read) => {
                if events
                    .send(ReaderEvent::Bytes(buffer[..read].to_vec()))
                    .is_err()
                {
                    break;
                }
            }
        }
    }
}

async fn write_carrier<W>(
    mut writer: W,
    mut commands: mpsc::UnboundedReceiver<WriterCommand>,
    state: watch::Sender<ConnectionState>,
) where
    W: AsyncWrite + Unpin,
{
    while let Some(command) = commands.recv().await {
        let success = match command {
            WriterCommand::Frame(bytes) => writer.write_all(&bytes).await.is_ok(),
            WriterCommand::Flush(reply) => {
                let success = writer.flush().await.is_ok();
                let _ = reply.send(success);
                success
            }
        };
        if !success {
            state.send_replace(ConnectionState::Gone);
            break;
        }
    }
}

async fn run_connection(
    mut commands: mpsc::UnboundedReceiver<Command>,
    mut open_events: mpsc::UnboundedReceiver<OpenFlush>,
    open_tx: mpsc::UnboundedSender<OpenFlush>,
    mut reader_events: mpsc::UnboundedReceiver<ReaderEvent>,
    writer: mpsc::UnboundedSender<WriterCommand>,
    control: ConnectionControl,
    #[cfg(test)] open_pause: Option<OpenPause>,
) {
    let mut driver = Driver::new(writer.clone(), Arc::clone(&control.retired));
    let mut connection = control.state.subscribe();
    let mut running = true;
    while running {
        tokio::select! {
            command = commands.recv() => match command {
                Some(Command::Open { reply }) => {
                    #[cfg(test)]
                    if let Some(open_pause) = &open_pause {
                        open_pause.wait().await;
                    }
                    match driver.open() {
                        Ok(opened) => {
                            let (flush_tx, flush_rx) = oneshot::channel();
                            if writer.send(WriterCommand::Flush(flush_tx)).is_err() {
                                running = false;
                                let _ = reply.send(Err(DialerError::ConnectionClosed));
                            } else {
                                let mut connection = control.state.subscribe();
                                let open_tx = open_tx.clone();
                                tokio::spawn(async move {
                                    let flushed = tokio::select! {
                                        result = flush_rx => result.unwrap_or(false),
                                        () = wait_for_connection_gone(&mut connection) => false,
                                    };
                                    let _ = open_tx.send(OpenFlush {
                                        opened,
                                        reply,
                                        flushed,
                                    });
                                });
                            }
                        }
                        Err(error) => {
                            running = error != DialerError::ConnectionClosed;
                            let _ = reply.send(Err(error));
                        }
                    }
                }
                Some(Command::Write { stream_id, bytes, reply }) => {
                    running = driver.write(stream_id, bytes, reply);
                }
                Some(Command::Consumed { stream_id, bytes }) => {
                    running = driver.consume(stream_id, bytes);
                }
                Some(Command::Close { stream_id, reply }) => {
                    let keep_running = driver.close(stream_id);
                    if keep_running {
                        let (flush_tx, flush_rx) = oneshot::channel();
                        if writer.send(WriterCommand::Flush(flush_tx)).is_err() {
                            running = false;
                            let _ = reply.send(false);
                        } else {
                            tokio::spawn(async move {
                                let _ = reply.send(flush_rx.await.unwrap_or(false));
                            });
                        }
                    } else {
                        let _ = reply.send(false);
                    }
                }
                Some(Command::Reset { stream_id, reason }) => {
                    running = driver.reset_stream(stream_id, reason);
                }
                Some(Command::Flush { reply }) => {
                    if writer.send(WriterCommand::Flush(reply)).is_err() {
                        running = false;
                    }
                }
                Some(Command::Shutdown) | None => running = false,
            },
            event = reader_events.recv() => match event {
                Some(ReaderEvent::Bytes(bytes)) => running = driver.read_bytes(&bytes),
                Some(ReaderEvent::Gone) | None => running = false,
            },
            completion = open_events.recv() => if let Some(OpenFlush { opened, reply, flushed }) = completion {
                let stream_id = opened.stream_id;
                if flushed {
                    if reply.send(Ok(opened)).is_err() {
                        running = driver.reset_stream(stream_id, RESET_CANCEL);
                    }
                } else {
                    let _ = reply.send(Err(DialerError::ConnectionClosed));
                    running = driver.reset_stream(stream_id, RESET_CANCEL);
                }
            },
            changed = connection.changed() => {
                if changed.is_err() || *connection.borrow_and_update() == ConnectionState::Gone {
                    running = false;
                }
            },
        }
    }
    control.stop.send_replace(true);
    driver.finish();
    control.state.send_replace(ConnectionState::Gone);
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "unit tests assert controlled flow-control values"
    )]

    use super::*;
    use std::time::Duration;

    #[test]
    fn debit_rejects_an_overrun_without_mutation() {
        let (mut send, _) = StreamSendState::new();
        assert_eq!(send.send_credit, INITIAL_WINDOW);
        assert_eq!(
            send.debit(INITIAL_WINDOW + 1),
            Err(DialerError::SendCreditExceeded)
        );
        assert_eq!(send.send_credit, INITIAL_WINDOW);
    }

    #[test]
    fn grant_rejects_credit_above_the_protocol_cap_without_mutation() {
        let (mut send, _) = StreamSendState::new();
        assert_eq!(send.grant(u32::MAX), Err(DialerError::SendCreditExceeded));
        assert_eq!(send.send_credit, INITIAL_WINDOW);
    }

    #[test]
    fn consumed_receive_bytes_emit_a_window_at_the_half_window_threshold() {
        let (inbound, _) = mpsc::unbounded_channel();
        let (mut stream, _) = StreamState::new(inbound);
        let consumed = INITIAL_WINDOW / 2;
        stream.debit_received(consumed).unwrap();
        assert_eq!(
            stream.consume_received(consumed).unwrap(),
            Some(consumed as u32)
        );
    }

    #[tokio::test]
    async fn open_waits_for_a_carrier_flush_when_the_peer_stops_reading() {
        let (carrier, _peer) = tokio::io::duplex(16);
        let dialer = FrameDialer::new(carrier);

        let first = dialer.open_stream().await.unwrap();
        let second = dialer.open_stream().await.unwrap();
        let third = dialer.open_stream();
        tokio::pin!(third);

        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut third)
                .await
                .is_err()
        );

        drop(first);
        drop(second);
    }

    #[tokio::test]
    async fn acceptance_criterion_8_retired_open_emits_zero_bytes() {
        let (carrier, mut peer) = tokio::io::duplex(1024);
        let pause = OpenPause::new();
        let dialer = FrameDialer::new_with_open_pause(carrier, pause.clone());
        let opening_dialer = dialer.clone();
        let opening = tokio::spawn(async move { opening_dialer.open_stream().await });

        pause.wait_until_open_is_paused().await;
        dialer.retire();
        pause.release();

        assert!(matches!(opening.await.unwrap(), Err(DialerError::Retired)));
        let mut byte = [0u8; 1];
        assert!(
            tokio::time::timeout(Duration::from_millis(50), peer.read(&mut byte))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn abandoned_open_is_reset_after_its_delayed_flush() {
        let (carrier, mut peer) = tokio::io::duplex(16);
        let dialer = FrameDialer::new(carrier);
        let _first = dialer.open_stream().await.unwrap();
        let _second = dialer.open_stream().await.unwrap();

        assert!(
            tokio::time::timeout(Duration::from_millis(50), dialer.open_stream())
                .await
                .is_err()
        );

        let mut decoder = FrameDecoder::new();
        let mut opened = 0;
        let mut reset = false;
        tokio::time::timeout(Duration::from_secs(1), async {
            while !reset {
                let mut bytes = [0u8; 64];
                let read = peer.read(&mut bytes).await.unwrap();
                assert_ne!(read, 0);
                decoder.feed(&bytes[..read]);
                while let Some(frame) = decoder.next_frame().unwrap() {
                    if frame.flags == FLAG_OPEN {
                        opened += 1;
                    }
                    if opened == 3
                        && frame.flags == FLAG_RESET
                        && frame.payload == vec![RESET_CANCEL]
                    {
                        reset = true;
                    }
                }
            }
        })
        .await
        .unwrap();
    }
}
