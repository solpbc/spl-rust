// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Persistent mux carrier for one local journal bridge instance.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use spl_core::bridge::FailureCategory;
use spl_core::frame::{Frame, FrameDialer, FrameViolation, RESET_CANCEL, RESET_FLOW_CONTROL_ERROR};
use spl_core::http;
use spl_core::mux::{
    CarrierDemux, MuxError, ResetReason, StreamEnd, StreamEvent, StreamItem, WindowedUpload,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf, split};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::time::{Instant, MissedTickBehavior};

use crate::client::{CarrierIo, CarrierKind};
use crate::journal_bridge::{CarrierOpener, SharedStatus, lock_status};
use crate::{TransportError, transport_error_code};

const READ_BUF_BYTES: usize = 64 * 1024;
const COMMAND_QUEUE: usize = 64;
const STREAM_QUEUE: usize = 16;
const WRITER_QUEUE: usize = 256;

type CarrierRead = ReadHalf<Box<dyn CarrierIo>>;
type CarrierWrite = WriteHalf<Box<dyn CarrierIo>>;

pub(crate) struct MuxCarrier {
    opener: Arc<dyn CarrierOpener>,
    slot: Mutex<Option<Arc<CarrierHandle>>>,
    keepalive: KeepaliveConfig,
    status: SharedStatus,
}

impl MuxCarrier {
    pub(crate) fn new(opener: Arc<dyn CarrierOpener>, status: SharedStatus) -> Self {
        Self::with_keepalive(opener, KeepaliveConfig::default(), status)
    }

    pub(crate) fn with_keepalive(
        opener: Arc<dyn CarrierOpener>,
        keepalive: KeepaliveConfig,
        status: SharedStatus,
    ) -> Self {
        Self {
            opener,
            slot: Mutex::new(None),
            keepalive,
            status,
        }
    }

    pub(crate) async fn open_stream(
        &self,
        method: &str,
        target: &str,
        upstream_headers: &[(String, String)],
        body: &[u8],
    ) -> Result<StreamRx, TransportError> {
        let headers = self.opener.proxy_headers(upstream_headers)?;
        let command = OpenStreamInput {
            method: method.to_string(),
            target: target.to_string(),
            headers,
            body: body.to_vec(),
        };

        let mut input = command;
        for attempt in 0..2 {
            let handle = self.get_or_dial().await?;
            match self.try_open(&handle, input).await {
                Ok(rx) => return Ok(rx),
                Err(OpenFailure::Transport(error)) => return Err(error),
                Err(OpenFailure::Dead(returned)) => {
                    self.clear_handle(&handle).await;
                    if attempt == 1 {
                        return Err(TransportError::Io(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "carrier coordinator stopped",
                        )));
                    }
                    input = returned;
                }
            }
        }
        Err(TransportError::Io(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "carrier coordinator stopped",
        )))
    }

    pub(crate) async fn shutdown(&self) {
        let handle = self.slot.lock().await.take();
        if let Some(handle) = handle {
            handle.alive.store(false, Ordering::SeqCst);
            mark_carrier_dead(&self.status, &handle.status_identity);
            let _ = handle.commands.send(CarrierCommand::Shutdown).await;
        }
    }

    async fn get_or_dial(&self) -> Result<Arc<CarrierHandle>, TransportError> {
        let mut slot = self.slot.lock().await;
        if let Some(handle) = slot.as_ref()
            && handle.alive.load(Ordering::SeqCst)
        {
            return Ok(handle.clone());
        }
        if let Some(handle) = slot.as_ref() {
            mark_carrier_dead(&self.status, &handle.status_identity);
        }

        let dialed = self.opener.dial_carrier().await?;
        let (stream, kind) = dialed.into_parts();
        let (read, write) = split(stream);
        let (commands_tx, commands_rx) = mpsc::channel(COMMAND_QUEUE);
        let (writer_tx, writer_rx) = mpsc::channel(WRITER_QUEUE);
        let alive = Arc::new(AtomicBool::new(true));
        let status_identity = Arc::new(());
        let handle = Arc::new(CarrierHandle {
            commands: commands_tx,
            alive: alive.clone(),
            status_identity: status_identity.clone(),
        });

        let mut status = lock_status(&self.status);
        tokio::spawn(writer_task(
            write,
            writer_rx,
            alive.clone(),
            self.status.clone(),
            status_identity.clone(),
        ));
        tokio::spawn(coordinator_task(
            read,
            commands_rx,
            handle.commands.clone(),
            writer_tx,
            alive,
            kind,
            self.keepalive,
            self.status.clone(),
            status_identity.clone(),
        ));

        *slot = Some(handle.clone());
        status.current_carrier = Some(status_identity);
        status.snapshot.carrier_live = true;
        drop(status);
        Ok(handle)
    }

    #[expect(
        clippy::unreachable,
        reason = "this branch documents the invariant that try_open sends only OpenStream commands"
    )]
    async fn try_open(
        &self,
        handle: &Arc<CarrierHandle>,
        input: OpenStreamInput,
    ) -> Result<StreamRx, OpenFailure> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let retry_input = input.clone();
        let command = CarrierCommand::OpenStream {
            input,
            reply: reply_tx,
        };
        if let Err(mpsc::error::SendError(command)) = handle.commands.send(command).await {
            match command {
                CarrierCommand::OpenStream { input, .. } => return Err(OpenFailure::Dead(input)),
                _ => unreachable!("try_open only sends OpenStream commands"),
            }
        }

        match reply_rx.await {
            Ok(Ok(rx)) => Ok(rx),
            Ok(Err(error)) => Err(OpenFailure::Transport(error)),
            Err(_) => Err(OpenFailure::Dead(retry_input)),
        }
    }

    async fn clear_handle(&self, handle: &Arc<CarrierHandle>) {
        let mut slot = self.slot.lock().await;
        #[expect(
            clippy::map_unwrap_or,
            reason = "the copied carrier identity check keeps the empty-slot fallback explicit"
        )]
        if slot
            .as_ref()
            .map(|current| Arc::ptr_eq(current, handle))
            .unwrap_or(false)
        {
            *slot = None;
            mark_carrier_dead(&self.status, &handle.status_identity);
        }
    }
}

enum OpenFailure {
    Dead(OpenStreamInput),
    Transport(TransportError),
}

pub(crate) struct CarrierHandle {
    commands: mpsc::Sender<CarrierCommand>,
    alive: Arc<AtomicBool>,
    status_identity: Arc<()>,
}

pub(crate) struct StreamRx {
    stream_id: u32,
    rx: mpsc::Receiver<StreamEvent>,
    commands: mpsc::Sender<CarrierCommand>,
    cancelled: bool,
}

impl StreamRx {
    pub(crate) async fn recv(&mut self) -> Option<StreamItem> {
        let Some(event) = self.rx.recv().await else {
            self.cancelled = true;
            return None;
        };
        if event.wire_cost != 0 {
            debug_assert!(matches!(event.item, StreamItem::Body(_)));
            let _ = self
                .commands
                .send(CarrierCommand::Consume {
                    stream_id: self.stream_id,
                    bytes: event.wire_cost,
                })
                .await;
        }
        if matches!(event.item, StreamItem::End(_)) {
            self.cancelled = true;
        }
        Some(event.item)
    }

    pub(crate) fn cancel(&mut self) {
        if self.cancelled {
            return;
        }
        self.cancelled = true;
        let _ = self.commands.try_send(CarrierCommand::CancelStream {
            stream_id: self.stream_id,
        });
    }
}

impl Drop for StreamRx {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[derive(Clone, Copy)]
pub(crate) struct KeepaliveConfig {
    interval: Duration,
    deadline: Duration,
    max_missed: u32,
}

impl Default for KeepaliveConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(30),
            deadline: Duration::from_secs(10),
            max_missed: 3,
        }
    }
}

#[derive(Clone)]
struct OpenStreamInput {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

enum CarrierCommand {
    OpenStream {
        input: OpenStreamInput,
        reply: oneshot::Sender<Result<StreamRx, TransportError>>,
    },
    CancelStream {
        stream_id: u32,
    },
    Consume {
        stream_id: u32,
        bytes: u64,
    },
    Shutdown,
}

struct StreamState {
    upload: WindowedUpload,
    delivery: mpsc::Sender<StreamEvent>,
}

struct OutstandingProbe {
    nonce: [u8; 8],
    deadline: Instant,
}

async fn writer_task(
    mut write: CarrierWrite,
    mut rx: mpsc::Receiver<Vec<u8>>,
    alive: Arc<AtomicBool>,
    status: SharedStatus,
    status_identity: Arc<()>,
) {
    while let Some(bytes) = rx.recv().await {
        if write.write_all(&bytes).await.is_err() || write.flush().await.is_err() {
            break;
        }
    }
    alive.store(false, Ordering::SeqCst);
    mark_carrier_dead(&status, &status_identity);
}

#[expect(
    clippy::too_many_lines,
    clippy::too_many_arguments,
    reason = "the copied coordinator keeps its single event loop, carrier generation, and ordering invariants together"
)]
async fn coordinator_task(
    mut read: CarrierRead,
    mut commands: mpsc::Receiver<CarrierCommand>,
    command_sender: mpsc::Sender<CarrierCommand>,
    writer: mpsc::Sender<Vec<u8>>,
    alive: Arc<AtomicBool>,
    kind: CarrierKind,
    keepalive: KeepaliveConfig,
    status: SharedStatus,
    status_identity: Arc<()>,
) {
    let mut demux = CarrierDemux::new();
    let mut dialer = FrameDialer::default();
    let mut streams: HashMap<u32, StreamState> = HashMap::new();
    let mut buf = vec![0u8; READ_BUF_BYTES];
    let mut interval = tokio::time::interval(keepalive.interval);
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    interval.tick().await;
    let mut outstanding: Option<OutstandingProbe> = None;
    let mut missed = 0u32;
    let mut next_nonce = 1u64;

    loop {
        tokio::select! {
            read_result = read.read(&mut buf) => {
                match read_result {
                    Ok(0) => {
                        fanout_eof(&mut streams);
                        break;
                    }
                    Ok(n) => {
                        if let Err(error) = handle_read(
                            &mut demux,
                            &mut streams,
                            &writer,
                            &buf[..n],
                            &mut outstanding,
                            &mut missed,
                        ) {
                            fanout_eof(&mut streams);
                            log_carrier_teardown(&kind, &transport_error_code(&error));
                            break;
                        }
                        outstanding = None;
                        missed = 0;
                    }
                    Err(_) => {
                        fanout_eof(&mut streams);
                        log_carrier_teardown(&kind, "io");
                        break;
                    }
                }
            }
            command = commands.recv() => {
                let Some(command) = command else {
                    fanout_eof(&mut streams);
                    break;
                };
                match command {
                    CarrierCommand::OpenStream { input, reply } => {
                        let result = open_stream_on_carrier(
                            input,
                            &mut dialer,
                            &mut demux,
                            &mut streams,
                            &writer,
                            command_sender.clone(),
                        );
                        match result {
                            Ok(rx) => {
                                let stream_id = rx.stream_id;
                                if reply.send(Ok(rx)).is_err()
                                    && let Err(error) = reset_active_stream(
                                        stream_id,
                                        &mut demux,
                                        &mut streams,
                                        &writer,
                                    )
                                {
                                    fanout_eof(&mut streams);
                                    log_carrier_teardown(&kind, &transport_error_code(&error));
                                    break;
                                }
                            }
                            Err(error) => {
                                let code = transport_error_code(&error);
                                let _ = reply.send(Err(error));
                                fanout_eof(&mut streams);
                                log_carrier_teardown(&kind, &code);
                                break;
                            }
                        }
                    }
                    CarrierCommand::CancelStream { stream_id } => {
                        if let Err(error) =
                            reset_active_stream(stream_id, &mut demux, &mut streams, &writer)
                        {
                            fanout_eof(&mut streams);
                            log_carrier_teardown(&kind, &transport_error_code(&error));
                            break;
                        }
                    }
                    CarrierCommand::Consume { stream_id, bytes } => {
                        if let Err(error) = consume_stream(stream_id, bytes, &mut demux, &writer) {
                            fanout_eof(&mut streams);
                            log_carrier_teardown(&kind, &transport_error_code(&error));
                            break;
                        }
                    }
                    CarrierCommand::Shutdown => {
                        fanout_eof(&mut streams);
                        break;
                    }
                }
            }
            _ = interval.tick() => {
                #[expect(
                    clippy::single_match_else,
                    reason = "the explicit result match keeps the keepalive success and teardown paths parallel with other coordinator events"
                )]
                match handle_keepalive(&writer, &mut outstanding, &mut missed, &mut next_nonce, keepalive) {
                    Ok(()) => {}
                    Err(()) => {
                        fanout_eof(&mut streams);
                        log_carrier_teardown(&kind, "io");
                        break;
                    }
                }
            }
        }
    }

    alive.store(false, Ordering::SeqCst);
    mark_carrier_dead(&status, &status_identity);
}

fn mark_carrier_dead(status: &SharedStatus, status_identity: &Arc<()>) {
    let mut record = lock_status(status);
    if record
        .current_carrier
        .as_ref()
        .is_some_and(|current| Arc::ptr_eq(current, status_identity))
    {
        record.current_carrier = None;
        record.snapshot.carrier_live = false;
    }
}

fn handle_read(
    demux: &mut CarrierDemux,
    streams: &mut HashMap<u32, StreamState>,
    writer: &mpsc::Sender<Vec<u8>>,
    data: &[u8],
    outstanding: &mut Option<OutstandingProbe>,
    missed: &mut u32,
) -> Result<(), TransportError> {
    let out = match demux.feed(data) {
        Ok(out) => out,
        Err(MuxError::Protocol(violation)) => {
            log_frame_violation(violation);
            return Err(TransportError::Mux(MuxError::Protocol(violation)));
        }
        Err(error) => return Err(TransportError::Mux(error)),
    };
    for violation in out.violations {
        log_frame_violation(violation);
    }
    for pong in out.pongs {
        send_writer(writer, pong)?;
    }
    for frame in out.emit_frames {
        send_writer(writer, frame)?;
    }
    for nonce in out.inbound_pongs {
        #[expect(
            clippy::map_unwrap_or,
            reason = "the copied keepalive check keeps a missing outstanding probe distinct in the expression"
        )]
        if outstanding
            .as_ref()
            .map(|probe| probe.nonce == nonce)
            .unwrap_or(false)
        {
            *outstanding = None;
            *missed = 0;
        }
    }
    for (stream_id, credit) in out.window_grants {
        let grant = streams
            .get_mut(&stream_id)
            .map(|state| state.upload.grant(credit));
        match grant {
            Some(Ok(())) => {
                #[expect(
                    clippy::expect_used,
                    reason = "successful demux credit granting proves the stream remains registered"
                )]
                let state = streams
                    .get_mut(&stream_id)
                    .expect("stream exists after successful grant");
                pump_upload(writer, state)?;
            }
            Some(Err(violation)) => {
                log_frame_violation(violation);
                let reset = Frame::reset(stream_id, RESET_FLOW_CONTROL_ERROR)
                    .encode()
                    .map_err(|error| TransportError::Mux(MuxError::Frame(error)))?;
                send_writer(writer, reset)?;
                demux.remove_stream(stream_id);
                deliver_stream_item(
                    stream_id,
                    StreamEvent {
                        item: StreamItem::End(StreamEnd::Reset(ResetReason::FlowControlError)),
                        wire_cost: 0,
                    },
                    demux,
                    streams,
                    writer,
                )?;
            }
            None => {}
        }
    }
    for (stream_id, event) in out.stream_events {
        deliver_stream_item(stream_id, event, demux, streams, writer)?;
    }
    Ok(())
}

fn consume_stream(
    stream_id: u32,
    bytes: u64,
    demux: &mut CarrierDemux,
    writer: &mpsc::Sender<Vec<u8>>,
) -> Result<(), TransportError> {
    if let Some(frame) = demux.consume(stream_id, bytes)? {
        send_writer(writer, frame)?;
    }
    Ok(())
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "the coordinator transfers ownership of each open request into its one write attempt"
)]
fn open_stream_on_carrier(
    input: OpenStreamInput,
    dialer: &mut FrameDialer,
    demux: &mut CarrierDemux,
    streams: &mut HashMap<u32, StreamState>,
    writer: &mpsc::Sender<Vec<u8>>,
    commands: mpsc::Sender<CarrierCommand>,
) -> Result<StreamRx, TransportError> {
    let stream_id = dialer.allocate();
    let request = http::build_request(&input.method, &input.target, &input.headers, &input.body);
    let (delivery, rx) = mpsc::channel(STREAM_QUEUE);
    let mut state = StreamState {
        upload: WindowedUpload::new(stream_id, &request),
        delivery,
    };
    demux.open_stream(stream_id);
    if let Err(error) = pump_upload(writer, &mut state) {
        demux.remove_stream(stream_id);
        return Err(error);
    }
    streams.insert(stream_id, state);
    Ok(StreamRx {
        stream_id,
        rx,
        commands,
        cancelled: false,
    })
}

fn deliver_stream_item(
    stream_id: u32,
    event: StreamEvent,
    demux: &mut CarrierDemux,
    streams: &mut HashMap<u32, StreamState>,
    writer: &mpsc::Sender<Vec<u8>>,
) -> Result<(), TransportError> {
    let ended = matches!(event.item, StreamItem::End(_));
    let Some(state) = streams.get(&stream_id) else {
        return Ok(());
    };
    let sent = state.delivery.try_send(event);

    match sent {
        Ok(()) => {
            if ended {
                streams.remove(&stream_id);
            }
        }
        Err(_) => {
            if ended {
                streams.remove(&stream_id);
            } else {
                reset_active_stream(stream_id, demux, streams, writer)?;
            }
        }
    }
    Ok(())
}

fn pump_upload(
    writer: &mpsc::Sender<Vec<u8>>,
    state: &mut StreamState,
) -> Result<(), TransportError> {
    while let Some(frame) = state
        .upload
        .poll_send()
        .map_err(|e| TransportError::Mux(MuxError::Frame(e)))?
    {
        send_writer(writer, frame)?;
    }
    Ok(())
}

fn reset_active_stream(
    stream_id: u32,
    demux: &mut CarrierDemux,
    streams: &mut HashMap<u32, StreamState>,
    writer: &mpsc::Sender<Vec<u8>>,
) -> Result<(), TransportError> {
    if streams.remove(&stream_id).is_none() {
        return Ok(());
    }
    demux.remove_stream(stream_id);
    let frame = Frame::reset(stream_id, RESET_CANCEL)
        .encode()
        .map_err(|e| TransportError::Mux(MuxError::Frame(e)))?;
    send_writer(writer, frame)
}

fn fanout_eof(streams: &mut HashMap<u32, StreamState>) {
    for (_, state) in streams.drain() {
        let _ = state.delivery.try_send(StreamEvent {
            item: StreamItem::End(StreamEnd::Eof),
            wire_cost: 0,
        });
    }
}

fn handle_keepalive(
    writer: &mpsc::Sender<Vec<u8>>,
    outstanding: &mut Option<OutstandingProbe>,
    missed: &mut u32,
    next_nonce: &mut u64,
    keepalive: KeepaliveConfig,
) -> Result<(), ()> {
    let now = Instant::now();
    if let Some(probe) = outstanding.as_ref() {
        if now < probe.deadline {
            return Ok(());
        }
        *missed = missed.saturating_add(1);
        if *missed >= keepalive.max_missed {
            return Err(());
        }
    }

    let nonce = next_nonce.to_be_bytes();
    *next_nonce = next_nonce.saturating_add(1);
    let frame = Frame::control_ping(nonce).encode().map_err(|_| ())?;
    send_writer(writer, frame).map_err(|_| ())?;
    *outstanding = Some(OutstandingProbe {
        nonce,
        deadline: now + keepalive.deadline,
    });
    Ok(())
}

fn send_writer(writer: &mpsc::Sender<Vec<u8>>, frame: Vec<u8>) -> Result<(), TransportError> {
    writer.try_send(frame).map_err(|error| {
        let reason = match error {
            mpsc::error::TrySendError::Full(_) => "carrier writer queue full",
            mpsc::error::TrySendError::Closed(_) => "carrier writer stopped",
        };
        TransportError::Io(io::Error::new(io::ErrorKind::BrokenPipe, reason))
    })
}

fn log_carrier_teardown(kind: &CarrierKind, fallback_code: &str) {
    let code = match kind {
        CarrierKind::Lan => fallback_code.to_string(),
        CarrierKind::Relay { termination } =>
        {
            #[expect(
                clippy::map_unwrap_or,
                reason = "the copied teardown mapping keeps the relay error and fallback code paths explicit"
            )]
            termination
                .current_error()
                .map(|error| transport_error_code(&TransportError::Relay(error)))
                .unwrap_or_else(|| fallback_code.to_string())
        }
    };
    tracing::warn!(
        target: "journal_bridge",
        category = FailureCategory::UpstreamUnreachable.token(),
        code = %code
    );
}

fn log_frame_violation(violation: FrameViolation) {
    tracing::warn!(
        target: "journal_bridge",
        code = "framing_protocol_violation",
        stream_id = violation.stream_id,
        flags = violation.flags,
        length = violation.length
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use spl_core::frame::{
        FLAG_CLOSE, FLAG_DATA, FLAG_OPEN, FLAG_PING, FLAG_PONG, FLAG_RESET, FLAG_WINDOW,
        FrameDecoder, RECOMMENDED_CHUNK, RESET_CANCEL, RESET_FLOW_CONTROL_ERROR,
    };
    use spl_core::mux::INITIAL_WINDOW;
    use tokio::io::{AsyncRead, AsyncWrite, DuplexStream};

    const TEST_INTERVAL: Duration = Duration::from_millis(100);
    const TEST_DEADLINE: Duration = Duration::from_millis(50);

    fn test_keepalive(max_missed: u32) -> KeepaliveConfig {
        KeepaliveConfig {
            interval: TEST_INTERVAL,
            deadline: TEST_DEADLINE,
            max_missed,
        }
    }

    fn spawn_duplex_carrier(
        keepalive: KeepaliveConfig,
        capacity: usize,
    ) -> (mpsc::Sender<CarrierCommand>, Arc<AtomicBool>, DuplexStream) {
        let (client, server) = tokio::io::duplex(capacity);
        let stream: Box<dyn CarrierIo> = Box::new(client);
        let (read, write) = split(stream);
        let (commands_tx, commands_rx) = mpsc::channel(COMMAND_QUEUE);
        let (writer_tx, writer_rx) = mpsc::channel(WRITER_QUEUE);
        let alive = Arc::new(AtomicBool::new(true));
        let status = crate::journal_bridge::new_status();
        let status_identity = Arc::new(());
        {
            let mut record = lock_status(&status);
            record.current_carrier = Some(status_identity.clone());
            record.snapshot.carrier_live = true;
        }
        tokio::spawn(writer_task(
            write,
            writer_rx,
            alive.clone(),
            status.clone(),
            status_identity.clone(),
        ));
        tokio::spawn(coordinator_task(
            read,
            commands_rx,
            commands_tx.clone(),
            writer_tx,
            alive.clone(),
            CarrierKind::Lan,
            keepalive,
            status,
            status_identity,
        ));
        (commands_tx, alive, server)
    }

    async fn open_test_stream(
        commands: &mpsc::Sender<CarrierCommand>,
        target: &str,
        body: Vec<u8>,
    ) -> StreamRx {
        let (reply, rx) = oneshot::channel();
        commands
            .send(CarrierCommand::OpenStream {
                input: OpenStreamInput {
                    method: "POST".to_string(),
                    target: target.to_string(),
                    headers: Vec::new(),
                    body,
                },
                reply,
            })
            .await
            .unwrap();
        rx.await.unwrap().unwrap()
    }

    async fn next_frame<S>(stream: &mut S, decoder: &mut FrameDecoder) -> Frame
    where
        S: AsyncRead + Unpin,
    {
        loop {
            if let Some(frame) = decoder.next_frame().unwrap() {
                return frame;
            }
            let mut buf = [0u8; 16 * 1024];
            let n = stream.read(&mut buf).await.unwrap();
            assert!(n > 0, "carrier closed before next frame");
            decoder.feed(&buf[..n]);
        }
    }

    async fn send_frame<S>(stream: &mut S, stream_id: u32, flags: u8, payload: &[u8])
    where
        S: AsyncWrite + Unpin,
    {
        let frame = Frame::new(stream_id, flags, payload.to_vec())
            .encode()
            .unwrap();
        stream.write_all(&frame).await.unwrap();
        stream.flush().await.unwrap();
    }

    async fn read_request_close<S>(
        stream: &mut S,
        decoder: &mut FrameDecoder,
        stream_id: u32,
    ) -> usize
    where
        S: AsyncRead + Unpin,
    {
        let mut data = 0usize;
        loop {
            let frame = next_frame(stream, decoder).await;
            if frame.stream_id != stream_id {
                continue;
            }
            if frame.flags & FLAG_DATA != 0 {
                data += frame.payload.len();
            }
            if frame.flags & FLAG_CLOSE != 0 {
                return data;
            }
        }
    }

    async fn read_until_reset<S>(stream: &mut S, decoder: &mut FrameDecoder, stream_id: u32)
    where
        S: AsyncRead + Unpin,
    {
        loop {
            let frame = next_frame(stream, decoder).await;
            if frame.stream_id == stream_id && frame.flags & FLAG_RESET != 0 {
                assert_eq!(frame.payload, vec![RESET_CANCEL]);
                return;
            }
        }
    }

    fn http_response(body: &[u8]) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            String::from_utf8_lossy(body)
        )
        .into_bytes()
    }

    fn http_head(content_length: usize) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {content_length}\r\n\r\n"
        )
        .into_bytes()
    }

    async fn send_credit_respecting_response<S>(
        stream: &mut S,
        decoder: &mut FrameDecoder,
        stream_id: u32,
        response: &[u8],
    ) where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        assert!(response.len() > INITIAL_WINDOW);
        let mut offset = 0usize;
        let mut send_credit = INITIAL_WINDOW;
        while offset < response.len() {
            if send_credit == 0 {
                loop {
                    let frame = next_frame(stream, decoder).await;
                    if frame.stream_id == stream_id {
                        if let Some(grant) = frame.window_credit() {
                            send_credit += grant as usize;
                            break;
                        }
                    }
                }
            }
            let count = (response.len() - offset)
                .min(spl_core::frame::RECOMMENDED_CHUNK)
                .min(send_credit);
            send_frame(
                stream,
                stream_id,
                FLAG_DATA,
                &response[offset..offset + count],
            )
            .await;
            offset += count;
            send_credit -= count;
            tokio::task::yield_now().await;
        }
        send_frame(stream, stream_id, FLAG_CLOSE, &[]).await;
    }

    async fn assert_stream_completes(rx: &mut StreamRx, expected_body: &[u8]) {
        let mut saw_head = false;
        let mut body = Vec::new();
        loop {
            match rx.recv().await.expect("stream item") {
                StreamItem::Head(head) => {
                    saw_head = true;
                    assert_eq!(head.status, 200);
                }
                StreamItem::Body(bytes) => body.extend_from_slice(&bytes),
                StreamItem::End(StreamEnd::Close) => break,
                other => panic!("unexpected stream item {other:?}"),
            }
        }
        assert!(saw_head);
        assert_eq!(body, expected_body);
    }

    async fn assert_stream_eof(rx: &mut StreamRx) {
        match tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("stream should finish")
        {
            Some(StreamItem::End(StreamEnd::Eof)) | None => {}
            other => panic!("expected eof/end channel close, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn carrier_allocates_distinct_odd_stream_ids() {
        let (commands, _alive, mut server) = spawn_duplex_carrier(test_keepalive(3), 256 * 1024);
        let mut decoder = FrameDecoder::new();
        let _rx1 = open_test_stream(&commands, "/one", Vec::new()).await;
        let _rx2 = open_test_stream(&commands, "/two", Vec::new()).await;

        let mut opened = Vec::new();
        while opened.len() < 2 {
            let frame = next_frame(&mut server, &mut decoder).await;
            if frame.flags & FLAG_OPEN != 0 {
                opened.push(frame.stream_id);
            }
        }

        assert_eq!(opened, vec![1, 3]);
    }

    #[tokio::test]
    async fn carrier_routes_window_grants_to_the_owning_upload() {
        let (commands, _alive, mut server) =
            spawn_duplex_carrier(test_keepalive(3), INITIAL_WINDOW * 4);
        let mut decoder = FrameDecoder::new();
        let body_a = vec![b'a'; INITIAL_WINDOW + 257];
        let body_b = vec![b'b'; INITIAL_WINDOW + 257];
        let request_a_len = http::build_request("POST", "/a", &[], &body_a).len();
        let request_b_len = http::build_request("POST", "/b", &[], &body_b).len();
        let _rx_a = open_test_stream(&commands, "/a", body_a).await;
        let _rx_b = open_test_stream(&commands, "/b", body_b).await;

        let mut data_a = 0usize;
        let mut data_b = 0usize;
        while data_a < INITIAL_WINDOW || data_b < INITIAL_WINDOW {
            let frame = next_frame(&mut server, &mut decoder).await;
            if frame.flags & FLAG_DATA == 0 {
                continue;
            }
            match frame.stream_id {
                1 => data_a += frame.payload.len(),
                3 => data_b += frame.payload.len(),
                other => panic!("unexpected stream {other}"),
            }
        }
        assert_eq!(data_a, INITIAL_WINDOW);
        assert_eq!(data_b, INITIAL_WINDOW);

        send_frame(
            &mut server,
            1,
            FLAG_WINDOW,
            &(request_a_len as u32).to_be_bytes(),
        )
        .await;
        let mut a_closed = false;
        while !a_closed {
            let frame = next_frame(&mut server, &mut decoder).await;
            match frame.stream_id {
                1 => {
                    if frame.flags & FLAG_DATA != 0 {
                        data_a += frame.payload.len();
                    }
                    if frame.flags & FLAG_CLOSE != 0 {
                        a_closed = true;
                    }
                }
                3 => {
                    if frame.flags & FLAG_DATA != 0 {
                        data_b += frame.payload.len();
                    }
                }
                other => panic!("unexpected stream {other}"),
            }
        }
        assert_eq!(data_a, request_a_len);
        assert_eq!(data_b, INITIAL_WINDOW, "stream B must stay blocked");

        send_frame(
            &mut server,
            3,
            FLAG_WINDOW,
            &(request_b_len as u32).to_be_bytes(),
        )
        .await;
        let mut b_closed = false;
        while !b_closed {
            let frame = next_frame(&mut server, &mut decoder).await;
            if frame.stream_id != 3 {
                continue;
            }
            if frame.flags & FLAG_DATA != 0 {
                data_b += frame.payload.len();
            }
            if frame.flags & FLAG_CLOSE != 0 {
                b_closed = true;
            }
        }
        assert_eq!(data_b, request_b_len);
    }

    #[tokio::test]
    async fn carrier_excess_send_credit_resets_only_owning_upload() {
        let (commands, _alive, mut server) =
            spawn_duplex_carrier(test_keepalive(3), INITIAL_WINDOW * 4);
        let mut decoder = FrameDecoder::new();
        let body_a = vec![b'a'; INITIAL_WINDOW + 257];
        let body_b = vec![b'b'; INITIAL_WINDOW + 257];
        let request_b_len = http::build_request("POST", "/b", &[], &body_b).len();
        let mut rx_a = open_test_stream(&commands, "/a", body_a).await;
        let mut rx_b = open_test_stream(&commands, "/b", body_b).await;

        let mut data_a = 0usize;
        let mut data_b = 0usize;
        while data_a < INITIAL_WINDOW || data_b < INITIAL_WINDOW {
            let frame = next_frame(&mut server, &mut decoder).await;
            if frame.flags & FLAG_DATA == 0 {
                continue;
            }
            match frame.stream_id {
                1 => data_a += frame.payload.len(),
                3 => data_b += frame.payload.len(),
                other => panic!("unexpected stream {other}"),
            }
        }

        send_frame(&mut server, 1, FLAG_WINDOW, &u32::MAX.to_be_bytes()).await;
        let reset = tokio::time::timeout(
            Duration::from_secs(1),
            next_frame(&mut server, &mut decoder),
        )
        .await
        .expect("excess send credit should reset the owning stream");
        assert_eq!(reset.stream_id, 1);
        assert_eq!(reset.flags, FLAG_RESET);
        assert_eq!(reset.payload, vec![RESET_FLOW_CONTROL_ERROR]);
        assert_eq!(
            rx_a.recv().await,
            Some(StreamItem::End(StreamEnd::Reset(
                ResetReason::FlowControlError
            )))
        );

        send_frame(
            &mut server,
            3,
            FLAG_WINDOW,
            &(request_b_len as u32).to_be_bytes(),
        )
        .await;
        read_request_close(&mut server, &mut decoder, 3).await;
        let response = http_response(b"b-ok");
        send_frame(&mut server, 3, FLAG_DATA | FLAG_CLOSE, &response).await;
        assert_stream_completes(&mut rx_b, b"b-ok").await;
    }

    #[tokio::test]
    async fn carrier_response_over_initial_window_replenishes_credit_on_consumer_drain() {
        const BODY_BYTES: usize = 1_600_000;

        let (commands, _alive, mut server) =
            spawn_duplex_carrier(KeepaliveConfig::default(), INITIAL_WINDOW * 2);
        let mut decoder = FrameDecoder::new();
        let mut rx = open_test_stream(&commands, "/large", Vec::new()).await;
        read_request_close(&mut server, &mut decoder, 1).await;

        let expected_body = vec![b'x'; BODY_BYTES];
        let response = http_response(&expected_body);
        let fake_peer = tokio::spawn(async move {
            send_credit_respecting_response(&mut server, &mut decoder, 1, &response).await;
        });

        tokio::time::timeout(
            Duration::from_secs(1),
            assert_stream_completes(&mut rx, &expected_body),
        )
        .await
        .expect("carrier response should complete after consumer drain grants receive credit");
        fake_peer.await.unwrap();
    }

    #[tokio::test]
    async fn carrier_without_body_drain_depletes_window_then_flow_control_resets() {
        let (commands, _alive, mut server) =
            spawn_duplex_carrier(KeepaliveConfig::default(), INITIAL_WINDOW * 2);
        let mut decoder = FrameDecoder::new();
        let mut rx = open_test_stream(&commands, "/no-drain", Vec::new()).await;
        read_request_close(&mut server, &mut decoder, 1).await;

        let head = http_head(1_700_321);
        send_frame(&mut server, 1, FLAG_DATA, &head).await;
        assert!(matches!(rx.recv().await, Some(StreamItem::Head(_))));

        let mut remaining = INITIAL_WINDOW - head.len();
        for _ in 0..STREAM_QUEUE {
            let count = remaining.min(RECOMMENDED_CHUNK);
            let payload = vec![b'x'; count];
            send_frame(&mut server, 1, FLAG_DATA, &payload).await;
            remaining -= count;
        }
        assert_eq!(remaining, 0);
        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                next_frame(&mut server, &mut decoder)
            )
            .await
            .is_err(),
            "a non-draining consumer must receive neither WINDOW nor RESET(CANCEL)"
        );

        send_frame(&mut server, 1, FLAG_DATA, b"x").await;
        let reset = tokio::time::timeout(
            Duration::from_secs(1),
            next_frame(&mut server, &mut decoder),
        )
        .await
        .expect("over-window DATA should be reset promptly");
        assert_eq!(reset.stream_id, 1);
        assert_eq!(reset.flags, FLAG_RESET);
        assert_eq!(reset.payload, vec![RESET_FLOW_CONTROL_ERROR]);
    }

    #[tokio::test]
    async fn carrier_grants_exact_wire_bytes_after_body_drain() {
        const BODY_BYTES: usize = 524_803;

        let (commands, _alive, mut server) =
            spawn_duplex_carrier(KeepaliveConfig::default(), INITIAL_WINDOW * 2);
        let mut decoder = FrameDecoder::new();
        let mut rx = open_test_stream(&commands, "/exact-window", Vec::new()).await;
        read_request_close(&mut server, &mut decoder, 1).await;

        let head = http_head(BODY_BYTES);
        send_frame(&mut server, 1, FLAG_DATA, &head).await;
        assert!(matches!(rx.recv().await, Some(StreamItem::Head(_))));

        let body = vec![b'x'; BODY_BYTES];
        let mut offset = 0usize;
        for _ in 0..7 {
            send_frame(
                &mut server,
                1,
                FLAG_DATA,
                &body[offset..offset + RECOMMENDED_CHUNK],
            )
            .await;
            assert!(matches!(rx.recv().await, Some(StreamItem::Body(_))));
            offset += RECOMMENDED_CHUNK;
        }
        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                next_frame(&mut server, &mut decoder)
            )
            .await
            .is_err(),
            "consumption below the half-window threshold must not grant"
        );

        send_frame(&mut server, 1, FLAG_DATA, &body[offset..]).await;
        assert!(matches!(rx.recv().await, Some(StreamItem::Body(_))));
        let window = tokio::time::timeout(
            Duration::from_secs(1),
            next_frame(&mut server, &mut decoder),
        )
        .await
        .expect("body drain should return receive credit");
        assert_eq!(window.stream_id, 1);
        assert_eq!(window.flags, FLAG_WINDOW);
        assert_eq!(
            window.window_credit(),
            Some((head.len() + BODY_BYTES) as u32)
        );

        send_frame(&mut server, 1, FLAG_CLOSE, &[]).await;
        assert_eq!(rx.recv().await, Some(StreamItem::End(StreamEnd::Close)));
    }

    #[tokio::test]
    async fn carrier_subthreshold_response_emits_no_window() {
        const BODY_BYTES: usize = 271_337;

        let (commands, _alive, mut server) =
            spawn_duplex_carrier(KeepaliveConfig::default(), INITIAL_WINDOW);
        let mut decoder = FrameDecoder::new();
        let mut rx = open_test_stream(&commands, "/small", Vec::new()).await;
        read_request_close(&mut server, &mut decoder, 1).await;

        let body = vec![b's'; BODY_BYTES];
        let response = http_response(&body);
        send_frame(&mut server, 1, FLAG_DATA | FLAG_CLOSE, &response).await;
        assert_stream_completes(&mut rx, &body).await;
        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                next_frame(&mut server, &mut decoder)
            )
            .await
            .is_err(),
            "a completed subthreshold response must not emit WINDOW"
        );
    }

    #[tokio::test]
    async fn carrier_chunked_window_counts_framing_wire_bytes_on_drain() {
        const BODY_BYTES: usize = 524_777;

        let (commands, _alive, mut server) =
            spawn_duplex_carrier(KeepaliveConfig::default(), INITIAL_WINDOW * 2);
        let mut decoder = FrameDecoder::new();
        let mut rx = open_test_stream(&commands, "/chunked", Vec::new()).await;
        read_request_close(&mut server, &mut decoder, 1).await;

        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        send_frame(&mut server, 1, FLAG_DATA, head).await;
        assert!(matches!(rx.recv().await, Some(StreamItem::Head(_))));

        let body = vec![b'c'; BODY_BYTES];
        let mut chunk_wire = format!("{BODY_BYTES:x}\r\n").into_bytes();
        chunk_wire.extend_from_slice(&body);
        chunk_wire.extend_from_slice(b"\r\n0\r\n\r\n");
        for part in chunk_wire.chunks(RECOMMENDED_CHUNK) {
            send_frame(&mut server, 1, FLAG_DATA, part).await;
        }
        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                next_frame(&mut server, &mut decoder)
            )
            .await
            .is_err(),
            "buffered chunk bytes must wait for Body drain"
        );

        assert_eq!(rx.recv().await, Some(StreamItem::Body(body)));
        let window = tokio::time::timeout(
            Duration::from_secs(1),
            next_frame(&mut server, &mut decoder),
        )
        .await
        .expect("draining the decoded chunk should grant its wire cost");
        assert_eq!(window.stream_id, 1);
        assert_eq!(window.flags, FLAG_WINDOW);
        assert_eq!(
            window.window_credit(),
            Some((head.len() + chunk_wire.len()) as u32)
        );

        send_frame(&mut server, 1, FLAG_CLOSE, &[]).await;
        assert_eq!(rx.recv().await, Some(StreamItem::End(StreamEnd::Close)));
    }

    #[tokio::test]
    async fn carrier_over_window_resets_one_stream_and_keeps_sibling_alive() {
        let (commands, _alive, mut server) =
            spawn_duplex_carrier(KeepaliveConfig::default(), INITIAL_WINDOW * 2);
        let mut decoder = FrameDecoder::new();
        let mut rx_a = open_test_stream(&commands, "/over-window", Vec::new()).await;
        let mut rx_b = open_test_stream(&commands, "/sibling", Vec::new()).await;
        read_request_close(&mut server, &mut decoder, 1).await;
        read_request_close(&mut server, &mut decoder, 3).await;

        let overrun = vec![b'x'; INITIAL_WINDOW + 37];
        send_frame(&mut server, 1, FLAG_DATA, &overrun).await;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), rx_a.recv())
                .await
                .expect("offending stream should end promptly"),
            Some(StreamItem::End(StreamEnd::Reset(
                ResetReason::FlowControlError
            )))
        );
        let reset = tokio::time::timeout(
            Duration::from_secs(1),
            next_frame(&mut server, &mut decoder),
        )
        .await
        .expect("peer should receive flow-control reset");
        assert_eq!(reset.stream_id, 1);
        assert_eq!(reset.flags, FLAG_RESET);
        assert_eq!(reset.payload, vec![RESET_FLOW_CONTROL_ERROR]);

        send_frame(&mut server, 1, FLAG_DATA, b"late").await;
        let late_reset = tokio::time::timeout(
            Duration::from_secs(1),
            next_frame(&mut server, &mut decoder),
        )
        .await
        .expect("late DATA should receive a protocol reset");
        assert_eq!(late_reset.stream_id, 1);
        assert_eq!(late_reset.flags, FLAG_RESET);
        assert_eq!(
            late_reset.payload,
            vec![spl_core::frame::RESET_PROTOCOL_ERROR]
        );
        assert_eq!(
            rx_a.recv().await,
            None,
            "late DATA must not deliver a second End"
        );

        let sibling_body = vec![b'b'; 19_731];
        let sibling_response = http_response(&sibling_body);
        send_frame(&mut server, 3, FLAG_DATA | FLAG_CLOSE, &sibling_response).await;
        assert_stream_completes(&mut rx_b, &sibling_body).await;
        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                next_frame(&mut server, &mut decoder)
            )
            .await
            .is_err(),
            "late offending-stream DATA must trigger exactly one protocol reset"
        );
    }

    #[tokio::test]
    async fn carrier_answers_stream_zero_ping_while_stream_is_active() {
        let (commands, _alive, mut server) = spawn_duplex_carrier(test_keepalive(3), 256 * 1024);
        let mut decoder = FrameDecoder::new();
        let mut rx = open_test_stream(&commands, "/ping", Vec::new()).await;
        read_request_close(&mut server, &mut decoder, 1).await;

        let nonce = [9, 8, 7, 6, 5, 4, 3, 2];
        send_frame(&mut server, 0, FLAG_PING, &nonce).await;
        let pong = next_frame(&mut server, &mut decoder).await;
        assert_eq!(pong.stream_id, 0);
        assert_eq!(pong.flags, FLAG_PONG);
        assert_eq!(pong.payload, nonce);

        let response = http_response(b"ok");
        send_frame(&mut server, 1, FLAG_DATA | FLAG_CLOSE, &response).await;
        assert_stream_completes(&mut rx, b"ok").await;
    }

    #[tokio::test(start_paused = true)]
    async fn carrier_keepalive_tears_down_silent_wedged_carrier() {
        let (commands, alive, mut server) = spawn_duplex_carrier(test_keepalive(2), 256 * 1024);
        let mut decoder = FrameDecoder::new();
        let mut rx = open_test_stream(&commands, "/silent", Vec::new()).await;
        read_request_close(&mut server, &mut decoder, 1).await;

        for _ in 0..3 {
            tokio::time::advance(TEST_INTERVAL + TEST_DEADLINE).await;
            tokio::task::yield_now().await;
        }

        assert!(!alive.load(Ordering::SeqCst));
        assert_stream_eof(&mut rx).await;
    }

    #[tokio::test]
    async fn carrier_drop_stream_rx_sends_reset_for_that_stream_only() {
        let (commands, _alive, mut server) = spawn_duplex_carrier(test_keepalive(3), 256 * 1024);
        let mut decoder = FrameDecoder::new();
        let rx_a = open_test_stream(&commands, "/a", Vec::new()).await;
        let mut rx_b = open_test_stream(&commands, "/b", Vec::new()).await;
        read_request_close(&mut server, &mut decoder, 1).await;
        read_request_close(&mut server, &mut decoder, 3).await;

        drop(rx_a);
        read_until_reset(&mut server, &mut decoder, 1).await;

        let response = http_response(b"b-ok");
        send_frame(&mut server, 3, FLAG_DATA | FLAG_CLOSE, &response).await;
        assert_stream_completes(&mut rx_b, b"b-ok").await;
    }

    #[tokio::test]
    async fn carrier_slow_consumer_resets_only_that_stream() {
        let (commands, _alive, mut server) = spawn_duplex_carrier(test_keepalive(3), 512 * 1024);
        let mut decoder = FrameDecoder::new();
        let _rx_a = open_test_stream(&commands, "/slow", Vec::new()).await;
        let mut rx_b = open_test_stream(&commands, "/ok", Vec::new()).await;
        read_request_close(&mut server, &mut decoder, 1).await;
        read_request_close(&mut server, &mut decoder, 3).await;

        send_frame(
            &mut server,
            1,
            FLAG_DATA,
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n",
        )
        .await;
        for _ in 0..(STREAM_QUEUE + 4) {
            send_frame(&mut server, 1, FLAG_DATA, b"x").await;
        }
        read_until_reset(&mut server, &mut decoder, 1).await;

        let response = http_response(b"b-ok");
        send_frame(&mut server, 3, FLAG_DATA | FLAG_CLOSE, &response).await;
        assert_stream_completes(&mut rx_b, b"b-ok").await;
    }

    #[tokio::test]
    async fn carrier_death_fans_out_eof_to_all_active_streams() {
        let (commands, alive, mut server) = spawn_duplex_carrier(test_keepalive(3), 256 * 1024);
        let mut decoder = FrameDecoder::new();
        let mut rx_a = open_test_stream(&commands, "/a", Vec::new()).await;
        let mut rx_b = open_test_stream(&commands, "/b", Vec::new()).await;
        read_request_close(&mut server, &mut decoder, 1).await;
        read_request_close(&mut server, &mut decoder, 3).await;

        drop(server);
        assert_stream_eof(&mut rx_a).await;
        assert_stream_eof(&mut rx_b).await;
        tokio::time::timeout(Duration::from_secs(1), async {
            while alive.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("carrier should mark dead");
    }
}
