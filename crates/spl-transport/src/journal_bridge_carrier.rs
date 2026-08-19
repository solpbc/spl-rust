// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Persistent mux carrier for one local journal bridge instance.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use spl_core::bridge::FailureCategory;
use spl_core::frame::{Frame, FrameDialer, FrameViolation, RESET_CANCEL, RESET_FLOW_CONTROL_ERROR};
use spl_core::http;
use spl_core::mux::{
    CarrierDemux, HttpHead, MuxError, ResetReason, StreamEnd, StreamEvent, StreamItem,
    UPLOAD_BODY_STAGE_CAPACITY, WindowedUpload,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf, split};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior};

#[cfg(test)]
use std::sync::atomic::AtomicUsize;

use crate::client::{CarrierIo, CarrierKind};
use crate::journal_bridge::{
    CarrierOpener, JournalBridgeTerminalReason, SharedStatus, lock_status,
};
use crate::{TransportError, received_tls_alert, transport_error_code};

const READ_BUF_BYTES: usize = 64 * 1024;
const COMMAND_QUEUE: usize = 64;
const STREAM_QUEUE: usize = 16;
const WRITER_QUEUE: usize = 256;
// One coordinator pass can coalesce a keepalive burst with stream-local WINDOW
// and RESET output; 32 slots leaves normal control batches clear of upload DATA.
const CONTROL_RESERVE: usize = 32;
const BODY_QUEUE: usize = 4;

type CarrierRead = ReadHalf<Box<dyn CarrierIo>>;
type CarrierWrite = WriteHalf<Box<dyn CarrierIo>>;

struct BodyBudget {
    permits: Arc<Semaphore>,
    #[cfg(test)]
    probe: Arc<BudgetProbe>,
}

impl BodyBudget {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            permits: Arc::new(Semaphore::new(UPLOAD_BODY_STAGE_CAPACITY)),
            #[cfg(test)]
            probe: Arc::new(BudgetProbe::default()),
        })
    }

    async fn reserve(self: &Arc<Self>, bytes: usize) -> Result<BodyLease, TransportError> {
        let count = u32::try_from(bytes).map_err(|_| {
            TransportError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "request body reservation exceeds transport capacity",
            ))
        })?;
        if count == 0 {
            return Err(TransportError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "request body reservation must be nonzero",
            )));
        }
        let permit = self
            .permits
            .clone()
            .acquire_many_owned(count)
            .await
            .map_err(|_| {
                TransportError::Io(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "request body stream closed",
                ))
            })?;
        #[cfg(test)]
        self.probe.note_reserved(bytes);
        Ok(BodyLease {
            permit,
            #[cfg(test)]
            probe: self.probe.clone(),
        })
    }

    fn close(&self) {
        self.permits.close();
    }

    #[cfg(test)]
    fn snapshot(&self) -> BudgetSnapshot {
        self.probe.snapshot()
    }
}

struct BodyLease {
    permit: OwnedSemaphorePermit,
    #[cfg(test)]
    probe: Arc<BudgetProbe>,
}

impl BodyLease {
    fn len(&self) -> usize {
        self.permit.num_permits()
    }

    fn split(&mut self, bytes: usize) -> Option<Self> {
        let permit = self.permit.split(bytes)?;
        Some(Self {
            permit,
            #[cfg(test)]
            probe: self.probe.clone(),
        })
    }

    #[cfg(test)]
    fn note_drained(&self) {
        self.probe.note_drained(self.len());
    }
}

#[cfg(test)]
impl Drop for BodyLease {
    fn drop(&mut self) {
        self.probe.note_released(self.len());
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy)]
struct BudgetSnapshot {
    reserved: usize,
    peak_reserved: usize,
    body_read: usize,
    writer_drained: usize,
    read_ahead: usize,
    peak_read_ahead: usize,
}

#[cfg(test)]
#[derive(Default)]
struct BudgetProbe {
    reserved: AtomicUsize,
    peak_reserved: AtomicUsize,
    body_read: AtomicUsize,
    writer_drained: AtomicUsize,
    peak_read_ahead: AtomicUsize,
}

#[cfg(test)]
impl BudgetProbe {
    fn note_reserved(&self, bytes: usize) {
        let reserved = self.reserved.fetch_add(bytes, Ordering::SeqCst) + bytes;
        self.peak_reserved.fetch_max(reserved, Ordering::SeqCst);
    }

    fn note_released(&self, bytes: usize) {
        self.reserved.fetch_sub(bytes, Ordering::SeqCst);
    }

    fn note_read(&self, bytes: usize) {
        let read = self.body_read.fetch_add(bytes, Ordering::SeqCst) + bytes;
        let drained = self.writer_drained.load(Ordering::SeqCst);
        self.peak_read_ahead
            .fetch_max(read.saturating_sub(drained), Ordering::SeqCst);
    }

    fn note_drained(&self, bytes: usize) {
        self.writer_drained.fetch_add(bytes, Ordering::SeqCst);
    }

    fn snapshot(&self) -> BudgetSnapshot {
        let read = self.body_read.load(Ordering::SeqCst);
        let drained = self.writer_drained.load(Ordering::SeqCst);
        BudgetSnapshot {
            reserved: self.reserved.load(Ordering::SeqCst),
            peak_reserved: self.peak_reserved.load(Ordering::SeqCst),
            body_read: read,
            writer_drained: drained,
            read_ahead: read.saturating_sub(drained),
            peak_read_ahead: self.peak_read_ahead.load(Ordering::SeqCst),
        }
    }
}

struct BodyChunk {
    bytes: Vec<u8>,
    lease: BodyLease,
}

pub(crate) struct BodyReservation {
    lease: BodyLease,
}

impl BodyReservation {
    pub(crate) fn capacity(&self) -> usize {
        self.lease.len()
    }

    fn retain(mut self, bytes: usize) -> Result<BodyLease, TransportError> {
        if bytes > self.lease.len() {
            return Err(TransportError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "request body exceeds its reservation",
            )));
        }
        if bytes == self.lease.len() {
            return Ok(self.lease);
        }
        self.lease.split(bytes).ok_or_else(|| {
            TransportError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "request body reservation could not be divided",
            ))
        })
    }
}

pub(crate) struct BodyTx {
    tx: Option<mpsc::Sender<BodyChunk>>,
    budget: Arc<BodyBudget>,
    ready: mpsc::UnboundedSender<u32>,
    stream_id: u32,
}

impl BodyTx {
    fn new(
        tx: mpsc::Sender<BodyChunk>,
        budget: Arc<BodyBudget>,
        ready: mpsc::UnboundedSender<u32>,
        stream_id: u32,
    ) -> Self {
        Self {
            tx: Some(tx),
            budget,
            ready,
            stream_id,
        }
    }

    pub(crate) async fn reserve(&self, bytes: usize) -> Result<BodyReservation, TransportError> {
        self.budget
            .reserve(bytes)
            .await
            .map(|lease| BodyReservation { lease })
    }

    pub(crate) async fn send_reserved(
        &self,
        reservation: BodyReservation,
        bytes: Vec<u8>,
    ) -> Result<(), TransportError> {
        self.send_reserved_inner(reservation, bytes, true).await
    }

    async fn send_reserved_inner(
        &self,
        reservation: BodyReservation,
        bytes: Vec<u8>,
        notify: bool,
    ) -> Result<(), TransportError> {
        let lease = reservation.retain(bytes.len())?;
        #[cfg(test)]
        self.budget.probe.note_read(bytes.len());
        let Some(tx) = self.tx.as_ref() else {
            return Err(TransportError::Io(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "request body sender closed",
            )));
        };
        tx.send(BodyChunk { bytes, lease }).await.map_err(|_| {
            TransportError::Io(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "request body receiver stopped",
            ))
        })?;
        if notify {
            self.notify()?;
        }
        Ok(())
    }

    #[cfg(test)]
    async fn send_without_wake(
        &self,
        reservation: BodyReservation,
        bytes: Vec<u8>,
    ) -> Result<(), TransportError> {
        self.send_reserved_inner(reservation, bytes, false).await
    }

    fn notify(&self) -> Result<(), TransportError> {
        self.ready.send(self.stream_id).map_err(|_| {
            TransportError::Io(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "carrier coordinator stopped",
            ))
        })
    }
}

impl Drop for BodyTx {
    fn drop(&mut self) {
        self.tx.take();
        let _ = self.ready.send(self.stream_id);
    }
}

pub(crate) struct OpenedStream {
    pub(crate) body: BodyTx,
    pub(crate) response: StreamRx,
}

pub(crate) struct MuxCarrier {
    opener: Arc<dyn CarrierOpener>,
    slot: Mutex<Option<Arc<CarrierHandle>>>,
    keepalive: KeepaliveConfig,
    status: SharedStatus,
    #[cfg(test)]
    redial_hook: Option<Arc<dyn Fn() + Send + Sync>>,
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
            #[cfg(test)]
            redial_hook: None,
        }
    }

    pub(crate) async fn open_stream(
        &self,
        method: &str,
        target: &str,
        upstream_headers: &[(String, String)],
        declared_body_len: usize,
    ) -> Result<OpenedStream, TransportError> {
        let headers = self.opener.proxy_headers(upstream_headers)?;
        let (body_tx, body_rx) = mpsc::channel(BODY_QUEUE);
        let budget = BodyBudget::new();
        let command = OpenStreamInput {
            method: method.to_string(),
            target: target.to_string(),
            headers,
            declared_body_len,
            body: body_rx,
            budget: budget.clone(),
        };

        let mut input = command;
        for attempt in 0..2 {
            let handle = self.get_or_dial().await?;
            match self.try_open(&handle, input).await {
                Ok(response) => {
                    let body = BodyTx::new(
                        body_tx,
                        budget,
                        handle.body_ready.clone(),
                        response.stream_id,
                    );
                    return Ok(OpenedStream { body, response });
                }
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
            if let Some(tasks) = handle.tasks.lock().await.take() {
                tasks.writer.abort();
                tasks.coordinator.abort();
                let _ = tasks.writer.await;
                let _ = tasks.coordinator.await;
            }
        }
    }

    async fn get_or_dial(&self) -> Result<Arc<CarrierHandle>, TransportError> {
        let mut slot = self.slot.lock().await;
        if lock_status(&self.status).snapshot.terminal_reason.is_some() {
            return Err(TransportError::TlsAccessDenied);
        }
        if let Some(handle) = slot.as_ref()
            && handle.alive.load(Ordering::SeqCst)
        {
            return Ok(handle.clone());
        }
        if let Some(handle) = slot.as_ref() {
            mark_carrier_dead(&self.status, &handle.status_identity);
        }

        #[cfg(test)]
        if let Some(redial_hook) = &self.redial_hook {
            redial_hook();
        }

        if lock_status(&self.status).snapshot.terminal_reason.is_some() {
            return Err(TransportError::TlsAccessDenied);
        }

        let dialed = match self.opener.dial_carrier().await {
            Ok(dialed) => dialed,
            Err(error) => {
                if matches!(error, TransportError::TlsAccessDenied) {
                    latch_tls_access_denied(&self.status);
                }
                return Err(error);
            }
        };
        let (stream, kind) = dialed.into_parts();
        let (read, write) = split(stream);
        let (commands_tx, commands_rx) = mpsc::channel(COMMAND_QUEUE);
        let (writer_tx, writer_rx) = mpsc::channel(WRITER_QUEUE);
        let (writer_events_tx, writer_events_rx) = mpsc::unbounded_channel();
        let (body_ready_tx, body_ready_rx) = mpsc::unbounded_channel();
        let (cancel_tx, cancel_rx) = mpsc::unbounded_channel();
        let alive = Arc::new(AtomicBool::new(true));
        let status_identity = Arc::new(());
        let mut status = lock_status(&self.status);
        if status.snapshot.terminal_reason.is_some() {
            drop(status);
            return Err(TransportError::TlsAccessDenied);
        }
        let writer = tokio::spawn(writer_task(
            write,
            writer_rx,
            writer_events_tx,
            kind.clone(),
            CarrierLiveGuard::new(alive.clone(), self.status.clone(), status_identity.clone()),
        ));
        let coordinator = tokio::spawn(coordinator_task(
            read,
            CoordinatorChannels {
                commands: commands_rx,
                command_sender: commands_tx.clone(),
                body_ready: body_ready_rx,
                cancels: cancel_rx,
                cancel_sender: cancel_tx.clone(),
                writer_tx,
                writer_events: writer_events_rx,
            },
            kind,
            self.keepalive,
            CarrierLiveGuard::new(alive.clone(), self.status.clone(), status_identity.clone()),
        ));
        let handle = Arc::new(CarrierHandle {
            commands: commands_tx,
            body_ready: body_ready_tx,
            alive: alive.clone(),
            status_identity: status_identity.clone(),
            tasks: Mutex::new(Some(CarrierTasks {
                writer,
                coordinator,
            })),
        });

        *slot = Some(handle.clone());
        status.current_carrier = Some(status_identity);
        status.snapshot.carrier_live = true;
        drop(status);
        Ok(handle)
    }

    async fn try_open(
        &self,
        handle: &Arc<CarrierHandle>,
        input: OpenStreamInput,
    ) -> Result<StreamRx, OpenFailure> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let (return_tx, return_rx) = oneshot::channel();
        let command = CarrierCommand::OpenStream {
            pending: PendingOpen::new(input, return_tx),
            reply: reply_tx,
        };
        if let Err(mpsc::error::SendError(command)) = handle.commands.send(command).await {
            if let CarrierCommand::OpenStream { pending, .. } = command
                && let Some(input) = pending.reclaim()
            {
                return Err(OpenFailure::Dead(input));
            }
            return Err(OpenFailure::Transport(stopped_after_claim_error()));
        }

        match reply_rx.await {
            Ok(Ok(rx)) => Ok(rx),
            Ok(Err(error)) => Err(OpenFailure::Transport(error)),
            Err(_) => match return_rx.await {
                Ok(input) => Err(OpenFailure::Dead(input)),
                Err(_) => Err(OpenFailure::Transport(stopped_after_claim_error())),
            },
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
    body_ready: mpsc::UnboundedSender<u32>,
    alive: Arc<AtomicBool>,
    status_identity: Arc<()>,
    tasks: Mutex<Option<CarrierTasks>>,
}

struct CarrierTasks {
    writer: JoinHandle<()>,
    coordinator: JoinHandle<()>,
}

fn stopped_after_claim_error() -> TransportError {
    TransportError::Io(io::Error::new(
        io::ErrorKind::BrokenPipe,
        "carrier coordinator stopped after claiming stream",
    ))
}

struct CarrierLiveGuard {
    alive: Arc<AtomicBool>,
    status: SharedStatus,
    status_identity: Arc<()>,
}

impl CarrierLiveGuard {
    fn new(alive: Arc<AtomicBool>, status: SharedStatus, status_identity: Arc<()>) -> Self {
        Self {
            alive,
            status,
            status_identity,
        }
    }
}

impl Drop for CarrierLiveGuard {
    fn drop(&mut self) {
        self.alive.store(false, Ordering::SeqCst);
        mark_carrier_dead(&self.status, &self.status_identity);
    }
}

pub(crate) struct StreamRx {
    stream_id: u32,
    rx: mpsc::Receiver<DeliveryEvent>,
    commands: mpsc::Sender<CarrierCommand>,
    cancel: mpsc::UnboundedSender<u32>,
    terminal: bool,
    early_final_status: Option<u16>,
    certificate_unknown: bool,
}

impl StreamRx {
    pub(crate) async fn recv(&mut self) -> Option<StreamItem> {
        let Some(delivery) = self.rx.recv().await else {
            self.terminal = true;
            return None;
        };
        let event = match delivery {
            DeliveryEvent::Stream(event) => event,
            DeliveryEvent::EarlyFinal(head) => {
                self.terminal = true;
                self.early_final_status = Some(head.status);
                return Some(StreamItem::Head(head));
            }
            DeliveryEvent::CertificateUnknown => {
                self.terminal = true;
                self.certificate_unknown = true;
                return None;
            }
        };
        debug_assert!(event.wire_cost == 0 || matches!(event.item, StreamItem::Body(_)));
        // Every drain wakes the coordinator, including zero-cost Head and End
        // events. A full per-stream delivery queue may have a bounded pending
        // event waiting for exactly this newly available slot.
        let _ = self
            .commands
            .send(CarrierCommand::Consume {
                stream_id: self.stream_id,
                bytes: event.wire_cost,
            })
            .await;
        if matches!(event.item, StreamItem::End(_)) {
            self.terminal = true;
        }
        Some(event.item)
    }

    pub(crate) fn early_final_status(&self) -> Option<u16> {
        self.early_final_status
    }

    /// Named carrier failure observed while this stream was still open, if any.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "loopback 502 stays untyped; carrier tests observe named 46 through this accessor"
        )
    )]
    pub(crate) fn carrier_failure(&self) -> Option<TransportError> {
        self.certificate_unknown
            .then_some(TransportError::TlsCertificateUnknown)
    }

    pub(crate) fn cancel(&mut self) {
        if self.terminal {
            return;
        }
        self.terminal = true;
        let _ = self.cancel.send(self.stream_id);
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

struct OpenStreamInput {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    declared_body_len: usize,
    body: mpsc::Receiver<BodyChunk>,
    budget: Arc<BodyBudget>,
}

struct PendingOpen {
    input: Option<OpenStreamInput>,
    return_input: Option<oneshot::Sender<OpenStreamInput>>,
}

impl PendingOpen {
    fn new(input: OpenStreamInput, return_input: oneshot::Sender<OpenStreamInput>) -> Self {
        Self {
            input: Some(input),
            return_input: Some(return_input),
        }
    }

    fn claim(mut self) -> Option<OpenStreamInput> {
        self.return_input.take();
        self.input.take()
    }

    fn reclaim(mut self) -> Option<OpenStreamInput> {
        self.return_input.take();
        self.input.take()
    }
}

impl Drop for PendingOpen {
    fn drop(&mut self) {
        if let (Some(input), Some(return_input)) = (self.input.take(), self.return_input.take()) {
            let _ = return_input.send(input);
        }
    }
}

enum CarrierCommand {
    OpenStream {
        pending: PendingOpen,
        reply: oneshot::Sender<Result<StreamRx, TransportError>>,
    },
    Consume {
        stream_id: u32,
        bytes: u64,
    },
    Shutdown,
}

enum DeliveryEvent {
    Stream(StreamEvent),
    EarlyFinal(HttpHead),
    CertificateUnknown,
}

struct StreamState {
    upload: WindowedUpload,
    declared_body_len: usize,
    received_body_len: usize,
    body: mpsc::Receiver<BodyChunk>,
    budget: Arc<BodyBudget>,
    staged_leases: VecDeque<BodyLease>,
    delivery: mpsc::Sender<DeliveryEvent>,
    pending_delivery: VecDeque<DeliveryEvent>,
    ready_queued: bool,
}

impl Drop for StreamState {
    fn drop(&mut self) {
        self.body.close();
        self.budget.close();
    }
}

struct OutstandingProbe {
    nonce: [u8; 8],
    deadline: Instant,
}

struct WriterPacket {
    bytes: Vec<u8>,
    body_leases: Vec<BodyLease>,
}

enum WriterEvent {
    Drained,
    Stopped(Option<TransportError>),
}

struct CoordinatorWriter {
    tx: mpsc::Sender<WriterPacket>,
    inflight: usize,
}

impl CoordinatorWriter {
    fn new(tx: mpsc::Sender<WriterPacket>) -> Self {
        Self { tx, inflight: 0 }
    }

    fn has_room(&self) -> bool {
        self.inflight < WRITER_QUEUE
    }

    fn has_upload_room(&self) -> bool {
        self.inflight < WRITER_QUEUE - CONTROL_RESERVE
    }

    fn send(&mut self, packet: WriterPacket) -> Result<(), TransportError> {
        if !self.has_room() {
            return Err(writer_error("carrier writer queue full"));
        }
        self.tx.try_send(packet).map_err(|error| {
            let reason = match error {
                mpsc::error::TrySendError::Full(_) => "carrier writer queue full",
                mpsc::error::TrySendError::Closed(_) => "carrier writer stopped",
            };
            writer_error(reason)
        })?;
        self.inflight += 1;
        Ok(())
    }

    fn drained(&mut self) {
        self.inflight = self.inflight.saturating_sub(1);
    }
}

struct CoordinatorChannels {
    commands: mpsc::Receiver<CarrierCommand>,
    command_sender: mpsc::Sender<CarrierCommand>,
    body_ready: mpsc::UnboundedReceiver<u32>,
    cancels: mpsc::UnboundedReceiver<u32>,
    cancel_sender: mpsc::UnboundedSender<u32>,
    writer_tx: mpsc::Sender<WriterPacket>,
    writer_events: mpsc::UnboundedReceiver<WriterEvent>,
}

async fn writer_task(
    mut write: CarrierWrite,
    mut rx: mpsc::Receiver<WriterPacket>,
    events: mpsc::UnboundedSender<WriterEvent>,
    kind: CarrierKind,
    carrier_guard: CarrierLiveGuard,
) {
    let mut stop_reason = None;
    while let Some(packet) = rx.recv().await {
        let WriterPacket { bytes, body_leases } = packet;
        if let Err(error) = write.write_all(&bytes).await {
            stop_reason = classify_carrier_tls_alert(&error, &kind, &carrier_guard.status);
            break;
        }
        if let Err(error) = write.flush().await {
            stop_reason = classify_carrier_tls_alert(&error, &kind, &carrier_guard.status);
            break;
        }
        #[cfg(test)]
        for lease in &body_leases {
            lease.note_drained();
        }
        drop(body_leases);
        if events.send(WriterEvent::Drained).is_err() {
            break;
        }
    }
    let _ = events.send(WriterEvent::Stopped(stop_reason));
    drop(carrier_guard);
}

#[expect(
    clippy::too_many_lines,
    reason = "the copied coordinator keeps its single event loop and ordering invariants together"
)]
async fn coordinator_task(
    mut read: CarrierRead,
    channels: CoordinatorChannels,
    kind: CarrierKind,
    keepalive: KeepaliveConfig,
    carrier_guard: CarrierLiveGuard,
) {
    let CoordinatorChannels {
        mut commands,
        command_sender,
        mut body_ready,
        mut cancels,
        cancel_sender,
        writer_tx,
        mut writer_events,
    } = channels;
    let mut demux = CarrierDemux::new();
    let mut dialer = FrameDialer::default();
    let mut streams: HashMap<u32, StreamState> = HashMap::new();
    let mut ready = VecDeque::new();
    let mut writer = CoordinatorWriter::new(writer_tx);
    let mut buf = vec![0u8; READ_BUF_BYTES];
    let mut interval = tokio::time::interval(keepalive.interval);
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    interval.tick().await;
    let mut outstanding: Option<OutstandingProbe> = None;
    let mut missed = 0u32;
    let mut next_nonce = 1u64;

    loop {
        let step = tokio::select! {
            read_result = read.read(&mut buf) => {
                match read_result {
                    Ok(0) => CoordinatorStep::Stop,
                    Ok(n) => {
                        match handle_read(
                            &mut demux,
                            &mut streams,
                            &mut ready,
                            &mut writer,
                            &buf[..n],
                            &mut outstanding,
                            &mut missed,
                        ) {
                            Ok(()) => {
                                outstanding = None;
                                missed = 0;
                                CoordinatorStep::Continue
                            }
                            Err(error) => CoordinatorStep::Error(error),
                        }
                    }
                    Err(error) => classify_carrier_tls_alert(&error, &kind, &carrier_guard.status)
                        .map_or_else(
                            || CoordinatorStep::Error(writer_error("carrier read failed")),
                            CoordinatorStep::Error,
                        ),
                }
            }
            command = commands.recv() => {
                match command {
                    Some(CarrierCommand::OpenStream { pending, reply }) => {
                        let Some(input) = pending.claim() else {
                            let error = stopped_after_claim_error();
                            let _ = reply.send(Err(error));
                            continue;
                        };
                        let rx = open_stream_on_carrier(
                            input,
                            &mut dialer,
                            &mut demux,
                            &mut streams,
                            &mut ready,
                            command_sender.clone(),
                            cancel_sender.clone(),
                        );
                        let stream_id = rx.stream_id;
                        if let Err(error) = pump_ready(&mut writer, &mut streams, &mut ready) {
                            let _ = reply.send(Err(error));
                            CoordinatorStep::Error(writer_error("carrier upload pump failed"))
                        } else if reply.send(Ok(rx)).is_err() {
                            match reset_active_stream(
                                stream_id,
                                &mut demux,
                                &mut streams,
                                &mut writer,
                            ) {
                                Ok(()) => CoordinatorStep::Continue,
                                Err(error) => CoordinatorStep::Error(error),
                            }
                        } else {
                            CoordinatorStep::Continue
                        }
                    }
                    Some(CarrierCommand::Consume { stream_id, bytes }) => {
                        match consume_stream(stream_id, bytes, &mut demux, &mut writer) {
                            Ok(()) => CoordinatorStep::Continue,
                            Err(error) => CoordinatorStep::Error(error),
                        }
                    }
                    Some(CarrierCommand::Shutdown) | None => CoordinatorStep::Stop,
                }
            }
            stream_id = body_ready.recv() => {
                if let Some(stream_id) = stream_id {
                    let mut result = receive_body(
                        stream_id,
                        &mut demux,
                        &mut streams,
                        &mut ready,
                        &mut writer,
                    );
                    while result.is_ok() {
                        match body_ready.try_recv() {
                            Ok(stream_id) => {
                                result = receive_body(
                                    stream_id,
                                    &mut demux,
                                    &mut streams,
                                    &mut ready,
                                    &mut writer,
                                );
                            }
                            Err(_) => break,
                        }
                    }
                    match result {
                        Ok(()) => CoordinatorStep::Continue,
                        Err(error) => CoordinatorStep::Error(error),
                    }
                } else {
                    CoordinatorStep::Continue
                }
            }
            stream_id = cancels.recv() => {
                if let Some(stream_id) = stream_id {
                    match reset_active_stream(stream_id, &mut demux, &mut streams, &mut writer) {
                        Ok(()) => CoordinatorStep::Continue,
                        Err(error) => CoordinatorStep::Error(error),
                    }
                } else {
                    CoordinatorStep::Continue
                }
            }
            event = writer_events.recv() => {
                match event {
                    Some(WriterEvent::Drained) => {
                        writer.drained();
                        CoordinatorStep::Continue
                    }
                    Some(WriterEvent::Stopped(Some(error))) => CoordinatorStep::Error(error),
                    Some(WriterEvent::Stopped(None)) | None => {
                        CoordinatorStep::Error(writer_error("carrier writer stopped"))
                    }
                }
            }
            _ = interval.tick() => {
                match handle_keepalive(&mut writer, &mut outstanding, &mut missed, &mut next_nonce, keepalive) {
                    Ok(()) => CoordinatorStep::Continue,
                    Err(()) => CoordinatorStep::Error(writer_error("carrier keepalive failed")),
                }
            }
        };

        match step {
            CoordinatorStep::Continue => {
                if let Err(error) = flush_pending_deliveries(&mut demux, &mut streams, &mut writer)
                {
                    fanout_eof(&mut streams);
                    log_carrier_teardown(&kind, &transport_error_code(&error));
                    break;
                }
                if let Err(error) = pump_ready(&mut writer, &mut streams, &mut ready) {
                    fanout_eof(&mut streams);
                    log_carrier_teardown(&kind, &transport_error_code(&error));
                    break;
                }
            }
            CoordinatorStep::Stop => {
                fanout_eof(&mut streams);
                break;
            }
            CoordinatorStep::Error(error) => {
                if matches!(error, TransportError::TlsCertificateUnknown) {
                    fanout_certificate_unknown(&mut streams);
                } else {
                    fanout_eof(&mut streams);
                }
                log_carrier_teardown(&kind, &transport_error_code(&error));
                break;
            }
        }
    }

    drop(carrier_guard);
}

enum CoordinatorStep {
    Continue,
    Stop,
    Error(TransportError),
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

fn latch_tls_access_denied(status: &SharedStatus) {
    let mut record = lock_status(status);
    if record.snapshot.terminal_reason.is_none() {
        record.snapshot.terminal_reason = Some(JournalBridgeTerminalReason::TlsAccessDenied);
    }
}

fn relay_termination_error(kind: &CarrierKind) -> Option<crate::RelayError> {
    match kind {
        CarrierKind::Lan => None,
        CarrierKind::Relay { termination } => termination.current_error(),
    }
}

fn classify_carrier_tls_alert(
    error: &io::Error,
    kind: &CarrierKind,
    status: &SharedStatus,
) -> Option<TransportError> {
    let error = received_tls_alert(error)?;
    if relay_termination_error(kind).is_some() {
        return None;
    }
    if matches!(error, TransportError::TlsAccessDenied) {
        latch_tls_access_denied(status);
    }
    Some(error)
}

fn handle_read(
    demux: &mut CarrierDemux,
    streams: &mut HashMap<u32, StreamState>,
    ready: &mut VecDeque<u32>,
    writer: &mut CoordinatorWriter,
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
        send_writer(writer, pong, Vec::new())?;
    }
    for frame in out.emit_frames {
        send_writer(writer, frame, Vec::new())?;
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
            Some(Ok(())) => enqueue_ready(stream_id, streams, ready),
            Some(Err(violation)) => {
                log_frame_violation(violation);
                let reset = Frame::reset(stream_id, RESET_FLOW_CONTROL_ERROR)
                    .encode()
                    .map_err(|error| TransportError::Mux(MuxError::Frame(error)))?;
                send_writer(writer, reset, Vec::new())?;
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
    writer: &mut CoordinatorWriter,
) -> Result<(), TransportError> {
    if let Some(frame) = demux.consume(stream_id, bytes)? {
        send_writer(writer, frame, Vec::new())?;
    }
    Ok(())
}

fn open_stream_on_carrier(
    input: OpenStreamInput,
    dialer: &mut FrameDialer,
    demux: &mut CarrierDemux,
    streams: &mut HashMap<u32, StreamState>,
    ready: &mut VecDeque<u32>,
    commands: mpsc::Sender<CarrierCommand>,
    cancel: mpsc::UnboundedSender<u32>,
) -> StreamRx {
    let stream_id = dialer.allocate();
    let request_head = http::build_request_head(
        &input.method,
        &input.target,
        &input.headers,
        input.declared_body_len,
    );
    let (delivery, rx) = mpsc::channel(STREAM_QUEUE);
    let state = StreamState {
        upload: WindowedUpload::new(stream_id, &request_head, input.declared_body_len),
        declared_body_len: input.declared_body_len,
        received_body_len: 0,
        body: input.body,
        budget: input.budget,
        staged_leases: VecDeque::new(),
        delivery,
        pending_delivery: VecDeque::new(),
        ready_queued: true,
    };
    demux.open_stream(stream_id);
    streams.insert(stream_id, state);
    ready.push_back(stream_id);
    StreamRx {
        stream_id,
        rx,
        commands,
        cancel,
        terminal: false,
        early_final_status: None,
        certificate_unknown: false,
    }
}

fn deliver_stream_item(
    stream_id: u32,
    event: StreamEvent,
    demux: &mut CarrierDemux,
    streams: &mut HashMap<u32, StreamState>,
    writer: &mut CoordinatorWriter,
) -> Result<(), TransportError> {
    let early_head = match &event.item {
        StreamItem::Head(head) => streams
            .get(&stream_id)
            .filter(|state| !state.upload.is_done())
            .map(|_| head.clone()),
        _ => None,
    };
    if let Some(head) = early_head {
        if let Some(state) = streams.get(&stream_id) {
            let _ = state.delivery.try_send(DeliveryEvent::EarlyFinal(head));
        }
        return reset_active_stream(stream_id, demux, streams, writer);
    }

    let ended = matches!(event.item, StreamItem::End(_));
    let Some(state) = streams.get_mut(&stream_id) else {
        return Ok(());
    };
    if !state.pending_delivery.is_empty() {
        enqueue_pending_delivery(state, DeliveryEvent::Stream(event));
        return Ok(());
    }
    let sent = state.delivery.try_send(DeliveryEvent::Stream(event));

    match sent {
        Ok(()) => {
            if ended {
                streams.remove(&stream_id);
            }
        }
        Err(mpsc::error::TrySendError::Full(event)) => {
            if let Some(state) = streams.get_mut(&stream_id) {
                enqueue_pending_delivery(state, event);
            }
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            reset_active_stream(stream_id, demux, streams, writer)?;
        }
    }
    Ok(())
}

fn enqueue_pending_delivery(state: &mut StreamState, event: DeliveryEvent) {
    match event {
        DeliveryEvent::Stream(StreamEvent {
            item: StreamItem::Body(mut bytes),
            wire_cost,
        }) => {
            if let Some(DeliveryEvent::Stream(StreamEvent {
                item: StreamItem::Body(buffered),
                wire_cost: buffered_cost,
            })) = state.pending_delivery.back_mut()
            {
                buffered.append(&mut bytes);
                *buffered_cost += wire_cost;
            } else {
                state
                    .pending_delivery
                    .push_back(DeliveryEvent::Stream(StreamEvent {
                        item: StreamItem::Body(bytes),
                        wire_cost,
                    }));
            }
        }
        event => state.pending_delivery.push_back(event),
    }
}

fn flush_pending_deliveries(
    demux: &mut CarrierDemux,
    streams: &mut HashMap<u32, StreamState>,
    writer: &mut CoordinatorWriter,
) -> Result<(), TransportError> {
    let stream_ids: Vec<u32> = streams
        .iter()
        .filter_map(|(&stream_id, state)| (!state.pending_delivery.is_empty()).then_some(stream_id))
        .collect();
    for stream_id in stream_ids {
        let mut remove = false;
        let mut reset = false;
        if let Some(state) = streams.get_mut(&stream_id) {
            while let Some(event) = state.pending_delivery.pop_front() {
                let ended = matches!(
                    event,
                    DeliveryEvent::Stream(StreamEvent {
                        item: StreamItem::End(_),
                        ..
                    })
                );
                match state.delivery.try_send(event) {
                    Ok(()) => {
                        if ended {
                            remove = true;
                            break;
                        }
                    }
                    Err(mpsc::error::TrySendError::Full(event)) => {
                        state.pending_delivery.push_front(event);
                        break;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        reset = true;
                        break;
                    }
                }
            }
        }
        if reset {
            reset_active_stream(stream_id, demux, streams, writer)?;
        } else if remove {
            streams.remove(&stream_id);
        }
    }
    Ok(())
}

fn receive_body(
    stream_id: u32,
    demux: &mut CarrierDemux,
    streams: &mut HashMap<u32, StreamState>,
    ready: &mut VecDeque<u32>,
    writer: &mut CoordinatorWriter,
) -> Result<(), TransportError> {
    let mut short_body = false;
    let Some(state) = streams.get_mut(&stream_id) else {
        return Ok(());
    };
    loop {
        match state.body.try_recv() {
            Ok(chunk) => {
                state.upload.feed_body(&chunk.bytes).map_err(|error| {
                    TransportError::Io(io::Error::new(io::ErrorKind::InvalidInput, error))
                })?;
                state.received_body_len += chunk.bytes.len();
                state.staged_leases.push_back(chunk.lease);
            }
            Err(mpsc::error::TryRecvError::Empty) => break,
            Err(mpsc::error::TryRecvError::Disconnected) => {
                short_body = state.received_body_len < state.declared_body_len;
                break;
            }
        }
    }
    if short_body {
        return reset_active_stream(stream_id, demux, streams, writer);
    }
    enqueue_ready(stream_id, streams, ready);
    Ok(())
}

fn enqueue_ready(
    stream_id: u32,
    streams: &mut HashMap<u32, StreamState>,
    ready: &mut VecDeque<u32>,
) {
    if let Some(state) = streams.get_mut(&stream_id)
        && !state.ready_queued
    {
        state.ready_queued = true;
        ready.push_back(stream_id);
    }
}

/// Schedule upload frames according to `.proto-ref/framing.md` "ordering
/// guarantees": "emit at most one frame per stream before scheduling another
/// stream — round-robin, not greedy."
fn pump_ready(
    writer: &mut CoordinatorWriter,
    streams: &mut HashMap<u32, StreamState>,
    ready: &mut VecDeque<u32>,
) -> Result<(), TransportError> {
    while writer.has_upload_room() {
        let Some(stream_id) = ready.pop_front() else {
            break;
        };
        let Some(state) = streams.get_mut(&stream_id) else {
            continue;
        };
        state.ready_queued = false;
        let emitted = pump_upload_once(writer, state)?;
        if emitted && !state.upload.is_done() && !state.upload.is_blocked() {
            state.ready_queued = true;
            ready.push_back(stream_id);
        }
    }
    Ok(())
}

fn pump_upload_once(
    writer: &mut CoordinatorWriter,
    state: &mut StreamState,
) -> Result<bool, TransportError> {
    let emitted_before = state.upload.emitted_body_len();
    let Some(frame) = state
        .upload
        .poll_send()
        .map_err(|error| TransportError::Mux(MuxError::Frame(error)))?
    else {
        return Ok(false);
    };
    let body_bytes = state
        .upload
        .emitted_body_len()
        .saturating_sub(emitted_before);
    let body_leases = take_body_leases(&mut state.staged_leases, body_bytes)?;
    send_writer(writer, frame, body_leases)?;
    Ok(true)
}

fn take_body_leases(
    staged: &mut VecDeque<BodyLease>,
    bytes: usize,
) -> Result<Vec<BodyLease>, TransportError> {
    let mut remaining = bytes;
    let mut leases = Vec::new();
    while remaining > 0 {
        let Some(front) = staged.front_mut() else {
            return Err(TransportError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "request body budget accounting underflow",
            )));
        };
        if front.len() <= remaining {
            let Some(lease) = staged.pop_front() else {
                return Err(TransportError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "request body budget accounting underflow",
                )));
            };
            remaining -= lease.len();
            leases.push(lease);
        } else {
            let Some(lease) = front.split(remaining) else {
                return Err(TransportError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "request body budget accounting could not divide a reservation",
                )));
            };
            leases.push(lease);
            remaining = 0;
        }
    }
    Ok(leases)
}

fn reset_active_stream(
    stream_id: u32,
    demux: &mut CarrierDemux,
    streams: &mut HashMap<u32, StreamState>,
    writer: &mut CoordinatorWriter,
) -> Result<(), TransportError> {
    if streams.remove(&stream_id).is_none() {
        return Ok(());
    }
    demux.remove_stream(stream_id);
    let frame = Frame::reset(stream_id, RESET_CANCEL)
        .encode()
        .map_err(|e| TransportError::Mux(MuxError::Frame(e)))?;
    send_writer(writer, frame, Vec::new())
}

fn fanout_eof(streams: &mut HashMap<u32, StreamState>) {
    for (_, state) in streams.drain() {
        let _ = state.delivery.try_send(DeliveryEvent::Stream(StreamEvent {
            item: StreamItem::End(StreamEnd::Eof),
            wire_cost: 0,
        }));
    }
}

fn fanout_certificate_unknown(streams: &mut HashMap<u32, StreamState>) {
    for (_, state) in streams.drain() {
        let _ = state.delivery.try_send(DeliveryEvent::CertificateUnknown);
    }
}

fn handle_keepalive(
    writer: &mut CoordinatorWriter,
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
    send_writer(writer, frame, Vec::new()).map_err(|_| ())?;
    *outstanding = Some(OutstandingProbe {
        nonce,
        deadline: now + keepalive.deadline,
    });
    Ok(())
}

fn send_writer(
    writer: &mut CoordinatorWriter,
    frame: Vec<u8>,
    body_leases: Vec<BodyLease>,
) -> Result<(), TransportError> {
    writer.send(WriterPacket {
        bytes: frame,
        body_leases,
    })
}

fn writer_error(reason: &'static str) -> TransportError {
    TransportError::Io(io::Error::new(io::ErrorKind::BrokenPipe, reason))
}

fn log_carrier_teardown(kind: &CarrierKind, fallback_code: &str) {
    let code = relay_termination_error(kind).map_or_else(
        || fallback_code.to_string(),
        |error| transport_error_code(&TransportError::Relay(error)),
    );
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
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};
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

    fn publish_test_carrier(status: &SharedStatus, status_identity: &Arc<()>) {
        let mut record = lock_status(status);
        record.current_carrier = Some(status_identity.clone());
        record.snapshot.carrier_live = true;
    }

    fn spawn_waiting_writer(
        status: SharedStatus,
        status_identity: Arc<()>,
    ) -> (mpsc::Sender<WriterPacket>, tokio::task::JoinHandle<()>) {
        let (client, _server) = tokio::io::duplex(1024);
        let stream: Box<dyn CarrierIo> = Box::new(client);
        let (_read, write) = split(stream);
        let (writer_tx, writer_rx) = mpsc::channel(WRITER_QUEUE);
        let (events_tx, _events_rx) = mpsc::unbounded_channel();
        let alive = Arc::new(AtomicBool::new(true));
        let task = tokio::spawn(writer_task(
            write,
            writer_rx,
            events_tx,
            CarrierKind::Lan,
            CarrierLiveGuard::new(alive, status, status_identity),
        ));
        (writer_tx, task)
    }

    struct AlertWriteStream {
        description: rustls::AlertDescription,
    }

    impl AsyncRead for AlertWriteStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for AlertWriteStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                rustls::Error::AlertReceived(self.description),
            )))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn spawn_access_denied_writer(
        status: SharedStatus,
        status_identity: Arc<()>,
        kind: CarrierKind,
    ) -> (
        mpsc::Sender<WriterPacket>,
        mpsc::UnboundedReceiver<WriterEvent>,
        tokio::task::JoinHandle<()>,
    ) {
        spawn_alert_writer(
            status,
            status_identity,
            kind,
            rustls::AlertDescription::AccessDenied,
        )
    }

    fn spawn_alert_writer(
        status: SharedStatus,
        status_identity: Arc<()>,
        kind: CarrierKind,
        description: rustls::AlertDescription,
    ) -> (
        mpsc::Sender<WriterPacket>,
        mpsc::UnboundedReceiver<WriterEvent>,
        tokio::task::JoinHandle<()>,
    ) {
        let stream: Box<dyn CarrierIo> = Box::new(AlertWriteStream { description });
        let (_read, write) = split(stream);
        let (writer_tx, writer_rx) = mpsc::channel(WRITER_QUEUE);
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let alive = Arc::new(AtomicBool::new(true));
        let task = tokio::spawn(writer_task(
            write,
            writer_rx,
            events_tx,
            kind,
            CarrierLiveGuard::new(alive, status, status_identity),
        ));
        (writer_tx, events_rx, task)
    }

    struct CountingFailOpener {
        dials: Arc<AtomicUsize>,
    }

    impl CarrierOpener for CountingFailOpener {
        fn proxy_headers(
            &self,
            upstream_headers: &[(String, String)],
        ) -> Result<Vec<(String, String)>, TransportError> {
            Ok(upstream_headers.to_vec())
        }

        fn dial_carrier(
            &self,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<crate::client::DialedCarrier, TransportError>>
                    + Send
                    + '_,
            >,
        > {
            self.dials.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err(TransportError::NoEndpoint) })
        }
    }

    struct InjectedTlsErrorStream {
        error: rustls::Error,
        fired: Arc<AtomicBool>,
        waker: Arc<std::sync::Mutex<Option<Waker>>>,
    }

    impl AsyncRead for InjectedTlsErrorStream {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.fired.load(Ordering::SeqCst) {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    self.error.clone(),
                )));
            }
            *self.waker.lock().unwrap() = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    impl AsyncWrite for InjectedTlsErrorStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct InjectedTlsErrorOpener {
        dials: Arc<AtomicUsize>,
        error: rustls::Error,
        fired: Arc<AtomicBool>,
        waker: Arc<std::sync::Mutex<Option<Waker>>>,
        kind: CarrierKind,
    }

    impl CarrierOpener for InjectedTlsErrorOpener {
        fn proxy_headers(
            &self,
            upstream_headers: &[(String, String)],
        ) -> Result<Vec<(String, String)>, TransportError> {
            Ok(upstream_headers.to_vec())
        }

        fn dial_carrier(
            &self,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<crate::client::DialedCarrier, TransportError>>
                    + Send
                    + '_,
            >,
        > {
            self.dials.fetch_add(1, Ordering::SeqCst);
            let stream = InjectedTlsErrorStream {
                error: self.error.clone(),
                fired: self.fired.clone(),
                waker: self.waker.clone(),
            };
            let kind = self.kind.clone();
            Box::pin(async move {
                Ok(crate::client::DialedCarrier::from_test_parts(
                    Box::new(stream),
                    kind,
                ))
            })
        }
    }

    struct AlertWriteOpener {
        dials: Arc<AtomicUsize>,
        description: rustls::AlertDescription,
        kind: CarrierKind,
    }

    impl CarrierOpener for AlertWriteOpener {
        fn proxy_headers(
            &self,
            upstream_headers: &[(String, String)],
        ) -> Result<Vec<(String, String)>, TransportError> {
            Ok(upstream_headers.to_vec())
        }

        fn dial_carrier(
            &self,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<crate::client::DialedCarrier, TransportError>>
                    + Send
                    + '_,
            >,
        > {
            self.dials.fetch_add(1, Ordering::SeqCst);
            let stream = AlertWriteStream {
                description: self.description,
            };
            let kind = self.kind.clone();
            Box::pin(async move {
                Ok(crate::client::DialedCarrier::from_test_parts(
                    Box::new(stream),
                    kind,
                ))
            })
        }
    }

    fn fire_injected_error(fired: &AtomicBool, waker: &std::sync::Mutex<Option<Waker>>) {
        fired.store(true, Ordering::SeqCst);
        if let Some(waker) = waker.lock().unwrap().take() {
            waker.wake();
        }
    }

    struct DropFlagDuplexStream {
        inner: DuplexStream,
        dropped: Arc<AtomicBool>,
    }

    impl AsyncRead for DropFlagDuplexStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for DropFlagDuplexStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    impl Drop for DropFlagDuplexStream {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    struct LatchingDuplexOpener {
        status: SharedStatus,
        dials: Arc<AtomicUsize>,
        dropped: Arc<AtomicBool>,
        peer: Arc<std::sync::Mutex<Option<DuplexStream>>>,
    }

    impl CarrierOpener for LatchingDuplexOpener {
        fn proxy_headers(
            &self,
            upstream_headers: &[(String, String)],
        ) -> Result<Vec<(String, String)>, TransportError> {
            Ok(upstream_headers.to_vec())
        }

        fn dial_carrier(
            &self,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<crate::client::DialedCarrier, TransportError>>
                    + Send
                    + '_,
            >,
        > {
            let status = self.status.clone();
            let dials = self.dials.clone();
            let dropped = self.dropped.clone();
            let peer = self.peer.clone();
            Box::pin(async move {
                dials.fetch_add(1, Ordering::SeqCst);
                let (client, server) = tokio::io::duplex(1024);
                *peer.lock().unwrap() = Some(server);
                let stream = DropFlagDuplexStream {
                    inner: client,
                    dropped,
                };
                latch_tls_access_denied(&status);
                Ok(crate::client::DialedCarrier::from_test_parts(
                    Box::new(stream),
                    CarrierKind::Lan,
                ))
            })
        }
    }

    #[derive(Clone)]
    struct TestCarrier {
        commands: mpsc::Sender<CarrierCommand>,
        body_ready: mpsc::UnboundedSender<u32>,
    }

    fn spawn_duplex_carrier(
        keepalive: KeepaliveConfig,
        capacity: usize,
    ) -> (TestCarrier, Arc<AtomicBool>, DuplexStream) {
        let (client, server) = tokio::io::duplex(capacity);
        let stream: Box<dyn CarrierIo> = Box::new(client);
        let (read, write) = split(stream);
        let (commands_tx, commands_rx) = mpsc::channel(COMMAND_QUEUE);
        let (writer_tx, writer_rx) = mpsc::channel(WRITER_QUEUE);
        let (writer_events_tx, writer_events_rx) = mpsc::unbounded_channel();
        let (body_ready_tx, body_ready_rx) = mpsc::unbounded_channel();
        let (cancel_tx, cancel_rx) = mpsc::unbounded_channel();
        let alive = Arc::new(AtomicBool::new(true));
        let status = crate::journal_bridge::new_status();
        let status_identity = Arc::new(());
        publish_test_carrier(&status, &status_identity);
        tokio::spawn(writer_task(
            write,
            writer_rx,
            writer_events_tx,
            CarrierKind::Lan,
            CarrierLiveGuard::new(alive.clone(), status.clone(), status_identity.clone()),
        ));
        tokio::spawn(coordinator_task(
            read,
            CoordinatorChannels {
                commands: commands_rx,
                command_sender: commands_tx.clone(),
                body_ready: body_ready_rx,
                cancels: cancel_rx,
                cancel_sender: cancel_tx.clone(),
                writer_tx,
                writer_events: writer_events_rx,
            },
            CarrierKind::Lan,
            keepalive,
            CarrierLiveGuard::new(alive.clone(), status, status_identity),
        ));
        (
            TestCarrier {
                commands: commands_tx,
                body_ready: body_ready_tx,
            },
            alive,
            server,
        )
    }

    #[tokio::test]
    async fn carrier_status_clears_when_writer_task_is_aborted() {
        let status = crate::journal_bridge::new_status();
        let status_identity = Arc::new(());
        publish_test_carrier(&status, &status_identity);
        let (_writer, task) = spawn_waiting_writer(status.clone(), status_identity);

        task.abort();
        let _ = task.await;

        assert!(!lock_status(&status).snapshot.carrier_live);
    }

    #[tokio::test]
    async fn aborted_replaced_writer_does_not_clear_live_successor() {
        let status = crate::journal_bridge::new_status();
        let old_identity = Arc::new(());
        publish_test_carrier(&status, &old_identity);
        let (_writer, task) = spawn_waiting_writer(status.clone(), old_identity);
        let successor_identity = Arc::new(());
        publish_test_carrier(&status, &successor_identity);

        task.abort();
        let _ = task.await;

        let record = lock_status(&status);
        assert!(record.snapshot.carrier_live);
        assert!(
            record
                .current_carrier
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &successor_identity))
        );
    }

    // Falsified by removing the writer-side classification call: the scripted writer still
    // stops, but this assertion observes no terminal reason. Real rustls writes do not expose
    // received alerts, so this seam deliberately injects the typed I/O error.
    #[tokio::test]
    async fn writer_latches_scripted_access_denied_before_stopping() {
        let status = crate::journal_bridge::new_status();
        let status_identity = Arc::new(());
        publish_test_carrier(&status, &status_identity);
        let (writer, mut events, task) =
            spawn_access_denied_writer(status.clone(), status_identity, CarrierKind::Lan);

        writer
            .send(WriterPacket {
                bytes: vec![1],
                body_leases: Vec::new(),
            })
            .await
            .unwrap();
        assert!(matches!(events.recv().await, Some(WriterEvent::Stopped(_))));
        assert_eq!(
            lock_status(&status).snapshot.terminal_reason,
            Some(JournalBridgeTerminalReason::TlsAccessDenied)
        );
        task.await.unwrap();
    }

    // Falsified by removing the write-once latch assignment: an old carrier cleanup leaves the
    // successor live but the terminal reason absent, which this assertion rejects.
    #[test]
    fn terminal_reason_survives_old_carrier_cleanup() {
        let status = crate::journal_bridge::new_status();
        let old_identity = Arc::new(());
        let successor_identity = Arc::new(());
        publish_test_carrier(&status, &old_identity);
        latch_tls_access_denied(&status);
        publish_test_carrier(&status, &successor_identity);

        mark_carrier_dead(&status, &old_identity);

        let record = lock_status(&status);
        assert!(record.snapshot.carrier_live);
        assert_eq!(
            record.snapshot.terminal_reason,
            Some(JournalBridgeTerminalReason::TlsAccessDenied)
        );
    }

    // Falsified by bypassing relay termination precedence in the writer classifier: the scripted
    // error would set a terminal reason despite the recorded relay close taking priority.
    #[tokio::test]
    async fn writer_preserves_recorded_relay_termination_precedence() {
        let status = crate::journal_bridge::new_status();
        let status_identity = Arc::new(());
        publish_test_carrier(&status, &status_identity);
        let termination = crate::relay::RelayTerminationHandle::new();
        termination.record_close_for_test(4401);
        let (writer, mut events, task) = spawn_access_denied_writer(
            status.clone(),
            status_identity,
            CarrierKind::Relay { termination },
        );

        writer
            .send(WriterPacket {
                bytes: vec![1],
                body_leases: Vec::new(),
            })
            .await
            .unwrap();
        assert!(matches!(events.recv().await, Some(WriterEvent::Stopped(_))));
        assert_eq!(lock_status(&status).snapshot.terminal_reason, None);
        task.await.unwrap();
    }

    // Protocol: `.proto-ref/session.md`, lines 189-198. Falsified by restoring the
    // writer_error("carrier read failed") fallback in coordinator_task's read arm:
    // carrier_failure stays None and the named 46 never reaches the in-flight stream.
    #[tokio::test]
    async fn reader_certificate_unknown_reaches_inflight_stream_without_latch() {
        let status = crate::journal_bridge::new_status();
        let fired = Arc::new(AtomicBool::new(false));
        let waker = Arc::new(std::sync::Mutex::new(None));
        let dials = Arc::new(AtomicUsize::new(0));
        let hook_calls = Arc::new(AtomicUsize::new(0));
        let hook_calls_for_hook = hook_calls.clone();
        let carrier = MuxCarrier {
            opener: Arc::new(InjectedTlsErrorOpener {
                dials: dials.clone(),
                error: rustls::Error::AlertReceived(rustls::AlertDescription::CertificateUnknown),
                fired: fired.clone(),
                waker: waker.clone(),
                kind: CarrierKind::Lan,
            }),
            slot: Mutex::new(None),
            keepalive: KeepaliveConfig::default(),
            status: status.clone(),
            redial_hook: Some(Arc::new(move || {
                hook_calls_for_hook.fetch_add(1, Ordering::SeqCst);
            })),
        };

        let opened = carrier
            .open_stream("GET", "/healthz", &[], 0)
            .await
            .unwrap();
        let mut rx = opened.response;
        fire_injected_error(&fired, &waker);
        let _ = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("in-flight stream should finish");
        assert!(matches!(
            rx.carrier_failure(),
            Some(TransportError::TlsCertificateUnknown)
        ));
        assert_eq!(lock_status(&status).snapshot.terminal_reason, None);

        let hook_before = hook_calls.load(Ordering::SeqCst);
        let dials_before = dials.load(Ordering::SeqCst);
        let _ = carrier.get_or_dial().await;
        assert!(hook_calls.load(Ordering::SeqCst) > hook_before);
        assert!(dials.load(Ordering::SeqCst) > dials_before);
    }

    // Protocol: `.proto-ref/session.md`, lines 193, 202-203. Falsified by broadening
    // received_tls_alert to every rustls::Error: DecryptError becomes named 46 or latches.
    #[tokio::test]
    async fn non_alert_rustls_error_is_not_certificate_unknown() {
        let status = crate::journal_bridge::new_status();
        let fired = Arc::new(AtomicBool::new(false));
        let waker = Arc::new(std::sync::Mutex::new(None));
        let dials = Arc::new(AtomicUsize::new(0));
        let carrier = MuxCarrier {
            opener: Arc::new(InjectedTlsErrorOpener {
                dials,
                error: rustls::Error::DecryptError,
                fired: fired.clone(),
                waker: waker.clone(),
                kind: CarrierKind::Lan,
            }),
            slot: Mutex::new(None),
            keepalive: KeepaliveConfig::default(),
            status: status.clone(),
            redial_hook: None,
        };

        let opened = carrier
            .open_stream("GET", "/healthz", &[], 0)
            .await
            .unwrap();
        let mut rx = opened.response;
        fire_injected_error(&fired, &waker);
        assert_stream_eof(&mut rx).await;
        assert!(rx.carrier_failure().is_none());
        assert_eq!(lock_status(&status).snapshot.terminal_reason, None);
    }

    // Protocol: `.proto-ref/session.md`, lines 189-193. Falsified by discarding the
    // classified writer error (always Stopped(None)): carrier_failure stays None.
    #[tokio::test]
    async fn writer_certificate_unknown_reaches_inflight_stream_without_latch() {
        let status = crate::journal_bridge::new_status();
        let dials = Arc::new(AtomicUsize::new(0));
        let carrier = MuxCarrier {
            opener: Arc::new(AlertWriteOpener {
                dials,
                description: rustls::AlertDescription::CertificateUnknown,
                kind: CarrierKind::Lan,
            }),
            slot: Mutex::new(None),
            keepalive: KeepaliveConfig::default(),
            status: status.clone(),
            redial_hook: None,
        };

        let opened = carrier
            .open_stream("GET", "/healthz", &[], 0)
            .await
            .unwrap();
        let mut rx = opened.response;
        let _ = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("in-flight stream should finish");
        assert!(matches!(
            rx.carrier_failure(),
            Some(TransportError::TlsCertificateUnknown)
        ));
        assert_eq!(lock_status(&status).snapshot.terminal_reason, None);
    }

    // Falsified by checking the TLS error before the recorded relay close: the in-flight
    // stream would then surface TlsCertificateUnknown and a terminal reason would latch.
    #[tokio::test]
    async fn writer_certificate_unknown_yields_to_recorded_relay_termination() {
        let status = crate::journal_bridge::new_status();
        let termination = crate::relay::RelayTerminationHandle::new();
        termination.record_close_for_test(4401);
        let dials = Arc::new(AtomicUsize::new(0));
        let carrier = MuxCarrier {
            opener: Arc::new(AlertWriteOpener {
                dials,
                description: rustls::AlertDescription::CertificateUnknown,
                kind: CarrierKind::Relay { termination },
            }),
            slot: Mutex::new(None),
            keepalive: KeepaliveConfig::default(),
            status: status.clone(),
            redial_hook: None,
        };

        let opened = carrier
            .open_stream("GET", "/healthz", &[], 0)
            .await
            .unwrap();
        let mut rx = opened.response;
        assert_stream_eof(&mut rx).await;
        assert!(rx.carrier_failure().is_none());
        assert_eq!(lock_status(&status).snapshot.terminal_reason, None);
    }

    // Falsified by moving the terminal check below cached-handle reuse: this call returns the
    // cached handle path instead of the terminal error, even though no opener dial is needed.
    #[tokio::test]
    async fn terminal_latch_precedes_cached_carrier_reuse() {
        let status = crate::journal_bridge::new_status();
        let status_identity = Arc::new(());
        publish_test_carrier(&status, &status_identity);
        let (commands, _commands_rx) = mpsc::channel(COMMAND_QUEUE);
        let (body_ready, _body_ready_rx) = mpsc::unbounded_channel();
        let handle = Arc::new(CarrierHandle {
            commands,
            body_ready,
            alive: Arc::new(AtomicBool::new(true)),
            status_identity,
            tasks: Mutex::new(None),
        });
        let dials = Arc::new(AtomicUsize::new(0));
        let carrier = MuxCarrier {
            opener: Arc::new(CountingFailOpener {
                dials: dials.clone(),
            }),
            slot: Mutex::new(Some(handle)),
            keepalive: KeepaliveConfig::default(),
            status: status.clone(),
            redial_hook: None,
        };
        latch_tls_access_denied(&status);

        assert!(matches!(
            carrier.get_or_dial().await,
            Err(TransportError::TlsAccessDenied)
        ));
        assert_eq!(dials.load(Ordering::SeqCst), 0);
    }

    // Falsified by removing the post-dead-carrier terminal check: the hook latches access denied
    // before dialing, so this call reaches the opener instead of returning the terminal error.
    #[tokio::test]
    async fn terminal_latch_after_dead_carrier_stops_redial() {
        let status = crate::journal_bridge::new_status();
        let status_identity = Arc::new(());
        publish_test_carrier(&status, &status_identity);
        let (commands, _commands_rx) = mpsc::channel(COMMAND_QUEUE);
        let (body_ready, _body_ready_rx) = mpsc::unbounded_channel();
        let handle = Arc::new(CarrierHandle {
            commands,
            body_ready,
            alive: Arc::new(AtomicBool::new(false)),
            status_identity,
            tasks: Mutex::new(None),
        });
        let dials = Arc::new(AtomicUsize::new(0));
        let hook_calls = Arc::new(AtomicUsize::new(0));
        let hook_status = status.clone();
        let hook_calls_for_hook = hook_calls.clone();
        let carrier = MuxCarrier {
            opener: Arc::new(CountingFailOpener {
                dials: dials.clone(),
            }),
            slot: Mutex::new(Some(handle)),
            keepalive: KeepaliveConfig::default(),
            status: status.clone(),
            redial_hook: Some(Arc::new(move || {
                hook_calls_for_hook.fetch_add(1, Ordering::SeqCst);
                latch_tls_access_denied(&hook_status);
            })),
        };

        assert!(matches!(
            carrier.get_or_dial().await,
            Err(TransportError::TlsAccessDenied)
        ));
        assert_eq!(hook_calls.load(Ordering::SeqCst), 1);
        assert_eq!(dials.load(Ordering::SeqCst), 0);
        let record = lock_status(&status);
        assert_eq!(
            record.snapshot.terminal_reason,
            Some(JournalBridgeTerminalReason::TlsAccessDenied)
        );
        assert!(!record.snapshot.carrier_live);
    }

    // Falsified by omitting the terminal recheck under the publish guard: a dial that latches
    // access denied still publishes its successor instead of dropping it before this call returns.
    #[tokio::test]
    async fn terminal_latch_during_dial_drops_successor_before_publish() {
        let status = crate::journal_bridge::new_status();
        let dials = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicBool::new(false));
        let peer = Arc::new(std::sync::Mutex::new(None));
        let carrier = MuxCarrier {
            opener: Arc::new(LatchingDuplexOpener {
                status: status.clone(),
                dials: dials.clone(),
                dropped: dropped.clone(),
                peer: peer.clone(),
            }),
            slot: Mutex::new(None),
            keepalive: KeepaliveConfig::default(),
            status: status.clone(),
            redial_hook: None,
        };

        assert!(matches!(
            carrier.get_or_dial().await,
            Err(TransportError::TlsAccessDenied)
        ));
        assert_eq!(dials.load(Ordering::SeqCst), 1);
        assert!(dropped.load(Ordering::SeqCst));
        assert!(peer.lock().unwrap().is_some());
        assert!(carrier.slot.lock().await.is_none());
        {
            let record = lock_status(&status);
            assert_eq!(
                record.snapshot.terminal_reason,
                Some(JournalBridgeTerminalReason::TlsAccessDenied)
            );
            assert!(record.current_carrier.is_none());
            assert!(!record.snapshot.carrier_live);
        }

        assert!(matches!(
            carrier.get_or_dial().await,
            Err(TransportError::TlsAccessDenied)
        ));
        assert_eq!(dials.load(Ordering::SeqCst), 1);
    }

    async fn open_test_stream(carrier: &TestCarrier, target: &str, body: Vec<u8>) -> StreamRx {
        let body_len = body.len();
        let (body_tx, response, _budget) = open_test_pipe(carrier, target, body_len).await;
        tokio::spawn(async move {
            for bytes in body.chunks(READ_BUF_BYTES) {
                let reservation = body_tx.reserve(bytes.len()).await.unwrap();
                body_tx
                    .send_reserved(reservation, bytes.to_vec())
                    .await
                    .unwrap();
            }
        });
        response
    }

    async fn open_test_pipe(
        carrier: &TestCarrier,
        target: &str,
        declared_body_len: usize,
    ) -> (BodyTx, StreamRx, Arc<BodyBudget>) {
        let (body_tx, body_rx) = mpsc::channel(BODY_QUEUE);
        let budget = BodyBudget::new();
        let (reply, rx) = oneshot::channel();
        let (return_input, _returned) = oneshot::channel();
        carrier
            .commands
            .send(CarrierCommand::OpenStream {
                pending: PendingOpen::new(
                    OpenStreamInput {
                        method: "POST".to_string(),
                        target: target.to_string(),
                        headers: Vec::new(),
                        declared_body_len,
                        body: body_rx,
                        budget: budget.clone(),
                    },
                    return_input,
                ),
                reply,
            })
            .await
            .unwrap();
        let response = rx.await.unwrap().unwrap();
        let body = BodyTx::new(
            body_tx,
            budget.clone(),
            carrier.body_ready.clone(),
            response.stream_id,
        );
        (body, response, budget)
    }

    async fn feed_test_body(body: BodyTx, bytes: usize, value: u8) -> Result<(), TransportError> {
        let mut remaining = bytes;
        while remaining > 0 {
            let count = remaining.min(READ_BUF_BYTES);
            let reservation = body.reserve(count).await?;
            body.send_reserved(reservation, vec![value; count]).await?;
            remaining -= count;
        }
        Ok(())
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

    fn drain_writer_frames_with_flag(
        writer: &mut CoordinatorWriter,
        writer_rx: &mut mpsc::Receiver<WriterPacket>,
        flag: u8,
    ) -> usize {
        let mut decoder = FrameDecoder::new();
        let mut matches = 0usize;
        while let Ok(packet) = writer_rx.try_recv() {
            decoder.feed(&packet.bytes);
            let frame = decoder.next_frame().unwrap().unwrap();
            matches += usize::from(frame.flags == flag);
            writer.drained();
        }
        matches
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
    async fn unclaimed_open_returns_untouched_input_for_one_retry() {
        let (_body_tx, body_rx) = mpsc::channel(BODY_QUEUE);
        let budget = BodyBudget::new();
        let input = OpenStreamInput {
            method: "POST".to_string(),
            target: "/retry".to_string(),
            headers: Vec::new(),
            declared_body_len: 17,
            body: body_rx,
            budget,
        };
        let (return_input, returned) = oneshot::channel();
        drop(PendingOpen::new(input, return_input));

        let returned = returned.await.unwrap();
        assert_eq!(returned.target, "/retry");
        assert_eq!(returned.declared_body_len, 17);
    }

    #[tokio::test(start_paused = true)]
    async fn claimed_open_is_disarmed_before_first_frame_and_ack() {
        let (carrier, _alive, mut server) =
            spawn_duplex_carrier(KeepaliveConfig::default(), INITIAL_WINDOW);
        let (body_tx, body_rx) = mpsc::channel(BODY_QUEUE);
        let budget = BodyBudget::new();
        let (reply, response) = oneshot::channel();
        let (return_input, returned) = oneshot::channel();
        carrier
            .commands
            .send(CarrierCommand::OpenStream {
                pending: PendingOpen::new(
                    OpenStreamInput {
                        method: "POST".to_string(),
                        target: "/claimed".to_string(),
                        headers: Vec::new(),
                        declared_body_len: 0,
                        body: body_rx,
                        budget,
                    },
                    return_input,
                ),
                reply,
            })
            .await
            .unwrap();
        let mut response = response.await.unwrap().unwrap();
        drop(body_tx);

        assert!(
            returned.await.is_err(),
            "claimed input must never return through the retry path"
        );
        let mut decoder = FrameDecoder::new();
        let first = next_frame(&mut server, &mut decoder).await;
        assert_eq!(first.stream_id, 1);
        assert_eq!(first.flags, FLAG_OPEN | FLAG_DATA);
        drop(server);
        assert_stream_eof(&mut response).await;
    }

    #[tokio::test(start_paused = true)]
    async fn carrier_bounds_body_read_ahead_when_credit_is_withheld() {
        for body_len in [
            UPLOAD_BODY_STAGE_CAPACITY / 2,
            INITIAL_WINDOW + UPLOAD_BODY_STAGE_CAPACITY + 17,
            INITIAL_WINDOW * 3 + 29,
        ] {
            let (carrier, _alive, mut server) =
                spawn_duplex_carrier(KeepaliveConfig::default(), INITIAL_WINDOW * 2);
            let mut decoder = FrameDecoder::new();
            let (body, mut response, budget) = open_test_pipe(&carrier, "/bounded", body_len).await;
            let producer = tokio::spawn(feed_test_body(body, body_len, b'x'));
            let request_head = http::build_request_head("POST", "/bounded", &[], body_len);
            let expected_before_grant = (request_head.len() + body_len).min(INITIAL_WINDOW);
            let mut data = 0usize;
            while data < expected_before_grant {
                let frame = next_frame(&mut server, &mut decoder).await;
                if frame.stream_id == 1 && frame.flags & FLAG_DATA != 0 {
                    data += frame.payload.len();
                }
            }
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }

            let snapshot = budget.snapshot();
            assert!(
                snapshot.peak_reserved <= UPLOAD_BODY_STAGE_CAPACITY,
                "reserved body bytes exceeded the fixed budget for total {body_len}"
            );
            assert!(
                snapshot.peak_read_ahead <= UPLOAD_BODY_STAGE_CAPACITY,
                "source read-ahead exceeded the fixed budget for total {body_len}"
            );
            assert!(snapshot.body_read <= body_len);
            assert!(snapshot.writer_drained <= snapshot.body_read);
            assert_eq!(
                snapshot.read_ahead,
                snapshot.body_read - snapshot.writer_drained
            );

            response.cancel();
            drop(server);
            if !producer.is_finished() {
                producer.abort();
            }
            let _ = producer.await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn carrier_streams_body_with_wire_and_budget_bounds() {
        const BODY_BYTES: usize = INITIAL_WINDOW * 3 + 777;

        let (carrier, _alive, mut server) =
            spawn_duplex_carrier(KeepaliveConfig::default(), RECOMMENDED_CHUNK * 2);
        let mut decoder = FrameDecoder::new();
        let (body, _response, budget) = open_test_pipe(&carrier, "/continuous", BODY_BYTES).await;
        let producer = tokio::spawn(feed_test_body(body, BODY_BYTES, b'c'));
        let request_head = http::build_request_head("POST", "/continuous", &[], BODY_BYTES);
        let expected_data = request_head.len() + BODY_BYTES;
        let mut available_credit = INITIAL_WINDOW;
        let mut data = 0usize;
        let mut open_count = 0usize;
        let mut close_count = 0usize;

        while close_count == 0 {
            let frame = next_frame(&mut server, &mut decoder).await;
            if frame.stream_id != 1 {
                continue;
            }
            if frame.flags & FLAG_OPEN != 0 {
                open_count += 1;
            }
            if frame.flags & FLAG_DATA != 0 {
                assert!(frame.payload.len() <= RECOMMENDED_CHUNK);
                assert!(frame.payload.len() <= available_credit);
                available_credit -= frame.payload.len();
                data += frame.payload.len();
                send_frame(
                    &mut server,
                    1,
                    FLAG_WINDOW,
                    &(frame.payload.len() as u32).to_be_bytes(),
                )
                .await;
                available_credit += frame.payload.len();
            }
            if frame.flags & FLAG_CLOSE != 0 {
                close_count += 1;
            }

            let snapshot = budget.snapshot();
            assert!(snapshot.peak_reserved <= UPLOAD_BODY_STAGE_CAPACITY);
            assert!(snapshot.peak_read_ahead <= UPLOAD_BODY_STAGE_CAPACITY);
        }

        producer.await.unwrap().unwrap();
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        let snapshot = budget.snapshot();
        assert_eq!(open_count, 1);
        assert_eq!(close_count, 1);
        assert_eq!(data, expected_data);
        assert_eq!(snapshot.body_read, BODY_BYTES);
        assert_eq!(snapshot.writer_drained, BODY_BYTES);
        assert_eq!(snapshot.reserved, 0);
        assert_eq!(snapshot.read_ahead, 0);
        assert!(
            tokio::time::timeout(
                Duration::from_millis(1),
                next_frame(&mut server, &mut decoder)
            )
            .await
            .is_err(),
            "CLOSE must be emitted exactly once"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn carrier_schedules_ready_uploads_round_robin() {
        // `.proto-ref/framing.md` "ordering guarantees": "emit at most one
        // frame per stream before scheduling another stream — round-robin, not
        // greedy."
        let (carrier, _alive, mut server) =
            spawn_duplex_carrier(KeepaliveConfig::default(), INITIAL_WINDOW);
        let mut decoder = FrameDecoder::new();
        let body_len = RECOMMENDED_CHUNK * 3;
        let (body_a, _rx_a, _budget_a) = open_test_pipe(&carrier, "/a", body_len).await;
        let (body_b, _rx_b, _budget_b) = open_test_pipe(&carrier, "/b", body_len).await;

        let mut opened = Vec::new();
        while opened.len() < 2 {
            let frame = next_frame(&mut server, &mut decoder).await;
            if frame.flags & FLAG_OPEN != 0 {
                opened.push(frame.stream_id);
            }
        }
        assert_eq!(opened, vec![1, 3]);

        let reservation_a = body_a.reserve(body_len).await.unwrap();
        body_a
            .send_without_wake(reservation_a, vec![b'a'; body_len])
            .await
            .unwrap();
        let reservation_b = body_b.reserve(body_len).await.unwrap();
        body_b
            .send_without_wake(reservation_b, vec![b'b'; body_len])
            .await
            .unwrap();
        body_a.notify().unwrap();
        body_b.notify().unwrap();

        let first = next_frame(&mut server, &mut decoder).await;
        let second = next_frame(&mut server, &mut decoder).await;
        assert_eq!(first.flags, FLAG_DATA);
        assert_eq!(second.flags, FLAG_DATA);
        assert_ne!(
            first.stream_id, second.stream_id,
            "one ready upload must not emit a second DATA frame before its sibling"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn carrier_short_body_resets_only_its_stream() {
        let (carrier, _alive, mut server) =
            spawn_duplex_carrier(KeepaliveConfig::default(), INITIAL_WINDOW);
        let mut decoder = FrameDecoder::new();
        let (body_a, mut rx_a, _budget_a) = open_test_pipe(&carrier, "/short", 100).await;
        let mut rx_b = open_test_stream(&carrier, "/sibling", Vec::new()).await;
        let reservation = body_a.reserve(50).await.unwrap();
        body_a
            .send_reserved(reservation, vec![b'a'; 50])
            .await
            .unwrap();
        drop(body_a);

        let mut reset_count = 0usize;
        let mut sibling_closed = false;
        while reset_count == 0 || !sibling_closed {
            let frame = next_frame(&mut server, &mut decoder).await;
            if frame.stream_id == 1 && frame.flags & FLAG_RESET != 0 {
                assert_eq!(frame.payload, vec![RESET_CANCEL]);
                reset_count += 1;
            }
            if frame.stream_id == 3 && frame.flags & FLAG_CLOSE != 0 {
                sibling_closed = true;
            }
        }
        assert_eq!(reset_count, 1);
        assert_eq!(rx_a.recv().await, None);

        let response = http_response(b"sibling-ok");
        send_frame(&mut server, 3, FLAG_DATA | FLAG_CLOSE, &response).await;
        assert_stream_completes(&mut rx_b, b"sibling-ok").await;
        assert!(
            tokio::time::timeout(
                Duration::from_millis(1),
                next_frame(&mut server, &mut decoder)
            )
            .await
            .is_err(),
            "short input must produce exactly one reset"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn carrier_dropped_blocked_source_resets_once_and_keeps_sibling_usable() {
        let body_len = INITIAL_WINDOW + UPLOAD_BODY_STAGE_CAPACITY * 2;
        let (carrier, _alive, mut server) =
            spawn_duplex_carrier(KeepaliveConfig::default(), INITIAL_WINDOW * 2);
        let mut decoder = FrameDecoder::new();
        let (body_a, mut rx_a, _budget_a) = open_test_pipe(&carrier, "/blocked", body_len).await;
        let mut rx_b = open_test_stream(&carrier, "/sibling", Vec::new()).await;
        let producer = tokio::spawn(feed_test_body(body_a, body_len, b'x'));

        let mut stream_a_data = 0usize;
        let mut sibling_closed = false;
        while stream_a_data < INITIAL_WINDOW || !sibling_closed {
            let frame = next_frame(&mut server, &mut decoder).await;
            if frame.stream_id == 1 && frame.flags & FLAG_DATA != 0 {
                stream_a_data += frame.payload.len();
            }
            if frame.stream_id == 3 && frame.flags & FLAG_CLOSE != 0 {
                sibling_closed = true;
            }
        }
        assert!(!producer.is_finished());
        producer.abort();
        let _ = producer.await;

        read_until_reset(&mut server, &mut decoder, 1).await;
        assert_eq!(rx_a.recv().await, None);
        let response = http_response(b"still-usable");
        send_frame(&mut server, 3, FLAG_DATA | FLAG_CLOSE, &response).await;
        assert_stream_completes(&mut rx_b, b"still-usable").await;
        assert!(
            tokio::time::timeout(
                Duration::from_millis(1),
                next_frame(&mut server, &mut decoder)
            )
            .await
            .is_err(),
            "a dropped blocked source must produce exactly one reset"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn carrier_cancel_bypasses_saturated_bounded_queues() {
        let (commands, mut command_rx) = mpsc::channel(1);
        commands.try_send(CarrierCommand::Shutdown).unwrap();
        let (cancel, mut cancels) = mpsc::unbounded_channel();
        let (delivery, delivery_rx) = mpsc::channel(1);
        let budget = BodyBudget::new();
        let (body_tx, body_rx) = mpsc::channel(1);
        let lease = budget.reserve(1).await.unwrap();
        body_tx
            .try_send(BodyChunk {
                bytes: vec![b'x'],
                lease,
            })
            .unwrap();
        let mut streams = HashMap::new();
        streams.insert(
            1,
            StreamState {
                upload: WindowedUpload::new(
                    1,
                    &http::build_request_head("POST", "/cancel", &[], 2),
                    2,
                ),
                declared_body_len: 2,
                received_body_len: 0,
                body: body_rx,
                budget,
                staged_leases: VecDeque::new(),
                delivery,
                pending_delivery: VecDeque::new(),
                ready_queued: false,
            },
        );
        let mut demux = CarrierDemux::new();
        demux.open_stream(1);
        let (writer_tx, mut writer_rx) = mpsc::channel(WRITER_QUEUE);
        let mut writer = CoordinatorWriter {
            tx: writer_tx,
            inflight: WRITER_QUEUE - 1,
        };
        let mut response = StreamRx {
            stream_id: 1,
            rx: delivery_rx,
            commands,
            cancel,
            terminal: false,
            early_final_status: None,
            certificate_unknown: false,
        };

        response.cancel();
        response.cancel();
        let stream_id = cancels.recv().await.unwrap();
        reset_active_stream(stream_id, &mut demux, &mut streams, &mut writer).unwrap();

        let packet = writer_rx.recv().await.unwrap();
        let mut decoder = FrameDecoder::new();
        decoder.feed(&packet.bytes);
        let reset = decoder.next_frame().unwrap().unwrap();
        assert_eq!(reset.stream_id, 1);
        assert_eq!(reset.flags, FLAG_RESET);
        assert_eq!(reset.payload, vec![RESET_CANCEL]);
        assert!(streams.is_empty());
        assert!(command_rx.try_recv().is_ok(), "command queue was saturated");
        assert!(
            tokio::time::timeout(Duration::from_millis(1), cancels.recv())
                .await
                .is_err(),
            "cancel must be delivered exactly once"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn carrier_upstream_reset_mid_upload_stops_only_that_source() {
        let body_len = INITIAL_WINDOW + UPLOAD_BODY_STAGE_CAPACITY * 4 + 91;
        let (carrier, _alive, mut server) =
            spawn_duplex_carrier(KeepaliveConfig::default(), INITIAL_WINDOW * 2);
        let mut decoder = FrameDecoder::new();
        let (body_a, mut rx_a, _budget_a) = open_test_pipe(&carrier, "/reset", body_len).await;
        let mut rx_b = open_test_stream(&carrier, "/sibling", Vec::new()).await;
        let producer = tokio::spawn(feed_test_body(body_a, body_len, b'r'));

        let first = next_frame(&mut server, &mut decoder).await;
        assert_eq!(first.stream_id, 1);
        assert_eq!(first.flags, FLAG_OPEN | FLAG_DATA);
        send_frame(&mut server, 1, FLAG_RESET, &[RESET_CANCEL]).await;
        assert_eq!(
            rx_a.recv().await,
            Some(StreamItem::End(StreamEnd::Reset(ResetReason::Unspecified)))
        );
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        assert!(producer.is_finished());
        assert!(producer.await.unwrap().is_err());

        read_request_close(&mut server, &mut decoder, 3).await;
        let response = http_response(b"sibling-ok");
        send_frame(&mut server, 3, FLAG_DATA | FLAG_CLOSE, &response).await;
        assert_stream_completes(&mut rx_b, b"sibling-ok").await;
        assert!(
            tokio::time::timeout(Duration::from_millis(1), async {
                loop {
                    let frame = next_frame(&mut server, &mut decoder).await;
                    if frame.stream_id == 1 && frame.flags & FLAG_RESET != 0 {
                        break;
                    }
                }
            })
            .await
            .is_err(),
            "peer reset must not trigger a local duplicate reset"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn carrier_early_final_stops_source_and_resets_once() {
        let (carrier, _alive, mut server) =
            spawn_duplex_carrier(KeepaliveConfig::default(), INITIAL_WINDOW);
        let mut decoder = FrameDecoder::new();
        let (body, mut response, budget) = open_test_pipe(&carrier, "/early", 100).await;
        let open = next_frame(&mut server, &mut decoder).await;
        assert_eq!(open.stream_id, 1);
        assert_eq!(open.flags, FLAG_OPEN | FLAG_DATA);

        let early = http_response(b"accepted");
        send_frame(&mut server, 1, FLAG_DATA | FLAG_CLOSE, &early).await;
        assert!(matches!(
            response.recv().await,
            Some(StreamItem::Head(HttpHead { status: 200, .. }))
        ));
        assert_eq!(response.early_final_status(), Some(200));
        read_until_reset(&mut server, &mut decoder, 1).await;
        assert!(body.reserve(1).await.is_err());
        drop(body);
        assert_eq!(budget.snapshot().reserved, 0);
        assert!(
            tokio::time::timeout(
                Duration::from_millis(1),
                next_frame(&mut server, &mut decoder)
            )
            .await
            .is_err(),
            "early final response must produce exactly one reset"
        );
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
        tokio::time::timeout(Duration::from_secs(1), async {
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
        })
        .await
        .expect("both uploads should emit their initial-window bytes");
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

    #[tokio::test]
    async fn carrier_reserves_writer_headroom_for_ping_burst() {
        // `.proto-ref/framing.md` "initiator behavior": receivers MUST tolerate
        // PING at any cadence, including bursts, without rate-limiting.
        const PING_COUNT: usize = 8;

        let (writer_tx, mut writer_rx) = mpsc::channel(WRITER_QUEUE);
        let mut writer = CoordinatorWriter::new(writer_tx);
        let mut demux = CarrierDemux::new();
        let mut dialer = FrameDialer::default();
        let mut streams = HashMap::new();
        let mut ready = VecDeque::new();
        let (commands, _command_rx) = mpsc::channel(COMMAND_QUEUE);
        let (cancel, _cancels) = mpsc::unbounded_channel();
        let (_body_a, body_rx_a) = mpsc::channel(BODY_QUEUE);
        let (_body_b, body_rx_b) = mpsc::channel(BODY_QUEUE);
        let mut rx_a = open_stream_on_carrier(
            OpenStreamInput {
                method: "GET".to_string(),
                target: "/a".to_string(),
                headers: Vec::new(),
                declared_body_len: 0,
                body: body_rx_a,
                budget: BodyBudget::new(),
            },
            &mut dialer,
            &mut demux,
            &mut streams,
            &mut ready,
            commands.clone(),
            cancel.clone(),
        );
        let mut rx_b = open_stream_on_carrier(
            OpenStreamInput {
                method: "GET".to_string(),
                target: "/b".to_string(),
                headers: Vec::new(),
                declared_body_len: 0,
                body: body_rx_b,
                budget: BodyBudget::new(),
            },
            &mut dialer,
            &mut demux,
            &mut streams,
            &mut ready,
            commands,
            cancel,
        );
        pump_ready(&mut writer, &mut streams, &mut ready).unwrap();
        while writer_rx.try_recv().is_ok() {
            writer.drained();
        }

        let upload_frame = Frame::new(1, FLAG_DATA, vec![b'x']).encode().unwrap();
        while writer.has_upload_room() {
            send_writer(&mut writer, upload_frame.clone(), Vec::new()).unwrap();
        }
        assert_eq!(writer.inflight, WRITER_QUEUE - CONTROL_RESERVE);

        let mut burst = Vec::new();
        for nonce in 0..PING_COUNT {
            burst.extend_from_slice(&Frame::control_ping([nonce as u8; 8]).encode().unwrap());
        }
        let mut outstanding = None;
        let mut missed = 0;
        handle_read(
            &mut demux,
            &mut streams,
            &mut ready,
            &mut writer,
            &burst,
            &mut outstanding,
            &mut missed,
        )
        .unwrap();

        assert_eq!(
            drain_writer_frames_with_flag(&mut writer, &mut writer_rx, FLAG_PONG),
            PING_COUNT
        );

        let response = Frame::new(3, FLAG_DATA | FLAG_CLOSE, http_response(b"ok"))
            .encode()
            .unwrap();
        handle_read(
            &mut demux,
            &mut streams,
            &mut ready,
            &mut writer,
            &response,
            &mut outstanding,
            &mut missed,
        )
        .unwrap();
        assert_stream_completes(&mut rx_b, b"ok").await;
        assert!(streams.contains_key(&rx_a.stream_id));
        rx_a.cancel();
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
    async fn carrier_delivery_queue_pressure_preserves_complete_stream() {
        let (commands, _alive, mut server) =
            spawn_duplex_carrier(KeepaliveConfig::default(), 512 * 1024);
        let mut decoder = FrameDecoder::new();
        let mut rx_a = open_test_stream(&commands, "/pressured", Vec::new()).await;
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
        send_frame(&mut server, 1, FLAG_CLOSE, b"").await;
        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                next_frame(&mut server, &mut decoder)
            )
            .await
            .is_err(),
            "scheduler pressure must not reset a valid response stream"
        );
        assert_stream_completes(&mut rx_a, &[b'x'; STREAM_QUEUE + 4]).await;

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
