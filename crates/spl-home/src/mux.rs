// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Pure listener-side SPL mux state machine.

use std::collections::HashMap;

use spl_core::frame::{
    CONTROL_NONCE_LEN, FLAG_CLOSE, FLAG_DATA, FLAG_OPEN, FLAG_PING, FLAG_PONG, FLAG_RESET,
    FLAG_WINDOW, Frame, FrameDecoder, FrameViolation, HEADER_LEN, RECOMMENDED_CHUNK, RESET_CANCEL,
    RESET_FLOW_CONTROL_ERROR, RESET_INTERNAL_ERROR, RESET_PROTOCOL_ERROR,
    RESET_STREAM_LIMIT_EXCEEDED, RESET_UNSPECIFIED, flags_valid,
};
use spl_core::mux::{INITIAL_WINDOW, RecvWindow};

use crate::{HomeError, MuxLimits, Refusal, RefusalClass};

const MAX_SEND_CREDIT: u64 = (1 << 31) - 1;

/// Pure listener-side mux state, independent of carrier I/O and clocks.
pub struct MuxAcceptor {
    limits: MuxLimits,
    decoder: FrameDecoder,
    decoder_buffered_bytes: usize,
    header_buffer: Vec<u8>,
    payload_remaining: Option<usize>,
    discarded_payload_remaining: Option<usize>,
    peer_high_water: Option<u32>,
    streams: HashMap<u32, StreamState>,
    next_listener_id: Option<u32>,
}

/// Frames to write and application-visible events produced by one mux action.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct MuxOutput {
    /// Frames that the carrier writer must send, in priority order.
    pub frames: Vec<Frame>,
    /// Events for the local stream-handle layer.
    pub events: Vec<MuxEvent>,
    /// Header-only classifications for peer frames refused by this endpoint.
    pub refusals: Vec<Refusal>,
}

/// An application-visible event from the peer-facing mux.
#[derive(Debug, PartialEq, Eq)]
pub enum MuxEvent {
    /// The peer opened a stream.
    Opened {
        /// Newly opened peer-owned odd stream identifier.
        stream_id: u32,
    },
    /// The peer supplied ordered bytes for a live stream.
    Data {
        /// Stream receiving the bytes.
        stream_id: u32,
        /// Opaque bytes, deliberately not inspected by this layer.
        bytes: Vec<u8>,
    },
    /// The peer half-closed its writer; the local reader should observe EOF.
    ReadClosed {
        /// Stream whose peer writer closed.
        stream_id: u32,
    },
    /// The peer reset a stream.
    Reset {
        /// Stream the peer reset.
        stream_id: u32,
        /// Tolerantly decoded reset reason.
        reason: ResetReason,
    },
    /// The carrier ended, with whether a partial frame was locally observed.
    PeerGone {
        /// Whether locally counted undecoded bytes prove frame truncation.
        truncated: bool,
    },
}

/// A SPL reset reason, including the specified fallback for unknown values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetReason {
    /// The peer violated a framing rule.
    ProtocolError,
    /// The peer exceeded flow-control credit.
    FlowControlError,
    /// The peer exceeded the concurrent-stream cap.
    StreamLimitExceeded,
    /// The peer reported an endpoint-local failure.
    InternalError,
    /// The peer cancelled a stream.
    Cancel,
    /// The peer supplied an unknown reset code.
    Unspecified,
}

struct StreamState {
    receive_window: RecvWindow,
    debited_not_consumed: usize,
    send_credit: u64,
    peer_closed: bool,
    local_closed: bool,
}

impl MuxAcceptor {
    /// Construct an acceptor after validating its protocol-derived limits.
    ///
    /// # Errors
    ///
    /// Returns [`HomeError::Config`] when the limits cannot satisfy the
    /// frame-buffer reservation.
    pub fn new(limits: MuxLimits) -> Result<Self, HomeError> {
        limits.validate()?;
        Ok(Self {
            limits,
            decoder: FrameDecoder::new(),
            decoder_buffered_bytes: 0,
            header_buffer: Vec::with_capacity(HEADER_LEN),
            payload_remaining: None,
            discarded_payload_remaining: None,
            peer_high_water: None,
            streams: HashMap::new(),
            next_listener_id: Some(2),
        })
    }

    /// Feed carrier bytes into the decoder and process every complete frame.
    ///
    /// # Errors
    ///
    /// Returns a classified fatal error for malformed stream-zero control or a
    /// frame-decoding error. Per-stream protocol errors are returned in the
    /// output as RESET frames and refusals.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<MuxOutput, HomeError> {
        let mut output = MuxOutput::default();
        for byte in bytes {
            if let Some(remaining) = self.discarded_payload_remaining {
                self.discarded_payload_remaining = (remaining > 1).then_some(remaining - 1);
                continue;
            }
            if self.decoder_buffered_bytes >= self.limits.decoder_buffer_bytes {
                return Err(HomeError::Refused(Refusal {
                    class: RefusalClass::FlowControl,
                    violation: None,
                }));
            }
            self.decoder_buffered_bytes =
                self.decoder_buffered_bytes
                    .checked_add(1)
                    .ok_or(HomeError::Refused(Refusal {
                        class: RefusalClass::Internal,
                        violation: None,
                    }))?;
            if self.payload_remaining.is_none() {
                self.header_buffer.push(*byte);
                if self.header_buffer.len() != HEADER_LEN {
                    continue;
                }
                let stream_id = u32::from_be_bytes([
                    self.header_buffer[0],
                    self.header_buffer[1],
                    self.header_buffer[2],
                    self.header_buffer[3],
                ]);
                let flags = self.header_buffer[4];
                let payload_length = ((self.header_buffer[5] as usize) << 16)
                    | ((self.header_buffer[6] as usize) << 8)
                    | self.header_buffer[7] as usize;
                if flags & spl_core::frame::FLAG_RESERVED_MASK != 0 {
                    let frame_violation = FrameViolation {
                        stream_id,
                        flags,
                        length: payload_length,
                    };
                    self.header_buffer.clear();
                    self.decoder_buffered_bytes = self
                        .decoder_buffered_bytes
                        .checked_sub(HEADER_LEN)
                        .ok_or(HomeError::Refused(Refusal {
                            class: RefusalClass::Internal,
                            violation: None,
                        }))?;
                    self.discarded_payload_remaining =
                        (payload_length > 0).then_some(payload_length);
                    if stream_id == 0 {
                        return Err(HomeError::Refused(Refusal {
                            class: RefusalClass::Protocol,
                            violation: Some(frame_violation),
                        }));
                    }
                    self.refuse_violation(frame_violation, RefusalClass::Protocol, &mut output);
                    continue;
                }
                self.decoder.feed(&self.header_buffer);
                self.header_buffer.clear();
                self.payload_remaining = (payload_length > 0).then_some(payload_length);
                self.drain_decoder(&mut output)?;
                continue;
            }

            self.decoder.feed(std::slice::from_ref(byte));
            if let Some(remaining) = self.payload_remaining {
                self.payload_remaining = (remaining > 1).then_some(remaining - 1);
            }
            self.drain_decoder(&mut output)?;
        }
        Ok(output)
    }

    /// Mark bytes previously delivered in a [`MuxEvent::Data`] event consumed.
    ///
    /// # Errors
    ///
    /// Returns an internal refusal instead of calling [`RecvWindow::consume`]
    /// when the caller asks to consume more bytes than this acceptor debited.
    pub fn consume(&mut self, stream_id: u32, bytes: usize) -> Result<MuxOutput, HomeError> {
        let grant = {
            let stream = self.streams.get_mut(&stream_id).ok_or(HomeError::Closed)?;
            if bytes > stream.debited_not_consumed {
                return Err(HomeError::Refused(Refusal {
                    class: RefusalClass::Internal,
                    violation: None,
                }));
            }
            // This local check makes RecvWindow's documented panic unreachable
            // from peer data and from an over-consuming caller.
            let grant = stream.receive_window.consume(bytes as u64);
            stream.debited_not_consumed =
                stream
                    .debited_not_consumed
                    .checked_sub(bytes)
                    .ok_or(HomeError::Refused(Refusal {
                        class: RefusalClass::Internal,
                        violation: None,
                    }))?;
            grant
        };

        let mut output = MuxOutput::default();
        if let Some(grant) = grant {
            output.frames.push(Frame::window(stream_id, grant));
        }
        Ok(output)
    }

    /// Send one listener-to-peer DATA frame when the peer has granted credit.
    ///
    /// Returns `Ok(None)` when the peer's advertised send credit is exhausted.
    ///
    /// # Errors
    ///
    /// Returns [`HomeError::Closed`] for a forgotten or locally closed stream,
    /// and an internal refusal if the driver exceeds the framing chunk limit.
    pub fn try_send_data(
        &mut self,
        stream_id: u32,
        bytes: Vec<u8>,
    ) -> Result<Option<MuxOutput>, HomeError> {
        if bytes.len() > RECOMMENDED_CHUNK {
            return Err(HomeError::Refused(Refusal {
                class: RefusalClass::Internal,
                violation: None,
            }));
        }
        let stream = self.streams.get_mut(&stream_id).ok_or(HomeError::Closed)?;
        if stream.local_closed {
            return Err(HomeError::Closed);
        }
        let bytes_len = bytes.len() as u64;
        if bytes_len > stream.send_credit {
            return Ok(None);
        }
        stream.send_credit =
            stream
                .send_credit
                .checked_sub(bytes_len)
                .ok_or(HomeError::Refused(Refusal {
                    class: RefusalClass::Internal,
                    violation: None,
                }))?;
        Ok(Some(MuxOutput {
            frames: vec![Frame::new(stream_id, FLAG_DATA, bytes)],
            events: Vec::new(),
            refusals: Vec::new(),
        }))
    }

    /// Reserve the next listener-owned even identifier for a future stream.
    ///
    /// This deliberately allocates only an identifier; listener-originated
    /// stream lifecycle is not exposed in this pass.
    ///
    /// # Errors
    ///
    /// Returns [`HomeError::StreamIdExhausted`] rather than wrapping or
    /// recycling an identifier.
    pub fn reserve_listener_id(&mut self) -> Result<u32, HomeError> {
        let stream_id = self.next_listener_id.ok_or(HomeError::StreamIdExhausted)?;
        self.next_listener_id = stream_id.checked_add(2);
        Ok(stream_id)
    }

    /// Half-close the local writer for one stream.
    ///
    /// # Errors
    ///
    /// Returns [`HomeError::Closed`] for an unknown or already locally closed
    /// stream.
    pub fn close_write(&mut self, stream_id: u32) -> Result<MuxOutput, HomeError> {
        let peer_closed = {
            let stream = self.streams.get_mut(&stream_id).ok_or(HomeError::Closed)?;
            if stream.local_closed {
                return Err(HomeError::Closed);
            }
            stream.local_closed = true;
            stream.peer_closed
        };
        let mut output = MuxOutput::default();
        output
            .frames
            .push(Frame::new(stream_id, FLAG_CLOSE, Vec::new()));
        if peer_closed {
            self.remove_stream(stream_id);
        }
        Ok(output)
    }

    /// Reset a local stream with the supplied classified reason.
    ///
    /// # Errors
    ///
    /// Returns [`HomeError::Closed`] when the stream is already forgotten.
    pub fn reset(&mut self, stream_id: u32, reason: ResetReason) -> Result<MuxOutput, HomeError> {
        if !self.streams.contains_key(&stream_id) {
            return Err(HomeError::Closed);
        }
        self.remove_stream(stream_id);
        let mut output = MuxOutput::default();
        output.frames.push(Frame::reset(stream_id, reason.code()));
        Ok(output)
    }

    /// Finish carrier input and classify any locally observed partial frame.
    pub fn finish_eof(&mut self) -> MuxOutput {
        let truncated = self.decoder_buffered_bytes != 0;
        self.streams.clear();
        MuxOutput {
            frames: Vec::new(),
            events: vec![MuxEvent::PeerGone { truncated }],
            refusals: Vec::new(),
        }
    }

    fn handle_frame(&mut self, frame: Frame, output: &mut MuxOutput) -> Result<(), HomeError> {
        if frame.stream_id == 0 {
            return Self::handle_control(&frame, output);
        }
        if !flags_valid(frame.flags) {
            self.refuse(&frame, RefusalClass::Protocol, output);
            return Ok(());
        }
        if frame.flags & (FLAG_PING | FLAG_PONG) != 0 {
            self.refuse(&frame, RefusalClass::Protocol, output);
            return Ok(());
        }
        if frame.flags & FLAG_OPEN != 0 {
            self.handle_open(frame, output);
            return Ok(());
        }

        let known = self.streams.contains_key(&frame.stream_id);
        if !known && frame.flags & (FLAG_CLOSE | FLAG_RESET) != 0 {
            // Protocol framing.md:110-112 tolerates terminal late frames.
            return Ok(());
        }
        if !known {
            // Protocol framing.md:110-112 replies once per DATA/WINDOW frame.
            self.refuse(&frame, RefusalClass::Protocol, output);
            return Ok(());
        }

        if frame.flags == FLAG_DATA | FLAG_CLOSE {
            self.handle_data(frame, true, output);
        } else {
            match frame.flags {
                FLAG_DATA => self.handle_data(frame, false, output),
                FLAG_CLOSE => self.handle_close(frame, output),
                FLAG_RESET => self.handle_reset(&frame, output),
                FLAG_WINDOW => self.handle_window(&frame, output),
                _ => {
                    self.refuse(&frame, RefusalClass::Protocol, output);
                }
            }
        }
        Ok(())
    }

    fn handle_control(frame: &Frame, output: &mut MuxOutput) -> Result<(), HomeError> {
        if frame.flags == FLAG_PING
            && frame.payload.len() == CONTROL_NONCE_LEN
            && let Some(pong) = frame.control_pong()
        {
            // Protocol framing.md:155-159: writers send this before DATA.
            output.frames.push(pong);
            return Ok(());
        }
        if frame.flags == FLAG_PONG && frame.payload.len() == CONTROL_NONCE_LEN {
            // Protocol framing.md:155-159: stray PONG is intentionally dropped.
            return Ok(());
        }
        // Protocol framing.md:105: stream zero has no stream RESET escape.
        Err(HomeError::Refused(Refusal {
            class: RefusalClass::Protocol,
            violation: Some(violation(frame)),
        }))
    }

    fn handle_open(&mut self, frame: Frame, output: &mut MuxOutput) {
        let stream_id = frame.stream_id;
        let valid_id = stream_id % 2 == 1
            && self
                .peer_high_water
                .is_none_or(|highest| stream_id > highest);
        if !valid_id {
            self.refuse(&frame, RefusalClass::Protocol, output);
            return;
        }
        // The id was validly opened even if a local resource policy refuses
        // the stream below; accepting it again later would violate monotonic
        // allocation and could collide with late frames.
        self.peer_high_water = Some(stream_id);
        if self.streams.len() >= self.limits.max_concurrent_streams {
            self.refuse(&frame, RefusalClass::StreamLimit, output);
            return;
        }
        if frame.payload.len() > INITIAL_WINDOW {
            self.refuse(&frame, RefusalClass::FlowControl, output);
            return;
        }

        let mut stream = StreamState {
            receive_window: RecvWindow::new(),
            debited_not_consumed: 0,
            send_credit: INITIAL_WINDOW as u64,
            peer_closed: false,
            local_closed: false,
        };
        // The prior length check makes this unable to return FlowControl.
        if stream.receive_window.debit(frame.payload.len()).is_err() {
            self.refuse(&frame, RefusalClass::FlowControl, output);
            return;
        }
        stream.debited_not_consumed = frame.payload.len();
        self.streams.insert(stream_id, stream);
        output.events.push(MuxEvent::Opened { stream_id });
        if !frame.payload.is_empty() || frame.flags & FLAG_DATA != 0 {
            output.events.push(MuxEvent::Data {
                stream_id,
                bytes: frame.payload,
            });
        }
        if frame.flags & FLAG_CLOSE != 0 {
            self.mark_peer_closed(stream_id, output);
        }
    }

    fn handle_data(&mut self, frame: Frame, closes: bool, output: &mut MuxOutput) {
        let stream_id = frame.stream_id;
        if self
            .streams
            .get(&stream_id)
            .is_some_and(|stream| stream.peer_closed)
        {
            self.refuse(&frame, RefusalClass::Protocol, output);
            return;
        }
        let debit_ok = self
            .streams
            .get_mut(&stream_id)
            .is_some_and(|stream| stream.receive_window.debit(frame.payload.len()).is_ok());
        if !debit_ok {
            self.refuse(&frame, RefusalClass::FlowControl, output);
            return;
        }
        let Some(next_debited) = self
            .streams
            .get(&stream_id)
            .and_then(|stream| stream.debited_not_consumed.checked_add(frame.payload.len()))
        else {
            self.refuse(&frame, RefusalClass::Internal, output);
            return;
        };
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.debited_not_consumed = next_debited;
        }
        output.events.push(MuxEvent::Data {
            stream_id,
            bytes: frame.payload,
        });
        if closes {
            self.mark_peer_closed(stream_id, output);
        }
    }

    fn handle_close(&mut self, frame: Frame, output: &mut MuxOutput) {
        if !frame.payload.is_empty() {
            // Protocol framing.md:75-97 allows a final contribution on CLOSE.
            self.handle_data(frame, true, output);
            return;
        }
        self.mark_peer_closed(frame.stream_id, output);
    }

    fn handle_reset(&mut self, frame: &Frame, output: &mut MuxOutput) {
        if frame.payload.len() != 1 {
            self.refuse(frame, RefusalClass::Protocol, output);
            return;
        }
        let reason = ResetReason::from_wire(frame.payload[0]);
        self.remove_stream(frame.stream_id);
        output.events.push(MuxEvent::Reset {
            stream_id: frame.stream_id,
            reason,
        });
    }

    fn handle_window(&mut self, frame: &Frame, output: &mut MuxOutput) {
        let Some(credit) = frame.window_credit() else {
            self.refuse(frame, RefusalClass::Protocol, output);
            return;
        };
        let credit_ok = self
            .streams
            .get_mut(&frame.stream_id)
            .is_some_and(|stream| {
                let Some(next) = stream.send_credit.checked_add(u64::from(credit)) else {
                    return false;
                };
                if next > MAX_SEND_CREDIT {
                    return false;
                }
                stream.send_credit = next;
                true
            });
        if !credit_ok {
            self.refuse(frame, RefusalClass::FlowControl, output);
        }
    }

    fn mark_peer_closed(&mut self, stream_id: u32, output: &mut MuxOutput) {
        let local_closed = match self.streams.get_mut(&stream_id) {
            Some(stream) => {
                stream.peer_closed = true;
                stream.local_closed
            }
            None => return,
        };
        output.events.push(MuxEvent::ReadClosed { stream_id });
        if local_closed {
            self.remove_stream(stream_id);
        }
    }

    fn remove_stream(&mut self, stream_id: u32) {
        self.streams.remove(&stream_id);
    }

    fn refuse(&mut self, frame: &Frame, class: RefusalClass, output: &mut MuxOutput) {
        self.refuse_violation(violation(frame), class, output);
    }

    fn refuse_violation(
        &mut self,
        frame_violation: FrameViolation,
        class: RefusalClass,
        output: &mut MuxOutput,
    ) {
        let refusal = Refusal {
            class,
            violation: Some(frame_violation),
        };
        output
            .frames
            .push(Frame::reset(frame_violation.stream_id, class.reset_code()));
        output.refusals.push(refusal);
        if self.streams.contains_key(&frame_violation.stream_id) {
            self.remove_stream(frame_violation.stream_id);
            output.events.push(MuxEvent::Reset {
                stream_id: frame_violation.stream_id,
                reason: ResetReason::from_class(class),
            });
        }
    }

    fn drain_decoder(&mut self, output: &mut MuxOutput) -> Result<(), HomeError> {
        while let Some(frame) = self.decoder.next_frame()? {
            self.decoder_buffered_bytes = self
                .decoder_buffered_bytes
                .checked_sub(HEADER_LEN + frame.payload.len())
                .ok_or(HomeError::Refused(Refusal {
                    class: RefusalClass::Internal,
                    violation: None,
                }))?;
            self.handle_frame(frame, output)?;
        }
        Ok(())
    }
}

impl ResetReason {
    fn code(self) -> u8 {
        match self {
            Self::ProtocolError => RESET_PROTOCOL_ERROR,
            Self::FlowControlError => RESET_FLOW_CONTROL_ERROR,
            Self::StreamLimitExceeded => RESET_STREAM_LIMIT_EXCEEDED,
            Self::InternalError => RESET_INTERNAL_ERROR,
            Self::Cancel => RESET_CANCEL,
            Self::Unspecified => RESET_UNSPECIFIED,
        }
    }

    fn from_wire(code: u8) -> Self {
        match code {
            RESET_PROTOCOL_ERROR => Self::ProtocolError,
            RESET_FLOW_CONTROL_ERROR => Self::FlowControlError,
            RESET_STREAM_LIMIT_EXCEEDED => Self::StreamLimitExceeded,
            RESET_INTERNAL_ERROR => Self::InternalError,
            RESET_CANCEL => Self::Cancel,
            _ => Self::Unspecified,
        }
    }

    fn from_class(class: RefusalClass) -> Self {
        match class {
            RefusalClass::Protocol => Self::ProtocolError,
            RefusalClass::StreamLimit => Self::StreamLimitExceeded,
            RefusalClass::FlowControl => Self::FlowControlError,
            RefusalClass::Internal => Self::InternalError,
            RefusalClass::Cancelled => Self::Cancel,
        }
    }
}

impl RefusalClass {
    fn reset_code(self) -> u8 {
        ResetReason::from_class(self).code()
    }
}

fn violation(frame: &Frame) -> FrameViolation {
    FrameViolation {
        stream_id: frame.stream_id,
        flags: frame.flags,
        length: frame.payload.len(),
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "tests assert protocol values")]

    use super::*;
    use crate::{DEFAULT_DECODER_BUFFER_BYTES, DEFAULT_MAX_CONCURRENT_STREAMS};

    fn acceptor(limits: MuxLimits) -> MuxAcceptor {
        MuxAcceptor::new(limits).unwrap()
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "tests pass frame literals directly into the wire helper"
    )]
    fn feed_frame(acceptor: &mut MuxAcceptor, frame: Frame) -> MuxOutput {
        acceptor.feed(&frame.encode().unwrap()).unwrap()
    }

    fn reset_code(output: &MuxOutput) -> u8 {
        assert_eq!(output.frames.len(), 1, "expected exactly one RESET frame");
        output.frames[0].payload[0]
    }

    #[test]
    fn even_peer_open_is_protocol_error() {
        // Protocol framing.md:101-108 assigns peer/dialer OPENs odd ids.
        let output = feed_frame(
            &mut acceptor(MuxLimits::default()),
            Frame::new(2, FLAG_OPEN, vec![]),
        );
        assert_eq!(reset_code(&output), RESET_PROTOCOL_ERROR);
        assert_eq!(output.refusals[0].class, RefusalClass::Protocol);
    }

    #[test]
    fn peer_open_ids_are_monotone_not_consecutive() {
        // Protocol framing.md:101-108 says increment, never recycle, not consecutive OPENs.
        let mut acceptor = acceptor(MuxLimits::default());
        assert!(
            feed_frame(&mut acceptor, Frame::new(1, FLAG_OPEN, vec![]))
                .frames
                .is_empty()
        );
        assert!(
            feed_frame(&mut acceptor, Frame::new(5, FLAG_OPEN, vec![]))
                .frames
                .is_empty()
        );
        let output = feed_frame(&mut acceptor, Frame::new(1, FLAG_OPEN, vec![]));
        assert_eq!(reset_code(&output), RESET_PROTOCOL_ERROR);
    }

    #[test]
    fn retired_peer_open_id_is_protocol_error() {
        // Protocol framing.md:101-108 requires allocation to increment, never recycle.
        let mut acceptor = acceptor(MuxLimits::default());
        feed_frame(&mut acceptor, Frame::new(3, FLAG_OPEN, Vec::new()));
        feed_frame(&mut acceptor, Frame::reset(3, RESET_CANCEL));
        let output = feed_frame(&mut acceptor, Frame::new(3, FLAG_OPEN, Vec::new()));
        assert_eq!(reset_code(&output), RESET_PROTOCOL_ERROR);
    }

    #[test]
    fn listener_ids_exhaust_without_wrapping() {
        // Protocol framing.md:101-108 requires listener ids to increment and never recycle.
        let mut acceptor = acceptor(MuxLimits::default());
        acceptor.next_listener_id = Some(u32::MAX - 1);
        assert_eq!(acceptor.reserve_listener_id().unwrap(), u32::MAX - 1);
        assert_eq!(
            acceptor.reserve_listener_id(),
            Err(HomeError::StreamIdExhausted)
        );
    }

    #[test]
    fn stream_cap_bounds_inbound_data_at_configured_eight_streams() {
        // Protocol framing.md:114-129 bounds each of eight live streams to its 1 MiB window.
        let limits = MuxLimits {
            max_concurrent_streams: 8,
            decoder_buffer_bytes: HEADER_LEN + spl_core::frame::MAX_PAYLOAD,
        };
        let mut acceptor = acceptor(limits);
        let body = vec![7; INITIAL_WINDOW];
        for id in (1..=15).step_by(2) {
            let output = feed_frame(
                &mut acceptor,
                Frame::new(id, FLAG_OPEN | FLAG_DATA, body.clone()),
            );
            assert!(output.frames.is_empty());
        }
        assert_eq!(acceptor.streams.len(), 8);
        assert_eq!(
            acceptor
                .streams
                .values()
                .map(|stream| stream.debited_not_consumed)
                .sum::<usize>(),
            8 * INITIAL_WINDOW
        );
        let ninth = feed_frame(&mut acceptor, Frame::new(17, FLAG_OPEN, vec![]));
        assert_eq!(reset_code(&ninth), RESET_STREAM_LIMIT_EXCEEDED);
    }

    #[test]
    fn default_limits_pin_protocol_budget_and_decoder_validation() {
        // Protocol framing.md:29-36 and :114-129 pin these v1 defaults.
        assert_eq!(DEFAULT_MAX_CONCURRENT_STREAMS, 256);
        assert_eq!(DEFAULT_MAX_CONCURRENT_STREAMS * INITIAL_WINDOW, 268_435_456);
        assert_eq!(DEFAULT_DECODER_BUFFER_BYTES, 16_777_223);
        assert_eq!(
            MuxLimits {
                max_concurrent_streams: 256,
                decoder_buffer_bytes: HEADER_LEN + spl_core::frame::MAX_PAYLOAD - 1,
            }
            .validate(),
            Err(crate::ConfigError::DecoderBelowMaximumFrame)
        );
        assert!(MuxLimits::default().validate().is_ok());
    }

    #[test]
    fn ping_is_answered_and_stray_pong_is_dropped() {
        // Protocol framing.md:155-159 requires a same-nonce PONG and tolerates stray PONGs.
        let mut acceptor = acceptor(MuxLimits::default());
        let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        let pong = feed_frame(&mut acceptor, Frame::control_ping(nonce));
        assert_eq!(pong.frames, vec![Frame::new(0, FLAG_PONG, nonce.to_vec())]);
        let dropped = feed_frame(&mut acceptor, Frame::new(0, FLAG_PONG, nonce.to_vec()));
        assert!(dropped.frames.is_empty());
        assert!(dropped.events.is_empty());
    }

    #[test]
    fn stream_zero_non_control_is_tunnel_fatal() {
        // Protocol framing.md:103-105 makes stream-zero OPEN/DATA/CLOSE/RESET/WINDOW tunnel-fatal.
        let result = feed_frame_result(
            &mut acceptor(MuxLimits::default()),
            Frame::new(0, FLAG_DATA, vec![]),
        );
        assert_eq!(
            result,
            Err(HomeError::Refused(Refusal {
                class: RefusalClass::Protocol,
                violation: Some(FrameViolation {
                    stream_id: 0,
                    flags: FLAG_DATA,
                    length: 0
                }),
            }))
        );
    }

    #[test]
    fn late_terminal_frames_are_tolerated_and_live_assertions_reset() {
        // Protocol framing.md:110-112 distinguishes terminal late frames from DATA/WINDOW desync.
        let mut acceptor = acceptor(MuxLimits::default());
        assert!(
            feed_frame(&mut acceptor, Frame::new(1, FLAG_CLOSE, vec![]))
                .frames
                .is_empty()
        );
        assert!(
            feed_frame(&mut acceptor, Frame::reset(1, RESET_CANCEL))
                .frames
                .is_empty()
        );
        assert_eq!(
            reset_code(&feed_frame(&mut acceptor, Frame::new(1, FLAG_DATA, vec![]))),
            RESET_PROTOCOL_ERROR
        );
        assert_eq!(
            reset_code(&feed_frame(&mut acceptor, Frame::window(1, 1))),
            RESET_PROTOCOL_ERROR
        );
    }

    #[test]
    fn open_data_close_delivers_bytes_then_read_eof() {
        // Protocol framing.md:75-97 and :53-60 define OPEN|DATA|CLOSE half-close delivery.
        let output = feed_frame(
            &mut acceptor(MuxLimits::default()),
            Frame::new(1, FLAG_OPEN | FLAG_DATA | FLAG_CLOSE, b"last".to_vec()),
        );
        assert_eq!(
            output.events,
            vec![
                MuxEvent::Opened { stream_id: 1 },
                MuxEvent::Data {
                    stream_id: 1,
                    bytes: b"last".to_vec()
                },
                MuxEvent::ReadClosed { stream_id: 1 },
            ]
        );
    }

    #[test]
    fn empty_open_close_delivers_open_then_read_eof() {
        // Protocol framing.md:75-97 and :53-60 permit an empty OPEN|CLOSE.
        let output = feed_frame(
            &mut acceptor(MuxLimits::default()),
            Frame::new(1, FLAG_OPEN | FLAG_CLOSE, Vec::new()),
        );
        assert_eq!(
            output.events,
            vec![
                MuxEvent::Opened { stream_id: 1 },
                MuxEvent::ReadClosed { stream_id: 1 },
            ]
        );
    }

    #[test]
    fn excessive_window_credit_is_flow_control_error() {
        // Protocol framing.md:120-129 caps advertised send credit at 2^31 - 1.
        let mut acceptor = acceptor(MuxLimits::default());
        feed_frame(&mut acceptor, Frame::new(1, FLAG_OPEN, Vec::new()));
        let output = feed_frame(&mut acceptor, Frame::window(1, u32::MAX));
        assert_eq!(reset_code(&output), RESET_FLOW_CONTROL_ERROR);
    }

    #[test]
    fn unknown_reset_reason_is_unspecified() {
        // Protocol framing.md:62-73 requires unknown reset reasons to degrade to UNSPECIFIED.
        let mut acceptor = acceptor(MuxLimits::default());
        feed_frame(&mut acceptor, Frame::new(1, FLAG_OPEN, vec![]));
        let output = feed_frame(&mut acceptor, Frame::reset(1, 0x44));
        assert_eq!(
            output.events,
            vec![MuxEvent::Reset {
                stream_id: 1,
                reason: ResetReason::Unspecified
            }]
        );
    }

    #[test]
    fn empty_data_is_delivered() {
        // Protocol framing.md:191-197 requires empty DATA to be tolerated.
        let mut acceptor = acceptor(MuxLimits::default());
        feed_frame(&mut acceptor, Frame::new(1, FLAG_OPEN, vec![]));
        let output = feed_frame(&mut acceptor, Frame::new(1, FLAG_DATA, vec![]));
        assert_eq!(
            output.events,
            vec![MuxEvent::Data {
                stream_id: 1,
                bytes: vec![]
            }]
        );
    }

    #[test]
    fn invalid_flags_and_reserved_bit_reset_the_offending_stream() {
        // Protocol framing.md:51 and :53-60 require rejecting reserved and illegal flags.
        let mut acceptor = acceptor(MuxLimits::default());
        let invalid = feed_frame(
            &mut acceptor,
            Frame::new(1, FLAG_DATA | FLAG_WINDOW, Vec::new()),
        );
        assert_eq!(reset_code(&invalid), RESET_PROTOCOL_ERROR);

        let reserved = [0, 0, 0, 3, spl_core::frame::FLAG_RESERVED_MASK, 0, 0, 0];
        let output = acceptor.feed(&reserved).unwrap();
        assert_eq!(reset_code(&output), RESET_PROTOCOL_ERROR);
        assert_eq!(
            output.refusals[0].violation,
            Some(FrameViolation {
                stream_id: 3,
                flags: spl_core::frame::FLAG_RESERVED_MASK,
                length: 0,
            })
        );
    }

    #[test]
    fn close_may_carry_final_bytes() {
        // Protocol framing.md:75-97 permits CLOSE to carry the final stream bytes.
        let mut acceptor = acceptor(MuxLimits::default());
        feed_frame(&mut acceptor, Frame::new(1, FLAG_OPEN, Vec::new()));
        let output = feed_frame(&mut acceptor, Frame::new(1, FLAG_CLOSE, b"end".to_vec()));
        assert_eq!(
            output.events,
            vec![
                MuxEvent::Data {
                    stream_id: 1,
                    bytes: b"end".to_vec(),
                },
                MuxEvent::ReadClosed { stream_id: 1 },
            ]
        );
    }

    #[test]
    fn over_consume_is_classified_without_reaching_recv_window_panic() {
        // Protocol framing.md:120-129 permits WINDOW only for bytes locally consumed.
        let mut acceptor = acceptor(MuxLimits::default());
        feed_frame(&mut acceptor, Frame::new(1, FLAG_OPEN | FLAG_DATA, vec![1]));
        assert_eq!(
            acceptor.consume(1, 2),
            Err(HomeError::Refused(Refusal {
                class: RefusalClass::Internal,
                violation: None
            }))
        );
    }

    #[test]
    fn data_beyond_initial_receive_window_is_refused_without_delivery() {
        // Protocol framing.md:120-129 refuses DATA beyond the advertised 1 MiB window.
        let mut acceptor = acceptor(MuxLimits::default());
        feed_frame(
            &mut acceptor,
            Frame::new(1, FLAG_OPEN | FLAG_DATA, vec![1; INITIAL_WINDOW]),
        );
        let retained_before = acceptor
            .streams
            .values()
            .map(|stream| stream.debited_not_consumed)
            .sum::<usize>();
        let output = feed_frame(&mut acceptor, Frame::new(1, FLAG_DATA, vec![2]));
        assert_eq!(reset_code(&output), RESET_FLOW_CONTROL_ERROR);
        assert_eq!(
            output.events,
            vec![MuxEvent::Reset {
                stream_id: 1,
                reason: ResetReason::FlowControlError,
            }]
        );
        let retained_after = acceptor
            .streams
            .values()
            .map(|stream| stream.debited_not_consumed)
            .sum::<usize>();
        assert_eq!(retained_before, INITIAL_WINDOW);
        assert_eq!(retained_after, 0);
    }

    #[test]
    fn partial_carrier_frame_is_classified_as_peer_gone() {
        // Protocol framing.md:29-36 makes a frame atomic; EOF mid-frame is carrier loss.
        let mut acceptor = acceptor(MuxLimits::default());
        acceptor.feed(&[0, 0, 0]).unwrap();
        assert_eq!(
            acceptor.finish_eof().events,
            vec![MuxEvent::PeerGone { truncated: true }]
        );
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "tests pass frame literals directly into the wire helper"
    )]
    fn feed_frame_result(acceptor: &mut MuxAcceptor, frame: Frame) -> Result<MuxOutput, HomeError> {
        acceptor.feed(&frame.encode().unwrap())
    }
}
