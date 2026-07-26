// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! spl multiplex framing.
//!
//! Eight-byte header plus payload, using the SPL framing layout:
//!
//! ```text
//! +------+------+-----------+
//! | sid4 | flg1 | len3      |  header (big-endian)
//! +------+------+-----------+
//! | payload (len bytes)     |
//! +-------------------------+
//! ```
//!
//! The flag bitfield names exactly one of OPEN/DATA/CLOSE/RESET/WINDOW/PING/PONG
//! per frame, except the legal `OPEN|DATA`, `DATA|CLOSE`, `OPEN|CLOSE`, and
//! `OPEN|DATA|CLOSE` compositions. PING/PONG ride stream 0 only with an 8-byte
//! nonce. Bit 7 is reserved and must be zero.

use thiserror::Error;

/// Opens a logical stream.
pub const FLAG_OPEN: u8 = 0x01;
/// Carries stream payload bytes.
pub const FLAG_DATA: u8 = 0x02;
/// Half-closes a logical stream.
pub const FLAG_CLOSE: u8 = 0x04;
/// Resets a logical stream.
pub const FLAG_RESET: u8 = 0x08;
/// Grants flow-control credit.
pub const FLAG_WINDOW: u8 = 0x10;
/// Carries a connection-level ping nonce.
pub const FLAG_PING: u8 = 0x20;
/// Carries a connection-level pong nonce.
pub const FLAG_PONG: u8 = 0x40;
/// Bit mask reserved for future framing flags.
pub const FLAG_RESERVED_MASK: u8 = 0x80;

/// Reset reason for a framing protocol violation.
pub const RESET_PROTOCOL_ERROR: u8 = 0x01;
/// Reset reason for exceeding flow-control credit.
pub const RESET_FLOW_CONTROL_ERROR: u8 = 0x02;
/// Reset reason for exceeding the stream limit.
pub const RESET_STREAM_LIMIT_EXCEEDED: u8 = 0x03;
/// Reset reason for an internal endpoint failure.
pub const RESET_INTERNAL_ERROR: u8 = 0x04;
/// Reset reason for caller cancellation.
pub const RESET_CANCEL: u8 = 0x05;
/// Reset reason used when no more specific code applies.
pub const RESET_UNSPECIFIED: u8 = 0xff;

/// Encoded frame-header length in bytes.
pub const HEADER_LEN: usize = 8;
/// Max payload that fits the 3-byte length field (16 MiB - 1).
pub const MAX_PAYLOAD: usize = (1 << 24) - 1;
/// Recommended per-DATA-frame chunk (64 KiB), matching the spl spec.
pub const RECOMMENDED_CHUNK: usize = 64 * 1024;
/// PING/PONG control-nonce length.
pub const CONTROL_NONCE_LEN: usize = 8;

/// Whether `flags` is one of the exact combinations permitted by the spl
/// framing contract. Stream-role and payload-length validation happen at
/// dispatch.
pub fn flags_valid(flags: u8) -> bool {
    matches!(
        flags,
        0x01 | 0x02 | 0x03 | 0x04 | 0x05 | 0x06 | 0x07 | 0x08 | 0x10 | 0x20 | 0x40
    )
}

/// Header-only metadata for one peer framing violation. Payload bytes are
/// deliberately absent so callers cannot accidentally log them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameViolation {
    /// Stream identifier from the rejected frame header.
    pub stream_id: u32,
    /// Flag byte from the rejected frame header.
    pub flags: u8,
    /// Rejected payload length without the payload contents.
    pub length: usize,
}

/// One decoded or not-yet-encoded SPL mux frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Logical stream identifier, or zero for connection control frames.
    pub stream_id: u32,
    /// SPL framing flag bitfield.
    pub flags: u8,
    /// Frame payload bytes.
    pub payload: Vec<u8>,
}

/// Errors produced while encoding or decoding frames.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum FrameError {
    /// The payload cannot fit in the three-byte wire length field.
    #[error("frame payload exceeds 16 MiB - 1: {0}")]
    PayloadTooLarge(usize),
    /// The frame sets the reserved high flag bit.
    #[error("reserved flag bit set: {0:#x}")]
    ReservedFlag(u8),
}

impl Frame {
    /// Construct a frame from its stream identifier, flags, and payload.
    pub fn new(stream_id: u32, flags: u8, payload: Vec<u8>) -> Self {
        Self {
            stream_id,
            flags,
            payload,
        }
    }

    /// Encode this frame to the wire (header + payload).
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::PayloadTooLarge`] when the payload exceeds the
    /// three-byte length field, or [`FrameError::ReservedFlag`] when the
    /// reserved flag bit is set.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        if self.payload.len() > MAX_PAYLOAD {
            return Err(FrameError::PayloadTooLarge(self.payload.len()));
        }
        if self.flags & FLAG_RESERVED_MASK != 0 {
            return Err(FrameError::ReservedFlag(self.flags));
        }
        let len = self.payload.len() as u32;
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&self.stream_id.to_be_bytes());
        out.push(self.flags);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// Build a control PING (stream 0, 8-byte nonce).
    pub fn control_ping(nonce: [u8; CONTROL_NONCE_LEN]) -> Frame {
        Frame::new(0, FLAG_PING, nonce.to_vec())
    }

    /// Build a per-stream receive-window credit grant.
    pub fn window(stream_id: u32, credit: u32) -> Frame {
        Frame::new(stream_id, FLAG_WINDOW, credit.to_be_bytes().to_vec())
    }

    /// Build a per-stream reset carrying one protocol reason code.
    pub fn reset(stream_id: u32, reason: u8) -> Frame {
        Frame::new(stream_id, FLAG_RESET, vec![reason])
    }

    /// If this is a control PING (stream 0, 8-byte nonce), the PONG to return.
    pub fn control_pong(&self) -> Option<Frame> {
        if self.stream_id == 0 && self.flags == FLAG_PING && self.payload.len() == CONTROL_NONCE_LEN
        {
            Some(Frame::new(0, FLAG_PONG, self.payload.clone()))
        } else {
            None
        }
    }

    /// If this is a control PONG (stream 0, 8-byte nonce), return the nonce.
    pub fn control_pong_nonce(&self) -> Option<[u8; CONTROL_NONCE_LEN]> {
        if self.stream_id == 0 && self.flags == FLAG_PONG && self.payload.len() == CONTROL_NONCE_LEN
        {
            let mut nonce = [0u8; CONTROL_NONCE_LEN];
            nonce.copy_from_slice(&self.payload);
            Some(nonce)
        } else {
            None
        }
    }

    /// If this is a `WINDOW` flow-control frame, the credit (bytes) it grants.
    /// The payload is a 4-byte big-endian count, byte-identical to the journal's
    /// `build_window` (`convey/secure_listener/framing.py`).
    pub fn window_credit(&self) -> Option<u32> {
        if self.flags & FLAG_WINDOW != 0 && self.payload.len() == 4 {
            Some(u32::from_be_bytes([
                self.payload[0],
                self.payload[1],
                self.payload[2],
                self.payload[3],
            ]))
        } else {
            None
        }
    }
}

/// Streaming frame decoder. Feed bytes off the wire; pull complete frames.
/// Re-frames across transport read boundaries, exactly like the journal decoder.
#[derive(Default)]
pub struct FrameDecoder {
    buf: Vec<u8>,
}

impl FrameDecoder {
    /// Construct an empty streaming decoder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append transport bytes to the decoder's input buffer.
    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Pull the next complete frame, if one is buffered.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::ReservedFlag`] if the buffered header sets the
    /// reserved flag bit.
    pub fn next_frame(&mut self) -> Result<Option<Frame>, FrameError> {
        if self.buf.len() < HEADER_LEN {
            return Ok(None);
        }
        let stream_id = u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]);
        let flags = self.buf[4];
        if flags & FLAG_RESERVED_MASK != 0 {
            return Err(FrameError::ReservedFlag(flags));
        }
        let len =
            ((self.buf[5] as usize) << 16) | ((self.buf[6] as usize) << 8) | (self.buf[7] as usize);
        let end = HEADER_LEN + len;
        if self.buf.len() < end {
            return Ok(None);
        }
        let payload = self.buf[HEADER_LEN..end].to_vec();
        self.buf.drain(..end);
        Ok(Some(Frame::new(stream_id, flags, payload)))
    }

    /// Drain all currently-complete frames.
    ///
    /// # Errors
    ///
    /// Returns the first frame-decoding error encountered in the buffer.
    pub fn drain(&mut self) -> Result<Vec<Frame>, FrameError> {
        let mut out = Vec::new();
        while let Some(frame) = self.next_frame()? {
            out.push(frame);
        }
        Ok(out)
    }
}

/// Dialer stream-id allocator: odd IDs starting at 1, the client side of the
/// mux (the journal/listener uses even IDs).
#[derive(Debug)]
pub struct FrameDialer {
    next: u32,
}

impl Default for FrameDialer {
    fn default() -> Self {
        Self { next: 1 }
    }
}

impl FrameDialer {
    /// Allocate the next odd dialer-owned stream identifier.
    pub fn allocate(&mut self) -> u32 {
        let id = self.next;
        self.next = self.next.wrapping_add(2);
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_round_trip() {
        let frame = Frame::new(7, FLAG_OPEN | FLAG_DATA, b"hello".to_vec());
        let bytes = frame.encode().unwrap();
        // Header is exactly the documented layout.
        assert_eq!(&bytes[0..4], &7u32.to_be_bytes());
        assert_eq!(bytes[4], FLAG_OPEN | FLAG_DATA);
        assert_eq!(&bytes[5..8], &[0, 0, 5]);
        let mut decoder = FrameDecoder::new();
        decoder.feed(&bytes);
        assert_eq!(decoder.next_frame().unwrap(), Some(frame));
        assert_eq!(decoder.next_frame().unwrap(), None);
    }

    #[test]
    fn decoder_reframes_across_split_reads() {
        let f1 = Frame::new(1, FLAG_DATA, b"abc".to_vec());
        let f2 = Frame::new(1, FLAG_CLOSE, Vec::new());
        let mut wire = f1.encode().unwrap();
        wire.extend(f2.encode().unwrap());
        let mut decoder = FrameDecoder::new();
        // Feed one byte at a time — framing must not depend on read boundaries.
        for b in wire {
            decoder.feed(&[b]);
        }
        assert_eq!(decoder.drain().unwrap(), vec![f1, f2]);
    }

    #[test]
    fn control_ping_yields_pong_with_same_nonce() {
        let ping = Frame::new(0, FLAG_PING, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let pong = ping.control_pong().unwrap();
        assert_eq!(pong.flags, FLAG_PONG);
        assert_eq!(pong.stream_id, 0);
        assert_eq!(pong.payload, ping.payload);
    }

    #[test]
    fn flags_valid_matches_exact_spl_set() {
        let valid = [
            0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x10, 0x20, 0x40,
        ];
        for flags in u8::MIN..=u8::MAX {
            assert_eq!(
                flags_valid(flags),
                valid.contains(&flags),
                "unexpected validity for {flags:#04x}"
            );
        }
    }

    #[test]
    fn control_helpers_require_exact_flags() {
        let combined = Frame::new(0, FLAG_PING | FLAG_PONG, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(combined.control_pong().is_none());
        assert!(combined.control_pong_nonce().is_none());
    }

    #[test]
    fn control_ping_builds_stream_zero_ping() {
        let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        let ping = Frame::control_ping(nonce);
        assert_eq!(ping.stream_id, 0);
        assert_eq!(ping.flags, FLAG_PING);
        assert_eq!(ping.payload, nonce.to_vec());
    }

    #[test]
    fn window_and_reset_builders_encode_protocol_payloads() {
        let window = Frame::window(5, 524_599);
        assert_eq!(window.stream_id, 5);
        assert_eq!(window.flags, FLAG_WINDOW);
        assert_eq!(window.payload, 524_599u32.to_be_bytes());
        assert_eq!(window.window_credit(), Some(524_599));

        let reset = Frame::reset(7, RESET_FLOW_CONTROL_ERROR);
        assert_eq!(reset.stream_id, 7);
        assert_eq!(reset.flags, FLAG_RESET);
        assert_eq!(reset.payload, vec![RESET_FLOW_CONTROL_ERROR]);
    }

    #[test]
    fn control_pong_nonce_round_trips() {
        let nonce = [9, 8, 7, 6, 5, 4, 3, 2];
        let ping = Frame::control_ping(nonce);
        let pong = ping.control_pong().unwrap();
        assert_eq!(pong.control_pong_nonce(), Some(nonce));
    }

    #[test]
    fn non_ping_is_not_a_pong() {
        let data = Frame::new(1, FLAG_DATA, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(data.control_pong().is_none());
    }

    #[test]
    fn non_pong_is_not_a_pong_nonce() {
        let data = Frame::new(1, FLAG_DATA, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(data.control_pong_nonce().is_none());
        let malformed = Frame::new(0, FLAG_PONG, vec![1, 2, 3]);
        assert!(malformed.control_pong_nonce().is_none());
    }

    #[test]
    fn dialer_allocates_odd_ids() {
        let mut dialer = FrameDialer::default();
        assert_eq!(dialer.allocate(), 1);
        assert_eq!(dialer.allocate(), 3);
        assert_eq!(dialer.allocate(), 5);
    }

    #[test]
    fn reserved_flag_is_rejected() {
        let frame = Frame::new(1, FLAG_RESERVED_MASK, Vec::new());
        assert_eq!(frame.encode().unwrap_err(), FrameError::ReservedFlag(0x80));
    }

    #[test]
    fn window_frame_parses_big_endian_credit() {
        // 0x00_08_00_00 = 512 KiB, the journal's 50%-consumed replenishment grant.
        let frame = Frame::new(5, FLAG_WINDOW, vec![0x00, 0x08, 0x00, 0x00]);
        assert_eq!(frame.window_credit(), Some(512 * 1024));
    }

    #[test]
    fn non_window_or_malformed_is_not_a_credit() {
        // Right flag, wrong length.
        assert!(
            Frame::new(5, FLAG_WINDOW, vec![1, 2, 3])
                .window_credit()
                .is_none()
        );
        // Right length, wrong flag.
        assert!(
            Frame::new(5, FLAG_DATA, vec![0, 0, 0, 1])
                .window_credit()
                .is_none()
        );
    }
}
