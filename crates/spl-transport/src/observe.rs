// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Operation-scoped recording seam for physical dials and request byte progress.
//!
//! An operation attaches a single [`OperationObserver`] to record physical dial attempts,
//! furthest request DATA payload byte progress, stream close completion, selected transport
//! paths, and enrollment control steps.
//!
//! **Observation only.** Every method uses relaxed atomics and returns `()` so recording
//! never panics, blocks, or alters control flow or loop bounds.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use crate::request::SelectedPath;

const PATH_DIRECT: u8 = 1;
const PATH_RELAY: u8 = 2;

/// Write-only counters and progress flags for one operation.
#[derive(Debug, Default)]
pub struct OperationObserver {
    dial_attempts: AtomicU64,
    request_bytes_sent: AtomicU64,
    close_completed: AtomicBool,
    selected_path: AtomicU8,
    enrollment_events: AtomicU64,
}

impl OperationObserver {
    /// Construct a new shared operation observer.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Construct a new standalone operation observer.
    pub fn new_unshared() -> Self {
        Self::default()
    }

    /// Record that one physical dial or carrier reconnect attempt is about to occur.
    pub fn record_dial_attempt(&self) {
        self.dial_attempts.fetch_add(1, Ordering::Relaxed);
    }

    /// Record furthest request DATA payload bytes delivered to the wire so far.
    pub fn record_request_bytes(&self, bytes: u64) {
        self.request_bytes_sent.fetch_max(bytes, Ordering::Relaxed);
    }

    /// Record that the request's `CLOSE` frame was sent and the peer's terminal response was received.
    pub fn record_close_completed(&self) {
        self.close_completed.store(true, Ordering::Relaxed);
    }

    /// Record the final successful transport path.
    pub fn record_selected_path(&self, path: SelectedPath) {
        let val = match path {
            SelectedPath::Direct => PATH_DIRECT,
            SelectedPath::Relay => PATH_RELAY,
        };
        self.selected_path.store(val, Ordering::Relaxed);
    }

    /// Record a control-plane enrollment event (does not count as a dial attempt).
    pub fn record_enrollment(&self) {
        self.enrollment_events.fetch_add(1, Ordering::Relaxed);
    }

    /// Cumulative physical dial attempts made during this operation.
    pub fn dial_attempts(&self) -> u64 {
        self.dial_attempts.load(Ordering::Relaxed)
    }

    /// Furthest request payload bytes delivered to the transport.
    pub fn request_bytes_sent(&self) -> u64 {
        self.request_bytes_sent.load(Ordering::Relaxed)
    }

    /// Whether the request completed its full bidirectional exchange.
    pub fn close_completed(&self) -> bool {
        self.close_completed.load(Ordering::Relaxed)
    }

    /// Selected transport path if completed.
    pub fn selected_path(&self) -> Option<SelectedPath> {
        match self.selected_path.load(Ordering::Relaxed) {
            PATH_DIRECT => Some(SelectedPath::Direct),
            PATH_RELAY => Some(SelectedPath::Relay),
            _ => None,
        }
    }

    /// Cumulative control-plane enrollment events.
    pub fn enrollment_events(&self) -> u64 {
        self.enrollment_events.load(Ordering::Relaxed)
    }
}

pub(crate) fn note_dial_attempt(obs: Option<&OperationObserver>) {
    if let Some(o) = obs {
        o.record_dial_attempt();
    }
}

pub(crate) fn note_request_bytes(obs: Option<&OperationObserver>, bytes: u64) {
    if let Some(o) = obs {
        o.record_request_bytes(bytes);
    }
}

pub(crate) fn note_close_completed(obs: Option<&OperationObserver>) {
    if let Some(o) = obs {
        o.record_close_completed();
    }
}

pub(crate) fn note_selected_path(obs: Option<&OperationObserver>, path: SelectedPath) {
    if let Some(o) = obs {
        o.record_selected_path(path);
    }
}

pub(crate) fn note_enrollment(obs: Option<&OperationObserver>) {
    if let Some(o) = obs {
        o.record_enrollment();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recording_methods_return_unit() {
        let obs = OperationObserver::new_unshared();
        let () = obs.record_dial_attempt();
        let () = obs.record_request_bytes(42);
        let () = obs.record_close_completed();
        let () = obs.record_selected_path(SelectedPath::Direct);
        let () = obs.record_enrollment();

        assert_eq!(obs.dial_attempts(), 1);
        assert_eq!(obs.request_bytes_sent(), 42);
        assert!(obs.close_completed());
        assert_eq!(obs.selected_path(), Some(SelectedPath::Direct));
        assert_eq!(obs.enrollment_events(), 1);
    }
}
