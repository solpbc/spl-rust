// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Operation-scoped recording seam for physical dials, transport successes, and request byte progress.
//!
//! An operation attaches a single [`OperationObserver`] to record physical dial attempts,
//! direct/relay transport leg successes, furthest request DATA payload byte progress, stream close completion,
//! selected transport paths, and enrollment control steps.
//!
//! **Observation only.** Every method uses relaxed atomics and returns `()` so recording
//! never panics, blocks, or alters control flow or loop bounds.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use crate::request::SelectedPath;

const PATH_DIRECT: u8 = 1;
const PATH_RELAY: u8 = 2;

fn saturating_inc(target: &AtomicU64) {
    let _ = target.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        Some(v.saturating_add(1))
    });
}

/// Point-in-time snapshot of operation metrics and selected transport state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationSnapshot {
    /// Cumulative physical dial attempts made during the operation.
    pub dial_attempts: u64,
    /// Cumulative direct transport legs or HTTP exchanges successfully completed.
    pub direct_successes: u64,
    /// Cumulative relay transport legs or HTTP exchanges successfully completed.
    pub relay_successes: u64,
    /// Furthest request payload bytes delivered to the transport.
    pub request_bytes_sent: u64,
    /// Whether the request completed its full bidirectional exchange.
    pub close_completed: bool,
    /// Selected transport path if completed.
    pub selected_path: Option<SelectedPath>,
    /// Cumulative control-plane enrollment contact events.
    pub enrollment_events: u64,
    /// Whether legacy enrollment remains a possibility for this operation.
    pub legacy_enrollment_possible: bool,
}

/// Write-only counters and progress flags for one operation.
#[derive(Debug, Default)]
pub struct OperationObserver {
    dial_attempts: AtomicU64,
    direct_successes: AtomicU64,
    relay_successes: AtomicU64,
    request_bytes_sent: AtomicU64,
    close_completed: AtomicBool,
    selected_path: AtomicU8,
    enrollment_events: AtomicU64,
    legacy_enrollment_possible: AtomicBool,
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
        saturating_inc(&self.dial_attempts);
    }

    /// Record a successful direct transport leg or HTTP exchange.
    pub fn record_direct_success(&self) {
        saturating_inc(&self.direct_successes);
    }

    /// Record a successful relay transport leg or HTTP exchange.
    pub fn record_relay_success(&self) {
        saturating_inc(&self.relay_successes);
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
        saturating_inc(&self.enrollment_events);
    }

    /// Record that legacy enrollment is potentially possible during this operation.
    pub fn record_legacy_enrollment_possible(&self) {
        self.legacy_enrollment_possible
            .store(true, Ordering::Relaxed);
    }

    /// Clear the legacy enrollment possibility flag upon confirmed v2 enrollment.
    pub fn clear_legacy_enrollment_possible(&self) {
        self.legacy_enrollment_possible
            .store(false, Ordering::Relaxed);
    }

    /// Cumulative physical dial attempts made during this operation.
    pub fn dial_attempts(&self) -> u64 {
        self.dial_attempts.load(Ordering::Relaxed)
    }

    /// Cumulative direct transport leg or HTTP exchange successes.
    pub fn direct_successes(&self) -> u64 {
        self.direct_successes.load(Ordering::Relaxed)
    }

    /// Cumulative relay transport leg or HTTP exchange successes.
    pub fn relay_successes(&self) -> u64 {
        self.relay_successes.load(Ordering::Relaxed)
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

    /// Whether legacy enrollment remains a possibility for this operation.
    pub fn legacy_enrollment_possible(&self) -> bool {
        self.legacy_enrollment_possible.load(Ordering::Relaxed)
    }

    /// Capture a point-in-time snapshot of all observed metrics.
    pub fn snapshot(&self) -> OperationSnapshot {
        OperationSnapshot {
            dial_attempts: self.dial_attempts(),
            direct_successes: self.direct_successes(),
            relay_successes: self.relay_successes(),
            request_bytes_sent: self.request_bytes_sent(),
            close_completed: self.close_completed(),
            selected_path: self.selected_path(),
            enrollment_events: self.enrollment_events(),
            legacy_enrollment_possible: self.legacy_enrollment_possible(),
        }
    }

    #[cfg(test)]
    pub(crate) fn set_dial_attempts_for_test(&self, v: u64) {
        self.dial_attempts.store(v, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn set_direct_successes_for_test(&self, v: u64) {
        self.direct_successes.store(v, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn set_relay_successes_for_test(&self, v: u64) {
        self.relay_successes.store(v, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn set_enrollment_events_for_test(&self, v: u64) {
        self.enrollment_events.store(v, Ordering::Relaxed);
    }
}

pub(crate) fn note_dial_attempt(obs: Option<&OperationObserver>) {
    if let Some(o) = obs {
        o.record_dial_attempt();
    }
}

pub(crate) fn note_direct_success(obs: Option<&OperationObserver>) {
    if let Some(o) = obs {
        o.record_direct_success();
    }
}

pub(crate) fn note_relay_success(obs: Option<&OperationObserver>) {
    if let Some(o) = obs {
        o.record_relay_success();
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

pub(crate) fn note_legacy_enrollment_possible(obs: Option<&OperationObserver>) {
    if let Some(o) = obs {
        o.record_legacy_enrollment_possible();
    }
}

pub(crate) fn note_clear_legacy_enrollment_possible(obs: Option<&OperationObserver>) {
    if let Some(o) = obs {
        o.clear_legacy_enrollment_possible();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recording_methods_return_unit() {
        let obs = OperationObserver::new_unshared();
        let () = obs.record_dial_attempt();
        let () = obs.record_direct_success();
        let () = obs.record_relay_success();
        let () = obs.record_request_bytes(42);
        let () = obs.record_close_completed();
        let () = obs.record_selected_path(SelectedPath::Direct);
        let () = obs.record_enrollment();
        let () = obs.record_legacy_enrollment_possible();

        assert_eq!(obs.dial_attempts(), 1);
        assert_eq!(obs.direct_successes(), 1);
        assert_eq!(obs.relay_successes(), 1);
        assert_eq!(obs.request_bytes_sent(), 42);
        assert!(obs.close_completed());
        assert_eq!(obs.selected_path(), Some(SelectedPath::Direct));
        assert_eq!(obs.enrollment_events(), 1);
        assert!(obs.legacy_enrollment_possible());

        let snapshot = obs.snapshot();
        assert_eq!(
            snapshot,
            OperationSnapshot {
                dial_attempts: 1,
                direct_successes: 1,
                relay_successes: 1,
                request_bytes_sent: 42,
                close_completed: true,
                selected_path: Some(SelectedPath::Direct),
                enrollment_events: 1,
                legacy_enrollment_possible: true,
            }
        );

        let () = obs.clear_legacy_enrollment_possible();
        assert!(!obs.legacy_enrollment_possible());
    }

    #[test]
    fn saturating_counters_do_not_wrap() {
        let obs = OperationObserver::new_unshared();

        obs.set_dial_attempts_for_test(u64::MAX - 1);
        obs.record_dial_attempt();
        assert_eq!(obs.dial_attempts(), u64::MAX);
        obs.record_dial_attempt();
        assert_eq!(obs.dial_attempts(), u64::MAX);

        obs.set_direct_successes_for_test(u64::MAX - 1);
        obs.record_direct_success();
        assert_eq!(obs.direct_successes(), u64::MAX);
        obs.record_direct_success();
        assert_eq!(obs.direct_successes(), u64::MAX);

        obs.set_relay_successes_for_test(u64::MAX - 1);
        obs.record_relay_success();
        assert_eq!(obs.relay_successes(), u64::MAX);
        obs.record_relay_success();
        assert_eq!(obs.relay_successes(), u64::MAX);

        obs.set_enrollment_events_for_test(u64::MAX - 1);
        obs.record_enrollment();
        assert_eq!(obs.enrollment_events(), u64::MAX);
        obs.record_enrollment();
        assert_eq!(obs.enrollment_events(), u64::MAX);
    }
}
