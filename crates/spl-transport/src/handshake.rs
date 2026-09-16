// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Client rules for a journal that refuses the inner TLS handshake.
//!
//! The SPL session protocol (`.proto-ref/session.md` § 7) splits refusals three
//! ways: access denied (49) means the device is unpaired, so stop; certificate
//! unknown (46) means the journal could not read its pairing records, so retry
//! and keep the credential; any other refusal retries until refusals have gone
//! on long enough, then stops as unpaired. A journal that was never reached is
//! not refusing anything and never counts.
//!
//! [`RefusalTracker`] is that rule as one value, so every client applies the
//! same bound. The journal bridge keeps one per bridge; a consumer that makes
//! its own requests keeps one per credential and classifies each failed request
//! from [`crate::RequestError::transport_error`], because a counted refusal can
//! arrive as [`crate::RequestError::ReplayUnsafe`].

use std::time::Duration;

use tokio::time::Instant;

use crate::TransportError;

/// Counted refusals that stop a client with [`HandshakeStop::RefusalsExhausted`].
pub const REFUSAL_LIMIT: u32 = 7;

/// Minimum spacing between two counted refusals.
///
/// Refusals closer together than this count once, so a burst of retries cannot
/// reach the limit. With [`REFUSAL_LIMIT`], a client stops only after refusals
/// have continued for at least `(REFUSAL_LIMIT - 1) * REFUSAL_SPACING`. Time
/// without attempts, or with the journal unreachable, never advances the count.
pub const REFUSAL_SPACING: Duration = Duration::from_mins(5);

/// How one attempt to reach the journal failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeFailure {
    /// The journal was not reached: no route, a timeout, a dropped
    /// connection, or a relay that could not connect. Retry; this never counts
    /// as a refusal. A relay's own rejection of the device (an expired token,
    /// an unknown instance, an unpaid account) also lands here, because the
    /// journal did not answer; a consumer that acts on relay rejections reads
    /// them from its transport error.
    Unreachable,
    /// The journal refused this device with access denied (49).
    TlsAccessDenied,
    /// The journal could not read its pairing records (46). Retry and keep the
    /// credential; this neither counts as a refusal nor clears the count.
    TlsCertificateUnknown,
    /// The journal refused the handshake with any other alert. Retry; counted
    /// toward [`REFUSAL_LIMIT`].
    TlsRefused,
    /// A peer that is not the paired journal answered: a different journal at a
    /// saved address, or this journal after its CA changed. Retry; this neither
    /// counts as a refusal nor clears the count. A journal whose CA changed needs
    /// a new pairing, which the owner is told about through the transport's
    /// [`crate::UnknownJournal`] sighting rather than a stop.
    UnknownJournal,
}

impl HandshakeFailure {
    /// Classify a failed attempt from its transport error.
    #[must_use]
    pub fn classify(error: &TransportError) -> Self {
        match error {
            TransportError::TlsAccessDenied => Self::TlsAccessDenied,
            TransportError::TlsCertificateUnknown => Self::TlsCertificateUnknown,
            TransportError::TlsRefused => Self::TlsRefused,
            TransportError::UnknownJournal(_) => Self::UnknownJournal,
            _ => Self::Unreachable,
        }
    }
}

/// Why a client stops trying a credential. Both present the unpaired state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeStop {
    /// The journal refused this device with access denied (49): it is not
    /// paired. Present the unpaired state and require a new pairing.
    TlsAccessDenied,
    /// Refusals other than access denied and certificate unknown reached
    /// [`REFUSAL_LIMIT`]. Present the unpaired state.
    RefusalsExhausted,
}

impl HandshakeStop {
    /// The error a stopped client reports instead of dialing.
    ///
    /// It repeats the stop; it is not a new refusal, so do not feed it back into
    /// a [`RefusalTracker`].
    #[must_use]
    pub fn error(self) -> TransportError {
        match self {
            Self::TlsAccessDenied => TransportError::TlsAccessDenied,
            Self::RefusalsExhausted => TransportError::TlsRefused,
        }
    }
}

/// The handshake-refusal state for one credential.
///
/// Feed it every attempt's outcome: [`RefusalTracker::accepted`] when the
/// journal accepted the handshake (it answered anything at all), and
/// [`RefusalTracker::failed`] otherwise. Once [`RefusalTracker::stop`] is set it
/// never clears; a new pairing starts a new tracker.
#[derive(Debug, Clone, Default)]
pub struct RefusalTracker {
    refusals: u32,
    last_counted: Option<Instant>,
    last_failure: Option<HandshakeFailure>,
    stop: Option<HandshakeStop>,
}

impl RefusalTracker {
    /// A tracker with no refusals.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The journal accepted a handshake. Only this clears the refusal count.
    pub fn accepted(&mut self) {
        self.refusals = 0;
        self.last_counted = None;
        self.last_failure = None;
    }

    /// Record one failed attempt and return the stop reason, if any.
    pub fn failed(&mut self, failure: HandshakeFailure) -> Option<HandshakeStop> {
        self.last_failure = Some(failure);
        match failure {
            HandshakeFailure::TlsAccessDenied => self.deny(),
            HandshakeFailure::TlsRefused => {
                let now = Instant::now();
                let counts = self
                    .last_counted
                    .is_none_or(|last| now.saturating_duration_since(last) >= REFUSAL_SPACING);
                if counts {
                    self.last_counted = Some(now);
                    self.refusals = self.refusals.saturating_add(1);
                    if self.refusals >= REFUSAL_LIMIT {
                        self.latch(HandshakeStop::RefusalsExhausted);
                    }
                }
            }
            HandshakeFailure::Unreachable
            | HandshakeFailure::TlsCertificateUnknown
            | HandshakeFailure::UnknownJournal => {}
        }
        self.stop
    }

    /// Stop for access denied without recording an attempt, for a refusal
    /// from an attempt that a newer one has already replaced.
    pub fn deny(&mut self) {
        self.latch(HandshakeStop::TlsAccessDenied);
    }

    fn latch(&mut self, stop: HandshakeStop) {
        if self.stop.is_none() {
            self.stop = Some(stop);
        }
    }

    /// Refusals counted since the journal last accepted a handshake.
    #[must_use]
    pub fn refusals(&self) -> u32 {
        self.refusals
    }

    /// How the most recent attempt failed, if none has been accepted since.
    #[must_use]
    pub fn last_failure(&self) -> Option<HandshakeFailure> {
        self.last_failure
    }

    /// Why this credential stopped, if it has.
    #[must_use]
    pub fn stop(&self) -> Option<HandshakeStop> {
        self.stop
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Protocol: `.proto-ref/session.md` § 7, "every other code". Falsified by counting every
    // refusal: the retry burst below reaches the limit within one spacing interval.
    #[tokio::test(start_paused = true)]
    async fn refusals_count_once_per_spacing_and_stop_at_the_limit() {
        let mut tracker = RefusalTracker::new();
        for _ in 0..(REFUSAL_LIMIT * 3) {
            assert_eq!(tracker.failed(HandshakeFailure::TlsRefused), None);
        }
        assert_eq!(tracker.refusals(), 1);
        assert_eq!(tracker.last_failure(), Some(HandshakeFailure::TlsRefused));

        for counted in 2..REFUSAL_LIMIT {
            tokio::time::advance(REFUSAL_SPACING).await;
            assert_eq!(tracker.failed(HandshakeFailure::TlsRefused), None);
            assert_eq!(tracker.refusals(), counted);
        }

        tokio::time::advance(REFUSAL_SPACING.checked_sub(Duration::from_secs(1)).unwrap()).await;
        assert_eq!(tracker.failed(HandshakeFailure::TlsRefused), None);

        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(
            tracker.failed(HandshakeFailure::TlsRefused),
            Some(HandshakeStop::RefusalsExhausted)
        );
        assert_eq!(tracker.refusals(), REFUSAL_LIMIT);

        // A stop never clears, not even after an accepted handshake.
        tracker.accepted();
        assert_eq!(tracker.stop(), Some(HandshakeStop::RefusalsExhausted));
    }

    // Protocol: `.proto-ref/session.md` § 7. Falsified by letting 46 or an unreachable attempt
    // reset the count (the count drops) or advance it (the count grows).
    #[tokio::test(start_paused = true)]
    async fn unreachable_certificate_unknown_and_unknown_journal_neither_advance_nor_clear_refusals()
     {
        let mut tracker = RefusalTracker::new();
        tracker.failed(HandshakeFailure::TlsRefused);
        for failure in [
            HandshakeFailure::Unreachable,
            HandshakeFailure::TlsCertificateUnknown,
            HandshakeFailure::UnknownJournal,
        ] {
            for _ in 0..(REFUSAL_LIMIT * 2) {
                tokio::time::advance(REFUSAL_SPACING).await;
                assert_eq!(tracker.failed(failure), None);
                assert_eq!(tracker.refusals(), 1);
                assert_eq!(tracker.last_failure(), Some(failure));
            }
        }
        // Days offline between two refusals still advance the count by one.
        tokio::time::advance(Duration::from_hours(48)).await;
        assert_eq!(tracker.failed(HandshakeFailure::TlsRefused), None);
        assert_eq!(tracker.refusals(), 2);
    }

    // Protocol: `.proto-ref/session.md` § 7, "only a completed handshake clears the state".
    #[tokio::test(start_paused = true)]
    async fn only_an_accepted_handshake_clears_refusals() {
        let mut tracker = RefusalTracker::new();
        for _ in 0..(REFUSAL_LIMIT - 1) {
            tracker.failed(HandshakeFailure::TlsRefused);
            tokio::time::advance(REFUSAL_SPACING).await;
        }
        assert_eq!(tracker.refusals(), REFUSAL_LIMIT - 1);

        tracker.accepted();
        assert_eq!(tracker.refusals(), 0);
        assert_eq!(tracker.last_failure(), None);

        // The spacing restarts with the count: the next refusal counts at once.
        tracker.failed(HandshakeFailure::TlsRefused);
        assert_eq!(tracker.refusals(), 1);
        assert_eq!(tracker.stop(), None);
    }

    #[test]
    fn access_denied_stops_and_certificate_unknown_never_does() {
        let mut tracker = RefusalTracker::new();
        for _ in 0..(REFUSAL_LIMIT * 2) {
            assert_eq!(
                tracker.failed(HandshakeFailure::TlsCertificateUnknown),
                None
            );
        }
        assert_eq!(
            tracker.failed(HandshakeFailure::TlsAccessDenied),
            Some(HandshakeStop::TlsAccessDenied)
        );
        assert!(matches!(
            HandshakeStop::TlsAccessDenied.error(),
            TransportError::TlsAccessDenied
        ));
        assert!(matches!(
            HandshakeStop::RefusalsExhausted.error(),
            TransportError::TlsRefused
        ));

        let mut denied = RefusalTracker::new();
        denied.deny();
        assert_eq!(denied.stop(), Some(HandshakeStop::TlsAccessDenied));
        assert_eq!(denied.last_failure(), None);
    }

    #[test]
    fn classify_names_refusals_and_treats_everything_else_as_unreachable() {
        assert_eq!(
            HandshakeFailure::classify(&TransportError::TlsAccessDenied),
            HandshakeFailure::TlsAccessDenied
        );
        assert_eq!(
            HandshakeFailure::classify(&TransportError::TlsCertificateUnknown),
            HandshakeFailure::TlsCertificateUnknown
        );
        assert_eq!(
            HandshakeFailure::classify(&TransportError::TlsRefused),
            HandshakeFailure::TlsRefused
        );
        assert_eq!(
            HandshakeFailure::classify(&TransportError::UnknownJournal(crate::UnknownJournal {
                address: None,
                jid: None,
            })),
            HandshakeFailure::UnknownJournal
        );
        for error in [
            TransportError::Tls("handshake".into()),
            TransportError::Io(std::io::Error::from(std::io::ErrorKind::ConnectionRefused)),
            TransportError::NoEndpoint,
            TransportError::Relay(crate::RelayError::HomeOffline),
            TransportError::Relay(crate::RelayError::Unauthorized),
        ] {
            assert_eq!(
                HandshakeFailure::classify(&error),
                HandshakeFailure::Unreachable
            );
        }
    }
}
