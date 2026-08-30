// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Hostname registrations for journal tunnel connections.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::RwLock;

use crate::frame_dialer::{ConnectionState, DialerError, DialerStream, FrameDialer};
use crate::pop_auth::{PopAuthenticator, RenewalIdentity};

const OPEN_STREAM_TIMEOUT: Duration = Duration::from_secs(3);
const REPLACEMENT_SHUTDOWN_BUDGET: Duration = Duration::from_millis(250);

/// A cheaply cloneable map from a claimed hostname to its current journal.
#[derive(Clone, Default)]
pub struct Registry {
    inner: Arc<RegistryInner>,
}

#[derive(Default)]
struct RegistryInner {
    entries: RwLock<HashMap<String, Arc<RegisteredJournal>>>,
    next_generation: AtomicU64,
}

/// One currently or formerly registered journal tunnel connection.
pub struct RegisteredJournal {
    dialer: FrameDialer,
    generation: u64,
    identity: RenewalIdentity,
    current_expiry: AtomicU64,
}

/// Cleans up a candidate that was never made observable through the registry.
struct CandidateGuard {
    candidate: Arc<RegisteredJournal>,
    armed: bool,
}

impl CandidateGuard {
    fn new(candidate: Arc<RegisteredJournal>) -> Self {
        Self {
            candidate,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CandidateGuard {
    fn drop(&mut self) {
        if self.armed {
            self.candidate.dialer.signal_shutdown();
        }
    }
}

/// Errors returned while opening a client stream through a registration.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegistryError {
    /// A newer registration has replaced this journal connection.
    #[error("journal registration has been retired")]
    Retired,
    /// The journal did not flush the stream OPEN frame within three seconds.
    #[error("journal stream open timed out")]
    OpenTimedOut,
    /// The registration token expired before the candidate could be committed.
    #[error("journal registration token expired before commit")]
    Expired,
    /// The caller's absolute admission deadline elapsed before commit.
    #[error("journal registration admission deadline elapsed before commit")]
    AdmissionDeadlineExceeded,
    /// The journal tunnel connection could not open the stream.
    #[error("journal dialer error: {0}")]
    Dialer(#[from] DialerError),
}

impl Registry {
    /// Register `carrier` as the current journal tunnel for `hostname`.
    ///
    /// Expiry and deadline checks run at the actual commit instant under the
    /// write lock. A displaced entry is retired before the map is updated in the
    /// same atomic section; its bounded shutdown then runs in a registry task.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::Expired`] or [`RegistryError::AdmissionDeadlineExceeded`]
    /// when the candidate cannot be committed at the actual commit instant.
    pub async fn register<T>(
        &self,
        hostname: String,
        carrier: T,
        authenticator: PopAuthenticator,
        identity: RenewalIdentity,
        expires_at: u64,
        admission_deadline: tokio::time::Instant,
    ) -> Result<Arc<RegisteredJournal>, RegistryError>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let generation = self.inner.next_generation.fetch_add(1, Ordering::Relaxed);
        let registered = Arc::new(RegisteredJournal {
            dialer: FrameDialer::new(carrier),
            generation,
            identity,
            current_expiry: AtomicU64::new(expires_at),
        });
        let mut candidate = CandidateGuard::new(Arc::clone(&registered));
        let control_stream = registered.dialer.open_stream().await?;

        let displaced = {
            let mut entries = self.inner.entries.write().await;
            if tokio::time::Instant::now() >= admission_deadline {
                return Err(RegistryError::AdmissionDeadlineExceeded);
            }
            if unix_seconds() >= expires_at {
                return Err(RegistryError::Expired);
            }
            let displaced = entries.get(&hostname).cloned();
            if let Some(displaced) = &displaced {
                displaced.dialer.retire();
            }
            entries.insert(hostname.clone(), Arc::clone(&registered));
            displaced
        };

        let registry = self.clone();
        let watcher = Arc::clone(&registered);
        let generation = registered.generation;
        tokio::spawn(async move {
            watcher.wait_until_gone().await;
            registry.remove_if_current(&hostname, generation).await;
        });

        if let Some(displaced) = displaced {
            tokio::spawn(async move {
                displaced.shutdown_bounded().await;
            });
        }

        tokio::spawn(crate::lease::run_supervisor(
            control_stream,
            Arc::clone(&registered),
            authenticator,
            expires_at,
        ));

        candidate.disarm();
        Ok(registered)
    }

    /// Return the currently registered journal for `hostname`, if one is live.
    pub async fn lookup(&self, hostname: &str) -> Option<Arc<RegisteredJournal>> {
        self.inner.entries.read().await.get(hostname).cloned()
    }

    async fn remove_if_current(&self, hostname: &str, generation: u64) {
        let mut entries = self.inner.entries.write().await;
        if entries
            .get(hostname)
            .is_some_and(|registered| registered.generation == generation)
        {
            entries.remove(hostname);
        }
    }
}

impl RegisteredJournal {
    /// Return this registration's monotonically assigned generation.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Return this registration's dialer connection state.
    pub fn connection_state(&self) -> ConnectionState {
        self.dialer.connection_state()
    }

    pub(crate) fn renewal_identity(&self) -> &RenewalIdentity {
        &self.identity
    }

    pub(crate) fn replace_expiry(&self, expected: u64, replacement: u64) -> bool {
        self.current_expiry
            .compare_exchange(expected, replacement, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    pub(crate) fn retire(&self) {
        self.dialer.retire();
    }

    pub(crate) fn is_retired(&self) -> bool {
        self.dialer.is_retired()
    }

    pub(crate) async fn shutdown_bounded(&self) {
        let _ = tokio::time::timeout(REPLACEMENT_SHUTDOWN_BUDGET, self.dialer.shutdown()).await;
    }

    #[cfg(test)]
    pub(crate) async fn new_for_lease_test<T>(
        carrier: T,
        identity: RenewalIdentity,
        expires_at: u64,
    ) -> Result<(Arc<Self>, DialerStream), DialerError>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let journal = Arc::new(Self {
            dialer: FrameDialer::new(carrier),
            generation: 0,
            identity,
            current_expiry: AtomicU64::new(expires_at),
        });
        let control_stream = journal.dialer.open_stream().await?;
        Ok((journal, control_stream))
    }

    #[cfg(test)]
    pub(crate) fn current_expiry_for_lease_test(&self) -> u64 {
        self.current_expiry.load(Ordering::Acquire)
    }

    /// Wait until this registration's control connection has ended.
    pub async fn wait_until_gone(&self) -> ConnectionState {
        let mut dialer = self.dialer.clone();
        dialer.wait_until_gone().await
    }

    /// Open a logical client stream, rejecting a stalled journal after 3 seconds.
    ///
    /// A caller receiving [`RegistryError::OpenTimedOut`] must close the waiting
    /// client connection instead of leaving it open indefinitely.
    ///
    /// # Errors
    ///
    /// Returns an error when this registration was retired, the journal fails
    /// to open a stream, or its OPEN frame does not flush within three seconds.
    pub async fn open_stream(&self) -> Result<DialerStream, RegistryError> {
        if self.dialer.is_retired() {
            return Err(RegistryError::Retired);
        }
        let stream = tokio::time::timeout(OPEN_STREAM_TIMEOUT, self.dialer.open_stream())
            .await
            .map_err(|_| RegistryError::OpenTimedOut)?
            .map_err(RegistryError::from)?;
        // Never hand out a stream opened by a registration retired mid-flight.
        if self.dialer.is_retired() {
            drop(stream);
            return Err(RegistryError::Retired);
        }
        Ok(stream)
    }
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(u64::MAX, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "tests construct controlled in-memory carrier pairs"
    )]

    use std::collections::HashMap;
    use std::time::Duration;

    use super::*;
    use crate::frame_dialer::StreamEnd;
    use crate::pop_auth::{FixtureTokenVerifier, RenewalIdentity};
    use ed25519_dalek::SigningKey;
    use spl_core::frame::{FLAG_DATA, FrameDecoder};
    use tokio::io::AsyncReadExt;
    use tokio::sync::oneshot;

    fn admission_deadline() -> tokio::time::Instant {
        tokio::time::Instant::now() + Duration::from_secs(10)
    }

    fn authenticator() -> PopAuthenticator {
        let verifier = FixtureTokenVerifier::new(
            HashMap::from([(String::from("fixture"), SigningKey::from_bytes(&[7; 32]))]),
            String::from("bridge-test"),
        );
        PopAuthenticator::new(Arc::new(verifier), String::from("bridge-test"))
    }

    fn identity() -> RenewalIdentity {
        let signing = SigningKey::from_bytes(&[19; 32]);
        RenewalIdentity::new(
            String::from("journal.test"),
            String::from("instance-test"),
            signing.verifying_key(),
        )
    }

    async fn assert_peer_stops(peer: &mut tokio::io::DuplexStream) {
        let mut bytes = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), peer.read_to_end(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        let mut decoder = FrameDecoder::new();
        decoder.feed(&bytes);
        let first = decoder.next_frame().unwrap().unwrap();
        assert_eq!(first.stream_id, 1);
        assert_eq!(first.flags, spl_core::frame::FLAG_OPEN);
        while let Some(frame) = decoder.next_frame().unwrap() {
            assert_eq!(frame.flags & FLAG_DATA, 0);
        }
    }

    #[tokio::test]
    async fn replacement_wins_and_ends_the_displaced_journals_streams() {
        let registry = Registry::default();
        let (first_carrier, mut first_peer) = tokio::io::duplex(1024);
        let first = registry
            .register(
                "journal.test".into(),
                first_carrier,
                authenticator(),
                identity(),
                u64::MAX,
                admission_deadline(),
            )
            .await
            .unwrap();
        let mut stream = first.open_stream().await.unwrap();
        let mut open_frame = [0u8; 16];
        assert_ne!(first_peer.read(&mut open_frame).await.unwrap(), 0);

        let (second_carrier, _second_peer) = tokio::io::duplex(1024);
        let second = registry
            .register(
                "journal.test".into(),
                second_carrier,
                authenticator(),
                identity(),
                u64::MAX,
                admission_deadline(),
            )
            .await
            .unwrap();

        let current = registry.lookup("journal.test").await.unwrap();
        assert!(Arc::ptr_eq(&current, &second));
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), first.wait_until_gone())
                .await
                .unwrap(),
            ConnectionState::Gone
        );
        let mut byte = [0u8; 1];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), first_peer.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );

        let error = tokio::io::AsyncReadExt::read(&mut stream, &mut byte)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
        assert_eq!(stream.end(), Some(StreamEnd::ConnectionGone));
    }

    #[tokio::test]
    async fn organic_connection_close_removes_its_hostname() {
        let registry = Registry::default();
        let (carrier, peer) = tokio::io::duplex(1024);
        let _registered = registry
            .register(
                "journal.test".into(),
                carrier,
                authenticator(),
                identity(),
                u64::MAX,
                admission_deadline(),
            )
            .await
            .unwrap();
        drop(peer);

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if registry.lookup("journal.test").await.is_none() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn acceptance_criterion_renewal_1_reservation_failure_never_publishes() {
        let registry = Registry::default();
        let (carrier, peer) = tokio::io::duplex(16);
        drop(peer);

        assert!(matches!(
            registry
                .register(
                    "closed.test".into(),
                    carrier,
                    authenticator(),
                    identity(),
                    u64::MAX,
                    admission_deadline(),
                )
                .await,
            Err(RegistryError::Dialer(DialerError::ConnectionClosed))
        ));
        assert!(registry.lookup("closed.test").await.is_none());
    }

    #[tokio::test]
    async fn stalled_open_times_out_after_three_seconds() {
        let registry = Registry::default();
        let (carrier, _peer) = tokio::io::duplex(24);
        let journal = registry
            .register(
                "journal.test".into(),
                carrier,
                authenticator(),
                identity(),
                u64::MAX,
                admission_deadline(),
            )
            .await
            .unwrap();
        let first = journal.open_stream().await.unwrap();
        let second = journal.open_stream().await.unwrap();

        let started = tokio::time::Instant::now();
        assert!(matches!(
            journal.open_stream().await,
            Err(RegistryError::OpenTimedOut)
        ));
        assert!(started.elapsed() >= Duration::from_secs(3));
        assert!(started.elapsed() < Duration::from_secs(4));

        drop(first);
        drop(second);
    }

    #[tokio::test]
    async fn acceptance_criterion_4_rejects_expired_and_deadline_candidates_before_publish() {
        let registry = Registry::default();
        let (expired_carrier, mut expired_peer) = tokio::io::duplex(1024);
        assert!(matches!(
            registry
                .register(
                    "expired.test".into(),
                    expired_carrier,
                    authenticator(),
                    identity(),
                    0,
                    admission_deadline(),
                )
                .await,
            Err(RegistryError::Expired)
        ));
        assert!(registry.lookup("expired.test").await.is_none());
        assert_peer_stops(&mut expired_peer).await;

        let (deadline_carrier, mut deadline_peer) = tokio::io::duplex(1024);
        assert!(matches!(
            registry
                .register(
                    "deadline.test".into(),
                    deadline_carrier,
                    authenticator(),
                    identity(),
                    u64::MAX,
                    tokio::time::Instant::now() - Duration::from_millis(1),
                )
                .await,
            Err(RegistryError::AdmissionDeadlineExceeded)
        ));
        assert!(registry.lookup("deadline.test").await.is_none());
        assert_peer_stops(&mut deadline_peer).await;
    }

    #[tokio::test]
    async fn acceptance_criterion_4_rechecks_deadline_at_commit_after_lock_contention() {
        let registry = Registry::default();
        let entries = registry.inner.entries.write().await;
        let pending_registry = registry.clone();
        let (carrier, mut peer) = tokio::io::duplex(1024);
        let deadline = tokio::time::Instant::now() + Duration::from_millis(20);
        let pending = tokio::spawn(async move {
            pending_registry
                .register(
                    "pending.test".into(),
                    carrier,
                    authenticator(),
                    identity(),
                    u64::MAX,
                    deadline,
                )
                .await
        });
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        drop(entries);

        assert!(matches!(
            pending.await.unwrap(),
            Err(RegistryError::AdmissionDeadlineExceeded)
        ));
        assert!(registry.lookup("pending.test").await.is_none());
        assert_peer_stops(&mut peer).await;

        let (carrier, _peer) = tokio::io::duplex(1024);
        assert!(
            registry
                .register(
                    "pending.test".into(),
                    carrier,
                    authenticator(),
                    identity(),
                    u64::MAX,
                    admission_deadline()
                )
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn acceptance_criterion_8_rejects_a_preacquired_handle_before_its_open_check() {
        let registry = Registry::default();
        let (old_carrier, mut old_peer) = tokio::io::duplex(1024);
        let old = registry
            .register(
                "journal.test".into(),
                old_carrier,
                authenticator(),
                identity(),
                u64::MAX,
                admission_deadline(),
            )
            .await
            .unwrap();
        let preacquired = registry.lookup("journal.test").await.unwrap();
        let (ready_tx, ready_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let blocked_open = tokio::spawn(async move {
            let _ = ready_tx.send(());
            release_rx.await.unwrap();
            preacquired.open_stream().await
        });
        ready_rx.await.unwrap();

        let (new_carrier, _new_peer) = tokio::io::duplex(1024);
        let new = registry
            .register(
                "journal.test".into(),
                new_carrier,
                authenticator(),
                identity(),
                u64::MAX,
                admission_deadline(),
            )
            .await
            .unwrap();

        release_tx.send(()).unwrap();
        assert!(matches!(
            blocked_open.await.unwrap(),
            Err(RegistryError::Retired)
        ));
        assert!(Arc::ptr_eq(
            &registry.lookup("journal.test").await.unwrap(),
            &new
        ));
        let stream = new.open_stream().await.unwrap();
        drop(stream);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), old.wait_until_gone())
                .await
                .unwrap(),
            ConnectionState::Gone
        );
        assert_peer_stops(&mut old_peer).await;
    }

    #[tokio::test]
    async fn acceptance_criterion_renewal_4_expiry_rejects_a_preacquired_handle_before_its_open_check()
     {
        let registry = Registry::default();
        let (old_carrier, mut old_peer) = tokio::io::duplex(1024);
        let old = registry
            .register(
                "journal.test".into(),
                old_carrier,
                authenticator(),
                identity(),
                u64::MAX,
                admission_deadline(),
            )
            .await
            .unwrap();
        let preacquired = registry.lookup("journal.test").await.unwrap();
        let (ready_tx, ready_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let blocked_open = tokio::spawn(async move {
            let _ = ready_tx.send(());
            release_rx.await.unwrap();
            preacquired.open_stream().await
        });
        ready_rx.await.unwrap();

        // This is the same pair of operations performed by lease expiry.
        old.retire();
        assert!(Arc::ptr_eq(
            &registry.lookup("journal.test").await.unwrap(),
            &old
        ));
        release_tx.send(()).unwrap();
        assert!(matches!(
            blocked_open.await.unwrap(),
            Err(RegistryError::Retired)
        ));

        old.shutdown_bounded().await;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), old.wait_until_gone())
                .await
                .unwrap(),
            ConnectionState::Gone
        );
        assert_peer_stops(&mut old_peer).await;
    }

    #[tokio::test]
    async fn acceptance_criterion_8_rechecks_a_preacquired_handle_after_stalled_open() {
        let registry = Registry::default();
        let (old_carrier, mut old_peer) = tokio::io::duplex(24);
        let old = registry
            .register(
                "journal.test".into(),
                old_carrier,
                authenticator(),
                identity(),
                u64::MAX,
                admission_deadline(),
            )
            .await
            .unwrap();
        let preacquired = registry.lookup("journal.test").await.unwrap();
        let first = preacquired.open_stream().await.unwrap();
        let second = preacquired.open_stream().await.unwrap();
        let late_open = preacquired.open_stream();
        tokio::pin!(late_open);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut late_open)
                .await
                .is_err()
        );

        let (new_carrier, _new_peer) = tokio::io::duplex(1024);
        let new = registry
            .register(
                "journal.test".into(),
                new_carrier,
                authenticator(),
                identity(),
                u64::MAX,
                admission_deadline(),
            )
            .await
            .unwrap();
        assert!(matches!(
            late_open.await,
            Err(RegistryError::Retired | RegistryError::Dialer(DialerError::ConnectionClosed))
        ));
        assert!(new.open_stream().await.is_ok());
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), old.wait_until_gone())
                .await
                .unwrap(),
            ConnectionState::Gone
        );
        let mut bytes = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), old_peer.read_to_end(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        let mut decoder = FrameDecoder::new();
        decoder.feed(&bytes);
        while let Some(frame) = decoder.next_frame().unwrap() {
            assert_eq!(frame.flags & FLAG_DATA, 0);
        }
        drop(first);
        drop(second);
    }

    #[tokio::test]
    async fn acceptance_criterion_renewal_4_expiry_rechecks_a_preacquired_handle_after_stalled_open()
     {
        let registry = Registry::default();
        let (old_carrier, mut old_peer) = tokio::io::duplex(24);
        let old = registry
            .register(
                "journal.test".into(),
                old_carrier,
                authenticator(),
                identity(),
                u64::MAX,
                admission_deadline(),
            )
            .await
            .unwrap();
        let preacquired = registry.lookup("journal.test").await.unwrap();
        let first = preacquired.open_stream().await.unwrap();
        let second = preacquired.open_stream().await.unwrap();
        let late_open = preacquired.open_stream();
        tokio::pin!(late_open);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut late_open)
                .await
                .is_err()
        );

        old.retire();
        old.shutdown_bounded().await;
        assert!(matches!(
            late_open.await,
            Err(RegistryError::Retired | RegistryError::Dialer(DialerError::ConnectionClosed))
        ));
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), old.wait_until_gone())
                .await
                .unwrap(),
            ConnectionState::Gone
        );
        let mut bytes = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), old_peer.read_to_end(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        let mut decoder = FrameDecoder::new();
        decoder.feed(&bytes);
        while let Some(frame) = decoder.next_frame().unwrap() {
            assert_eq!(frame.flags & FLAG_DATA, 0);
        }
        drop(first);
        drop(second);
    }

    #[tokio::test]
    async fn acceptance_criterion_renewal_4_expiry_during_fast_open_lets_the_writer_win() {
        let registry = Registry::default();
        let (carrier, mut peer) = tokio::io::duplex(1024);
        let old = registry
            .register(
                "journal.test".into(),
                carrier,
                authenticator(),
                identity(),
                u64::MAX,
                admission_deadline(),
            )
            .await
            .unwrap();
        let preacquired = registry.lookup("journal.test").await.unwrap();
        let stream = preacquired.open_stream().await.unwrap();
        let stream_id = stream.id();

        let mut decoder = FrameDecoder::new();
        let mut saw_open = false;
        tokio::time::timeout(Duration::from_secs(1), async {
            while !saw_open {
                let mut bytes = [0u8; 64];
                let read = peer.read(&mut bytes).await.unwrap();
                assert_ne!(read, 0);
                decoder.feed(&bytes[..read]);
                while let Some(frame) = decoder.next_frame().unwrap() {
                    if frame.stream_id == stream_id && frame.flags == spl_core::frame::FLAG_OPEN {
                        saw_open = true;
                    }
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(stream.id(), stream_id);

        old.retire();
        old.shutdown_bounded().await;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), old.wait_until_gone())
                .await
                .unwrap(),
            ConnectionState::Gone
        );
        drop(stream);
    }

    #[tokio::test]
    async fn acceptance_criterion_renewal_4_expiry_removes_the_entry_and_a_new_generation_stays_usable()
     {
        let registry = Registry::default();
        let (old_carrier, _old_peer) = tokio::io::duplex(1024);
        let old = registry
            .register(
                "journal.test".into(),
                old_carrier,
                authenticator(),
                identity(),
                u64::MAX,
                admission_deadline(),
            )
            .await
            .unwrap();

        old.retire();
        old.shutdown_bounded().await;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), old.wait_until_gone())
                .await
                .unwrap(),
            ConnectionState::Gone
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if registry.lookup("journal.test").await.is_none() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        let (new_carrier, _new_peer) = tokio::io::duplex(1024);
        let new = registry
            .register(
                "journal.test".into(),
                new_carrier,
                authenticator(),
                identity(),
                u64::MAX,
                admission_deadline(),
            )
            .await
            .unwrap();
        assert!(Arc::ptr_eq(
            &registry.lookup("journal.test").await.unwrap(),
            &new
        ));
        assert!(new.open_stream().await.is_ok());
    }

    #[tokio::test]
    async fn acceptance_criterion_9_timeout_drop_cleans_an_unpublished_candidate() {
        let registry = Registry::default();
        let entries = registry.inner.entries.write().await;
        let pending_registry = registry.clone();
        let (carrier, mut peer) = tokio::io::duplex(1024);
        assert!(
            tokio::time::timeout(
                Duration::from_millis(20),
                pending_registry.register(
                    "cancelled.test".into(),
                    carrier,
                    authenticator(),
                    identity(),
                    u64::MAX,
                    admission_deadline(),
                ),
            )
            .await
            .is_err()
        );
        drop(entries);

        assert!(registry.lookup("cancelled.test").await.is_none());
        assert_peer_stops(&mut peer).await;
        let (carrier, _peer) = tokio::io::duplex(1024);
        assert!(
            registry
                .register(
                    "cancelled.test".into(),
                    carrier,
                    authenticator(),
                    identity(),
                    u64::MAX,
                    admission_deadline(),
                )
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn acceptance_criterion_10_abort_cleans_an_unpublished_candidate() {
        let registry = Registry::default();
        let entries = registry.inner.entries.write().await;
        let pending_registry = registry.clone();
        let (carrier, mut peer) = tokio::io::duplex(1024);
        let pending = tokio::spawn(async move {
            pending_registry
                .register(
                    "aborted.test".into(),
                    carrier,
                    authenticator(),
                    identity(),
                    u64::MAX,
                    admission_deadline(),
                )
                .await
        });
        tokio::task::yield_now().await;
        pending.abort();
        assert!(pending.await.is_err());
        assert_peer_stops(&mut peer).await;
        drop(entries);

        assert!(registry.lookup("aborted.test").await.is_none());
        let (carrier, _peer) = tokio::io::duplex(1024);
        assert!(
            registry
                .register(
                    "aborted.test".into(),
                    carrier,
                    authenticator(),
                    identity(),
                    u64::MAX,
                    admission_deadline(),
                )
                .await
                .is_ok()
        );
    }
}
