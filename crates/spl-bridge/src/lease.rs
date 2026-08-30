// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Journal lease renewal scheduling.

use std::future::pending;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::time::Instant;

use crate::BridgeLogEvent;
use crate::frame_dialer::DialerStream;
use crate::pop_auth::{PopAuthenticator, PopError, RenewalError};
use crate::registry::RegisteredJournal;

const RENEWAL_WINDOW: Duration = Duration::from_mins(2);
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);
const ATTEMPT_FLOOR: Duration = Duration::from_secs(15);
const RECONCILIATION_INTERVAL: Duration = Duration::from_secs(1);

type WallClockFn = Arc<dyn Fn() -> SystemTime + Send + Sync>;

#[cfg(test)]
#[derive(Clone)]
struct CommitPause {
    reached: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

#[cfg(test)]
impl CommitPause {
    fn new() -> Self {
        Self {
            reached: Arc::new(tokio::sync::Notify::new()),
            release: Arc::new(tokio::sync::Notify::new()),
        }
    }

    async fn wait_until_paused(&self) {
        self.reached.notified().await;
    }
    fn release(&self) {
        self.release.notify_one();
    }
    async fn wait(&self) {
        self.reached.notify_one();
        self.release.notified().await;
    }
}

struct LeaseSchedule {
    renewal_start: Option<Instant>,
    max_deadline: Option<Instant>,
}

impl LeaseSchedule {
    fn install(expires_at: u64, wall_now: SystemTime, monotonic_now: Instant) -> Self {
        Self {
            renewal_start: deadline_from_wall(expires_at, RENEWAL_WINDOW, wall_now, monotonic_now),
            max_deadline: deadline_from_wall(expires_at, Duration::ZERO, wall_now, monotonic_now),
        }
    }

    fn ratchet_earlier(&mut self, expires_at: u64, wall_now: SystemTime, monotonic_now: Instant) {
        ratchet_deadline(
            &mut self.renewal_start,
            deadline_from_wall(expires_at, RENEWAL_WINDOW, wall_now, monotonic_now),
        );
        ratchet_deadline(
            &mut self.max_deadline,
            deadline_from_wall(expires_at, Duration::ZERO, wall_now, monotonic_now),
        );
    }

    fn next_attempt_at(
        &self,
        last_attempt_start: Option<Instant>,
        now: Instant,
    ) -> Option<Instant> {
        let renewal_start = self.renewal_start?;
        if renewal_start > now {
            return Some(renewal_start);
        }
        match last_attempt_start.and_then(|start| start.checked_add(ATTEMPT_FLOOR)) {
            Some(floor) if floor > now => Some(floor),
            _ => Some(now),
        }
    }
}

pub(crate) async fn run_supervisor(
    control_stream: DialerStream,
    journal: Arc<RegisteredJournal>,
    authenticator: PopAuthenticator,
    expires_at: u64,
) {
    run_supervisor_with_clock(
        control_stream,
        journal,
        authenticator,
        expires_at,
        Arc::new(SystemTime::now),
        #[cfg(test)]
        None,
    )
    .await;
}

async fn run_supervisor_with_clock(
    control_stream: DialerStream,
    journal: Arc<RegisteredJournal>,
    authenticator: PopAuthenticator,
    expires_at: u64,
    wall_clock: WallClockFn,
    #[cfg(test)] commit_pause: Option<CommitPause>,
) {
    let (wall_now, monotonic_now) = sample_clocks(&wall_clock);
    let mut schedule = LeaseSchedule::install(expires_at, wall_now, monotonic_now);
    let mut current_expiry = expires_at;
    let mut control_stream = Some(control_stream);
    let mut next_reconciliation = monotonic_now
        .checked_add(RECONCILIATION_INTERVAL)
        .unwrap_or(monotonic_now);
    let mut last_attempt_start = None;
    let mut poisoned = false;
    let gone = journal.wait_until_gone();
    tokio::pin!(gone);

    loop {
        let now = Instant::now();
        if deadline_due(schedule.max_deadline, now) {
            retire_for_expiry(&journal).await;
            return;
        }

        let attempt_at = if poisoned {
            None
        } else {
            schedule.next_attempt_at(last_attempt_start, now)
        };
        tokio::select! {
            _state = &mut gone => return,
            () = tokio::time::sleep_until(next_reconciliation) => {
                let (wall_now, monotonic_now) = sample_clocks(&wall_clock);
                schedule.ratchet_earlier(current_expiry, wall_now, monotonic_now);
                next_reconciliation = monotonic_now
                    .checked_add(RECONCILIATION_INTERVAL)
                    .unwrap_or(monotonic_now);
            }
            () = wait_until(schedule.max_deadline) => {
                retire_for_expiry(&journal).await;
                return;
            }
            () = wait_until(attempt_at), if !poisoned => {
                let started = Instant::now();
                last_attempt_start = Some(started);
                let Some(stream) = control_stream.as_mut() else {
                    poisoned = true;
                    continue;
                };
                let context = AttemptContext {
                    authenticator: &authenticator,
                    identity: journal.renewal_identity(),
                    current_expiry,
                    schedule: &mut schedule,
                    wall_clock: &wall_clock,
                    next_reconciliation: &mut next_reconciliation,
                    started,
                };
                match run_attempt(stream, context).await {
                    AttemptResult::Renewed(successor_expiry) => {
                        #[cfg(test)]
                        if let Some(pause) = &commit_pause {
                            pause.wait().await;
                            let attempt_deadline = started.checked_add(ATTEMPT_TIMEOUT);
                            if deadline_due(
                                earlier_deadline(attempt_deadline, schedule.max_deadline),
                                Instant::now(),
                            ) {
                                retire_for_expiry(&journal).await;
                                return;
                            }
                        }
                        if journal.is_retired()
                            || !journal.replace_expiry(current_expiry, successor_expiry)
                        {
                            control_stream.take();
                            poisoned = true;
                            BridgeLogEvent::JournalLeaseRenewalTerminalPoisoned.emit();
                            continue;
                        }
                        current_expiry = successor_expiry;
                        let (wall_now, monotonic_now) = sample_clocks(&wall_clock);
                        schedule = LeaseSchedule::install(current_expiry, wall_now, monotonic_now);
                        next_reconciliation = monotonic_now
                            .checked_add(RECONCILIATION_INTERVAL)
                            .unwrap_or(monotonic_now);
                        BridgeLogEvent::JournalLeaseRenewed.emit();
                    }
                    AttemptResult::Retryable(error) => emit_retryable(&error),
                    AttemptResult::Terminal => {
                        control_stream.take();
                        poisoned = true;
                        BridgeLogEvent::JournalLeaseRenewalTerminalPoisoned.emit();
                    }
                }
            }
        }
    }
}

enum AttemptResult {
    Renewed(u64),
    Retryable(PopError),
    Terminal,
}

struct AttemptContext<'a> {
    authenticator: &'a PopAuthenticator,
    identity: &'a crate::pop_auth::RenewalIdentity,
    current_expiry: u64,
    schedule: &'a mut LeaseSchedule,
    wall_clock: &'a WallClockFn,
    next_reconciliation: &'a mut Instant,
    started: Instant,
}

async fn run_attempt(stream: &mut DialerStream, context: AttemptContext<'_>) -> AttemptResult {
    let attempt = context
        .authenticator
        .renew(stream, context.identity, context.current_expiry);
    tokio::pin!(attempt);
    let attempt_cap = context.started.checked_add(ATTEMPT_TIMEOUT);

    loop {
        let effective_deadline = earlier_deadline(attempt_cap, context.schedule.max_deadline);
        tokio::select! {
            result = &mut attempt => match result {
                Ok(successor_expiry) => return AttemptResult::Renewed(successor_expiry),
                Err(RenewalError::Retryable(error)) => return AttemptResult::Retryable(error),
                Err(RenewalError::Terminal) => return AttemptResult::Terminal,
            },
            () = tokio::time::sleep_until(*context.next_reconciliation) => {
                let (wall_now, monotonic_now) = sample_clocks(context.wall_clock);
                context.schedule.ratchet_earlier(context.current_expiry, wall_now, monotonic_now);
                *context.next_reconciliation = monotonic_now
                    .checked_add(RECONCILIATION_INTERVAL)
                    .unwrap_or(monotonic_now);
                if deadline_due(context.schedule.max_deadline, monotonic_now) {
                    return AttemptResult::Terminal;
                }
            }
            () = wait_until(effective_deadline) => return AttemptResult::Terminal,
        }
    }
}

async fn retire_for_expiry(journal: &RegisteredJournal) {
    journal.retire();
    BridgeLogEvent::JournalLeaseExpiredWallClock.emit();
    journal.shutdown_bounded().await;
}

fn emit_retryable(error: &PopError) {
    match error {
        PopError::NonceOutstandingCapacity => {
            BridgeLogEvent::JournalLeaseRenewalNonceOutstandingCapacity.emit();
        }
        PopError::NonceSpentCapacity => {
            BridgeLogEvent::JournalLeaseRenewalNonceSpentCapacity.emit();
        }
        _ => BridgeLogEvent::JournalLeaseRenewalRetryableAttemptFailed.emit(),
    }
}

fn sample_clocks(wall_clock: &WallClockFn) -> (SystemTime, Instant) {
    (wall_clock(), Instant::now())
}

fn deadline_from_wall(
    expires_at: u64,
    lead_time: Duration,
    wall_now: SystemTime,
    monotonic_now: Instant,
) -> Option<Instant> {
    let Ok(now) = wall_now.duration_since(UNIX_EPOCH) else {
        return Some(monotonic_now);
    };
    let threshold = Duration::from_secs(expires_at.saturating_sub(lead_time.as_secs()));
    let remaining = threshold.checked_sub(now).unwrap_or(Duration::ZERO);
    monotonic_now.checked_add(remaining)
}

fn ratchet_deadline(installed: &mut Option<Instant>, candidate: Option<Instant>) {
    match (*installed, candidate) {
        (None, Some(candidate)) => *installed = Some(candidate),
        (Some(installed_deadline), Some(candidate)) if candidate < installed_deadline => {
            *installed = Some(candidate);
        }
        _ => {}
    }
}

fn earlier_deadline(first: Option<Instant>, second: Option<Instant>) -> Option<Instant> {
    match (first, second) {
        (Some(first), Some(second)) => Some(first.min(second)),
        (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
        (None, None) => None,
    }
}

fn deadline_due(deadline: Option<Instant>, now: Instant) -> bool {
    deadline.is_some_and(|deadline| deadline <= now)
}

async fn wait_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => pending::<()>().await,
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "clock fixtures use controlled in-memory state"
    )]

    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::Value;
    use spl_core::frame::Frame;
    use spl_home::{MuxAcceptor, MuxEvent, MuxLimits};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::sync::oneshot;

    use crate::pop_auth::{FixtureTokenVerifier, RenewalIdentity};

    const BRIDGE_ID: &str = "bridge-lease-schedule-test";
    const HOSTNAME: &str = "aaaqeaye.solstone.me";
    const INSTANCE_ID: &str = "8488ae64-b592-80a3-97c6-490e995daa85";

    #[tokio::test(start_paused = true)]
    async fn acceptance_criterion_renewal_9_wall_clock_ratchet_never_extends_a_deadline() {
        let wall = Arc::new(Mutex::new(
            UNIX_EPOCH + Duration::from_secs(1_000) + Duration::from_millis(500),
        ));
        let clock: WallClockFn = {
            let wall = Arc::clone(&wall);
            Arc::new(move || *wall.lock().unwrap())
        };
        let (wall_now, monotonic_now) = sample_clocks(&clock);
        let mut schedule = LeaseSchedule::install(1_300, wall_now, monotonic_now);
        let installed_max_deadline = schedule.max_deadline.unwrap();
        let installed_renewal_start = schedule.renewal_start.unwrap();

        *wall.lock().unwrap() = UNIX_EPOCH + Duration::from_mins(20) + Duration::from_millis(250);
        tokio::time::advance(RECONCILIATION_INTERVAL).await;
        let (wall_now, monotonic_now) = sample_clocks(&clock);
        schedule.ratchet_earlier(1_300, wall_now, monotonic_now);
        let shortened_max_deadline = schedule.max_deadline.unwrap();
        let shortened_renewal_start = schedule.renewal_start.unwrap();
        assert!(shortened_max_deadline < installed_max_deadline);
        assert!(shortened_renewal_start < installed_renewal_start);

        *wall.lock().unwrap() =
            UNIX_EPOCH + Duration::from_secs(1_001) + Duration::from_millis(125);
        tokio::time::advance(RECONCILIATION_INTERVAL).await;
        let (wall_now, monotonic_now) = sample_clocks(&clock);
        schedule.ratchet_earlier(1_300, wall_now, monotonic_now);
        assert_eq!(schedule.max_deadline, Some(shortened_max_deadline));
        assert_eq!(schedule.renewal_start, Some(shortened_renewal_start));
    }

    #[test]
    fn unbounded_test_expiry_does_not_overflow_schedule_math() {
        let schedule = LeaseSchedule::install(u64::MAX, SystemTime::now(), Instant::now());
        assert_eq!(schedule.renewal_start, None);
        assert_eq!(schedule.max_deadline, None);
    }

    #[test]
    fn renewal_window_starts_immediately_and_attempts_observe_the_floor() {
        let monotonic_now = Instant::now();
        let schedule = LeaseSchedule::install(
            1_120,
            UNIX_EPOCH + Duration::from_secs(1_000) + Duration::from_millis(750),
            monotonic_now,
        );
        assert_eq!(schedule.renewal_start, Some(monotonic_now));
        let previous = monotonic_now.checked_add(Duration::from_secs(1)).unwrap();
        assert_eq!(
            schedule.next_attempt_at(Some(previous), monotonic_now),
            previous.checked_add(ATTEMPT_FLOOR)
        );
    }

    #[test]
    fn attempt_deadline_is_capped_by_the_current_lease_deadline() {
        let now = Instant::now();
        let cap = now.checked_add(ATTEMPT_TIMEOUT);
        let lease_deadline = now.checked_add(Duration::from_secs(3));
        assert_eq!(earlier_deadline(cap, lease_deadline), lease_deadline);
    }

    #[tokio::test(start_paused = true)]
    async fn acceptance_criterion_renewal_2_e2_replaces_e1_and_wall_expiry_retires() {
        let real_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let e1 = real_now + 600;
        let e2 = real_now + 900;
        let issuer = SigningKey::from_bytes(&[7; 32]);
        let pop = SigningKey::from_bytes(&[19; 32]);
        let verifier = FixtureTokenVerifier::new(
            HashMap::from([(String::from("fixture"), issuer)]),
            String::from(BRIDGE_ID),
        );
        let successor = verifier
            .mint(
                "fixture",
                INSTANCE_ID,
                HOSTNAME,
                real_now,
                e2,
                &pop.verifying_key(),
            )
            .unwrap();
        let authenticator = PopAuthenticator::new(Arc::new(verifier), String::from(BRIDGE_ID));
        let identity = RenewalIdentity::new(
            String::from(HOSTNAME),
            String::from(INSTANCE_ID),
            pop.verifying_key(),
        );
        let wall = Arc::new(Mutex::new(
            UNIX_EPOCH + Duration::from_secs(e1 - RENEWAL_WINDOW.as_secs()),
        ));
        let clock: WallClockFn = {
            let wall = Arc::clone(&wall);
            Arc::new(move || *wall.lock().unwrap())
        };
        let (carrier, peer) = tokio::io::duplex(128 * 1024);
        let (journal, control_stream) =
            RegisteredJournal::new_for_lease_test(carrier, identity, e1)
                .await
                .unwrap();
        let (renewed_tx, renewed_rx) = oneshot::channel();
        let challenges = Arc::new(AtomicUsize::new(0));
        let commit_pause = CommitPause::new();
        let peer_task = tokio::spawn(renewal_peer(
            peer,
            pop,
            successor,
            renewed_tx,
            Arc::clone(&challenges),
        ));
        let supervisor = tokio::spawn(run_supervisor_with_clock(
            control_stream,
            Arc::clone(&journal),
            authenticator,
            e1,
            clock,
            Some(commit_pause.clone()),
        ));

        renewed_rx.await.unwrap();
        commit_pause.wait_until_paused().await;
        assert_eq!(journal.current_expiry_for_lease_test(), e1);
        commit_pause.release();
        for _ in 0..32 {
            if journal.current_expiry_for_lease_test() == e2 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(journal.current_expiry_for_lease_test(), e2);

        tokio::time::advance(Duration::from_secs(121)).await;
        assert!(journal.open_stream().await.is_ok(), "E2 must outlive E1");

        *wall.lock().unwrap() = UNIX_EPOCH + Duration::from_secs(e2) + Duration::from_millis(125);
        tokio::time::advance(RECONCILIATION_INTERVAL).await;
        for _ in 0..32 {
            if journal.is_retired() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(journal.is_retired());
        assert!(matches!(
            journal.open_stream().await,
            Err(crate::registry::RegistryError::Retired)
        ));
        assert_eq!(challenges.load(Ordering::Relaxed), 1);

        tokio::time::advance(Duration::from_secs(1)).await;
        supervisor.await.unwrap();
        peer_task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn acceptance_criterion_renewal_3_paused_commit_after_max_deadline_is_rejected() {
        let real_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let e1 = real_now + 600;
        let e2 = real_now + 900;
        let issuer = SigningKey::from_bytes(&[7; 32]);
        let pop = SigningKey::from_bytes(&[19; 32]);
        let verifier = FixtureTokenVerifier::new(
            HashMap::from([(String::from("fixture"), issuer)]),
            String::from(BRIDGE_ID),
        );
        let successor = verifier
            .mint(
                "fixture",
                INSTANCE_ID,
                HOSTNAME,
                real_now,
                e2,
                &pop.verifying_key(),
            )
            .unwrap();
        let authenticator = PopAuthenticator::new(Arc::new(verifier), String::from(BRIDGE_ID));
        let identity = RenewalIdentity::new(
            String::from(HOSTNAME),
            String::from(INSTANCE_ID),
            pop.verifying_key(),
        );
        let wall = Arc::new(Mutex::new(
            UNIX_EPOCH + Duration::from_secs(e1 - RENEWAL_WINDOW.as_secs()),
        ));
        let clock: WallClockFn = {
            let wall = Arc::clone(&wall);
            Arc::new(move || *wall.lock().unwrap())
        };
        let (carrier, peer) = tokio::io::duplex(128 * 1024);
        let (journal, control_stream) =
            RegisteredJournal::new_for_lease_test(carrier, identity, e1)
                .await
                .unwrap();
        let (renewed_tx, renewed_rx) = oneshot::channel();
        let challenges = Arc::new(AtomicUsize::new(0));
        let commit_pause = CommitPause::new();
        let peer_task = tokio::spawn(renewal_peer(
            peer,
            pop,
            successor,
            renewed_tx,
            Arc::clone(&challenges),
        ));
        let supervisor = tokio::spawn(run_supervisor_with_clock(
            control_stream,
            Arc::clone(&journal),
            authenticator,
            e1,
            clock,
            Some(commit_pause.clone()),
        ));

        renewed_rx.await.unwrap();
        commit_pause.wait_until_paused().await;
        assert_eq!(journal.current_expiry_for_lease_test(), e1);
        tokio::time::advance(Duration::from_secs(121)).await;
        commit_pause.release();
        for _ in 0..32 {
            if journal.is_retired() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(journal.current_expiry_for_lease_test(), e1);
        assert!(journal.is_retired());
        supervisor.await.unwrap();
        peer_task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn acceptance_criterion_renewal_3_abort_while_paused_leaves_e1_unchanged() {
        let real_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let e1 = real_now + 600;
        let e2 = real_now + 900;
        let issuer = SigningKey::from_bytes(&[7; 32]);
        let pop = SigningKey::from_bytes(&[19; 32]);
        let verifier = FixtureTokenVerifier::new(
            HashMap::from([(String::from("fixture"), issuer)]),
            String::from(BRIDGE_ID),
        );
        let successor = verifier
            .mint(
                "fixture",
                INSTANCE_ID,
                HOSTNAME,
                real_now,
                e2,
                &pop.verifying_key(),
            )
            .unwrap();
        let authenticator = PopAuthenticator::new(Arc::new(verifier), String::from(BRIDGE_ID));
        let identity = RenewalIdentity::new(
            String::from(HOSTNAME),
            String::from(INSTANCE_ID),
            pop.verifying_key(),
        );
        let wall = Arc::new(Mutex::new(
            UNIX_EPOCH + Duration::from_secs(e1 - RENEWAL_WINDOW.as_secs()),
        ));
        let clock: WallClockFn = {
            let wall = Arc::clone(&wall);
            Arc::new(move || *wall.lock().unwrap())
        };
        let (carrier, peer) = tokio::io::duplex(128 * 1024);
        let (journal, control_stream) =
            RegisteredJournal::new_for_lease_test(carrier, identity, e1)
                .await
                .unwrap();
        let (renewed_tx, renewed_rx) = oneshot::channel();
        let challenges = Arc::new(AtomicUsize::new(0));
        let commit_pause = CommitPause::new();
        let peer_task = tokio::spawn(renewal_peer(
            peer,
            pop,
            successor,
            renewed_tx,
            Arc::clone(&challenges),
        ));
        let supervisor = tokio::spawn(run_supervisor_with_clock(
            control_stream,
            Arc::clone(&journal),
            authenticator,
            e1,
            clock,
            Some(commit_pause.clone()),
        ));

        renewed_rx.await.unwrap();
        commit_pause.wait_until_paused().await;
        assert_eq!(journal.current_expiry_for_lease_test(), e1);
        supervisor.abort();
        let _ = supervisor.await;
        assert_eq!(journal.current_expiry_for_lease_test(), e1);
        peer_task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn acceptance_criterion_renewal_3_paused_commit_after_attempt_deadline_is_rejected() {
        let real_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let e1 = real_now + 600;
        let e2 = real_now + 900;
        let issuer = SigningKey::from_bytes(&[7; 32]);
        let pop = SigningKey::from_bytes(&[19; 32]);
        let verifier = FixtureTokenVerifier::new(
            HashMap::from([(String::from("fixture"), issuer)]),
            String::from(BRIDGE_ID),
        );
        let successor = verifier
            .mint(
                "fixture",
                INSTANCE_ID,
                HOSTNAME,
                real_now,
                e2,
                &pop.verifying_key(),
            )
            .unwrap();
        let authenticator = PopAuthenticator::new(Arc::new(verifier), String::from(BRIDGE_ID));
        let identity = RenewalIdentity::new(
            String::from(HOSTNAME),
            String::from(INSTANCE_ID),
            pop.verifying_key(),
        );
        let wall = Arc::new(Mutex::new(
            UNIX_EPOCH + Duration::from_secs(e1 - RENEWAL_WINDOW.as_secs()),
        ));
        let clock: WallClockFn = {
            let wall = Arc::clone(&wall);
            Arc::new(move || *wall.lock().unwrap())
        };
        let (carrier, peer) = tokio::io::duplex(128 * 1024);
        let (journal, control_stream) =
            RegisteredJournal::new_for_lease_test(carrier, identity, e1)
                .await
                .unwrap();
        let (renewed_tx, renewed_rx) = oneshot::channel();
        let challenges = Arc::new(AtomicUsize::new(0));
        let commit_pause = CommitPause::new();
        let peer_task = tokio::spawn(renewal_peer(
            peer,
            pop,
            successor,
            renewed_tx,
            Arc::clone(&challenges),
        ));
        let supervisor = tokio::spawn(run_supervisor_with_clock(
            control_stream,
            Arc::clone(&journal),
            authenticator,
            e1,
            clock,
            Some(commit_pause.clone()),
        ));

        renewed_rx.await.unwrap();
        commit_pause.wait_until_paused().await;
        assert_eq!(journal.current_expiry_for_lease_test(), e1);
        tokio::time::advance(Duration::from_secs(11)).await;
        commit_pause.release();
        for _ in 0..32 {
            if journal.current_expiry_for_lease_test() != e1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(journal.current_expiry_for_lease_test(), e1);
        let _ = tokio::time::timeout(Duration::from_secs(1), supervisor).await;
        peer_task.abort();
    }

    async fn renewal_peer(
        mut peer: DuplexStream,
        pop: SigningKey,
        successor: String,
        renewed: oneshot::Sender<()>,
        challenges: Arc<AtomicUsize>,
    ) {
        let mut acceptor = MuxAcceptor::new(MuxLimits::default()).unwrap();
        let mut control_body = Vec::new();
        let mut renewed = Some(renewed);
        let mut bytes = [0u8; 16 * 1024];
        loop {
            let read = peer.read(&mut bytes).await.unwrap();
            if read == 0 {
                return;
            }
            let output = acceptor.feed(&bytes[..read]).unwrap();
            for event in output.events {
                if let MuxEvent::Data {
                    stream_id: 1,
                    bytes,
                } = event
                {
                    control_body.extend_from_slice(&bytes);
                    if let Some(response) = renewal_response(&control_body, &pop, &successor) {
                        challenges.fetch_add(1, Ordering::Relaxed);
                        if let Some(renewed) = renewed.take() {
                            let output = acceptor.try_send_data(1, response).unwrap().unwrap();
                            write_frames(&mut peer, &output.frames).await;
                            renewed.send(()).unwrap();
                        }
                    }
                }
            }
            write_frames(&mut peer, &output.frames).await;
        }
    }

    fn renewal_response(body: &[u8], pop: &SigningKey, successor: &str) -> Option<Vec<u8>> {
        let prefix: [u8; 4] = body.get(..4)?.try_into().ok()?;
        let length = u32::from_be_bytes(prefix) as usize;
        let challenge: Value = serde_json::from_slice(body.get(4..4 + length)?).ok()?;
        let nonce: [u8; 16] = URL_SAFE_NO_PAD
            .decode(challenge.get("nonce")?.as_str()?)
            .ok()?
            .try_into()
            .ok()?;
        let bridge_id = challenge.get("bridge_id")?.as_str()?;
        let timestamp = challenge.get("timestamp")?.as_i64()?;
        let mut signed = Vec::with_capacity(16 + bridge_id.len() + 8);
        signed.extend_from_slice(&nonce);
        signed.extend_from_slice(bridge_id.as_bytes());
        signed.extend_from_slice(&timestamp.to_be_bytes());
        let response = serde_json::json!({
            "token": successor,
            "hostname": HOSTNAME,
            "signature": URL_SAFE_NO_PAD.encode(pop.sign(&signed).to_bytes()),
        });
        let body = serde_json::to_vec(&response).ok()?;
        let length = u32::try_from(body.len()).ok()?;
        let mut framed = length.to_be_bytes().to_vec();
        framed.extend_from_slice(&body);
        Some(framed)
    }

    async fn write_frames(peer: &mut DuplexStream, frames: &[Frame]) {
        for frame in frames {
            peer.write_all(&frame.encode().unwrap()).await.unwrap();
        }
        peer.flush().await.unwrap();
    }

    async fn retry_then_succeed_peer(
        mut peer: DuplexStream,
        pop: SigningKey,
        successor: String,
        nonces: Arc<Mutex<Vec<[u8; 16]>>>,
        renewed: oneshot::Sender<()>,
    ) {
        let mut acceptor = MuxAcceptor::new(MuxLimits::default()).unwrap();
        let mut body = Vec::new();
        let mut consumed = 0;
        let mut attempts = 0;
        let mut renewed = Some(renewed);
        let mut bytes = [0; 16 * 1024];
        loop {
            let read = peer.read(&mut bytes).await.unwrap();
            if read == 0 {
                return;
            }
            let output = acceptor.feed(&bytes[..read]).unwrap();
            for event in output.events {
                if let MuxEvent::Data {
                    stream_id: 1,
                    bytes,
                } = event
                {
                    body.extend_from_slice(&bytes);
                    loop {
                        let remaining = &body[consumed..];
                        let Some(prefix) = remaining.get(..4) else {
                            break;
                        };
                        let length = u32::from_be_bytes(prefix.try_into().unwrap()) as usize;
                        let Some(challenge_bytes) = remaining.get(4..4 + length) else {
                            break;
                        };
                        let challenge: Value = serde_json::from_slice(challenge_bytes).unwrap();
                        let nonce: [u8; 16] = URL_SAFE_NO_PAD
                            .decode(challenge.get("nonce").unwrap().as_str().unwrap())
                            .unwrap()
                            .try_into()
                            .unwrap();
                        nonces.lock().unwrap().push(nonce);
                        let response = if attempts == 0 {
                            serde_json::json!({"token":"not-a-real-jwt","hostname":HOSTNAME,"signature":""})
                        } else {
                            let bridge_id = challenge.get("bridge_id").unwrap().as_str().unwrap();
                            let timestamp = challenge.get("timestamp").unwrap().as_i64().unwrap();
                            let mut signed = Vec::new();
                            signed.extend_from_slice(&nonce);
                            signed.extend_from_slice(bridge_id.as_bytes());
                            signed.extend_from_slice(&timestamp.to_be_bytes());
                            serde_json::json!({"token":successor,"hostname":HOSTNAME,"signature":URL_SAFE_NO_PAD.encode(pop.sign(&signed).to_bytes())})
                        };
                        consumed += 4 + length;
                        attempts += 1;
                        let response = serde_json::to_vec(&response).unwrap();
                        let mut framed = u32::try_from(response.len())
                            .unwrap()
                            .to_be_bytes()
                            .to_vec();
                        framed.extend_from_slice(&response);
                        let output = acceptor.try_send_data(1, framed).unwrap().unwrap();
                        write_frames(&mut peer, &output.frames).await;
                        if attempts == 2
                            && let Some(sender) = renewed.take()
                        {
                            sender.send(()).unwrap();
                        }
                    }
                }
            }
            write_frames(&mut peer, &output.frames).await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn acceptance_criterion_renewal_6_retry_waits_15s_and_uses_a_fresh_nonce() {
        let real_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let e1 = real_now + 600;
        let e2 = real_now + 900;
        let issuer = SigningKey::from_bytes(&[7; 32]);
        let pop = SigningKey::from_bytes(&[19; 32]);
        let verifier = FixtureTokenVerifier::new(
            HashMap::from([(String::from("fixture"), issuer)]),
            String::from(BRIDGE_ID),
        );
        let successor = verifier
            .mint(
                "fixture",
                INSTANCE_ID,
                HOSTNAME,
                real_now,
                e2,
                &pop.verifying_key(),
            )
            .unwrap();
        let authenticator = PopAuthenticator::new(Arc::new(verifier), String::from(BRIDGE_ID));
        let identity = RenewalIdentity::new(
            String::from(HOSTNAME),
            String::from(INSTANCE_ID),
            pop.verifying_key(),
        );
        let wall = Arc::new(Mutex::new(
            UNIX_EPOCH + Duration::from_secs(e1 - RENEWAL_WINDOW.as_secs()),
        ));
        let clock: WallClockFn = {
            let wall = Arc::clone(&wall);
            Arc::new(move || *wall.lock().unwrap())
        };
        let (carrier, peer) = tokio::io::duplex(128 * 1024);
        let (journal, control_stream) =
            RegisteredJournal::new_for_lease_test(carrier, identity, e1)
                .await
                .unwrap();
        let (renewed_tx, renewed_rx) = oneshot::channel();
        let nonces = Arc::new(Mutex::new(Vec::new()));
        let peer_task = tokio::spawn(retry_then_succeed_peer(
            peer,
            pop,
            successor,
            Arc::clone(&nonces),
            renewed_tx,
        ));
        let supervisor = tokio::spawn(run_supervisor_with_clock(
            control_stream,
            Arc::clone(&journal),
            authenticator,
            e1,
            clock,
            None,
        ));
        for _ in 0..64 {
            if !nonces.lock().unwrap().is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(nonces.lock().unwrap().len(), 1);
        tokio::time::advance(Duration::from_secs(14)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            nonces.lock().unwrap().len(),
            1,
            "retry must not start before the 15s floor"
        );
        tokio::time::advance(Duration::from_secs(2)).await;
        renewed_rx.await.unwrap();
        assert_eq!(nonces.lock().unwrap().len(), 2);
        let first_nonce = nonces.lock().unwrap()[0];
        let second_nonce = nonces.lock().unwrap()[1];
        assert_ne!(first_nonce, second_nonce, "retry must use a fresh nonce");
        for _ in 0..32 {
            if journal.current_expiry_for_lease_test() == e2 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(journal.current_expiry_for_lease_test(), e2);
        supervisor.abort();
        peer_task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn acceptance_criterion_renewal_9_forward_correction_starts_renewal_within_1s() {
        let real_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let e1 = real_now + 700;
        let e2 = real_now + 900;
        let issuer = SigningKey::from_bytes(&[7; 32]);
        let pop = SigningKey::from_bytes(&[19; 32]);
        let verifier = FixtureTokenVerifier::new(
            HashMap::from([(String::from("fixture"), issuer)]),
            String::from(BRIDGE_ID),
        );
        let successor = verifier
            .mint(
                "fixture",
                INSTANCE_ID,
                HOSTNAME,
                real_now,
                e2,
                &pop.verifying_key(),
            )
            .unwrap();
        let authenticator = PopAuthenticator::new(Arc::new(verifier), String::from(BRIDGE_ID));
        let identity = RenewalIdentity::new(
            String::from(HOSTNAME),
            String::from(INSTANCE_ID),
            pop.verifying_key(),
        );
        let wall = Arc::new(Mutex::new(UNIX_EPOCH + Duration::from_secs(real_now)));
        let clock: WallClockFn = {
            let wall = Arc::clone(&wall);
            Arc::new(move || *wall.lock().unwrap())
        };
        let (carrier, peer) = tokio::io::duplex(128 * 1024);
        let (journal, control_stream) =
            RegisteredJournal::new_for_lease_test(carrier, identity, e1)
                .await
                .unwrap();
        let (renewed_tx, renewed_rx) = oneshot::channel();
        let challenges = Arc::new(AtomicUsize::new(0));
        let peer_task = tokio::spawn(renewal_peer(
            peer,
            pop,
            successor,
            renewed_tx,
            Arc::clone(&challenges),
        ));
        let supervisor = tokio::spawn(run_supervisor_with_clock(
            control_stream,
            Arc::clone(&journal),
            authenticator,
            e1,
            clock,
            None,
        ));
        tokio::time::advance(Duration::from_secs(30)).await;
        tokio::task::yield_now().await;
        assert_eq!(challenges.load(Ordering::Relaxed), 0);
        *wall.lock().unwrap() = UNIX_EPOCH + Duration::from_secs(e1 - 60);
        tokio::time::advance(RECONCILIATION_INTERVAL).await;
        for _ in 0..64 {
            if challenges.load(Ordering::Relaxed) >= 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(challenges.load(Ordering::Relaxed), 1);
        renewed_rx.await.unwrap();
        for _ in 0..32 {
            if journal.current_expiry_for_lease_test() == e2 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(journal.current_expiry_for_lease_test(), e2);
        supervisor.abort();
        peer_task.abort();
    }
}
