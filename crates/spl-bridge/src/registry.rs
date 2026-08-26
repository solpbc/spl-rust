// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Hostname registrations for journal tunnel connections.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::RwLock;

use crate::frame_dialer::{ConnectionState, DialerError, DialerStream, FrameDialer};

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
    retired: AtomicBool,
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
    /// The journal tunnel connection could not open the stream.
    #[error("journal dialer error: {0}")]
    Dialer(#[from] DialerError),
}

impl Registry {
    /// Register `carrier` as the current journal tunnel for `hostname`.
    ///
    /// Replacing an existing entry first makes that old entry reject new opens,
    /// then waits up to 250 ms for its dialer shutdown to end all of its live
    /// streams. The map swap happens before that bounded shutdown work.
    pub async fn register<T>(&self, hostname: String, carrier: T) -> Arc<RegisteredJournal>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let generation = self.inner.next_generation.fetch_add(1, Ordering::Relaxed);
        let registered = Arc::new(RegisteredJournal {
            dialer: FrameDialer::new(carrier),
            generation,
            retired: AtomicBool::new(false),
        });

        let displaced = self
            .inner
            .entries
            .write()
            .await
            .insert(hostname.clone(), Arc::clone(&registered));

        if let Some(displaced) = displaced {
            displaced.retired.store(true, Ordering::Release);
            let _ = tokio::time::timeout(REPLACEMENT_SHUTDOWN_BUDGET, displaced.dialer.shutdown())
                .await;
        }

        let registry = self.clone();
        let watcher = Arc::clone(&registered);
        let generation = registered.generation;
        tokio::spawn(async move {
            watcher.wait_until_gone().await;
            registry.remove_if_current(&hostname, generation).await;
        });

        registered
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
        if self.retired.load(Ordering::Acquire) {
            return Err(RegistryError::Retired);
        }
        tokio::time::timeout(OPEN_STREAM_TIMEOUT, self.dialer.open_stream())
            .await
            .map_err(|_| RegistryError::OpenTimedOut)?
            .map_err(RegistryError::from)
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "tests construct controlled in-memory carrier pairs"
    )]

    use std::time::Duration;

    use super::*;
    use crate::frame_dialer::StreamEnd;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn replacement_wins_and_ends_the_displaced_journals_streams() {
        let registry = Registry::default();
        let (first_carrier, mut first_peer) = tokio::io::duplex(1024);
        let first = registry
            .register("journal.test".into(), first_carrier)
            .await;
        let mut stream = first.open_stream().await.unwrap();
        let mut open_frame = [0u8; 16];
        assert_ne!(first_peer.read(&mut open_frame).await.unwrap(), 0);

        let (second_carrier, _second_peer) = tokio::io::duplex(1024);
        let second = registry
            .register("journal.test".into(), second_carrier)
            .await;

        let current = registry.lookup("journal.test").await.unwrap();
        assert!(Arc::ptr_eq(&current, &second));
        assert_eq!(first.connection_state(), ConnectionState::Gone);
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
        let _registered = registry.register("journal.test".into(), carrier).await;
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
    async fn stalled_open_times_out_after_three_seconds() {
        let registry = Registry::default();
        let (carrier, _peer) = tokio::io::duplex(16);
        let journal = registry.register("journal.test".into(), carrier).await;
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
}
