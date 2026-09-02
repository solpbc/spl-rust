// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Public SNI-routing relay for the journal-MCP endpoint wire protocol (§ C2).
//!
//! This crate is unrelated to both [`spl_core::bridge`], which provides pure
//! transforms for the local journal bridge loopback proxy, and
//! `spl-transport`'s `journal_bridge`/`journal_bridge_carrier` modules, which
//! implement the consumer-side paired-device HTTP loopback proxy. Neither is
//! this crate: it routes public client TLS bytes to a registered journal without
//! terminating that client TLS session.

use std::future::Future;
use std::io::{self, BufReader, Cursor};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

pub mod frame_dialer;
mod lease;
pub mod pop_auth;
pub mod proxy_protocol;
pub mod registry;
mod routed;
pub mod sni;

/// Errors returned while configuring or operating the public bridge listeners.
#[derive(Debug, Error)]
pub enum BridgeError {
    /// PEM input could not be decoded into the requested TLS material.
    #[error("TLS PEM input is invalid")]
    Pem,
    /// The PEM key input did not contain a private key.
    #[error("TLS PEM input contains no private key")]
    MissingPrivateKey,
    /// Rustls rejected the server configuration or certificate chain.
    #[error("TLS server configuration is invalid")]
    TlsConfiguration,
    /// A listener could not bind its configured network address.
    #[error("listener bind failed")]
    ListenerBind,
}

/// Decode every PEM certificate in `pem` into a rustls certificate chain.
///
/// # Errors
///
/// Returns [`BridgeError::Pem`] when the input cannot be decoded as PEM.
pub fn pem_certificate_chain(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, BridgeError> {
    rustls_pemfile::certs(&mut BufReader::new(Cursor::new(pem)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| BridgeError::Pem)
}

/// Decode the first PEM private key in `pem`.
///
/// # Errors
///
/// Returns [`BridgeError::Pem`] when the input cannot be decoded and
/// [`BridgeError::MissingPrivateKey`] when it contains no private key.
pub fn pem_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, BridgeError> {
    rustls_pemfile::private_key(&mut BufReader::new(Cursor::new(pem)))
        .map_err(|_| BridgeError::Pem)?
        .ok_or(BridgeError::MissingPrivateKey)
}

/// Build the TLS server configuration for journal control registrations.
///
/// Control TLS authenticates the bridge server only. Journal authentication is
/// performed by the application-level proof-of-possession exchange.
///
/// # Errors
///
/// Returns [`BridgeError::TlsConfiguration`] when rustls rejects the ring
/// provider setup or supplied certificate/key pair.
pub fn server_tls_config(
    certificate_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, BridgeError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| BridgeError::TlsConfiguration)?
        .with_no_client_auth()
        .with_single_cert(certificate_chain, private_key)
        .map_err(|_| BridgeError::TlsConfiguration)
}

/// Absolute time allowed for one journal control connection's admission.
pub const DEFAULT_ADMISSION_DEADLINE: Duration = Duration::from_secs(10);

const MAX_SNI_ADMISSION_SLOTS: usize = 256;
const CONTROL_SPLICE_CONNECT_DEADLINE: Duration = Duration::from_secs(3);
const RESERVED_CONTROL_SNI: &str = "bridge.solstone.me";

/// Absolute time a routed client waits for its journal's first response byte.
///
/// A registered journal whose host slept or lost its network leaves the
/// carrier socket open, so `open_stream` succeeds against a locally buffered
/// OPEN frame and the splice then waits forever. This bounds that wait: a
/// journal that has not produced one byte by the deadline loses the client
/// connection and its registration, which is ordinary in-memory runtime state.
/// It is deliberately far above any healthy handshake (measured 0.25s
/// end to end against the live endpoint, 2026-09-02) so a busy journal is
/// never mistaken for an absent one.
pub const ROUTED_FIRST_RESPONSE_DEADLINE: Duration = Duration::from_secs(10);

#[derive(Clone, Copy)]
pub(crate) enum BridgeLogEvent {
    ControlListenerStarted,
    ControlListenerAcceptFailed,
    ControlTlsHandshakeRejected,
    JournalRegistrationTokenRejected,
    JournalRegistrationJwksUnavailable,
    JournalRegistrationNonceOutstandingCapacity,
    JournalRegistrationNonceSpentCapacity,
    JournalRegistrationNonceGenerationFailed,
    JournalRegistrationFramingOrProofRejected,
    JournalRegistrationRejectedAdmissionTimeout,
    JournalRegistrationRegistryFailed,
    JournalRegistered,
    JournalEvicted,
    JournalRegistrationAdmissionTimedOut,
    JournalLeaseRenewalRetryableAttemptFailed,
    JournalLeaseRenewalTerminalPoisoned,
    JournalLeaseRenewalNonceOutstandingCapacity,
    JournalLeaseRenewalNonceSpentCapacity,
    JournalLeaseRenewed,
    JournalLeaseExpiredWallClock,
    ClientListenerStarted,
    ClientListenerAcceptFailed,
    ClientRejectedBeforeRouting,
    ClientRejectedWithoutJournalRegistration,
    ClientRejectedJournalStreamOpen,
    ClientRejectedProxyHeaderBuild,
    ClientRejectedProxyHeaderWrite,
    ClientRejectedJournalUnresponsive,
    JournalRetiredUnresponsive,
    ClientRoutedToJournal,
    ClientSpliceClosed,
    ClientSpliceClosedWithIoError,
    ControlSpliceDialFailed,
    ControlSpliceDialTimedOut,
    ControlSpliceConnected,
}

impl BridgeLogEvent {
    pub(crate) fn emit(self) {
        match self {
            Self::ControlListenerStarted => tracing::info!("control listener started"),
            Self::ControlListenerAcceptFailed => tracing::warn!("control listener accept failed"),
            Self::ControlTlsHandshakeRejected => tracing::warn!("control TLS handshake rejected"),
            Self::JournalRegistrationTokenRejected => {
                tracing::warn!("journal registration rejected: token rejection");
            }
            Self::JournalRegistrationJwksUnavailable => {
                tracing::warn!("journal registration rejected: JWKS unavailable");
            }
            Self::JournalRegistrationNonceOutstandingCapacity => {
                tracing::warn!("journal registration rejected: nonce outstanding capacity");
            }
            Self::JournalRegistrationNonceSpentCapacity => {
                tracing::warn!("journal registration rejected: nonce spent capacity");
            }
            Self::JournalRegistrationNonceGenerationFailed => {
                tracing::warn!("journal registration rejected: nonce generation failed");
            }
            Self::JournalRegistrationFramingOrProofRejected => {
                tracing::warn!("journal registration rejected: framing or proof rejection");
            }
            Self::JournalRegistrationRejectedAdmissionTimeout => {
                tracing::warn!("journal registration failed: admission timeout");
            }
            Self::JournalRegistrationRegistryFailed => {
                tracing::warn!("journal registration failed: registry failure");
            }
            Self::JournalRegistered => tracing::info!("journal registered"),
            Self::JournalEvicted => tracing::info!("journal evicted"),
            Self::JournalRegistrationAdmissionTimedOut => {
                tracing::warn!("journal registration timed out");
            }
            Self::JournalLeaseRenewalRetryableAttemptFailed => {
                tracing::warn!("journal lease renewal attempt rejected");
            }
            Self::JournalLeaseRenewalTerminalPoisoned => {
                tracing::warn!("journal lease renewal stream poisoned");
            }
            Self::JournalLeaseRenewalNonceOutstandingCapacity => {
                tracing::warn!("journal lease renewal rejected: nonce outstanding capacity");
            }
            Self::JournalLeaseRenewalNonceSpentCapacity => {
                tracing::warn!("journal lease renewal rejected: nonce spent capacity");
            }
            Self::JournalLeaseRenewed => tracing::info!("journal lease renewed"),
            Self::JournalLeaseExpiredWallClock => {
                tracing::warn!("journal lease expired");
            }
            Self::ClientListenerStarted => tracing::info!("client listener started"),
            Self::ClientListenerAcceptFailed => tracing::warn!("client listener accept failed"),
            Self::ClientRejectedBeforeRouting => tracing::warn!("client rejected before routing"),
            Self::ClientRejectedWithoutJournalRegistration => {
                tracing::warn!("client rejected without journal registration");
            }
            Self::ClientRejectedJournalStreamOpen => {
                tracing::warn!("client rejected because journal stream could not open");
            }
            Self::ClientRejectedProxyHeaderBuild => {
                tracing::warn!("client rejected because PROXY header could not be built");
            }
            Self::ClientRejectedProxyHeaderWrite => {
                tracing::warn!("client rejected because PROXY header could not be written");
            }
            Self::ClientRejectedJournalUnresponsive => {
                tracing::warn!("client rejected because the journal never answered");
            }
            Self::JournalRetiredUnresponsive => {
                tracing::info!("journal retired: unresponsive to a routed client");
            }
            Self::ClientRoutedToJournal => tracing::info!("client routed to journal"),
            Self::ClientSpliceClosed => tracing::info!("client splice closed"),
            Self::ClientSpliceClosedWithIoError => {
                tracing::warn!("client splice closed with I/O error");
            }
            Self::ControlSpliceDialFailed => tracing::warn!("control splice dial failed"),
            Self::ControlSpliceDialTimedOut => tracing::warn!("control splice dial timed out"),
            Self::ControlSpliceConnected => tracing::info!("control splice connected"),
        }
    }
}

trait ControlConnector: Clone + Send + Sync + 'static {
    fn connect(&self, target: SocketAddr) -> impl Future<Output = io::Result<TcpStream>> + Send;
}

#[derive(Clone, Copy)]
struct TokioControlConnector;

impl ControlConnector for TokioControlConnector {
    async fn connect(&self, target: SocketAddr) -> io::Result<TcpStream> {
        TcpStream::connect(target).await
    }
}

/// Accept journal control connections indefinitely on `listener`.
///
/// Every registration is handled in its own task so a slow peer cannot block
/// later journal registrations.
pub async fn run_control_listener(
    listener: TcpListener,
    tls_config: Arc<ServerConfig>,
    registry: registry::Registry,
    authenticator: pop_auth::PopAuthenticator,
    admission_deadline: Duration,
) {
    BridgeLogEvent::ControlListenerStarted.emit();
    loop {
        let Ok((stream, _peer)) = listener.accept().await else {
            BridgeLogEvent::ControlListenerAcceptFailed.emit();
            continue;
        };
        let deadline = tokio::time::Instant::now() + admission_deadline;
        let acceptor = TlsAcceptor::from(Arc::clone(&tls_config));
        let registry = registry.clone();
        let authenticator = authenticator.clone();
        tokio::spawn(async move {
            if tokio::time::timeout_at(deadline, async move {
                let Ok(mut tls_stream) = acceptor.accept(stream).await else {
                    BridgeLogEvent::ControlTlsHandshakeRejected.emit();
                    return;
                };
                let registration = match authenticator.authenticate(&mut tls_stream).await {
                    Ok(registration) => registration,
                    Err(error) => {
                        pop_admission_event(&error).emit();
                        return;
                    }
                };
                let hostname = registration.hostname().to_owned();
                let identity = registration.renewal_identity();
                let journal = match registry
                    .register(
                        hostname,
                        tls_stream,
                        authenticator,
                        identity,
                        registration.claims().expires_at(),
                        deadline,
                    )
                    .await
                {
                    Ok(journal) => journal,
                    Err(error) => {
                        registry_admission_event(&error).emit();
                        return;
                    }
                };
                BridgeLogEvent::JournalRegistered.emit();
                tokio::spawn(async move {
                    journal.wait_until_gone().await;
                    BridgeLogEvent::JournalEvicted.emit();
                });
            })
            .await
            .is_err()
            {
                BridgeLogEvent::JournalRegistrationAdmissionTimedOut.emit();
            }
        });
    }
}

fn pop_admission_event(error: &pop_auth::PopError) -> BridgeLogEvent {
    match error {
        pop_auth::PopError::TokenRejected
        | pop_auth::PopError::HostnameMismatch
        | pop_auth::PopError::TokenTimeInvalid => BridgeLogEvent::JournalRegistrationTokenRejected,
        pop_auth::PopError::JwksUnavailable
        | pop_auth::PopError::JwksKeyUnavailable
        | pop_auth::PopError::JwksUrl
        | pop_auth::PopError::JwksTlsConfiguration => {
            BridgeLogEvent::JournalRegistrationJwksUnavailable
        }
        pop_auth::PopError::NonceOutstandingCapacity => {
            BridgeLogEvent::JournalRegistrationNonceOutstandingCapacity
        }
        pop_auth::PopError::NonceSpentCapacity => {
            BridgeLogEvent::JournalRegistrationNonceSpentCapacity
        }
        pop_auth::PopError::NonceCollisionExhausted | pop_auth::PopError::Randomness => {
            BridgeLogEvent::JournalRegistrationNonceGenerationFailed
        }
        pop_auth::PopError::Io
        | pop_auth::PopError::MessageTooLarge
        | pop_auth::PopError::InvalidMessage
        | pop_auth::PopError::ChallengeTimeInvalid
        | pop_auth::PopError::InvalidProof
        | pop_auth::PopError::NonceReplay => {
            BridgeLogEvent::JournalRegistrationFramingOrProofRejected
        }
    }
}

fn registry_admission_event(error: &registry::RegistryError) -> BridgeLogEvent {
    match error {
        registry::RegistryError::Expired | registry::RegistryError::AdmissionDeadlineExceeded => {
            BridgeLogEvent::JournalRegistrationRejectedAdmissionTimeout
        }
        registry::RegistryError::Retired
        | registry::RegistryError::OpenTimedOut
        | registry::RegistryError::Dialer(_) => BridgeLogEvent::JournalRegistrationRegistryFailed,
    }
}

/// Accept raw client TLS connections indefinitely on `listener`.
///
/// Client TLS remains opaque: this listener peeks only far enough to route by
/// SNI. Registered journal hostnames receive a PROXY v1 header before bytes are
/// spliced; the reserved control hostname is spliced directly to the internal
/// control listener without a PROXY header.
pub async fn run_client_listener(
    listener: TcpListener,
    registry: registry::Registry,
    control_dial_target: SocketAddr,
    sni_deadline: Duration,
) {
    run_client_listener_with_connector(
        listener,
        registry,
        control_dial_target,
        sni_deadline,
        TokioControlConnector,
    )
    .await;
}

async fn run_client_listener_with_connector<C>(
    listener: TcpListener,
    registry: registry::Registry,
    control_dial_target: SocketAddr,
    sni_deadline: Duration,
    connector: C,
) where
    C: ControlConnector,
{
    BridgeLogEvent::ClientListenerStarted.emit();
    let sni_admission = Arc::new(Semaphore::new(MAX_SNI_ADMISSION_SLOTS));
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            BridgeLogEvent::ClientListenerAcceptFailed.emit();
            continue;
        };
        let registry = registry.clone();
        let sni_admission = Arc::clone(&sni_admission);
        let connector = connector.clone();
        tokio::spawn(async move {
            handle_client(
                stream,
                peer,
                registry,
                control_dial_target,
                sni_deadline,
                sni_admission,
                connector,
            )
            .await;
        });
    }
}

async fn handle_client<C>(
    mut client: TcpStream,
    _peer: SocketAddr,
    registry: registry::Registry,
    control_dial_target: SocketAddr,
    sni_deadline: Duration,
    sni_admission: Arc<Semaphore>,
    connector: C,
) where
    C: ControlConnector,
{
    let hostname = {
        let Ok(_permit) = sni_admission.try_acquire_owned() else {
            BridgeLogEvent::ClientRejectedBeforeRouting.emit();
            return;
        };
        let Ok(hostname) = sni::extract_sni(&client, sni_deadline).await else {
            BridgeLogEvent::ClientRejectedBeforeRouting.emit();
            return;
        };
        hostname
    };

    if hostname == RESERVED_CONTROL_SNI {
        let mut control = match tokio::time::timeout(
            CONTROL_SPLICE_CONNECT_DEADLINE,
            connector.connect(control_dial_target),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(_)) => {
                BridgeLogEvent::ControlSpliceDialFailed.emit();
                return;
            }
            Err(_) => {
                BridgeLogEvent::ControlSpliceDialTimedOut.emit();
                return;
            }
        };
        BridgeLogEvent::ControlSpliceConnected.emit();
        let _ = tokio::io::copy_bidirectional(&mut client, &mut control).await;
        return;
    }

    if !pop_auth::valid_hostname(&hostname) {
        BridgeLogEvent::ClientRejectedBeforeRouting.emit();
        return;
    }
    let Some(journal) = registry.lookup(&hostname).await else {
        BridgeLogEvent::ClientRejectedWithoutJournalRegistration.emit();
        return;
    };
    let Ok(stream) = journal.open_stream().await else {
        BridgeLogEvent::ClientRejectedJournalStreamOpen.emit();
        return;
    };
    let Ok(source) = client.peer_addr() else {
        return;
    };
    let Ok(destination) = client.local_addr() else {
        return;
    };
    let Ok(header) = proxy_protocol::v1_header(source, destination) else {
        BridgeLogEvent::ClientRejectedProxyHeaderBuild.emit();
        return;
    };
    let flag = routed::FirstByteFlag::default();
    let mut stream = routed::FirstByteWitness::new(stream, flag.clone());
    if stream.write_all(&header).await.is_err() || stream.flush().await.is_err() {
        BridgeLogEvent::ClientRejectedProxyHeaderWrite.emit();
        return;
    }

    BridgeLogEvent::ClientRoutedToJournal.emit();
    splice_until_journal_answers_or_deadline(
        &mut client,
        &mut stream,
        &flag,
        &registry,
        &hostname,
        &journal,
    )
    .await;
}

/// Splice a routed client, closing it if the journal never answers.
///
/// The deadline is armed only until the journal's first byte, so an ordinary
/// long-running tool call is unaffected once its TLS handshake has begun.
async fn splice_until_journal_answers_or_deadline<S>(
    client: &mut TcpStream,
    stream: &mut S,
    flag: &routed::FirstByteFlag,
    registry: &registry::Registry,
    hostname: &str,
    journal: &Arc<registry::RegisteredJournal>,
) where
    S: tokio::io::AsyncRead + AsyncWriteExt + Unpin,
{
    let splice = tokio::io::copy_bidirectional(client, stream);
    tokio::pin!(splice);
    let mut armed = true;
    loop {
        if !armed {
            match (&mut splice).await {
                Ok(_) => BridgeLogEvent::ClientSpliceClosed.emit(),
                Err(_) => BridgeLogEvent::ClientSpliceClosedWithIoError.emit(),
            }
            return;
        }
        match tokio::time::timeout(ROUTED_FIRST_RESPONSE_DEADLINE, &mut splice).await {
            Ok(Ok(_)) => {
                BridgeLogEvent::ClientSpliceClosed.emit();
                return;
            }
            Ok(Err(_)) => {
                BridgeLogEvent::ClientSpliceClosedWithIoError.emit();
                return;
            }
            Err(_) if flag.observed() => armed = false,
            Err(_) => {
                BridgeLogEvent::ClientRejectedJournalUnresponsive.emit();
                registry.retire_unresponsive(hostname, journal).await;
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "tests use an in-memory log capture fixture"
    )]

    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::frame_dialer::DialerError;
    use crate::pop_auth::PopError;
    use crate::registry::RegistryError;
    use spl_core::frame::{FLAG_DATA, FLAG_OPEN, Frame, FrameDecoder};
    use tokio::io::AsyncReadExt;
    use tokio::sync::Notify;

    #[derive(Clone)]
    struct LogBuffer(Arc<Mutex<Vec<u8>>>);

    struct LogWriter(LogBuffer);

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuffer {
        type Writer = LogWriter;

        fn make_writer(&'a self) -> Self::Writer {
            LogWriter(self.clone())
        }
    }

    impl Write for LogWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct NeverReadyControlConnector(Arc<Notify>);

    impl ControlConnector for NeverReadyControlConnector {
        fn connect(
            &self,
            _target: SocketAddr,
        ) -> impl Future<Output = io::Result<TcpStream>> + Send {
            self.0.notify_waiters();
            std::future::pending()
        }
    }

    fn reserved_client_hello() -> Vec<u8> {
        client_hello_for(RESERVED_CONTROL_SNI)
    }

    fn client_hello_for(server_name: &str) -> Vec<u8> {
        let hostname = server_name.as_bytes();
        let mut names = vec![0];
        names.extend_from_slice(&(u16::try_from(hostname.len()).unwrap_or(0)).to_be_bytes());
        names.extend_from_slice(hostname);
        let mut server_name = Vec::new();
        server_name.extend_from_slice(&(u16::try_from(names.len()).unwrap_or(0)).to_be_bytes());
        server_name.extend_from_slice(&names);
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0_u16.to_be_bytes());
        extensions
            .extend_from_slice(&(u16::try_from(server_name.len()).unwrap_or(0)).to_be_bytes());
        extensions.extend_from_slice(&server_name);

        let mut body = vec![0x03, 0x03];
        body.extend([0x55; 32]);
        body.push(0);
        body.extend_from_slice(&2_u16.to_be_bytes());
        body.extend([0x13, 0x01, 1, 0]);
        body.extend_from_slice(&(u16::try_from(extensions.len()).unwrap_or(0)).to_be_bytes());
        body.extend_from_slice(&extensions);
        let mut handshake = vec![1];
        handshake.extend_from_slice(&[
            u8::try_from(body.len() >> 16).unwrap_or(0),
            u8::try_from(body.len() >> 8).unwrap_or(0),
            u8::try_from(body.len()).unwrap_or(0),
        ]);
        handshake.extend_from_slice(&body);
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(u16::try_from(handshake.len()).unwrap_or(0)).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    async fn tcp_pair() -> Result<(TcpStream, TcpStream), io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let client = TcpStream::connect(address).await?;
        let (server, _) = listener.accept().await?;
        Ok((client, server))
    }

    #[tokio::test(start_paused = true)]
    async fn control_dial_timeout_releases_the_sni_permit_before_routing() -> Result<(), io::Error>
    {
        let (mut client, server) = tcp_pair().await?;
        client.write_all(&reserved_client_hello()).await?;
        let permits = Arc::new(Semaphore::new(1));
        let connect_entered = Arc::new(Notify::new());
        let entered_wait = connect_entered.notified();
        let task = tokio::spawn(handle_client(
            server,
            SocketAddr::from(([127, 0, 0, 1], 0)),
            registry::Registry::default(),
            SocketAddr::from(([127, 0, 0, 1], 0)),
            Duration::from_secs(1),
            Arc::clone(&permits),
            NeverReadyControlConnector(Arc::clone(&connect_entered)),
        ));
        entered_wait.await;
        assert_eq!(permits.available_permits(), 1);
        tokio::time::advance(CONTROL_SPLICE_CONNECT_DEADLINE).await;
        task.await.map_err(io::Error::other)?;
        let mut byte = [0_u8; 1];
        assert!(matches!(client.read(&mut byte).await, Ok(0) | Err(_)));
        Ok(())
    }

    #[tokio::test]
    async fn sni_admission_gate_rejects_the_connection_after_256_slots() -> Result<(), io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let mut clients = Vec::new();
        let mut servers = Vec::new();
        for _ in 0..=MAX_SNI_ADMISSION_SLOTS {
            clients.push(TcpStream::connect(address).await?);
            servers.push(listener.accept().await?.0);
        }
        let permits = Arc::new(Semaphore::new(MAX_SNI_ADMISSION_SLOTS));
        let mut pending = Vec::new();
        for server in servers.drain(..MAX_SNI_ADMISSION_SLOTS) {
            pending.push(tokio::spawn(handle_client(
                server,
                SocketAddr::from(([127, 0, 0, 1], 0)),
                registry::Registry::default(),
                SocketAddr::from(([127, 0, 0, 1], 0)),
                Duration::from_mins(1),
                Arc::clone(&permits),
                NeverReadyControlConnector(Arc::new(Notify::new())),
            )));
        }
        assert!(
            tokio::time::timeout(Duration::from_secs(1), async {
                while permits.available_permits() != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .is_ok()
        );
        let last_server = servers
            .pop()
            .ok_or_else(|| io::Error::other("overload test has no server connection"))?;
        handle_client(
            last_server,
            SocketAddr::from(([127, 0, 0, 1], 0)),
            registry::Registry::default(),
            SocketAddr::from(([127, 0, 0, 1], 0)),
            Duration::from_mins(1),
            Arc::clone(&permits),
            NeverReadyControlConnector(Arc::new(Notify::new())),
        )
        .await;
        let mut rejected_client = clients
            .pop()
            .ok_or_else(|| io::Error::other("overload test has no client connection"))?;
        let mut byte = [0_u8; 1];
        assert!(matches!(rejected_client.read(&mut byte).await, Ok(0)));
        for task in pending {
            task.abort();
        }
        Ok(())
    }

    const UNRESPONSIVE_TEST_HOSTNAME: &str = "abcdefgh.solstone.me";

    async fn registry_with_silent_journal() -> Result<
        (
            registry::Registry,
            Arc<registry::RegisteredJournal>,
            tokio::io::DuplexStream,
            frame_dialer::DialerStream,
        ),
        io::Error,
    > {
        let (carrier, peer) = tokio::io::duplex(64 * 1024);
        let signing = ed25519_dalek::SigningKey::from_bytes(&[23; 32]);
        let identity = pop_auth::RenewalIdentity::new(
            UNRESPONSIVE_TEST_HOSTNAME.to_owned(),
            String::from("instance-unresponsive"),
            signing.verifying_key(),
        );
        let (journal, control) =
            registry::RegisteredJournal::new_for_lease_test(carrier, identity, u64::MAX)
                .await
                .map_err(io::Error::other)?;
        let registry = registry::Registry::default();
        registry
            .insert_for_test(UNRESPONSIVE_TEST_HOSTNAME.to_owned(), Arc::clone(&journal))
            .await;
        Ok((registry, journal, peer, control))
    }

    fn unresponsive_client_task(
        server: TcpStream,
        registry: registry::Registry,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(handle_client(
            server,
            SocketAddr::from(([127, 0, 0, 1], 0)),
            registry,
            SocketAddr::from(([127, 0, 0, 1], 0)),
            Duration::from_secs(1),
            Arc::new(Semaphore::new(MAX_SNI_ADMISSION_SLOTS)),
            NeverReadyControlConnector(Arc::new(Notify::new())),
        ))
    }

    /// A registered journal whose host slept keeps its carrier socket open, so
    /// carrier EOF never arrives. The routed client must still be closed, and
    /// the stale registration must stop answering later clients.
    #[tokio::test(start_paused = true)]
    async fn a_silent_registered_journal_loses_the_client_and_its_registration()
    -> Result<(), io::Error> {
        let (registry, journal, _peer, _control) = registry_with_silent_journal().await?;
        let (mut client, server) = tcp_pair().await?;
        client
            .write_all(&client_hello_for(UNRESPONSIVE_TEST_HOSTNAME))
            .await?;
        let task = unresponsive_client_task(server, registry.clone());
        tokio::time::advance(ROUTED_FIRST_RESPONSE_DEADLINE + Duration::from_secs(1)).await;
        task.await.map_err(io::Error::other)?;

        let mut byte = [0_u8; 1];
        assert!(matches!(client.read(&mut byte).await, Ok(0) | Err(_)));
        assert!(registry.lookup(UNRESPONSIVE_TEST_HOSTNAME).await.is_none());
        assert!(matches!(
            journal.open_stream().await,
            Err(registry::RegistryError::Retired)
        ));
        Ok(())
    }

    /// One answered byte disarms the deadline, so an ordinary long-running
    /// tool call is never cut short once its handshake has begun.
    #[tokio::test(start_paused = true)]
    async fn an_answering_journal_keeps_a_client_past_the_deadline() -> Result<(), io::Error> {
        let (registry, _journal, mut peer, _control) = registry_with_silent_journal().await?;
        let (mut client, server) = tcp_pair().await?;
        client
            .write_all(&client_hello_for(UNRESPONSIVE_TEST_HOSTNAME))
            .await?;
        let task = unresponsive_client_task(server, registry.clone());

        let mut carrier = Vec::new();
        let stream_id = loop {
            let mut chunk = [0_u8; 4096];
            let read = peer.read(&mut chunk).await?;
            carrier.extend_from_slice(&chunk[..read]);
            let mut decoder = FrameDecoder::new();
            decoder.feed(&carrier);
            let mut opened = None;
            while let Ok(Some(frame)) = decoder.next_frame() {
                if frame.flags & FLAG_OPEN != 0 {
                    opened = Some(frame.stream_id);
                }
            }
            if let Some(stream_id) = opened {
                break stream_id;
            }
        };
        let answer = Frame {
            stream_id,
            flags: FLAG_DATA,
            payload: vec![0x16],
        };
        peer.write_all(&answer.encode().map_err(io::Error::other)?)
            .await?;
        peer.flush().await?;
        tokio::time::advance(ROUTED_FIRST_RESPONSE_DEADLINE * 4).await;
        tokio::task::yield_now().await;

        assert!(!task.is_finished());
        assert!(registry.lookup(UNRESPONSIVE_TEST_HOSTNAME).await.is_some());
        task.abort();
        Ok(())
    }

    #[test]
    fn acceptance_criterion_12_admission_events_are_fixed_and_exhaustive() {
        for error in [
            PopError::TokenRejected,
            PopError::HostnameMismatch,
            PopError::TokenTimeInvalid,
        ] {
            assert!(matches!(
                pop_admission_event(&error),
                BridgeLogEvent::JournalRegistrationTokenRejected
            ));
        }
        for error in [
            PopError::JwksUnavailable,
            PopError::JwksKeyUnavailable,
            PopError::JwksUrl,
            PopError::JwksTlsConfiguration,
        ] {
            assert!(matches!(
                pop_admission_event(&error),
                BridgeLogEvent::JournalRegistrationJwksUnavailable
            ));
        }
        assert!(matches!(
            pop_admission_event(&PopError::NonceOutstandingCapacity),
            BridgeLogEvent::JournalRegistrationNonceOutstandingCapacity
        ));
        assert!(matches!(
            pop_admission_event(&PopError::NonceSpentCapacity),
            BridgeLogEvent::JournalRegistrationNonceSpentCapacity
        ));
        for error in [PopError::NonceCollisionExhausted, PopError::Randomness] {
            assert!(matches!(
                pop_admission_event(&error),
                BridgeLogEvent::JournalRegistrationNonceGenerationFailed
            ));
        }
        for error in [
            PopError::Io,
            PopError::MessageTooLarge,
            PopError::InvalidMessage,
            PopError::ChallengeTimeInvalid,
            PopError::InvalidProof,
            PopError::NonceReplay,
        ] {
            assert!(matches!(
                pop_admission_event(&error),
                BridgeLogEvent::JournalRegistrationFramingOrProofRejected
            ));
        }

        for error in [
            RegistryError::Expired,
            RegistryError::AdmissionDeadlineExceeded,
        ] {
            assert!(matches!(
                registry_admission_event(&error),
                BridgeLogEvent::JournalRegistrationRejectedAdmissionTimeout
            ));
        }
        for error in [
            RegistryError::Retired,
            RegistryError::OpenTimedOut,
            RegistryError::Dialer(DialerError::ConnectionClosed),
        ] {
            assert!(matches!(
                registry_admission_event(&error),
                BridgeLogEvent::JournalRegistrationRegistryFailed
            ));
        }

        for event in [
            BridgeLogEvent::ClientRejectedJournalUnresponsive,
            BridgeLogEvent::JournalRetiredUnresponsive,
            BridgeLogEvent::JournalLeaseRenewalRetryableAttemptFailed,
            BridgeLogEvent::JournalLeaseRenewalTerminalPoisoned,
            BridgeLogEvent::JournalLeaseRenewalNonceOutstandingCapacity,
            BridgeLogEvent::JournalLeaseRenewalNonceSpentCapacity,
            BridgeLogEvent::JournalLeaseRenewed,
            BridgeLogEvent::JournalLeaseExpiredWallClock,
        ] {
            event.emit();
        }
    }

    #[test]
    fn acceptance_criterion_renewal_12_lease_events_do_not_reflect_peer_data() {
        let logs = LogBuffer(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_writer(logs.clone())
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            for event in [
                BridgeLogEvent::ClientRejectedJournalUnresponsive,
                BridgeLogEvent::JournalRetiredUnresponsive,
                BridgeLogEvent::JournalLeaseRenewalRetryableAttemptFailed,
                BridgeLogEvent::JournalLeaseRenewalTerminalPoisoned,
                BridgeLogEvent::JournalLeaseRenewalNonceOutstandingCapacity,
                BridgeLogEvent::JournalLeaseRenewalNonceSpentCapacity,
                BridgeLogEvent::JournalLeaseRenewed,
                BridgeLogEvent::JournalLeaseExpiredWallClock,
            ] {
                event.emit();
            }
        });

        let output = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
        for peer_value in [
            "eyJhbGciOiJFZERTQSJ9.payload.signature",
            "journal.example.test",
            "8488ae64-b592-80a3-97c6-490e995daa85",
            "AAECAwQFBgcICQoLDA0ODw",
            "127.0.0.1:443",
            "nonce-or-proof-bytes",
        ] {
            assert!(!output.contains(peer_value));
        }
    }
}
