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

use std::io::{BufReader, Cursor};
use std::sync::Arc;
use std::time::Duration;

use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

pub mod frame_dialer;
pub mod pop_auth;
pub mod proxy_protocol;
pub mod registry;
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
    tracing::info!(address = %listener.local_addr().ok().map_or_else(String::new, |address| address.to_string()), "control listener started");
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            tracing::warn!("control listener accept failed");
            continue;
        };
        let deadline = tokio::time::Instant::now() + admission_deadline;
        let acceptor = TlsAcceptor::from(Arc::clone(&tls_config));
        let registry = registry.clone();
        let authenticator = authenticator.clone();
        tokio::spawn(async move {
            if tokio::time::timeout_at(deadline, async move {
                let Ok(mut tls_stream) = acceptor.accept(stream).await else {
                    tracing::warn!(%peer, "control TLS handshake rejected");
                    return;
                };
                let registration = match authenticator.authenticate(&mut tls_stream).await {
                    Ok(registration) => registration,
                    Err(error) => {
                        tracing::warn!(%peer, reason = pop_admission_reason(&error), "journal registration rejected");
                        return;
                    }
                };
                let hostname = registration.hostname().to_owned();
                let journal = match registry
                    .register(
                        hostname,
                        tls_stream,
                        registration.claims().expires_at(),
                        deadline,
                    )
                    .await
                {
                    Ok(journal) => journal,
                    Err(error) => {
                        tracing::warn!(reason = registry_admission_reason(&error), "journal registration failed");
                        return;
                    }
                };
                let generation = journal.generation();
                tracing::info!(%peer, generation, "journal registered");
                tokio::spawn(async move {
                    journal.wait_until_gone().await;
                    tracing::info!(generation, "journal evicted");
                });
            })
            .await
            .is_err()
            {
                tracing::warn!(reason = "admission_timeout", "journal registration timed out");
            }
        });
    }
}

fn pop_admission_reason(error: &pop_auth::PopError) -> &'static str {
    match error {
        pop_auth::PopError::TokenRejected
        | pop_auth::PopError::HostnameMismatch
        | pop_auth::PopError::TokenTimeInvalid => "token_rejection",
        pop_auth::PopError::JwksUnavailable
        | pop_auth::PopError::JwksKeyUnavailable
        | pop_auth::PopError::JwksUrl
        | pop_auth::PopError::JwksTlsConfiguration => "jwks_unavailable",
        pop_auth::PopError::NonceOutstandingCapacity => "nonce_outstanding_capacity",
        pop_auth::PopError::NonceSpentCapacity => "nonce_spent_capacity",
        pop_auth::PopError::NonceCollisionExhausted | pop_auth::PopError::Randomness => {
            "nonce_generation_failure"
        }
        pop_auth::PopError::Io
        | pop_auth::PopError::MessageTooLarge
        | pop_auth::PopError::InvalidMessage
        | pop_auth::PopError::ChallengeTimeInvalid
        | pop_auth::PopError::InvalidProof
        | pop_auth::PopError::NonceReplay => "framing_or_proof_rejection",
    }
}

fn registry_admission_reason(error: &registry::RegistryError) -> &'static str {
    match error {
        registry::RegistryError::Expired | registry::RegistryError::AdmissionDeadlineExceeded => {
            "admission_timeout"
        }
        registry::RegistryError::Retired
        | registry::RegistryError::OpenTimedOut
        | registry::RegistryError::Dialer(_) => "registry_failure",
    }
}

/// Accept raw client TLS connections indefinitely on `listener`.
///
/// Client TLS remains opaque: this listener peeks only far enough to route by
/// SNI, writes a PROXY v1 header to the journal stream, and then splices bytes.
pub async fn run_client_listener(
    listener: TcpListener,
    registry: registry::Registry,
    sni_deadline: Duration,
) {
    tracing::info!(address = %listener.local_addr().ok().map_or_else(String::new, |address| address.to_string()), "client listener started");
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            tracing::warn!("client listener accept failed");
            continue;
        };
        let registry = registry.clone();
        tokio::spawn(async move {
            handle_client(stream, peer, registry, sni_deadline).await;
        });
    }
}

async fn handle_client(
    mut client: TcpStream,
    peer: std::net::SocketAddr,
    registry: registry::Registry,
    sni_deadline: Duration,
) {
    let Ok(hostname) = sni::extract_sni(&client, sni_deadline).await else {
        tracing::warn!(%peer, "client rejected before routing");
        return;
    };
    let Some(journal) = registry.lookup(&hostname).await else {
        tracing::warn!(%peer, hostname = ?hostname, "client rejected without journal registration");
        return;
    };
    let Ok(mut stream) = journal.open_stream().await else {
        tracing::warn!(%peer, hostname = ?hostname, "client rejected because journal stream could not open");
        return;
    };
    let Ok(source) = client.peer_addr() else {
        return;
    };
    let Ok(destination) = client.local_addr() else {
        return;
    };
    let Ok(header) = proxy_protocol::v1_header(source, destination) else {
        tracing::warn!(%peer, hostname = ?hostname, "client rejected because PROXY header could not be built");
        return;
    };
    if stream.write_all(&header).await.is_err() || stream.flush().await.is_err() {
        tracing::warn!(%peer, hostname = ?hostname, "client rejected because PROXY header could not be written");
        return;
    }

    let stream_id = stream.id();
    tracing::info!(%peer, hostname = ?hostname, stream_id, "client routed to journal");
    match tokio::io::copy_bidirectional(&mut client, &mut stream).await {
        Ok((client_to_journal, journal_to_client)) => {
            tracing::info!(%peer, hostname = ?hostname, stream_id, client_to_journal, journal_to_client, "client splice closed");
        }
        Err(_) => {
            tracing::warn!(%peer, hostname = ?hostname, stream_id, "client splice closed with I/O error");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame_dialer::DialerError;
    use crate::pop_auth::PopError;
    use crate::registry::RegistryError;

    #[test]
    fn acceptance_criterion_12_admission_reason_categories_are_fixed_and_exhaustive() {
        for error in [
            PopError::TokenRejected,
            PopError::HostnameMismatch,
            PopError::TokenTimeInvalid,
        ] {
            assert_eq!(pop_admission_reason(&error), "token_rejection");
        }
        for error in [
            PopError::JwksUnavailable,
            PopError::JwksKeyUnavailable,
            PopError::JwksUrl,
            PopError::JwksTlsConfiguration,
        ] {
            assert_eq!(pop_admission_reason(&error), "jwks_unavailable");
        }
        assert_eq!(
            pop_admission_reason(&PopError::NonceOutstandingCapacity),
            "nonce_outstanding_capacity"
        );
        assert_eq!(
            pop_admission_reason(&PopError::NonceSpentCapacity),
            "nonce_spent_capacity"
        );
        for error in [PopError::NonceCollisionExhausted, PopError::Randomness] {
            assert_eq!(pop_admission_reason(&error), "nonce_generation_failure");
        }
        for error in [
            PopError::Io,
            PopError::MessageTooLarge,
            PopError::InvalidMessage,
            PopError::ChallengeTimeInvalid,
            PopError::InvalidProof,
            PopError::NonceReplay,
        ] {
            assert_eq!(pop_admission_reason(&error), "framing_or_proof_rejection");
        }

        for error in [
            RegistryError::Expired,
            RegistryError::AdmissionDeadlineExceeded,
        ] {
            assert_eq!(registry_admission_reason(&error), "admission_timeout");
        }
        for error in [
            RegistryError::Retired,
            RegistryError::OpenTimedOut,
            RegistryError::Dialer(DialerError::ConnectionClosed),
        ] {
            assert_eq!(registry_admission_reason(&error), "registry_failure");
        }
    }
}
