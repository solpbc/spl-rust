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

/// Accept journal control connections indefinitely on `listener`.
///
/// Every registration is handled in its own task so a slow peer cannot block
/// later journal registrations.
pub async fn run_control_listener(
    listener: TcpListener,
    tls_config: Arc<ServerConfig>,
    registry: registry::Registry,
    authenticator: pop_auth::PopAuthenticator,
) {
    tracing::info!(address = %listener.local_addr().ok().map_or_else(String::new, |address| address.to_string()), "control listener started");
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            tracing::warn!("control listener accept failed");
            continue;
        };
        let acceptor = TlsAcceptor::from(Arc::clone(&tls_config));
        let registry = registry.clone();
        let authenticator = authenticator.clone();
        tokio::spawn(async move {
            let Ok(mut tls_stream) = acceptor.accept(stream).await else {
                tracing::warn!(%peer, "control TLS handshake rejected");
                return;
            };
            let Ok(registration) = authenticator.authenticate(&mut tls_stream).await else {
                tracing::warn!(%peer, "journal registration rejected");
                return;
            };
            let hostname = registration.hostname().to_owned();
            let journal = registry.register(hostname.clone(), tls_stream).await;
            let generation = journal.generation();
            tracing::info!(%peer, hostname = ?hostname, generation, "journal registered");
            tokio::spawn(async move {
                journal.wait_until_gone().await;
                tracing::info!(hostname = ?hostname, generation, "journal evicted");
            });
        });
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
