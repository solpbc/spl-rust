// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Dynamic control TLS certificate resolver and reload coordinator.

use std::io;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use rustls::RootCertStore;
pub use rustls::pki_types::UnixTime;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{Error as RustlsError, ServerConfig};
use thiserror::Error;
use tokio::sync::Mutex as TokioMutex;
use webpki::{EndEntityCert, KeyUsage};

use crate::BridgeLogEvent;

/// The single reserved host name served by the bridge's dynamic control TLS listener.
pub const RESERVED_CONTROL_SNI: &str = "bridge.solstone.me";

/// Epoch seconds timestamp type for certificate time validation.
pub type UnixTimeSecs = u64;

/// A clock function returning current unix time in seconds.
pub type ClockFn = Arc<dyn Fn() -> UnixTimeSecs + Send + Sync>;

/// Certificate material loader function returning (`cert_pem`, `key_pem`).
pub type CertMaterialLoader = Arc<dyn Fn() -> Result<(Vec<u8>, Vec<u8>), io::Error> + Send + Sync>;

/// Errors during control certificate validation or dynamic reload.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ControlCertError {
    /// The certificate chain or private key was malformed or empty.
    #[error("invalid certificate material")]
    InvalidCertificate,
    /// The private key was rejected or did not match the certificate.
    #[error("invalid private key")]
    InvalidPrivateKey,
    /// The certificate chain does not include a valid SAN for `bridge.solstone.me`.
    #[error("certificate subject name mismatch")]
    SubjectNameMismatch,
    /// The certificate has expired or is not yet valid at the reference time.
    #[error("certificate expired or not yet valid")]
    Expired,
    /// The certificate chain is untrusted against the active root store.
    #[error("untrusted certificate chain")]
    Untrusted,
    /// An internal rustls error occurred.
    #[error("TLS configuration error: {0}")]
    Tls(String),
}

/// Dynamic certificate resolver serving the live control TLS certificate.
#[derive(Debug)]
pub struct ControlCertResolver {
    current: RwLock<Arc<CertifiedKey>>,
}

impl ControlCertResolver {
    /// Create a new resolver holding `initial_key`.
    pub fn new(initial_key: Arc<CertifiedKey>) -> Self {
        Self {
            current: RwLock::new(initial_key),
        }
    }

    /// Read the currently active certified key.
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` is poisoned.
    pub fn current(&self) -> Arc<CertifiedKey> {
        #[expect(
            clippy::unwrap_used,
            reason = "poisoned resolver lock indicates unrecoverable internal failure"
        )]
        Arc::clone(&self.current.read().unwrap())
    }

    /// Atomically update the active certified key.
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` is poisoned.
    pub fn update(&self, new_key: Arc<CertifiedKey>) {
        #[expect(
            clippy::unwrap_used,
            reason = "poisoned resolver lock indicates unrecoverable internal failure"
        )]
        let mut write = self.current.write().unwrap();
        *write = new_key;
    }
}

impl ResolvesServerCert for ControlCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current())
    }
}

/// Build a rustls `ServerConfig` for the control listener using `resolver`.
///
/// Uses the ring crypto provider and disables client TLS authentication.
///
/// # Errors
///
/// Returns a `RustlsError` if safe protocol defaults cannot be configured.
pub fn control_server_tls_config(
    resolver: Arc<ControlCertResolver>,
) -> Result<ServerConfig, RustlsError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    Ok(config)
}

/// Validate a candidate control certificate chain and key.
///
/// Ensures:
/// 1. The key matches the leaf certificate.
/// 2. The leaf certificate covers `bridge.solstone.me`.
/// 3. The certificate chain verifies against `roots` at `now_secs`.
///
/// # Errors
///
/// Returns a `ControlCertError` if key parsing, SAN matching, or `WebPKI` chain validation fails.
pub fn validate_control_certified_key(
    chain: &[CertificateDer<'static>],
    key: &PrivateKeyDer<'static>,
    roots: &RootCertStore,
    now_secs: UnixTimeSecs,
) -> Result<Arc<CertifiedKey>, ControlCertError> {
    if chain.is_empty() {
        return Err(ControlCertError::InvalidCertificate);
    }
    let leaf_der = chain.first().ok_or(ControlCertError::InvalidCertificate)?;

    let signing_key = rustls::crypto::ring::sign::any_supported_type(key)
        .map_err(|_| ControlCertError::InvalidPrivateKey)?;
    let certified_key = CertifiedKey::new(chain.to_vec(), signing_key);
    certified_key
        .keys_match()
        .map_err(|_| ControlCertError::InvalidPrivateKey)?;

    let leaf =
        EndEntityCert::try_from(leaf_der).map_err(|_| ControlCertError::InvalidCertificate)?;

    let server_name = ServerName::try_from(RESERVED_CONTROL_SNI)
        .map_err(|_| ControlCertError::SubjectNameMismatch)?;
    leaf.verify_is_valid_for_subject_name(&server_name)
        .map_err(|_| ControlCertError::SubjectNameMismatch)?;

    let intermediates: Vec<CertificateDer<'static>> = chain.iter().skip(1).cloned().collect();
    let unix_time = UnixTime::since_unix_epoch(Duration::from_secs(now_secs));

    leaf.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &roots.roots,
        &intermediates,
        unix_time,
        KeyUsage::server_auth(),
        None,
        None,
    )
    .map_err(|err| match err {
        webpki::Error::CertExpired { .. } | webpki::Error::CertNotValidYet { .. } => {
            ControlCertError::Expired
        }
        _ => ControlCertError::Untrusted,
    })?;

    Ok(Arc::new(certified_key))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReloadState {
    Idle,
    Busy { rerun: bool },
}

/// Coordinates async SIGHUP certificate reloads with coalescing and `spawn_blocking`.
pub struct ReloadCoordinator {
    resolver: Arc<ControlCertResolver>,
    roots: RootCertStore,
    clock: ClockFn,
    loader: CertMaterialLoader,
    state: TokioMutex<ReloadState>,
}

impl ReloadCoordinator {
    /// Construct a new reload coordinator.
    pub fn new(
        resolver: Arc<ControlCertResolver>,
        roots: RootCertStore,
        clock: ClockFn,
        loader: CertMaterialLoader,
    ) -> Self {
        Self {
            resolver,
            roots,
            clock,
            loader,
            state: TokioMutex::new(ReloadState::Idle),
        }
    }

    /// Request a reload. Coalesces concurrent SIGHUP signals.
    pub async fn request_reload(&self) {
        let mut lock = self.state.lock().await;
        match *lock {
            ReloadState::Busy { .. } => {
                *lock = ReloadState::Busy { rerun: true };
                return;
            }
            ReloadState::Idle => {
                *lock = ReloadState::Busy { rerun: false };
            }
        }
        drop(lock);

        loop {
            let result = self.request_reload_inner().await;
            match result {
                Ok(new_key) => {
                    self.resolver.update(new_key);
                }
                Err(_) => {
                    BridgeLogEvent::ControlCertificateReloadFailed.emit();
                }
            }

            let mut lock = self.state.lock().await;
            if let ReloadState::Busy { rerun: true } = *lock {
                *lock = ReloadState::Busy { rerun: false };
            } else {
                *lock = ReloadState::Idle;
                break;
            }
        }
    }

    async fn request_reload_inner(&self) -> Result<Arc<CertifiedKey>, ControlCertError> {
        let loader = Arc::clone(&self.loader);
        let roots = self.roots.clone();
        let clock = Arc::clone(&self.clock);

        tokio::task::spawn_blocking(move || {
            let (cert_pem, key_pem) = loader().map_err(|_| ControlCertError::InvalidCertificate)?;
            let cert_chain = crate::pem_certificate_chain(&cert_pem)
                .map_err(|_| ControlCertError::InvalidCertificate)?;
            let private_key = crate::pem_private_key(&key_pem)
                .map_err(|_| ControlCertError::InvalidPrivateKey)?;
            let now = clock();
            validate_control_certified_key(&cert_chain, &private_key, &roots, now)
        })
        .await
        .map_err(|e| ControlCertError::Tls(e.to_string()))?
    }
}
