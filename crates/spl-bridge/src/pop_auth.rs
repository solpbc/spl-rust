// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Journal proof-of-possession authentication for control registrations.
//!
//! The JWT claims contract is locked and externally verified against the
//! committed account-service fixture (`account/test-fixtures/mcp_bridge_v1.json`,
//! provenance commit `6c3dc18376b365792f5cb512eb5bf17d8eff17bc`): issuer
//! `services.solstone.app`, a `home:<instance-id>` subject, configured
//! bridge-id audience, Unix-second `iat`/`exp` with a 600--900 second TTL,
//! `[a-z2-7]{8}.solstone.me` hostname, and `cnf.jwk`.
//!
//! The surrounding length-prefixed JSON envelope and its registration
//! challenge/response exchange remain this repository's local protocol, not a
//! published journal-MCP wire specification. Reconcile that framing before use
//! with a journal outside this repository's tests if it is ever standardized.
//!
//! The journal first sends `{"token":"...","hostname":"..."}`. The
//! verified token claims contain the fixed issuer, bridge audience, a
//! `home:<instance-id>` subject, Unix-second `exp` and `iat`, a constrained
//! Solstone hostname, and `cnf.jwk`, a base64url-without-padding raw 32-byte
//! Ed25519 public key. The bridge replies with
//! `{"nonce":"...","bridge_id":"...","timestamp":...}`, containing a
//! base64url 16-byte nonce and bridge-issued Unix-second timestamp. The journal
//! then sends `{"signature":"..."}`, where `signature` is an Ed25519
//! signature over `nonce || bridge_id UTF-8 bytes || timestamp`, with the
//! timestamp encoded as an eight-byte big-endian signed integer.
//! Each JSON value is prefixed by a four-byte big-endian byte length.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio_rustls::TlsConnector;

const MAX_MESSAGE_BYTES: usize = 64 * 1024;
const NONCE_BYTES: usize = 16;
const POP_SKEW: u64 = 60;
const OUTSTANDING_NONCE_LIMIT: usize = 256;
const SPENT_NONCE_LIMIT: usize = 4096;
const NONCE_GENERATION_ATTEMPTS: usize = 8;
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const DEFAULT_FETCH_TIMEOUT: Duration = Duration::from_secs(3);
const JWKS_CACHE_TTL: Duration = Duration::from_mins(5);
const JWKS_CACHE_LIMIT: usize = 64;
const MAX_JWKS_RESPONSE_BYTES: usize = 1024 * 1024;
const EXPECTED_ISSUER: &str = "services.solstone.app";

/// A source of Unix seconds used only for JWT time-claim validation.
pub type ClockFn = Arc<dyn Fn() -> u64 + Send + Sync>;

fn real_clock() -> ClockFn {
    Arc::new(|| unix_seconds().unwrap_or_default())
}

/// A verified token claim set used to bind a registration proof to a journal.
#[derive(Clone)]
pub struct VerifiedClaims {
    instance_id: String,
    hostname: String,
    expires_at: u64,
    pop_key: VerifyingKey,
}

/// Identity attributes that stay fixed for one registered journal generation.
#[derive(Clone)]
pub struct RenewalIdentity {
    hostname: String,
    instance_id: String,
    pop_key: VerifyingKey,
}

impl RenewalIdentity {
    /// Build the immutable identity bound to one journal registration generation.
    pub fn new(hostname: String, instance_id: String, pop_key: VerifyingKey) -> Self {
        Self {
            hostname,
            instance_id,
            pop_key,
        }
    }

    /// Return the hostname fixed at initial registration.
    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    /// Return the instance id fixed at initial registration.
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// Return the proof key fixed at initial registration.
    pub fn pop_key(&self) -> &VerifyingKey {
        &self.pop_key
    }
}

impl VerifiedClaims {
    /// Return the Solstone instance id authorized by the token subject.
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// Return the hostname authorized by the token.
    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    /// Return the token expiry as Unix seconds.
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Return the Ed25519 key that must sign the challenge response.
    pub fn pop_key(&self) -> &VerifyingKey {
        &self.pop_key
    }
}

/// Errors returned while authenticating a journal registration.
#[derive(Debug, Error)]
pub enum PopError {
    /// The control carrier could not read or write the bounded handshake.
    #[error("proof-of-possession I/O failed")]
    Io,
    /// A length-prefixed control message exceeded the fixed maximum size.
    #[error("proof-of-possession message is too large")]
    MessageTooLarge,
    /// A control message was not valid JSON for its handshake position.
    #[error("proof-of-possession message is invalid")]
    InvalidMessage,
    /// The JWT was malformed, used a disallowed algorithm, or failed signature validation.
    #[error("journal token was rejected")]
    TokenRejected,
    /// The claimed hostname did not match the verified token hostname.
    #[error("journal token hostname does not match registration")]
    HostnameMismatch,
    /// The token was expired or its issue time was not plausible.
    #[error("journal token time claims are invalid")]
    TokenTimeInvalid,
    /// A bridge-issued challenge timestamp was too old or too far in the future.
    #[error("proof-of-possession challenge timestamp is invalid")]
    ChallengeTimeInvalid,
    /// The challenge response signature did not verify with the claimed key.
    #[error("proof-of-possession signature is invalid")]
    InvalidProof,
    /// The challenge nonce was already redeemed or was not currently issued.
    #[error("proof-of-possession nonce was replayed")]
    NonceReplay,
    /// Random nonce generation failed.
    #[error("proof-of-possession nonce generation failed")]
    Randomness,
    /// The outstanding nonce cache reached its fixed capacity.
    #[error("proof-of-possession outstanding nonce capacity is exhausted")]
    NonceOutstandingCapacity,
    /// The spent nonce cache reached its fixed capacity.
    #[error("proof-of-possession spent nonce capacity is exhausted")]
    NonceSpentCapacity,
    /// The nonce generator repeatedly collided with a live nonce.
    #[error("proof-of-possession nonce generation collided repeatedly")]
    NonceCollisionExhausted,
    /// The configured JWKS URL is not a valid HTTPS URL.
    #[error("JWKS URL is invalid")]
    JwksUrl,
    /// Rustls could not create the pinned ring-provider client configuration.
    #[error("JWKS TLS configuration failed")]
    JwksTlsConfiguration,
    /// The JWKS origin could not be reached or did not provide valid key material.
    #[error("JWKS is unavailable")]
    JwksUnavailable,
    /// The requested JWKS key was unavailable after a fetch or during cooldown.
    #[error("requested JWKS key is unavailable")]
    JwksKeyUnavailable,
}

/// The initial length-prefixed JSON message sent by a registering journal.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationRequest {
    /// `EdDSA` JWT authorizing the named hostname and challenge public key.
    pub token: String,
    /// Hostname the journal is registering with this bridge.
    pub hostname: String,
}

/// The bridge's length-prefixed JSON challenge message.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    /// Base64url-without-padding encoding of the random 16-byte nonce.
    pub nonce: String,
    /// Configured bridge identifier bound into the proof signature.
    pub bridge_id: String,
    /// Bridge-issued Unix seconds bound into the proof signature.
    pub timestamp: i64,
}

/// The length-prefixed JSON response to a [`Challenge`].
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeResponse {
    /// Base64url-without-padding encoding of the 64-byte Ed25519 signature.
    pub signature: String,
}

/// The complete response to a bridge-initiated journal lease renewal challenge.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RenewalResponse {
    token: String,
    hostname: String,
    signature: String,
}

/// The result category for one renewal attempt.
#[derive(Debug)]
pub(crate) enum RenewalError {
    /// The complete response was received but could not be accepted.
    Retryable(PopError),
    /// Carrier byte synchronization was lost before a complete response arrived.
    Terminal,
}

/// The journal identity established by a successful proof-of-possession exchange.
#[derive(Clone)]
pub struct AuthenticatedRegistration {
    hostname: String,
    claims: VerifiedClaims,
}

impl AuthenticatedRegistration {
    /// Return the hostname authorized for this registration.
    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    /// Return the verified JWT claim set bound to this registration.
    pub fn claims(&self) -> &VerifiedClaims {
        &self.claims
    }

    pub(crate) fn renewal_identity(&self) -> RenewalIdentity {
        RenewalIdentity {
            hostname: self.hostname.clone(),
            instance_id: self.claims.instance_id.clone(),
            pop_key: self.claims.pop_key,
        }
    }
}

/// An asynchronously callable JWT verifier that can be supplied by tests or JWKS.
pub trait TokenVerifier: Send + Sync {
    /// Verify `token` and return the claims required by the `PoP` handshake.
    fn verify<'a>(
        &'a self,
        token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<VerifiedClaims, PopError>> + Send + 'a>>;
}

/// The server-side `PoP` state shared across registration control connections.
#[derive(Clone)]
pub struct PopAuthenticator {
    verifier: Arc<dyn TokenVerifier>,
    nonces: Arc<Mutex<NonceCache>>,
    bridge_id: String,
}

/// A deterministic, in-memory `EdDSA` token verifier for tests and fixtures.
#[derive(Clone)]
pub struct FixtureTokenVerifier {
    signing_keys: HashMap<String, SigningKey>,
    expected_audience: String,
    clock: ClockFn,
}

/// A HTTPS JWKS-backed `EdDSA` token verifier with a small in-memory key cache.
#[derive(Clone)]
pub struct JwksTokenVerifier {
    requests: mpsc::UnboundedSender<JwksRequest>,
    expected_audience: String,
    clock: ClockFn,
}

/// Timeout limits for one JWKS fetch attempt.
#[derive(Clone, Copy)]
pub struct JwksTimeouts {
    /// Bound for establishing the TCP connection to the JWKS origin.
    pub connect: Duration,
    /// Bound for TLS handshake, request write, and response read after connect.
    pub fetch: Duration,
}

impl Default for JwksTimeouts {
    fn default() -> Self {
        Self {
            connect: DEFAULT_CONNECT_TIMEOUT,
            fetch: DEFAULT_FETCH_TIMEOUT,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawClaims {
    iss: String,
    sub: String,
    aud: String,
    iat: u64,
    exp: u64,
    hostname: String,
    cnf: Confirmation,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Confirmation {
    jwk: PopJwk,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PopJwk {
    kty: String,
    crv: String,
    x: String,
}

struct NonceCache {
    outstanding: HashMap<[u8; NONCE_BYTES], NonceEntry>,
    spent: HashMap<[u8; NONCE_BYTES], NonceEntry>,
}

struct NonceEntry {
    expires_at: u64,
}

/// An issued nonce slot that is released unless it is redeemed.
struct NonceLease {
    cache: Arc<Mutex<NonceCache>>,
    nonce: [u8; NONCE_BYTES],
    armed: bool,
}

#[derive(Clone)]
struct JwksOrigin {
    host: String,
    port: u16,
    authority: String,
    path_and_query: String,
}

struct CachedJwk {
    key: Arc<VerifyingKey>,
    expires_at: tokio::time::Instant,
}

struct JwksRequest {
    kid: String,
    reply: oneshot::Sender<Result<Arc<VerifyingKey>, PopError>>,
}

struct InFlightFetch {
    completion: oneshot::Receiver<Result<HashMap<String, VerifyingKey>, PopError>>,
    waiters: Vec<JwksRequest>,
}

#[derive(Deserialize)]
struct JwksDocument {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kid: String,
    kty: String,
    crv: String,
    x: String,
    #[serde(default)]
    alg: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JoseHeader {
    alg: String,
    typ: String,
    kid: String,
}

struct ParsedToken {
    header: JoseHeader,
    claims: RawClaims,
    signature: Signature,
    signing_input: Vec<u8>,
}

impl PopAuthenticator {
    /// Construct an authenticator using `verifier`, `bridge_id`, and an empty replay cache.
    pub fn new(verifier: Arc<dyn TokenVerifier>, bridge_id: String) -> Self {
        Self {
            verifier,
            nonces: Arc::new(Mutex::new(NonceCache {
                outstanding: HashMap::new(),
                spent: HashMap::new(),
            })),
            bridge_id,
        }
    }

    /// Authenticate one registration exchange over a length-prefixed JSON carrier.
    ///
    /// The caller may register the returned identity only after this method has
    /// succeeded. Any error rejects the registration before a carrier is handed
    /// to the registry.
    ///
    /// # Errors
    ///
    /// Returns an error when the JSON exchange, JWT validation, proof signature,
    /// timestamp, or nonce replay validation fails.
    pub async fn authenticate<S>(
        &self,
        carrier: &mut S,
    ) -> Result<AuthenticatedRegistration, PopError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let request: RegistrationRequest = read_message(carrier).await?;
        let claims = self.verifier.verify(&request.token).await?;
        let now = unix_seconds()?;
        validate_registration_hostname(&claims, &request.hostname)?;

        let issued_at = i64::try_from(now).map_err(|_| PopError::ChallengeTimeInvalid)?;
        let mut nonce = NonceLease::issue(Arc::clone(&self.nonces), now, claims.expires_at())?;
        let challenge = Challenge {
            nonce: URL_SAFE_NO_PAD.encode(nonce.bytes()),
            bridge_id: self.bridge_id.clone(),
            timestamp: issued_at,
        };
        write_message(carrier, &challenge).await?;

        let response: ChallengeResponse = read_message(carrier).await?;
        let verified_now = unix_seconds()?;
        let verified_at =
            i64::try_from(verified_now).map_err(|_| PopError::ChallengeTimeInvalid)?;
        if !challenge_timestamp_is_fresh(issued_at, verified_at) {
            return Err(PopError::ChallengeTimeInvalid);
        }
        let signature = decode_signature(&response.signature)?;
        let signed = proof_message(nonce.bytes(), &self.bridge_id, issued_at);
        claims
            .pop_key()
            .verify_strict(&signed, &signature)
            .map_err(|_| PopError::InvalidProof)?;
        nonce.redeem(claims.expires_at(), verified_now)?;

        Ok(AuthenticatedRegistration {
            hostname: request.hostname,
            claims,
        })
    }

    pub(crate) async fn renew<S>(
        &self,
        carrier: &mut S,
        identity: &RenewalIdentity,
        check_expires_at: u64,
    ) -> Result<u64, RenewalError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let now = unix_seconds().map_err(RenewalError::Retryable)?;
        let issued_at = i64::try_from(now)
            .map_err(|_| RenewalError::Retryable(PopError::ChallengeTimeInvalid))?;
        let mut nonce = NonceLease::issue(Arc::clone(&self.nonces), now, check_expires_at)
            .map_err(RenewalError::Retryable)?;
        let challenge = Challenge {
            nonce: URL_SAFE_NO_PAD.encode(nonce.bytes()),
            bridge_id: self.bridge_id.clone(),
            timestamp: issued_at,
        };
        write_message(carrier, &challenge)
            .await
            .map_err(|_| RenewalError::Terminal)?;

        let body = read_renewal_body(carrier)
            .await
            .map_err(|_| RenewalError::Terminal)?;
        let response: RenewalResponse = serde_json::from_slice(&body)
            .map_err(|_| RenewalError::Retryable(PopError::InvalidMessage))?;
        let claims = self
            .verifier
            .verify(&response.token)
            .await
            .map_err(RenewalError::Retryable)?;
        let verified_now = unix_seconds().map_err(RenewalError::Retryable)?;
        let verified_at = i64::try_from(verified_now)
            .map_err(|_| RenewalError::Retryable(PopError::ChallengeTimeInvalid))?;
        if !challenge_timestamp_is_fresh(issued_at, verified_at) {
            return Err(RenewalError::Retryable(PopError::ChallengeTimeInvalid));
        }
        let signature = decode_signature(&response.signature).map_err(RenewalError::Retryable)?;
        let signed = proof_message(nonce.bytes(), &self.bridge_id, issued_at);
        identity
            .pop_key()
            .verify_strict(&signed, &signature)
            .map_err(|_| RenewalError::Retryable(PopError::InvalidProof))?;

        let successor_expiry = claims.expires_at();
        nonce
            .redeem_and_extend(check_expires_at, successor_expiry, verified_now)
            .map_err(RenewalError::Retryable)?;

        if response.hostname != claims.hostname()
            || claims.hostname() != identity.hostname()
            || claims.instance_id() != identity.instance_id()
            || claims.pop_key() != identity.pop_key()
        {
            return Err(RenewalError::Retryable(PopError::TokenRejected));
        }
        if successor_expiry <= check_expires_at {
            return Err(RenewalError::Retryable(PopError::TokenTimeInvalid));
        }
        Ok(successor_expiry)
    }
}

impl FixtureTokenVerifier {
    /// Build a fixture verifier from deterministic Ed25519 JWT signing keys by key id.
    pub fn new(keys: HashMap<String, SigningKey>, expected_audience: String) -> Self {
        Self::with_clock(keys, expected_audience, real_clock())
    }

    /// Build a fixture verifier with a deterministic JWT time source.
    pub fn with_clock(
        signing_keys: HashMap<String, SigningKey>,
        expected_audience: String,
        clock: ClockFn,
    ) -> Self {
        Self {
            signing_keys,
            expected_audience,
            clock,
        }
    }

    /// Mint a signed compact JWT from arbitrary JSON header and claim values.
    ///
    /// # Errors
    ///
    /// Returns an error when `kid` has no fixture signing key or JSON
    /// serialization fails.
    pub fn mint_raw(
        &self,
        kid: &str,
        header: &serde_json::Value,
        claims: &serde_json::Value,
    ) -> Result<String, PopError> {
        let signing = self.signing_keys.get(kid).ok_or(PopError::TokenRejected)?;
        let header = serde_json::to_vec(header).map_err(|_| PopError::InvalidMessage)?;
        let claims = serde_json::to_vec(claims).map_err(|_| PopError::InvalidMessage)?;
        let message = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(claims)
        );
        let signature = signing.sign(message.as_bytes());
        Ok(format!(
            "{message}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ))
    }

    /// Mint a deterministic conformant `EdDSA` JWT for a fixture key and `PoP` public key.
    ///
    /// # Errors
    ///
    /// Returns an error when `kid` has no fixture signing key or JSON
    /// serialization fails.
    pub fn mint(
        &self,
        kid: &str,
        instance_id: &str,
        hostname: &str,
        issued_at: u64,
        expires_at: u64,
        pop_key: &VerifyingKey,
    ) -> Result<String, PopError> {
        let header = serde_json::json!({"alg": "EdDSA", "typ": "JWT", "kid": kid});
        let claims = serde_json::json!({
            "iss": EXPECTED_ISSUER,
            "sub": format!("home:{instance_id}"),
            "aud": self.expected_audience,
            "iat": issued_at,
            "exp": expires_at,
            "hostname": hostname,
            "cnf": {
                "jwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": URL_SAFE_NO_PAD.encode(pop_key.to_bytes()),
                }
            }
        });
        self.mint_raw(kid, &header, &claims)
    }
}

impl TokenVerifier for FixtureTokenVerifier {
    fn verify<'a>(
        &'a self,
        token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<VerifiedClaims, PopError>> + Send + 'a>> {
        Box::pin(async move {
            let parsed = parse_compact_token(token)?;
            let signing = self
                .signing_keys
                .get(&parsed.header.kid)
                .ok_or(PopError::TokenRejected)?;
            verify_parsed_token(
                parsed,
                &signing.verifying_key(),
                &self.expected_audience,
                &self.clock,
            )
        })
    }
}

impl JwksTokenVerifier {
    /// Construct a verifier for one HTTPS JWKS URL.
    ///
    /// Cache misses make one connect attempt bounded to three seconds, followed
    /// by one TLS/request/response attempt bounded to three seconds. There is no
    /// retry loop; successfully fetched Ed25519 keys are retained by `kid` for
    /// five minutes, up to 64 entries.
    ///
    /// # Errors
    ///
    /// Returns an error when `url` is not a valid HTTPS URL or rustls cannot
    /// construct its ring-provider client configuration.
    pub fn new(url: &str, expected_audience: String) -> Result<Self, PopError> {
        Self::with_timeouts(url, JwksTimeouts::default(), expected_audience)
    }

    /// Construct a verifier for one HTTPS JWKS URL with explicit timeout limits.
    ///
    /// # Errors
    ///
    /// Returns an error when `url` is not a valid HTTPS URL or rustls cannot
    /// construct its ring-provider client configuration.
    pub fn with_timeouts(
        url: &str,
        timeouts: JwksTimeouts,
        expected_audience: String,
    ) -> Result<Self, PopError> {
        Self::with_timeouts_and_clock(url, timeouts, expected_audience, real_clock())
    }

    /// Construct a verifier with explicit timeout limits and JWT time source.
    ///
    /// # Errors
    ///
    /// Returns an error when `url` is not a valid HTTPS URL or rustls cannot
    /// construct its ring-provider client configuration.
    pub fn with_timeouts_and_clock(
        url: &str,
        timeouts: JwksTimeouts,
        expected_audience: String,
        clock: ClockFn,
    ) -> Result<Self, PopError> {
        Self::with_trust_store(
            url,
            default_jwks_root_store(),
            timeouts,
            expected_audience,
            clock,
        )
    }

    /// Construct a verifier with explicit trust roots, timeouts, and JWT time source.
    ///
    /// # Errors
    ///
    /// Returns an error when `url` is not a valid HTTPS URL or rustls cannot
    /// construct its ring-provider client configuration.
    pub fn with_trust_store(
        url: &str,
        root_store: RootCertStore,
        timeouts: JwksTimeouts,
        expected_audience: String,
        clock: ClockFn,
    ) -> Result<Self, PopError> {
        let origin = parse_jwks_url(url)?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| PopError::JwksTlsConfiguration)?
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));
        let (requests, receiver) = mpsc::unbounded_channel();
        tokio::spawn(run_jwks_aggregator(receiver, connector, origin, timeouts));
        Ok(Self {
            requests,
            expected_audience,
            clock,
        })
    }

    async fn key_for_kid(&self, kid: &str) -> Result<Arc<VerifyingKey>, PopError> {
        let (reply, response) = oneshot::channel();
        self.requests
            .send(JwksRequest {
                kid: kid.to_owned(),
                reply,
            })
            .map_err(|_| PopError::JwksUnavailable)?;
        response.await.map_err(|_| PopError::JwksUnavailable)?
    }
}

impl TokenVerifier for JwksTokenVerifier {
    fn verify<'a>(
        &'a self,
        token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<VerifiedClaims, PopError>> + Send + 'a>> {
        Box::pin(async move {
            let parsed = parse_compact_token(token)?;
            let key = self.key_for_kid(&parsed.header.kid).await?;
            verify_parsed_token(parsed, &key, &self.expected_audience, &self.clock)
        })
    }
}

async fn run_jwks_aggregator(
    mut receiver: mpsc::UnboundedReceiver<JwksRequest>,
    connector: TlsConnector,
    origin: JwksOrigin,
    timeouts: JwksTimeouts,
) {
    let mut cache = HashMap::new();
    let mut in_flight = None;
    let mut last_fetch_begin = None;
    let mut requests_closed = false;

    loop {
        if requests_closed && in_flight.is_none() {
            break;
        }
        let awaiting_fetch = in_flight.is_some();
        tokio::select! {
            request = receiver.recv(), if !requests_closed => match request {
                Some(request) => {
                    let now = tokio::time::Instant::now();
                    prune_jwks_cache(&mut cache, now);
                    if let Some(entry) = cache.get(&request.kid) {
                        let _ = request.reply.send(Ok(Arc::clone(&entry.key)));
                    } else if let Some(fetch) = in_flight.as_mut() {
                        fetch.waiters.push(request);
                    } else if last_fetch_begin.is_some_and(|started| {
                        now.checked_duration_since(started)
                            .is_some_and(|elapsed| elapsed < Duration::from_secs(5))
                    }) {
                        let _ = request.reply.send(Err(PopError::JwksKeyUnavailable));
                    } else {
                        last_fetch_begin = Some(now);
                        let completion = spawn_jwks_fetch(
                            connector.clone(),
                            origin.clone(),
                            timeouts,
                        );
                        in_flight = Some(InFlightFetch {
                            completion,
                            waiters: vec![request],
                        });
                    }
                }
                None => requests_closed = true,
            },
            result = receive_fetch_completion(&mut in_flight), if awaiting_fetch => {
                let Some(fetch) = in_flight.take() else {
                    continue;
                };
                match result {
                    Ok(keys) => {
                        let now = tokio::time::Instant::now();
                        prune_jwks_cache(&mut cache, now);
                        insert_jwks_keys(&mut cache, keys, now + JWKS_CACHE_TTL);
                        for request in fetch.waiters {
                            let result = cache
                                .get(&request.kid)
                                .map(|entry| Arc::clone(&entry.key))
                                .ok_or(PopError::JwksKeyUnavailable);
                            let _ = request.reply.send(result);
                        }
                    }
                    Err(_) => {
                        for request in fetch.waiters {
                            let _ = request.reply.send(Err(PopError::JwksUnavailable));
                        }
                    }
                }
            },
        }
    }
}

fn spawn_jwks_fetch(
    connector: TlsConnector,
    origin: JwksOrigin,
    timeouts: JwksTimeouts,
) -> oneshot::Receiver<Result<HashMap<String, VerifyingKey>, PopError>> {
    let (sender, receiver) = oneshot::channel();
    tokio::spawn(async move {
        let _ = sender.send(fetch_jwks(connector, origin, timeouts).await);
    });
    receiver
}

async fn receive_fetch_completion(
    in_flight: &mut Option<InFlightFetch>,
) -> Result<HashMap<String, VerifyingKey>, PopError> {
    match in_flight {
        Some(fetch) => match (&mut fetch.completion).await {
            Ok(result) => result,
            Err(_) => Err(PopError::JwksUnavailable),
        },
        None => std::future::pending().await,
    }
}

fn prune_jwks_cache(cache: &mut HashMap<String, CachedJwk>, now: tokio::time::Instant) {
    cache.retain(|_, entry| entry.expires_at > now);
}

fn insert_jwks_keys(
    cache: &mut HashMap<String, CachedJwk>,
    keys: HashMap<String, VerifyingKey>,
    expires_at: tokio::time::Instant,
) {
    for (key_id, key) in keys {
        if !cache.contains_key(&key_id)
            && cache.len() >= JWKS_CACHE_LIMIT
            && let Some(evicted) = cache
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(key_id, _)| key_id.clone())
        {
            cache.remove(&evicted);
        }
        cache.insert(
            key_id,
            CachedJwk {
                key: Arc::new(key),
                expires_at,
            },
        );
    }
}

async fn fetch_jwks(
    connector: TlsConnector,
    origin: JwksOrigin,
    timeouts: JwksTimeouts,
) -> Result<HashMap<String, VerifyingKey>, PopError> {
    let tcp = tokio::time::timeout(
        timeouts.connect,
        TcpStream::connect((origin.host.as_str(), origin.port)),
    )
    .await
    .map_err(|_| PopError::JwksUnavailable)?
    .map_err(|_| PopError::JwksUnavailable)?;
    tokio::time::timeout(timeouts.fetch, fetch_jwks_over_tls(tcp, &origin, connector))
        .await
        .map_err(|_| PopError::JwksUnavailable)?
}

impl NonceCache {
    fn issue(&mut self, now: u64, expires_at: u64) -> Result<[u8; NONCE_BYTES], PopError> {
        self.issue_with(now, expires_at, || {
            let mut nonce = [0u8; NONCE_BYTES];
            getrandom::getrandom(&mut nonce).map_err(|_| PopError::Randomness)?;
            Ok(nonce)
        })
    }

    fn issue_with<F>(
        &mut self,
        now: u64,
        expires_at: u64,
        mut next_nonce: F,
    ) -> Result<[u8; NONCE_BYTES], PopError>
    where
        F: FnMut() -> Result<[u8; NONCE_BYTES], PopError>,
    {
        self.prune(now);
        if self.outstanding.len() >= OUTSTANDING_NONCE_LIMIT {
            return Err(PopError::NonceOutstandingCapacity);
        }
        for _ in 0..NONCE_GENERATION_ATTEMPTS {
            let nonce = next_nonce()?;
            if self.outstanding.contains_key(&nonce) || self.spent.contains_key(&nonce) {
                continue;
            }
            self.outstanding.insert(nonce, NonceEntry { expires_at });
            return Ok(nonce);
        }
        Err(PopError::NonceCollisionExhausted)
    }

    fn redeem(
        &mut self,
        nonce: [u8; NONCE_BYTES],
        expires_at: u64,
        now: u64,
    ) -> Result<(), PopError> {
        self.prune(now);
        let entry = self.outstanding.get(&nonce).ok_or(PopError::NonceReplay)?;
        if entry.expires_at != expires_at {
            return Err(PopError::NonceReplay);
        }
        if self.spent.len() >= SPENT_NONCE_LIMIT {
            return Err(PopError::NonceSpentCapacity);
        }
        let entry = self
            .outstanding
            .remove(&nonce)
            .ok_or(PopError::NonceReplay)?;
        self.spent.insert(nonce, entry);
        Ok(())
    }

    fn redeem_renewal(
        &mut self,
        nonce: [u8; NONCE_BYTES],
        check_expires_at: u64,
        retain_until: u64,
        now: u64,
    ) -> Result<(), PopError> {
        self.prune(now);
        let entry = self.outstanding.get(&nonce).ok_or(PopError::NonceReplay)?;
        if entry.expires_at != check_expires_at {
            return Err(PopError::NonceReplay);
        }
        if self.spent.len() >= SPENT_NONCE_LIMIT {
            return Err(PopError::NonceSpentCapacity);
        }
        self.outstanding
            .remove(&nonce)
            .ok_or(PopError::NonceReplay)?;
        self.spent.insert(
            nonce,
            NonceEntry {
                expires_at: retain_until,
            },
        );
        Ok(())
    }

    fn prune(&mut self, now: u64) {
        self.outstanding.retain(|_, entry| entry.expires_at > now);
        self.spent.retain(|_, entry| entry.expires_at > now);
    }
}

impl NonceLease {
    fn issue(cache: Arc<Mutex<NonceCache>>, now: u64, expires_at: u64) -> Result<Self, PopError> {
        let nonce = lock_nonce_cache(&cache).issue(now, expires_at)?;
        Ok(Self {
            cache,
            nonce,
            armed: true,
        })
    }

    fn bytes(&self) -> &[u8; NONCE_BYTES] {
        &self.nonce
    }

    fn redeem(&mut self, expires_at: u64, now: u64) -> Result<(), PopError> {
        if !self.armed {
            return Err(PopError::NonceReplay);
        }
        lock_nonce_cache(&self.cache).redeem(self.nonce, expires_at, now)?;
        self.armed = false;
        Ok(())
    }

    fn redeem_and_extend(
        &mut self,
        check_expires_at: u64,
        retain_until: u64,
        now: u64,
    ) -> Result<(), PopError> {
        if !self.armed {
            return Err(PopError::NonceReplay);
        }
        lock_nonce_cache(&self.cache).redeem_renewal(
            self.nonce,
            check_expires_at,
            retain_until,
            now,
        )?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for NonceLease {
    fn drop(&mut self) {
        if self.armed {
            lock_nonce_cache(&self.cache)
                .outstanding
                .remove(&self.nonce);
        }
    }
}

fn lock_nonce_cache(cache: &Mutex<NonceCache>) -> MutexGuard<'_, NonceCache> {
    match cache.lock() {
        Ok(cache) => cache,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn default_jwks_root_store() -> RootCertStore {
    #[expect(
        clippy::from_iter_instead_of_collect,
        reason = "the explicit root-store type mirrors the transport TLS configuration"
    )]
    RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())
}

fn parse_compact_token(token: &str) -> Result<ParsedToken, PopError> {
    if !token.is_ascii() {
        return Err(PopError::TokenRejected);
    }
    let mut segments = token.split('.');
    let Some(header_b64) = segments.next().filter(|segment| !segment.is_empty()) else {
        return Err(PopError::TokenRejected);
    };
    let Some(claims_b64) = segments.next().filter(|segment| !segment.is_empty()) else {
        return Err(PopError::TokenRejected);
    };
    let Some(signature_b64) = segments.next().filter(|segment| !segment.is_empty()) else {
        return Err(PopError::TokenRejected);
    };
    if segments.next().is_some() {
        return Err(PopError::TokenRejected);
    }

    let header = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| PopError::TokenRejected)?;
    let claims = URL_SAFE_NO_PAD
        .decode(claims_b64)
        .map_err(|_| PopError::TokenRejected)?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|_| PopError::TokenRejected)?;
    let header = serde_json::from_slice(&header).map_err(|_| PopError::TokenRejected)?;
    let claims = serde_json::from_slice(&claims).map_err(|_| PopError::TokenRejected)?;
    let signature = Signature::from_slice(&signature).map_err(|_| PopError::TokenRejected)?;
    Ok(ParsedToken {
        header,
        claims,
        signature,
        signing_input: format!("{header_b64}.{claims_b64}").into_bytes(),
    })
}

fn verify_parsed_token(
    parsed: ParsedToken,
    key: &VerifyingKey,
    expected_audience: &str,
    clock: &ClockFn,
) -> Result<VerifiedClaims, PopError> {
    if parsed.header.alg != "EdDSA" || parsed.header.typ != "JWT" || parsed.header.kid.is_empty() {
        return Err(PopError::TokenRejected);
    }
    key.verify_strict(&parsed.signing_input, &parsed.signature)
        .map_err(|_| PopError::TokenRejected)?;
    validate_token_claims(parsed.claims, expected_audience, clock)
}

fn validate_token_claims(
    claims: RawClaims,
    expected_audience: &str,
    clock: &ClockFn,
) -> Result<VerifiedClaims, PopError> {
    if claims.iss != EXPECTED_ISSUER || claims.aud != expected_audience {
        return Err(PopError::TokenRejected);
    }
    let instance_id = claims
        .sub
        .strip_prefix("home:")
        .filter(|instance_id| !instance_id.is_empty())
        .ok_or(PopError::TokenRejected)?
        .to_owned();
    if claims.iat > claims.exp {
        return Err(PopError::TokenRejected);
    }
    let ttl = claims.exp - claims.iat;
    if !(600..=900).contains(&ttl) {
        return Err(PopError::TokenRejected);
    }
    let now = clock();
    if claims.iat > now.saturating_add(POP_SKEW) || now >= claims.exp {
        return Err(PopError::TokenRejected);
    }
    if !valid_hostname(&claims.hostname) {
        return Err(PopError::TokenRejected);
    }
    if claims.cnf.jwk.kty != "OKP" || claims.cnf.jwk.crv != "Ed25519" {
        return Err(PopError::TokenRejected);
    }
    let public_key = URL_SAFE_NO_PAD
        .decode(claims.cnf.jwk.x)
        .map_err(|_| PopError::TokenRejected)?;
    let public_key: [u8; 32] = public_key.try_into().map_err(|_| PopError::TokenRejected)?;
    let pop_key = VerifyingKey::from_bytes(&public_key).map_err(|_| PopError::TokenRejected)?;
    Ok(VerifiedClaims {
        instance_id,
        hostname: claims.hostname,
        expires_at: claims.exp,
        pop_key,
    })
}

pub(crate) fn valid_hostname(hostname: &str) -> bool {
    let Some(label) = hostname.strip_suffix(".solstone.me") else {
        return false;
    };
    label.len() == 8
        && label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || matches!(byte, b'2'..=b'7'))
}

fn validate_registration_hostname(claims: &VerifiedClaims, hostname: &str) -> Result<(), PopError> {
    if claims.hostname() != hostname {
        return Err(PopError::HostnameMismatch);
    }
    Ok(())
}

fn unix_seconds() -> Result<u64, PopError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PopError::TokenTimeInvalid)?
        .as_secs())
}

fn challenge_timestamp_is_fresh(issued_at: i64, verified_at: i64) -> bool {
    issued_at.abs_diff(verified_at) <= POP_SKEW
}

fn proof_message(nonce: &[u8; NONCE_BYTES], bridge_id: &str, timestamp: i64) -> Vec<u8> {
    // Fixed nonce and timestamp widths leave bridge_id as the unique middle span.
    let mut message = Vec::with_capacity(NONCE_BYTES + bridge_id.len() + 8);
    message.extend_from_slice(nonce);
    message.extend_from_slice(bridge_id.as_bytes());
    message.extend_from_slice(&timestamp.to_be_bytes());
    message
}

fn decode_signature(encoded: &str) -> Result<Signature, PopError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| PopError::InvalidProof)?;
    Signature::from_slice(&bytes).map_err(|_| PopError::InvalidProof)
}

async fn read_message<S, T>(carrier: &mut S) -> Result<T, PopError>
where
    S: AsyncRead + Unpin,
    T: for<'a> Deserialize<'a>,
{
    let length = carrier
        .read_u32()
        .await
        .map_err(|_| PopError::Io)?
        .try_into()
        .map_err(|_| PopError::MessageTooLarge)?;
    if length > MAX_MESSAGE_BYTES {
        return Err(PopError::MessageTooLarge);
    }
    let mut bytes = vec![0u8; length];
    carrier
        .read_exact(&mut bytes)
        .await
        .map_err(|_| PopError::Io)?;
    serde_json::from_slice(&bytes).map_err(|_| PopError::InvalidMessage)
}

async fn read_renewal_body<S>(carrier: &mut S) -> Result<Vec<u8>, PopError>
where
    S: AsyncRead + Unpin,
{
    let length = carrier
        .read_u32()
        .await
        .map_err(|_| PopError::Io)?
        .try_into()
        .map_err(|_| PopError::MessageTooLarge)?;
    if length > MAX_MESSAGE_BYTES {
        return Err(PopError::MessageTooLarge);
    }
    let mut bytes = vec![0u8; length];
    carrier
        .read_exact(&mut bytes)
        .await
        .map_err(|_| PopError::Io)?;
    Ok(bytes)
}

async fn write_message<S, T>(carrier: &mut S, message: &T) -> Result<(), PopError>
where
    S: AsyncWrite + Unpin,
    T: Serialize,
{
    let bytes = serde_json::to_vec(message).map_err(|_| PopError::InvalidMessage)?;
    let length = u32::try_from(bytes.len()).map_err(|_| PopError::MessageTooLarge)?;
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(PopError::MessageTooLarge);
    }
    carrier.write_u32(length).await.map_err(|_| PopError::Io)?;
    carrier.write_all(&bytes).await.map_err(|_| PopError::Io)?;
    carrier.flush().await.map_err(|_| PopError::Io)
}

fn parse_jwks_url(url: &str) -> Result<JwksOrigin, PopError> {
    let rest = url.strip_prefix("https://").ok_or(PopError::JwksUrl)?;
    let (authority, path_and_query) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    if authority.is_empty() || path_and_query.contains('#') {
        return Err(PopError::JwksUrl);
    }
    let (host, port) = parse_authority(authority)?;
    Ok(JwksOrigin {
        host,
        port,
        authority: authority.to_owned(),
        path_and_query: path_and_query.to_owned(),
    })
}

fn parse_authority(authority: &str) -> Result<(String, u16), PopError> {
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']').ok_or(PopError::JwksUrl)?;
        let host = rest[..end].to_owned();
        let after = &rest[end + 1..];
        let port = if let Some(port) = after.strip_prefix(':') {
            parse_port(port)?
        } else if after.is_empty() {
            443
        } else {
            return Err(PopError::JwksUrl);
        };
        return Ok((host, port));
    }

    match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && !host.is_empty() => {
            Ok((host.to_owned(), parse_port(port)?))
        }
        None if !authority.is_empty() => Ok((authority.to_owned(), 443)),
        _ => Err(PopError::JwksUrl),
    }
}

fn parse_port(port: &str) -> Result<u16, PopError> {
    let port = port.parse::<u16>().map_err(|_| PopError::JwksUrl)?;
    if port == 0 {
        Err(PopError::JwksUrl)
    } else {
        Ok(port)
    }
}

async fn fetch_jwks_over_tls(
    tcp: TcpStream,
    origin: &JwksOrigin,
    connector: TlsConnector,
) -> Result<HashMap<String, VerifyingKey>, PopError> {
    let server_name = ServerName::try_from(origin.host.clone()).map_err(|_| PopError::JwksUrl)?;
    let mut stream = connector
        .connect(server_name, tcp)
        .await
        .map_err(|_| PopError::JwksUnavailable)?;
    let request = format!(
        "GET {} HTTP/1.1\r\nhost: {}\r\naccept: application/json\r\nconnection: close\r\n\r\n",
        origin.path_and_query, origin.authority
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|_| PopError::JwksUnavailable)?;
    stream
        .flush()
        .await
        .map_err(|_| PopError::JwksUnavailable)?;
    let body = read_http_response(&mut stream).await?;
    let document: JwksDocument =
        serde_json::from_slice(&body).map_err(|_| PopError::JwksUnavailable)?;
    let mut keys = HashMap::new();
    for jwk in document.keys {
        if jwk.kty != "OKP"
            || jwk.crv != "Ed25519"
            || jwk.alg.as_deref() != Some("EdDSA")
            || jwk.kid.is_empty()
        {
            continue;
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(jwk.x)
            .map_err(|_| PopError::JwksUnavailable)?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| PopError::JwksUnavailable)?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| PopError::JwksUnavailable)?;
        keys.insert(jwk.kid, key);
    }
    Ok(keys)
}

async fn read_http_response<S>(stream: &mut S) -> Result<Vec<u8>, PopError>
where
    S: AsyncRead + Unpin,
{
    let mut response = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let read = stream
            .read(&mut buffer)
            .await
            .map_err(|_| PopError::JwksUnavailable)?;
        if read == 0 {
            return Err(PopError::JwksUnavailable);
        }
        response.extend_from_slice(&buffer[..read]);
        if response.len() > MAX_JWKS_RESPONSE_BYTES {
            return Err(PopError::JwksUnavailable);
        }
        if let Some(body_start) = response.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            let body_start = body_start + 4;
            let content_length = parse_http_head(&response[..body_start])?;
            let body_end = body_start
                .checked_add(content_length)
                .ok_or(PopError::JwksUnavailable)?;
            if body_end > MAX_JWKS_RESPONSE_BYTES || response.len() > body_end {
                return Err(PopError::JwksUnavailable);
            }
            if response.len() == body_end {
                return Ok(response[body_start..].to_vec());
            }
        }
    }
}

fn parse_http_head(head: &[u8]) -> Result<usize, PopError> {
    let head = std::str::from_utf8(head).map_err(|_| PopError::JwksUnavailable)?;
    let mut lines = head.split("\r\n");
    let status = lines.next().ok_or(PopError::JwksUnavailable)?;
    if !status.starts_with("HTTP/1.1 200 ") && !status.starts_with("HTTP/1.0 200 ") {
        return Err(PopError::JwksUnavailable);
    }
    let mut content_length = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(PopError::JwksUnavailable);
            }
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| PopError::JwksUnavailable)?,
            );
        }
    }
    content_length.ok_or(PopError::JwksUnavailable)
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "tests use fixed fixture keys and in-memory carriers"
    )]

    use std::time::Duration;

    use super::*;

    const ISSUER_KEY: [u8; 32] = [7; 32];
    const POP_KEY: [u8; 32] = [8; 32];
    const WRONG_POP_KEY: [u8; 32] = [9; 32];
    const BRIDGE_ID: &str = "mcp-bridge-test";
    const INSTANCE_ID: &str = "8488ae64-b592-80a3-97c6-490e995daa85";
    const HOSTNAME: &str = "aaaqeaye.solstone.me";

    fn fixture() -> (FixtureTokenVerifier, SigningKey) {
        let issuer = SigningKey::from_bytes(&ISSUER_KEY);
        let pop = SigningKey::from_bytes(&POP_KEY);
        (
            FixtureTokenVerifier::new(
                HashMap::from([(String::from("fixture"), issuer)]),
                String::from(BRIDGE_ID),
            ),
            pop,
        )
    }

    fn mint_token(
        fixture: &FixtureTokenVerifier,
        pop: &SigningKey,
        issued_at: u64,
        expires_at: u64,
    ) -> String {
        fixture
            .mint(
                "fixture",
                INSTANCE_ID,
                HOSTNAME,
                issued_at,
                expires_at,
                &pop.verifying_key(),
            )
            .unwrap()
    }

    async fn send_request<S>(client: &mut S, token: String) -> Result<Challenge, PopError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        write_message(
            client,
            &RegistrationRequest {
                token,
                hostname: String::from(HOSTNAME),
            },
        )
        .await?;
        read_message(client).await
    }

    fn response(challenge: &Challenge, signing: &SigningKey) -> ChallengeResponse {
        let nonce: [u8; NONCE_BYTES] = URL_SAFE_NO_PAD
            .decode(&challenge.nonce)
            .unwrap()
            .try_into()
            .unwrap();
        let signature = signing.sign(&proof_message(
            &nonce,
            &challenge.bridge_id,
            challenge.timestamp,
        ));
        ChallengeResponse {
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        }
    }

    fn renewal_response(
        challenge: &Challenge,
        signing: &SigningKey,
        token: String,
        hostname: &str,
    ) -> RenewalResponse {
        let signature = response(challenge, signing).signature;
        RenewalResponse {
            token,
            hostname: String::from(hostname),
            signature,
        }
    }

    async fn assert_framed_message_rejected<T>(body: &str)
    where
        T: for<'a> Deserialize<'a>,
    {
        let (mut client, mut server) = tokio::io::duplex(4096);
        client
            .write_u32(body.len().try_into().unwrap())
            .await
            .unwrap();
        client.write_all(body.as_bytes()).await.unwrap();
        client.flush().await.unwrap();
        assert!(matches!(
            read_message::<_, T>(&mut server).await,
            Err(PopError::InvalidMessage)
        ));
    }

    fn nonce_from_index(index: usize) -> [u8; NONCE_BYTES] {
        let mut nonce = [0u8; NONCE_BYTES];
        nonce[..2].copy_from_slice(&(index as u16).to_be_bytes());
        nonce
    }

    fn nonce_cache() -> NonceCache {
        NonceCache {
            outstanding: HashMap::new(),
            spent: HashMap::new(),
        }
    }

    fn strict_fixture(now: u64) -> FixtureTokenVerifier {
        let signing_keys = (1u8..=48)
            .map(|index| {
                (
                    format!("twin-{index}"),
                    SigningKey::from_bytes(&[index; 32]),
                )
            })
            .collect();
        FixtureTokenVerifier::with_clock(
            signing_keys,
            String::from(BRIDGE_ID),
            Arc::new(move || now),
        )
    }

    fn raw_header(kid: &str) -> serde_json::Value {
        serde_json::json!({"alg": "EdDSA", "typ": "JWT", "kid": kid})
    }

    fn raw_claims(pop_key: &VerifyingKey, issued_at: u64, expires_at: u64) -> serde_json::Value {
        serde_json::json!({
            "iss": EXPECTED_ISSUER,
            "sub": format!("home:{INSTANCE_ID}"),
            "aud": BRIDGE_ID,
            "iat": issued_at,
            "exp": expires_at,
            "hostname": HOSTNAME,
            "cnf": {
                "jwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": URL_SAFE_NO_PAD.encode(pop_key.to_bytes()),
                }
            }
        })
    }

    async fn assert_token_rejected(verifier: &FixtureTokenVerifier, token: String) {
        assert!(matches!(
            verifier.verify(&token).await,
            Err(PopError::TokenRejected)
        ));
    }

    fn replace_segment(token: &str, index: usize, replacement: String) -> String {
        let mut segments: Vec<_> = token.split('.').map(ToOwned::to_owned).collect();
        segments[index] = replacement;
        segments.join(".")
    }

    fn noncanonical_base64url(encoded: &str) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

        let mut bytes = encoded.as_bytes().to_vec();
        let last = bytes.last_mut().unwrap();
        let value = ALPHABET.iter().position(|symbol| symbol == last).unwrap();
        *last = ALPHABET[value | 1];
        String::from_utf8(bytes).unwrap()
    }

    #[tokio::test]
    async fn valid_token_and_matching_proof_succeeds() {
        let (verifier, pop) = fixture();
        let now = unix_seconds().unwrap();
        let token = mint_token(&verifier, &pop, now, now + 600);
        let authenticator = PopAuthenticator::new(Arc::new(verifier), String::from(BRIDGE_ID));
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task =
            tokio::spawn(async move { authenticator.authenticate(&mut server).await });

        let challenge = send_request(&mut client, token).await.unwrap();
        write_message(&mut client, &response(&challenge, &pop))
            .await
            .unwrap();
        let registration = server_task.await.unwrap().unwrap();
        assert_eq!(registration.hostname(), HOSTNAME);
    }

    #[tokio::test]
    async fn acceptance_criterion_renewal_2_binds_e1_and_extends_to_e2() {
        let (verifier, pop) = fixture();
        let now = unix_seconds().unwrap();
        let e1 = now + 600;
        let e2 = now + 900;
        let token = mint_token(&verifier, &pop, now, e2);
        let authenticator = PopAuthenticator::new(Arc::new(verifier), String::from(BRIDGE_ID));
        let identity = RenewalIdentity::new(
            String::from(HOSTNAME),
            String::from(INSTANCE_ID),
            pop.verifying_key(),
        );
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task =
            tokio::spawn(async move { authenticator.renew(&mut server, &identity, e1).await });

        let challenge: Challenge = read_message(&mut client).await.unwrap();
        write_message(
            &mut client,
            &renewal_response(&challenge, &pop, token, HOSTNAME),
        )
        .await
        .unwrap();
        assert_eq!(server_task.await.unwrap().unwrap(), e2);
    }

    #[tokio::test]
    async fn acceptance_criterion_renewal_2_accepts_a_short_successor_lease() {
        let (verifier, pop) = fixture();
        let now = unix_seconds().unwrap();
        let e1 = now + 4;
        let e2 = now + 16;
        let token = mint_token(&verifier, &pop, e2 - 700, e2);
        let authenticator = PopAuthenticator::new(Arc::new(verifier), String::from(BRIDGE_ID));
        let identity = RenewalIdentity::new(
            String::from(HOSTNAME),
            String::from(INSTANCE_ID),
            pop.verifying_key(),
        );
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task =
            tokio::spawn(async move { authenticator.renew(&mut server, &identity, e1).await });

        let challenge: Challenge = read_message(&mut client).await.unwrap();
        write_message(
            &mut client,
            &renewal_response(&challenge, &pop, token, HOSTNAME),
        )
        .await
        .unwrap();
        assert_eq!(server_task.await.unwrap().unwrap(), e2);
    }

    #[tokio::test]
    async fn acceptance_criterion_renewal_7_complete_invalid_response_is_retryable() {
        let (verifier, pop) = fixture();
        let now = unix_seconds().unwrap();
        let authenticator = PopAuthenticator::new(Arc::new(verifier), String::from(BRIDGE_ID));
        let identity = RenewalIdentity::new(
            String::from(HOSTNAME),
            String::from(INSTANCE_ID),
            pop.verifying_key(),
        );
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task =
            tokio::spawn(
                async move { authenticator.renew(&mut server, &identity, now + 600).await },
            );

        let _: Challenge = read_message(&mut client).await.unwrap();
        client.write_u32(1).await.unwrap();
        client.write_all(b"{").await.unwrap();
        client.flush().await.unwrap();
        assert!(matches!(
            server_task.await.unwrap(),
            Err(RenewalError::Retryable(PopError::InvalidMessage))
        ));
    }

    #[tokio::test]
    async fn acceptance_criterion_renewal_11_wire_mutations_are_retryable_after_a_complete_frame() {
        for body in [
            r#"{"token":"first","token":"second","hostname":"journal.test","signature":"x"}"#,
            r#"{"token":"token","hostname":"journal.test","signature":"x","extra":true}"#,
        ] {
            let (verifier, pop) = fixture();
            let now = unix_seconds().unwrap();
            let authenticator = PopAuthenticator::new(Arc::new(verifier), String::from(BRIDGE_ID));
            let identity = RenewalIdentity::new(
                String::from(HOSTNAME),
                String::from(INSTANCE_ID),
                pop.verifying_key(),
            );
            let (mut client, mut server) = tokio::io::duplex(4096);
            let server_task = tokio::spawn(async move {
                authenticator.renew(&mut server, &identity, now + 600).await
            });

            let _: Challenge = read_message(&mut client).await.unwrap();
            client
                .write_u32(body.len().try_into().unwrap())
                .await
                .unwrap();
            client.write_all(body.as_bytes()).await.unwrap();
            client.flush().await.unwrap();
            assert!(matches!(
                server_task.await.unwrap(),
                Err(RenewalError::Retryable(PopError::InvalidMessage))
            ));
        }
    }

    #[tokio::test]
    async fn acceptance_criterion_renewal_7_partial_response_is_terminal() {
        let (verifier, pop) = fixture();
        let now = unix_seconds().unwrap();
        let authenticator = PopAuthenticator::new(Arc::new(verifier), String::from(BRIDGE_ID));
        let identity = RenewalIdentity::new(
            String::from(HOSTNAME),
            String::from(INSTANCE_ID),
            pop.verifying_key(),
        );
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task =
            tokio::spawn(
                async move { authenticator.renew(&mut server, &identity, now + 600).await },
            );

        let _: Challenge = read_message(&mut client).await.unwrap();
        client.write_u32(16).await.unwrap();
        client.write_all(b"partial").await.unwrap();
        client.shutdown().await.unwrap();
        assert!(matches!(
            server_task.await.unwrap(),
            Err(RenewalError::Terminal)
        ));
    }

    #[tokio::test]
    async fn acceptance_criterion_renewal_5_wrong_successor_key_releases_the_unspent_nonce() {
        let (verifier, pop) = fixture();
        let wrong_pop = SigningKey::from_bytes(&WRONG_POP_KEY);
        let now = unix_seconds().unwrap();
        let e1 = now + 600;
        let e2 = now + 900;
        let token = mint_token(&verifier, &wrong_pop, now, e2);
        let authenticator = PopAuthenticator::new(Arc::new(verifier), String::from(BRIDGE_ID));
        let identity = RenewalIdentity::new(
            String::from(HOSTNAME),
            String::from(INSTANCE_ID),
            pop.verifying_key(),
        );
        let cache = Arc::clone(&authenticator.nonces);
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task =
            tokio::spawn(async move { authenticator.renew(&mut server, &identity, e1).await });

        let challenge: Challenge = read_message(&mut client).await.unwrap();
        write_message(
            &mut client,
            &renewal_response(&challenge, &wrong_pop, token, HOSTNAME),
        )
        .await
        .unwrap();

        assert!(matches!(
            server_task.await.unwrap(),
            Err(RenewalError::Retryable(PopError::InvalidProof))
        ));
        let cache = lock_nonce_cache(&cache);
        assert!(cache.outstanding.is_empty());
        assert!(cache.spent.is_empty());
    }

    #[tokio::test]
    async fn acceptance_criterion_renewal_5_identity_mismatch_spends_through_e2() {
        let (verifier, pop) = fixture();
        let now = unix_seconds().unwrap();
        let e1 = now + 600;
        let e2 = now + 900;
        let token = mint_token(&verifier, &pop, now, e2);
        let authenticator = PopAuthenticator::new(Arc::new(verifier), String::from(BRIDGE_ID));
        let identity = RenewalIdentity::new(
            String::from(HOSTNAME),
            String::from(INSTANCE_ID),
            pop.verifying_key(),
        );
        let cache = Arc::clone(&authenticator.nonces);
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task =
            tokio::spawn(async move { authenticator.renew(&mut server, &identity, e1).await });

        let challenge: Challenge = read_message(&mut client).await.unwrap();
        write_message(
            &mut client,
            &renewal_response(&challenge, &pop, token, "other.solstone.me"),
        )
        .await
        .unwrap();

        assert!(matches!(
            server_task.await.unwrap(),
            Err(RenewalError::Retryable(PopError::TokenRejected))
        ));
        let mut cache = lock_nonce_cache(&cache);
        assert!(cache.outstanding.is_empty());
        assert_eq!(cache.spent.len(), 1);
        cache.prune(e2 - 1);
        assert_eq!(cache.spent.len(), 1);
        cache.prune(e2);
        assert!(cache.spent.is_empty());
    }

    #[tokio::test]
    async fn acceptance_criterion_renewal_5_jwt_claim_hostname_mismatch_spends_through_e2() {
        let (verifier, pop) = fixture();
        let now = unix_seconds().unwrap();
        let e1 = now + 600;
        let e2 = now + 900;
        let token = verifier
            .mint(
                "fixture",
                INSTANCE_ID,
                "bbbbbbbb.solstone.me",
                now,
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
        let cache = Arc::clone(&authenticator.nonces);
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task =
            tokio::spawn(async move { authenticator.renew(&mut server, &identity, e1).await });

        let challenge: Challenge = read_message(&mut client).await.unwrap();
        write_message(
            &mut client,
            &renewal_response(&challenge, &pop, token, "bbbbbbbb.solstone.me"),
        )
        .await
        .unwrap();

        assert!(matches!(
            server_task.await.unwrap(),
            Err(RenewalError::Retryable(PopError::TokenRejected))
        ));
        let mut cache = lock_nonce_cache(&cache);
        assert!(cache.outstanding.is_empty());
        assert_eq!(cache.spent.len(), 1);
        cache.prune(e2 - 1);
        assert_eq!(cache.spent.len(), 1);
        cache.prune(e2);
        assert!(cache.spent.is_empty());
    }

    #[test]
    fn acceptance_criterion_renewal_5_spent_capacity_keeps_the_outstanding_nonce() {
        let now = 10;
        let e1 = 100;
        let e2 = 200;
        let mut cache = nonce_cache();
        for index in 0..SPENT_NONCE_LIMIT {
            cache
                .spent
                .insert(nonce_from_index(index), NonceEntry { expires_at: e2 });
        }
        let nonce = [0xFF; NONCE_BYTES];
        cache.issue_with(now, e1, || Ok(nonce)).unwrap();

        assert!(matches!(
            cache.redeem_renewal(nonce, e1, e2, now),
            Err(PopError::NonceSpentCapacity)
        ));
        assert!(cache.outstanding.contains_key(&nonce));
        assert_eq!(cache.outstanding.len(), 1);
        assert_eq!(cache.spent.len(), SPENT_NONCE_LIMIT);
    }

    #[tokio::test]
    async fn acceptance_criterion_renewal_7_prefix_body_oversize_and_eof_are_terminal() {
        enum BrokenResponse {
            Prefix,
            Body,
            Oversize,
            Eof,
        }

        for broken in [
            BrokenResponse::Prefix,
            BrokenResponse::Body,
            BrokenResponse::Oversize,
            BrokenResponse::Eof,
        ] {
            let (verifier, pop) = fixture();
            let now = unix_seconds().unwrap();
            let authenticator = PopAuthenticator::new(Arc::new(verifier), String::from(BRIDGE_ID));
            let identity = RenewalIdentity::new(
                String::from(HOSTNAME),
                String::from(INSTANCE_ID),
                pop.verifying_key(),
            );
            let (mut client, mut server) = tokio::io::duplex(4096);
            let server_task = tokio::spawn(async move {
                authenticator.renew(&mut server, &identity, now + 600).await
            });

            let _: Challenge = read_message(&mut client).await.unwrap();
            match broken {
                BrokenResponse::Prefix => client.write_all(&[0, 0]).await.unwrap(),
                BrokenResponse::Body => {
                    client.write_u32(8).await.unwrap();
                    client.write_all(b"short").await.unwrap();
                }
                BrokenResponse::Oversize => {
                    client
                        .write_u32((MAX_MESSAGE_BYTES as u32) + 1)
                        .await
                        .unwrap();
                }
                BrokenResponse::Eof => {}
            }
            client.shutdown().await.unwrap();
            assert!(matches!(
                server_task.await.unwrap(),
                Err(RenewalError::Terminal)
            ));
        }
    }

    #[tokio::test]
    async fn acceptance_criterion_1_rejects_duplicate_and_unknown_wire_fields() {
        for body in [
            r#"{"token":"first","token":"second","hostname":"journal.test"}"#,
            r#"{"token":"token","hostname":"journal.test","extra":true}"#,
            "{",
        ] {
            assert_framed_message_rejected::<RegistrationRequest>(body).await;
        }
        for body in [
            r#"{"nonce":"AAECAwQFBgcICQoLDA0ODw","nonce":"AAECAwQFBgcICQoLDA0ODw","bridge_id":"bridge","timestamp":1}"#,
            r#"{"nonce":"AAECAwQFBgcICQoLDA0ODw","bridge_id":"bridge","timestamp":1,"extra":true}"#,
        ] {
            assert_framed_message_rejected::<Challenge>(body).await;
        }
        for body in [
            r#"{"signature":"first","signature":"second"}"#,
            r#"{"signature":"signature","timestamp":1}"#,
        ] {
            assert_framed_message_rejected::<ChallengeResponse>(body).await;
        }
    }

    #[tokio::test]
    async fn acceptance_criterion_1_rejects_oversize_frames_before_body_allocation() {
        let (mut client, mut server) = tokio::io::duplex(16);
        client.write_u32(65_537).await.unwrap();
        client.flush().await.unwrap();
        assert!(matches!(
            read_message::<_, RegistrationRequest>(&mut server).await,
            Err(PopError::MessageTooLarge)
        ));
    }

    #[test]
    fn acceptance_criterion_1_fixed_wire_fixture_binds_exact_proof_bytes() {
        const CHALLENGE_FRAME: &[u8] = b"\0\0\0\x5b{\"nonce\":\"AAECAwQFBgcICQoLDA0ODw\",\"bridge_id\":\"bridge:alpha\",\"timestamp\":72623859790382856}";
        const NONCE: [u8; NONCE_BYTES] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        const TIMESTAMP: i64 = 72_623_859_790_382_856;
        const EXPECTED_PROOF: &[u8] = b"\0\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0fbridge:alpha\x01\x02\x03\x04\x05\x06\x07\x08";

        assert_eq!(URL_SAFE_NO_PAD.encode(NONCE), "AAECAwQFBgcICQoLDA0ODw");
        assert_eq!(&CHALLENGE_FRAME[..4], &[0, 0, 0, 91]);
        assert_eq!(CHALLENGE_FRAME.len(), 95);
        assert_eq!(&CHALLENGE_FRAME[4..], b"{\"nonce\":\"AAECAwQFBgcICQoLDA0ODw\",\"bridge_id\":\"bridge:alpha\",\"timestamp\":72623859790382856}");
        assert_eq!(
            proof_message(&NONCE, "bridge:alpha", TIMESTAMP),
            EXPECTED_PROOF
        );

        let signing = SigningKey::from_bytes(&POP_KEY);
        let signature = signing.sign(EXPECTED_PROOF);
        signing
            .verifying_key()
            .verify_strict(EXPECTED_PROOF, &signature)
            .unwrap();
        assert!(signing
            .verifying_key()
            .verify_strict(b"spl-bridge-pop-v1\0\0\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0fbridge:alpha\x01\x02\x03\x04\x05\x06\x07\x08", &signature)
            .is_err());
    }

    #[tokio::test]
    async fn invalid_token_is_rejected_before_a_challenge_is_issued() {
        let (fixture, pop) = fixture();
        let now = unix_seconds().unwrap();
        let mut token = mint_token(&fixture, &pop, now, now + 600);
        token.push('x');
        let authenticator = PopAuthenticator::new(Arc::new(fixture), String::from(BRIDGE_ID));
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task =
            tokio::spawn(async move { authenticator.authenticate(&mut server).await });

        write_message(
            &mut client,
            &RegistrationRequest {
                token,
                hostname: String::from(HOSTNAME),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            server_task.await.unwrap(),
            Err(PopError::TokenRejected)
        ));
        let mut byte = [0u8; 1];
        assert_eq!(client.read(&mut byte).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn proof_with_the_wrong_ed25519_key_is_rejected() {
        let (verifier, pop) = fixture();
        let now = unix_seconds().unwrap();
        let token = mint_token(&verifier, &pop, now, now + 600);
        let authenticator = PopAuthenticator::new(Arc::new(verifier), String::from(BRIDGE_ID));
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task =
            tokio::spawn(async move { authenticator.authenticate(&mut server).await });

        let challenge = send_request(&mut client, token).await.unwrap();
        let wrong = SigningKey::from_bytes(&WRONG_POP_KEY);
        write_message(&mut client, &response(&challenge, &wrong))
            .await
            .unwrap();
        assert!(matches!(
            server_task.await.unwrap(),
            Err(PopError::InvalidProof)
        ));
    }

    #[tokio::test]
    async fn acceptance_criterion_2_rejects_wrong_bridge_and_old_prototype_proofs() {
        let (first_verifier, pop) = fixture();
        let now = unix_seconds().unwrap();
        let token = mint_token(&first_verifier, &pop, now, now + 600);
        let authenticator =
            PopAuthenticator::new(Arc::new(first_verifier), String::from(BRIDGE_ID));
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task =
            tokio::spawn(async move { authenticator.authenticate(&mut server).await });

        let challenge = send_request(&mut client, token).await.unwrap();
        let nonce: [u8; NONCE_BYTES] = URL_SAFE_NO_PAD
            .decode(&challenge.nonce)
            .unwrap()
            .try_into()
            .unwrap();
        let wrong_bridge = proof_message(&nonce, "other-bridge", challenge.timestamp);
        write_message(
            &mut client,
            &ChallengeResponse {
                signature: URL_SAFE_NO_PAD.encode(pop.sign(&wrong_bridge).to_bytes()),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            server_task.await.unwrap(),
            Err(PopError::InvalidProof)
        ));

        let (fixture, pop) = fixture();
        let now = unix_seconds().unwrap();
        let token = mint_token(&fixture, &pop, now, now + 600);
        let authenticator = PopAuthenticator::new(Arc::new(fixture), String::from(BRIDGE_ID));
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task =
            tokio::spawn(async move { authenticator.authenticate(&mut server).await });
        let challenge = send_request(&mut client, token).await.unwrap();
        let nonce: [u8; NONCE_BYTES] = URL_SAFE_NO_PAD
            .decode(&challenge.nonce)
            .unwrap()
            .try_into()
            .unwrap();
        let mut prototype = b"spl-bridge-pop-v1\0".to_vec();
        prototype.extend_from_slice(&nonce);
        prototype.extend_from_slice(&challenge.timestamp.to_be_bytes());
        write_message(
            &mut client,
            &ChallengeResponse {
                signature: URL_SAFE_NO_PAD.encode(pop.sign(&prototype).to_bytes()),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            server_task.await.unwrap(),
            Err(PopError::InvalidProof)
        ));
    }

    #[test]
    fn acceptance_criterion_2_rejects_stale_and_future_bridge_timestamps() {
        assert!(challenge_timestamp_is_fresh(1_000, 1_060));
        assert!(!challenge_timestamp_is_fresh(1_000, 1_061));
        assert!(!challenge_timestamp_is_fresh(1_061, 1_000));
    }

    #[tokio::test]
    async fn acceptance_criterion_2_rejects_a_32_byte_prototype_nonce_proof() {
        let (fixture, pop) = fixture();
        let now = unix_seconds().unwrap();
        let token = mint_token(&fixture, &pop, now, now + 600);
        let authenticator = PopAuthenticator::new(Arc::new(fixture), String::from(BRIDGE_ID));
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task =
            tokio::spawn(async move { authenticator.authenticate(&mut server).await });
        let challenge = send_request(&mut client, token).await.unwrap();
        let nonce: [u8; NONCE_BYTES] = URL_SAFE_NO_PAD
            .decode(&challenge.nonce)
            .unwrap()
            .try_into()
            .unwrap();
        let mut prototype = nonce.to_vec();
        prototype.extend_from_slice(&[0; NONCE_BYTES]);
        prototype.extend_from_slice(challenge.bridge_id.as_bytes());
        prototype.extend_from_slice(&challenge.timestamp.to_be_bytes());
        write_message(
            &mut client,
            &ChallengeResponse {
                signature: URL_SAFE_NO_PAD.encode(pop.sign(&prototype).to_bytes()),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            server_task.await.unwrap(),
            Err(PopError::InvalidProof)
        ));
    }

    #[tokio::test]
    async fn acceptance_criterion_2_rejects_wrong_hostname_and_old_response_shape() {
        let (first_verifier, pop) = fixture();
        let now = unix_seconds().unwrap();
        let token = mint_token(&first_verifier, &pop, now, now + 600);
        let authenticator =
            PopAuthenticator::new(Arc::new(first_verifier), String::from(BRIDGE_ID));
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task =
            tokio::spawn(async move { authenticator.authenticate(&mut server).await });
        write_message(
            &mut client,
            &RegistrationRequest {
                token,
                hostname: String::from("other.solstone.me"),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            server_task.await.unwrap(),
            Err(PopError::HostnameMismatch)
        ));

        let (fixture, pop) = fixture();
        let now = unix_seconds().unwrap();
        let token = mint_token(&fixture, &pop, now, now + 600);
        let authenticator = PopAuthenticator::new(Arc::new(fixture), String::from(BRIDGE_ID));
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task =
            tokio::spawn(async move { authenticator.authenticate(&mut server).await });
        let _challenge = send_request(&mut client, token).await.unwrap();
        client
            .write_all(b"\0\0\0\x1e{\"timestamp\":1,\"signature\":\"x\"}")
            .await
            .unwrap();
        client.flush().await.unwrap();
        assert!(matches!(
            server_task.await.unwrap(),
            Err(PopError::InvalidMessage)
        ));
    }

    #[test]
    fn replayed_nonce_is_rejected_within_its_token_lifetime() {
        let mut cache = nonce_cache();
        let nonce = [1; NONCE_BYTES];
        cache
            .outstanding
            .insert(nonce, NonceEntry { expires_at: 300 });
        cache.redeem(nonce, 300, 1).unwrap();
        assert!(matches!(
            cache.redeem(nonce, 300, 1),
            Err(PopError::NonceReplay)
        ));
    }

    #[test]
    fn renewal_redemption_checks_current_expiry_and_retains_through_successor_expiry() {
        let mut cache = nonce_cache();
        let nonce = [8; NONCE_BYTES];
        cache
            .outstanding
            .insert(nonce, NonceEntry { expires_at: 100 });
        cache.redeem_renewal(nonce, 100, 200, 1).unwrap();
        assert!(matches!(
            cache.redeem_renewal(nonce, 100, 200, 101),
            Err(PopError::NonceReplay)
        ));
        cache.prune(199);
        assert!(cache.spent.contains_key(&nonce));
        cache.prune(200);
        assert!(!cache.spent.contains_key(&nonce));
    }

    #[test]
    fn renewal_nonce_lease_releases_when_extension_fails() {
        let cache = Arc::new(Mutex::new(nonce_cache()));
        let mut lease = NonceLease::issue(Arc::clone(&cache), 1, 100).unwrap();
        let nonce = *lease.bytes();
        assert!(matches!(
            lease.redeem_and_extend(99, 200, 1),
            Err(PopError::NonceReplay)
        ));
        drop(lease);
        assert!(!lock_nonce_cache(&cache).outstanding.contains_key(&nonce));
    }

    #[test]
    fn acceptance_criterion_6_5_caps_outstanding_nonces_without_live_eviction() {
        let mut cache = nonce_cache();
        for index in 0..OUTSTANDING_NONCE_LIMIT {
            let nonce = nonce_from_index(index);
            assert_eq!(cache.issue_with(1, 100, || Ok(nonce)).unwrap(), nonce);
        }
        assert!(matches!(
            cache.issue_with(1, 100, || Ok([255; NONCE_BYTES])),
            Err(PopError::NonceOutstandingCapacity)
        ));
        assert_eq!(cache.outstanding.len(), OUTSTANDING_NONCE_LIMIT);
        assert!(cache.outstanding.contains_key(&nonce_from_index(42)));
    }

    #[test]
    fn acceptance_criterion_6_5_caps_spent_nonces_without_live_eviction() {
        let mut cache = nonce_cache();
        for index in 0..SPENT_NONCE_LIMIT {
            cache
                .spent
                .insert(nonce_from_index(index), NonceEntry { expires_at: 100 });
        }
        let nonce = [42; NONCE_BYTES];
        cache
            .outstanding
            .insert(nonce, NonceEntry { expires_at: 100 });
        assert!(matches!(
            cache.redeem(nonce, 100, 1),
            Err(PopError::NonceSpentCapacity)
        ));
        assert!(cache.outstanding.contains_key(&nonce));
        assert_eq!(cache.spent.len(), SPENT_NONCE_LIMIT);
        assert!(cache.spent.contains_key(&nonce_from_index(42)));
    }

    #[test]
    fn acceptance_criterion_6_5_prunes_exact_expiry_from_both_nonce_sets() {
        let mut cache = nonce_cache();
        let outstanding = [1; NONCE_BYTES];
        let spent = [2; NONCE_BYTES];
        cache
            .outstanding
            .insert(outstanding, NonceEntry { expires_at: 10 });
        cache.spent.insert(spent, NonceEntry { expires_at: 10 });
        cache.prune(9);
        assert!(cache.outstanding.contains_key(&outstanding));
        assert!(cache.spent.contains_key(&spent));
        cache.prune(10);
        assert!(!cache.outstanding.contains_key(&outstanding));
        assert!(!cache.spent.contains_key(&spent));
    }

    #[test]
    fn acceptance_criterion_6_5_bounds_collisions_and_never_reissues_spent_nonce() {
        let mut cache = nonce_cache();
        let spent = [5; NONCE_BYTES];
        cache
            .outstanding
            .insert(spent, NonceEntry { expires_at: 100 });
        cache.redeem(spent, 100, 1).unwrap();
        assert!(matches!(
            cache.issue_with(1, 100, || Ok(spent)),
            Err(PopError::NonceCollisionExhausted)
        ));
        let mut attempts = 0;
        let fresh = [6; NONCE_BYTES];
        assert_eq!(
            cache
                .issue_with(1, 100, || {
                    attempts += 1;
                    Ok(if attempts == 1 { spent } else { fresh })
                })
                .unwrap(),
            fresh
        );
        assert!(cache.spent.contains_key(&spent));
        assert!(cache.outstanding.contains_key(&fresh));
    }

    #[test]
    fn acceptance_criterion_6_5_nonce_lease_releases_on_early_drop() {
        let cache = Arc::new(Mutex::new(nonce_cache()));
        let lease = NonceLease::issue(Arc::clone(&cache), 1, 100).unwrap();
        let issued = *lease.bytes();
        assert!(lock_nonce_cache(&cache).outstanding.contains_key(&issued));
        drop(lease);
        assert!(!lock_nonce_cache(&cache).outstanding.contains_key(&issued));
        let replacement = [7; NONCE_BYTES];
        assert_eq!(
            lock_nonce_cache(&cache)
                .issue_with(1, 100, || Ok(replacement))
                .unwrap(),
            replacement
        );
    }

    #[tokio::test]
    async fn acceptance_criterion_6_5_releases_after_invalid_and_malformed_proofs() {
        for signature in [
            String::from("not-base64"),
            URL_SAFE_NO_PAD.encode([0u8; 64]),
        ] {
            let (fixture, pop) = fixture();
            let now = unix_seconds().unwrap();
            let token = mint_token(&fixture, &pop, now, now + 600);
            let authenticator = PopAuthenticator::new(Arc::new(fixture), String::from(BRIDGE_ID));
            let observer = authenticator.clone();
            let (mut client, mut server) = tokio::io::duplex(4096);
            let server_task =
                tokio::spawn(async move { authenticator.authenticate(&mut server).await });
            let _challenge = send_request(&mut client, token).await.unwrap();
            write_message(&mut client, &ChallengeResponse { signature })
                .await
                .unwrap();
            assert!(matches!(
                server_task.await.unwrap(),
                Err(PopError::InvalidProof)
            ));
            assert!(lock_nonce_cache(&observer.nonces).outstanding.is_empty());
        }
    }

    #[tokio::test]
    async fn acceptance_criterion_6_5_releases_after_prefix_and_body_read_failures() {
        for partial_response in [None, Some(b"{".as_slice())] {
            let (fixture, pop) = fixture();
            let now = unix_seconds().unwrap();
            let token = mint_token(&fixture, &pop, now, now + 600);
            let authenticator = PopAuthenticator::new(Arc::new(fixture), String::from(BRIDGE_ID));
            let observer = authenticator.clone();
            let (mut client, mut server) = tokio::io::duplex(4096);
            let server_task =
                tokio::spawn(async move { authenticator.authenticate(&mut server).await });
            let _challenge = send_request(&mut client, token).await.unwrap();
            if let Some(partial_response) = partial_response {
                client.write_u32(2).await.unwrap();
                client.write_all(partial_response).await.unwrap();
                client.flush().await.unwrap();
            }
            drop(client);
            assert!(matches!(
                tokio::time::timeout(Duration::from_secs(1), server_task)
                    .await
                    .unwrap()
                    .unwrap(),
                Err(PopError::Io)
            ));
            assert!(lock_nonce_cache(&observer.nonces).outstanding.is_empty());
        }
    }

    #[tokio::test]
    async fn acceptance_criterion_6_5_releases_after_challenge_write_failure() {
        let (fixture, pop) = fixture();
        let now = unix_seconds().unwrap();
        let token = mint_token(&fixture, &pop, now, now + 600);
        let authenticator = PopAuthenticator::new(Arc::new(fixture), String::from(BRIDGE_ID));
        let observer = authenticator.clone();
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task =
            tokio::spawn(async move { authenticator.authenticate(&mut server).await });
        write_message(
            &mut client,
            &RegistrationRequest {
                token,
                hostname: String::from(HOSTNAME),
            },
        )
        .await
        .unwrap();
        drop(client);
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), server_task)
                .await
                .unwrap()
                .unwrap(),
            Err(PopError::Io)
        ));
        assert!(lock_nonce_cache(&observer.nonces).outstanding.is_empty());
    }

    #[tokio::test]
    async fn acceptance_criterion_6_5_releases_after_authentication_future_drop() {
        let (fixture, pop) = fixture();
        let now = unix_seconds().unwrap();
        let token = mint_token(&fixture, &pop, now, now + 600);
        let authenticator = PopAuthenticator::new(Arc::new(fixture), String::from(BRIDGE_ID));
        let observer = authenticator.clone();
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task =
            tokio::spawn(async move { authenticator.authenticate(&mut server).await });
        let _challenge = send_request(&mut client, token).await.unwrap();
        server_task.abort();
        assert!(server_task.await.is_err());
        assert!(lock_nonce_cache(&observer.nonces).outstanding.is_empty());
    }

    #[tokio::test]
    async fn expired_token_is_rejected_before_a_challenge_is_issued() {
        let (fixture, pop) = fixture();
        let now = unix_seconds().unwrap();
        let token = mint_token(&fixture, &pop, now - 600, now - 1);
        let authenticator = PopAuthenticator::new(Arc::new(fixture), String::from(BRIDGE_ID));
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task =
            tokio::spawn(async move { authenticator.authenticate(&mut server).await });

        write_message(
            &mut client,
            &RegistrationRequest {
                token,
                hostname: String::from(HOSTNAME),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            server_task.await.unwrap(),
            Err(PopError::TokenRejected)
        ));
        let mut byte = [0u8; 1];
        assert_eq!(client.read(&mut byte).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn jwks_connection_refusal_is_rejected_without_retrying() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);

        let (fixture, pop) = fixture();
        let now = unix_seconds().unwrap();
        let token = mint_token(&fixture, &pop, now, now + 600);
        let verifier =
            JwksTokenVerifier::new(&format!("https://{address}/jwks"), String::from(BRIDGE_ID))
                .unwrap();
        let started = tokio::time::Instant::now();
        assert!(matches!(
            verifier.verify(&token).await,
            Err(PopError::JwksUnavailable)
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn jwks_black_hole_is_bounded_by_the_fetch_timeout() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accept_task = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(4)).await;
        });

        let (fixture, pop) = fixture();
        let now = unix_seconds().unwrap();
        let token = mint_token(&fixture, &pop, now, now + 600);
        let verifier =
            JwksTokenVerifier::new(&format!("https://{address}/jwks"), String::from(BRIDGE_ID))
                .unwrap();
        let started = tokio::time::Instant::now();
        assert!(matches!(
            verifier.verify(&token).await,
            Err(PopError::JwksUnavailable)
        ));
        assert!(started.elapsed() < Duration::from_secs(4));
        accept_task.abort();
    }

    #[tokio::test]
    async fn header_twins_are_rejected_as_tokens() {
        let now = 1_700_000_300;
        let verifier = strict_fixture(now);
        let pop = SigningKey::from_bytes(&POP_KEY);
        let cases = [
            serde_json::json!({"alg": "HS256", "typ": "JWT", "kid": "twin-1"}),
            serde_json::json!({"alg": "EdDSA", "kid": "twin-2"}),
            serde_json::json!({"alg": "EdDSA", "typ": "JWT", "kid": "twin-3", "extra": true}),
            serde_json::json!({"alg": "EdDSA", "typ": "JWT", "kid": ""}),
        ];
        for (index, header) in cases.into_iter().enumerate() {
            let kid = format!("twin-{}", index + 1);
            let token = verifier
                .mint_raw(
                    &kid,
                    &header,
                    &raw_claims(&pop.verifying_key(), now - 300, now + 300),
                )
                .unwrap();
            assert_token_rejected(&verifier, token).await;
        }
    }

    #[tokio::test]
    async fn claim_twins_and_ttl_boundaries_are_validated() {
        let now = 1_700_000_300;
        let verifier = strict_fixture(now);
        let pop = SigningKey::from_bytes(&POP_KEY);

        for (kid, issued_at, expires_at) in [
            ("twin-5", now - 300, now + 299),
            ("twin-6", now - 400, now + 501),
        ] {
            let token = verifier
                .mint_raw(
                    kid,
                    &raw_header(kid),
                    &raw_claims(&pop.verifying_key(), issued_at, expires_at),
                )
                .unwrap();
            assert_token_rejected(&verifier, token).await;
        }

        for (kid, issued_at, expires_at) in [
            ("twin-9", now - 300, now + 300),
            ("twin-10", now - 400, now + 500),
        ] {
            let claims = raw_claims(&pop.verifying_key(), issued_at, expires_at);
            let token = verifier.mint_raw(kid, &raw_header(kid), &claims).unwrap();
            assert!(verifier.verify(&token).await.is_ok());
        }

        let mut claims = raw_claims(
            &pop.verifying_key(),
            now + POP_SKEW + 1,
            now + POP_SKEW + 601,
        );
        let token = verifier
            .mint_raw("twin-11", &raw_header("twin-11"), &claims)
            .unwrap();
        assert_token_rejected(&verifier, token).await;

        claims = raw_claims(&pop.verifying_key(), now - 600, now + 1);
        claims["iss"] = serde_json::json!("wrong.example");
        let token = verifier
            .mint_raw("twin-12", &raw_header("twin-12"), &claims)
            .unwrap();
        assert_token_rejected(&verifier, token).await;

        claims = raw_claims(&pop.verifying_key(), now - 600, now + 1);
        claims["aud"] = serde_json::json!("other-bridge");
        let token = verifier
            .mint_raw("twin-13", &raw_header("twin-13"), &claims)
            .unwrap();
        assert_token_rejected(&verifier, token).await;

        for (kid, subject) in [("twin-14", "device:id"), ("twin-15", "home:")] {
            let mut claims = raw_claims(&pop.verifying_key(), now - 600, now + 1);
            claims["sub"] = serde_json::json!(subject);
            let token = verifier.mint_raw(kid, &raw_header(kid), &claims).unwrap();
            assert_token_rejected(&verifier, token).await;
        }

        claims = raw_claims(&pop.verifying_key(), now - 600, now + 1);
        claims["extra"] = serde_json::json!(true);
        let token = verifier
            .mint_raw("twin-16", &raw_header("twin-16"), &claims)
            .unwrap();
        assert_token_rejected(&verifier, token).await;

        for (kid, value) in [
            ("twin-17", serde_json::json!(1_700_000_000.5)),
            ("twin-18", serde_json::json!("1700000000")),
        ] {
            let mut claims = raw_claims(&pop.verifying_key(), now - 600, now + 1);
            claims["iat"] = value;
            let token = verifier.mint_raw(kid, &raw_header(kid), &claims).unwrap();
            assert_token_rejected(&verifier, token).await;
        }
    }

    #[tokio::test]
    async fn jwk_and_base64_twins_are_rejected_as_tokens() {
        let now = 1_700_000_300;
        let verifier = strict_fixture(now);
        let pop = SigningKey::from_bytes(&POP_KEY);
        let cases = [
            ("twin-19", "d", serde_json::json!("private")),
            ("twin-20", "kty", serde_json::json!("EC")),
            ("twin-21", "crv", serde_json::json!("P-256")),
            ("twin-22", "x", serde_json::json!("AA")),
        ];
        for (kid, field, value) in cases {
            let mut claims = raw_claims(&pop.verifying_key(), now - 600, now + 1);
            claims["cnf"]["jwk"][field] = value;
            let token = verifier.mint_raw(kid, &raw_header(kid), &claims).unwrap();
            assert_token_rejected(&verifier, token).await;
        }

        let mut claims = raw_claims(&pop.verifying_key(), now - 600, now + 1);
        let encoded = claims["cnf"]["jwk"]["x"].as_str().unwrap();
        claims["cnf"]["jwk"]["x"] = serde_json::json!(format!("{encoded}="));
        let token = verifier
            .mint_raw("twin-23", &raw_header("twin-23"), &claims)
            .unwrap();
        assert_token_rejected(&verifier, token).await;

        let mut claims = raw_claims(&pop.verifying_key(), now - 600, now + 1);
        let encoded = claims["cnf"]["jwk"]["x"].as_str().unwrap();
        claims["cnf"]["jwk"]["x"] = serde_json::json!(noncanonical_base64url(encoded));
        let token = verifier
            .mint_raw("twin-24", &raw_header("twin-24"), &claims)
            .unwrap();
        assert_token_rejected(&verifier, token).await;

        let token = verifier
            .mint_raw(
                "twin-25",
                &raw_header("twin-25"),
                &raw_claims(&pop.verifying_key(), now - 600, now + 1),
            )
            .unwrap();
        for index in 0..3 {
            let segment = token.split('.').nth(index).unwrap();
            let malformed = if index == 1 {
                format!("{segment}=")
            } else {
                noncanonical_base64url(segment)
            };
            assert_token_rejected(&verifier, replace_segment(&token, index, malformed)).await;
        }
    }

    #[tokio::test]
    async fn hostname_twins_are_rejected_as_tokens() {
        let now = 1_700_000_300;
        let verifier = strict_fixture(now);
        let pop = SigningKey::from_bytes(&POP_KEY);
        let hostnames = [
            "aaaqeay.solstone.me",
            "aaaqeayey.solstone.me",
            "AAAQEAYE.solstone.me",
            "aaaqeay0.solstone.me",
            "aaaqeay1.solstone.me",
            "aaaqeay!.solstone.me",
            "ab.aaaqeaye.solstone.me",
            "aaaqeaye.solstone.com",
        ];
        for (index, hostname) in hostnames.into_iter().enumerate() {
            let kid = format!("twin-{}", index + 26);
            let mut claims = raw_claims(&pop.verifying_key(), now - 600, now + 1);
            claims["hostname"] = serde_json::json!(hostname);
            let token = verifier.mint_raw(&kid, &raw_header(&kid), &claims).unwrap();
            assert_token_rejected(&verifier, token).await;
        }
    }

    #[tokio::test]
    async fn boundary_clock_truncates_to_seconds() {
        let seconds = (UNIX_EPOCH + Duration::new(1_700_000_300, 999_999_999))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let verifier = FixtureTokenVerifier::with_clock(
            HashMap::from([(String::from("fixture"), SigningKey::from_bytes(&ISSUER_KEY))]),
            String::from(BRIDGE_ID),
            Arc::new(move || seconds),
        );
        let pop = SigningKey::from_bytes(&POP_KEY);
        let token = verifier
            .mint(
                "fixture",
                INSTANCE_ID,
                HOSTNAME,
                seconds - 300,
                seconds + 600,
                &pop.verifying_key(),
            )
            .unwrap();
        assert!(verifier.verify(&token).await.is_ok());
        let expired = verifier
            .mint(
                "fixture",
                INSTANCE_ID,
                HOSTNAME,
                seconds - 600,
                seconds,
                &pop.verifying_key(),
            )
            .unwrap();
        assert_token_rejected(&verifier, expired).await;
    }
}
