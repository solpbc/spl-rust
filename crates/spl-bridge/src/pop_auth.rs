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
//! Ed25519 public key. The bridge replies with `{"nonce":"..."}`, containing a
//! base64url 32-byte nonce. The journal then sends
//! `{"timestamp":...,"signature":"..."}`, where `signature` is an
//! Ed25519 signature over `b"spl-bridge-pop-v1\\0" || nonce || timestamp`,
//! with the timestamp encoded as an eight-byte big-endian signed integer.
//! Each JSON value is prefixed by a four-byte big-endian byte length.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
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
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio_rustls::TlsConnector;

const MAX_MESSAGE_BYTES: usize = 64 * 1024;
const NONCE_BYTES: usize = 32;
const POP_SKEW: u64 = 60;
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const DEFAULT_FETCH_TIMEOUT: Duration = Duration::from_secs(3);
const JWKS_CACHE_TTL: Duration = Duration::from_mins(5);
const JWKS_CACHE_LIMIT: usize = 64;
const MAX_JWKS_RESPONSE_BYTES: usize = 1024 * 1024;
const POP_DOMAIN_SEPARATOR: &[u8] = b"spl-bridge-pop-v1\0";
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
    /// The challenge response carried an implausible timestamp.
    #[error("proof-of-possession response timestamp is invalid")]
    ResponseTimeInvalid,
    /// The challenge response signature did not verify with the claimed key.
    #[error("proof-of-possession signature is invalid")]
    InvalidProof,
    /// The challenge nonce was already redeemed or was not currently issued.
    #[error("proof-of-possession nonce was replayed")]
    NonceReplay,
    /// Random nonce generation failed.
    #[error("proof-of-possession nonce generation failed")]
    Randomness,
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
pub struct RegistrationRequest {
    /// `EdDSA` JWT authorizing the named hostname and challenge public key.
    pub token: String,
    /// Hostname the journal is registering with this bridge.
    pub hostname: String,
}

/// The bridge's length-prefixed JSON challenge message.
#[derive(Serialize, Deserialize)]
pub struct Challenge {
    /// Base64url-without-padding encoding of the random 32-byte nonce.
    pub nonce: String,
}

/// The length-prefixed JSON response to a [`Challenge`].
#[derive(Serialize, Deserialize)]
pub struct ChallengeResponse {
    /// Unix seconds included in the signature and bounded to 60 seconds of bridge time.
    pub timestamp: i64,
    /// Base64url-without-padding encoding of the 64-byte Ed25519 signature.
    pub signature: String,
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
    entries: HashMap<[u8; NONCE_BYTES], NonceEntry>,
}

struct NonceEntry {
    expires_at: u64,
    consumed: bool,
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
    /// Construct an authenticator using `verifier` and an empty replay cache.
    pub fn new(verifier: Arc<dyn TokenVerifier>) -> Self {
        Self {
            verifier,
            nonces: Arc::new(Mutex::new(NonceCache {
                entries: HashMap::new(),
            })),
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

        let nonce = {
            let mut cache = self.nonces.lock().await;
            cache.issue(now, claims.expires_at())?
        };
        let challenge = Challenge {
            nonce: URL_SAFE_NO_PAD.encode(nonce),
        };
        write_message(carrier, &challenge).await?;

        let response: ChallengeResponse = read_message(carrier).await?;
        let response_now = i64::try_from(now).map_err(|_| PopError::ResponseTimeInvalid)?;
        if response.timestamp.abs_diff(response_now) > POP_SKEW {
            return Err(PopError::ResponseTimeInvalid);
        }
        let signature = decode_signature(&response.signature)?;
        let signed = proof_message(&nonce, response.timestamp);
        claims
            .pop_key()
            .verify_strict(&signed, &signature)
            .map_err(|_| PopError::InvalidProof)?;
        self.nonces
            .lock()
            .await
            .redeem(nonce, claims.expires_at(), now)?;

        Ok(AuthenticatedRegistration {
            hostname: request.hostname,
            claims,
        })
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
        self.entries.retain(|_, entry| entry.expires_at > now);
        loop {
            let mut nonce = [0u8; NONCE_BYTES];
            getrandom::getrandom(&mut nonce).map_err(|_| PopError::Randomness)?;
            if self.entries.contains_key(&nonce) {
                continue;
            }
            self.entries.insert(
                nonce,
                NonceEntry {
                    expires_at,
                    consumed: false,
                },
            );
            return Ok(nonce);
        }
    }

    fn redeem(
        &mut self,
        nonce: [u8; NONCE_BYTES],
        expires_at: u64,
        now: u64,
    ) -> Result<(), PopError> {
        self.entries.retain(|_, entry| entry.expires_at > now);
        let entry = self.entries.get_mut(&nonce).ok_or(PopError::NonceReplay)?;
        if entry.expires_at != expires_at || entry.consumed {
            return Err(PopError::NonceReplay);
        }
        entry.consumed = true;
        Ok(())
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

fn valid_hostname(hostname: &str) -> bool {
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

fn proof_message(nonce: &[u8; NONCE_BYTES], timestamp: i64) -> Vec<u8> {
    let mut message = Vec::with_capacity(POP_DOMAIN_SEPARATOR.len() + NONCE_BYTES + 8);
    message.extend_from_slice(POP_DOMAIN_SEPARATOR);
    message.extend_from_slice(nonce);
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

    fn response(challenge: &Challenge, signing: &SigningKey, timestamp: u64) -> ChallengeResponse {
        let nonce: [u8; NONCE_BYTES] = URL_SAFE_NO_PAD
            .decode(&challenge.nonce)
            .unwrap()
            .try_into()
            .unwrap();
        let timestamp = i64::try_from(timestamp).unwrap();
        let signature = signing.sign(&proof_message(&nonce, timestamp));
        ChallengeResponse {
            timestamp,
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
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
        let (fixture, pop) = fixture();
        let now = unix_seconds().unwrap();
        let token = mint_token(&fixture, &pop, now, now + 600);
        let authenticator = PopAuthenticator::new(Arc::new(fixture));
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task =
            tokio::spawn(async move { authenticator.authenticate(&mut server).await });

        let challenge = send_request(&mut client, token).await.unwrap();
        write_message(&mut client, &response(&challenge, &pop, now))
            .await
            .unwrap();
        let registration = server_task.await.unwrap().unwrap();
        assert_eq!(registration.hostname(), HOSTNAME);
    }

    #[tokio::test]
    async fn invalid_token_is_rejected_before_a_challenge_is_issued() {
        let (fixture, pop) = fixture();
        let now = unix_seconds().unwrap();
        let mut token = mint_token(&fixture, &pop, now, now + 600);
        token.push('x');
        let authenticator = PopAuthenticator::new(Arc::new(fixture));
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
        let (fixture, pop) = fixture();
        let now = unix_seconds().unwrap();
        let token = mint_token(&fixture, &pop, now, now + 600);
        let authenticator = PopAuthenticator::new(Arc::new(fixture));
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task =
            tokio::spawn(async move { authenticator.authenticate(&mut server).await });

        let challenge = send_request(&mut client, token).await.unwrap();
        let wrong = SigningKey::from_bytes(&WRONG_POP_KEY);
        write_message(&mut client, &response(&challenge, &wrong, now))
            .await
            .unwrap();
        assert!(matches!(
            server_task.await.unwrap(),
            Err(PopError::InvalidProof)
        ));
    }

    #[tokio::test]
    async fn proof_timestamp_outside_the_skew_window_is_rejected() {
        let (fixture, pop) = fixture();
        let now = unix_seconds().unwrap();
        let token = mint_token(&fixture, &pop, now, now + 600);
        let authenticator = PopAuthenticator::new(Arc::new(fixture));
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task =
            tokio::spawn(async move { authenticator.authenticate(&mut server).await });

        let challenge = send_request(&mut client, token).await.unwrap();
        write_message(&mut client, &response(&challenge, &pop, now + 90))
            .await
            .unwrap();
        assert!(matches!(
            server_task.await.unwrap(),
            Err(PopError::ResponseTimeInvalid)
        ));
    }

    #[test]
    fn replayed_nonce_is_rejected_within_its_token_lifetime() {
        let mut cache = NonceCache {
            entries: HashMap::new(),
        };
        let nonce = [1; NONCE_BYTES];
        cache.entries.insert(
            nonce,
            NonceEntry {
                expires_at: 300,
                consumed: false,
            },
        );
        cache.redeem(nonce, 300, 1).unwrap();
        assert!(matches!(
            cache.redeem(nonce, 300, 1),
            Err(PopError::NonceReplay)
        ));
    }

    #[tokio::test]
    async fn expired_token_is_rejected_before_a_challenge_is_issued() {
        let (fixture, pop) = fixture();
        let now = unix_seconds().unwrap();
        let token = mint_token(&fixture, &pop, now - 600, now - 1);
        let authenticator = PopAuthenticator::new(Arc::new(fixture));
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
