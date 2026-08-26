// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Journal proof-of-possession authentication for control registrations.
//!
//! The upstream journal-MCP endpoint specification is unavailable in this
//! environment. The field names and length-prefixed JSON schema in this module
//! are therefore this implementation's own choice, not copied from that
//! specification. They must be reconciled with the upstream document before
//! this protocol is used with a journal outside this repository's tests.
//!
//! The journal first sends `{"token":"...","hostname":"..."}`. The
//! verified token claims contain `hostname`, Unix-second `exp` and `iat`, and
//! `pop_ed25519`, a base64url-without-padding encoded raw 32-byte Ed25519
//! public key. The bridge replies with `{"nonce":"..."}`, containing a
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
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
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

/// A verified token claim set used to bind a registration proof to a journal.
#[derive(Clone)]
pub struct VerifiedClaims {
    hostname: String,
    expires_at: i64,
    issued_at: i64,
    pop_key: VerifyingKey,
}

impl VerifiedClaims {
    /// Return the hostname authorized by the token.
    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    /// Return the token expiry as Unix seconds.
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }

    /// Return the token issue time as Unix seconds.
    pub fn issued_at(&self) -> i64 {
        self.issued_at
    }

    /// Return the Ed25519 key that must sign the challenge response.
    pub fn pop_key(&self) -> VerifyingKey {
        self.pop_key
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
    /// The token's proof key was not a valid raw Ed25519 public key.
    #[error("journal token proof key is invalid")]
    InvalidProofKey,
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
    /// Connecting to or fetching from the JWKS origin failed or timed out.
    #[error("JWKS fetch failed")]
    JwksFetch,
    /// The JWKS origin did not return a bounded successful JSON document.
    #[error("JWKS response is invalid")]
    JwksResponse,
    /// Rustls could not create the pinned ring-provider client configuration.
    #[error("JWKS TLS configuration failed")]
    JwksTlsConfiguration,
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
    decoding_keys: HashMap<String, DecodingKey>,
}

/// A HTTPS JWKS-backed `EdDSA` token verifier with a small in-memory key cache.
pub struct JwksTokenVerifier {
    origin: JwksOrigin,
    connector: TlsConnector,
    cache: Mutex<HashMap<String, CachedJwk>>,
    timeouts: JwksTimeouts,
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
struct RawClaims {
    hostname: String,
    exp: u64,
    iat: u64,
    pop_ed25519: String,
}

#[derive(Serialize)]
struct MintClaims<'a> {
    hostname: &'a str,
    exp: i64,
    iat: i64,
    pop_ed25519: String,
}

struct NonceCache {
    entries: HashMap<[u8; NONCE_BYTES], NonceEntry>,
}

struct NonceEntry {
    expires_at: i64,
    consumed: bool,
}

struct JwksOrigin {
    host: String,
    port: u16,
    authority: String,
    path_and_query: String,
}

struct CachedJwk {
    key: Arc<DecodingKey>,
    expires_at: tokio::time::Instant,
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
        validate_claims(&claims, &request.hostname, now)?;

        let nonce = {
            let mut cache = self.nonces.lock().await;
            cache.issue(now, claims.expires_at)?
        };
        let challenge = Challenge {
            nonce: URL_SAFE_NO_PAD.encode(nonce),
        };
        write_message(carrier, &challenge).await?;

        let response: ChallengeResponse = read_message(carrier).await?;
        if response.timestamp.abs_diff(now) > POP_SKEW {
            return Err(PopError::ResponseTimeInvalid);
        }
        let signature = decode_signature(&response.signature)?;
        let signed = proof_message(&nonce, response.timestamp);
        claims
            .pop_key
            .verify_strict(&signed, &signature)
            .map_err(|_| PopError::InvalidProof)?;
        self.nonces
            .lock()
            .await
            .redeem(nonce, claims.expires_at, now)?;

        Ok(AuthenticatedRegistration {
            hostname: request.hostname,
            claims,
        })
    }
}

impl FixtureTokenVerifier {
    /// Build a fixture verifier from deterministic Ed25519 JWT signing keys by key id.
    ///
    /// # Errors
    ///
    /// Returns an error when a fixture public key cannot be converted into a
    /// `jsonwebtoken` decoding key.
    pub fn new(keys: impl IntoIterator<Item = (String, SigningKey)>) -> Result<Self, PopError> {
        let mut signing_keys = HashMap::new();
        let mut decoding_keys = HashMap::new();
        for (kid, signing) in keys {
            let public_key = URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes());
            let decoding = DecodingKey::from_ed_components(&public_key)
                .map_err(|_| PopError::InvalidProofKey)?;
            signing_keys.insert(kid.clone(), signing);
            decoding_keys.insert(kid, decoding);
        }
        Ok(Self {
            signing_keys,
            decoding_keys,
        })
    }

    /// Mint a deterministic `EdDSA` JWT for a fixture key and `PoP` public key.
    ///
    /// # Errors
    ///
    /// Returns an error when `kid` has no fixture signing key or JSON
    /// serialization fails.
    pub fn mint(
        &self,
        kid: &str,
        hostname: &str,
        issued_at: i64,
        expires_at: i64,
        pop_key: VerifyingKey,
    ) -> Result<String, PopError> {
        let signing = self.signing_keys.get(kid).ok_or(PopError::TokenRejected)?;
        let header = serde_json::json!({"alg": "EdDSA", "typ": "JWT", "kid": kid});
        let claims = MintClaims {
            hostname,
            exp: expires_at,
            iat: issued_at,
            pop_ed25519: URL_SAFE_NO_PAD.encode(pop_key.to_bytes()),
        };
        let header = serde_json::to_vec(&header).map_err(|_| PopError::InvalidMessage)?;
        let claims = serde_json::to_vec(&claims).map_err(|_| PopError::InvalidMessage)?;
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
}

impl TokenVerifier for FixtureTokenVerifier {
    fn verify<'a>(
        &'a self,
        token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<VerifiedClaims, PopError>> + Send + 'a>> {
        Box::pin(async move {
            let header = decode_header(token).map_err(|_| PopError::TokenRejected)?;
            if header.alg != Algorithm::EdDSA {
                return Err(PopError::TokenRejected);
            }
            let kid = header.kid.ok_or(PopError::TokenRejected)?;
            let key = self
                .decoding_keys
                .get(&kid)
                .ok_or(PopError::TokenRejected)?;
            decode_claims(token, key)
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
    pub fn new(url: &str) -> Result<Self, PopError> {
        Self::with_timeouts(url, JwksTimeouts::default())
    }

    /// Construct a verifier for one HTTPS JWKS URL with explicit timeout limits.
    ///
    /// # Errors
    ///
    /// Returns an error when `url` is not a valid HTTPS URL or rustls cannot
    /// construct its ring-provider client configuration.
    pub fn with_timeouts(url: &str, timeouts: JwksTimeouts) -> Result<Self, PopError> {
        let origin = parse_jwks_url(url)?;
        #[expect(
            clippy::from_iter_instead_of_collect,
            reason = "the explicit root-store type mirrors the transport TLS configuration"
        )]
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| PopError::JwksTlsConfiguration)?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            origin,
            connector: TlsConnector::from(Arc::new(config)),
            cache: Mutex::new(HashMap::new()),
            timeouts,
        })
    }

    async fn key_for_kid(&self, kid: &str) -> Result<Arc<DecodingKey>, PopError> {
        let now = tokio::time::Instant::now();
        {
            let mut cache = self.cache.lock().await;
            cache.retain(|_, entry| entry.expires_at > now);
            if let Some(entry) = cache.get(kid) {
                return Ok(Arc::clone(&entry.key));
            }
        }

        let keys = self.fetch_jwks().await?;
        let expires_at = tokio::time::Instant::now() + JWKS_CACHE_TTL;
        let mut cache = self.cache.lock().await;
        cache.retain(|_, entry| entry.expires_at > tokio::time::Instant::now());
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
        cache
            .get(kid)
            .map(|entry| Arc::clone(&entry.key))
            .ok_or(PopError::TokenRejected)
    }

    async fn fetch_jwks(&self) -> Result<HashMap<String, DecodingKey>, PopError> {
        let tcp = tokio::time::timeout(
            self.timeouts.connect,
            TcpStream::connect((self.origin.host.as_str(), self.origin.port)),
        )
        .await
        .map_err(|_| PopError::JwksFetch)?
        .map_err(|_| PopError::JwksFetch)?;
        let origin = &self.origin;
        let connector = self.connector.clone();
        tokio::time::timeout(
            self.timeouts.fetch,
            fetch_jwks_over_tls(tcp, origin, connector),
        )
        .await
        .map_err(|_| PopError::JwksFetch)?
    }
}

impl TokenVerifier for JwksTokenVerifier {
    fn verify<'a>(
        &'a self,
        token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<VerifiedClaims, PopError>> + Send + 'a>> {
        Box::pin(async move {
            let header = decode_header(token).map_err(|_| PopError::TokenRejected)?;
            if header.alg != Algorithm::EdDSA {
                return Err(PopError::TokenRejected);
            }
            let kid = header.kid.ok_or(PopError::TokenRejected)?;
            let key = self.key_for_kid(&kid).await?;
            decode_claims(token, &key)
        })
    }
}

impl NonceCache {
    fn issue(&mut self, now: i64, expires_at: i64) -> Result<[u8; NONCE_BYTES], PopError> {
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
        expires_at: i64,
        now: i64,
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

fn decode_claims(token: &str, key: &DecodingKey) -> Result<VerifiedClaims, PopError> {
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.algorithms = vec![Algorithm::EdDSA];
    validation.leeway = 0;
    let claims = decode::<RawClaims>(token, key, &validation)
        .map_err(|_| PopError::TokenRejected)?
        .claims;
    let expires_at = i64::try_from(claims.exp).map_err(|_| PopError::TokenTimeInvalid)?;
    let issued_at = i64::try_from(claims.iat).map_err(|_| PopError::TokenTimeInvalid)?;
    let public_key = URL_SAFE_NO_PAD
        .decode(claims.pop_ed25519)
        .map_err(|_| PopError::InvalidProofKey)?;
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| PopError::InvalidProofKey)?;
    let pop_key = VerifyingKey::from_bytes(&public_key).map_err(|_| PopError::InvalidProofKey)?;
    Ok(VerifiedClaims {
        hostname: claims.hostname,
        expires_at,
        issued_at,
        pop_key,
    })
}

fn validate_claims(claims: &VerifiedClaims, hostname: &str, now: i64) -> Result<(), PopError> {
    if claims.hostname != hostname {
        return Err(PopError::HostnameMismatch);
    }
    if claims.expires_at <= now
        || claims.issued_at > now.saturating_add(POP_SKEW.cast_signed())
        || claims.issued_at > claims.expires_at
    {
        return Err(PopError::TokenTimeInvalid);
    }
    Ok(())
}

fn unix_seconds() -> Result<i64, PopError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PopError::TokenTimeInvalid)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| PopError::TokenTimeInvalid)
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
) -> Result<HashMap<String, DecodingKey>, PopError> {
    let server_name = ServerName::try_from(origin.host.clone()).map_err(|_| PopError::JwksUrl)?;
    let mut stream = connector
        .connect(server_name, tcp)
        .await
        .map_err(|_| PopError::JwksFetch)?;
    let request = format!(
        "GET {} HTTP/1.1\r\nhost: {}\r\naccept: application/json\r\nconnection: close\r\n\r\n",
        origin.path_and_query, origin.authority
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|_| PopError::JwksFetch)?;
    stream.flush().await.map_err(|_| PopError::JwksFetch)?;
    let body = read_http_response(&mut stream).await?;
    let document: JwksDocument =
        serde_json::from_slice(&body).map_err(|_| PopError::JwksResponse)?;
    let mut keys = HashMap::new();
    for jwk in document.keys {
        if jwk.kty != "OKP"
            || jwk.crv != "Ed25519"
            || jwk.alg.as_deref() != Some("EdDSA")
            || jwk.kid.is_empty()
        {
            continue;
        }
        let key = DecodingKey::from_ed_components(&jwk.x).map_err(|_| PopError::JwksResponse)?;
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
            .map_err(|_| PopError::JwksFetch)?;
        if read == 0 {
            return Err(PopError::JwksResponse);
        }
        response.extend_from_slice(&buffer[..read]);
        if response.len() > MAX_JWKS_RESPONSE_BYTES {
            return Err(PopError::JwksResponse);
        }
        if let Some(body_start) = response.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            let body_start = body_start + 4;
            let content_length = parse_http_head(&response[..body_start])?;
            let body_end = body_start
                .checked_add(content_length)
                .ok_or(PopError::JwksResponse)?;
            if body_end > MAX_JWKS_RESPONSE_BYTES || response.len() > body_end {
                return Err(PopError::JwksResponse);
            }
            if response.len() == body_end {
                return Ok(response[body_start..].to_vec());
            }
        }
    }
}

fn parse_http_head(head: &[u8]) -> Result<usize, PopError> {
    let head = std::str::from_utf8(head).map_err(|_| PopError::JwksResponse)?;
    let mut lines = head.split("\r\n");
    let status = lines.next().ok_or(PopError::JwksResponse)?;
    if !status.starts_with("HTTP/1.1 200 ") && !status.starts_with("HTTP/1.0 200 ") {
        return Err(PopError::JwksResponse);
    }
    let mut content_length = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(PopError::JwksResponse);
            }
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| PopError::JwksResponse)?,
            );
        }
    }
    content_length.ok_or(PopError::JwksResponse)
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

    fn fixture() -> (FixtureTokenVerifier, SigningKey) {
        let issuer = SigningKey::from_bytes(&ISSUER_KEY);
        let pop = SigningKey::from_bytes(&POP_KEY);
        (
            FixtureTokenVerifier::new([(String::from("fixture"), issuer)]).unwrap(),
            pop,
        )
    }

    async fn send_request<S>(client: &mut S, token: String) -> Result<Challenge, PopError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        write_message(
            client,
            &RegistrationRequest {
                token,
                hostname: String::from("journal.test"),
            },
        )
        .await?;
        read_message(client).await
    }

    fn response(challenge: &Challenge, signing: &SigningKey, timestamp: i64) -> ChallengeResponse {
        let nonce: [u8; NONCE_BYTES] = URL_SAFE_NO_PAD
            .decode(&challenge.nonce)
            .unwrap()
            .try_into()
            .unwrap();
        let signature = signing.sign(&proof_message(&nonce, timestamp));
        ChallengeResponse {
            timestamp,
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        }
    }

    #[tokio::test]
    async fn valid_token_and_matching_proof_succeeds() {
        let (fixture, pop) = fixture();
        let now = unix_seconds().unwrap();
        let token = fixture
            .mint(
                "fixture",
                "journal.test",
                now,
                now + 300,
                pop.verifying_key(),
            )
            .unwrap();
        let authenticator = PopAuthenticator::new(Arc::new(fixture));
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task =
            tokio::spawn(async move { authenticator.authenticate(&mut server).await });

        let challenge = send_request(&mut client, token).await.unwrap();
        write_message(&mut client, &response(&challenge, &pop, now))
            .await
            .unwrap();
        let registration = server_task.await.unwrap().unwrap();
        assert_eq!(registration.hostname(), "journal.test");
    }

    #[tokio::test]
    async fn invalid_token_is_rejected_before_a_challenge_is_issued() {
        let (fixture, pop) = fixture();
        let now = unix_seconds().unwrap();
        let mut token = fixture
            .mint(
                "fixture",
                "journal.test",
                now,
                now + 300,
                pop.verifying_key(),
            )
            .unwrap();
        token.push('x');
        let authenticator = PopAuthenticator::new(Arc::new(fixture));
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task =
            tokio::spawn(async move { authenticator.authenticate(&mut server).await });

        write_message(
            &mut client,
            &RegistrationRequest {
                token,
                hostname: String::from("journal.test"),
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
        let token = fixture
            .mint(
                "fixture",
                "journal.test",
                now,
                now + 300,
                pop.verifying_key(),
            )
            .unwrap();
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
        let token = fixture
            .mint(
                "fixture",
                "journal.test",
                now,
                now + 300,
                pop.verifying_key(),
            )
            .unwrap();
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
        let token = fixture
            .mint(
                "fixture",
                "journal.test",
                now - 300,
                now - 1,
                pop.verifying_key(),
            )
            .unwrap();
        let authenticator = PopAuthenticator::new(Arc::new(fixture));
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task =
            tokio::spawn(async move { authenticator.authenticate(&mut server).await });

        write_message(
            &mut client,
            &RegistrationRequest {
                token,
                hostname: String::from("journal.test"),
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
        let token = fixture
            .mint(
                "fixture",
                "journal.test",
                now,
                now + 300,
                pop.verifying_key(),
            )
            .unwrap();
        let verifier = JwksTokenVerifier::new(&format!("https://{address}/jwks")).unwrap();
        let started = tokio::time::Instant::now();
        assert!(matches!(
            verifier.verify(&token).await,
            Err(PopError::JwksFetch)
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
        let token = fixture
            .mint(
                "fixture",
                "journal.test",
                now,
                now + 300,
                pop.verifying_key(),
            )
            .unwrap();
        let verifier = JwksTokenVerifier::new(&format!("https://{address}/jwks")).unwrap();
        let started = tokio::time::Instant::now();
        assert!(matches!(
            verifier.verify(&token).await,
            Err(PopError::JwksFetch)
        ));
        assert!(started.elapsed() < Duration::from_secs(4));
        accept_task.abort();
    }
}
