// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Pure transforms for the local journal bridge loopback proxy.

use crate::http;
use thiserror::Error;

/// Local route that exchanges a bootstrap query capability for a cookie.
pub const BOOTSTRAP_ROUTE: &str = "/_bridge/bootstrap";
/// Maximum accepted HTTP request-head size, including the terminating empty line.
pub const MAX_REQUEST_HEAD_BYTES: usize = 64 * 1024;

/// Consumer-selected names used by the pure loopback bridge transforms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeNames {
    /// Name of the cookie carrying the loopback capability. It must match the
    /// name used to set that cookie; a mismatch makes authorization reject it.
    pub capability_cookie_name: String,
    /// Prefix applied to upstream cookie names before returning them locally.
    /// Empty is supported: every non-capability request cookie is forwarded
    /// under its original name and response cookies return without namespacing.
    pub upstream_cookie_prefix: String,
    /// Header name reserved for consumer-specific caller authentication. It
    /// must be lowercase for caller-auth rejection to match normalized request
    /// names. Any other case bypasses that rejection, but request forwarding
    /// strips the configured name case-insensitively under either policy.
    pub observer_header_name: String,
    /// Header name reserved for the consumer's protocol version. It must be
    /// lowercase for caller-auth rejection to match normalized request names.
    /// Any other case bypasses that rejection, but request forwarding strips
    /// the configured name case-insensitively under either policy.
    pub protocol_version_header_name: String,
}

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Policy for selecting non-cookie request headers to forward upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestHeaderPolicy {
    /// Forward only headers whose names match one of the supplied names.
    Allow(Vec<String>),
    /// Forward every header except those reserved by the bridge.
    ForwardAll,
}

/// Parsed request-line and headers used by bridge authorization and rewrites.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead {
    /// HTTP request method exactly as parsed from the request line.
    pub method: String,
    /// Request target exactly as sent on the wire: path plus optional query.
    pub target: String,
    /// Header names are lowercased; values are trimmed but otherwise unchanged.
    pub headers: Vec<(String, String)>,
}

/// A structurally validated HTTP request head and its declared body length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedRequestHead {
    /// Parsed request-line and normalized headers.
    pub head: RequestHead,
    /// The single valid `Content-Length`, or zero when it is absent.
    pub content_length: usize,
}

/// Framing errors found while validating a local HTTP request head.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RequestFramingError {
    /// The terminating empty line ends beyond [`MAX_REQUEST_HEAD_BYTES`].
    #[error("HTTP request head exceeds the size limit")]
    HeadTooLarge,
    /// The request head has no terminating empty line.
    #[error("HTTP request head missing terminator")]
    MissingTerminator,
    /// The request head is not valid UTF-8.
    #[error("HTTP request head is not valid UTF-8")]
    InvalidEncoding,
    /// The request line has no nonempty method and target.
    #[error("invalid HTTP request line")]
    InvalidRequestLine,
    /// A header line is malformed.
    #[error("invalid HTTP request header")]
    InvalidHeader,
    /// Request transfer coding is unsupported.
    #[error("transfer-encoding is unsupported")]
    TransferEncoding,
    /// More than one `Content-Length` header was supplied.
    #[error("duplicate content-length")]
    DuplicateContentLength,
    /// `Content-Length` is not a nonempty ASCII decimal value representable as `usize`.
    #[error("invalid content-length")]
    InvalidContentLength,
    /// An expectation was supplied, but the bridge does not send interim responses.
    #[error("expectation is unsupported")]
    Expectation,
}

impl RequestHead {
    /// Return the first `Host` header value.
    pub fn host(&self) -> Option<&str> {
        self.headers
            .iter()
            .find(|(name, _)| name == "host")
            .map(|(_, value)| value.as_str())
    }

    /// Return the request target without its query string.
    #[expect(
        clippy::map_unwrap_or,
        reason = "the map step names the selected path before borrowing the full target fallback"
    )]
    pub fn path(&self) -> &str {
        self.target
            .split_once('?')
            .map(|(path, _)| path)
            .unwrap_or(&self.target)
    }

    /// Return the request target's query string, when present.
    pub fn query(&self) -> Option<&str> {
        self.target.split_once('?').map(|(_, query)| query)
    }

    /// Return the first cookie value with the exact supplied name.
    pub fn cookie(&self, name: &str) -> Option<&str> {
        for (_, value) in self.headers.iter().filter(|(key, _)| key == "cookie") {
            for part in value.split(';') {
                let trimmed = part.trim();
                let Some((cookie_name, cookie_value)) = trimmed.split_once('=') else {
                    continue;
                };
                if cookie_name == name {
                    return Some(cookie_value);
                }
            }
        }
        None
    }

    /// Whether the request carries caller-owned authentication headers.
    pub fn has_caller_auth(&self, names: &BridgeNames) -> bool {
        self.headers.iter().any(|(name, _)| {
            name == "authorization"
                || name == &names.observer_header_name
                || name == &names.protocol_version_header_name
        })
    }
}

/// Parse and validate an HTTP request head.
///
/// Header names are matched case-insensitively. A request may have at most one
/// `Content-Length`, may not use `Transfer-Encoding`, and may not carry
/// `Expect` because the bridge does not implement interim responses.
///
/// # Errors
///
/// Returns [`RequestFramingError`] for an oversized or malformed head,
/// unsupported transfer coding or expectation, or invalid body framing.
pub fn parse_request_head(raw: &[u8]) -> Result<ValidatedRequestHead, RequestFramingError> {
    let Some(split) = http::find_subsequence(raw, b"\r\n\r\n") else {
        return Err(if raw.len() > MAX_REQUEST_HEAD_BYTES {
            RequestFramingError::HeadTooLarge
        } else {
            RequestFramingError::MissingTerminator
        });
    };
    let head_end = split + 4;
    if head_end > MAX_REQUEST_HEAD_BYTES {
        return Err(RequestFramingError::HeadTooLarge);
    }

    let head_bytes = &raw[..split];
    let text =
        core::str::from_utf8(head_bytes).map_err(|_| RequestFramingError::InvalidEncoding)?;
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or(RequestFramingError::InvalidRequestLine)?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or(RequestFramingError::InvalidRequestLine)?
        .to_string();
    let target = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or(RequestFramingError::InvalidRequestLine)?
        .to_string();

    let mut headers = Vec::new();
    let mut content_lengths = Vec::new();
    let mut has_transfer_encoding = false;
    let mut has_expectation = false;
    for line in lines {
        let colon = line.find(':').ok_or(RequestFramingError::InvalidHeader)?;
        let key = line[..colon].trim().to_ascii_lowercase();
        if key.is_empty() {
            return Err(RequestFramingError::InvalidHeader);
        }
        let value = line[colon + 1..].trim().to_string();
        if key == "content-length" {
            content_lengths.push(value.clone());
        } else if key == "transfer-encoding" {
            has_transfer_encoding = true;
        } else if key == "expect" {
            has_expectation = true;
        }
        headers.push((key, value));
    }

    if has_transfer_encoding {
        return Err(RequestFramingError::TransferEncoding);
    }
    if content_lengths.len() > 1 {
        return Err(RequestFramingError::DuplicateContentLength);
    }
    let content_length = match content_lengths.first() {
        Some(value) => parse_content_length(value)?,
        None => 0,
    };
    if has_expectation {
        return Err(RequestFramingError::Expectation);
    }

    Ok(ValidatedRequestHead {
        head: RequestHead {
            method,
            target,
            headers,
        },
        content_length,
    })
}

fn parse_content_length(value: &str) -> Result<usize, RequestFramingError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(RequestFramingError::InvalidContentLength);
    }
    value.bytes().try_fold(0usize, |length, byte| {
        length
            .checked_mul(10)
            .and_then(|length| length.checked_add((byte - b'0') as usize))
            .ok_or(RequestFramingError::InvalidContentLength)
    })
}

/// Stable rejection categories for loopback bridge authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// The request does not target the exact loopback host and port.
    BadHost,
    /// The request method is not allowed by the bridge.
    BadMethod,
    /// Caller-owned authentication would cross the bridge boundary.
    CallerAuth,
    /// The capability cookie is absent or does not match.
    BadCapability,
}

impl RejectReason {
    /// Return the stable machine-readable diagnostic token.
    pub fn token(&self) -> &'static str {
        match self {
            Self::BadHost => "bad_host",
            Self::BadMethod => "bad_method",
            Self::CallerAuth => "caller_auth",
            Self::BadCapability => "bad_capability",
        }
    }
}

/// Authorize a parsed request for an exact loopback port and capability.
///
/// Host and method checks precede caller-auth and capability checks, preserving
/// stable rejection ordering.
///
/// # Errors
///
/// Returns a [`RejectReason`] for a host mismatch, unsupported method,
/// caller-owned authentication header, or invalid capability cookie.
pub fn authorize(
    head: &RequestHead,
    expected_cap: &[u8],
    port: u16,
    names: &BridgeNames,
) -> Result<(), RejectReason> {
    check_loopback_host(head, port)?;
    check_method(head)?;
    check_caller_auth(head, names)?;
    check_capability_cookie(head, expected_cap, names)
}

/// Require the exact IPv4 loopback host and listener port.
///
/// # Errors
///
/// Returns [`RejectReason::BadHost`] when the first `Host` header does not
/// exactly match `127.0.0.1:{port}`.
pub fn check_loopback_host(head: &RequestHead, port: u16) -> Result<(), RejectReason> {
    let expected_host = format!("127.0.0.1:{port}");
    if head.host() != Some(expected_host.as_str()) {
        return Err(RejectReason::BadHost);
    }
    Ok(())
}

/// Require a method supported by the capability-gated bridge.
///
/// # Errors
///
/// Returns [`RejectReason::BadMethod`] unless the method is `GET`, `HEAD`, or
/// `POST`.
pub fn check_method(head: &RequestHead) -> Result<(), RejectReason> {
    if !matches!(head.method.as_str(), "GET" | "HEAD" | "POST") {
        return Err(RejectReason::BadMethod);
    }
    Ok(())
}

/// Reject caller-owned authentication headers at the bridge boundary.
///
/// # Errors
///
/// Returns [`RejectReason::CallerAuth`] when a caller supplies
/// `Authorization` or either configured reserved header.
pub fn check_caller_auth(head: &RequestHead, names: &BridgeNames) -> Result<(), RejectReason> {
    if head.has_caller_auth(names) {
        return Err(RejectReason::CallerAuth);
    }
    Ok(())
}

/// Require the configured capability cookie using constant-time comparison.
///
/// # Errors
///
/// Returns [`RejectReason::BadCapability`] when the capability cookie is
/// absent or does not match.
pub fn check_capability_cookie(
    head: &RequestHead,
    expected_cap: &[u8],
    names: &BridgeNames,
) -> Result<(), RejectReason> {
    match head.cookie(&names.capability_cookie_name) {
        Some(cap) if ct_eq(cap.as_bytes(), expected_cap) => Ok(()),
        _ => Err(RejectReason::BadCapability),
    }
}

/// Compare two byte strings without data-dependent early exit after length.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (left, right)| acc | (left ^ right))
        == 0
}

/// Select request headers safe to forward and restore configured upstream cookies.
pub fn upstream_request_headers(
    head: &RequestHead,
    names: &BridgeNames,
    policy: &RequestHeaderPolicy,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (name, value) in &head.headers {
        if name == "cookie" {
            if let Some(cookie) = upstream_cookie_header(value, names) {
                out.push((name.clone(), cookie));
            }
            continue;
        }
        if is_reserved_request_header(name, names) {
            continue;
        }
        let allowed = match policy {
            RequestHeaderPolicy::Allow(names) => names
                .iter()
                .any(|allowed| name.eq_ignore_ascii_case(allowed)),
            RequestHeaderPolicy::ForwardAll => true,
        };
        if allowed {
            out.push((name.clone(), value.clone()));
        }
    }
    out
}

fn is_reserved_request_header(name: &str, names: &BridgeNames) -> bool {
    name.eq_ignore_ascii_case("authorization")
        || name.eq_ignore_ascii_case(&names.observer_header_name)
        || name.eq_ignore_ascii_case(&names.protocol_version_header_name)
        || name.eq_ignore_ascii_case("host")
        || name.eq_ignore_ascii_case("content-length")
        || HOP_BY_HOP
            .iter()
            .any(|reserved| name.eq_ignore_ascii_case(reserved))
}

fn upstream_cookie_header(value: &str, names: &BridgeNames) -> Option<String> {
    let cookies = value
        .split(';')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .filter_map(|part| {
            let (name, cookie_value) = part.split_once('=')?;
            let name = name.trim();
            if name == names.capability_cookie_name {
                return None;
            }
            let upstream_name = name.strip_prefix(&names.upstream_cookie_prefix)?;
            Some(format!("{upstream_name}={}", cookie_value.trim()))
        })
        .collect::<Vec<_>>();
    (!cookies.is_empty()).then(|| cookies.join("; "))
}

/// Select safe response headers and rewrite cookies and journal redirects.
pub fn response_headers(
    upstream: &[(String, String)],
    journal_hosts: &[String],
    loopback_origin: &str,
    names: &BridgeNames,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (raw_name, value) in upstream {
        let name = raw_name.to_ascii_lowercase();
        if name == "content-length" || HOP_BY_HOP.contains(&name.as_str()) {
            continue;
        }
        match name.as_str() {
            "set-cookie" => out.push((name, rewrite_set_cookie(value, names))),
            "location" => out.push((
                name,
                rewrite_redirect(value, journal_hosts, loopback_origin),
            )),
            _ if should_preserve_response_header(&name) => out.push((name, value.clone())),
            _ => {}
        }
    }
    out
}

/// Prefix an upstream cookie name and remove attributes invalid on loopback.
#[expect(
    clippy::map_unwrap_or,
    reason = "the mapped cookie pieces are clearer than boolean fallback combinators"
)]
pub fn rewrite_set_cookie(value: &str, names: &BridgeNames) -> String {
    let mut parts = value.split(';').map(str::trim);
    let Some(first) = parts.next() else {
        return String::new();
    };
    let first = first
        .split_once('=')
        .map(|(name, cookie_value)| {
            format!(
                "{}{}={cookie_value}",
                names.upstream_cookie_prefix,
                name.trim()
            )
        })
        .unwrap_or_else(|| first.to_string());
    let mut out = vec![first];

    for attr in parts {
        if attr.is_empty() {
            continue;
        }
        let attr_name = attr
            .split_once('=')
            .map(|(name, _)| name)
            .unwrap_or(attr)
            .trim();
        if attr_name.eq_ignore_ascii_case("domain") || attr_name.eq_ignore_ascii_case("secure") {
            continue;
        }
        out.push(attr.to_string());
    }

    out.join("; ")
}

/// Rewrite an absolute redirect to a known journal host onto loopback.
///
/// Relative and foreign redirects are returned unchanged.
pub fn rewrite_redirect(location: &str, journal_hosts: &[String], loopback_origin: &str) -> String {
    let Some((scheme, authority, suffix)) = split_http_url(location) else {
        return location.to_string();
    };
    if journal_hosts
        .iter()
        .any(|known| authority_matches(scheme, authority, known))
    {
        format!("{}{}", loopback_origin.trim_end_matches('/'), suffix)
    } else {
        location.to_string()
    }
}

/// Extract the `cap` query value from the exact bootstrap route.
pub fn bootstrap_cap(target: &str) -> Option<&str> {
    let (path, query) = target.split_once('?')?;
    if path != BOOTSTRAP_ROUTE {
        return None;
    }
    query.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name == "cap").then_some(value)
    })
}

/// Return the fixed security attributes for the local capability cookie.
pub fn bootstrap_cookie_attributes() -> &'static str {
    "Path=/; HttpOnly; SameSite=Strict"
}

/// Stable operational failure categories for bridge consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureCategory {
    /// The local loopback listener could not bind.
    LocalBind,
    /// A local request failed capability authorization.
    LocalCapabilityReject,
    /// The configured upstream endpoint could not be reached.
    UpstreamUnreachable,
    /// Upstream credentials were rejected.
    UpstreamCredential,
}

impl FailureCategory {
    /// Return the stable machine-readable diagnostic token.
    pub fn token(&self) -> &'static str {
        match self {
            Self::LocalBind => "local_bind_fail",
            Self::LocalCapabilityReject => "local_capability_reject",
            Self::UpstreamUnreachable => "upstream_unreachable",
            Self::UpstreamCredential => "upstream_credential",
        }
    }
}

fn should_preserve_response_header(name: &str) -> bool {
    matches!(
        name,
        "content-type"
            | "content-encoding"
            | "cache-control"
            | "etag"
            | "last-modified"
            | "expires"
            | "vary"
            | "accept-ranges"
            | "content-range"
            | "www-authenticate"
            | "retry-after"
            | "content-security-policy"
            | "content-security-policy-report-only"
            | "referrer-policy"
            | "x-content-type-options"
            | "x-frame-options"
            | "x-xss-protection"
            | "permissions-policy"
            | "cross-origin-opener-policy"
            | "cross-origin-resource-policy"
            | "cross-origin-embedder-policy"
            | "strict-transport-security"
    )
}

fn split_http_url(location: &str) -> Option<(&str, &str, &str)> {
    let (scheme, rest) = location.split_once("://")?;
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return None;
    }
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    Some((scheme, &rest[..authority_end], &rest[authority_end..]))
}

#[expect(
    clippy::map_unwrap_or,
    reason = "the tuple-producing map makes optional known schemes explicit"
)]
fn authority_matches(location_scheme: &str, location_authority: &str, known: &str) -> bool {
    let (location_host, location_port) = split_authority(location_authority);
    let location_effective_port = location_port.or_else(|| default_port(location_scheme));

    let (known_scheme, known_authority) = split_http_url(known)
        .map(|(scheme, authority, _)| (Some(scheme), authority))
        .unwrap_or((None, known));
    let (known_host, known_port) = split_authority(known_authority);
    if location_host != known_host {
        return false;
    }

    match known_port.or_else(|| known_scheme.and_then(default_port)) {
        Some(port) => location_effective_port == Some(port),
        None => true,
    }
}

#[expect(
    clippy::map_unwrap_or,
    reason = "the explicit user-info projection keeps the authority fallback readable"
)]
fn split_authority(authority: &str) -> (String, Option<u16>) {
    let host_port = authority
        .rsplit_once('@')
        .map(|(_, after_userinfo)| after_userinfo)
        .unwrap_or(authority);

    if let Some(after_bracket) = host_port.strip_prefix('[')
        && let Some(end) = after_bracket.find(']')
    {
        let host = after_bracket[..end].to_ascii_lowercase();
        let remainder = &after_bracket[end + 1..];
        let port = remainder
            .strip_prefix(':')
            .and_then(|port| port.parse::<u16>().ok());
        return (host, port);
    }

    match host_port.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => {
            (host.to_ascii_lowercase(), port.parse::<u16>().ok())
        }
        _ => (host_port.to_ascii_lowercase(), None),
    }
}

fn default_port(scheme: &str) -> Option<u16> {
    if scheme.eq_ignore_ascii_case("http") {
        Some(80)
    } else if scheme.eq_ignore_ascii_case("https") {
        Some(443)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names() -> BridgeNames {
        BridgeNames {
            capability_cookie_name: "__journal_cap".to_string(),
            upstream_cookie_prefix: "__journal_up_".to_string(),
            observer_header_name: ["x", "solstone", "observer"].join("-"),
            protocol_version_header_name: ["x", "solstone", "protocol-version"].join("-"),
        }
    }

    fn request(
        method: &str,
        target: &str,
        host: Option<&str>,
        extra: &[(&str, &str)],
    ) -> RequestHead {
        let mut raw = format!("{method} {target} HTTP/1.1\r\n");
        if let Some(host) = host {
            raw.push_str("Host: ");
            raw.push_str(host);
            raw.push_str("\r\n");
        }
        for (name, value) in extra {
            raw.push_str(name);
            raw.push_str(": ");
            raw.push_str(value);
            raw.push_str("\r\n");
        }
        raw.push_str("\r\n");
        parse_request_head(raw.as_bytes()).unwrap().head
    }

    #[test]
    fn request_head_validation_returns_single_declared_length() {
        let parsed = parse_request_head(
            b"POST /objects HTTP/1.1\r\nHoSt: local\r\nContent-Length: 0007\r\n\r\n",
        )
        .unwrap();
        assert_eq!(parsed.head.method, "POST");
        assert_eq!(parsed.head.target, "/objects");
        assert_eq!(parsed.head.host(), Some("local"));
        assert_eq!(parsed.content_length, 7);

        let bodyless = parse_request_head(b"GET /objects HTTP/1.1\r\nHost: local\r\n\r\n").unwrap();
        assert_eq!(bodyless.content_length, 0);
    }

    #[test]
    fn request_head_validation_rejects_duplicate_lengths_and_transfer_coding() {
        for raw in [
            "POST / HTTP/1.1\r\nContent-Length: 1\r\ncontent-length: 1\r\n\r\n",
            "POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
        ] {
            assert_eq!(
                parse_request_head(raw.as_bytes()),
                Err(RequestFramingError::DuplicateContentLength)
            );
        }

        assert_eq!(
            parse_request_head(b"POST / HTTP/1.1\r\ntRaNsFeR-EnCoDiNg: chunked\r\n\r\n"),
            Err(RequestFramingError::TransferEncoding)
        );
    }

    #[test]
    fn request_head_validation_rejects_invalid_lengths() {
        for value in [
            "",
            "+1",
            "-1",
            "1.0",
            "1 0",
            "18446744073709551616000000000000000000",
        ] {
            let raw = format!("POST / HTTP/1.1\r\nContent-Length: {value}\r\n\r\n");
            assert_eq!(
                parse_request_head(raw.as_bytes()),
                Err(RequestFramingError::InvalidContentLength),
                "{value:?}"
            );
        }
    }

    #[test]
    fn request_head_validation_checks_expectation_after_body_framing() {
        assert_eq!(
            parse_request_head(
                b"POST / HTTP/1.1\r\nContent-Length: 1\r\nExpect: 100-continue\r\n\r\n"
            ),
            Err(RequestFramingError::Expectation)
        );
        assert_eq!(
            parse_request_head(
                b"POST / HTTP/1.1\r\nContent-Length: bad\r\nExpect: 100-continue\r\n\r\n"
            ),
            Err(RequestFramingError::InvalidContentLength)
        );
        assert_eq!(
            parse_request_head(
                b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\n\r\n"
            ),
            Err(RequestFramingError::TransferEncoding)
        );
    }

    #[test]
    fn request_head_limit_uses_delimiter_end_boundary() {
        const EXPECTED_HEAD_LIMIT: usize = 65_536;

        let prefix = "GET / HTTP/1.1\r\nX-Pad: ";
        let suffix = "\r\n\r\n";
        assert_eq!(MAX_REQUEST_HEAD_BYTES, EXPECTED_HEAD_LIMIT);
        let at_limit_padding = EXPECTED_HEAD_LIMIT - prefix.len() - suffix.len();
        let at_limit = format!("{prefix}{}{suffix}", "a".repeat(at_limit_padding));
        assert_eq!(at_limit.len(), EXPECTED_HEAD_LIMIT);
        assert!(parse_request_head(at_limit.as_bytes()).is_ok());

        let past_limit = format!("{prefix}{}{suffix}", "a".repeat(at_limit_padding + 1));
        assert_eq!(past_limit.len(), EXPECTED_HEAD_LIMIT + 1);
        assert_eq!(
            parse_request_head(past_limit.as_bytes()),
            Err(RequestFramingError::HeadTooLarge)
        );
    }

    fn authed_request(
        method: &str,
        host: Option<&str>,
        cap: &str,
        names: &BridgeNames,
    ) -> RequestHead {
        request(
            method,
            "/",
            host,
            &[(
                "Cookie",
                &format!("{}={cap}; sid=journal", names.capability_cookie_name),
            )],
        )
    }

    #[test]
    fn parses_request_head_helpers() {
        let names = names();
        let head = request(
            "GET",
            "/journal?day=20260701",
            Some("127.0.0.1:49152"),
            &[("Cookie", "a=1; __journal_cap=secret")],
        );

        assert_eq!(head.method, "GET");
        assert_eq!(head.target, "/journal?day=20260701");
        assert_eq!(head.host(), Some("127.0.0.1:49152"));
        assert_eq!(head.path(), "/journal");
        assert_eq!(head.query(), Some("day=20260701"));
        assert_eq!(head.cookie(&names.capability_cookie_name), Some("secret"));
    }

    #[test]
    fn authorize_accepts_valid_local_request() {
        let names = names();
        let head = authed_request("GET", Some("127.0.0.1:49152"), "secret", &names);
        assert_eq!(authorize(&head, b"secret", 49152, &names), Ok(()));
    }

    #[test]
    fn authorize_rejects_bad_or_missing_capability() {
        let names = names();
        let wrong = authed_request("GET", Some("127.0.0.1:49152"), "wrong", &names);
        assert_eq!(
            authorize(&wrong, b"secret", 49152, &names),
            Err(RejectReason::BadCapability)
        );

        let missing = request("GET", "/", Some("127.0.0.1:49152"), &[]);
        assert_eq!(
            authorize(&missing, b"secret", 49152, &names),
            Err(RejectReason::BadCapability)
        );
    }

    #[test]
    fn authorize_rejects_host_mismatch_before_anything_else() {
        let names = names();
        let wrong_port = authed_request("GET", Some("127.0.0.1:49153"), "secret", &names);
        assert_eq!(
            authorize(&wrong_port, b"secret", 49152, &names),
            Err(RejectReason::BadHost)
        );

        let non_loopback = authed_request("GET", Some("localhost:49152"), "secret", &names);
        assert_eq!(
            authorize(&non_loopback, b"secret", 49152, &names),
            Err(RejectReason::BadHost)
        );

        let missing = authed_request("GET", None, "secret", &names);
        assert_eq!(
            authorize(&missing, b"secret", 49152, &names),
            Err(RejectReason::BadHost)
        );
    }

    #[test]
    fn authorize_rejects_unsupported_methods() {
        let names = names();
        for method in ["OPTIONS", "PUT", "DELETE"] {
            let head = authed_request(method, Some("127.0.0.1:49152"), "secret", &names);
            assert_eq!(
                authorize(&head, b"secret", 49152, &names),
                Err(RejectReason::BadMethod)
            );
        }
    }

    #[test]
    fn authorize_rejects_caller_auth_headers() {
        let names = names();
        for header in [
            "Authorization",
            "X-Solstone-Observer",
            "X-Solstone-Protocol-Version",
        ] {
            let head = request(
                "GET",
                "/",
                Some("127.0.0.1:49152"),
                &[("Cookie", "__journal_cap=secret"), (header, "caller-owned")],
            );
            assert_eq!(
                authorize(&head, b"secret", 49152, &names),
                Err(RejectReason::CallerAuth)
            );
        }
    }

    #[test]
    fn constant_time_compare_basics() {
        assert!(ct_eq(b"secret", b"secret"));
        assert!(!ct_eq(b"secret", b"secreu"));
        assert!(!ct_eq(b"secret", b"secret!"));
    }

    #[test]
    fn upstream_request_headers_keep_only_allowlist() {
        let names = names();
        let head = request(
            "POST",
            "/",
            Some("127.0.0.1:49152"),
            &[
                ("Accept", "text/html"),
                ("Accept-Language", "en-US"),
                ("Content-Type", "application/json"),
                ("Cache-Control", "no-cache"),
                ("If-None-Match", "\"abc\""),
                ("If-Modified-Since", "Wed, 01 Jul 2026 00:00:00 GMT"),
                ("Range", "bytes=0-10"),
                ("User-Agent", "WebView2"),
                (
                    "Cookie",
                    "__journal_cap=secret; __journal_up_sid=journal; unrelated=drop",
                ),
                ("Origin", "http://127.0.0.1:49152"),
                ("Referer", "http://127.0.0.1:49152/"),
                ("Content-Length", "99"),
                ("Connection", "keep-alive"),
                ("Authorization", "Bearer bad"),
            ],
        );

        let headers = upstream_request_headers(
            &head,
            &names,
            &RequestHeaderPolicy::Allow(vec![
                "accept".to_string(),
                "accept-language".to_string(),
                "content-type".to_string(),
                "cache-control".to_string(),
                "if-none-match".to_string(),
                "if-modified-since".to_string(),
                "range".to_string(),
                "user-agent".to_string(),
            ]),
        );

        assert!(headers.contains(&("accept".to_string(), "text/html".to_string())));
        assert!(headers.contains(&("accept-language".to_string(), "en-US".to_string())));
        assert!(headers.contains(&("content-type".to_string(), "application/json".to_string())));
        assert!(headers.contains(&("cache-control".to_string(), "no-cache".to_string())));
        assert!(headers.contains(&("if-none-match".to_string(), "\"abc\"".to_string())));
        assert!(headers.contains(&(
            "if-modified-since".to_string(),
            "Wed, 01 Jul 2026 00:00:00 GMT".to_string()
        )));
        assert!(headers.contains(&("range".to_string(), "bytes=0-10".to_string())));
        assert!(headers.contains(&("user-agent".to_string(), "WebView2".to_string())));
        assert!(headers.contains(&("cookie".to_string(), "sid=journal".to_string())));
        assert!(!headers.iter().any(|(name, _)| matches!(
            name.as_str(),
            "host" | "origin" | "referer" | "content-length" | "connection" | "authorization"
        )));
        assert!(
            !headers
                .iter()
                .any(|(_, value)| value.contains(&names.capability_cookie_name)
                    || value.contains("secret")
                    || value.contains("unrelated"))
        );
    }

    #[test]
    fn upstream_request_headers_omit_cookie_when_only_capability_cookie_present() {
        let names = names();
        let head = request(
            "GET",
            "/",
            Some("127.0.0.1:49152"),
            &[("Cookie", "__journal_cap=secret")],
        );

        let headers = upstream_request_headers(
            &head,
            &names,
            &RequestHeaderPolicy::Allow(vec![
                "accept".to_string(),
                "accept-language".to_string(),
                "content-type".to_string(),
                "cache-control".to_string(),
                "if-none-match".to_string(),
                "if-modified-since".to_string(),
                "range".to_string(),
                "user-agent".to_string(),
            ]),
        );

        assert!(!headers.iter().any(|(name, _)| name == "cookie"));
    }

    #[test]
    fn upstream_request_headers_forward_all_keeps_only_unreserved() {
        let names = names();
        let mut head = request(
            "PUT",
            "/",
            Some("127.0.0.1:49152"),
            &[
                ("X-Custom", "forwarded"),
                ("Authorization", "Bearer caller"),
                ("X-Solstone-Observer", "caller"),
                ("X-Solstone-Protocol-Version", "caller"),
                ("Content-Length", "4"),
                ("Connection", "close"),
                ("Keep-Alive", "timeout=5"),
                ("Proxy-Authenticate", "Basic realm=test"),
                ("Proxy-Authorization", "Basic caller"),
                ("TE", "trailers"),
                ("Trailer", "x-checksum"),
                ("Upgrade", "websocket"),
            ],
        );
        // Exercise the pure filtering function with a manually constructed
        // impossible-after-validation reserved header.
        head.headers
            .push(("transfer-encoding".to_string(), "chunked".to_string()));

        let headers = upstream_request_headers(&head, &names, &RequestHeaderPolicy::ForwardAll);

        assert_eq!(
            headers,
            vec![("x-custom".to_string(), "forwarded".to_string())]
        );
    }

    #[test]
    fn upstream_request_headers_empty_cookie_prefix_forwards_non_capability_cookies() {
        let mut names = names();
        names.upstream_cookie_prefix.clear();
        let head = request(
            "GET",
            "/",
            Some("127.0.0.1:49152"),
            &[("Cookie", "__journal_cap=secret; sid=journal; theme=dark")],
        );

        let headers = upstream_request_headers(&head, &names, &RequestHeaderPolicy::ForwardAll);

        assert_eq!(
            headers,
            vec![("cookie".to_string(), "sid=journal; theme=dark".to_string())]
        );
    }

    #[test]
    fn rewrite_set_cookie_drops_domain_and_secure() {
        let names = names();
        let rewritten = rewrite_set_cookie(
            "sid=abc; Domain=journal.example; Secure; Path=/; HttpOnly; SameSite=Lax; Max-Age=60",
            &names,
        );

        assert_eq!(
            rewritten,
            "__journal_up_sid=abc; Path=/; HttpOnly; SameSite=Lax; Max-Age=60"
        );
    }

    #[test]
    fn rewrite_redirect_handles_relative_journal_foreign_and_spl() {
        let loopback = "http://127.0.0.1:49152";
        let journal_hosts = vec![
            "journal.example".to_string(),
            "https://default.example".to_string(),
            "spl.local".to_string(),
        ];

        assert_eq!(
            rewrite_redirect("/app?day=1#top", &journal_hosts, loopback),
            "/app?day=1#top"
        );
        assert_eq!(
            rewrite_redirect(
                "https://journal.example/app?day=1#top",
                &journal_hosts,
                loopback
            ),
            "http://127.0.0.1:49152/app?day=1#top"
        );
        assert_eq!(
            rewrite_redirect("https://foreign.example/app", &journal_hosts, loopback),
            "https://foreign.example/app"
        );
        assert_eq!(
            rewrite_redirect("http://spl.local/sse/events", &journal_hosts, loopback),
            "http://127.0.0.1:49152/sse/events"
        );
        assert_eq!(
            rewrite_redirect("https://default.example:443/x", &journal_hosts, loopback),
            "http://127.0.0.1:49152/x"
        );
    }

    #[test]
    fn response_headers_filter_and_rewrite() {
        let names = names();
        let upstream = vec![
            ("content-type".to_string(), "text/html".to_string()),
            ("content-length".to_string(), "10".to_string()),
            ("transfer-encoding".to_string(), "chunked".to_string()),
            ("connection".to_string(), "close".to_string()),
            ("etag".to_string(), "\"abc\"".to_string()),
            ("x-content-type-options".to_string(), "nosniff".to_string()),
            (
                "set-cookie".to_string(),
                "sid=abc; Domain=journal.example; Secure; Path=/; HttpOnly".to_string(),
            ),
            (
                "location".to_string(),
                "https://journal.example/app?x=1#frag".to_string(),
            ),
            ("x-debug".to_string(), "drop".to_string()),
        ];
        let headers = response_headers(
            &upstream,
            &["journal.example".to_string()],
            "http://127.0.0.1:49152",
            &names,
        );

        assert!(headers.contains(&("content-type".to_string(), "text/html".to_string())));
        assert!(headers.contains(&("etag".to_string(), "\"abc\"".to_string())));
        assert!(headers.contains(&("x-content-type-options".to_string(), "nosniff".to_string())));
        assert!(headers.contains(&(
            "set-cookie".to_string(),
            "__journal_up_sid=abc; Path=/; HttpOnly".to_string()
        )));
        assert!(headers.contains(&(
            "location".to_string(),
            "http://127.0.0.1:49152/app?x=1#frag".to_string()
        )));
        assert!(!headers.iter().any(|(name, _)| matches!(
            name.as_str(),
            "content-length" | "transfer-encoding" | "connection" | "x-debug"
        )));
    }

    #[test]
    fn bootstrap_cap_extracts_only_exact_route_query() {
        assert_eq!(
            bootstrap_cap("/_bridge/bootstrap?cap=secret"),
            Some("secret")
        );
        assert_eq!(
            bootstrap_cap("/_bridge/bootstrap?x=1&cap=secret"),
            Some("secret")
        );
        assert_eq!(bootstrap_cap("/_bridge/bootstrap"), None);
        assert_eq!(bootstrap_cap("/_bridge/bootstrap/extra?cap=secret"), None);
        assert_eq!(bootstrap_cap("/?cap=secret"), None);
        assert_eq!(
            bootstrap_cookie_attributes(),
            "Path=/; HttpOnly; SameSite=Strict"
        );
    }

    #[test]
    fn failure_category_tokens_are_stable() {
        assert_eq!(FailureCategory::LocalBind.token(), "local_bind_fail");
        assert_eq!(
            FailureCategory::LocalCapabilityReject.token(),
            "local_capability_reject"
        );
        assert_eq!(
            FailureCategory::UpstreamUnreachable.token(),
            "upstream_unreachable"
        );
        assert_eq!(
            FailureCategory::UpstreamCredential.token(),
            "upstream_credential"
        );
        assert_eq!(RejectReason::BadHost.token(), "bad_host");
    }
}
