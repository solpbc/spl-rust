// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Instance capability v2 wire checks, per `.proto-ref/tokens.md`.
//!
//! These are decoding checks on authenticated HTTPS/mTLS responses, not JWT
//! signature verification. The relay verifies its own signature at use.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::jwt::JwtClaims;

/// A ready capability supplied by the home inside the encrypted pair response.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayAccess {
    /// Explicit response negotiation discriminator.
    pub protocol_version: u8,
    /// Must be `ready` for pairing bootstrap.
    pub status: String,
    /// Relay endpoint under the consuming transport's origin policy.
    pub relay_origin: String,
    /// Paired home identity, never a device identity.
    pub instance_id: String,
    /// Instance admission bearer, using the legacy storage field name.
    pub device_token: String,
    /// RFC3339 expiration matching the token's integer `exp`.
    pub expires_at: String,
}

impl std::fmt::Debug for RelayAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayAccess").finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstanceClaims {
    iss: String,
    sub: String,
    aud: String,
    scope: String,
    ver: u8,
    instance_id: String,
    iat: i64,
    exp: i64,
    jti: String,
}

/// Decode a JWT payload for self-held credential inspection only.
pub fn unverified_payload(token: &str) -> Option<serde_json::Value> {
    let mut parts = token.split('.');
    if parts.next()?.is_empty() {
        return None;
    }
    let payload = parts.next()?;
    if parts.next()?.is_empty() || parts.next().is_some() {
        return None;
    }
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()
}

/// Validate the exact instance-only claim shape against a paired home and time.
/// No clock or signature verifier is invoked by this pure function.
pub fn instance_claims(token: &str, instance_id: &str, now: i64) -> Option<JwtClaims> {
    let claims: InstanceClaims = serde_json::from_value(unverified_payload(token)?).ok()?;
    if claims.ver != 2
        || claims.aud != "spl-relay"
        || claims.scope != "session.dial"
        || claims.instance_id != instance_id
        || claims.sub != format!("instance:{instance_id}")
        || claims.iss.is_empty()
        || claims.jti.is_empty()
        || claims.exp <= now
        || claims.exp <= claims.iat
        || claims.iat > now.saturating_add(60)
    {
        return None;
    }
    Some(JwtClaims {
        iat: claims.iat,
        exp: claims.exp,
    })
}

/// Validate a legacy dial capability returned by an older relay.
/// This remains an unverified decode check, never authorization.
pub fn legacy_claims(token: &str, instance_id: &str, now: i64) -> Option<JwtClaims> {
    let payload = unverified_payload(token)?;
    let object = payload.as_object()?;
    let sub = object.get("sub")?.as_str()?.strip_prefix("device:")?;
    let fp = object.get("device_fp")?.as_str()?.strip_prefix("sha256:")?;
    let claims = crate::jwt::decode_unverified_claims(token)?;
    if object.contains_key("ver")
        || sub.is_empty()
        || fp.len() != 64
        || !fp.bytes().all(|b| b.is_ascii_hexdigit())
        || object.get("instance_id")?.as_str()? != instance_id
        || object.get("aud")?.as_str()? != "spl-relay"
        || object.get("scope")?.as_str()? != "session.dial"
        || object.get("iss")?.as_str()?.is_empty()
        || object.get("jti")?.as_str()?.is_empty()
        || claims.exp <= now
        || claims.exp <= claims.iat
        || claims.iat > now.saturating_add(60)
    {
        return None;
    }
    Some(claims)
}

/// Validate negotiated v2 access and matching RFC3339 expiration.
/// The caller separately validates the relay origin using its transport policy.
pub fn negotiated_claims(
    protocol_version: u8,
    token: &str,
    expires_at: &str,
    instance_id: &str,
    now: i64,
) -> Option<JwtClaims> {
    if protocol_version != 2 {
        return None;
    }
    let claims = instance_claims(token, instance_id, now)?;
    let expiry = OffsetDateTime::parse(expires_at, &Rfc3339).ok()?;
    if expiry.unix_timestamp() != claims.exp || expiry.nanosecond() != 0 {
        return None;
    }
    Some(claims)
}

impl RelayAccess {
    /// Check ready-state, paired identity and negotiated token shape/expiry.
    pub fn claims(&self, instance_id: &str, now: i64) -> Option<JwtClaims> {
        if self.status != "ready" || self.instance_id != instance_id {
            return None;
        }
        negotiated_claims(
            self.protocol_version,
            &self.device_token,
            &self.expires_at,
            instance_id,
            now,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn claims() -> serde_json::Value {
        json!({"iss":"independent-issuer","sub":"instance:home","aud":"spl-relay",
            "scope":"session.dial","ver":2,"instance_id":"home","iat":100,"exp":200,"jti":"fresh"})
    }

    fn token(payload: &serde_json::Value) -> String {
        format!("e30.{}.sig", URL_SAFE_NO_PAD.encode(payload.to_string()))
    }

    #[test]
    fn negotiated_access_checks_identity_shape_and_exact_expiry() {
        let valid = token(&claims());
        assert!(negotiated_claims(2, &valid, "1970-01-01T00:03:20Z", "home", 150).is_some());
        assert!(negotiated_claims(2, &valid, "1970-01-01T00:03:20.001Z", "home", 150).is_none());
        assert!(negotiated_claims(2, &valid, "1970-01-01T00:03:21Z", "home", 150).is_none());
        assert!(negotiated_claims(1, &valid, "1970-01-01T00:03:20Z", "home", 150).is_none());
        assert!(instance_claims(&valid, "other-home", 150).is_none());
        assert!(instance_claims(&valid, "home", 200).is_none());
        for (field, value) in [
            ("ver", json!(3)),
            ("device_fp", json!("private")),
            ("ca_fp", json!("private")),
            ("previous_jti", json!("old")),
            ("iat", json!(211)),
            ("exp", json!(100)),
            ("exp", json!(200.5)),
            ("sub", json!("device:old")),
            ("scope", json!("session.listen")),
            ("aud", json!("other")),
            ("iss", json!("")),
            ("jti", json!("")),
        ] {
            let mut bad = claims();
            bad[field] = value;
            assert!(
                instance_claims(&token(&bad), "home", 150).is_none(),
                "{field}"
            );
        }
        for bad in ["a.b.c.d", ".e30.sig", "e30.e30.", "e30.!!!!.sig"] {
            assert!(instance_claims(bad, "home", 150).is_none());
        }
    }
}
