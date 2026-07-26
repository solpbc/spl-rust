// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Minimal JWT claim decoding for relay device-token lifetime checks.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq)]
/// Unverified JWT timestamps used only for refresh scheduling.
pub struct JwtClaims {
    /// Token issuance time as Unix seconds.
    pub iat: i64,
    /// Token expiration time as Unix seconds.
    pub exp: i64,
}

#[derive(Deserialize)]
struct RawClaims {
    iat: i64,
    exp: i64,
}

/// Decode token lifetime claims without authenticating the JWT. This is a
/// self-held token lifetime hint only; it is not an authorization decision.
pub fn decode_unverified_claims(token: &str) -> Option<JwtClaims> {
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    let _signature = parts.next()?;
    if parts.next().is_some() {
        return None;
    }

    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let raw: RawClaims = serde_json::from_slice(&decoded).ok()?;
    Some(JwtClaims {
        iat: raw.iat,
        exp: raw.exp,
    })
}

/// Whether the current time is past four-fifths of a positive token lifetime.
pub fn should_refresh(claims: &JwtClaims, now_secs: i64) -> bool {
    let Some(ttl) = claims.exp.checked_sub(claims.iat) else {
        return false;
    };
    if ttl <= 0 {
        return false;
    }
    let Some(scaled_ttl) = ttl.checked_mul(4) else {
        return false;
    };
    let Some(refresh_at) = claims.iat.checked_add(scaled_ttl / 5) else {
        return false;
    };
    now_secs > refresh_at
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token_with_payload(payload: &[u8]) -> String {
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(b"{}"),
            URL_SAFE_NO_PAD.encode(payload),
            "sig"
        )
    }

    #[test]
    fn decodes_valid_claims() {
        let token = token_with_payload(br#"{"iat":100,"exp":200}"#);
        assert_eq!(
            decode_unverified_claims(&token),
            Some(JwtClaims { iat: 100, exp: 200 })
        );
    }

    #[test]
    fn malformed_tokens_decode_to_none() {
        assert_eq!(decode_unverified_claims("two.parts"), None);
        assert_eq!(decode_unverified_claims("too.many.parts.here"), None);
        assert_eq!(decode_unverified_claims("header.!!!!.sig"), None);
        assert_eq!(
            decode_unverified_claims(&token_with_payload(b"not json")),
            None
        );
        assert_eq!(
            decode_unverified_claims(&token_with_payload(br#"{"iat":100}"#)),
            None
        );
        assert_eq!(
            decode_unverified_claims(&token_with_payload(br#"{"iat":"100","exp":200}"#)),
            None
        );
    }

    #[test]
    fn refresh_boundary_is_strictly_greater_than_eighty_percent() {
        let claims = JwtClaims { iat: 100, exp: 200 };
        assert!(!should_refresh(&claims, 180));
        assert!(should_refresh(&claims, 181));
    }

    #[test]
    fn expired_positive_ttl_refreshes() {
        let claims = JwtClaims { iat: 100, exp: 200 };
        assert!(should_refresh(&claims, 250));
    }

    #[test]
    fn non_positive_ttl_does_not_refresh() {
        assert!(!should_refresh(&JwtClaims { iat: 200, exp: 200 }, 300));
        assert!(!should_refresh(&JwtClaims { iat: 201, exp: 200 }, 300));
    }

    #[test]
    fn extreme_and_degenerate_claims_are_total() {
        let cases = [
            (
                JwtClaims {
                    iat: i64::MIN,
                    exp: i64::MAX,
                },
                0,
                false,
            ),
            (
                JwtClaims {
                    iat: 0,
                    exp: i64::MAX,
                },
                0,
                false,
            ),
            (JwtClaims { iat: 200, exp: 100 }, 150, false),
            (JwtClaims { iat: 100, exp: 100 }, 100, false),
            (JwtClaims { iat: 100, exp: 200 }, i64::MIN, false),
            (JwtClaims { iat: 100, exp: 200 }, i64::MAX, true),
        ];

        for (claims, now_secs, expected) in cases {
            assert_eq!(should_refresh(&claims, now_secs), expected);
        }
    }
}
