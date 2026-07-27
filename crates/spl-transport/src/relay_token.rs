// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Low-level relay device-token refresh helpers consumed by `TransportClient`.
//!
//! The refresh-once/redial-once policy lives in the client relay dial path.

use serde::Deserialize;
use serde_json::json;

use crate::{TransportError, relay_http};

#[derive(Debug, PartialEq, Eq)]
/// Result of a best-effort relay device-token refresh.
pub enum RefreshOutcome {
    /// A replacement token and its Unix expiry were returned.
    Refreshed {
        /// Replacement relay device token.
        device_token: String,
        /// Replacement token expiry as Unix seconds.
        expires_at: i64,
    },
    /// The device must repeat relay enrollment before dialing again. A stored
    /// home attestation is bound to a pairing window of at most five minutes; once
    /// that window has elapsed, enrollment requires a new pairing ceremony.
    ReconnectNeeded,
    /// A transient control-plane failure left the current token unchanged.
    TransientError,
}

#[derive(Deserialize)]
struct RefreshResponse {
    device_token: String,
}

/// Attempt one relay device-token refresh without exposing control-plane errors.
pub async fn refresh_device_token(relay_origin: &str, current_token: &str) -> RefreshOutcome {
    #[expect(
        clippy::large_futures,
        reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
    )]
    let refresh = refresh_device_token_inner(relay_origin, current_token).await;
    match refresh {
        Ok(outcome) => outcome,
        Err(_) => RefreshOutcome::TransientError,
    }
}

async fn refresh_device_token_inner(
    relay_origin: &str,
    current_token: &str,
) -> Result<RefreshOutcome, TransportError> {
    let body = serde_json::to_vec(&json!({ "device_token": current_token }))?;
    #[expect(
        clippy::large_futures,
        reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
    )]
    let response = relay_http::relay_https_post_json(relay_origin, "/token/refresh", &body).await?;
    if response.is_success() {
        let parsed: RefreshResponse = serde_json::from_slice(&response.body)
            .map_err(|_| TransportError::Pairing("relay refresh response malformed".into()))?;
        let claims = spl_core::jwt::decode_unverified_claims(&parsed.device_token)
            .ok_or_else(|| TransportError::Pairing("relay refresh response malformed".into()))?;
        return Ok(RefreshOutcome::Refreshed {
            device_token: parsed.device_token,
            expires_at: claims.exp,
        });
    }

    match response.status {
        401 if expired_reason(&response.body) => Ok(RefreshOutcome::ReconnectNeeded),
        403 | 404 => Ok(RefreshOutcome::ReconnectNeeded),
        _ => Ok(RefreshOutcome::TransientError),
    }
}

fn expired_reason(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("reason")
                .and_then(|reason| reason.as_str())
                .map(|reason| reason == "expired")
        })
        .unwrap_or(false)
}
