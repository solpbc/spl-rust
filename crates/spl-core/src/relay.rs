// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Pure helpers for constructing SPL relay dial URLs.

use thiserror::Error;

/// Errors produced while constructing a relay WebSocket URL.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DialUrlError {
    /// The relay origin does not use HTTP or HTTPS.
    #[error("unsupported relay origin scheme")]
    UnsupportedScheme,
}

/// Construct the instance-scoped relay dial WebSocket URL.
///
/// # Errors
///
/// Returns [`DialUrlError::UnsupportedScheme`] when `relay_origin` is not an
/// HTTP or HTTPS origin.
pub fn dial_url(relay_origin: &str, instance_id: &str) -> Result<String, DialUrlError> {
    relay_url(relay_origin, "/session/dial", instance_id)
}

/// Construct the relay pair-window dial WebSocket URL.
///
/// # Errors
///
/// Returns [`DialUrlError::UnsupportedScheme`] when `relay_origin` is not an
/// HTTP or HTTPS origin.
pub fn pair_dial_url(relay_origin: &str) -> Result<String, DialUrlError> {
    Ok(format!("{}/session/pair-dial", ws_origin(relay_origin)?))
}

/// Construct the home relay-listen WebSocket URL.
///
/// Protocol: `.proto-ref/session.md`, lines 23-45. Authentication is carried
/// only in the WebSocket `Authorization` header, never in this URL.
///
/// # Errors
///
/// Returns [`DialUrlError::UnsupportedScheme`] when `relay_origin` is not an
/// HTTP or HTTPS origin.
pub fn listen_url(relay_origin: &str) -> Result<String, DialUrlError> {
    Ok(format!("{}/session/listen", ws_origin(relay_origin)?))
}

/// Construct the home tunnel-attachment WebSocket URL.
///
/// Protocol: `.proto-ref/session.md`, lines 153-173. Authentication is carried
/// only in the WebSocket `Authorization` header, never in this URL.
///
/// # Errors
///
/// Returns [`DialUrlError::UnsupportedScheme`] when `relay_origin` is not an
/// HTTP or HTTPS origin.
pub fn tunnel_url(relay_origin: &str, tunnel_id: &str) -> Result<String, DialUrlError> {
    Ok(format!(
        "{}/tunnel/{}",
        ws_origin(relay_origin)?,
        percent_encode(tunnel_id)
    ))
}

/// A parsed listen control message.
#[derive(Clone, PartialEq, Eq)]
pub enum ListenControl {
    /// A relay-offered tunnel identifier.
    Incoming {
        /// Relay-assigned opaque tunnel identifier.
        tunnel_id: String,
    },
    /// A well-formed future control type that v1 ignores.
    Ignore,
    /// Malformed or incomplete control text.
    Invalid,
}

impl std::fmt::Debug for ListenControl {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Incoming { tunnel_id: _ } => formatter
                .debug_struct("Incoming")
                .field("tunnel_id", &"[REDACTED]")
                .finish(),
            Self::Ignore => formatter.write_str("Ignore"),
            Self::Invalid => formatter.write_str("Invalid"),
        }
    }
}

/// Parse a text-frame listen control message.
///
/// Protocol: `.proto-ref/session.md`, lines 153-161. Callers must pass only
/// WebSocket text frames; malformed controls are nonfatal and unknown types are
/// ignored.
pub fn parse_listen_control(text: &str) -> ListenControl {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return ListenControl::Invalid;
    };
    let Some(object) = value.as_object() else {
        return ListenControl::Invalid;
    };
    match object.get("type").and_then(serde_json::Value::as_str) {
        Some("incoming") => {}
        Some(_) => return ListenControl::Ignore,
        None => return ListenControl::Invalid,
    }
    let tunnel_id = match object.get("tunnel_id") {
        Some(serde_json::Value::String(value)) if !value.is_empty() => Some(value.clone()),
        Some(serde_json::Value::Number(value)) => value
            .as_i64()
            .map(|value| value.to_string())
            .or_else(|| value.as_u64().map(|value| value.to_string())),
        _ => None,
    };
    match tunnel_id {
        Some(tunnel_id) => ListenControl::Incoming { tunnel_id },
        None => ListenControl::Invalid,
    }
}

fn relay_url(relay_origin: &str, path: &str, instance_id: &str) -> Result<String, DialUrlError> {
    let origin = ws_origin(relay_origin)?;
    Ok(format!(
        "{origin}{path}?instance={}",
        percent_encode(instance_id)
    ))
}

fn ws_origin(relay_origin: &str) -> Result<String, DialUrlError> {
    let rewritten = if let Some(rest) = relay_origin.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = relay_origin.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        return Err(DialUrlError::UnsupportedScheme);
    };
    Ok(rewritten
        .strip_suffix('/')
        .unwrap_or(&rewritten)
        .to_string())
}

fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if is_unreserved(byte) {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(hex(byte >> 4));
            out.push(hex(byte & 0x0F));
        }
    }
    out
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn hex(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'A' + (nibble - 10)) as char,
        _ => unreachable!("nibble is masked to 4 bits"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_https_to_wss() {
        assert_eq!(
            dial_url("https://link.solstone.app", "inst").unwrap(),
            "wss://link.solstone.app/session/dial?instance=inst"
        );
    }

    #[test]
    fn rewrites_http_to_ws() {
        assert_eq!(
            dial_url("http://127.0.0.1:7657", "inst").unwrap(),
            "ws://127.0.0.1:7657/session/dial?instance=inst"
        );
    }

    #[test]
    fn trims_one_trailing_slash() {
        assert_eq!(
            dial_url("https://link.solstone.app/", "inst").unwrap(),
            "wss://link.solstone.app/session/dial?instance=inst"
        );
    }

    #[test]
    fn percent_encodes_query_value() {
        assert_eq!(
            dial_url("https://link.solstone.app", "inst one/two").unwrap(),
            "wss://link.solstone.app/session/dial?instance=inst%20one%2Ftwo"
        );
    }

    #[test]
    fn rejects_unsupported_scheme() {
        assert_eq!(
            dial_url("wss://link.solstone.app", "inst").unwrap_err(),
            DialUrlError::UnsupportedScheme
        );
    }

    #[test]
    fn builds_normal_relay_url() {
        assert_eq!(
            dial_url("https://link.solstone.app", "inst-123").unwrap(),
            "wss://link.solstone.app/session/dial?instance=inst-123"
        );
    }

    #[test]
    fn pair_dial_rewrites_https_to_wss() {
        assert_eq!(
            pair_dial_url("https://link.solstone.app").unwrap(),
            "wss://link.solstone.app/session/pair-dial"
        );
    }

    #[test]
    fn pair_dial_rewrites_http_to_ws() {
        assert_eq!(
            pair_dial_url("http://127.0.0.1:7657").unwrap(),
            "ws://127.0.0.1:7657/session/pair-dial"
        );
    }

    #[test]
    fn pair_dial_trims_one_trailing_slash() {
        assert_eq!(
            pair_dial_url("https://link.solstone.app/").unwrap(),
            "wss://link.solstone.app/session/pair-dial"
        );
    }

    #[test]
    fn pair_dial_rejects_unsupported_scheme() {
        assert_eq!(
            pair_dial_url("wss://link.solstone.app").unwrap_err(),
            DialUrlError::UnsupportedScheme
        );
    }
}
