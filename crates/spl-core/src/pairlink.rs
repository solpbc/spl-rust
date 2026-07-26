// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Pair-link parsing.
//!
//! A journal QR / pasted pair-link is `https://go.solstone.app/p#<fragment>`,
//! where `<fragment>` is Crockford base32 over a small binary blob. We parse the
//! LAN-direct shapes and the relay form the journal emits:
//!
//! - **v06** (relay pair-window): `0x06 S(8) ca_fp_tag(1)=0x01
//!   ca_fp_spki(16) relay_origin_selector(1) origin?` = 27 B base
//! - **v04** (single IPv4): `0x04 0x01 ip(4) port(2,BE) nonce(16) ca_fp(16)` = 40 B
//! - **v05** (multi IPv4, current): `0x05 0x01 count port(2,BE) ip(4)*count
//!   nonce(16) ca_fp(16)` = 37 + 4*count B
//!
//! Byte layout follows the vendored SPL pairing protocol and is shared by every
//! consumer implementation. Port 0 means
//! [`DEFAULT_DIRECT_PORT`](crate::DEFAULT_DIRECT_PORT). Direct addresses are
//! limited to RFC 1918, 169.254/16, 100.64/10, and 127/8 (loopback is admitted);
//! one disallowed address refuses the whole link. V05 accepts one through four
//! raw candidates and coalesces duplicates in first-occurrence order. The CA
//! fingerprint is the 16-byte SHA-256-of-CA-cert-DER prefix the TLS layer pins.

use thiserror::Error;

use crate::DEFAULT_DIRECT_PORT;
use crate::crockford::{self, CrockfordError};

/// Default relay origin selected by relay-form selector `0x00`.
pub const DEFAULT_RELAY_ORIGIN: &str = "https://link.solstone.app";

/// One dialable journal address from the pair-link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// IPv4 address in dotted-decimal notation.
    pub host: String,
    /// Normalized TCP port for the direct pairing endpoint.
    pub port: u16,
}

/// A parsed LAN-direct pair-link: where to reach the journal, the one-shot
/// pairing nonce, and the CA-fingerprint prefix to pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairLink {
    /// Policy-approved, de-duplicated journal endpoints in first-occurrence
    /// pair-link order.
    pub candidates: Vec<Endpoint>,
    /// The pairing nonce, lowercase hex (32 chars for the 16 raw bytes).
    pub nonce_hex: String,
    /// SHA-256(CA cert DER) prefix — 16 bytes — pinned at the TLS handshake.
    pub ca_fp_prefix: Vec<u8>,
}

/// Parsed pair-link variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedPairLink {
    /// A LAN-direct link containing one or more IPv4 candidates.
    Direct(PairLink),
    /// An off-LAN relay pair-window link.
    Relay(RelayPairLink),
}

/// A parsed relay pair-window link: the 8-byte relay secret, the relay target,
/// and the SPKI fingerprint prefix used later for live-peer binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayPairLink {
    /// Eight-byte single-use pair-window secret.
    pub s: [u8; 8],
    /// First 16 bytes of SHA-256 over the journal CA's SPKI DER.
    pub ca_fp_spki: Vec<u8>,
    /// Selected relay origin, including its HTTP or HTTPS scheme.
    pub relay_origin: String,
}

/// Errors produced while decoding and validating pair-links.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PairLinkError {
    /// A URL was supplied without its fragment payload.
    #[error("pair-link missing the '#<fragment>' part")]
    MissingFragment,
    /// The fragment is not valid Crockford base32.
    #[error("pair-link fragment is not valid crockford base32: {0}")]
    Crockford(#[from] CrockfordError),
    /// The decoded form version is not implemented.
    #[error("unsupported pair-link version byte: {0:#x}")]
    UnsupportedVersion(u8),
    /// A direct form uses an address tag other than IPv4.
    #[error("unsupported pair-link address type: {0:#x}")]
    UnsupportedAddressType(u8),
    /// A relay form uses an unsupported CA fingerprint algorithm tag.
    #[error("unsupported relay CA-fingerprint tag: {0:#x}")]
    UnknownCaFpTag(u8),
    /// A custom relay origin is not valid UTF-8.
    #[error("relay origin is not valid UTF-8")]
    BadRelayOrigin,
    /// The blob ends before all fields required by its form are present.
    #[error("pair-link blob truncated (expected {expected} bytes, got {got})")]
    Truncated {
        /// Minimum byte length required at the point of failure.
        expected: usize,
        /// Actual decoded blob length.
        got: usize,
    },
    /// An exact-length relay form contains too few or too many bytes.
    #[error("pair-link blob length mismatch (expected {expected} bytes, got {got})")]
    LengthMismatch {
        /// Exact byte length selected by the form.
        expected: usize,
        /// Actual decoded blob length.
        got: usize,
    },
    /// A direct candidate falls outside the protocol allow-list.
    #[error("direct pair-link address is outside the allowed IPv4 ranges: {address}")]
    DisallowedDirectIpv4 {
        /// Refused address in dotted-decimal notation.
        address: String,
    },
    /// A multi-candidate form advertises zero or more than four addresses.
    #[error("direct pair-link candidate count must be between 1 and 4, got {count}")]
    InvalidCandidateCount {
        /// Candidate count encoded in the pair-link.
        count: u8,
    },
}

const ADDR_TYPE_IPV4: u8 = 0x01;
const NONCE_LEN: usize = 16;
const CA_FP_LEN: usize = 16;
const MAX_DIRECT_CANDIDATES: u8 = 4;
const ALLOWED_DIRECT_IPV4_RANGES: [(u32, u32); 6] = [
    (0x0a00_0000, 0x0aff_ffff), // 10/8
    (0xac10_0000, 0xac1f_ffff), // 172.16/12
    (0xc0a8_0000, 0xc0a8_ffff), // 192.168/16
    (0xa9fe_0000, 0xa9fe_ffff), // 169.254/16
    (0x6440_0000, 0x647f_ffff), // 100.64/10
    (0x7f00_0000, 0x7fff_ffff), // 127/8
];
const RELAY_CA_FP_TAG_SPKI_SHA256: u8 = 0x01;
const RELAY_WINDOW_BASE_LEN: usize = 27;

#[expect(
    clippy::format_push_string,
    reason = "the fixed two-digit byte format is clearest at the append site"
)]
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "borrowing matches the adjacent parser slices and avoids a wire-helper special case"
)]
fn ipv4_string(octets: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
}

pub(crate) fn uuid_string(raw: &[u8]) -> String {
    let h = hex_lower(raw);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "borrowing keeps address admission consistent with parsed wire slices"
)]
fn is_allowed_direct_ipv4(octets: &[u8; 4]) -> bool {
    let address = u32::from_be_bytes(*octets);
    ALLOWED_DIRECT_IPV4_RANGES
        .iter()
        .any(|(lo, hi)| (*lo..=*hi).contains(&address))
}

fn normalize_port(raw: u16) -> u16 {
    if raw == 0 { DEFAULT_DIRECT_PORT } else { raw }
}

/// Parse a full pair-link URL (or a bare fragment).
///
/// # Errors
///
/// Returns [`PairLinkError`] when the fragment is missing, its Crockford text
/// or binary form is malformed, or direct-address admission rejects a
/// candidate.
pub fn parse(link: &str) -> Result<ParsedPairLink, PairLinkError> {
    let fragment = match link.split_once('#') {
        Some((_, frag)) => frag,
        // Allow callers to pass a bare fragment too.
        None if !link.contains("://") && !link.contains('/') => link,
        None => return Err(PairLinkError::MissingFragment),
    };
    let blob = crockford::decode(fragment)?;
    parse_blob(&blob)
}

/// Parse the decoded binary blob.
///
/// # Errors
///
/// Returns [`PairLinkError`] when the version or field tags are unsupported,
/// the selected form is structurally malformed, or a direct candidate is not
/// admitted by policy.
pub fn parse_blob(blob: &[u8]) -> Result<ParsedPairLink, PairLinkError> {
    let version = *blob.first().ok_or(PairLinkError::Truncated {
        expected: 1,
        got: 0,
    })?;
    match version {
        0x04 => parse_v04(blob).map(ParsedPairLink::Direct),
        0x05 => parse_v05(blob).map(ParsedPairLink::Direct),
        0x06 => parse_v06(blob).map(ParsedPairLink::Relay),
        other => Err(PairLinkError::UnsupportedVersion(other)),
    }
}

fn require(blob: &[u8], end: usize) -> Result<(), PairLinkError> {
    if blob.len() < end {
        Err(PairLinkError::Truncated {
            expected: end,
            got: blob.len(),
        })
    } else {
        Ok(())
    }
}

#[expect(
    clippy::if_not_else,
    reason = "the mismatch-first branch mirrors the emitted LengthMismatch error"
)]
fn require_exact(blob: &[u8], expected: usize) -> Result<(), PairLinkError> {
    require(blob, expected)?;
    if blob.len() != expected {
        Err(PairLinkError::LengthMismatch {
            expected,
            got: blob.len(),
        })
    } else {
        Ok(())
    }
}

#[expect(
    clippy::expect_used,
    reason = "the preceding exact base-length check guarantees the eight-byte slice"
)]
fn parse_v06(blob: &[u8]) -> Result<RelayPairLink, PairLinkError> {
    require(blob, RELAY_WINDOW_BASE_LEN)?;
    let ca_fp_tag = blob[9];
    if ca_fp_tag != RELAY_CA_FP_TAG_SPKI_SHA256 {
        return Err(PairLinkError::UnknownCaFpTag(ca_fp_tag));
    }

    let selector = blob[26] as usize;
    let relay_origin = if selector == 0 {
        require_exact(blob, RELAY_WINDOW_BASE_LEN)?;
        DEFAULT_RELAY_ORIGIN.to_string()
    } else {
        let expected = RELAY_WINDOW_BASE_LEN + selector;
        require_exact(blob, expected)?;
        std::str::from_utf8(&blob[RELAY_WINDOW_BASE_LEN..expected])
            .map_err(|_| PairLinkError::BadRelayOrigin)?
            .to_string()
    };

    Ok(RelayPairLink {
        s: blob[1..9].try_into().expect("slice length is fixed"),
        ca_fp_spki: blob[10..26].to_vec(),
        relay_origin,
    })
}

fn parse_v04(blob: &[u8]) -> Result<PairLink, PairLinkError> {
    const TOTAL: usize = 40;
    require(blob, TOTAL)?;
    if blob[1] != ADDR_TYPE_IPV4 {
        return Err(PairLinkError::UnsupportedAddressType(blob[1]));
    }
    let octets = [blob[2], blob[3], blob[4], blob[5]];
    let port = normalize_port(u16::from_be_bytes([blob[6], blob[7]]));
    let nonce = &blob[8..8 + NONCE_LEN];
    let ca_fp = &blob[24..24 + CA_FP_LEN];

    if !is_allowed_direct_ipv4(&octets) {
        return Err(PairLinkError::DisallowedDirectIpv4 {
            address: ipv4_string(&octets),
        });
    }
    Ok(PairLink {
        candidates: vec![Endpoint {
            host: ipv4_string(&octets),
            port,
        }],
        nonce_hex: hex_lower(nonce),
        ca_fp_prefix: ca_fp.to_vec(),
    })
}

fn parse_v05(blob: &[u8]) -> Result<PairLink, PairLinkError> {
    require(blob, 3)?;
    if blob[1] != ADDR_TYPE_IPV4 {
        return Err(PairLinkError::UnsupportedAddressType(blob[1]));
    }
    let raw_count = blob[2];
    if raw_count == 0 || raw_count > MAX_DIRECT_CANDIDATES {
        return Err(PairLinkError::InvalidCandidateCount { count: raw_count });
    }
    let count = raw_count as usize;
    require(blob, 5)?;
    let port = normalize_port(u16::from_be_bytes([blob[3], blob[4]]));
    let addrs_start = 5;
    let addrs_end = addrs_start + 4 * count;
    let nonce_end = addrs_end + NONCE_LEN;
    let total = nonce_end + CA_FP_LEN;
    require(blob, total)?;

    for i in 0..count {
        let offset = addrs_start + 4 * i;
        let octets = [
            blob[offset],
            blob[offset + 1],
            blob[offset + 2],
            blob[offset + 3],
        ];
        if !is_allowed_direct_ipv4(&octets) {
            return Err(PairLinkError::DisallowedDirectIpv4 {
                address: ipv4_string(&octets),
            });
        }
    }

    let mut candidates = Vec::with_capacity(count);
    for i in 0..count {
        let offset = addrs_start + 4 * i;
        let octets = [
            blob[offset],
            blob[offset + 1],
            blob[offset + 2],
            blob[offset + 3],
        ];
        let host = ipv4_string(&octets);
        if !candidates
            .iter()
            .any(|candidate: &Endpoint| candidate.host == host && candidate.port == port)
        {
            candidates.push(Endpoint { host, port });
        }
    }
    let nonce = &blob[addrs_end..nonce_end];
    let ca_fp = &blob[nonce_end..total];
    Ok(PairLink {
        candidates,
        nonce_hex: hex_lower(nonce),
        ca_fp_prefix: ca_fp.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crockford;

    const RELAY_WELL_KNOWN_FRAGMENT: &str = "0R0J6HB7H6NWVVR1VTPVXVYAZTXBW0938NKRKAYDXW00";
    const RELAY_CUSTOM_FRAGMENT: &str =
        "0R0J6HB7H6NWVVR1VTPVXVYAZTXBW0938NKRKAYDXWAPGX3ME1SKMBSFE9JPRRBS5SJQGRBDE1P6A";

    fn direct(parsed: ParsedPairLink) -> PairLink {
        match parsed {
            ParsedPairLink::Direct(pl) => pl,
            ParsedPairLink::Relay(_) => panic!("expected direct pair-link"),
        }
    }

    fn relay(parsed: ParsedPairLink) -> RelayPairLink {
        match parsed {
            ParsedPairLink::Relay(pl) => pl,
            ParsedPairLink::Direct(_) => panic!("expected relay pair-link"),
        }
    }

    fn nonce16() -> [u8; 16] {
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ]
    }
    fn cafp16() -> [u8; 16] {
        [
            0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad,
            0xae, 0xaf,
        ]
    }
    fn relay_s() -> [u8; 8] {
        [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
    }

    fn relay_ca_fp_spki() -> [u8; 16] {
        [
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef,
        ]
    }

    fn build_v05(addrs: &[[u8; 4]], port: u16) -> Vec<u8> {
        let mut b = vec![0x05, 0x01, addrs.len() as u8];
        b.extend_from_slice(&port.to_be_bytes());
        for a in addrs {
            b.extend_from_slice(a);
        }
        b.extend_from_slice(&nonce16());
        b.extend_from_slice(&cafp16());
        b
    }

    fn build_v04(addr: [u8; 4], port: u16) -> Vec<u8> {
        let mut b = vec![0x04, 0x01];
        b.extend_from_slice(&addr);
        b.extend_from_slice(&port.to_be_bytes());
        b.extend_from_slice(&nonce16());
        b.extend_from_slice(&cafp16());
        b
    }

    fn build_v06(origin: Option<&str>, ca_fp_tag: u8) -> Vec<u8> {
        let mut b = vec![0x06];
        b.extend_from_slice(&relay_s());
        b.push(ca_fp_tag);
        b.extend_from_slice(&relay_ca_fp_spki());
        match origin {
            Some(origin) => {
                b.push(origin.len() as u8);
                b.extend_from_slice(origin.as_bytes());
            }
            None => b.push(0),
        }
        b
    }

    fn assert_relay_fields(pl: RelayPairLink, relay_origin: &str) {
        assert_eq!(pl.s, relay_s());
        assert_eq!(pl.ca_fp_spki, relay_ca_fp_spki().to_vec());
        assert_eq!(pl.relay_origin, relay_origin);
    }

    #[test]
    fn allowed_direct_ipv4_ranges_include_exact_boundaries() {
        for address in [
            [10, 0, 0, 0],
            [10, 255, 255, 255],
            [172, 16, 0, 0],
            [172, 31, 255, 255],
            [192, 168, 0, 0],
            [192, 168, 255, 255],
            [169, 254, 0, 0],
            [169, 254, 255, 255],
            [100, 64, 0, 0],
            [100, 127, 255, 255],
            [127, 0, 0, 0],
            [127, 255, 255, 255],
        ] {
            assert!(
                is_allowed_direct_ipv4(&address),
                "{} should be allowed",
                ipv4_string(&address)
            );
        }
    }

    #[test]
    fn addresses_immediately_outside_allowed_ranges_are_rejected() {
        for address in [
            [9, 255, 255, 255],
            [11, 0, 0, 0],
            [172, 15, 255, 255],
            [172, 32, 0, 0],
            [192, 167, 255, 255],
            [192, 169, 0, 0],
            [169, 253, 255, 255],
            [169, 255, 0, 0],
            [100, 63, 255, 255],
            [100, 128, 0, 0],
            [126, 255, 255, 255],
            [128, 0, 0, 0],
            [0, 0, 0, 0],
            [255, 255, 255, 255],
            [224, 0, 0, 1],
            [192, 0, 2, 42],
            [198, 51, 100, 20],
            [203, 0, 113, 5],
            [198, 18, 0, 1],
            [8, 8, 8, 8],
        ] {
            assert!(
                !is_allowed_direct_ipv4(&address),
                "{} should be rejected",
                ipv4_string(&address)
            );
        }
    }

    #[test]
    fn parses_v05_multi_address() {
        let blob = build_v05(&[[192, 168, 2, 10], [100, 64, 100, 20]], 7657);
        let url = format!("https://go.solstone.app/p#{}", crockford::encode(&blob));
        let pl = direct(parse(&url).unwrap());
        assert_eq!(
            pl.candidates,
            vec![
                Endpoint {
                    host: "192.168.2.10".into(),
                    port: 7657
                },
                Endpoint {
                    host: "100.64.100.20".into(),
                    port: 7657
                },
            ]
        );
        assert_eq!(pl.nonce_hex, "000102030405060708090a0b0c0d0e0f");
        assert_eq!(pl.ca_fp_prefix, cafp16().to_vec());
    }

    #[test]
    fn parses_v04_single_address() {
        let blob = build_v04([10, 0, 0, 5], 7657);
        let pl = direct(parse(&crockford::encode(&blob)).unwrap());
        assert_eq!(pl.candidates.len(), 1);
        assert_eq!(pl.candidates[0].host, "10.0.0.5");
        assert_eq!(pl.ca_fp_prefix.len(), 16);
    }

    #[test]
    fn parses_v04_cgnat_single_address() {
        let blob = build_v04([100, 64, 0, 1], 7657);
        let pl = direct(parse_blob(&blob).unwrap());
        assert_eq!(
            pl.candidates,
            vec![Endpoint {
                host: "100.64.0.1".into(),
                port: 7657,
            }]
        );
    }

    #[test]
    fn v04_rejects_disallowed_direct_ipv4_with_address_only() {
        let blob = build_v04([192, 0, 2, 42], 7657);
        assert_eq!(
            parse_blob(&blob).unwrap_err(),
            PairLinkError::DisallowedDirectIpv4 {
                address: "192.0.2.42".into(),
            }
        );
    }

    #[test]
    fn port_zero_defaults_to_direct_port() {
        let blob = build_v05(&[[10, 0, 0, 5]], 0);
        let pl = direct(parse_blob(&blob).unwrap());
        assert_eq!(pl.candidates[0].port, DEFAULT_DIRECT_PORT);
    }

    #[test]
    fn admits_loopback_candidates_in_pair_link_order() {
        let blob = build_v05(&[[127, 0, 0, 1], [192, 168, 1, 9]], 7657);
        let pl = direct(parse_blob(&blob).unwrap());
        assert_eq!(
            pl.candidates,
            vec![
                Endpoint {
                    host: "127.0.0.1".into(),
                    port: 7657,
                },
                Endpoint {
                    host: "192.168.1.9".into(),
                    port: 7657,
                },
            ]
        );
    }

    #[test]
    fn admits_single_loopback_candidate() {
        let blob = build_v05(&[[127, 0, 0, 1]], 7657);
        assert_eq!(
            direct(parse_blob(&blob).unwrap()).candidates,
            vec![Endpoint {
                host: "127.0.0.1".into(),
                port: 7657,
            }]
        );
    }

    #[test]
    fn v05_rejects_disallowed_member_in_every_position() {
        let allowed_a = [10, 0, 0, 1];
        let allowed_b = [192, 168, 1, 2];
        let disallowed = [192, 0, 2, 42];
        for addresses in [
            [disallowed, allowed_a, allowed_b],
            [allowed_a, disallowed, allowed_b],
            [allowed_a, allowed_b, disallowed],
        ] {
            let result = parse_blob(&build_v05(&addresses, 7657));
            assert!(result.is_err());
            assert_eq!(
                result.unwrap_err(),
                PairLinkError::DisallowedDirectIpv4 {
                    address: "192.0.2.42".into(),
                }
            );
        }
    }

    #[test]
    fn v05_rejects_candidate_counts_outside_one_through_four() {
        assert_eq!(
            parse_blob(&build_v05(&[], 7657)).unwrap_err(),
            PairLinkError::InvalidCandidateCount { count: 0 }
        );
        assert_eq!(
            parse_blob(&build_v05(
                &[
                    [10, 0, 0, 1],
                    [10, 0, 0, 2],
                    [10, 0, 0, 3],
                    [10, 0, 0, 4],
                    [10, 0, 0, 5],
                ],
                7657,
            ))
            .unwrap_err(),
            PairLinkError::InvalidCandidateCount { count: 5 }
        );
    }

    #[test]
    fn v05_count_four_round_trips_fields_and_normalizes_port() {
        let pl = direct(
            parse_blob(&build_v05(
                &[
                    [10, 0, 0, 1],
                    [172, 16, 0, 2],
                    [192, 168, 0, 3],
                    [100, 64, 0, 4],
                ],
                0,
            ))
            .unwrap(),
        );
        assert_eq!(
            pl.candidates,
            vec![
                Endpoint {
                    host: "10.0.0.1".into(),
                    port: DEFAULT_DIRECT_PORT,
                },
                Endpoint {
                    host: "172.16.0.2".into(),
                    port: DEFAULT_DIRECT_PORT,
                },
                Endpoint {
                    host: "192.168.0.3".into(),
                    port: DEFAULT_DIRECT_PORT,
                },
                Endpoint {
                    host: "100.64.0.4".into(),
                    port: DEFAULT_DIRECT_PORT,
                },
            ]
        );
        assert_eq!(pl.nonce_hex, "000102030405060708090a0b0c0d0e0f");
        assert_eq!(pl.ca_fp_prefix, cafp16());
    }

    #[test]
    fn v05_coalesces_duplicate_candidates_in_first_occurrence_order() {
        let pl = direct(
            parse_blob(&build_v05(
                &[
                    [10, 0, 0, 1],
                    [192, 168, 0, 2],
                    [10, 0, 0, 1],
                    [100, 64, 0, 3],
                ],
                7657,
            ))
            .unwrap(),
        );
        assert_eq!(
            pl.candidates,
            vec![
                Endpoint {
                    host: "10.0.0.1".into(),
                    port: 7657,
                },
                Endpoint {
                    host: "192.168.0.2".into(),
                    port: 7657,
                },
                Endpoint {
                    host: "100.64.0.3".into(),
                    port: 7657,
                },
            ]
        );
    }

    #[test]
    fn duplicate_candidates_do_not_hide_a_disallowed_member() {
        let blob = build_v05(&[[10, 0, 0, 1], [10, 0, 0, 1], [192, 0, 2, 42]], 7657);
        assert_eq!(
            parse_blob(&blob).unwrap_err(),
            PairLinkError::DisallowedDirectIpv4 {
                address: "192.0.2.42".into(),
            }
        );
    }

    #[test]
    fn v05_structural_errors_precede_address_policy_and_trailing_bytes_remain_tolerated() {
        let mut truncated = build_v05(&[[192, 0, 2, 42]], 7657);
        truncated.pop();
        assert!(matches!(
            parse_blob(&truncated).unwrap_err(),
            PairLinkError::Truncated { .. }
        ));

        let mut unsupported = build_v05(&[[10, 0, 0, 1]], 7657);
        unsupported[1] = 0x02;
        assert_eq!(
            parse_blob(&unsupported).unwrap_err(),
            PairLinkError::UnsupportedAddressType(0x02)
        );

        let mut trailing = build_v05(&[[10, 0, 0, 1]], 7657);
        trailing.extend_from_slice(&[0xaa, 0xbb]);
        assert_eq!(
            direct(parse_blob(&trailing).unwrap()).candidates[0].host,
            "10.0.0.1"
        );
    }

    #[test]
    fn rejects_truncated_blob() {
        let blob = build_v05(&[[10, 0, 0, 1], [10, 0, 0, 2]], 7657);
        let truncated = &blob[..blob.len() - 4];
        assert!(matches!(
            parse_blob(truncated).unwrap_err(),
            PairLinkError::Truncated { .. }
        ));
    }

    #[test]
    fn rejects_unknown_version() {
        assert_eq!(
            parse_blob(&[0x02, 0x01, 0x00]).unwrap_err(),
            PairLinkError::UnsupportedVersion(0x02)
        );
    }

    #[test]
    fn parses_v06_well_known_conformance_fragment() {
        let blob = build_v06(None, RELAY_CA_FP_TAG_SPKI_SHA256);
        assert_eq!(crockford::encode(&blob), RELAY_WELL_KNOWN_FRAGMENT);
        let pl = relay(parse(RELAY_WELL_KNOWN_FRAGMENT).unwrap());
        assert_relay_fields(pl, DEFAULT_RELAY_ORIGIN);
    }

    #[test]
    fn parses_v06_custom_origin_conformance_fragment() {
        let origin = "https://relay.example";
        let blob = build_v06(Some(origin), RELAY_CA_FP_TAG_SPKI_SHA256);
        assert_eq!(crockford::encode(&blob), RELAY_CUSTOM_FRAGMENT);
        let pl = relay(parse(RELAY_CUSTOM_FRAGMENT).unwrap());
        assert_relay_fields(pl, origin);
    }

    #[test]
    fn parses_v06_from_built_blob() {
        let origin = "https://relay.example";
        let pl = relay(parse_blob(&build_v06(Some(origin), RELAY_CA_FP_TAG_SPKI_SHA256)).unwrap());
        assert_relay_fields(pl, origin);
    }

    #[test]
    fn rejects_unknown_relay_ca_fp_tag() {
        assert_eq!(
            parse_blob(&build_v06(None, 0x02)).unwrap_err(),
            PairLinkError::UnknownCaFpTag(0x02)
        );
    }

    #[test]
    fn rejects_v06_truncation_before_selector() {
        let blob = build_v06(None, RELAY_CA_FP_TAG_SPKI_SHA256);
        assert!(matches!(
            parse_blob(&blob[..26]).unwrap_err(),
            PairLinkError::Truncated {
                expected: RELAY_WINDOW_BASE_LEN,
                got: 26
            }
        ));
    }

    #[test]
    fn rejects_v06_custom_origin_truncation() {
        let blob = build_v06(Some("https://relay.example"), RELAY_CA_FP_TAG_SPKI_SHA256);
        assert!(matches!(
            parse_blob(&blob[..blob.len() - 1]).unwrap_err(),
            PairLinkError::Truncated { .. }
        ));
    }

    #[test]
    fn rejects_v06_selector_length_mismatch() {
        let mut blob = build_v06(None, RELAY_CA_FP_TAG_SPKI_SHA256);
        blob.push(0xff);
        assert_eq!(
            parse_blob(&blob).unwrap_err(),
            PairLinkError::LengthMismatch {
                expected: RELAY_WINDOW_BASE_LEN,
                got: RELAY_WINDOW_BASE_LEN + 1
            }
        );
    }

    #[test]
    fn rejects_bad_relay_origin_utf8() {
        let mut blob = build_v06(None, RELAY_CA_FP_TAG_SPKI_SHA256);
        blob[26] = 1;
        blob.push(0xff);
        assert_eq!(
            parse_blob(&blob).unwrap_err(),
            PairLinkError::BadRelayOrigin
        );
    }
}
