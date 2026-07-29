// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

use serde::Deserialize;
use spl_core::pairlink::{self, PairLinkError, ParsedPairLink};
use std::error::Error;
use std::path::{Path, PathBuf};

pub(crate) const PROTOCOL_REVISION: &str = "0f49108dbe64f6d3ae906fa6f415182c10c83bc4";
const VECTORS_PATH_FROM_MANIFEST: &str = "../../conformance/bundle/vectors.json";

#[derive(Deserialize)]
pub(crate) struct Corpus {
    pub(crate) vectors: Vec<Vector>,
}

#[derive(Deserialize)]
pub(crate) struct Vector {
    pub(crate) id: String,
    pub(crate) kind: VectorKind,
    pub(crate) citation: Option<Citation>,
    #[serde(flatten)]
    pub(crate) case: VectorCase,
}

#[derive(PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum VectorKind {
    Declared,
    Recorded,
}

#[derive(Deserialize)]
pub(crate) struct Citation {
    pub(crate) document: String,
    pub(crate) marker: String,
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub(crate) enum VectorCase {
    ParsePairLink {
        input: PairInput,
        expected: PairExpectation,
    },
    DecodeCrockford {
        input: String,
        expected_hex: String,
    },
    DeriveRelayKey {
        secret_hex: String,
        expected_hex: String,
    },
}

#[derive(Deserialize)]
#[serde(tag = "encoding", rename_all = "snake_case")]
pub(crate) enum PairInput {
    Link { value: String },
    BlobHex { value: String },
}

#[derive(Debug, PartialEq, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub(crate) enum PairExpectation {
    Direct {
        candidates: Vec<EndpointExpectation>,
        nonce_hex: String,
        ca_fp_hex: String,
    },
    Relay {
        secret_hex: String,
        ca_fp_spki_hex: String,
        relay_origin: String,
    },
    Error {
        error: PairErrorExpectation,
    },
}

#[derive(Debug, PartialEq, Deserialize)]
pub(crate) struct EndpointExpectation {
    pub(crate) host: String,
    pub(crate) port: u16,
}

#[derive(Debug, PartialEq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum PairErrorExpectation {
    MissingFragment,
    CrockfordInvalidSymbol { symbol: char },
    CrockfordNonZeroPadding,
    UnsupportedVersion { version: u8 },
    UnsupportedAddressType { address_type: u8 },
    UnknownCaFpTag { tag: u8 },
    BadRelayOrigin,
    Truncated { expected: usize, got: usize },
    LengthMismatch { expected: usize, got: usize },
    DisallowedDirectIpv4 { address: String },
    InvalidCandidateCount { count: u8 },
}

pub(crate) fn vectors_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(VECTORS_PATH_FROM_MANIFEST)
}

pub(crate) fn observe_pair(input: &PairInput) -> Result<PairExpectation, Box<dyn Error>> {
    let parsed = match input {
        PairInput::Link { value } => pairlink::parse(value),
        PairInput::BlobHex { value } => {
            let blob = hex_decode(value)?;
            pairlink::parse_blob(&blob)
        }
    };

    Ok(match parsed {
        Ok(ParsedPairLink::Direct(link)) => PairExpectation::Direct {
            candidates: link
                .candidates
                .into_iter()
                .map(|endpoint| EndpointExpectation {
                    host: endpoint.host,
                    port: endpoint.port,
                })
                .collect(),
            nonce_hex: link.nonce_hex,
            ca_fp_hex: hex_encode(&link.ca_fp_prefix),
        },
        Ok(ParsedPairLink::Relay(link)) => PairExpectation::Relay {
            secret_hex: hex_encode(&link.s),
            ca_fp_spki_hex: hex_encode(&link.ca_fp_spki),
            relay_origin: link.relay_origin,
        },
        Err(error) => PairExpectation::Error {
            error: pair_error(&error),
        },
    })
}

pub(crate) fn observe_crockford(input: &str) -> Result<String, Box<dyn Error>> {
    Ok(hex_encode(&spl_core::crockford::decode(input)?))
}

pub(crate) fn observe_relay_key(secret_hex: &str) -> Result<String, Box<dyn Error>> {
    let secret = hex_decode(secret_hex)?;
    let secret: [u8; 8] = secret
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("relay secret must be 8 bytes, got {}", bytes.len()))?;
    Ok(hex_encode(&spl_core::relay_window::derive_rk(&secret)))
}

fn pair_error(error: &PairLinkError) -> PairErrorExpectation {
    match error {
        PairLinkError::MissingFragment => PairErrorExpectation::MissingFragment,
        PairLinkError::Crockford(spl_core::crockford::CrockfordError::InvalidSymbol(symbol)) => {
            PairErrorExpectation::CrockfordInvalidSymbol { symbol: *symbol }
        }
        PairLinkError::Crockford(spl_core::crockford::CrockfordError::NonZeroPadding) => {
            PairErrorExpectation::CrockfordNonZeroPadding
        }
        PairLinkError::UnsupportedVersion(version) => {
            PairErrorExpectation::UnsupportedVersion { version: *version }
        }
        PairLinkError::UnsupportedAddressType(address_type) => {
            PairErrorExpectation::UnsupportedAddressType {
                address_type: *address_type,
            }
        }
        PairLinkError::UnknownCaFpTag(tag) => PairErrorExpectation::UnknownCaFpTag { tag: *tag },
        PairLinkError::BadRelayOrigin => PairErrorExpectation::BadRelayOrigin,
        PairLinkError::Truncated { expected, got } => PairErrorExpectation::Truncated {
            expected: *expected,
            got: *got,
        },
        PairLinkError::LengthMismatch { expected, got } => PairErrorExpectation::LengthMismatch {
            expected: *expected,
            got: *got,
        },
        PairLinkError::DisallowedDirectIpv4 { address } => {
            PairErrorExpectation::DisallowedDirectIpv4 {
                address: address.clone(),
            }
        }
        PairLinkError::InvalidCandidateCount { count } => {
            PairErrorExpectation::InvalidCandidateCount { count: *count }
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(value: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if !value.len().is_multiple_of(2) {
        return Err(format!("hex input has odd length: {}", value.len()).into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digits = std::str::from_utf8(pair)?;
            Ok(u8::from_str_radix(digits, 16)?)
        })
        .collect()
}
