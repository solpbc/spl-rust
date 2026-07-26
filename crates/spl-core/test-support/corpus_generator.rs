// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

use serde::{Deserialize, Serialize};
use spl_core::pairlink::{self, PairLinkError, ParsedPairLink};
use std::error::Error;
use std::path::{Path, PathBuf};

pub(crate) const PROTOCOL_REVISION: &str = "92b54d057d445d60b06b0fbe6f0c6b14120148ff";
const CORPUS_PATH_FROM_MANIFEST: &str = "../../conformance/spl-core-vectors.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Corpus {
    pub(crate) spdx_license_identifier: String,
    pub(crate) schema_version: u32,
    pub(crate) protocol_revision: String,
    pub(crate) vectors: Vec<Vector>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Vector {
    pub(crate) id: String,
    pub(crate) evidence: Evidence,
    pub(crate) citations: Vec<Citation>,
    #[serde(flatten)]
    pub(crate) case: VectorCase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Evidence {
    PublishedFixture,
    Regression,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Citation {
    pub(crate) document: String,
    pub(crate) clause: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "encoding", rename_all = "snake_case")]
pub(crate) enum PairInput {
    Link { value: String },
    BlobHex { value: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EndpointExpectation {
    pub(crate) host: String,
    pub(crate) port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

pub(crate) fn corpus_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(CORPUS_PATH_FROM_MANIFEST)
}

pub(crate) fn generate_corpus() -> Result<Corpus, Box<dyn Error>> {
    let mut vectors = Vec::new();
    add_direct_admission_vectors(&mut vectors)?;
    add_v04_vectors(&mut vectors)?;
    add_v05_vectors(&mut vectors)?;
    add_v06_vectors(&mut vectors)?;

    Ok(Corpus {
        spdx_license_identifier: "AGPL-3.0-only".to_string(),
        schema_version: 1,
        protocol_revision: PROTOCOL_REVISION.to_string(),
        vectors,
    })
}

pub(crate) fn serialize_corpus(corpus: &Corpus) -> Result<String, serde_json::Error> {
    let mut encoded = serde_json::to_string_pretty(corpus)?;
    encoded.push('\n');
    Ok(encoded)
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

fn add_direct_admission_vectors(vectors: &mut Vec<Vector>) -> Result<(), Box<dyn Error>> {
    let ranges = [
        ("rfc1918-10", 0x0a00_0000_u32, 0x0aff_ffff_u32),
        ("rfc6598", 0x6440_0000, 0x647f_ffff),
        ("loopback", 0x7f00_0000, 0x7fff_ffff),
        ("link-local", 0xa9fe_0000, 0xa9fe_ffff),
        ("rfc1918-172", 0xac10_0000, 0xac1f_ffff),
        ("rfc1918-192", 0xc0a8_0000, 0xc0a8_ffff),
    ];
    for (name, lower, upper) in ranges {
        for (position, address) in [
            ("below", lower - 1),
            ("lower", lower),
            ("upper", upper),
            ("above", upper + 1),
        ] {
            add_regression_blob(
                vectors,
                &format!("direct.admission.{name}.{position}"),
                vec![pairing(
                    "Verifies every candidate address is in the explicit direct-pair allow-list",
                )],
                v04(address.to_be_bytes(), 7070),
            )?;
        }
    }

    add_regression_blob(
        vectors,
        "direct.admission.link-local.example",
        vec![pairing(
            "Address-admission conformance cases (normative policy vectors):",
        )],
        v04([169, 254, 0, 1], 7070),
    )?;
    Ok(())
}

fn add_v04_vectors(vectors: &mut Vec<Vector>) -> Result<(), Box<dyn Error>> {
    const LINK: &str = "https://go.solstone.app/p#0G0W000258DSX8DJRFAEBXG7308J4CT4ANK7F26YNPZEZJQYQAZ028T5CY4TQKFF";
    const BLOB_HEX: &str =
        "0401c000022a1b9ea1b2c3d4e5f607181122334455667788deadbeefcafebabe0123456789abcdef";
    let fragment = LINK.split_once('#').map_or(LINK, |(_, fragment)| fragment);
    if observe_crockford(fragment)? != BLOB_HEX {
        return Err("published v04 fragment does not decode to its documented fields".into());
    }

    vectors.push(Vector {
        id: "pair.v04.canonical.decode".to_string(),
        evidence: Evidence::PublishedFixture,
        citations: vec![pairing("Direct form conformance vector uses fixed inputs")],
        case: VectorCase::DecodeCrockford {
            input: fragment.to_string(),
            expected_hex: BLOB_HEX.to_string(),
        },
    });
    vectors.push(Vector {
        id: "pair.v04.canonical.admission".to_string(),
        evidence: Evidence::PublishedFixture,
        citations: vec![pairing("canonical direct vector `192.0.2.42`")],
        case: VectorCase::ParsePairLink {
            input: PairInput::Link {
                value: LINK.to_string(),
            },
            expected: PairExpectation::Error {
                error: PairErrorExpectation::DisallowedDirectIpv4 {
                    address: "192.0.2.42".to_string(),
                },
            },
        },
    });

    let canonical = hex_decode(BLOB_HEX)?;
    for length in [0, 1, 2, 6, 8, 24, 39] {
        add_regression_blob(
            vectors,
            &format!("pair.v04.truncated.{length}"),
            vec![pairing("Direct form, version `0x04` (40 bytes):")],
            canonical[..length].to_vec(),
        )?;
    }
    let mut bad_tag = v04([10, 0, 0, 1], 7070);
    bad_tag[1] = 2;
    add_regression_blob(
        vectors,
        "pair.v04.unsupported-address-tag",
        vec![pairing("`0x01` = IPv4")],
        bad_tag,
    )?;
    Ok(())
}

fn add_v05_vectors(vectors: &mut Vec<Vector>) -> Result<(), Box<dyn Error>> {
    let allowed = [
        [192, 168, 1, 10],
        [100, 64, 0, 5],
        [10, 0, 0, 1],
        [127, 0, 0, 1],
    ];
    for count in 1..=4 {
        add_regression_blob(
            vectors,
            &format!("pair.v05.count.{count}"),
            vec![pairing("Candidate-count conformance cases:")],
            v05(&allowed[..count], 7070),
        )?;
    }
    for count in [0_u8, 5, 255] {
        add_regression_blob(
            vectors,
            &format!("pair.v05.count.{count}.refuse"),
            vec![pairing("Candidate-count conformance cases:")],
            vec![0x05, 0x01, count],
        )?;
    }

    let exact = v05(&allowed[..2], 7070);
    for length in [1, 2, 3, 4, 5, 8, 12, exact.len() - 1] {
        add_regression_blob(
            vectors,
            &format!("pair.v05.truncated.{length}"),
            vec![pairing("Total length is `5 + 4·count + 32`")],
            exact[..length].to_vec(),
        )?;
    }
    let mut bad_tag = exact.clone();
    bad_tag[1] = 2;
    add_regression_blob(
        vectors,
        "pair.v05.unsupported-address-tag",
        vec![pairing("`0x01` = IPv4")],
        bad_tag,
    )?;

    add_regression_blob(
        vectors,
        "pair.v05.admission.all-allowed",
        vec![pairing("`0x05`: `192.168.1.10`, `100.64.0.5`")],
        v05(&allowed[..2], 7070),
    )?;
    add_regression_blob(
        vectors,
        "pair.v05.admission.mixed-refused",
        vec![pairing("`0x05`: `192.168.1.10`, `192.0.2.42`")],
        v05(&[[192, 168, 1, 10], [192, 0, 2, 42]], 7070),
    )?;
    add_regression_blob(
        vectors,
        "pair.v05.duplicate.coalesced",
        vec![pairing("coalescing exact duplicate host/port endpoints")],
        v05(&[[10, 0, 0, 1], [10, 0, 0, 1]], 7070),
    )?;
    add_regression_blob(
        vectors,
        "pair.v05.duplicate.disallowed",
        vec![pairing(
            "a link with any public-address candidate is refused as a whole",
        )],
        v05(&[[192, 0, 2, 42], [192, 0, 2, 42]], 7070),
    )?;
    add_regression_blob(
        vectors,
        "pair.v05.duplicate.count-five-refused",
        vec![pairing("count is outside `1...4` is malformed")],
        vec![0x05, 0x01, 5],
    )?;

    for (position, candidates) in [
        ("first", [[192, 0, 2, 42], [10, 0, 0, 1], [127, 0, 0, 1]]),
        ("middle", [[10, 0, 0, 1], [192, 0, 2, 42], [127, 0, 0, 1]]),
        ("last", [[10, 0, 0, 1], [127, 0, 0, 1], [192, 0, 2, 42]]),
    ] {
        add_regression_blob(
            vectors,
            &format!("pair.v05.disallowed-member.{position}"),
            vec![pairing(
                "a link with any public-address candidate is refused as a whole",
            )],
            v05(&candidates, 7070),
        )?;
    }
    Ok(())
}

fn add_v06_vectors(vectors: &mut Vec<Vector>) -> Result<(), Box<dyn Error>> {
    const DEFAULT_LINK: &str =
        "https://go.solstone.app/p#0R0J6HB7H6NWVVR1VTPVXVYAZTXBW0938NKRKAYDXW00";
    const DEFAULT_HEX: &str = "060123456789abcdef01deadbeefcafebabe0123456789abcdef00";
    const CUSTOM_LINK: &str = "https://go.solstone.app/p#0R0J6HB7H6NWVVR1VTPVXVYAZTXBW0938NKRKAYDXWAPGX3ME1SKMBSFE9JPRRBS5SJQGRBDE1P6A";
    const CUSTOM_HEX: &str = "060123456789abcdef01deadbeefcafebabe0123456789abcdef1568747470733a2f2f72656c61792e6578616d706c65";
    const RK_HEX: &str = "e34481a4cde647ba9c9fb29a59e18271";
    if observe_relay_key("0123456789abcdef")? != RK_HEX {
        return Err("published pair-window relay key does not match the implementation".into());
    }
    let relay_expected = |origin: &str| PairExpectation::Relay {
        secret_hex: "0123456789abcdef".to_string(),
        ca_fp_spki_hex: "deadbeefcafebabe0123456789abcdef".to_string(),
        relay_origin: origin.to_string(),
    };

    vectors.push(Vector {
        id: "pair.v06.default.published".to_string(),
        evidence: Evidence::PublishedFixture,
        citations: vec![pair_window(
            "Default relay (`relay_origin = None`, selector `0x00`):",
        )],
        case: VectorCase::ParsePairLink {
            input: PairInput::Link {
                value: DEFAULT_LINK.to_string(),
            },
            expected: relay_expected(pairlink::DEFAULT_RELAY_ORIGIN),
        },
    });
    vectors.push(Vector {
        id: "pair.v06.custom.published".to_string(),
        evidence: Evidence::PublishedFixture,
        citations: vec![pair_window(
            "Custom relay (`relay_origin = https://relay.example`):",
        )],
        case: VectorCase::ParsePairLink {
            input: PairInput::Link {
                value: CUSTOM_LINK.to_string(),
            },
            expected: relay_expected("https://relay.example"),
        },
    });
    vectors.push(Vector {
        id: "relay.rk.published".to_string(),
        evidence: Evidence::PublishedFixture,
        citations: vec![pair_window(
            "RK (L=16)    = e34481a4cde647ba9c9fb29a59e18271",
        )],
        case: VectorCase::DeriveRelayKey {
            secret_hex: "0123456789abcdef".to_string(),
            expected_hex: RK_HEX.to_string(),
        },
    });

    let default_blob = hex_decode(DEFAULT_HEX)?;
    for length in [1, 9, 10, 26] {
        add_regression_blob(
            vectors,
            &format!("pair.v06.truncated.{length}"),
            vec![pair_window("Base size **27 bytes**")],
            default_blob[..length].to_vec(),
        )?;
    }
    let mut unknown_tag = default_blob;
    unknown_tag[9] = 2;
    add_regression_blob(
        vectors,
        "pair.v06.unknown-ca-tag",
        vec![pair_window("ca_fp_tag | `0x01` = SHA-256 over CA DER SPKI")],
        unknown_tag,
    )?;

    let custom = hex_decode(CUSTOM_HEX)?;
    add_regression_blob(
        vectors,
        "pair.v06.custom-origin-truncated",
        vec![pair_window("`N` (`1..255`) = custom origin byte length")],
        custom[..custom.len() - 1].to_vec(),
    )?;
    let mut invalid_utf8 = hex_decode(DEFAULT_HEX)?;
    invalid_utf8[26] = 1;
    invalid_utf8.push(0xff);
    add_regression_blob(
        vectors,
        "pair.v06.custom-origin-invalid-utf8",
        vec![pair_window(
            "relay_origin | UTF-8 bytes of the custom origin",
        )],
        invalid_utf8,
    )?;
    Ok(())
}

fn add_regression_blob(
    vectors: &mut Vec<Vector>,
    id: &str,
    citations: Vec<Citation>,
    blob: impl Into<Vec<u8>>,
) -> Result<(), Box<dyn Error>> {
    let blob = blob.into();
    let input = PairInput::BlobHex {
        value: hex_encode(&blob),
    };
    let expected = observe_pair(&input)?;
    vectors.push(Vector {
        id: id.to_string(),
        evidence: Evidence::Regression,
        citations,
        case: VectorCase::ParsePairLink { input, expected },
    });
    Ok(())
}

fn v04(address: [u8; 4], port: u16) -> Vec<u8> {
    let mut blob = vec![0x04, 0x01];
    blob.extend_from_slice(&address);
    blob.extend_from_slice(&port.to_be_bytes());
    blob.extend_from_slice(&fixed_nonce());
    blob.extend_from_slice(&fixed_ca_fp());
    blob
}

fn v05(candidates: &[[u8; 4]], port: u16) -> Vec<u8> {
    let mut blob = vec![0x05, 0x01, candidates.len() as u8];
    blob.extend_from_slice(&port.to_be_bytes());
    for candidate in candidates {
        blob.extend_from_slice(candidate);
    }
    blob.extend_from_slice(&fixed_nonce());
    blob.extend_from_slice(&fixed_ca_fp());
    blob
}

fn fixed_nonce() -> [u8; 16] {
    [
        0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88,
    ]
}

fn fixed_ca_fp() -> [u8; 16] {
    [
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef,
    ]
}

fn pairing(clause: &str) -> Citation {
    Citation {
        document: ".proto-ref/pairing.md".to_string(),
        clause: clause.to_string(),
    }
}

fn pair_window(clause: &str) -> Citation {
    Citation {
        document: ".proto-ref/pair-window.md".to_string(),
        clause: clause.to_string(),
    }
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
