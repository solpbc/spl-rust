// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Crockford base32 — the pair-link fragment encoding.
//!
//! Implements the pair-link alphabet used by SPL peers:
//! `0123456789ABCDEFGHJKMNPQRSTVWXYZ`, case-insensitive on decode with the
//! `I`/`L` -> `1` and `O` -> `0` confusables folded, 5 bits per symbol, MSB
//! first. Trailing partial groups must be zero-padded (a non-zero remainder is
//! a decode error), so the round-trip is exact.

use thiserror::Error;

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

#[derive(Debug, Error, PartialEq, Eq)]
/// Errors produced while decoding Crockford base32.
pub enum CrockfordError {
    /// The input contains a character outside the Crockford alphabet.
    #[error("invalid crockford base32 symbol: {0:?}")]
    InvalidSymbol(char),
    /// A final partial symbol group contains non-zero padding bits.
    #[error("non-zero trailing bits in crockford base32 input")]
    NonZeroPadding,
}

fn symbol_value(c: char) -> Result<u8, CrockfordError> {
    let upper = c.to_ascii_uppercase();
    let normalized = match upper {
        'I' | 'L' => '1',
        'O' => '0',
        other => other,
    };
    ALPHABET
        .iter()
        .position(|&a| a as char == normalized)
        .map(|p| p as u8)
        .ok_or(CrockfordError::InvalidSymbol(c))
}

/// Decode a Crockford base32 string into bytes. Hyphens are ignored (Crockford
/// allows them as visual separators).
///
/// # Errors
///
/// Returns [`CrockfordError::InvalidSymbol`] for an unsupported character or
/// [`CrockfordError::NonZeroPadding`] for a non-canonical trailing bit group.
pub fn decode(input: &str) -> Result<Vec<u8>, CrockfordError> {
    let mut out = Vec::with_capacity(input.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for c in input.chars() {
        if c == '-' {
            continue;
        }
        let value = symbol_value(c)? as u32;
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    // Any leftover bits must be zero padding.
    if bits > 0 && (buffer & ((1 << bits) - 1)) != 0 {
        return Err(CrockfordError::NonZeroPadding);
    }
    Ok(out)
}

/// Encode bytes into a Crockford base32 string (uppercase, no separators).
/// Provided so tests can round-trip without depending on the journal builder.
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 8 / 5 + 1);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &b in bytes {
        buffer = (buffer << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = ((buffer >> bits) & 0x1f) as usize;
            out.push(ALPHABET[index] as char);
        }
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(ALPHABET[index] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_arbitrary_bytes() {
        for len in 0..40usize {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let encoded = encode(&bytes);
            assert_eq!(decode(&encoded).unwrap(), bytes, "len {len}");
        }
    }

    #[test]
    fn folds_confusable_symbols_case_insensitively() {
        // 'O'->0, 'I'/'L'->1; lowercase accepted. "10" = 00001 00000 -> [0x08].
        let canonical = decode("10").unwrap();
        assert_eq!(canonical, vec![0x08]);
        assert_eq!(decode("IO").unwrap(), canonical); // I->1, O->0
        assert_eq!(decode("LO").unwrap(), canonical); // L->1, O->0
        assert_eq!(decode("lo").unwrap(), canonical); // lowercase
    }

    #[test]
    fn ignores_hyphen_separators() {
        // "1000" -> [0x40,0x00] with zero trailing padding.
        assert_eq!(decode("10-00").unwrap(), decode("1000").unwrap());
    }

    #[test]
    fn rejects_invalid_symbol() {
        assert_eq!(decode("U").unwrap_err(), CrockfordError::InvalidSymbol('U'));
    }
}
