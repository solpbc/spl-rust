// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! PROXY protocol v1 headers for journal-bound client streams.

use std::net::SocketAddr;

use ppp::v1::Addresses;
use thiserror::Error;

/// Errors returned while constructing a PROXY protocol v1 header.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProxyProtocolError {
    /// The source and destination addresses do not share an IP address family.
    #[error("PROXY protocol v1 source and destination address families differ")]
    AddressFamilyMismatch,
}

/// Encode a PROXY protocol v1 header for one client connection.
///
/// `source` is the client's observed remote address and `destination` is the
/// bridge listener's local address. The `ppp` v1 address model selects TCP4 or
/// TCP6 while formatting the header.
///
/// # Errors
///
/// Returns [`ProxyProtocolError::AddressFamilyMismatch`] when `source` and
/// `destination` do not have the same IP address family.
pub fn v1_header(
    source: SocketAddr,
    destination: SocketAddr,
) -> Result<Vec<u8>, ProxyProtocolError> {
    let addresses = Addresses::from((source, destination));
    if matches!(addresses, Addresses::Unknown) {
        return Err(ProxyProtocolError::AddressFamilyMismatch);
    }
    Ok(addresses.to_string().into_bytes())
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "the test uses fixed, valid PROXY protocol addresses"
    )]

    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use ppp::v1::{Addresses, Header};

    use super::*;

    #[test]
    fn encoded_header_round_trips_through_the_ppp_v1_decoder() {
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 45678);
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 443);

        let encoded = v1_header(source, destination).unwrap();
        let decoded = Header::try_from(encoded.as_slice()).unwrap();
        assert!(matches!(decoded.addresses, Addresses::Tcp4(_)));
        if let Addresses::Tcp4(addresses) = decoded.addresses {
            assert_eq!(addresses.source_address, Ipv4Addr::new(198, 51, 100, 7));
            assert_eq!(addresses.source_port, source.port());
        }
    }
}
