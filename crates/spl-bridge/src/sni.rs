// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Bounded, non-consuming SNI extraction from a TLS `ClientHello`.

use std::time::Duration;

use thiserror::Error;
use tokio::net::TcpStream;

const INITIAL_PEEK_BYTES: usize = 4 * 1024;
const INCOMPLETE_RETRY_DELAY: Duration = Duration::from_millis(10);
const TLS_HANDSHAKE: u8 = 0x16;
const CLIENT_HELLO: u8 = 0x01;
const SERVER_NAME_EXTENSION: u16 = 0;
const HOST_NAME: u8 = 0;

/// Default limit for waiting on a complete client TLS `ClientHello`.
///
/// Five seconds admits ordinary segmented `ClientHellos` while bounding an idle
/// or slowloris connection before the listener has enough information to route
/// it.
pub const DEFAULT_READ_DEADLINE: Duration = Duration::from_secs(5);

/// Bounds applied while reassembling a TLS `ClientHello` across TLS records.
///
/// The handshake bound includes its four-byte TLS handshake header. The wire
/// bound permits a one-byte record payload for every allowed handshake byte:
/// `32_768 * (5 + 1) == 196_608`.
#[derive(Clone, Copy)]
struct ClientHelloLimits {
    handshake_message_bytes: usize,
    record_payload_bytes: usize,
    record_count: usize,
    encoded_wire_bytes: usize,
}

const CLIENT_HELLO_LIMITS: ClientHelloLimits = ClientHelloLimits {
    handshake_message_bytes: 32_768,
    record_payload_bytes: 16_384,
    record_count: 32_768,
    encoded_wire_bytes: 196_608,
};

/// Errors returned while extracting a TLS SNI hostname.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SniError {
    /// The `ClientHello` did not become complete before the supplied deadline.
    #[error("TLS ClientHello read timed out")]
    Timeout,
    /// The received bytes were not a bounded TLS `ClientHello` shape.
    #[error("TLS ClientHello is malformed or truncated")]
    MalformedClientHello,
    /// The `ClientHello` did not contain a `host_name` `server_name` entry.
    #[error("TLS ClientHello has no SNI hostname")]
    NoServerName,
    /// Peeking or waiting for the client socket failed.
    #[error("TLS ClientHello socket I/O failed")]
    Io,
}

/// Extract the first `host_name` SNI value from a TLS `ClientHello` without consuming it.
///
/// The listener can subsequently splice the untouched `ClientHello` to either
/// the selected journal tunnel or the internal control listener. `deadline`
/// applies to the whole peek-and-parse operation rather than to each
/// individual socket readiness wait.
///
/// # Errors
///
/// Returns an error when the `ClientHello` is malformed, has no SNI value, does
/// not complete before `deadline`, or the socket cannot be peeked.
pub async fn extract_sni(stream: &TcpStream, deadline: Duration) -> Result<String, SniError> {
    tokio::time::timeout(deadline, extract_sni_inner(stream))
        .await
        .map_err(|_| SniError::Timeout)?
}

async fn extract_sni_inner(stream: &TcpStream) -> Result<String, SniError> {
    let mut capacity = INITIAL_PEEK_BYTES;
    loop {
        let mut bytes = vec![0u8; capacity];
        let received = stream.peek(&mut bytes).await.map_err(|_| SniError::Io)?;
        if received == 0 {
            return Err(SniError::MalformedClientHello);
        }

        match parse_client_hello(&bytes[..received])? {
            ParseOutcome::Complete(hostname) => return Ok(hostname),
            ParseOutcome::Incomplete if capacity == CLIENT_HELLO_LIMITS.encoded_wire_bytes => {
                return Err(SniError::MalformedClientHello);
            }
            ParseOutcome::Incomplete if received == capacity => {
                capacity = (capacity * 2).min(CLIENT_HELLO_LIMITS.encoded_wire_bytes);
            }
            ParseOutcome::Incomplete => {
                stream.readable().await.map_err(|_| SniError::Io)?;
                // A successful non-consuming peek can leave readiness asserted.
                // This small delay avoids spinning on the same partial bytes until
                // more data arrives or the caller's overall deadline expires.
                tokio::time::sleep(INCOMPLETE_RETRY_DELAY).await;
            }
        }
    }
}

enum ParseOutcome {
    Complete(String),
    Incomplete,
}

fn parse_client_hello(input: &[u8]) -> Result<ParseOutcome, SniError> {
    parse_client_hello_with_limits(input, CLIENT_HELLO_LIMITS)
}

/// Parse complete TLS records from a freshly peeked prefix.
///
/// `extract_sni_inner` re-peeks from byte zero whenever it grows its window, so
/// this parser deliberately derives all reassembly state from `input` on every
/// call. Nothing here is retained between peeks.
fn parse_client_hello_with_limits(
    input: &[u8],
    limits: ClientHelloLimits,
) -> Result<ParseOutcome, SniError> {
    let mut record_cursor = 0;
    let mut record_count = 0;
    let mut encoded_wire_bytes: usize = 0;
    let mut handshake = Vec::new();
    let mut handshake_length = None;

    loop {
        if record_cursor == input.len() {
            return Ok(ParseOutcome::Incomplete);
        }
        if record_count == limits.record_count {
            return Err(SniError::MalformedClientHello);
        }
        let Some(record_header) = input.get(record_cursor..record_cursor + 5) else {
            return Ok(ParseOutcome::Incomplete);
        };
        if record_header[0] != TLS_HANDSHAKE {
            return Err(SniError::MalformedClientHello);
        }
        let payload_length = usize::from(u16::from_be_bytes([record_header[3], record_header[4]]));
        if payload_length > limits.record_payload_bytes {
            return Err(SniError::MalformedClientHello);
        }
        let encoded_record_length = 5usize
            .checked_add(payload_length)
            .ok_or(SniError::MalformedClientHello)?;
        let next_encoded_wire_bytes = encoded_wire_bytes
            .checked_add(encoded_record_length)
            .ok_or(SniError::MalformedClientHello)?;
        if next_encoded_wire_bytes > limits.encoded_wire_bytes {
            return Err(SniError::MalformedClientHello);
        }
        let record_end = record_cursor
            .checked_add(encoded_record_length)
            .ok_or(SniError::MalformedClientHello)?;
        let Some(payload) = input.get(record_cursor + 5..record_end) else {
            return Ok(ParseOutcome::Incomplete);
        };

        record_count += 1;
        encoded_wire_bytes = next_encoded_wire_bytes;
        for (index, byte) in payload.iter().copied().enumerate() {
            if handshake.len() == limits.handshake_message_bytes {
                return Err(SniError::MalformedClientHello);
            }
            handshake.push(byte);
            if handshake.len() == 1 && handshake[0] != CLIENT_HELLO {
                return Err(SniError::MalformedClientHello);
            }
            if handshake.len() == 4 {
                let body_length = (usize::from(handshake[1]) << 16)
                    | (usize::from(handshake[2]) << 8)
                    | usize::from(handshake[3]);
                let total_length = 4usize
                    .checked_add(body_length)
                    .ok_or(SniError::MalformedClientHello)?;
                if total_length > limits.handshake_message_bytes {
                    return Err(SniError::MalformedClientHello);
                }
                handshake_length = Some(total_length);
            }
            if handshake_length == Some(handshake.len()) {
                if index + 1 != payload.len() {
                    return Err(SniError::MalformedClientHello);
                }
                return parse_client_hello_body(&handshake[4..]).map(ParseOutcome::Complete);
            }
        }
        record_cursor = record_end;
    }
}

fn parse_client_hello_body(body: &[u8]) -> Result<String, SniError> {
    let mut cursor = Cursor::new(body);
    cursor.skip(2)?;
    cursor.skip(32)?;
    let session_id_length = cursor.u8()?;
    cursor.skip(usize::from(session_id_length))?;
    let cipher_suites_length = cursor.u16()?;
    cursor.skip(usize::from(cipher_suites_length))?;
    let compression_methods_length = cursor.u8()?;
    cursor.skip(usize::from(compression_methods_length))?;
    let all_extensions_length = cursor.u16()?;
    let extensions = cursor.take(usize::from(all_extensions_length))?;
    if !cursor.is_empty() {
        return Err(SniError::MalformedClientHello);
    }

    let mut extensions = Cursor::new(extensions);
    let mut hostname = None;
    while !extensions.is_empty() {
        let extension_type = extensions.u16()?;
        let extension_length = extensions.u16()?;
        let extension_data = extensions.take(usize::from(extension_length))?;
        if extension_type == SERVER_NAME_EXTENSION && hostname.is_none() {
            hostname = Some(parse_server_name(extension_data)?);
        }
    }
    hostname.ok_or(SniError::NoServerName)
}

fn parse_server_name(data: &[u8]) -> Result<String, SniError> {
    let mut cursor = Cursor::new(data);
    let server_name_list_length = cursor.u16()?;
    let names = cursor.take(usize::from(server_name_list_length))?;
    if !cursor.is_empty() {
        return Err(SniError::MalformedClientHello);
    }

    let mut names = Cursor::new(names);
    let mut hostname = None;
    while !names.is_empty() {
        let name_type = names.u8()?;
        let name_length = names.u16()?;
        let name = names.take(usize::from(name_length))?;
        if name_type == HOST_NAME && hostname.is_none() {
            if name.is_empty() {
                return Err(SniError::MalformedClientHello);
            }
            hostname = Some(
                std::str::from_utf8(name)
                    .map_err(|_| SniError::MalformedClientHello)?
                    .to_owned(),
            );
        }
    }
    hostname.ok_or(SniError::NoServerName)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn skip(&mut self, length: usize) -> Result<(), SniError> {
        self.take(length).map(|_| ())
    }

    fn u8(&mut self) -> Result<u8, SniError> {
        Ok(*self
            .take(1)?
            .first()
            .ok_or(SniError::MalformedClientHello)?)
    }

    fn u16(&mut self) -> Result<u16, SniError> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| SniError::MalformedClientHello)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], SniError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(SniError::MalformedClientHello)?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or(SniError::MalformedClientHello)?;
        self.position = end;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "tests construct local sockets and fixed ClientHello bytes"
    )]

    use std::time::Duration;

    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client_task = tokio::spawn(async move { TcpStream::connect(address).await });
        let (server, _) = listener.accept().await.unwrap();
        let client = client_task.await.unwrap().unwrap();
        (client, server)
    }

    fn client_hello(hostname: &str, grease: bool) -> Vec<u8> {
        let mut extensions = Vec::new();
        if grease {
            extension(&mut extensions, 0x0a0a, &[]);
        }
        let mut names = Vec::new();
        names.push(HOST_NAME);
        push_u16(&mut names, hostname.len().try_into().unwrap());
        names.extend_from_slice(hostname.as_bytes());
        let mut server_name = Vec::new();
        push_u16(&mut server_name, names.len().try_into().unwrap());
        server_name.extend_from_slice(&names);
        extension(&mut extensions, SERVER_NAME_EXTENSION, &server_name);
        if grease {
            let mut groups = Vec::new();
            push_u16(&mut groups, 4);
            push_u16(&mut groups, 0x1a1a);
            push_u16(&mut groups, 0x001d);
            extension(&mut extensions, 10, &groups);
            extension(&mut extensions, 0x2a2a, &[0]);
        }

        let mut body = Vec::new();
        body.extend([0x03, 0x03]);
        body.extend([0x55; 32]);
        body.push(0);
        let ciphers: &[u8] = if grease {
            &[0x0a, 0x0a, 0x13, 0x01]
        } else {
            &[0x13, 0x01]
        };
        push_u16(&mut body, ciphers.len().try_into().unwrap());
        body.extend_from_slice(ciphers);
        body.extend([1, 0]);
        push_u16(&mut body, extensions.len().try_into().unwrap());
        body.extend_from_slice(&extensions);

        let mut handshake = vec![CLIENT_HELLO];
        push_u24(&mut handshake, body.len());
        handshake.extend_from_slice(&body);
        let mut record = vec![TLS_HANDSHAKE, 0x03, 0x01];
        push_u16(&mut record, handshake.len().try_into().unwrap());
        record.extend_from_slice(&handshake);
        record
    }

    fn fragment_handshake(handshake_record: &[u8], seed: u32) -> Vec<u8> {
        let handshake = &handshake_record[5..];
        let mut state = seed;
        let mut position = 0;
        let mut records = Vec::new();
        while position < handshake.len() {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let mut length = 1 + usize::try_from((state >> 24) % 11).unwrap();
            if position < 4 {
                length = [1, 2, 1][position.min(2)];
            }
            let end = (position + length).min(handshake.len());
            records.extend([TLS_HANDSHAKE, 0x03, 0x01]);
            push_u16(&mut records, (end - position).try_into().unwrap());
            records.extend_from_slice(&handshake[position..end]);
            position = end;
        }
        records
    }

    fn one_byte_records(handshake_record: &[u8]) -> Vec<u8> {
        let mut records = Vec::new();
        for byte in &handshake_record[5..] {
            records.extend([TLS_HANDSHAKE, 0x03, 0x01, 0, 1, *byte]);
        }
        records
    }

    fn extension(out: &mut Vec<u8>, extension_type: u16, data: &[u8]) {
        push_u16(out, extension_type);
        push_u16(out, data.len().try_into().unwrap());
        out.extend_from_slice(data);
    }

    fn push_u16(out: &mut Vec<u8>, value: u16) {
        out.extend_from_slice(&value.to_be_bytes());
    }

    fn push_u24(out: &mut Vec<u8>, value: usize) {
        out.extend_from_slice(&[
            (value >> 16).try_into().unwrap(),
            (value >> 8).try_into().unwrap(),
            value.try_into().unwrap(),
        ]);
    }

    #[tokio::test]
    async fn extracts_sni_from_a_complete_client_hello_under_250ms() {
        let (mut client, server) = tcp_pair().await;
        let hello = client_hello("mcp.journal.test", false);
        let started = tokio::time::Instant::now();
        let extraction =
            tokio::spawn(async move { extract_sni(&server, DEFAULT_READ_DEADLINE).await });

        client.write_all(&hello).await.unwrap();
        assert_eq!(extraction.await.unwrap().unwrap(), "mcp.journal.test");
        assert!(started.elapsed() < Duration::from_millis(250));
    }

    #[tokio::test]
    async fn extracts_sni_when_the_client_hello_arrives_in_two_writes() {
        let (mut client, server) = tcp_pair().await;
        let hello = client_hello("mcp.journal.test", false);
        let split = hello.len() / 2;
        let extraction =
            tokio::spawn(async move { extract_sni(&server, DEFAULT_READ_DEADLINE).await });

        client.write_all(&hello[..split]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        client.write_all(&hello[split..]).await.unwrap();
        assert_eq!(extraction.await.unwrap().unwrap(), "mcp.journal.test");
    }

    #[tokio::test]
    async fn ignores_grease_entries_while_finding_server_name() {
        let (mut client, server) = tcp_pair().await;
        let hello = client_hello("grease.journal.test", true);
        let extraction =
            tokio::spawn(async move { extract_sni(&server, DEFAULT_READ_DEADLINE).await });

        client.write_all(&hello).await.unwrap();
        assert_eq!(extraction.await.unwrap().unwrap(), "grease.journal.test");
    }

    #[tokio::test]
    async fn extracts_sni_across_lcg_fragmented_tls_records_and_header_splits() {
        let (mut client, server) = tcp_pair().await;
        let hello = fragment_handshake(&client_hello("record.journal.test", true), 0x5151_7eed);
        let extraction =
            tokio::spawn(async move { extract_sni(&server, DEFAULT_READ_DEADLINE).await });

        client.write_all(&hello).await.unwrap();
        assert_eq!(extraction.await.unwrap().unwrap(), "record.journal.test");
    }

    #[test]
    fn one_byte_record_encoding_reaches_the_exact_cumulative_wire_limit() {
        let hostname = "limit.journal.test";
        let mut hello = client_hello(hostname, false);
        let target_handshake_length = CLIENT_HELLO_LIMITS.handshake_message_bytes;
        let current_handshake_length = hello.len() - 5;
        let padding_length = target_handshake_length - current_handshake_length - 4;

        let record_length = u16::from_be_bytes([hello[3], hello[4]]);
        let extension_length_index = 5 + 4 + 2 + 32 + 1 + 2 + 2 + 1 + 1;
        let old_extensions_length = usize::from(u16::from_be_bytes([
            hello[extension_length_index],
            hello[extension_length_index + 1],
        ]));
        let padding_length_u16: u16 = padding_length.try_into().unwrap();
        let new_extensions_length: u16 = (old_extensions_length + 4 + padding_length)
            .try_into()
            .unwrap();
        hello[extension_length_index..extension_length_index + 2]
            .copy_from_slice(&new_extensions_length.to_be_bytes());
        hello.extend_from_slice(&0xfafa_u16.to_be_bytes());
        hello.extend_from_slice(&padding_length_u16.to_be_bytes());
        hello.extend(std::iter::repeat_n(0, padding_length));
        let new_record_length: u16 = (usize::from(record_length) + 4 + padding_length)
            .try_into()
            .unwrap();
        hello[3..5].copy_from_slice(&new_record_length.to_be_bytes());
        let body_length = target_handshake_length - 4;
        hello[6..9].copy_from_slice(&[
            (body_length >> 16).try_into().unwrap(),
            (body_length >> 8).try_into().unwrap(),
            (body_length & 0xff).try_into().unwrap(),
        ]);

        let records = one_byte_records(&hello);
        assert_eq!(records.len(), CLIENT_HELLO_LIMITS.encoded_wire_bytes);
        assert!(matches!(
            parse_client_hello(&records),
            Ok(ParseOutcome::Complete(actual)) if actual == hostname
        ));
    }

    #[tokio::test]
    async fn malformed_or_truncated_inputs_never_panic() {
        for index in 0..200_u32 {
            let (mut client, server) = tcp_pair().await;
            let malformed = malformed_variant(index);
            let parser =
                tokio::spawn(async move { extract_sni(&server, Duration::from_millis(10)).await });
            client.write_all(&malformed).await.unwrap();
            client.shutdown().await.unwrap();

            let result = tokio::time::timeout(Duration::from_secs(1), parser)
                .await
                .unwrap();
            assert!(
                matches!(result, Ok(Err(_))),
                "variant {index} panicked or succeeded"
            );
        }
    }

    #[tokio::test]
    async fn slowloris_client_hello_times_out_at_the_configured_deadline() {
        let (mut client, server) = tcp_pair().await;
        let hello = client_hello("slow.journal.test", false);
        let writer = tokio::spawn(async move {
            for byte in hello {
                client.write_all(&[byte]).await?;
                tokio::time::sleep(DEFAULT_READ_DEADLINE + Duration::from_millis(100)).await;
            }
            Ok::<(), std::io::Error>(())
        });

        let started = tokio::time::Instant::now();
        assert_eq!(
            extract_sni(&server, DEFAULT_READ_DEADLINE).await,
            Err(SniError::Timeout)
        );
        assert!(started.elapsed() >= DEFAULT_READ_DEADLINE);
        assert!(started.elapsed() < DEFAULT_READ_DEADLINE + Duration::from_secs(1));
        writer.abort();
    }

    fn malformed_variant(index: u32) -> Vec<u8> {
        match index % 4 {
            0 => {
                let length = usize::try_from((index % 63) + 1).unwrap();
                let mut state = index.wrapping_add(1);
                (0..length)
                    .map(|_| {
                        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                        (state >> 24).try_into().unwrap()
                    })
                    .collect()
            }
            1 => {
                let mut hello = client_hello("truncated.journal.test", false);
                hello.truncate(hello.len() / 2);
                hello
            }
            2 => vec![TLS_HANDSHAKE, 0x03, 0x03, 0x7f, 0xff],
            _ => {
                let mut hello = client_hello("extension.journal.test", false);
                let last = hello.len() - 1;
                hello[last] = 0xff;
                hello.truncate(last);
                hello
            }
        }
    }
}
