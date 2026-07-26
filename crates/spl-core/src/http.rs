// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! HTTP/1.1 over PL — request build + response parse.
//!
//! Frames the HTTP request shape shared by SPL transports so the journal sees
//! identical bytes: a `host: spl.local` line the transport owns,
//! an `accept` line (caller-overridable), the caller's headers, then a
//! transport-owned `content-length`. Response parsing lowercases header keys,
//! honors `content-length`, and de-chunks `transfer-encoding: chunked`.

use crate::frame::MAX_PAYLOAD;
use thiserror::Error;

/// A parsed HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// Numeric HTTP response status.
    pub status: u16,
    /// Response headers with lowercase names in wire order.
    pub headers: Vec<(String, String)>,
    /// Decoded response body bytes.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Return the first response header matching `name`, ignoring name case.
    pub fn header(&self, name: &str) -> Option<&str> {
        let lower = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| *k == lower)
            .map(|(_, v)| v.as_str())
    }

    /// Decode the body as UTF-8, replacing malformed sequences.
    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// Whether the status is in the successful 2xx range.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// Errors produced while parsing HTTP response bytes.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum HttpError {
    /// The header block has no terminating empty line.
    #[error("HTTP response missing header terminator")]
    MissingTerminator,
    /// The response head has no status line.
    #[error("HTTP response missing status line")]
    MissingStatusLine,
    /// The response status line does not contain a numeric status.
    #[error("bad HTTP status line: {0}")]
    BadStatusLine(String),
    /// `Content-Length` exceeds the received body length.
    #[error("HTTP response body truncated")]
    TruncatedBody,
    /// Chunked transfer framing is malformed or exceeds the frame limit.
    #[error("chunked body is malformed: {0}")]
    BadChunkedBody(String),
}

fn parse_chunk_size(line: &str) -> Result<usize, HttpError> {
    let size_field = line.split(';').next().unwrap_or("").trim();
    let size = usize::from_str_radix(size_field, 16)
        .map_err(|_| HttpError::BadChunkedBody(format!("bad chunk size {size_field:?}")))?;
    if size > MAX_PAYLOAD {
        return Err(HttpError::BadChunkedBody(format!(
            "chunk size {size} exceeds max {MAX_PAYLOAD}"
        )));
    }
    Ok(size)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChunkState {
    Size,
    Data(usize),
    DataCrlf,
    Trailer,
    Done,
    Failed,
}

/// Incremental decoder for `Transfer-Encoding: chunked` response bodies.
///
/// `push` buffers partial size lines, chunk data, and terminators across calls,
/// returning only newly decoded body bytes. The terminal zero-size chunk does
/// not itself produce bytes; trailers are consumed and ignored.
/// Each declared chunk is capped at [`MAX_PAYLOAD`].
#[derive(Debug, PartialEq, Eq)]
pub struct ChunkedDecoder {
    buf: Vec<u8>,
    state: ChunkState,
}

impl Default for ChunkedDecoder {
    fn default() -> Self {
        Self {
            buf: Vec::new(),
            state: ChunkState::Size,
        }
    }
}

impl ChunkedDecoder {
    /// Construct an empty incremental chunked-body decoder.
    pub fn new() -> Self {
        Self::default()
    }

    fn fail(&mut self, err: HttpError) -> HttpError {
        self.state = ChunkState::Failed;
        self.buf.clear();
        err
    }

    /// Append encoded body bytes and return newly decoded payload bytes.
    ///
    /// # Errors
    ///
    /// Returns [`HttpError::BadChunkedBody`] for malformed size lines, chunks
    /// larger than [`MAX_PAYLOAD`], or invalid chunk terminators. Once failed,
    /// the decoder remains failed.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<u8>, HttpError> {
        if self.state == ChunkState::Done {
            return Ok(Vec::new());
        }
        if self.state == ChunkState::Failed {
            return Err(HttpError::BadChunkedBody(
                "decoder previously failed".into(),
            ));
        }

        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();

        loop {
            match self.state {
                ChunkState::Size => {
                    let Some(line_end) = find_subsequence(&self.buf, b"\r\n") else {
                        break;
                    };
                    let size_text = String::from_utf8_lossy(&self.buf[..line_end]);
                    let size = match parse_chunk_size(&size_text) {
                        Ok(size) => size,
                        Err(err) => return Err(self.fail(err)),
                    };
                    self.buf.drain(..line_end + 2);
                    self.state = if size == 0 {
                        ChunkState::Trailer
                    } else {
                        ChunkState::Data(size)
                    };
                }
                ChunkState::Data(size) => {
                    if self.buf.len() < size {
                        break;
                    }
                    out.extend_from_slice(&self.buf[..size]);
                    self.buf.drain(..size);
                    self.state = ChunkState::DataCrlf;
                }
                ChunkState::DataCrlf => {
                    if self.buf.len() < 2 {
                        break;
                    }
                    if &self.buf[..2] != b"\r\n" {
                        let err = HttpError::BadChunkedBody("missing chunk terminator".into());
                        return Err(self.fail(err));
                    }
                    self.buf.drain(..2);
                    self.state = ChunkState::Size;
                }
                ChunkState::Trailer => {
                    if self.buf.starts_with(b"\r\n") {
                        self.buf.clear();
                        self.state = ChunkState::Done;
                        break;
                    }
                    let Some(trailer_end) = find_subsequence(&self.buf, b"\r\n\r\n") else {
                        break;
                    };
                    self.buf.drain(..trailer_end + 4);
                    self.buf.clear();
                    self.state = ChunkState::Done;
                    break;
                }
                ChunkState::Done | ChunkState::Failed => break,
            }
        }

        Ok(out)
    }
}

fn is_framing_owned(name: &str) -> bool {
    name.eq_ignore_ascii_case("host")
        || name.eq_ignore_ascii_case("content-length")
        || name.eq_ignore_ascii_case("accept")
}

/// Build the HTTP/1.1 request bytes for a single PL stream. `headers` are the
/// caller's extra headers (e.g. auth, content-type); `host`, `content-length`,
/// and a default `accept` are added by the transport, `accept` overridable.
pub fn build_request(
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Vec<u8> {
    let mut head = String::new();
    head.push_str(method);
    head.push(' ');
    head.push_str(path);
    head.push_str(" HTTP/1.1\r\n");
    head.push_str("host: spl.local\r\n");

    match headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("accept"))
    {
        Some((k, v)) => {
            head.push_str(k);
            head.push_str(": ");
            head.push_str(v);
            head.push_str("\r\n");
        }
        None => head.push_str("accept: application/json\r\n"),
    }

    for (name, value) in headers {
        if !is_framing_owned(name) {
            head.push_str(name);
            head.push_str(": ");
            head.push_str(value);
            head.push_str("\r\n");
        }
    }

    head.push_str("content-length: ");
    head.push_str(&body.len().to_string());
    head.push_str("\r\n\r\n");

    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

pub(crate) fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Parse a complete HTTP/1.1 response (headers + body) off a PL stream.
///
/// # Errors
///
/// Returns [`HttpError`] when the response head, declared body length, or
/// chunked transfer framing is malformed.
#[expect(
    clippy::map_unwrap_or,
    reason = "the explicit transfer-encoding lookup preserves the parsing steps"
)]
pub fn parse_response(raw: &[u8]) -> Result<HttpResponse, HttpError> {
    let split = find_subsequence(raw, b"\r\n\r\n").ok_or(HttpError::MissingTerminator)?;
    let (status, headers) = parse_head(&raw[..split])?;
    let mut body = raw[split + 4..].to_vec();
    let header_lookup = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };

    if header_lookup("transfer-encoding")
        .map(|v| v.eq_ignore_ascii_case("chunked"))
        .unwrap_or(false)
    {
        body = dechunk(&body)?;
    } else if let Some(len) = header_lookup("content-length").and_then(|v| v.parse::<usize>().ok())
    {
        if len < body.len() {
            body.truncate(len);
        } else if len > body.len() {
            return Err(HttpError::TruncatedBody);
        }
    }

    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

/// Parse an HTTP/1.1 response head without the trailing `\r\n\r\n`.
///
/// # Errors
///
/// Returns [`HttpError::MissingStatusLine`] or [`HttpError::BadStatusLine`]
/// when a numeric response status cannot be read.
pub fn parse_head(head_bytes: &[u8]) -> Result<(u16, Vec<(String, String)>), HttpError> {
    // Headers are ASCII/latin-1; lossy is safe and matches the reference parser.
    let head = String::from_utf8_lossy(head_bytes);
    let mut lines = head.split("\r\n");

    let status_line = lines.next().ok_or(HttpError::MissingStatusLine)?;
    let mut status_parts = status_line.splitn(3, ' ');
    let _http = status_parts.next();
    let status = status_parts
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| HttpError::BadStatusLine(status_line.to_string()))?;

    let mut headers = Vec::new();
    for line in lines {
        if let Some(colon) = line.find(':') {
            let key = line[..colon].trim().to_ascii_lowercase();
            let value = line[colon + 1..].trim().to_string();
            headers.push((key, value));
        }
    }

    Ok((status, headers))
}

/// Decode a `chunked` transfer-encoding body.
/// Each declared chunk is capped at [`MAX_PAYLOAD`].
///
/// # Errors
///
/// Returns [`HttpError::BadChunkedBody`] when a size line, chunk payload, or
/// terminal chunk is malformed.
pub fn dechunk(raw: &[u8]) -> Result<Vec<u8>, HttpError> {
    let mut out = Vec::new();
    let mut index = 0;
    while index < raw.len() {
        let line_end = find_subsequence(&raw[index..], b"\r\n")
            .map(|p| index + p)
            .ok_or_else(|| HttpError::BadChunkedBody("missing size line".into()))?;
        let size_text = String::from_utf8_lossy(&raw[index..line_end]);
        let size = parse_chunk_size(&size_text)?;
        index = line_end + 2;
        if size == 0 {
            return Ok(out);
        }
        if index + size > raw.len() {
            return Err(HttpError::BadChunkedBody("truncated chunk".into()));
        }
        out.extend_from_slice(&raw[index..index + size]);
        index += size + 2; // skip the chunk data + trailing CRLF
    }
    Err(HttpError::BadChunkedBody("missing terminal chunk".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_request_owns_host_accept_and_content_length() {
        let headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("X-Solstone-Observer".to_string(), "handle123".to_string()),
            // Caller attempts to set framing-owned headers — must be dropped.
            ("host".to_string(), "evil".to_string()),
            ("content-length".to_string(), "999".to_string()),
        ];
        let bytes = build_request("POST", "/app/observer/ingest", &headers, b"payload");
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("POST /app/observer/ingest HTTP/1.1\r\n"));
        assert!(text.contains("host: spl.local\r\n"));
        assert!(text.contains("accept: application/json\r\n"));
        assert!(text.contains("Content-Type: application/json\r\n"));
        assert!(text.contains("X-Solstone-Observer: handle123\r\n"));
        assert!(text.contains("content-length: 7\r\n"));
        // The caller's spoofed host/content-length never reach the wire.
        assert!(!text.contains("host: evil"));
        assert!(!text.contains("content-length: 999"));
        assert!(text.ends_with("\r\n\r\npayload"));
    }

    #[test]
    fn caller_can_override_accept() {
        let headers = vec![("Accept".to_string(), "*/*".to_string())];
        let text = String::from_utf8(build_request("GET", "/x", &headers, b"")).unwrap();
        assert!(text.contains("Accept: */*\r\n"));
        assert!(!text.contains("accept: application/json"));
    }

    #[test]
    fn parses_content_length_response() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4\r\n\r\n{ok}trailing-garbage";
        let resp = parse_response(raw).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"{ok}");
        assert_eq!(resp.header("content-type"), Some("application/json"));
    }

    #[test]
    fn short_content_length_is_an_error() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nhi";
        assert_eq!(parse_response(raw).unwrap_err(), HttpError::TruncatedBody);
    }

    #[test]
    fn parses_chunked_response() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        let resp = parse_response(raw).unwrap();
        assert_eq!(resp.body, b"Wikipedia");
    }

    #[test]
    fn chunked_response_without_terminal_chunk_is_an_error() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n";
        assert_eq!(
            parse_response(raw).unwrap_err(),
            HttpError::BadChunkedBody("missing terminal chunk".into())
        );
    }

    #[test]
    fn parses_401_with_body() {
        let raw = b"HTTP/1.1 401 UNAUTHORIZED\r\nContent-Length: 16\r\n\r\n{\"error\":\"auth\"}";
        let resp = parse_response(raw).unwrap();
        assert_eq!(resp.status, 401);
        assert!(!resp.is_success());
    }

    #[test]
    fn parse_head_lowercases_headers() {
        let (status, headers) =
            parse_head(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream").unwrap();
        assert_eq!(status, 200);
        assert_eq!(
            headers,
            vec![("content-type".to_string(), "text/event-stream".to_string())]
        );
    }

    #[test]
    fn parse_head_accepts_401() {
        let (status, headers) =
            parse_head(b"HTTP/1.1 401 UNAUTHORIZED\r\nWWW-Authenticate: Bearer").unwrap();
        assert_eq!(status, 401);
        assert_eq!(
            headers,
            vec![("www-authenticate".to_string(), "Bearer".to_string())]
        );
    }

    #[test]
    fn chunked_decoder_byte_at_a_time_reconstructs_body() {
        let raw = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        let mut decoder = ChunkedDecoder::new();
        let mut out = Vec::new();
        for byte in raw {
            out.extend(decoder.push(&[*byte]).unwrap());
        }
        assert_eq!(out, b"Wikipedia");
    }

    #[test]
    fn chunked_decoder_handles_arbitrary_splits() {
        let mut decoder = ChunkedDecoder::new();
        let mut out = Vec::new();
        out.extend(decoder.push(b"4\r\nWi").unwrap());
        out.extend(decoder.push(b"ki\r\n5").unwrap());
        out.extend(decoder.push(b"\r\npedia\r\n0\r").unwrap());
        out.extend(decoder.push(b"\n\r\nignored").unwrap());
        assert_eq!(out, b"Wikipedia");
        assert_eq!(decoder.push(b"more").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn dechunk_rejects_usize_max_chunk_size() {
        assert_eq!(
            dechunk(b"ffffffffffffffff\r\nshort").unwrap_err(),
            HttpError::BadChunkedBody(format!(
                "chunk size {} exceeds max {MAX_PAYLOAD}",
                usize::MAX
            ))
        );
    }

    #[test]
    fn dechunk_rejects_first_over_cap_size_before_truncated_chunk() {
        assert_eq!(
            dechunk(b"1000000\r\nshort").unwrap_err(),
            HttpError::BadChunkedBody(format!(
                "chunk size {} exceeds max {MAX_PAYLOAD}",
                MAX_PAYLOAD + 1
            ))
        );
    }

    #[test]
    fn dechunk_accepts_chunk_at_max_payload() {
        let mut raw = format!("{MAX_PAYLOAD:x}\r\n").into_bytes();
        let body_start = raw.len();
        raw.resize(body_start + MAX_PAYLOAD, b'x');
        raw.extend_from_slice(b"\r\n0\r\n\r\n");

        let body = dechunk(&raw).unwrap();

        assert_eq!(body.len(), MAX_PAYLOAD);
        assert_eq!(body[0], b'x');
        assert_eq!(body[MAX_PAYLOAD / 2], b'x');
        assert_eq!(body[MAX_PAYLOAD - 1], b'x');
    }

    #[test]
    fn chunked_decoder_rejects_over_cap_size_and_latches_failure() {
        let mut decoder = ChunkedDecoder::new();

        assert_eq!(
            decoder.push(b"2000000\r\n").unwrap_err(),
            HttpError::BadChunkedBody(format!(
                "chunk size {} exceeds max {MAX_PAYLOAD}",
                0x2000000
            ))
        );
        assert_eq!(decoder.state, ChunkState::Failed);
        assert!(decoder.buf.is_empty());

        let mut trickled = 0;
        for bytes in [&b"a"[..], &b"bc"[..], &b"def"[..]] {
            trickled += bytes.len();
            assert_eq!(
                decoder.push(bytes).unwrap_err(),
                HttpError::BadChunkedBody("decoder previously failed".into())
            );
            assert!(decoder.buf.len() <= trickled);
            assert!(decoder.buf.len() <= MAX_PAYLOAD);
        }
    }

    #[test]
    fn chunked_decoder_allows_total_body_over_per_chunk_cap() {
        const CHUNK_SIZE: usize = 8 * 1024 * 1024;

        let mut decoder = ChunkedDecoder::new();
        let mut body = Vec::new();
        for byte in [b'a', b'b', b'c'] {
            let mut chunk = format!("{CHUNK_SIZE:x}\r\n").into_bytes();
            let data_start = chunk.len();
            chunk.resize(data_start + CHUNK_SIZE, byte);
            chunk.extend_from_slice(b"\r\n");
            body.extend(decoder.push(&chunk).unwrap());
        }
        assert_eq!(decoder.push(b"0\r\n\r\n").unwrap(), Vec::<u8>::new());

        assert_eq!(body.len(), CHUNK_SIZE * 3);
        assert!(body.len() > MAX_PAYLOAD);
        assert_eq!(body[0], b'a');
        assert_eq!(body[CHUNK_SIZE - 1], b'a');
        assert_eq!(body[CHUNK_SIZE], b'b');
        assert_eq!(body[CHUNK_SIZE * 2], b'c');
        assert_eq!(body[CHUNK_SIZE * 3 - 1], b'c');
    }

    #[test]
    fn missing_terminator_is_an_error() {
        assert_eq!(
            parse_response(b"HTTP/1.1 200 OK\r\n").unwrap_err(),
            HttpError::MissingTerminator
        );
    }
}
