// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Plain HTTP/HTTPS JSON POSTs to the relay control plane.

use std::io;
use std::time::Duration;

use rustls::pki_types::ServerName;
use spl_core::http::{self, HttpResponse};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::{TransportError, relay};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Upper bound on the control-plane TLS handshake. This leg crosses the public
/// internet rather than a LAN, so it carries the same budget as the relay carrier's
/// inner handshake rather than the tighter direct-dial one.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
#[expect(
    clippy::duration_suboptimal_units,
    reason = "the copied relay timeout remains expressed in protocol-facing seconds"
)]
const READ_TIMEOUT: Duration = Duration::from_secs(60);
const READ_BUF: usize = 16 * 1024;

enum RelayScheme {
    Http,
    Https,
}

struct RelayOrigin {
    scheme: RelayScheme,
    host: String,
    port: u16,
    authority: String,
}

pub(crate) async fn relay_https_post_json(
    relay_origin: &str,
    path_and_query: &str,
    body: &[u8],
) -> Result<HttpResponse, TransportError> {
    if !path_and_query.starts_with('/') {
        return Err(TransportError::PairLink("relay request path".into()));
    }

    let origin = parse_relay_origin(relay_origin)?;
    match origin.scheme {
        RelayScheme::Http => {
            let tcp = connect(&origin.host, origin.port).await?;
            #[expect(
                clippy::large_futures,
                reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
            )]
            let response =
                post_json_over_stream(tcp, &origin.authority, path_and_query, body).await;
            response
        }
        RelayScheme::Https => {
            let tcp = connect(&origin.host, origin.port).await?;
            let server_name = ServerName::try_from(origin.host.clone())
                .map_err(|_| TransportError::Tls("relay server name".into()))?;
            let connector = TlsConnector::from(relay::outer_config());
            // Bounded for the same reason the carrier's handshake is: reaching the peer
            // and completing a handshake with it are separate things, and a peer that
            // accepts the connection then goes silent must not park a control request
            // for longer than the request itself is allowed.
            let tls =
                match tokio::time::timeout(HANDSHAKE_TIMEOUT, connector.connect(server_name, tcp))
                    .await
                {
                    Err(_) => {
                        return Err(TransportError::Io(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "relay control tls handshake timed out",
                        )));
                    }
                    Ok(result) => result
                        .map_err(|e| TransportError::Tls(format!("relay control tls: {e}")))?,
                };
            #[expect(
                clippy::large_futures,
                reason = "the copied transport future keeps its established stack layout; this site goes red if a later refactor shrinks it"
            )]
            let response =
                post_json_over_stream(tls, &origin.authority, path_and_query, body).await;
            response
        }
    }
}

fn parse_relay_origin(origin: &str) -> Result<RelayOrigin, TransportError> {
    let (scheme, rest, default_port) = if let Some(rest) = origin.strip_prefix("https://") {
        (RelayScheme::Https, rest, 443)
    } else if let Some(rest) = origin.strip_prefix("http://") {
        (RelayScheme::Http, rest, 80)
    } else {
        return Err(TransportError::PairLink(
            "unsupported relay origin scheme".into(),
        ));
    };

    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if authority.is_empty()
        || authority.contains('/')
        || authority.contains('?')
        || authority.contains('#')
    {
        return Err(TransportError::PairLink("relay origin must be bare".into()));
    }

    let (host, port) = parse_authority(authority, default_port)?;
    Ok(RelayOrigin {
        scheme,
        host,
        port,
        authority: authority.to_string(),
    })
}

fn parse_authority(authority: &str, default_port: u16) -> Result<(String, u16), TransportError> {
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| TransportError::PairLink("bad relay origin host".into()))?;
        let host = rest[..end].to_string();
        let after = &rest[end + 1..];
        let port = if let Some(port) = after.strip_prefix(':') {
            parse_port(port)?
        } else if after.is_empty() {
            default_port
        } else {
            return Err(TransportError::PairLink("bad relay origin port".into()));
        };
        return Ok((host, port));
    }

    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (host.to_string(), parse_port(port)?),
        _ => (authority.to_string(), default_port),
    };
    if host.is_empty() {
        return Err(TransportError::PairLink("bad relay origin host".into()));
    }
    Ok((host, port))
}

fn parse_port(port: &str) -> Result<u16, TransportError> {
    let port = port
        .parse::<u16>()
        .map_err(|_| TransportError::PairLink("bad relay origin port".into()))?;
    if port == 0 {
        Err(TransportError::PairLink("bad relay origin port".into()))
    } else {
        Ok(port)
    }
}

async fn connect(host: &str, port: u16) -> Result<TcpStream, TransportError> {
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port)))
        .await
        .map_err(|_| {
            TransportError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "relay control connect timed out",
            ))
        })??;
    tcp.set_nodelay(true).ok();
    Ok(tcp)
}

async fn post_json_over_stream<S>(
    mut stream: S,
    authority: &str,
    path_and_query: &str,
    body: &[u8],
) -> Result<HttpResponse, TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = build_request(authority, path_and_query, body);
    stream.write_all(&request).await?;
    stream.flush().await?;

    let mut raw = Vec::new();
    let mut buf = [0u8; READ_BUF];
    loop {
        match tokio::time::timeout(READ_TIMEOUT, stream.read(&mut buf)).await {
            Err(_) => {
                return Err(TransportError::Io(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "relay control read timed out",
                )));
            }
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                raw.extend_from_slice(&buf[..n]);
                if let Ok(response) = http::parse_response(&raw)
                    && response_is_complete(&response)
                {
                    let _ = stream.shutdown().await;
                    return Ok(response);
                }
            }
            Ok(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Ok(Err(e)) => return Err(TransportError::Io(e)),
        }
    }

    let response = http::parse_response(&raw)?;
    let _ = stream.shutdown().await;
    Ok(response)
}

fn build_request(authority: &str, path_and_query: &str, body: &[u8]) -> Vec<u8> {
    let head = format!(
        "POST {path_and_query} HTTP/1.1\r\n\
         host: {authority}\r\n\
         accept: application/json\r\n\
         content-type: application/json\r\n\
         content-length: {}\r\n\
         connection: close\r\n\r\n",
        body.len()
    );
    let mut request = head.into_bytes();
    request.extend_from_slice(body);
    request
}

fn response_is_complete(response: &HttpResponse) -> bool {
    #[expect(
        clippy::map_unwrap_or,
        reason = "the copied completeness predicate keeps missing or invalid lengths as an explicit false fallback"
    )]
    response
        .header("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .map(|len| response.body.len() >= len)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[tokio::test]
    async fn chunked_response_split_across_reads_waits_for_eof() {
        let (client, mut server) = duplex(1024);
        let server_task = tokio::spawn(async move {
            let mut request = Vec::new();
            let mut buf = [0u8; 256];
            loop {
                let n = server.read(&mut buf).await.unwrap();
                assert_ne!(n, 0);
                request.extend_from_slice(&buf[..n]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }

            server
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n")
                .await
                .unwrap();
            tokio::task::yield_now().await;
            server.write_all(b"5\r\npedia\r\n0\r\n\r\n").await.unwrap();
            server.shutdown().await.unwrap();
        });

        let response = post_json_over_stream(client, "relay.test", "/x", b"{}")
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"Wikipedia");
        server_task.await.unwrap();
    }
}
