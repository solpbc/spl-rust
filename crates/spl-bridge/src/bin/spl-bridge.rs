// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Standalone public SNI-passthrough MCP relay.

use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use spl_bridge::pop_auth::{JwksTimeouts, JwksTokenVerifier, PopAuthenticator};
use spl_bridge::{
    pem_certificate_chain, pem_private_key, run_client_listener, run_control_listener,
    server_tls_config,
};
use tokio::net::TcpListener;

const DEFAULT_JWKS_TIMEOUT_MS: u64 = 3_000;

struct Options {
    control_listen: SocketAddr,
    client_listen: SocketAddr,
    control_tls_cert: String,
    control_tls_key: String,
    jwks_url: String,
    bridge_id: String,
    jwks_connect_timeout: Duration,
    jwks_read_timeout: Duration,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("spl-bridge: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    let options = parse_options(std::env::args().skip(1))?;
    let certificate_pem = std::fs::read(&options.control_tls_cert)
        .map_err(|_| String::from("could not read --control-tls-cert"))?;
    let private_key_pem = std::fs::read(&options.control_tls_key)
        .map_err(|_| String::from("could not read --control-tls-key"))?;
    let tls_config = server_tls_config(
        pem_certificate_chain(&certificate_pem)
            .map_err(|_| String::from("could not parse --control-tls-cert"))?,
        pem_private_key(&private_key_pem)
            .map_err(|_| String::from("could not parse --control-tls-key"))?,
    )
    .map_err(|_| String::from("could not build control TLS configuration"))?;
    let verifier = JwksTokenVerifier::with_timeouts(
        &options.jwks_url,
        JwksTimeouts {
            connect: options.jwks_connect_timeout,
            fetch: options.jwks_read_timeout,
        },
        options.bridge_id.clone(),
    )
    .map_err(|_| String::from("invalid --jwks-url"))?;
    let control_listener = TcpListener::bind(options.control_listen)
        .await
        .map_err(|_| String::from("could not bind --control-listen"))?;
    let client_listener = TcpListener::bind(options.client_listen)
        .await
        .map_err(|_| String::from("could not bind --client-listen"))?;

    let registry = spl_bridge::registry::Registry::default();
    let authenticator = PopAuthenticator::new(Arc::new(verifier), options.bridge_id);
    tokio::join!(
        run_control_listener(
            control_listener,
            Arc::new(tls_config),
            registry.clone(),
            authenticator,
            spl_bridge::DEFAULT_ADMISSION_DEADLINE,
        ),
        run_client_listener(
            client_listener,
            registry,
            spl_bridge::sni::DEFAULT_READ_DEADLINE,
        ),
    );
    Ok(())
}

fn parse_options(arguments: impl Iterator<Item = String>) -> Result<Options, String> {
    let mut control_listen = None;
    let mut client_listen = None;
    let mut control_tls_cert = None;
    let mut control_tls_key = None;
    let mut jwks_url = None;
    let mut bridge_id = None;
    let mut jwks_connect_timeout = DEFAULT_JWKS_TIMEOUT_MS;
    let mut jwks_read_timeout = DEFAULT_JWKS_TIMEOUT_MS;
    let mut arguments = arguments;

    while let Some(flag) = arguments.next() {
        let value = arguments
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag.as_str() {
            "--control-listen" => {
                let address = parse_address(&value, &flag)?;
                validate_control_listen(&address)?;
                control_listen = Some(address);
            }
            "--client-listen" => client_listen = Some(parse_address(&value, &flag)?),
            "--control-tls-cert" => control_tls_cert = Some(value),
            "--control-tls-key" => control_tls_key = Some(value),
            "--jwks-url" => jwks_url = Some(value),
            "--bridge-id" => {
                validate_bridge_id(&value)?;
                bridge_id = Some(value);
            }
            "--jwks-connect-timeout-ms" => jwks_connect_timeout = parse_timeout(&value, &flag)?,
            "--jwks-read-timeout-ms" => jwks_read_timeout = parse_timeout(&value, &flag)?,
            _ => return Err(format!("unknown option {flag}")),
        }
    }

    Ok(Options {
        control_listen: control_listen.ok_or(String::from("--control-listen is required"))?,
        client_listen: client_listen.ok_or(String::from("--client-listen is required"))?,
        control_tls_cert: control_tls_cert.ok_or(String::from("--control-tls-cert is required"))?,
        control_tls_key: control_tls_key.ok_or(String::from("--control-tls-key is required"))?,
        jwks_url: jwks_url.ok_or(String::from("--jwks-url is required"))?,
        bridge_id: bridge_id.ok_or(String::from("--bridge-id is required"))?,
        jwks_connect_timeout: Duration::from_millis(jwks_connect_timeout),
        jwks_read_timeout: Duration::from_millis(jwks_read_timeout),
    })
}

fn parse_address(value: &str, flag: &str) -> Result<SocketAddr, String> {
    value
        .parse()
        .map_err(|_| format!("invalid address for {flag}"))
}

fn validate_control_listen(address: &SocketAddr) -> Result<(), String> {
    if address.ip().is_loopback() {
        Ok(())
    } else {
        Err(String::from(
            "invalid --control-listen: address must be loopback",
        ))
    }
}

fn parse_timeout(value: &str, flag: &str) -> Result<u64, String> {
    let timeout = value
        .parse::<u64>()
        .map_err(|_| format!("invalid timeout for {flag}"))?;
    if timeout == 0 {
        Err(format!("timeout for {flag} must be greater than zero"))
    } else {
        Ok(timeout)
    }
}

fn validate_bridge_id(value: &str) -> Result<(), String> {
    if (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        Ok(())
    } else {
        Err(String::from(
            "invalid --bridge-id: must be 1-128 characters from [A-Za-z0-9._:-]",
        ))
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test asserts on the rejection error directly"
    )]

    use super::{parse_options, validate_bridge_id, validate_control_listen};

    #[test]
    fn bridge_id_accepts_the_configured_grammar() {
        for value in ["bridge", "mcp-bridge-fixture", "a.b_c:d-9"] {
            assert_eq!(validate_bridge_id(value), Ok(()));
        }
    }

    #[test]
    fn bridge_id_rejections_do_not_echo_the_input() {
        let too_long = "a".repeat(129);
        let invalid = [
            "",
            " ",
            " bridge",
            "bridge ",
            "bridge\n",
            "brídge",
            "bridge!",
            "bridge/name",
            &too_long,
        ];
        for value in invalid {
            let error = validate_bridge_id(value).unwrap_err();
            assert_eq!(
                error,
                "invalid --bridge-id: must be 1-128 characters from [A-Za-z0-9._:-]"
            );
        }
    }

    #[test]
    fn control_listen_accepts_ipv4_and_ipv6_loopback() {
        for value in ["127.0.0.1:8080", "[::1]:8080"] {
            assert_eq!(validate_control_listen(&value.parse().unwrap()), Ok(()));
        }
    }

    #[test]
    fn control_listen_rejections_do_not_echo_the_input() {
        for value in [
            "0.0.0.0:8080",
            "[::]:8080",
            "10.0.0.1:8080",
            "192.168.1.1:8080",
            "169.254.1.1:8080",
            "[fe80::1]:8080",
            "1.1.1.1:8080",
        ] {
            let error = validate_control_listen(&value.parse().unwrap()).unwrap_err();
            assert_eq!(error, "invalid --control-listen: address must be loopback");
            assert!(!error.contains(value));
        }
    }

    #[test]
    fn client_listen_remains_unrestricted() {
        let options = parse_options(
            [
                "--control-listen",
                "127.0.0.1:8080",
                "--client-listen",
                "1.1.1.1:8443",
                "--control-tls-cert",
                "cert.pem",
                "--control-tls-key",
                "key.pem",
                "--jwks-url",
                "https://jwks.test/keys",
                "--bridge-id",
                "bridge",
            ]
            .into_iter()
            .map(String::from),
        )
        .unwrap();
        assert_eq!(options.client_listen, "1.1.1.1:8443".parse().unwrap());
    }
}
