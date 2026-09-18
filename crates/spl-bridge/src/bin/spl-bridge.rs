// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Standalone public SNI-passthrough MCP relay.

use std::io::Write;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::RootCertStore;
use spl_bridge::control_cert::{
    CertMaterialLoader, ControlCertResolver, ReloadCoordinator, control_server_tls_config,
    validate_control_certified_key,
};
use spl_bridge::pop_auth::{JwksTimeouts, JwksTokenVerifier, PopAuthenticator};
use spl_bridge::{
    BridgeLogEvent, TokioControlConnector, pem_certificate_chain, pem_private_key,
    run_client_listener, run_control_listener,
};
use tokio::net::TcpListener;

const DEFAULT_JWKS_TIMEOUT_MS: u64 = 3_000;

struct Options {
    client_listen: SocketAddr,
    control_tls_cert: String,
    control_tls_key: String,
    jwks_url: String,
    bridge_id: String,
    jwks_connect_timeout: Duration,
    jwks_read_timeout: Duration,
    acme_tls_alpn_target: Option<SocketAddr>,
    control_tls_roots: Option<String>,
}

/// Publish the bridge's fixed operational vocabulary to stderr.
///
/// Every event this crate emits is a fixed string literal with no fields,
/// enforced mechanically by the source-policy scanner, so an operator gets
/// routing and admission outcomes without any journal, client, or payload
/// identifier. The level is compiled in rather than read from the
/// environment: the bridge takes no state input from its process
/// environment.
fn install_operational_logging() {
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::INFO)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
}

fn check_version_flag() -> bool {
    std::env::args_os().skip(1).any(|arg| arg == "--version")
}

enum RunError {
    AlreadyEmitted,
    Generic(String),
}

impl From<String> for RunError {
    fn from(s: String) -> Self {
        RunError::Generic(s)
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    if check_version_flag() {
        let version = concat!(
            "spl-bridge ",
            env!("CARGO_PKG_VERSION"),
            " (",
            env!("SPL_BRIDGE_BUILD_ID"),
            ")\n"
        );
        let _ = std::io::stdout().write_all(version.as_bytes());
        return ExitCode::SUCCESS;
    }

    install_operational_logging();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(RunError::AlreadyEmitted) => ExitCode::FAILURE,
        Err(RunError::Generic(_error)) => {
            eprintln!("spl-bridge failed");
            ExitCode::FAILURE
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "bridge startup, validation, and signal lifecycle supervisor"
)]
async fn run() -> Result<(), RunError> {
    let options = parse_options(std::env::args().skip(1))?;

    if let Some(acme_target) = options.acme_tls_alpn_target
        && !acme_target.ip().is_loopback()
    {
        BridgeLogEvent::AcmeTargetRejected.emit();
        return Err(RunError::AlreadyEmitted);
    }

    let certificate_pem = std::fs::read(&options.control_tls_cert)
        .map_err(|_| String::from("could not read --control-tls-cert"))?;
    let private_key_pem = std::fs::read(&options.control_tls_key)
        .map_err(|_| String::from("could not read --control-tls-key"))?;

    let roots = if let Some(roots_path) = &options.control_tls_roots {
        let roots_pem = std::fs::read(roots_path)
            .map_err(|_| String::from("could not read --control-tls-roots"))?;
        let roots_ders = pem_certificate_chain(&roots_pem)
            .map_err(|_| String::from("could not parse --control-tls-roots"))?;
        let mut store = RootCertStore::empty();
        for cert in roots_ders {
            store
                .add(cert)
                .map_err(|_| String::from("could not build root cert store"))?;
        }
        store
    } else {
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned()
            .collect::<RootCertStore>()
    };

    let cert_chain = pem_certificate_chain(&certificate_pem)
        .map_err(|_| String::from("could not parse --control-tls-cert"))?;
    let private_key = pem_private_key(&private_key_pem)
        .map_err(|_| String::from("could not parse --control-tls-key"))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let initial_key = validate_control_certified_key(&cert_chain, &private_key, &roots, now)
        .map_err(|_| {
            BridgeLogEvent::ControlCertificateStartupFailed.emit();
            RunError::AlreadyEmitted
        })?;

    let resolver = Arc::new(ControlCertResolver::new(initial_key));
    let tls_config = control_server_tls_config(Arc::clone(&resolver))
        .map_err(|_| String::from("could not build control TLS configuration"))?;

    let cert_path = options.control_tls_cert.clone();
    let key_path = options.control_tls_key.clone();
    let loader: CertMaterialLoader = Arc::new(move || {
        let cert = std::fs::read(&cert_path)?;
        let key = std::fs::read(&key_path)?;
        Ok((cert, key))
    });
    let clock = Arc::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    });
    let reload_coordinator = Arc::new(ReloadCoordinator::new(
        Arc::clone(&resolver),
        roots,
        clock,
        loader,
    ));

    let verifier = JwksTokenVerifier::with_timeouts(
        &options.jwks_url,
        JwksTimeouts {
            connect: options.jwks_connect_timeout,
            fetch: options.jwks_read_timeout,
        },
        options.bridge_id.clone(),
    )
    .map_err(|_| String::from("invalid --jwks-url"))?;

    let control_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|_| String::from("could not bind internal control listener"))?;
    let control_dial_target = control_listener
        .local_addr()
        .map_err(|_| String::from("could not inspect internal control listener"))?;
    let client_listener = TcpListener::bind(options.client_listen)
        .await
        .map_err(|_| String::from("could not bind --client-listen"))?;

    let registry = spl_bridge::registry::Registry::default();
    let authenticator = PopAuthenticator::new(Arc::new(verifier), options.bridge_id);

    let (shutdown_tx, shutdown_rx_control) = tokio::sync::watch::channel(false);
    let shutdown_rx_client = shutdown_tx.subscribe();

    let control_handle = tokio::spawn(run_control_listener(
        control_listener,
        Arc::new(tls_config),
        registry.clone(),
        authenticator,
        spl_bridge::DEFAULT_ADMISSION_DEADLINE,
        shutdown_rx_control,
    ));

    let client_handle = tokio::spawn(run_client_listener(
        client_listener,
        registry.clone(),
        control_dial_target,
        options.acme_tls_alpn_target,
        spl_bridge::sni::DEFAULT_READ_DEADLINE,
        TokioControlConnector,
        TokioControlConnector,
        shutdown_rx_client,
    ));

    let signal_task = handle_unix_signals(shutdown_tx.clone(), reload_coordinator);
    signal_task.await;

    // Drain sequence
    let _ = shutdown_tx.send_replace(true);
    registry.shutdown_all().await;
    let _ = tokio::join!(control_handle, client_handle);

    Ok(())
}

// SIGHUP/SIGTERM/SIGINT are Unix signals; production is the host-checked Linux bridge.
#[cfg(unix)]
async fn handle_unix_signals(
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    reload_coordinator: Arc<ReloadCoordinator>,
) {
    use tokio::signal::unix::{SignalKind, signal};
    let Ok(mut hup) = signal(SignalKind::hangup()) else {
        return;
    };
    let Ok(mut term) = signal(SignalKind::terminate()) else {
        return;
    };
    let Ok(mut int) = signal(SignalKind::interrupt()) else {
        return;
    };

    let mut reload_tasks = tokio::task::JoinSet::new();

    loop {
        while reload_tasks.try_join_next().is_some() {}

        tokio::select! {
            _ = hup.recv() => {
                let coordinator = Arc::clone(&reload_coordinator);
                reload_tasks.spawn(async move {
                    coordinator.request_reload().await;
                });
            }
            _ = term.recv() => {
                BridgeLogEvent::BridgeShutdownReceived.emit();
                let _ = shutdown_tx.send_replace(true);
                break;
            }
            _ = int.recv() => {
                BridgeLogEvent::BridgeShutdownReceived.emit();
                let _ = shutdown_tx.send_replace(true);
                break;
            }
        }
    }

    reload_tasks.abort_all();
}

#[cfg(not(unix))]
async fn handle_unix_signals(
    _shutdown_tx: tokio::sync::watch::Sender<bool>,
    _reload_coordinator: Arc<ReloadCoordinator>,
) {
    std::future::pending::<()>().await;
}

fn parse_options(arguments: impl Iterator<Item = String>) -> Result<Options, String> {
    let mut client_listen = None;
    let mut control_tls_cert = None;
    let mut control_tls_key = None;
    let mut jwks_url = None;
    let mut bridge_id = None;
    let mut jwks_connect_timeout = DEFAULT_JWKS_TIMEOUT_MS;
    let mut jwks_read_timeout = DEFAULT_JWKS_TIMEOUT_MS;
    let mut acme_tls_alpn_target = None;
    let mut control_tls_roots = None;
    let mut arguments = arguments;

    while let Some(flag) = arguments.next() {
        if flag == "--version" {
            continue;
        }
        let value = arguments
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag.as_str() {
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
            "--acme-tls-alpn-target" => {
                acme_tls_alpn_target = Some(parse_address(&value, &flag)?);
            }
            "--control-tls-roots" => control_tls_roots = Some(value),
            _ => return Err(format!("unknown option {flag}")),
        }
    }

    Ok(Options {
        client_listen: client_listen.ok_or(String::from("--client-listen is required"))?,
        control_tls_cert: control_tls_cert.ok_or(String::from("--control-tls-cert is required"))?,
        control_tls_key: control_tls_key.ok_or(String::from("--control-tls-key is required"))?,
        jwks_url: jwks_url.ok_or(String::from("--jwks-url is required"))?,
        bridge_id: bridge_id.ok_or(String::from("--bridge-id is required"))?,
        jwks_connect_timeout: Duration::from_millis(jwks_connect_timeout),
        jwks_read_timeout: Duration::from_millis(jwks_read_timeout),
        acme_tls_alpn_target,
        control_tls_roots,
    })
}

fn parse_address(value: &str, flag: &str) -> Result<SocketAddr, String> {
    value
        .parse()
        .map_err(|_| format!("invalid address for {flag}"))
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

    use super::{parse_options, validate_bridge_id};

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
    fn client_listen_remains_unrestricted() {
        let options = parse_options(
            [
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

    #[test]
    fn control_listen_is_not_a_recognized_option() {
        let result = parse_options(
            ["--control-listen", "127.0.0.1:8080"]
                .into_iter()
                .map(String::from),
        );
        assert!(matches!(result, Err(error) if error == "unknown option --control-listen"));
    }

    #[test]
    fn parses_optional_acme_target_and_roots() {
        let options = parse_options(
            [
                "--client-listen",
                "127.0.0.1:443",
                "--control-tls-cert",
                "cert.pem",
                "--control-tls-key",
                "key.pem",
                "--jwks-url",
                "https://jwks.test/keys",
                "--bridge-id",
                "bridge",
                "--acme-tls-alpn-target",
                "127.0.0.1:5001",
                "--control-tls-roots",
                "roots.pem",
            ]
            .into_iter()
            .map(String::from),
        )
        .unwrap();
        assert_eq!(
            options.acme_tls_alpn_target,
            Some("127.0.0.1:5001".parse().unwrap())
        );
        assert_eq!(options.control_tls_roots, Some(String::from("roots.pem")));
    }
}
