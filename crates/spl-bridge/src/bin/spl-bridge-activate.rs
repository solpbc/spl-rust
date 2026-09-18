// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Atomic staged certificate activation tool for spl-bridge.

#![expect(
    clippy::unwrap_used,
    clippy::manual_let_else,
    clippy::too_many_lines,
    reason = "CLI binary uses validated optional CLI arguments and staged generation workflows"
)]

use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::RootCertStore;
use rustls::pki_types::ServerName;
use spl_bridge::control_cert::{RESERVED_CONTROL_SNI, validate_control_certified_key};
use spl_bridge::{pem_certificate_chain, pem_private_key};
use tokio_rustls::TlsConnector;

const OVERALL_DEADLINE: Duration = Duration::from_secs(30);
const VERIFY_DEADLINE: Duration = Duration::from_secs(10);

fn check_version_flag() -> bool {
    std::env::args_os().skip(1).any(|arg| arg == "--version")
}

#[derive(Debug, Default)]
struct ActivateOptions {
    issued_cert: Option<PathBuf>,
    issued_key: Option<PathBuf>,
    generations_dir: Option<PathBuf>,
    verify_addr: Option<SocketAddr>,
    reload_cmd: Option<String>,
    control_tls_roots: Option<PathBuf>,
    retry_pending: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    if check_version_flag() {
        let version = concat!(
            "spl-bridge-activate ",
            env!("CARGO_PKG_VERSION"),
            " (",
            env!("SPL_BRIDGE_BUILD_ID"),
            ")\n"
        );
        let _ = std::io::stdout().write_all(version.as_bytes());
        return ExitCode::SUCCESS;
    }

    let options = if let Ok(opts) = parse_activate_options(std::env::args().skip(1)) {
        opts
    } else {
        eprintln!(
            "usage: spl-bridge-activate --issued-cert <path> --issued-key <path> --generations-dir <path> --verify-addr <addr> --reload-cmd <cmd>"
        );
        return ExitCode::from(1);
    };

    if let Ok(code) = tokio::time::timeout(OVERALL_DEADLINE, run_activate(options)).await {
        code
    } else {
        eprintln!("activation timed out");
        ExitCode::from(1)
    }
}

fn parse_activate_options(arguments: impl Iterator<Item = String>) -> Result<ActivateOptions, ()> {
    let mut options = ActivateOptions::default();
    let mut args = arguments.peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--issued-cert" => {
                options.issued_cert = Some(PathBuf::from(args.next().ok_or(())?));
            }
            "--issued-key" => {
                options.issued_key = Some(PathBuf::from(args.next().ok_or(())?));
            }
            "--generations-dir" => {
                options.generations_dir = Some(PathBuf::from(args.next().ok_or(())?));
            }
            "--verify-addr" => {
                let addr_str = args.next().ok_or(())?;
                options.verify_addr = Some(addr_str.parse().map_err(|_| ())?);
            }
            "--reload-cmd" => {
                options.reload_cmd = Some(args.next().ok_or(())?);
            }
            "--control-tls-roots" => {
                options.control_tls_roots = Some(PathBuf::from(args.next().ok_or(())?));
            }
            "--retry-pending" => {
                options.retry_pending = true;
            }
            _ => return Err(()),
        }
    }

    if options.generations_dir.is_none()
        || options.verify_addr.is_none()
        || options.reload_cmd.is_none()
    {
        return Err(());
    }

    if !options.retry_pending && (options.issued_cert.is_none() || options.issued_key.is_none()) {
        return Err(());
    }

    Ok(options)
}

fn load_roots(control_tls_roots: Option<&Path>) -> Result<RootCertStore, ()> {
    if let Some(roots_path) = control_tls_roots {
        let roots_pem = fs::read(roots_path).map_err(|_| ())?;
        let root_certs = pem_certificate_chain(&roots_pem).map_err(|_| ())?;
        let mut store = RootCertStore::empty();
        for cert in root_certs {
            store.add(cert).map_err(|_| ())?;
        }
        Ok(store)
    } else {
        Ok(webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned()
            .collect::<RootCertStore>())
    }
}

async fn run_activate(options: ActivateOptions) -> ExitCode {
    let generations_dir = options.generations_dir.as_ref().unwrap();
    if fs::create_dir_all(generations_dir).is_err() {
        eprintln!("failed to create generations directory");
        return ExitCode::from(1);
    }

    let roots = if let Ok(r) = load_roots(options.control_tls_roots.as_deref()) {
        r
    } else {
        eprintln!("certificate validation failed");
        return ExitCode::from(1);
    };

    let verify_addr = options.verify_addr.unwrap();
    let reload_cmd = options.reload_cmd.as_ref().unwrap();

    if options.retry_pending {
        return retry_pending_flow(generations_dir, &roots, verify_addr, reload_cmd).await;
    }

    let issued_cert_path = options.issued_cert.as_ref().unwrap();
    let issued_key_path = options.issued_key.as_ref().unwrap();

    let cert_bytes = if let Ok(b) = fs::read(issued_cert_path) {
        b
    } else {
        eprintln!("certificate validation failed");
        return ExitCode::from(1);
    };
    let key_bytes = if let Ok(b) = fs::read(issued_key_path) {
        b
    } else {
        eprintln!("certificate validation failed");
        return ExitCode::from(1);
    };

    let cert_chain = if let Ok(c) = pem_certificate_chain(&cert_bytes) {
        c
    } else {
        eprintln!("certificate validation failed");
        return ExitCode::from(1);
    };
    let private_key = if let Ok(k) = pem_private_key(&key_bytes) {
        k
    } else {
        eprintln!("certificate validation failed");
        return ExitCode::from(1);
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let initial_key =
        if let Ok(k) = validate_control_certified_key(&cert_chain, &private_key, &roots, now) {
            k
        } else {
            eprintln!("certificate validation failed");
            return ExitCode::from(1);
        };

    let expected_leaf = if let Ok(cert) = initial_key.end_entity_cert() {
        cert.as_ref().to_vec()
    } else {
        eprintln!("certificate validation failed");
        return ExitCode::from(1);
    };

    // Stage new generation
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id();
    let gen_dir = generations_dir.join(format!("gen_{timestamp}_{pid}"));
    if fs::create_dir_all(&gen_dir).is_err() {
        eprintln!("failed to stage generation");
        return ExitCode::from(1);
    }

    if write_generation_files(&gen_dir, &cert_bytes, &key_bytes).is_err() {
        let _ = fs::remove_dir_all(&gen_dir);
        eprintln!("failed to stage generation");
        return ExitCode::from(1);
    }

    let prior_generation = fs::read_link(generations_dir.join("active")).ok();
    let prior_leaf = prior_generation.as_ref().and_then(|prior| {
        let prior_path = if prior.is_relative() {
            generations_dir.join(prior)
        } else {
            prior.clone()
        };
        let cert_data = fs::read(prior_path.join("cert.pem")).ok()?;
        let chain = pem_certificate_chain(&cert_data).ok()?;
        chain.first().map(|c| c.as_ref().to_vec())
    });

    // Switch active pointer
    if atomic_symlink_switch(generations_dir, &gen_dir, "active").is_err() {
        let _ = fs::remove_dir_all(&gen_dir);
        eprintln!("failed to switch active pointer");
        return ExitCode::from(1);
    }

    // Run reload command
    if run_reload(reload_cmd).await.is_err()
        || verify_generation(verify_addr, &roots, &expected_leaf)
            .await
            .is_err()
    {
        // Retain generation as pending
        let pending_path = generations_dir.join("pending");
        let _ = fs::remove_dir_all(&pending_path);
        let _ = fs::remove_file(&pending_path);
        let _ = atomic_symlink_switch(generations_dir, &gen_dir, "pending");

        // Rollback active pointer
        if let Some(prior) = &prior_generation {
            let prior_path = if prior.is_relative() {
                generations_dir.join(prior)
            } else {
                prior.clone()
            };
            let _ = atomic_symlink_switch(generations_dir, &prior_path, "active");
            let rollback_reload = run_reload(reload_cmd).await;
            let rollback_verify = if let Some(leaf) = &prior_leaf {
                verify_generation(verify_addr, &roots, leaf).await
            } else {
                Ok(())
            };

            if rollback_reload.is_err() || rollback_verify.is_err() {
                eprintln!("rollback activation failed");
                return ExitCode::from(1);
            }
        }

        eprintln!("activation failed: reload or verify failed; rolled back");
        return ExitCode::from(1);
    }

    ExitCode::SUCCESS
}

async fn retry_pending_flow(
    generations_dir: &Path,
    roots: &RootCertStore,
    verify_addr: SocketAddr,
    reload_cmd: &str,
) -> ExitCode {
    let pending_link = generations_dir.join("pending");
    if !pending_link.exists() {
        eprintln!("pending generation not found");
        return ExitCode::from(1);
    }

    let pending_dir = match fs::read_link(&pending_link) {
        Ok(target) => {
            if target.is_relative() {
                generations_dir.join(target)
            } else {
                target
            }
        }
        Err(_) => pending_link.clone(),
    };

    let cert_bytes = if let Ok(b) = fs::read(pending_dir.join("cert.pem")) {
        b
    } else {
        quarantine_pending(generations_dir, &pending_link);
        eprintln!("pending certificate quarantined: validation failed");
        return ExitCode::from(2);
    };
    let key_bytes = if let Ok(b) = fs::read(pending_dir.join("key.pem")) {
        b
    } else {
        quarantine_pending(generations_dir, &pending_link);
        eprintln!("pending certificate quarantined: validation failed");
        return ExitCode::from(2);
    };

    let cert_chain = if let Ok(c) = pem_certificate_chain(&cert_bytes) {
        c
    } else {
        quarantine_pending(generations_dir, &pending_link);
        eprintln!("pending certificate quarantined: validation failed");
        return ExitCode::from(2);
    };
    let private_key = if let Ok(k) = pem_private_key(&key_bytes) {
        k
    } else {
        quarantine_pending(generations_dir, &pending_link);
        eprintln!("pending certificate quarantined: validation failed");
        return ExitCode::from(2);
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let initial_key =
        if let Ok(k) = validate_control_certified_key(&cert_chain, &private_key, roots, now) {
            k
        } else {
            quarantine_pending(generations_dir, &pending_link);
            eprintln!("pending certificate quarantined: validation failed");
            return ExitCode::from(2);
        };

    let expected_leaf = if let Ok(cert) = initial_key.end_entity_cert() {
        cert.as_ref().to_vec()
    } else {
        quarantine_pending(generations_dir, &pending_link);
        eprintln!("pending certificate quarantined: validation failed");
        return ExitCode::from(2);
    };

    let prior_generation = fs::read_link(generations_dir.join("active")).ok();
    let prior_leaf = prior_generation.as_ref().and_then(|prior| {
        let prior_path = if prior.is_relative() {
            generations_dir.join(prior)
        } else {
            prior.clone()
        };
        let cert_data = fs::read(prior_path.join("cert.pem")).ok()?;
        let chain = pem_certificate_chain(&cert_data).ok()?;
        chain.first().map(|c| c.as_ref().to_vec())
    });

    if atomic_symlink_switch(generations_dir, &pending_dir, "active").is_err() {
        eprintln!("failed to switch active pointer");
        return ExitCode::from(3);
    }

    if run_reload(reload_cmd).await.is_err()
        || verify_generation(verify_addr, roots, &expected_leaf)
            .await
            .is_err()
    {
        if let Some(prior) = &prior_generation {
            let prior_path = if prior.is_relative() {
                generations_dir.join(prior)
            } else {
                prior.clone()
            };
            let _ = atomic_symlink_switch(generations_dir, &prior_path, "active");
            let rollback_reload = run_reload(reload_cmd).await;
            let rollback_verify = if let Some(leaf) = &prior_leaf {
                verify_generation(verify_addr, roots, leaf).await
            } else {
                Ok(())
            };

            if rollback_reload.is_err() || rollback_verify.is_err() {
                eprintln!("rollback activation failed");
                return ExitCode::from(3);
            }
        }

        eprintln!("activation failed: reload or verify failed; rolled back");
        return ExitCode::from(3);
    }

    let _ = fs::remove_file(&pending_link);
    let _ = fs::remove_dir_all(&pending_link);
    ExitCode::SUCCESS
}

fn quarantine_pending(generations_dir: &Path, pending_path: &Path) {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let quarantine_name = format!("quarantine_{timestamp}");
    let quarantine_path = generations_dir.join(quarantine_name);
    let _ = fs::rename(pending_path, quarantine_path);
}

fn write_generation_files(
    gen_dir: &Path,
    cert_bytes: &[u8],
    key_bytes: &[u8],
) -> Result<(), std::io::Error> {
    let cert_file_path = gen_dir.join("cert.pem");
    fs::write(&cert_file_path, cert_bytes)?;

    #[cfg(unix)]
    {
        let perms = std::os::unix::fs::PermissionsExt::from_mode(0o644);
        let _ = fs::set_permissions(&cert_file_path, perms);
    }

    let key_file_path = gen_dir.join("key.pem");
    fs::write(&key_file_path, key_bytes)?;

    #[cfg(unix)]
    {
        let perms = std::os::unix::fs::PermissionsExt::from_mode(0o640);
        let _ = fs::set_permissions(&key_file_path, perms);
    }

    Ok(())
}

fn atomic_symlink_switch(
    generations_dir: &Path,
    target: &Path,
    link_name: &str,
) -> Result<(), std::io::Error> {
    let pid = std::process::id();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tmp_link = generations_dir.join(format!(".{link_name}.tmp.{pid}.{timestamp}"));
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, &tmp_link)?;
    #[cfg(not(unix))]
    let _ = target;

    fs::rename(&tmp_link, generations_dir.join(link_name))?;
    Ok(())
}

async fn run_reload(reload_cmd: &str) -> Result<(), ()> {
    let mut child = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(reload_cmd)
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| ())?;
    let status = tokio::time::timeout(VERIFY_DEADLINE, child.wait())
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;

    if status.success() { Ok(()) } else { Err(()) }
}

async fn verify_generation(
    verify_addr: SocketAddr,
    roots: &RootCertStore,
    expected_leaf: &[u8],
) -> Result<(), ()> {
    tokio::time::timeout(
        VERIFY_DEADLINE,
        verify_handshake(verify_addr, roots, expected_leaf),
    )
    .await
    .map_err(|_| ())?
}

async fn verify_handshake(
    addr: SocketAddr,
    roots: &RootCertStore,
    expected_leaf: &[u8],
) -> Result<(), ()> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let client_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| ())?
        .with_root_certificates(roots.clone())
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(client_config));
    let tcp_stream = tokio::net::TcpStream::connect(addr).await.map_err(|_| ())?;

    let server_name = ServerName::try_from(RESERVED_CONTROL_SNI).map_err(|_| ())?;
    let tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .map_err(|_| ())?;

    let (_, session) = tls_stream.into_inner();
    let peer_certs = session.peer_certificates().ok_or(())?;
    let leaf = peer_certs.first().ok_or(())?;

    if leaf.as_ref() == expected_leaf {
        Ok(())
    } else {
        Err(())
    }
}
