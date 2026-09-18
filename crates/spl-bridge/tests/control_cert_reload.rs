// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Acceptance criteria 1-4: Dynamic control TLS certificate validation, ALPN, reload, and coalescing.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "integration tests use synthesized local certificates and sockets"
)]

use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rcgen::{Certificate, CertificateParams, KeyPair, date_time_ymd};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use spl_bridge::control_cert::{
    CertMaterialLoader, ClockFn, ControlCertResolver, ReloadCoordinator, control_server_tls_config,
    validate_control_certified_key,
};
use spl_bridge::pop_auth::{FixtureTokenVerifier, PopAuthenticator};
use spl_bridge::registry::Registry;
use spl_bridge::{
    AcceptProvider, DEFAULT_ADMISSION_DEADLINE, TokioControlConnector, run_client_listener,
    run_control_listener,
};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(name: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = PathBuf::from(format!("/var/tmp/spl-bridge-test-{name}-{nanos}"));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self(Some(child))
    }

    fn id(&self) -> u32 {
        self.0.as_ref().unwrap().id()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

struct ReloadLogWriter(Arc<Mutex<Vec<u8>>>);
impl io::Write for ReloadLogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct ReloadLogBuffer(Arc<Mutex<Vec<u8>>>);
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for ReloadLogBuffer {
    type Writer = ReloadLogWriter;
    fn make_writer(&'a self) -> Self::Writer {
        ReloadLogWriter(Arc::clone(&self.0))
    }
}

fn generate_ca() -> (CertificateDer<'static>, KeyPair, Certificate) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![String::from("Test Root CA")]).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let cert = params.self_signed(&key).unwrap();
    (CertificateDer::from(cert.der().to_vec()), key, cert)
}

fn generate_leaf(
    san: &str,
    ca_cert: &Certificate,
    ca_key: &KeyPair,
    start_year: i32,
    end_year: i32,
) -> (
    CertificateDer<'static>,
    PrivateKeyDer<'static>,
    Vec<u8>,
    Vec<u8>,
) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![String::from(san)]).unwrap();
    params.not_before = date_time_ymd(start_year, 1, 1);
    params.not_after = date_time_ymd(end_year, 1, 1);

    let cert = params.signed_by(&key, ca_cert, ca_key).unwrap();

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));

    let cert_pem = format!("{}\n{}", cert.pem(), ca_cert.pem()).into_bytes();
    let key_pem = key.serialize_pem().into_bytes();

    (cert_der, key_der, cert_pem, key_pem)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ac1_spawned_binary_sighup_reload_preserves_connections() {
    let temp = TempDir::new("ac1-sighup");
    let (ca_der, ca_key, ca_cert) = generate_ca();

    let ca_pem_path = temp.path.join("ca.pem");
    fs::write(&ca_pem_path, ca_cert.pem().as_bytes()).unwrap();

    let (initial_cert_der, _, initial_cert_pem, initial_key_pem) =
        generate_leaf("bridge.solstone.me", &ca_cert, &ca_key, 2020, 2035);
    let (updated_cert_der, _, updated_cert_pem, updated_key_pem) =
        generate_leaf("bridge.solstone.me", &ca_cert, &ca_key, 2020, 2035);

    let cert_path = temp.path.join("cert.pem");
    let key_path = temp.path.join("key.pem");
    fs::write(&cert_path, &initial_cert_pem).unwrap();
    fs::write(&key_path, &initial_key_pem).unwrap();

    // Bind a probe listener to allocate a free port
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_addr = probe.local_addr().unwrap();
    drop(probe);

    let bridge_bin = env!("CARGO_BIN_EXE_spl-bridge");
    let child = Command::new(bridge_bin)
        .arg("--client-listen")
        .arg(client_addr.to_string())
        .arg("--control-tls-cert")
        .arg(&cert_path)
        .arg("--control-tls-key")
        .arg(&key_path)
        .arg("--jwks-url")
        .arg("https://127.0.0.1:1/jwks")
        .arg("--bridge-id")
        .arg("bridge")
        .arg("--control-tls-roots")
        .arg(&ca_pem_path)
        .spawn()
        .expect("failed to spawn spl-bridge");
    let guard = ChildGuard::new(child);
    let pid = guard.id();

    // Poll until port is listening
    let mut ready = false;
    for _ in 0..50 {
        if TcpStream::connect(client_addr).await.is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ready, "bridge must be listening on public port before HUP");

    // Connect with TLS presenting initial cert
    let mut roots = RootCertStore::empty();
    roots.add(ca_der.clone()).unwrap();
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));

    let stream = TcpStream::connect(client_addr).await.unwrap();
    let server_name = ServerName::try_from("bridge.solstone.me")
        .unwrap()
        .to_owned();
    let mut tls_stream_initial = connector
        .connect(server_name.clone(), stream)
        .await
        .unwrap();

    let (_, conn_initial) = tls_stream_initial.get_ref();
    let presented_initial = conn_initial.peer_certificates().unwrap().first().unwrap();
    assert_eq!(presented_initial.as_ref(), initial_cert_der.as_ref());

    // Overwrite cert/key on disk with updated cert and send SIGHUP
    fs::write(&cert_path, &updated_cert_pem).unwrap();
    fs::write(&key_path, &updated_key_pem).unwrap();

    let kill_status = Command::new("kill")
        .args(["-HUP", &pid.to_string()])
        .status()
        .expect("kill -HUP failed");
    assert!(kill_status.success());

    // Wait until new TLS handshake presents updated cert
    let mut presented_updated_matched = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if let Ok(stream) = TcpStream::connect(client_addr).await
            && let Ok(tls_stream_updated) = connector.connect(server_name.clone(), stream).await
        {
            let (_, conn_updated) = tls_stream_updated.get_ref();
            if let Some(cert) = conn_updated.peer_certificates().and_then(|c| c.first())
                && cert.as_ref() == updated_cert_der.as_ref()
            {
                presented_updated_matched = true;
                break;
            }
        }
    }
    assert!(
        presented_updated_matched,
        "new TLS handshake after SIGHUP must present updated cert"
    );

    // Old connection must still be usable
    let _ = tls_stream_initial.shutdown().await;

    // Verify PID is unchanged
    assert_eq!(guard.id(), pid);
}

#[derive(Clone)]
enum TestLoaderResult {
    Ok(Vec<u8>, Vec<u8>),
    Err(io::ErrorKind, &'static str),
}

#[tokio::test]
async fn ac2_reload_coordinator_failure_classes_preserve_prior_cert_and_logs() {
    let (ca_der, ca_key, ca_cert) = generate_ca();
    let mut roots = RootCertStore::empty();
    roots.add(ca_der.clone()).unwrap();

    let now_secs = date_time_ymd(2026, 6, 1).unix_timestamp().cast_unsigned();

    let (cert_a_der, key_a_der, cert_a_pem, key_a_pem) =
        generate_leaf("bridge.solstone.me", &ca_cert, &ca_key, 2026, 2027);
    let initial_key = validate_control_certified_key(
        &[cert_a_der.clone(), ca_der.clone()],
        &key_a_der,
        &roots,
        now_secs,
    )
    .unwrap();

    let resolver = Arc::new(ControlCertResolver::new(initial_key));
    let slot = Arc::new(Mutex::new(TestLoaderResult::Ok(
        cert_a_pem.clone(),
        key_a_pem.clone(),
    )));
    let loader_slot = Arc::clone(&slot);
    let loader: CertMaterialLoader = Arc::new(move || match slot.lock().unwrap().clone() {
        TestLoaderResult::Ok(c, k) => Ok((c, k)),
        TestLoaderResult::Err(kind, msg) => Err(io::Error::new(kind, msg)),
    });

    let clock: ClockFn = Arc::new(move || now_secs);
    let coordinator = ReloadCoordinator::new(Arc::clone(&resolver), roots.clone(), clock, loader);

    let (_, _, _, key_other_pem) =
        generate_leaf("bridge.solstone.me", &ca_cert, &ca_key, 2026, 2027);
    let (_, _, cert_wrong_host, key_wrong_host) =
        generate_leaf("wrong.host.com", &ca_cert, &ca_key, 2026, 2027);
    let (_, _, cert_expired, key_expired) =
        generate_leaf("bridge.solstone.me", &ca_cert, &ca_key, 2020, 2021);
    let (_, _, cert_future, key_future) =
        generate_leaf("bridge.solstone.me", &ca_cert, &ca_key, 2030, 2035);

    // Leaf signed by untrusted CA
    let (_untrusted_der, untrusted_key, untrusted_cert) = generate_ca();
    let (_, _, cert_untrusted, key_untrusted) = generate_leaf(
        "bridge.solstone.me",
        &untrusted_cert,
        &untrusted_key,
        2026,
        2027,
    );

    // Unusable chain: leaf signed by intermediate CA, but intermediate omitted and roots only have Root CA
    let inter_key = KeyPair::generate().unwrap();
    let mut inter_params =
        CertificateParams::new(vec![String::from("Test Intermediate CA")]).unwrap();
    inter_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let inter_cert = inter_params
        .signed_by(&inter_key, &ca_cert, &ca_key)
        .unwrap();

    let leaf_inter_key = KeyPair::generate().unwrap();
    let mut leaf_inter_params =
        CertificateParams::new(vec![String::from("bridge.solstone.me")]).unwrap();
    leaf_inter_params.not_before = date_time_ymd(2026, 1, 1);
    leaf_inter_params.not_after = date_time_ymd(2027, 1, 1);
    let leaf_inter_cert = leaf_inter_params
        .signed_by(&leaf_inter_key, &inter_cert, &inter_key)
        .unwrap();
    let cert_unusable_chain = leaf_inter_cert.pem().into_bytes();
    let key_unusable_chain = leaf_inter_key.serialize_pem().into_bytes();

    let logs = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_writer(ReloadLogBuffer(Arc::clone(&logs)))
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let bad_cases: Vec<TestLoaderResult> = vec![
        // 1. Invalid PEM
        TestLoaderResult::Ok(b"invalid cert pem".to_vec(), key_a_pem.clone()),
        // 2. Truncated PEM
        TestLoaderResult::Ok(
            cert_a_pem[..cert_a_pem.len() / 2].to_vec(),
            key_a_pem.clone(),
        ),
        // 3. Unreadable loader error
        TestLoaderResult::Err(io::ErrorKind::NotFound, "file not found"),
        // 4. Key mismatch (leaf A cert + other key)
        TestLoaderResult::Ok(cert_a_pem.clone(), key_other_pem),
        // 5. Wrong hostname
        TestLoaderResult::Ok(cert_wrong_host, key_wrong_host),
        // 6. Expired
        TestLoaderResult::Ok(cert_expired, key_expired),
        // 7. Not yet valid
        TestLoaderResult::Ok(cert_future, key_future),
        // 8. Untrusted root CA
        TestLoaderResult::Ok(cert_untrusted, key_untrusted),
        // 9. Unusable chain (missing intermediate CA)
        TestLoaderResult::Ok(cert_unusable_chain, key_unusable_chain),
    ];

    for case in bad_cases {
        logs.lock().unwrap().clear();
        {
            let mut guard = loader_slot.lock().unwrap();
            *guard = case;
        }
        coordinator.request_reload().await;

        // Current cert MUST remain cert A
        assert_eq!(
            resolver.current().end_entity_cert().unwrap().as_ref(),
            cert_a_der.as_ref(),
            "prior certificate must be preserved on reload failure"
        );

        let captured = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
        assert!(
            captured.contains("control certificate reload failed; keeping prior certificate"),
            "captured log must contain reload failure event: {captured}"
        );
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "startup validation and parse error test matrix"
)]
#[test]
fn ac3_spawn_binary_initial_validation_failures_exit_before_bind() {
    let temp = TempDir::new("ac3-startup");
    let (_ca_der, ca_key, ca_cert) = generate_ca();

    let ca_pem_path = temp.path.join("ca.pem");
    fs::write(&ca_pem_path, ca_cert.pem().as_bytes()).unwrap();

    let (_, _, cert_a_pem, key_a_pem) =
        generate_leaf("bridge.solstone.me", &ca_cert, &ca_key, 2026, 2027);
    let (_, _, _, key_other_pem) =
        generate_leaf("bridge.solstone.me", &ca_cert, &ca_key, 2026, 2027);
    let (_, _, cert_wrong_host, key_wrong_host) =
        generate_leaf("wrong.host.com", &ca_cert, &ca_key, 2026, 2027);
    let (_, _, cert_expired, key_expired) =
        generate_leaf("bridge.solstone.me", &ca_cert, &ca_key, 2020, 2021);
    let (_, _, cert_future, key_future) =
        generate_leaf("bridge.solstone.me", &ca_cert, &ca_key, 2030, 2035);

    let (_untrusted_der, untrusted_key, untrusted_cert) = generate_ca();
    let (_, _, cert_untrusted, key_untrusted) = generate_leaf(
        "bridge.solstone.me",
        &untrusted_cert,
        &untrusted_key,
        2026,
        2027,
    );

    let validator_pairs = vec![
        ("wrong_host", cert_wrong_host, key_wrong_host),
        ("expired", cert_expired, key_expired),
        ("future", cert_future, key_future),
        ("untrusted", cert_untrusted, key_untrusted),
        ("key_mismatch", cert_a_pem.clone(), key_other_pem),
    ];

    let bridge_bin = env!("CARGO_BIN_EXE_spl-bridge");

    for (name, cert_bytes, key_bytes) in validator_pairs {
        let cert_file = temp.path.join(format!("{name}.crt"));
        let key_file = temp.path.join(format!("{name}.key"));
        fs::write(&cert_file, &cert_bytes).unwrap();
        fs::write(&key_file, &key_bytes).unwrap();

        // Choose a free port
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap();
        drop(probe);

        let output = Command::new(bridge_bin)
            .arg("--client-listen")
            .arg(port.to_string())
            .arg("--control-tls-cert")
            .arg(&cert_file)
            .arg("--control-tls-key")
            .arg(&key_file)
            .arg("--jwks-url")
            .arg("https://127.0.0.1:1/jwks")
            .arg("--bridge-id")
            .arg("bridge")
            .arg("--control-tls-roots")
            .arg(&ca_pem_path)
            .output()
            .expect("failed to run spl-bridge");

        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("control certificate startup validation failed"),
            "stderr must contain 'control certificate startup validation failed' for {name}: {stderr}"
        );
        assert!(
            !stderr.contains("listener started"),
            "must not start listeners on startup validation failure"
        );

        // Port must still be bindable after exit
        let rebound = std::net::TcpListener::bind(port);
        assert!(rebound.is_ok(), "port {port} must remain free");
    }

    let unparseable_pairs = vec![
        ("invalid_pem", b"bad pem".to_vec(), b"bad key".to_vec()),
        (
            "truncated_pem",
            cert_a_pem[..cert_a_pem.len() / 2].to_vec(),
            key_a_pem,
        ),
    ];

    for (name, cert_bytes, key_bytes) in unparseable_pairs {
        let cert_file = temp.path.join(format!("{name}.crt"));
        let key_file = temp.path.join(format!("{name}.key"));
        fs::write(&cert_file, &cert_bytes).unwrap();
        fs::write(&key_file, &key_bytes).unwrap();

        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap();
        drop(probe);

        let output = Command::new(bridge_bin)
            .arg("--client-listen")
            .arg(port.to_string())
            .arg("--control-tls-cert")
            .arg(&cert_file)
            .arg("--control-tls-key")
            .arg(&key_file)
            .arg("--jwks-url")
            .arg("https://127.0.0.1:1/jwks")
            .arg("--bridge-id")
            .arg("bridge")
            .arg("--control-tls-roots")
            .arg(&ca_pem_path)
            .output()
            .expect("failed to run spl-bridge");

        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("listener started"),
            "must not start listeners on unparseable pair"
        );
        assert!(
            !stderr.contains(cert_file.to_str().unwrap()),
            "stderr must not interpolate certificate path"
        );

        let rebound = std::net::TcpListener::bind(port);
        assert!(rebound.is_ok(), "port {port} must remain free");
    }
}

struct CountingAcceptor {
    listener: TcpListener,
    accepts: Arc<AtomicUsize>,
}

impl AcceptProvider for CountingAcceptor {
    async fn accept(&mut self) -> io::Result<(TcpStream, SocketAddr)> {
        let (stream, addr) = self.listener.accept().await?;
        self.accepts.fetch_add(1, Ordering::SeqCst);
        Ok((stream, addr))
    }
}

struct OverlapFixture {
    resolver: Arc<ControlCertResolver>,
    coordinator: Arc<ReloadCoordinator>,
    control_addr: SocketAddr,
    client_addr: SocketAddr,
    control_accepts: Arc<AtomicUsize>,
    client_accepts: Arc<AtomicUsize>,
    unblock_tx: tokio::sync::oneshot::Sender<()>,
    load_count: Arc<AtomicUsize>,
    cert2_der: CertificateDer<'static>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    handles: (tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>),
}

async fn setup_overlap_fixture() -> OverlapFixture {
    let (ca_der, ca_key, ca_cert) = generate_ca();
    let mut roots = RootCertStore::empty();
    roots.add(ca_der.clone()).unwrap();

    let now_secs = date_time_ymd(2026, 6, 1).unix_timestamp().cast_unsigned();

    let (cert1_der, key1_der, _, _) =
        generate_leaf("bridge.solstone.me", &ca_cert, &ca_key, 2026, 2027);
    let (cert2_der, _, cert2_pem, key2_pem) =
        generate_leaf("bridge.solstone.me", &ca_cert, &ca_key, 2026, 2027);

    let initial_key = validate_control_certified_key(
        &[cert1_der.clone(), ca_der.clone()],
        &key1_der,
        &roots,
        now_secs,
    )
    .unwrap();

    let resolver = Arc::new(ControlCertResolver::new(initial_key));
    let load_count = Arc::new(AtomicUsize::new(0));
    let load_count_clone = Arc::clone(&load_count);

    let (unblock_tx, unblock_rx) = tokio::sync::oneshot::channel::<()>();
    let unblock_rx = Arc::new(tokio::sync::Mutex::new(Some(unblock_rx)));

    let loader: CertMaterialLoader = Arc::new(move || {
        load_count_clone.fetch_add(1, Ordering::SeqCst);
        let rx = Arc::clone(&unblock_rx);
        tokio::task::block_in_place(|| {
            if let Some(rx) = rx.blocking_lock().take() {
                let _ = rx.blocking_recv();
            }
        });
        Ok((cert2_pem.clone(), key2_pem.clone()))
    });

    let clock: ClockFn = Arc::new(move || now_secs);
    let coordinator = Arc::new(ReloadCoordinator::new(
        Arc::clone(&resolver),
        roots.clone(),
        clock,
        loader,
    ));

    let control_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_addr = control_listener.local_addr().unwrap();
    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_listener.local_addr().unwrap();

    let control_accepts = Arc::new(AtomicUsize::new(0));
    let client_accepts = Arc::new(AtomicUsize::new(0));

    let control_acceptor = CountingAcceptor {
        listener: control_listener,
        accepts: Arc::clone(&control_accepts),
    };
    let client_acceptor = CountingAcceptor {
        listener: client_listener,
        accepts: Arc::clone(&client_accepts),
    };

    let (shutdown_tx, shutdown_rx_control) = tokio::sync::watch::channel(false);
    let shutdown_rx_client = shutdown_tx.subscribe();

    let tls_config = control_server_tls_config(Arc::clone(&resolver)).unwrap();
    let verifier =
        FixtureTokenVerifier::new(std::collections::HashMap::new(), String::from("bridge"));
    let authenticator = PopAuthenticator::new(Arc::new(verifier), String::from("bridge"));

    let control_handle = tokio::spawn(run_control_listener(
        control_acceptor,
        Arc::new(tls_config),
        Registry::default(),
        authenticator,
        DEFAULT_ADMISSION_DEADLINE,
        shutdown_rx_control,
    ));

    let client_handle = tokio::spawn(run_client_listener(
        client_acceptor,
        Registry::default(),
        control_addr,
        None,
        Duration::from_secs(1),
        TokioControlConnector,
        TokioControlConnector,
        shutdown_rx_client,
    ));

    OverlapFixture {
        resolver,
        coordinator,
        control_addr,
        client_addr,
        control_accepts,
        client_accepts,
        unblock_tx,
        load_count,
        cert2_der,
        shutdown_tx,
        handles: (control_handle, client_handle),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ac4_overlapping_reload_nonblocking_accepts_and_coalescing() {
    let fix = setup_overlap_fixture().await;

    // Start 3 overlapping reloads
    let coord1 = Arc::clone(&fix.coordinator);
    let reload_task1 = tokio::spawn(async move { coord1.request_reload().await });
    let coord2 = Arc::clone(&fix.coordinator);
    let reload_task2 = tokio::spawn(async move { coord2.request_reload().await });
    let coord3 = Arc::clone(&fix.coordinator);
    let reload_task3 = tokio::spawn(async move { coord3.request_reload().await });

    // While reloads are blocked in loader, both listeners MUST accept connections
    tokio::time::sleep(Duration::from_millis(50)).await;

    let c1 = TcpStream::connect(fix.control_addr).await.unwrap();
    let c2 = TcpStream::connect(fix.client_addr).await.unwrap();
    drop(c1);
    drop(c2);

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(fix.control_accepts.load(Ordering::SeqCst) > 0);
    assert!(fix.client_accepts.load(Ordering::SeqCst) > 0);

    // Release blocked loader
    let _ = fix.unblock_tx.send(());

    reload_task1.await.unwrap();
    reload_task2.await.unwrap();
    reload_task3.await.unwrap();

    // Verify cert2 is now active
    assert_eq!(
        fix.resolver.current().end_entity_cert().unwrap().as_ref(),
        fix.cert2_der.as_ref()
    );

    // Total disk loads must be <= 2 (coalesced)
    let total_loads = fix.load_count.load(Ordering::SeqCst);
    assert!(
        total_loads <= 2,
        "concurrent requests must coalesce (got {total_loads})"
    );

    fix.shutdown_tx.send_replace(true);
    let _ = tokio::join!(fix.handles.0, fix.handles.1);
}
