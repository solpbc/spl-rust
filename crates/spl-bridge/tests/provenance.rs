// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Acceptance criteria 11-15: Provenance version format, isolated git dirty checks, systemd hardening, and renew wrapper.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "integration tests verify deploy assets and CLI behavior"
)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

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

#[test]
fn ac11_version_format() {
    let bridge_bin = env!("CARGO_BIN_EXE_spl-bridge");
    let output = Command::new(bridge_bin)
        .arg("--version")
        .output()
        .expect("failed to execute spl-bridge --version");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("spl-bridge 0.1.0 ("));
    assert!(stdout.trim_end().ends_with(')'));

    let activate_bin = env!("CARGO_BIN_EXE_spl-bridge-activate");
    let output = Command::new(activate_bin)
        .arg("--version")
        .output()
        .expect("failed to execute spl-bridge-activate --version");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("spl-bridge-activate 0.1.0 ("));
    assert!(stdout.trim_end().ends_with(')'));
}

fn init_isolated_repo(tree_dir: &Path) {
    let ws_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    fs::create_dir_all(tree_dir).unwrap();

    let cp_status = Command::new("cp")
        .args([
            "-r",
            &ws_root.join("Cargo.toml").to_string_lossy(),
            &ws_root.join("Cargo.lock").to_string_lossy(),
            &ws_root.join("crates").to_string_lossy(),
            &tree_dir.to_string_lossy(),
        ])
        .status()
        .expect("copy workspace");
    assert!(cp_status.success());

    assert!(
        Command::new("git")
            .current_dir(tree_dir)
            .args(["init"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .current_dir(tree_dir)
            .args(["config", "user.name", "Test"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .current_dir(tree_dir)
            .args(["config", "user.email", "test@test.me"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .current_dir(tree_dir)
            .args(["add", "."])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .current_dir(tree_dir)
            .args(["commit", "-m", "init"])
            .status()
            .unwrap()
            .success()
    );
}

fn build_and_get_version(manifest_dir: &Path, target_dir: &Path) -> String {
    let build = Command::new("cargo")
        .current_dir(manifest_dir)
        .args([
            "build",
            "-p",
            "spl-bridge",
            "--bin",
            "spl-bridge",
            "--target-dir",
            &target_dir.to_string_lossy(),
        ])
        .status()
        .expect("cargo build");
    assert!(build.success());

    let bin_path = target_dir.join("debug").join("spl-bridge");
    let out = Command::new(&bin_path)
        .arg("--version")
        .output()
        .expect("read version");
    String::from_utf8_lossy(&out.stdout).to_string()
}

#[test]
fn ac12_isolated_git_trees_provenance_lifecycle() {
    let temp = TempDir::new("ac12-git");
    let tree_dir = temp.path.join("repo");
    init_isolated_repo(&tree_dir);

    let target_dir = temp.path.join("target");

    // 1. Build clean git commit -> expect 40 hex characters
    let v1 = build_and_get_version(&tree_dir, &target_dir);
    assert!(v1.starts_with("spl-bridge 0.1.0 ("));
    let hash1 = v1
        .strip_prefix("spl-bridge 0.1.0 (")
        .unwrap()
        .strip_suffix(")\n")
        .unwrap();
    assert_eq!(hash1.len(), 40);
    assert!(
        hash1.chars().all(|c| c.is_ascii_hexdigit()),
        "expected hex hash, got {hash1}"
    );

    // 2. Modify a tracked file -> rebuild -> expect hash-dirty
    let lib_rs = tree_dir.join("crates/spl-bridge/src/lib.rs");
    let mut lib_content = fs::read_to_string(&lib_rs).unwrap();
    lib_content.push_str("\n// dirty modification\n");
    fs::write(&lib_rs, lib_content).unwrap();

    let v2 = build_and_get_version(&tree_dir, &target_dir);
    let hash2 = v2
        .strip_prefix("spl-bridge 0.1.0 (")
        .unwrap()
        .strip_suffix(")\n")
        .unwrap();
    assert!(
        hash2.ends_with("-dirty"),
        "expected dirty hash, got {hash2}"
    );

    // 3. Revert change -> rebuild -> expect hex WITHOUT -dirty
    assert!(
        Command::new("git")
            .current_dir(&tree_dir)
            .args(["checkout", "--", "."])
            .status()
            .unwrap()
            .success()
    );

    let v3 = build_and_get_version(&tree_dir, &target_dir);
    let hash3 = v3
        .strip_prefix("spl-bridge 0.1.0 (")
        .unwrap()
        .strip_suffix(")\n")
        .unwrap();
    assert_eq!(hash3, hash1);
    assert!(!hash3.ends_with("-dirty"));

    // 4. Copy tree without .git -> rebuild -> expect unavailable
    let non_git_dir = temp.path.join("non_git");
    fs::create_dir_all(&non_git_dir).unwrap();
    assert!(
        Command::new("cp")
            .args([
                "-r",
                &tree_dir.join("Cargo.toml").to_string_lossy(),
                &tree_dir.join("Cargo.lock").to_string_lossy(),
                &tree_dir.join("crates").to_string_lossy(),
                &non_git_dir.to_string_lossy(),
            ])
            .status()
            .unwrap()
            .success()
    );

    let target_dir_non_git = temp.path.join("target_non_git");
    let v4 = build_and_get_version(&non_git_dir, &target_dir_non_git);
    assert_eq!(v4, "spl-bridge 0.1.0 (unavailable)\n");
}

#[test]
fn ac13_systemd_assets_exist_and_contain_hardening_directives() {
    let deploy_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("deploy");

    let service = std::fs::read_to_string(deploy_dir.join("spl-bridge.service")).unwrap();
    assert!(service.contains("ExecReload=/bin/kill -HUP $MAINPID"));
    assert!(service.contains("KillSignal=SIGTERM"));
    assert!(service.contains("TimeoutStopSec=45"));
    assert!(service.contains("Restart=always"));
    assert!(service.contains("LimitNOFILE=65536"));
    assert!(service.contains("AmbientCapabilities=CAP_NET_BIND_SERVICE"));
    assert!(service.contains("CapabilityBoundingSet=CAP_NET_BIND_SERVICE"));
    assert!(service.contains("ProtectSystem=strict"));
    assert!(service.contains("ProtectHome=true"));
    assert!(service.contains("NoNewPrivileges=true"));
    assert!(service.contains("PrivateTmp=true"));
    assert!(service.contains("PrivateDevices=true"));
    assert!(service.contains("ProtectKernelTunables=true"));
    assert!(service.contains("ProtectKernelModules=true"));
    assert!(service.contains("ProtectControlGroups=true"));
    assert!(service.contains("User=spl-bridge"));
    assert!(service.contains("Group=spl-bridge"));
    assert!(service.contains("/etc/spl-bridge/tls-generations/active/cert.pem"));
    assert!(service.contains("--acme-tls-alpn-target 127.0.0.1:8443"));

    let renewal_service =
        std::fs::read_to_string(deploy_dir.join("spl-bridge-renewal.service")).unwrap();
    assert!(renewal_service.contains("Type=oneshot"));
    assert!(renewal_service.contains("Restart=on-failure"));
    assert!(renewal_service.contains("RestartSec=6h"));
    assert!(renewal_service.contains("ExecStart=/usr/local/bin/spl-bridge-renew"));
    assert!(renewal_service.contains("User=root"));
    assert!(renewal_service.contains("Group=spl-bridge"));
    assert!(renewal_service.contains("After=network-online.target spl-bridge.service"));
    assert!(renewal_service.contains("Requires=spl-bridge.service"));
    assert!(renewal_service.contains("RuntimeDirectory=spl-bridge-renew"));
    assert!(renewal_service.contains(
        "ReadWritePaths=/etc/spl-bridge/tls-generations /etc/spl-bridge/acme-production /run/spl-bridge-renew"
    ));
    assert!(renewal_service.contains("EnvironmentFile=/etc/spl-bridge/renewal.env"));
    assert!(!renewal_service.contains("stop spl-bridge"));
    assert!(!renewal_service.contains("restart spl-bridge"));

    let renewal_timer =
        std::fs::read_to_string(deploy_dir.join("spl-bridge-renewal.timer")).unwrap();
    assert!(renewal_timer.contains("OnCalendar=daily"));
    assert!(renewal_timer.contains("Persistent=true"));
    assert!(renewal_timer.contains("RandomizedDelaySec=1h"));

    let renew_script = std::fs::read_to_string(deploy_dir.join("spl-bridge-renew")).unwrap();
    assert!(renew_script.contains("set -euo pipefail"));
    assert!(renew_script.contains("flock"));
    assert!(renew_script.contains("renew --days 30"));
    assert!(renew_script.contains("--renew-hook"));
    assert!(renew_script.contains("127.0.0.1"));
    assert!(renew_script.contains("spl-bridge-activate"));
    assert!(renew_script.contains("--retry-pending"));
    assert!(!renew_script.contains("ISSUED_CERT="));

    let renew_hook = std::fs::read_to_string(deploy_dir.join("spl-bridge-renew-hook")).unwrap();
    assert!(renew_hook.contains("LEGO_HOOK_CERT_PATH"));
    assert!(renew_hook.contains("LEGO_CERT_PATH"));
    assert!(renew_hook.contains("--issued-cert"));
    assert!(renew_hook.contains("--issued-key"));

    for executable in ["spl-bridge-renew", "spl-bridge-renew-hook"] {
        let mode = std::fs::metadata(deploy_dir.join(executable))
            .unwrap()
            .permissions()
            .mode();
        assert_ne!(mode & 0o111, 0, "{executable} must be executable");
    }

    let runbook = std::fs::read_to_string(deploy_dir.join("RUNBOOK.md")).unwrap();
    assert!(runbook.contains("SPL Bridge Operations Runbook"));
    assert!(runbook.contains("acme-staging-v02.api.letsencrypt.org"));
}

struct RenewHarness {
    _temp: TempDir,
    script_path: String,
    fake_lego: PathBuf,
    fake_activate: PathBuf,
    lego_invocations: PathBuf,
    activate_invocations: PathBuf,
    generations_dir: PathBuf,
    lego_dir: PathBuf,
    lock_file: PathBuf,
    fail_retry_file: PathBuf,
    renew_hook: PathBuf,
}

impl RenewHarness {
    fn setup() -> Self {
        let temp = TempDir::new("renew-harness");
        let deploy_script = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("deploy")
            .join("spl-bridge-renew");

        let fake_lego = temp.path.join("fake-lego");
        let lego_invocations = temp.path.join("lego_ran");
        let issued_cert = temp.path.join("issued.crt");
        let issued_key = temp.path.join("issued.key");
        fs::write(&issued_cert, b"fixture cert path").unwrap();
        fs::write(&issued_key, b"fixture key path").unwrap();
        let fake_lego_script = format!(
            r#"#!/usr/bin/env bash
echo 1 >> "{}"
hook=""
while [ "$#" -gt 0 ]; do
    if [ "$1" = "--renew-hook" ]; then
        shift
        hook="$1"
    fi
    shift
done
if [ "${{FAKE_LEGO_RENEW:-0}}" = "1" ]; then
    LEGO_CERT_PATH="{}" LEGO_CERT_KEY_PATH="{}" "$hook"
fi
"#,
            lego_invocations.to_string_lossy(),
            issued_cert.to_string_lossy(),
            issued_key.to_string_lossy(),
        );
        fs::write(&fake_lego, fake_lego_script).unwrap();
        fs::set_permissions(&fake_lego, fs::Permissions::from_mode(0o755)).unwrap();

        let fake_activate = temp.path.join("fake-activate");
        let activate_invocations = temp.path.join("activate_ran");
        let fail_retry_file = temp.path.join("fail_retry");
        let fake_activate_script = format!(
            r#"#!/usr/bin/env bash
echo "$@" >> "{}"
for arg in "$@"; do
    if [ "$arg" = "--retry-pending" ]; then
        if [ -f "{}" ]; then
            exit 2
        else
            exit 0
        fi
    fi
done
exit 0
"#,
            activate_invocations.to_string_lossy(),
            fail_retry_file.to_string_lossy()
        );
        fs::write(&fake_activate, fake_activate_script).unwrap();
        fs::set_permissions(&fake_activate, fs::Permissions::from_mode(0o755)).unwrap();

        let generations_dir = temp.path.join("generations");
        let lego_dir = temp.path.join("lego");
        let lock_file = temp.path.join("renew.lock");
        let renew_hook = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("deploy")
            .join("spl-bridge-renew-hook");
        fs::create_dir_all(&generations_dir).unwrap();
        fs::create_dir_all(&lego_dir).unwrap();

        Self {
            script_path: deploy_script.to_string_lossy().to_string(),
            fake_lego,
            fake_activate,
            lego_invocations,
            activate_invocations,
            generations_dir,
            lego_dir,
            lock_file,
            fail_retry_file,
            renew_hook,
            _temp: temp,
        }
    }

    fn run(&self, renewed: bool) -> std::process::Output {
        Command::new("bash")
            .arg(&self.script_path)
            .env("LEGO", &self.fake_lego)
            .env("ACTIVATE", &self.fake_activate)
            .env("GENERATIONS_DIR", &self.generations_dir)
            .env("LEGO_DIR", &self.lego_dir)
            .env("RENEW_LOCK_FILE", &self.lock_file)
            .env("RENEW_HOOK", &self.renew_hook)
            .env("EMAIL", "operator@example.test")
            .env("FAKE_LEGO_RENEW", if renewed { "1" } else { "0" })
            .output()
            .expect("run renew script")
    }
}

#[test]
fn ac15_spl_bridge_renew_wrapper_lifecycle_branches() {
    let harness = RenewHarness::setup();

    // Case 1: Pending symlink to valid generation -> lego NOT run, activate --retry-pending run
    let gen1_dir = harness.generations_dir.join("gen_1");
    fs::create_dir_all(&gen1_dir).unwrap();
    std::os::unix::fs::symlink(&gen1_dir, harness.generations_dir.join("pending")).unwrap();

    let out1 = harness.run(false);
    assert!(out1.status.success());
    assert!(!harness.lego_invocations.exists());
    let act_log = fs::read_to_string(&harness.activate_invocations).unwrap();
    assert!(act_log.contains("--retry-pending"));

    // Case 2: No pending -> fake lego runs
    let _ = fs::remove_file(harness.generations_dir.join("pending"));
    let _ = fs::remove_file(&harness.activate_invocations);

    let out2 = harness.run(false);
    assert!(out2.status.success());
    assert!(harness.lego_invocations.exists());
    assert!(
        !harness.activate_invocations.exists(),
        "no-op renewal must not activate or reload"
    );

    // Case 3: Quarantined-only -> fake lego runs
    let _ = fs::remove_file(&harness.lego_invocations);
    fs::create_dir_all(harness.generations_dir.join("quarantine_12345")).unwrap();

    let out3 = harness.run(false);
    assert!(out3.status.success());
    assert!(harness.lego_invocations.exists());

    // Case 4: Pending fails validation -> wrapper runs lego
    let _ = fs::remove_file(&harness.lego_invocations);
    std::os::unix::fs::symlink(&gen1_dir, harness.generations_dir.join("pending")).unwrap();
    fs::write(&harness.fail_retry_file, b"1").unwrap();

    let out4 = harness.run(false);
    assert!(out4.status.success());
    assert!(harness.lego_invocations.exists());

    // Case 5: An effective renewal invokes the hook, which owns activation.
    let _ = fs::remove_file(&harness.fail_retry_file);
    let _ = fs::remove_file(harness.generations_dir.join("pending"));
    let _ = fs::remove_file(&harness.activate_invocations);
    let out5 = harness.run(true);
    assert!(out5.status.success());
    let hook_log = fs::read_to_string(&harness.activate_invocations).unwrap();
    assert!(hook_log.contains("--issued-cert"));
    assert!(hook_log.contains("--issued-key"));
}
