// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Mechanical dependency and retention boundaries for the public bridge.

#![expect(
    clippy::expect_used,
    reason = "source-policy tests use direct assertions over controlled fixture paths"
)]

use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

mod support;

static TEMPORARY_CORPUS_COUNTER: AtomicU64 = AtomicU64::new(0);

#[test]
fn checked_in_tree_satisfies_source_policy() -> Result<(), Box<dyn Error>> {
    let (crate_root, workspace_manifest) = real_paths()?;
    let result = support::scan(&crate_root, &workspace_manifest)?;
    let inventory = &result.inventory;
    println!(
        "source-policy inventory: library={}, binary={}, manifest={}, template={}",
        inventory.library.len(),
        inventory.binary.len(),
        inventory.manifest.len(),
        inventory.template.len(),
    );
    assert!(
        !inventory.library.is_empty()
            && !inventory.binary.is_empty()
            && !inventory.manifest.is_empty()
            && result.violations.is_empty(),
        "source-policy inventory: library={}, binary={}, manifest={}, template={}; violations={:?}",
        inventory.library.len(),
        inventory.binary.len(),
        inventory.manifest.len(),
        inventory.template.len(),
        result.violations,
    );
    Ok(())
}

#[test]
fn zero_file_corpus_fails_source_policy() -> Result<(), Box<dyn Error>> {
    let corpus = CorpusCopy::empty()?;
    let result = support::scan(&corpus.crate_root, &corpus.workspace_manifest)?;
    assert!(!result.violations.is_empty());
    assert!(result.inventory.library.is_empty());
    assert!(result.inventory.binary.is_empty());
    assert!(result.inventory.manifest.is_empty());
    assert!(result.inventory.template.is_empty());
    Ok(())
}

#[test]
fn corpus_missing_a_required_manifest_class_fails_source_policy() -> Result<(), Box<dyn Error>> {
    let (corpus, snapshot) = copied_real_corpus()?;
    fs::remove_file(corpus.crate_root.join("Cargo.toml"))?;
    let result = support::scan(&corpus.crate_root, &corpus.workspace_manifest)?;
    snapshot.assert_unchanged()?;
    assert!(result.inventory.manifest.is_empty());
    assert!(!result.violations.is_empty());
    Ok(())
}

#[test]
fn forbidden_library_customer_state_write_fails_source_policy() -> Result<(), Box<dyn Error>> {
    let (corpus, snapshot) = copied_real_corpus()?;
    append(
        &corpus.crate_root.join("src/lib.rs"),
        "\nfn policy_fixture_state_write() { let _ = std::fs::write(\"/var/lib/spl-bridge/customer-state\", b\"x\"); }\n",
    )?;
    assert_rejected(&corpus, &snapshot)
}

#[test]
fn aliased_library_filesystem_use_fails_source_policy() -> Result<(), Box<dyn Error>> {
    let (corpus, snapshot) = copied_real_corpus()?;
    append(
        &corpus.crate_root.join("src/lib.rs"),
        "\nuse std::fs as sfs;\nfn policy_fixture_aliased_write() { let _ = sfs::write(\"/var/lib/spl-bridge/customer-state\", b\"x\"); }\n",
    )?;
    assert_rejected(&corpus, &snapshot)
}

#[test]
fn binary_state_path_environment_input_fails_source_policy() -> Result<(), Box<dyn Error>> {
    let (corpus, snapshot) = copied_real_corpus()?;
    append(
        &corpus.crate_root.join("src/bin/spl-bridge.rs"),
        "\nfn policy_fixture_state_input() { let _ = std::env::var(\"SPL_BRIDGE_STATE_DIR\"); }\n",
    )?;
    assert_rejected(&corpus, &snapshot)
}

#[test]
fn direct_storage_dependency_fails_source_policy() -> Result<(), Box<dyn Error>> {
    let (corpus, snapshot) = copied_real_corpus()?;
    add_dependency(&corpus.crate_root.join("Cargo.toml"), "rusqlite = \"0.31\"")?;
    assert_rejected(&corpus, &snapshot)
}

#[test]
fn package_aliased_storage_dependency_fails_source_policy() -> Result<(), Box<dyn Error>> {
    let (corpus, snapshot) = copied_real_corpus()?;
    add_dependency(
        &corpus.crate_root.join("Cargo.toml"),
        "db = { package = \"rusqlite\", version = \"0.31\" }",
    )?;
    assert_rejected(&corpus, &snapshot)
}

#[test]
fn runtime_log_field_or_interpolation_fails_source_policy() -> Result<(), Box<dyn Error>> {
    for source in [
        "\nfn policy_fixture_log_field(h: &str) { tracing::warn!(hostname = %h, \"message\"); }\n",
        "\nuse tracing::warn as bridge_warn;\nfn policy_fixture_log_interpolation(h: &str) { bridge_warn!(\"message {}\", h); }\n",
    ] {
        let (corpus, snapshot) = copied_real_corpus()?;
        append(&corpus.crate_root.join("src/lib.rs"), source)?;
        assert_rejected(&corpus, &snapshot)?;
    }
    Ok(())
}

#[test]
fn dynamic_cli_diagnostic_fails_source_policy() -> Result<(), Box<dyn Error>> {
    let (corpus, snapshot) = copied_real_corpus()?;
    append(
        &corpus.crate_root.join("src/bin/spl-bridge.rs"),
        "\nfn policy_fixture_diagnostic(error: &str) { eprintln!(\"{error}\"); }\n",
    )?;
    assert_rejected(&corpus, &snapshot)
}

#[test]
fn forbidden_service_template_is_inventoried_then_rejected() -> Result<(), Box<dyn Error>> {
    let (corpus, snapshot) = copied_real_corpus()?;
    let service = corpus.crate_root.join("deploy/spl-bridge.service");
    fs::write(
        &service,
        "[Service]\nStateDirectory=spl-bridge\nExecStart=/home/customer/.spl-bridge/state.db\n",
    )?;
    let result = support::scan(&corpus.crate_root, &corpus.workspace_manifest)?;
    snapshot.assert_unchanged()?;
    assert!(result.inventory.template.contains(&service));
    assert!(!result.violations.is_empty());
    Ok(())
}

fn real_paths() -> Result<(PathBuf, PathBuf), io::Error> {
    let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_manifest = crate_root
        .parent()
        .and_then(Path::parent)
        .map(|root| root.join("Cargo.toml"))
        .ok_or_else(|| io::Error::other("bridge crate must be beneath the workspace root"))?;
    Ok((crate_root, workspace_manifest))
}

fn copied_real_corpus() -> Result<(CorpusCopy, TreeSnapshot), Box<dyn Error>> {
    let (crate_root, workspace_manifest) = real_paths()?;
    let snapshot = TreeSnapshot::capture(&crate_root, &workspace_manifest)?;
    let corpus = CorpusCopy::from_real(&crate_root, &workspace_manifest)?;
    Ok((corpus, snapshot))
}

fn assert_rejected(corpus: &CorpusCopy, snapshot: &TreeSnapshot) -> Result<(), Box<dyn Error>> {
    let result = support::scan(&corpus.crate_root, &corpus.workspace_manifest)?;
    snapshot.assert_unchanged()?;
    assert!(!result.violations.is_empty());
    Ok(())
}

fn append(path: &Path, source: &str) -> Result<(), io::Error> {
    let mut contents = fs::read_to_string(path)?;
    contents.push_str(source);
    fs::write(path, contents)
}

fn add_dependency(path: &Path, dependency: &str) -> Result<(), io::Error> {
    let manifest = fs::read_to_string(path)?;
    let header = "[dependencies]\n";
    let Some(offset) = manifest.find(header) else {
        return Err(io::Error::other(
            "copied manifest has no dependencies section",
        ));
    };
    let insert_at = offset + header.len();
    let mut updated = String::with_capacity(manifest.len() + dependency.len() + 1);
    updated.push_str(&manifest[..insert_at]);
    updated.push_str(dependency);
    updated.push('\n');
    updated.push_str(&manifest[insert_at..]);
    fs::write(path, updated)
}

struct CorpusCopy {
    root: PathBuf,
    crate_root: PathBuf,
    workspace_manifest: PathBuf,
}

impl CorpusCopy {
    fn empty() -> Result<Self, io::Error> {
        let root = unique_temp_root()?;
        let crate_root = root.join("crates/spl-bridge");
        fs::create_dir_all(&crate_root)?;
        Ok(Self {
            workspace_manifest: root.join("Cargo.toml"),
            root,
            crate_root,
        })
    }

    fn from_real(crate_root: &Path, workspace_manifest: &Path) -> Result<Self, io::Error> {
        let root = unique_temp_root()?;
        let copied_crate_root = root.join("crates/spl-bridge");
        fs::create_dir_all(&copied_crate_root)?;
        copy_directory(&crate_root.join("src"), &copied_crate_root.join("src"))?;
        let deploy = crate_root.join("deploy");
        if deploy.exists() {
            copy_directory(&deploy, &copied_crate_root.join("deploy"))?;
        }
        fs::copy(
            crate_root.join("Cargo.toml"),
            copied_crate_root.join("Cargo.toml"),
        )?;
        let copied_workspace_manifest = root.join("Cargo.toml");
        fs::copy(workspace_manifest, &copied_workspace_manifest)?;
        Ok(Self {
            root,
            crate_root: copied_crate_root,
            workspace_manifest: copied_workspace_manifest,
        })
    }
}

impl Drop for CorpusCopy {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn unique_temp_root() -> Result<PathBuf, io::Error> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock must be after epoch")
        .as_nanos();
    let root = Path::new("/var/tmp").join(format!(
        "spl-bridge-source-policy-mutation-{}-{nanos}-{}",
        std::process::id(),
        TEMPORARY_CORPUS_COUNTER.fetch_add(1, Ordering::Relaxed),
    ));
    fs::create_dir(&root)?;
    Ok(root)
}

fn copy_directory(source: &Path, destination: &Path) -> Result<(), io::Error> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let destination_path = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_directory(&entry.path(), &destination_path)?;
        } else {
            fs::copy(entry.path(), destination_path)?;
        }
    }
    Ok(())
}

struct TreeSnapshot {
    paths: Vec<PathBuf>,
    fingerprint: u64,
}

impl TreeSnapshot {
    fn capture(crate_root: &Path, workspace_manifest: &Path) -> Result<Self, Box<dyn Error>> {
        let result = support::scan(crate_root, workspace_manifest)?;
        let mut paths = result.inventory.library;
        paths.extend(result.inventory.binary);
        paths.extend(result.inventory.manifest);
        paths.extend(result.inventory.template);
        paths.push(workspace_manifest.to_owned());
        paths.sort();
        let fingerprint = fingerprint(&paths)?;
        Ok(Self { paths, fingerprint })
    }

    fn assert_unchanged(&self) -> Result<(), io::Error> {
        if fingerprint(&self.paths)? == self.fingerprint {
            Ok(())
        } else {
            Err(io::Error::other(
                "real source-policy corpus changed during mutation test",
            ))
        }
    }
}

fn fingerprint(paths: &[PathBuf]) -> Result<u64, io::Error> {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for path in paths {
        for byte in path.to_string_lossy().bytes().chain(fs::read(path)?) {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    Ok(hash)
}
