// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Offline source purity, product-literal, and protocol-mirror content gates.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

#[test]
fn library_sources_remain_pure_and_product_neutral() -> Result<(), Box<dyn Error>> {
    let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let needles = [
        "std::fs",
        "std::net",
        "std::time",
        "SystemTime",
        "Instant",
        "tokio",
        "async fn",
        "x-solstone-",
        "__solstone_journal",
    ];
    for path in rust_sources(&source_root)? {
        let source = fs::read_to_string(&path)?;
        for needle in needles {
            assert!(
                !source.contains(needle),
                "forbidden source needle {needle:?} in {}",
                path.display()
            );
        }
    }
    Ok(())
}

#[test]
fn sources_and_tests_exclude_consumer_dependencies() -> Result<(), Box<dyn Error>> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let consumer_crates = [
        "observer_pl",
        "pl_transport_win",
        "observer_model",
        "platform_win",
        "solstone_windows",
    ];
    for dir in ["src", "tests"] {
        let root = manifest_dir.join(dir);
        if !root.exists() {
            continue;
        }
        for path in rust_sources(&root)? {
            if path.ends_with("source_policy.rs") {
                continue;
            }
            let source = fs::read_to_string(&path)?;
            for c in consumer_crates {
                let use_pattern = format!("use {c}");
                let path_pattern = format!("{c}::");
                let extern_pattern = format!("extern crate {c}");
                assert!(
                    !source.contains(&use_pattern)
                        && !source.contains(&path_pattern)
                        && !source.contains(&extern_pattern),
                    "forbidden consumer dependency import/path {c:?} in {}",
                    path.display()
                );
            }
        }
    }
    let manifest_path = manifest_dir.join("Cargo.toml");
    let manifest = fs::read_to_string(manifest_path)?;
    assert!(
        !manifest.contains("solstone-windows"),
        "forbidden dependency solstone-windows in Cargo.toml"
    );
    Ok(())
}

#[test]
fn protocol_mirror_has_exact_pinned_contents() -> Result<(), Box<dyn Error>> {
    let mirror = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.proto-ref");
    // Re-pin these digests deliberately whenever the protocol mirror is re-vendored.
    let pinned_documents = [
        (
            "framing.md",
            "7dfd8b8c6cd99d8d5769528f8b8d99c6f7ebaf60908377a454d6e82aee2da3e3",
        ),
        (
            "identity.md",
            "49e5495a233f34466776cc1d2e295342b8bb1c18329d199436884b9ba42cb9fb",
        ),
        (
            "pair-window.md",
            "83e0a7ab94a95ae5b7234354754188e80707373c09feeea06fc4fb6591ec4746",
        ),
        (
            "pairing.md",
            "a2888ac8cdfcd78a20f28f3f8856fe9bddedff9bf1f724f842ad47fd3ec2a672",
        ),
        (
            "session.md",
            "5b8eee5ec9e7388164774fd1e260e5ba0d998127d84d2a6be368eac0832f464c",
        ),
        (
            "tokens.md",
            "93fae6624e1b0af91aa7f19f3f8f899837bc584903f62a0488cea32c86194147",
        ),
    ];
    let actual = fs::read_dir(&mirror)?
        .map(|entry| {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                return Err(std::io::Error::other("protocol mirror contains a non-file"));
            }
            entry
                .file_name()
                .into_string()
                .map_err(|_| std::io::Error::other("protocol mirror filename is not UTF-8"))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let mut expected = BTreeSet::from(["README.md".to_string()]);
    expected.extend(
        pinned_documents
            .iter()
            .map(|(filename, _)| (*filename).to_string()),
    );
    assert_eq!(actual, expected);

    for (filename, expected_digest) in pinned_documents {
        let contents = fs::read(mirror.join(filename))?;
        let actual_digest = format!("{:x}", Sha256::digest(contents));
        assert_eq!(
            actual_digest, expected_digest,
            "vendored protocol digest changed for {filename}; re-vendor deliberately and update its pinned SHA-256"
        );
    }
    Ok(())
}

fn rust_sources(root: &Path) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut sources = Vec::new();
    collect_rust_sources(root, &mut sources)?;
    sources.sort();
    Ok(sources)
}

fn collect_rust_sources(root: &Path, sources: &mut Vec<PathBuf>) -> Result<(), std::io::Error> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            collect_rust_sources(&path, sources)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push(path);
        }
    }
    Ok(())
}
