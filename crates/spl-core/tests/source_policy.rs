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
            "3735db388e0105131c346ca4a932a673ad56b0854ac31c23568e541031cde069",
        ),
        (
            "pair-window.md",
            "5ef0084f8efde114064499da184b2e9b97dd6cef8b722314b07fff23d82a7d47",
        ),
        (
            "pairing.md",
            "4544a33a66df6b776e689a312b8b88c677f1fee85fc74eb841ff9e700e73c240",
        ),
        (
            "session.md",
            "8d79d35bcc5f8ffede315235f1eb3621e96a402caea5e89cd7be2034bd239eac",
        ),
        (
            "tokens.md",
            "9a5dadfe0af64eb8b1f081d00846744e5d2b1199b6155543b61ef7574589a026",
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
