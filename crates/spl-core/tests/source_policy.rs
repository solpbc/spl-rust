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
fn protocol_mirror_has_exact_pinned_contents() -> Result<(), Box<dyn Error>> {
    let mirror = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.proto-ref");
    // Re-pin these digests deliberately whenever the protocol mirror is re-vendored.
    let pinned_documents = [
        (
            "framing.md",
            "1844ac1d2bee7037fac577dfb81abeb21527529b8ab5648c418b7b19b98172ce",
        ),
        (
            "pair-window.md",
            "990e9bc902175c486544bdf0442c53e2fb31c24e59ae41787efb5f8188b01f58",
        ),
        (
            "pairing.md",
            "214f0779a1f08c733bc4094cbbc3b29d5167ec8ab5df1491a2ed60d482ee61d4",
        ),
        (
            "session.md",
            "ea73dbdd4e33588c3c054ba5d292e1dcda65c915aa5f2d3394f6dd687db87d8e",
        ),
        (
            "tokens.md",
            "99d8d83a8253a3599b23e7441449445a03d056c03e7a2bcd0506a86f623de278",
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
