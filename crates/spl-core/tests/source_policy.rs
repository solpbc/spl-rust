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
            "0691a9d7cf76234986d9277604a5717b213d1abc63d98c28b9978c0121575e76",
        ),
        (
            "identity.md",
            "49e5495a233f34466776cc1d2e295342b8bb1c18329d199436884b9ba42cb9fb",
        ),
        (
            "pair-window.md",
            "df2e60fd3e579081ea0b2673591f540cbfd0c39717bd2cfdbb05231a3c27072e",
        ),
        (
            "pairing.md",
            "335e68568c8cb8fb4d378c521b0035bdfcc021505f84f91751f68ee8cfd3b03f",
        ),
        (
            "session.md",
            "eaaff1ef0e2c6df200aa2c1778dc4669573f8bd9f77c69863e5b6fcecafdd83f",
        ),
        (
            "tokens.md",
            "80868a51d2176c5355b52a7947621c10d322760d7617b3945e3fb1370e6e7f4c",
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
