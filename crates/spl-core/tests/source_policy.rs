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
            "a00c87a8b465e8c438576818ced4428fce039fda242b6540cb72f121c377dcc4",
        ),
        (
            "identity.md",
            "e333fa6a9db7aa7ac7a701144454622130c56ad63d9a993885644ae522a732b4",
        ),
        (
            "pair-window.md",
            "6845844f14871ee7c9991e5c363620f4002d87099640b5156532ff6fd0922b67",
        ),
        (
            "pairing.md",
            "526b1b479ba875501b965d531ab0a1214d06820d1db4d7e354196af8c910de91",
        ),
        (
            "session.md",
            "7acfb5030ae9f4ead7546118cb02abc6136cf44b05b47a94606eac79ee16d396",
        ),
        (
            "tokens.md",
            "c6bfb80cdae62988bb65ffb6972dac2f1f0b195b3ff46be115eddb25bc65aec4",
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
