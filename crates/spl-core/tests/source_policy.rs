// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Offline source purity, product-literal, and protocol-mirror content gates.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

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
    let actual = fs::read_dir(mirror)?
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
    let expected = BTreeSet::from([
        "README.md".to_string(),
        "framing.md".to_string(),
        "pair-window.md".to_string(),
        "pairing.md".to_string(),
        "session.md".to_string(),
        "tokens.md".to_string(),
    ]);
    assert_eq!(actual, expected);
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
