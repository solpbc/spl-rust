// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Offline source-boundary and manifest-path gates for the shared transport.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn library_sources_exclude_consumer_crates() -> Result<(), Box<dyn Error>> {
    let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    // `observer_` strictly broadens the four former observer-specific needles:
    // observer_model, observer_retention, observer_log, and observer_segment.
    let needles = [
        "sender_instance_id",
        "role",
        "segment",
        "linked_system",
        "observer_",
        "platform_win",
        "xtask",
    ];
    for path in rust_sources(&source_root)? {
        let source = fs::read_to_string(&path)?;
        for needle in needles {
            assert!(
                !source.contains(needle),
                "forbidden consumer source needle {needle:?} in {}",
                path.display()
            );
        }
    }
    Ok(())
}

#[test]
fn tcp_listener_binds_use_literal_ipv4_loopback() -> Result<(), Box<dyn Error>> {
    let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let needle = "TcpListener::bind(";
    let expected = "(\"127.0.0.1\"";
    let mut occurrence_count = 0;

    for path in rust_sources(&source_root)? {
        let source = fs::read_to_string(&path)?;
        for (index, _) in source.match_indices(needle) {
            occurrence_count += 1;
            let following = &source[index + needle.len()..];
            assert!(
                following.starts_with(expected),
                "TCP listener bind must use literal IPv4 loopback in {}",
                path.display()
            );
        }
    }

    assert!(
        occurrence_count > 0,
        "expected at least one TCP listener bind in transport sources"
    );
    Ok(())
}

#[test]
fn manifest_paths_remain_inside_workspace() -> Result<(), Box<dyn Error>> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = fs::canonicalize(manifest_dir.join("../.."))?;
    let manifest_path = manifest_dir.join("Cargo.toml");
    let manifest = fs::read_to_string(&manifest_path)?;

    for (line_index, line) in manifest.lines().enumerate() {
        let Some((_, after_path)) = line.split_once("path =") else {
            continue;
        };
        let Some((_, after_quote)) = after_path.split_once('"') else {
            continue;
        };
        let Some((dependency_path, _)) = after_quote.split_once('"') else {
            continue;
        };
        let dependency_path = Path::new(dependency_path);
        let joined = if dependency_path.is_absolute() {
            dependency_path.to_path_buf()
        } else {
            manifest_dir.join(dependency_path)
        };
        let resolved = fs::canonicalize(&joined)?;
        assert!(
            resolved.starts_with(&workspace_root),
            "out-of-workspace path dependency on line {}: {}",
            line_index + 1,
            resolved.display()
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
