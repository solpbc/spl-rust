// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Mechanical dependency and retention boundaries for the public bridge.

#![expect(
    clippy::expect_used,
    reason = "source-policy tests use direct assertions over controlled fixture text"
)]

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn library_sources_do_not_access_files_or_rejected_mux_types() -> Result<(), Box<dyn Error>> {
    let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let sources = rust_sources(&source_root, true)?;
    for path in sources {
        let source = fs::read_to_string(&path)?;
        for needle in ["std::fs::", "tokio::fs::"] {
            assert!(
                !source.contains(needle),
                "library source {} contains forbidden filesystem access {needle:?}",
                path.display()
            );
        }
        for needle in [
            "WindowedUpload",
            "ResponseAssembler",
            "spl_home::HomeConnection",
            "spl_home::HomeStream",
        ] {
            assert!(
                !source.contains(needle),
                "library source {} contains forbidden dependency {needle:?}",
                path.display()
            );
        }
    }
    Ok(())
}

#[test]
fn manifest_keeps_home_dev_only_and_excludes_rejected_dependencies() -> Result<(), Box<dyn Error>> {
    let manifest = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))?;
    let dependencies = section_dependency_names(&manifest, "dependencies");
    let dev_dependencies = section_dependency_names(&manifest, "dev-dependencies");
    assert!(
        !dependencies
            .iter()
            .any(|dependency| dependency == "spl-home")
            && dev_dependencies
                .iter()
                .any(|dependency| dependency == "spl-home"),
        "spl-home must be a dev-dependency only"
    );

    let all_dependencies = dependency_names(&manifest);
    for dependency in [
        "aws-lc-rs",
        "boring",
        "boring-sys",
        "superboring",
        "jwt-simple",
        "openssl",
        "reqwest",
        "hyper",
        "h2",
        "http-body",
        "tower",
    ] {
        assert!(
            !all_dependencies.iter().any(|name| name == dependency),
            "forbidden manifest dependency {dependency:?}"
        );
    }
    Ok(())
}

#[test]
fn workspace_jsonwebtoken_keeps_the_rust_crypto_feature_shape() -> Result<(), Box<dyn Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate must be in the workspace")
        .join("Cargo.toml");
    let root_manifest = fs::read_to_string(root)?;
    let line = root_manifest
        .lines()
        .find(|line| line.trim_start().starts_with("jsonwebtoken ="))
        .expect("workspace must declare jsonwebtoken");
    assert!(line.contains("rust_crypto"));
    assert!(!line.contains("aws_lc_rs"));
    Ok(())
}

fn section_dependency_names(manifest: &str, section: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut in_section = false;
    for line in manifest.lines().map(str::trim) {
        if line.starts_with('[') && line.ends_with(']') {
            in_section = line == format!("[{section}]");
            continue;
        }
        if in_section
            && !line.is_empty()
            && !line.starts_with('#')
            && let Some((name, _)) = line.split_once('=')
        {
            names.push(name.trim().trim_matches('"').to_owned());
        }
    }
    names
}

fn dependency_names(manifest: &str) -> Vec<String> {
    manifest
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('[') && !line.starts_with('#'))
        .filter_map(|line| {
            line.split_once('=')
                .map(|(name, _)| name.trim().trim_matches('"'))
        })
        .filter(|name| !name.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn rust_sources(root: &Path, skip_bin: bool) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut sources = Vec::new();
    collect_rust_sources(root, skip_bin, &mut sources)?;
    sources.sort();
    Ok(sources)
}

fn collect_rust_sources(
    root: &Path,
    skip_bin: bool,
    sources: &mut Vec<PathBuf>,
) -> Result<(), std::io::Error> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            if skip_bin && path.file_name().is_some_and(|name| name == "bin") {
                continue;
            }
            collect_rust_sources(&path, skip_bin, sources)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push(path);
        }
    }
    Ok(())
}
