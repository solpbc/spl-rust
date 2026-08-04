// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Structural boundary gates for the listener-only crate.

#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "source-policy tests use direct assertions over controlled fixture text"
)]

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn listener_sources_exclude_http_and_verifier_implementations() -> Result<(), Box<dyn Error>> {
    let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let needles = [
        "spl_core::http",
        "impl ClientCertVerifier",
        "impl rustls::server::danger::ClientCertVerifier",
        "httparse::",
        "http::Request",
        "http::Response",
        "hyper::",
        "h2::",
        "Authorization",
    ];

    let sources = rust_sources(&source_root)?;
    let _first_source = sources
        .first()
        .expect("the listener crate must contain at least one source file");
    for path in sources {
        let source = strip_comments(&fs::read_to_string(&path)?);
        for needle in needles {
            assert!(
                !source.contains(needle),
                "forbidden listener source needle {needle:?} in {}",
                path.display()
            );
        }
    }
    Ok(())
}

#[test]
fn manifest_excludes_http_parsers_and_transport_runtime_dependencies() -> Result<(), Box<dyn Error>>
{
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let manifest = fs::read_to_string(manifest_path)?;
    let regular_dependencies = dependency_names(&manifest, "dependencies");
    let build_dependencies = dependency_names(&manifest, "build-dependencies");
    let forbidden_http = [
        "http",
        "httparse",
        "hyper",
        "h2",
        "http-body",
        "http-body-util",
        "headers",
        "mime",
    ];

    for name in forbidden_http {
        assert!(
            !regular_dependencies
                .iter()
                .any(|dependency| dependency == name)
                && !build_dependencies
                    .iter()
                    .any(|dependency| dependency == name),
            "HTTP parsing dependency {name:?} is forbidden outside dev-dependencies"
        );
    }
    assert!(
        !regular_dependencies
            .iter()
            .any(|dependency| dependency == "spl-transport")
            && !build_dependencies
                .iter()
                .any(|dependency| dependency == "spl-transport"),
        "spl-transport is forbidden outside dev-dependencies"
    );
    Ok(())
}

#[test]
fn home_config_requires_a_caller_supplied_verifier() -> Result<(), Box<dyn Error>> {
    let config = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/config.rs"))?;
    let config = strip_comments(&config);
    assert!(
        config.contains("pub client_cert_verifier: Arc<dyn ClientCertVerifier>"),
        "HomeConfig must expose Arc<dyn ClientCertVerifier> supplied by its caller"
    );
    Ok(())
}

fn dependency_names(manifest: &str, section: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut in_section = false;
    for raw_line in manifest.lines() {
        let line = raw_line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            let header = &line[1..line.len() - 1];
            let subtable_prefix = format!("{section}.");
            if let Some(name) = header.strip_prefix(&subtable_prefix) {
                if let Some(name) = name.split('.').next() {
                    names.push(name.to_owned());
                }
                in_section = false;
            } else {
                in_section = header == section;
            }
            continue;
        }
        if !in_section || line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, _)) = line.split_once('=') else {
            continue;
        };
        names.push(name.trim().trim_matches('"').to_owned());
    }
    names
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

fn strip_comments(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let mut index = 0;
    let mut block_depth = 0;
    while index < source.len() {
        if block_depth > 0 {
            if source[index..].starts_with("/*") {
                block_depth += 1;
                index += 2;
            } else if source[index..].starts_with("*/") {
                block_depth -= 1;
                index += 2;
            } else {
                let character = source[index..].chars().next().unwrap();
                if character == '\n' {
                    output.push('\n');
                }
                index += character.len_utf8();
            }
            continue;
        }
        if source[index..].starts_with("//") {
            while index < source.len() {
                let character = source[index..].chars().next().unwrap();
                if character == '\n' {
                    break;
                }
                index += character.len_utf8();
            }
        } else if source[index..].starts_with("/*") {
            block_depth = 1;
            index += 2;
        } else {
            let character = source[index..].chars().next().unwrap();
            output.push(character);
            index += character.len_utf8();
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{dependency_names, strip_comments};

    #[test]
    fn comments_do_not_satisfy_or_trip_structural_checks() {
        let source = "// http::Request\ncode é /* impl ClientCertVerifier */ more";
        let stripped = strip_comments(source);
        assert_eq!(stripped, "\ncode é  more");
        assert_eq!(stripped.chars().next().unwrap(), '\n');
    }

    #[test]
    fn dependency_subtables_are_counted() {
        let manifest = "[dependencies.httparse]\nversion = \"1\"\n[build-dependencies.spl-transport]\npath = \"../spl-transport\"\n";
        assert_eq!(dependency_names(manifest, "dependencies"), vec!["httparse"]);
        assert_eq!(
            dependency_names(manifest, "build-dependencies"),
            vec!["spl-transport"]
        );
    }
}
