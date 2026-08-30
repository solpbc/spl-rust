// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Shared source-policy scanner for the bridge's checked-in source tree and fixtures.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

const REJECTED_DEPENDENCIES: &[&str] = &[
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
    "rusqlite",
    "sqlx",
    "sled",
    "rocksdb",
    "redis",
];

const ALLOWED_BINARY_OPTIONS: &[&str] = &[
    "--client-listen",
    "--control-tls-cert",
    "--control-tls-key",
    "--jwks-url",
    "--bridge-id",
    "--jwks-connect-timeout-ms",
    "--jwks-read-timeout-ms",
];

/// Paths discovered in each source-policy inventory class.
#[derive(Debug, Default)]
pub struct Inventory {
    /// Rust sources below `src/`, excluding `src/bin/`.
    pub library: Vec<PathBuf>,
    /// Rust sources below `src/bin/`.
    pub binary: Vec<PathBuf>,
    /// The crate manifest, when present.
    pub manifest: Vec<PathBuf>,
    /// Files below the optional `deploy/` template directory.
    pub template: Vec<PathBuf>,
}

/// The complete result of scanning a bridge source corpus.
#[derive(Debug, Default)]
pub struct ScanResult {
    /// Per-class paths and counts, including empty template inventories.
    pub inventory: Inventory,
    /// Every policy violation found while scanning the inventory.
    pub violations: Vec<String>,
}

/// Scan every source-policy inventory class beneath `crate_root`.
pub fn scan(crate_root: &Path, workspace_manifest: &Path) -> Result<ScanResult, std::io::Error> {
    let source_root = crate_root.join("src");
    let inventory = Inventory {
        library: rust_sources(&source_root, true)?,
        binary: rust_sources(&source_root.join("bin"), false)?,
        manifest: manifest_paths(crate_root),
        template: files_below(&crate_root.join("deploy"))?,
    };
    let mut result = ScanResult {
        inventory,
        violations: Vec::new(),
    };
    check_inventory_completeness(&result.inventory, &mut result.violations);

    for path in &result.inventory.library {
        let source = fs::read_to_string(path)?;
        check_library_source(path, &source, &mut result.violations);
    }
    for path in &result.inventory.binary {
        let source = fs::read_to_string(path)?;
        check_binary_source(path, &source, &mut result.violations);
    }
    if let Some(manifest) = result.inventory.manifest.first() {
        check_manifest(&fs::read_to_string(manifest)?, &mut result.violations);
    }
    if workspace_manifest.is_file() {
        check_workspace_manifest(
            &fs::read_to_string(workspace_manifest)?,
            &mut result.violations,
        );
    } else {
        result
            .violations
            .push(String::from("workspace manifest is missing"));
    }
    for path in &result.inventory.template {
        check_template(path, &fs::read_to_string(path)?, &mut result.violations);
    }
    Ok(result)
}

fn manifest_paths(crate_root: &Path) -> Vec<PathBuf> {
    let manifest = crate_root.join("Cargo.toml");
    manifest.is_file().then_some(manifest).into_iter().collect()
}

fn check_inventory_completeness(inventory: &Inventory, violations: &mut Vec<String>) {
    for (class, paths) in [
        ("library", &inventory.library),
        ("binary", &inventory.binary),
        ("manifest", &inventory.manifest),
    ] {
        if paths.is_empty() {
            violations.push(format!("required {class} inventory is empty"));
        }
    }
}

fn check_library_source(path: &Path, source: &str, violations: &mut Vec<String>) {
    check_filesystem_access(path, source, false, violations);
    for needle in [
        "WindowedUpload",
        "ResponseAssembler",
        "spl_home::HomeConnection",
        "spl_home::HomeStream",
    ] {
        if source.contains(needle) {
            violations.push(format!("library {} contains {needle:?}", path.display()));
        }
    }
    check_runtime_log_calls(path, source, violations);
}

fn check_binary_source(path: &Path, source: &str, violations: &mut Vec<String>) {
    check_filesystem_access(path, source, true, violations);
    check_runtime_log_calls(path, source, violations);
    check_binary_state_inputs(path, source, violations);
}

fn check_filesystem_access(
    path: &Path,
    source: &str,
    permit_control_reads: bool,
    violations: &mut Vec<String>,
) {
    let mut control_read_counts = BTreeMap::new();
    for namespace in ["std::fs::", "tokio::fs::"] {
        let mut offset = 0;
        while let Some(found) = source[offset..].find(namespace) {
            let start = offset + found;
            let call_start = start + namespace.len();
            let method_length = source[call_start..]
                .bytes()
                .take_while(u8::is_ascii_alphanumeric)
                .count();
            let method_end = call_start + method_length;
            let Some(body) = call_body(&source[method_end..]) else {
                violations.push(format!("filesystem access in {}", path.display()));
                offset = method_end;
                continue;
            };
            if permit_control_reads
                && let Some(control_read) =
                    control_startup_read(path, namespace, &source[call_start..method_end], body)
            {
                let count = control_read_counts.entry(control_read).or_insert(0usize);
                *count += 1;
                if *count > 1 {
                    violations.push(format!(
                        "duplicate startup filesystem access in {}",
                        path.display()
                    ));
                }
            } else {
                violations.push(format!("filesystem access in {}", path.display()));
            }
            offset = method_end + body.len() + 2;
        }
    }

    for alias in filesystem_aliases(source).keys() {
        let mut offset = 0;
        while let Some(found) = source[offset..].find(&format!("{alias}::")) {
            let start = offset + found;
            let method_start = start + alias.len() + 2;
            let method_length = source[method_start..]
                .bytes()
                .take_while(u8::is_ascii_alphanumeric)
                .count();
            let method_end = method_start + method_length;
            if call_body(&source[method_end..]).is_some() {
                violations.push(format!("aliased filesystem access in {}", path.display()));
            }
            offset = method_end;
        }
    }
    if permit_control_reads && path.ends_with("src/bin/spl-bridge.rs") {
        for required in ["&options.control_tls_cert", "&options.control_tls_key"] {
            if control_read_counts.get(required) != Some(&1) {
                violations.push(format!(
                    "missing startup filesystem access in {}",
                    path.display()
                ));
            }
        }
    }
}

fn control_startup_read<'a>(
    path: &Path,
    namespace: &str,
    method: &str,
    body: &'a str,
) -> Option<&'a str> {
    (path.ends_with("src/bin/spl-bridge.rs")
        && namespace == "std::fs::"
        && method == "read"
        && matches!(
            body.trim(),
            "&options.control_tls_cert" | "&options.control_tls_key"
        ))
    .then_some(body.trim())
}

fn filesystem_aliases(source: &str) -> BTreeMap<String, String> {
    let mut aliases = BTreeMap::new();
    for line in source.lines().map(str::trim) {
        let Some(rest) = line.strip_prefix("use ") else {
            continue;
        };
        let rest = rest.trim_end_matches(';');
        if let Some((path, alias)) = rest.split_once(" as ") {
            if is_filesystem_module(path) {
                aliases.insert(alias.trim().to_owned(), path.trim().to_owned());
            }
        } else if is_filesystem_module(rest)
            && let Some(alias) = rest.rsplit("::").next()
        {
            aliases.insert(alias.to_owned(), rest.to_owned());
        }
        if let Some((module, group)) = rest
            .split_once("::{")
            .and_then(|(module, group)| group.strip_suffix('}').map(|group| (module, group)))
        {
            for entry in group.split(',').map(str::trim) {
                let (name, alias) = entry.split_once(" as ").map_or((entry, entry), |pair| pair);
                let path = format!("{module}::{}", name.trim());
                if is_filesystem_module(&path) {
                    aliases.insert(alias.trim().to_owned(), path);
                }
            }
        }
    }
    aliases
}

fn is_filesystem_module(path: &str) -> bool {
    matches!(path.trim(), "std::fs" | "tokio::fs")
}

fn check_binary_state_inputs(path: &Path, source: &str, violations: &mut Vec<String>) {
    if source.contains("std::env::var") {
        violations.push(format!("environment variable input in {}", path.display()));
    }
    let mut offset = 0;
    while let Some(found) = source[offset..].find("match flag.as_str()") {
        let start = offset + found + "match flag.as_str()".len();
        let Some(body) = braced_body(&source[start..]) else {
            violations.push(format!(
                "unparseable CLI option match in {}",
                path.display()
            ));
            break;
        };
        for line in body.lines() {
            let Some((pattern, _)) = line.split_once("=>") else {
                continue;
            };
            let pattern = pattern.trim();
            if let Some(option) = string_literal(pattern)
                && option.starts_with("--")
                && !ALLOWED_BINARY_OPTIONS.contains(&option)
            {
                violations.push(format!(
                    "unexpected CLI option {option:?} in {}",
                    path.display()
                ));
            }
        }
        offset = start + body.len() + 2;
    }
}

fn check_template(path: &Path, source: &str, violations: &mut Vec<String>) {
    if path
        .file_name()
        .is_some_and(|name| name == "spl-bridge.service")
    {
        violations.push(format!("forbidden deployment service {}", path.display()));
    }
    for forbidden in [
        "--control-listen",
        "/home/",
        "/Users/",
        "%USERPROFILE%",
        "StateDirectory=",
        ".spl-bridge/state",
    ] {
        if source.contains(forbidden) {
            violations.push(format!(
                "template {} contains {forbidden:?}",
                path.display()
            ));
        }
    }
}

fn check_manifest(manifest: &str, violations: &mut Vec<String>) {
    let dependencies = dependencies_in_section(manifest, "dependencies");
    let dev_dependencies = dependencies_in_section(manifest, "dev-dependencies");
    if dependencies.iter().any(|name| name == "spl-home")
        || !dev_dependencies.iter().any(|name| name == "spl-home")
    {
        violations.push(String::from("spl-home must be a dev-dependency only"));
    }
    for dependency in all_dependencies(manifest) {
        if REJECTED_DEPENDENCIES.contains(&dependency.as_str()) {
            violations.push(format!("forbidden manifest dependency {dependency:?}"));
        }
    }
}

fn check_workspace_manifest(manifest: &str, violations: &mut Vec<String>) {
    let jsonwebtoken = dependency_assignment(manifest, "jsonwebtoken");
    let Some(jsonwebtoken) = jsonwebtoken else {
        violations.push(String::from("workspace must declare jsonwebtoken"));
        return;
    };
    if !jsonwebtoken.contains("rust_crypto") || jsonwebtoken.contains("aws_lc_rs") {
        violations.push(String::from(
            "jsonwebtoken must use rust_crypto and not aws_lc_rs",
        ));
    }
}

fn dependencies_in_section(manifest: &str, section: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut in_section = false;
    for line in manifest.lines().map(str::trim) {
        if line.starts_with('[') && line.ends_with(']') {
            let section_name = line.trim_matches(['[', ']']);
            in_section = section_name == section || section_name.ends_with(&format!(".{section}"));
            continue;
        }
        if in_section && let Some((name, value)) = dependency_line(line) {
            names.push(package_name(name, value));
        }
    }
    names
}

fn all_dependencies(manifest: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut in_dependencies = false;
    for line in manifest.lines().map(str::trim) {
        if line.starts_with('[') && line.ends_with(']') {
            in_dependencies = line.trim_matches(['[', ']']).ends_with("dependencies");
            continue;
        }
        if in_dependencies && let Some((name, value)) = dependency_line(line) {
            names.push(package_name(name, value));
        }
    }
    names
}

fn dependency_assignment<'a>(manifest: &'a str, wanted: &str) -> Option<&'a str> {
    manifest.lines().map(str::trim).find_map(|line| {
        let (name, value) = dependency_line(line)?;
        (package_name(name, value) == wanted).then_some(value)
    })
}

fn dependency_line(line: &str) -> Option<(&str, &str)> {
    if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
        return None;
    }
    let (name, value) = line.split_once('=')?;
    Some((name.trim().trim_matches('"'), value.trim()))
}

fn package_name(name: &str, value: &str) -> String {
    value
        .split("package")
        .nth(1)
        .and_then(|rest| rest.split_once('='))
        .map(|(_, rest)| rest.trim_start().trim_start_matches('"'))
        .and_then(|rest| rest.split('"').next())
        .filter(|package| !package.is_empty())
        .map_or_else(|| name.to_owned(), ToOwned::to_owned)
}

fn check_runtime_log_calls(path: &Path, source: &str, violations: &mut Vec<String>) {
    if source.contains("#[instrument") || source.contains("#[tracing::instrument") {
        violations.push(format!("runtime log attribute in {}", path.display()));
    }
    let aliases = log_aliases(source);
    let mut macros = BTreeMap::new();
    for name in [
        "tracing::info",
        "tracing::warn",
        "tracing::error",
        "tracing::debug",
        "tracing::trace",
        "tracing::event",
        "tracing::span",
        "println",
        "eprintln",
    ] {
        macros.insert(name.to_owned(), name.to_owned());
    }
    macros.extend(aliases);
    for macro_name in macros.keys() {
        let mut offset = 0;
        while let Some(found) = source[offset..].find(&format!("{macro_name}!")) {
            let start = offset + found + macro_name.len() + 1;
            let Some(body) = macro_body(&source[start..]) else {
                violations.push(format!(
                    "unterminated runtime log call in {}",
                    path.display()
                ));
                break;
            };
            if !is_fixed_literal(body) {
                violations.push(format!(
                    "runtime log call has fields or interpolation in {}",
                    path.display()
                ));
            }
            offset = start + body.len() + 2;
        }
    }
}

fn log_aliases(source: &str) -> BTreeMap<String, String> {
    let mut aliases = BTreeMap::new();
    for line in source.lines().map(str::trim) {
        let Some(rest) = line.strip_prefix("use ") else {
            continue;
        };
        let rest = rest.trim_end_matches(';');
        if let Some((path, alias)) = rest.split_once(" as ") {
            if let Some(canonical) = canonical_log_macro(path) {
                aliases.insert(alias.trim().to_owned(), canonical.to_owned());
            } else if path.trim() == "tracing" {
                for macro_name in ["info", "warn", "error", "debug", "trace", "event", "span"] {
                    aliases.insert(
                        format!("{alias}::{macro_name}"),
                        format!("tracing::{macro_name}"),
                    );
                }
            }
        }
        if let Some((module, group)) = rest
            .split_once("::{")
            .and_then(|(module, group)| group.strip_suffix('}').map(|group| (module, group)))
        {
            for entry in group.split(',').map(str::trim) {
                let (name, alias) = entry.split_once(" as ").map_or((entry, entry), |pair| pair);
                if let Some(canonical) = canonical_log_macro(&format!("{module}::{name}")) {
                    aliases.insert(alias.trim().to_owned(), canonical.to_owned());
                }
            }
        }
    }
    aliases
}

fn canonical_log_macro(path: &str) -> Option<&'static str> {
    Some(match path.trim() {
        "tracing::info" => "tracing::info",
        "tracing::warn" => "tracing::warn",
        "tracing::error" => "tracing::error",
        "tracing::debug" => "tracing::debug",
        "tracing::trace" => "tracing::trace",
        "tracing::event" => "tracing::event",
        "tracing::span" => "tracing::span",
        "println" | "std::println" => "println",
        "eprintln" | "std::eprintln" => "eprintln",
        _ => return None,
    })
}

fn call_body(source: &str) -> Option<&str> {
    let source = source.trim_start();
    let body = source.strip_prefix('(')?;
    balanced_body(body, b'(', b')')
}

fn macro_body(source: &str) -> Option<&str> {
    let source = source.trim_start();
    let body = source.strip_prefix('(')?;
    balanced_body(body, b'(', b')')
}

fn braced_body(source: &str) -> Option<&str> {
    let source = source.trim_start();
    let body = source.strip_prefix('{')?;
    balanced_body(body, b'{', b'}')
}

fn balanced_body(source: &str, open: u8, close: u8) -> Option<&str> {
    let mut depth = 1usize;
    let mut quoted = false;
    let mut escaped = false;
    for (index, byte) in source.bytes().enumerate() {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
            continue;
        }
        match byte {
            b'"' => quoted = true,
            byte if byte == open => depth += 1,
            byte if byte == close => {
                depth -= 1;
                if depth == 0 {
                    return Some(&source[..index]);
                }
            }
            _ => {}
        }
    }
    None
}

fn string_literal(source: &str) -> Option<&str> {
    let source = source.trim();
    let literal = source.strip_prefix('"')?;
    let end = literal.find('"')?;
    Some(&literal[..end])
}

fn is_fixed_literal(body: &str) -> bool {
    let body = body.trim();
    body.len() >= 2
        && body.starts_with('"')
        && body.ends_with('"')
        && !body[..body.len() - 1].contains('{')
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
    if !root.exists() {
        return Ok(());
    }
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

fn files_below(root: &Path) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut files = Vec::new();
    collect_files(root, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_files(root: &Path, files: &mut Vec<PathBuf>) -> Result<(), std::io::Error> {
    if !root.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            collect_files(&path, files)?;
        } else {
            files.push(path);
        }
    }
    Ok(())
}
