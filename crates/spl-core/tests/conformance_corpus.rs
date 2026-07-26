// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Offline authority-bundle integrity, provenance, citation, and behavior gates.

#[path = "../test-support/corpus_observers.rs"]
mod corpus_observers;

use corpus_observers::{Corpus, VectorCase, VectorKind};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::ffi::OsStr;
use std::fs;
use std::path::{Component, Path, PathBuf};

const AUTHORITY_COMMIT: &str = "2682ea2aeb589c87b5153a54576c61daff6eef7c";
const AUTHORITY_MANIFEST_SHA256: &str =
    "a5eee1cdd45bed91c0adb08c1030ae327f3587312cab23a0af6ac59155635b6f";
const BUNDLE_SEMVER: &str = "1.1.1";
const BUNDLE_SCHEMA_IDENTITY: &str = "spl.pair-link-definition-bundle.schema.v1";
const ADOPTION_SCHEMA_VERSION: u32 = 1;
const CONSUMER_IDENTIFIER: &str = "solpbc/spl-rust";
const AUTHORITY_REPOSITORY: &str = "https://github.com/solpbc/spl";
const AUTHORITY_MANIFEST_PATH: &str = "proto/definition/bundle/manifest.json";

#[derive(Debug, Deserialize)]
struct Manifest {
    bundle_schema_identity: String,
    bundle_semver: String,
    files: Vec<FileDigest>,
    generator_inputs: Vec<GeneratorInput>,
}

#[derive(Debug, Deserialize)]
struct FileDigest {
    path: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct GeneratorInput {
    id: String,
    path: String,
    role: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct Adoption {
    spdx_license_identifier: String,
    #[serde(rename = "adoption_schema_version")]
    schema_version: u32,
    consumer_identifier: String,
    authority_repository: String,
    authority_commit: String,
    bundle_semver: String,
    authority_manifest_path: String,
    authority_manifest_sha256: String,
    bundle_files: Vec<FileDigest>,
}

#[test]
fn vendored_bundle_is_byte_exact_against_manifest() -> Result<(), Box<dyn Error>> {
    let actual_inventory = read_bundle_inventory()?;
    if !actual_inventory.contains("manifest.json") {
        return Err(bundle_inventory_error(
            &BTreeSet::from(["manifest.json".to_string()]),
            &BTreeSet::new(),
        )
        .into());
    }

    let manifest = read_pinned_manifest()?;
    require_value(
        "conformance/bundle/manifest.json",
        "bundle_schema_identity",
        &manifest.bundle_schema_identity,
        BUNDLE_SCHEMA_IDENTITY,
    )?;
    require_value(
        "conformance/bundle/manifest.json",
        "bundle_semver",
        &manifest.bundle_semver,
        BUNDLE_SEMVER,
    )?;

    let manifest_paths =
        validate_file_digest_paths(&manifest.files, "conformance/bundle/manifest.json files[]")?;
    let mut expected_inventory = manifest_paths;
    expected_inventory.insert("manifest.json".to_string());
    let missing = expected_inventory
        .difference(&actual_inventory)
        .cloned()
        .collect::<BTreeSet<_>>();
    let unexpected = actual_inventory
        .difference(&expected_inventory)
        .cloned()
        .collect::<BTreeSet<_>>();
    if !missing.is_empty() || !unexpected.is_empty() {
        return Err(bundle_inventory_error(&missing, &unexpected).into());
    }

    for file in &manifest.files {
        let path = bundle_dir().join(&file.path);
        let bytes = read_bytes(&path)?;
        let observed = sha256_hex(&bytes);
        if observed != file.sha256 {
            return Err(format!(
                "digest disagreement for {}: manifest expected {}, observed {}",
                repo_relative_display(&path),
                file.sha256,
                observed
            )
            .into());
        }
    }
    Ok(())
}

#[test]
fn adoption_record_agrees_with_vendored_bundle() -> Result<(), Box<dyn Error>> {
    let manifest = read_pinned_manifest()?;
    let adoption_path = adoption_path();
    let adoption_bytes = read_bytes(&adoption_path)?;
    let adoption: Adoption = serde_json::from_slice(&adoption_bytes).map_err(|error| {
        format!(
            "failed to deserialize {}: {error}",
            repo_relative_display(&adoption_path)
        )
    })?;

    validate_adoption_metadata(&adoption)?;
    validate_adopted_files(&adoption, &manifest)?;
    Ok(())
}

fn validate_adoption_metadata(adoption: &Adoption) -> Result<(), Box<dyn Error>> {
    require_value(
        "conformance/adoption.json",
        "spdx_license_identifier",
        &adoption.spdx_license_identifier,
        "AGPL-3.0-only",
    )?;
    if adoption.schema_version != ADOPTION_SCHEMA_VERSION {
        return Err(format!(
            "conformance/adoption.json adoption_schema_version disagrees with the Rust const: expected {}, observed {}",
            ADOPTION_SCHEMA_VERSION, adoption.schema_version
        )
        .into());
    }
    for (field, observed, expected) in [
        (
            "consumer_identifier",
            adoption.consumer_identifier.as_str(),
            CONSUMER_IDENTIFIER,
        ),
        (
            "authority_repository",
            adoption.authority_repository.as_str(),
            AUTHORITY_REPOSITORY,
        ),
        (
            "authority_commit",
            adoption.authority_commit.as_str(),
            AUTHORITY_COMMIT,
        ),
        (
            "bundle_semver",
            adoption.bundle_semver.as_str(),
            BUNDLE_SEMVER,
        ),
        (
            "authority_manifest_path",
            adoption.authority_manifest_path.as_str(),
            AUTHORITY_MANIFEST_PATH,
        ),
        (
            "authority_manifest_sha256",
            adoption.authority_manifest_sha256.as_str(),
            AUTHORITY_MANIFEST_SHA256,
        ),
    ] {
        require_value("conformance/adoption.json", field, observed, expected)?;
    }
    Ok(())
}

fn validate_adopted_files(adoption: &Adoption, manifest: &Manifest) -> Result<(), Box<dyn Error>> {
    let manifest_paths =
        validate_file_digest_paths(&manifest.files, "conformance/bundle/manifest.json files[]")?;
    let adoption_paths = validate_file_digest_paths(
        &adoption.bundle_files,
        "conformance/adoption.json bundle_files[]",
    )?;
    let missing = manifest_paths
        .difference(&adoption_paths)
        .cloned()
        .collect::<BTreeSet<_>>();
    let unexpected = adoption_paths
        .difference(&manifest_paths)
        .cloned()
        .collect::<BTreeSet<_>>();
    if !missing.is_empty() || !unexpected.is_empty() {
        return Err(format!(
            "conformance/adoption.json bundle_files[] disagrees with conformance/bundle/manifest.json files[]: missing [{}], unexpected [{}]",
            prefixed_paths(&missing).join(", "),
            prefixed_paths(&unexpected).join(", ")
        )
        .into());
    }

    let manifest_order = manifest
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect::<Vec<_>>();
    let adoption_order = adoption
        .bundle_files
        .iter()
        .map(|file| file.path.as_str())
        .collect::<Vec<_>>();
    if adoption_order != manifest_order {
        return Err(format!(
            "conformance/adoption.json bundle_files[] order disagrees with conformance/bundle/manifest.json files[]: adoption {adoption_order:?}, manifest {manifest_order:?}"
        )
        .into());
    }

    let manifest_digests = manifest
        .files
        .iter()
        .map(|file| (file.path.as_str(), file.sha256.as_str()))
        .collect::<BTreeMap<_, _>>();
    for file in &adoption.bundle_files {
        let manifest_digest = manifest_digests.get(file.path.as_str()).ok_or_else(|| {
            format!(
                "conformance/adoption.json bundle_files[{}] is absent from conformance/bundle/manifest.json",
                file.path
            )
        })?;
        if file.sha256 != *manifest_digest {
            return Err(format!(
                "conformance/adoption.json bundle_files[{}].sha256 disagrees with conformance/bundle/manifest.json: adoption {}, manifest {}",
                file.path, file.sha256, manifest_digest
            )
            .into());
        }
    }
    Ok(())
}

#[test]
fn vendored_vectors_pin_library_behavior() -> Result<(), Box<dyn Error>> {
    let corpus = read_corpus()?;
    for vector in &corpus.vectors {
        match &vector.case {
            VectorCase::ParsePairLink { input, expected } => {
                let actual = corpus_observers::observe_pair(input)?;
                assert_eq!(&actual, expected, "vector {}", vector.id);
            }
            VectorCase::DecodeCrockford {
                input,
                expected_hex,
            } => {
                let actual = corpus_observers::observe_crockford(input)?;
                assert_eq!(&actual, expected_hex, "vector {}", vector.id);
            }
            VectorCase::DeriveRelayKey {
                secret_hex,
                expected_hex,
            } => {
                let actual = corpus_observers::observe_relay_key(secret_hex)?;
                assert_eq!(&actual, expected_hex, "vector {}", vector.id);
            }
        }
    }
    Ok(())
}

#[test]
fn declared_vector_subset_is_explicit() -> Result<(), Box<dyn Error>> {
    let corpus = read_corpus()?;
    let actual = corpus
        .vectors
        .iter()
        .filter(|vector| vector.kind == VectorKind::Declared)
        .map(|vector| vector.id.as_str())
        .collect::<BTreeSet<_>>();
    let expected = BTreeSet::from([
        "pair.v04.canonical.admission",
        "pair.v04.canonical.decode",
        "pair.v06.custom.published",
        "pair.v06.default.published",
        "relay.rk.published",
    ]);
    assert_eq!(actual, expected);
    Ok(())
}

#[test]
fn citations_resolve_to_exact_vendored_markers() -> Result<(), Box<dyn Error>> {
    let corpus = read_corpus()?;
    for vector in &corpus.vectors {
        let citation = vector
            .citation
            .as_ref()
            .ok_or_else(|| format!("vector {} citation is missing", vector.id))?;
        if citation.document.trim().is_empty() {
            return Err(format!("vector {} citation document is empty", vector.id).into());
        }
        if citation.marker.trim().is_empty() {
            return Err(format!("vector {} citation marker is empty", vector.id).into());
        }

        let basename = validate_authority_document_path(
            &citation.document,
            &format!("vector {} citation", vector.id),
        )?;
        let mapped = Path::new(".proto-ref").join(&basename);
        let mapped_remainder = mapped.strip_prefix(".proto-ref").map_err(|_| {
            format!(
                "vector {} mapped citation path is outside .proto-ref: {}",
                vector.id,
                mapped.display()
            )
        })?;
        if !mapped.is_relative()
            || !matches!(
                mapped_remainder.components().collect::<Vec<_>>().as_slice(),
                [Component::Normal(_)]
            )
        {
            return Err(format!(
                "vector {} mapped citation path is not confined to one file under .proto-ref: {}",
                vector.id,
                mapped.display()
            )
            .into());
        }

        let target = repo_root().join(&mapped);
        if !target.is_file() {
            return Err(format!(
                "vector {} citation file does not exist: {}",
                vector.id,
                repo_relative_display(&target)
            )
            .into());
        }
        let document = read_bytes(&target)?;
        let marker = citation.marker.as_bytes();
        if !document
            .windows(marker.len())
            .any(|window| window == marker)
        {
            return Err(format!(
                "vector {} citation marker is absent from {}",
                vector.id,
                repo_relative_display(&target)
            )
            .into());
        }
    }
    Ok(())
}

#[test]
fn normative_sources_match_authority_manifest() -> Result<(), Box<dyn Error>> {
    let manifest = read_pinned_manifest()?;
    let mut basenames = BTreeSet::new();
    for input in manifest
        .generator_inputs
        .iter()
        .filter(|input| input.role == "normative_source_document")
    {
        let basename = validate_authority_document_path(
            &input.path,
            &format!(
                "conformance/bundle/manifest.json generator_inputs[{}]",
                input.id
            ),
        )?;
        if !basenames.insert(basename.clone()) {
            return Err(format!(
                "conformance/bundle/manifest.json has duplicate normative-source basename {basename}"
            )
            .into());
        }
        let target = repo_root().join(".proto-ref").join(&basename);
        if !target.is_file() {
            return Err(format!(
                "conformance/bundle/manifest.json generator_inputs[{}] maps to missing {}",
                input.id,
                repo_relative_display(&target)
            )
            .into());
        }
        let observed = sha256_hex(&read_bytes(&target)?);
        if observed != input.sha256 {
            return Err(format!(
                "normative-source digest disagreement for conformance/bundle/manifest.json generator_inputs[{}] and {}: manifest {}, observed {}",
                input.id,
                repo_relative_display(&target),
                input.sha256,
                observed
            )
            .into());
        }
    }
    Ok(())
}

#[test]
fn protocol_mirror_revision_is_documented() -> Result<(), Box<dyn Error>> {
    let readme_path = repo_root().join(".proto-ref/README.md");
    let readme = fs::read_to_string(&readme_path).map_err(|error| {
        format!(
            "failed to read {}: {error}",
            repo_relative_display(&readme_path)
        )
    })?;
    assert!(
        readme.contains(corpus_observers::PROTOCOL_REVISION),
        "{} does not contain PROTOCOL_REVISION {}",
        repo_relative_display(&readme_path),
        corpus_observers::PROTOCOL_REVISION
    );
    Ok(())
}

fn read_corpus() -> Result<Corpus, Box<dyn Error>> {
    let path = corpus_observers::vectors_path();
    let contents = read_bytes(&path)?;
    serde_json::from_slice(&contents).map_err(|error| {
        format!(
            "failed to deserialize {}: {error}",
            repo_relative_display(&path)
        )
        .into()
    })
}

fn read_pinned_manifest() -> Result<Manifest, Box<dyn Error>> {
    let path = bundle_dir().join("manifest.json");
    let contents = read_bytes(&path)?;
    let observed = sha256_hex(&contents);
    if observed != AUTHORITY_MANIFEST_SHA256 {
        return Err(format!(
            "digest disagreement for {}: Rust const expected {}, observed {}",
            repo_relative_display(&path),
            AUTHORITY_MANIFEST_SHA256,
            observed
        )
        .into());
    }
    serde_json::from_slice(&contents).map_err(|error| {
        format!(
            "failed to deserialize externally pinned {}: {error}",
            repo_relative_display(&path)
        )
        .into()
    })
}

fn read_bundle_inventory() -> Result<BTreeSet<String>, Box<dyn Error>> {
    let directory = bundle_dir();
    let mut paths = BTreeSet::new();
    let mut non_files = Vec::new();
    for entry in fs::read_dir(&directory).map_err(|error| {
        format!(
            "failed to inventory {}: {error}",
            repo_relative_display(&directory)
        )
    })? {
        let entry = entry.map_err(|error| {
            format!(
                "failed to read an entry under {}: {error}",
                repo_relative_display(&directory)
            )
        })?;
        let path = entry.path();
        let name = entry.file_name().into_string().map_err(|_| {
            format!(
                "bundle inventory disagreement: non-UTF-8 path {}",
                path.display()
            )
        })?;
        let file_type = entry.file_type().map_err(|error| {
            format!(
                "failed to inspect bundle entry {}: {error}",
                repo_relative_display(&path)
            )
        })?;
        if !file_type.is_file() {
            non_files.push(format!("conformance/bundle/{name}"));
        }
        paths.insert(name);
    }
    if !non_files.is_empty() {
        non_files.sort();
        return Err(format!(
            "bundle inventory disagreement: non-regular entries [{}]",
            non_files.join(", ")
        )
        .into());
    }
    Ok(paths)
}

fn validate_file_digest_paths(
    files: &[FileDigest],
    owner: &str,
) -> Result<BTreeSet<String>, Box<dyn Error>> {
    let mut paths = BTreeSet::new();
    for file in files {
        let path = Path::new(&file.path);
        let components = path.components().collect::<Vec<_>>();
        if path.is_absolute()
            || !matches!(components.as_slice(), [Component::Normal(name)] if *name == path.as_os_str())
        {
            return Err(format!(
                "{owner} contains unsafe bundle path {:?}; expected one relative normal component",
                file.path
            )
            .into());
        }
        if file.path == "manifest.json" {
            return Err(format!(
                "{owner} lists manifest.json even though the authority manifest excludes itself"
            )
            .into());
        }
        if !paths.insert(file.path.clone()) {
            return Err(format!("{owner} contains duplicate path {:?}", file.path).into());
        }
    }
    Ok(paths)
}

fn validate_authority_document_path(document: &str, owner: &str) -> Result<String, Box<dyn Error>> {
    let path = Path::new(document);
    if !path.is_relative() {
        return Err(format!("{owner} document path is absolute: {document:?}").into());
    }
    let components = path.components().collect::<Vec<_>>();
    if components
        .iter()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!(
            "{owner} document path contains traversal or a non-normal component: {document:?}"
        )
        .into());
    }
    let basename = match components.as_slice() {
        [Component::Normal(prefix), Component::Normal(basename)]
            if *prefix == OsStr::new("proto") =>
        {
            basename
        }
        _ => {
            return Err(format!(
                "{owner} document path is outside the authority proto directory: {document:?}"
            )
            .into());
        }
    };
    basename
        .to_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("{owner} document basename is not UTF-8: {document:?}").into())
}

fn require_value(
    owner: &str,
    field: &str,
    observed: &str,
    expected: &str,
) -> Result<(), Box<dyn Error>> {
    if observed != expected {
        return Err(format!(
            "{owner} {field} disagrees with the Rust const: expected {expected:?}, observed {observed:?}"
        )
        .into());
    }
    Ok(())
}

fn bundle_inventory_error(missing: &BTreeSet<String>, unexpected: &BTreeSet<String>) -> String {
    format!(
        "bundle inventory disagreement: missing [{}], unexpected [{}]",
        prefixed_paths(missing).join(", "),
        prefixed_paths(unexpected).join(", ")
    )
}

fn prefixed_paths(paths: &BTreeSet<String>) -> Vec<String> {
    paths
        .iter()
        .map(|path| format!("conformance/bundle/{path}"))
        .collect()
}

fn read_bytes(path: &Path) -> Result<Vec<u8>, Box<dyn Error>> {
    fs::read(path)
        .map_err(|error| format!("failed to read {}: {error}", repo_relative_display(path)).into())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn bundle_dir() -> PathBuf {
    repo_root().join("conformance/bundle")
}

fn adoption_path() -> PathBuf {
    repo_root().join("conformance/adoption.json")
}

fn repo_relative_display(path: &Path) -> String {
    path.strip_prefix(repo_root()).map_or_else(
        |_| path.display().to_string(),
        |path| path.display().to_string(),
    )
}
