// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Offline regression, determinism, citation, and published-fixture gates.

#[path = "../test-support/corpus_generator.rs"]
mod corpus_generator;

use corpus_generator::{Corpus, Evidence, VectorCase};
use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Component, Path};

/// Regeneration/determinism drift check; explicitly not a protocol-conformance gate.
#[test]
fn committed_corpus_is_deterministic() -> Result<(), Box<dyn Error>> {
    let committed = fs::read_to_string(corpus_generator::corpus_path())?;
    let regenerated = corpus_generator::serialize_corpus(&corpus_generator::generate_corpus()?)?;
    if committed != regenerated {
        let committed_lines = committed.lines().count();
        let regenerated_lines = regenerated.lines().count();
        let line_index = committed
            .lines()
            .zip(regenerated.lines())
            .position(|(left, right)| left != right)
            .unwrap_or(committed_lines.min(regenerated_lines));
        let committed_line = committed
            .lines()
            .nth(line_index)
            .map_or("<end of file>", |line| line);
        let regenerated_line = regenerated
            .lines()
            .nth(line_index)
            .map_or("<end of file>", |line| line);
        return Err(format!(
            "committed corpus differs from regeneration at line {}: committed {committed_line:?}, regenerated {regenerated_line:?}",
            line_index + 1
        )
        .into());
    }
    Ok(())
}

#[test]
fn committed_vectors_pin_library_behavior() -> Result<(), Box<dyn Error>> {
    let corpus = read_corpus()?;
    for vector in &corpus.vectors {
        match &vector.case {
            VectorCase::ParsePairLink { input, expected } => {
                let actual = corpus_generator::observe_pair(input)?;
                assert_eq!(&actual, expected, "vector {}", vector.id);
            }
            VectorCase::DecodeCrockford {
                input,
                expected_hex,
            } => {
                let actual = corpus_generator::observe_crockford(input)?;
                assert_eq!(&actual, expected_hex, "vector {}", vector.id);
            }
            VectorCase::DeriveRelayKey {
                secret_hex,
                expected_hex,
            } => {
                let actual = corpus_generator::observe_relay_key(secret_hex)?;
                assert_eq!(&actual, expected_hex, "vector {}", vector.id);
            }
        }
    }
    Ok(())
}

#[test]
fn published_fixture_subset_is_explicit() -> Result<(), Box<dyn Error>> {
    let corpus = read_corpus()?;
    let actual = corpus
        .vectors
        .iter()
        .filter(|vector| vector.evidence == Evidence::PublishedFixture)
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
fn citations_resolve_to_exact_vendored_clauses() -> Result<(), Box<dyn Error>> {
    let corpus = read_corpus()?;
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for vector in &corpus.vectors {
        assert!(
            !vector.citations.is_empty(),
            "vector {} has no citation",
            vector.id
        );
        for citation in &vector.citations {
            assert!(
                !citation.clause.trim().is_empty(),
                "empty clause marker for {}",
                vector.id
            );
            let relative = Path::new(&citation.document);
            assert!(relative.is_relative(), "absolute citation in {}", vector.id);
            assert!(
                relative.components().all(|component| {
                    matches!(component, Component::Normal(_) | Component::CurDir)
                }),
                "citation traversal in {}",
                vector.id
            );
            assert!(
                relative.strip_prefix(".proto-ref").is_ok(),
                "citation outside .proto-ref in {}",
                vector.id
            );
            let target = repo_root.join(relative);
            assert!(target.is_file(), "missing citation file for {}", vector.id);
            let document = fs::read_to_string(&target)?;
            assert!(
                document.contains(&citation.clause),
                "missing clause marker for {}: {}",
                vector.id,
                citation.clause
            );
        }
    }
    Ok(())
}

#[test]
fn prose_and_machine_provenance_agree() -> Result<(), Box<dyn Error>> {
    let corpus = read_corpus()?;
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mirror_readme = fs::read_to_string(repo_root.join(".proto-ref/README.md"))?;
    assert_eq!(
        corpus.protocol_revision,
        corpus_generator::PROTOCOL_REVISION
    );
    assert!(
        mirror_readme.contains(&corpus.protocol_revision),
        "protocol mirror README and corpus revision disagree"
    );
    Ok(())
}

fn read_corpus() -> Result<Corpus, Box<dyn Error>> {
    Ok(serde_json::from_str(&fs::read_to_string(
        corpus_generator::corpus_path(),
    )?)?)
}
