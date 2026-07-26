// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Writes the deterministic SPL core regression and published-fixture corpus.

#[path = "../test-support/corpus_generator.rs"]
mod corpus_generator;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let corpus = corpus_generator::generate_corpus()?;
    std::fs::write(
        corpus_generator::corpus_path(),
        corpus_generator::serialize_corpus(&corpus)?,
    )?;
    Ok(())
}
