<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (c) 2026 sol pbc -->

# Protocol reference mirror

This directory is a read-only mirror of the six protocol documents consumed by `spl-rust` from <https://github.com/solpbc/spl/tree/main/proto>, pinned at commit `2393102495dca0e692562e33a5fcb2bc1e18de7d`.

The mirrored documents carry no local SPDX header because they are byte-identical upstream copies; adding one would destroy the byte identity this mirror preserves. This README records the directory's SPDX coverage.

To re-vendor, check out the intended upstream commit in a separate clean worktree and copy exactly `framing.md`, `identity.md`, `pairing.md`, `pair-window.md`, `session.md`, and `tokens.md` from its `proto/` directory. Do not copy upstream's `proto/README.md`, and do not edit the mirrored documents locally.

The upstream commit and the bundle are pinned in **five** places, and a re-vendor that misses one fails the gate rather than passing quietly. Update all of them:

1. the commit pin in this file;
2. `PROTOCOL_REVISION` in `crates/spl-core/test-support/corpus_observers.rs`;
3. the per-document SHA-256 pins in `crates/spl-core/tests/source_policy.rs`;
4. `AUTHORITY_COMMIT`, `AUTHORITY_MANIFEST_SHA256` and `BUNDLE_SEMVER` in `crates/spl-core/tests/conformance_corpus.rs`;
5. `authority_commit`, `bundle_semver` and `authority_manifest_sha256` in `conformance/adoption.json`.

If `identity.md`, `pairing.md`, or `pair-window.md` changes, also adopt the matching authority bundle: its pinned manifest binds the exact normative-source bytes. A change confined to `framing.md`, `session.md`, or `tokens.md` leaves the bundle untouched, because those three are not generator inputs upstream. Then run the repository gates.

This list previously named only the first three. The gate caught the gap — the three bundle-agreement tests failed one at a time, each naming a different missing pin — but only after the re-vendor was already half applied, so the list is now complete.
