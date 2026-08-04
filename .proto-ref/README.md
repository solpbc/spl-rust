<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (c) 2026 sol pbc -->

# Protocol reference mirror

This directory is a read-only mirror of the six protocol documents consumed by `spl-rust` from <https://github.com/solpbc/spl/tree/main/proto>, pinned at commit `ddfe13b2abce2fd40acbe2e18d0551727e7ef757`.

The mirrored documents carry no local SPDX header because they are byte-identical upstream copies; adding one would destroy the byte identity this mirror preserves. This README records the directory's SPDX coverage.

To re-vendor, check out the intended upstream commit in a separate clean worktree and copy exactly `framing.md`, `identity.md`, `pairing.md`, `pair-window.md`, `session.md`, and `tokens.md` from its `proto/` directory. Update the commit pin here, `PROTOCOL_REVISION` in `crates/spl-core/test-support/corpus_observers.rs`, and the per-document SHA-256 pins in `crates/spl-core/tests/source_policy.rs`. If `identity.md`, `pairing.md`, or `pair-window.md` changes, also adopt the matching authority bundle: its pinned manifest binds the exact normative-source bytes. Then run the repository gates. Do not copy upstream's `proto/README.md`, and do not edit the mirrored documents locally.
