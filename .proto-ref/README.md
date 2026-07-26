<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (c) 2026 sol pbc -->

# Protocol reference mirror

This directory is a read-only mirror of the five protocol documents consumed by `spl-rust` from <https://github.com/solpbc/spl/tree/main/proto>, pinned at commit `92b54d057d445d60b06b0fbe6f0c6b14120148ff`.

To re-vendor, check out the intended upstream commit in a separate clean worktree, copy exactly `framing.md`, `pairing.md`, `pair-window.md`, `session.md`, and `tokens.md` from its `proto/` directory, update the pin here and in `conformance/spl-core-vectors.json`, and run the repository gates. Do not copy upstream's `proto/README.md`, and do not edit the mirrored documents locally.
