<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (c) 2026 sol pbc -->

# SPL core conformance corpus

Published-fixture vectors are independent protocol-conformance evidence. The corpus runner is a regression pin on current library behavior, not general proof of protocol conformance. The regeneration check detects generator or implementation drift only and is not a conformance gate.

Regenerate `spl-core-vectors.json` with `cargo run -p spl-core --example generate_conformance`. Citations name a mirrored protocol document and exact clause marker checked offline by the test gate.

This corpus is input to the authority's bundle and will be replaced by the vendored authority bundle when available.
