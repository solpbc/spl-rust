<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (c) 2026 sol pbc -->

# SPL authority definition bundle

`bundle/` is a read-only, byte-identical vendored copy of the complete
five-file pair-link definition bundle published by
<https://github.com/solpbc/spl>. The currently adopted authority repository,
commit, bundle version, manifest digest, and payload records are in
`adoption.json`. The authority-owned `bundle/manifest.json` is the source of
truth for payload names and digests; consumer-owned `adoption.json` records
which authority material this repository adopted.

The conformance test gate verifies the externally pinned manifest, the exact
bundle inventory and payload bytes, the adoption record, the normative-source
digests, citation markers, and every applicable vector against `spl-core`.
Builds and gates are strictly offline: nothing in a build or gate may fetch or
otherwise contact the authority repository.

## Re-vendor

1. Check out `solpbc/spl` at the intended, explicitly named commit in a
   separate clean worktree and verify that worktree is clean.
2. Copy exactly `manifest.json`, `definition.json`,
   `definition.schema.json`, `vectors.json`, and `vectors.schema.json` from
   that checkout's `proto/definition/bundle/` into `conformance/bundle/`.
   Do not copy the authority definition README, add another bundle file, or
   edit the copied JSON.
3. Update `conformance/adoption.json` to record the selected authority commit,
   bundle metadata, manifest digest, and the manifest's four `files[]` entries.
4. Update `AUTHORITY_COMMIT`, `AUTHORITY_MANIFEST_SHA256`, `BUNDLE_SEMVER`, and
   `BUNDLE_SCHEMA_IDENTITY` in
   `crates/spl-core/tests/conformance_corpus.rs`.
5. Review the vendored and adoption diffs, then run the repository gates.

The SPDX header on this README provides `AGPL-3.0-only` coverage for every file
under `conformance/bundle/`. The bundle cannot carry a separate SPDX marker
without violating its exact-five-file inventory, and the authority JSON cannot
be annotated without destroying byte identity.
