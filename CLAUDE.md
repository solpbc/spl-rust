# Agent guide — spl-rust

This repo is the SPL (solstone private link) client library for Rust consumers — crates `spl-core` and `spl-transport`. It is security-critical transport code that ships inside released products via exact version tags. Read this file fully before changing anything.

## What governs this codebase

1. **The protocol documents win.** All wire behavior follows the [`proto/` docs in solpbc/spl](https://github.com/solpbc/spl/tree/main/proto) (framing, session, pairing, pair-window, tokens) and the conformance-vector corpus generated from them. When code and protocol disagree, the protocol is authoritative; if the protocol looks wrong, raise it — never silently invent wire behavior. A vendored corpus is checked in and its gate runs offline in `make ci`; **never fetch the protocol repository during a build or a gate**.
2. **Vendoring without a gate is decoration.** If a copy of protocol material lands here, something in `make ci` must consume it and be capable of going red. A vendored artifact nothing reads is worse than no artifact — it looks like conformance and proves nothing.
3. **This is the shared implementation — application layers stay out.** Observer registration and segment ingest, linked-system credential provisioning, credential storage, retry supervision policy, and service lifecycles belong to the consuming product. `spl-core` must compile with no consumer's application types in scope. A "while we're here" application type in this package is the specific failure that turns a shared core into a grab-bag.
4. **`spl-core` is pure.** No I/O, no clock, no filesystem, no platform dependency, no async. If a change to `spl-core` needs any of those, it belongs in `spl-transport` or in the consumer.
5. **Platform differences are configuration, not conditionals.** `rustls` is cross-platform; a `#[cfg(target_os)]` in this package needs a written justification and is wrong until proven otherwise. Credential storage — the one genuinely platform-bound concern — is deliberately not in this package.
6. **Dependency policy is enforced, not advisory.** `cargo deny` runs in `make ci` against an explicit license allowlist, banned crates, and approved registries. Crypto and transport crates pin the `ring` provider with `default-features = false`; keep one audited provider across every consumer rather than mixing backends.
7. **No telemetry, analytics, or crash reporting in any form** — this is a covenant, not a preference. A change that adds one, or any phone-home behavior, will not ship.
8. **Never log secrets.** No token, key, certificate, nonce, pair-link fragment, or payload bytes in any log line at any level, including error paths. A rejection diagnostic must not reflect an untrusted peer's response body back into a log.

## Conventions

- Layout: `crates/spl-core/src/` (pure wire) and `crates/spl-transport/src/` (sockets, TLS, mux carrier, loopback proxy).
- Build/test: `make install`, `make test`, `make ci`. All must be green before any commit.
- `make ci` runs fmt, clippy (`-D warnings`), tests, `cargo deny`, and a `cargo check` for every consumer target. A target break belongs here, not at a consumer's adoption.
- `unsafe_code = "forbid"` at the workspace level. There is no exception in this package.
- Every source file carries the SPDX header (`AGPL-3.0-only`).
- A behavior fix lands with a test that fails on the pre-fix code. A test that cannot go red is not a regression test.
- Conformance tests cite the protocol clause they pin. Keep that discipline for every new wire behavior.

## Safety rails

- **Never weaken a gate to get green** — no skipped tests, no loosened lints, no `-D warnings` removal, no dropped target from the check matrix. If a gate is red for environmental reasons, say so and stop.
- **Never retag or force-push a tag.** Consumers pin exact tags and cache by hash; a moved tag silently serves stale or wrong code. New content = new tag, always.
- **The MSRV floor is the lowest consuming product's toolchain.** Raising `rust-version` breaks a consumer's build silently. Treat it as a contract, not a convenience.
- **No GitHub workflows.** CI is operator-run locally; do not add `.github/workflows/`.
- **No pushes to consumer repositories from here.** Migrating a consumer onto this package is separate, operator-driven work with that product's own release gates.
- **Before tagging a release, run the full-circle integration gate on every platform that has one.** Running a consumer's gate is validation, not a push to its repository. A change to wire behavior is not validated by this repository's own tests — they run against mocks of the peer, and the defects that have actually shipped were disagreements between real implementations.
- Releases (tags) are operator approval only.
