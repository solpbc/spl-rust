# spl-rust — SPL client library for Rust consumers
#
# The five-target contract: install, test, ci, format, clean.
# ci is the pre-commit gate and must be green before any commit.

CARGO ?= cargo

.PHONY: install test ci fmt-check clippy deny targets size format clean

install:
	@$(CARGO) fetch

test:
	@$(CARGO) test --workspace --all-targets

# The full gate. Every step is fail-closed; none may be skipped to get green.
ci: fmt-check clippy test deny targets

fmt-check:
	@$(CARGO) fmt --all --check

clippy:
	@$(CARGO) clippy --workspace --all-targets -- -D warnings

deny:
	@$(CARGO) deny --all-features check licenses bans sources

# spl-core's purity is a mechanically enforced invariant, not a claim: it has no
# C build scripts and no platform dependency, so it must type-check for every
# consumer target from any host with only `rustup target add` — no cross C
# toolchain, no Apple SDK. Adding a C-dependent or platform-bound crate to
# spl-core turns this red, which is exactly the intent.
#
# spl-transport is checked on the host only. It pulls `ring`, whose C build
# script needs a real cross toolchain, and aarch64-apple-darwin cannot be built
# from a non-Apple host at all. Cross-target *compilation* proof for the
# transport tier belongs to each consumer's own release rail, which has the right
# hosts; `cargo deny`'s [graph] targets already proves the dependency graph
# resolves for all four here.
CONSUMER_TARGETS = x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu aarch64-apple-darwin x86_64-pc-windows-msvc

targets:
	@for t in $(CONSUMER_TARGETS); do \
		echo "== spl-core --target $$t"; \
		$(CARGO) check -p spl-core --target $$t || exit 1; \
	done
	@echo "== spl-transport (host)"
	@$(CARGO) check -p spl-transport

# Records the transport tier's contribution to a consumer's binary. Evidence for
# the release record, NOT a pass/fail threshold: its job is to make a future
# silent dependency bump visible, which a recorded baseline does on its own.
size:
	@$(CARGO) build --release --workspace
	@ls -l target/release/libspl_core.rlib target/release/libspl_transport.rlib 2>/dev/null || true

format:
	@$(CARGO) fmt --all

clean:
	@$(CARGO) clean
