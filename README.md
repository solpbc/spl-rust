# spl-rust

The SPL (**solstone private link**) library for Rust consumers. Three crates: **`spl-core`** (pure wire), **`spl-transport`** (client sockets and TLS), and **`spl-home`** (listener-side mux).

SPL is the encrypted connection between a [solstone](https://solstone.app) client and the owner's journal: mutual TLS with a pairing-minted client certificate, carried over a direct LAN connection or a WebSocket relay when no direct path exists. Neither the relay operator nor sol pbc holds a key that can decrypt what flows inside — the relay authenticates the rendezvous, never the payload.

The wire protocol is specified in the [`proto/` directory of solpbc/spl](https://github.com/solpbc/spl/tree/main/proto). Those documents, and the conformance-vector corpus generated from them, are the source of truth for every wire behavior in this package.

## Why this exists

SPL clients were implemented independently in six languages. When one address-admission policy needed correcting, the fix had to land in six repositories — and a survey found six *different* behaviors for that one policy. This package is the Rust half of the answer: one implementation per language, consumed at an exact version pin, conforming to a machine-checkable corpus rather than to prose.

[`spl-swift`](https://github.com/solpbc/spl-swift) is the Apple-platform sibling.

## Status

Alpha, pre-1.0. The API will change. Consumers pin an exact tag.

## Crates

| Crate | What it owns |
|---|---|
| **`spl-core`** | Pair-link parsing and direct-address admission, mux framing and per-stream flow control, HTTP-over-SPL, CA-fingerprint pinning, pair-window and journal-identity derivations. No I/O, no platform dependency, host-testable. |
| **`spl-transport`** | CA-fp-pinned mutual TLS over direct and relay dials, including the home-side relay attachment client, mux carrier, and local loopback proxy. Built on `rustls`, so it is cross-platform and host-testable. |
| **`spl-home`** | Listener-side SPL mux acceptance and server-side mutual TLS. Inbound stream data is bounded by 1 MiB per live stream, plus the decoder ceiling and 1 MiB of outbound staging per live stream; it owns no HTTP parsing or authorization policy. |
| **`spl-bridge`** | Public SNI-passthrough MCP relay for the journal-MCP endpoint, routing opaque client TLS bytes to a registered journal. |

Application layers stay with the consuming product: observer registration and segment ingest, linked-system credential provisioning, credential storage, and service lifecycles are **not** in this package.

## Requirements

- Rust 1.95+ (the floor is the lowest consuming product's toolchain)
- No system TLS library — `rustls` with the `ring` provider, no C toolchain in the graph

## Build and test

```sh
make install   # fetch dependencies
make test      # unit tests
make ci        # fmt + clippy + tests + license/dependency policy + every consumer target
```

`make ci` is the gate; it must be green before any commit. It type-checks every target a consuming product ships on, so a target break surfaces here rather than at adoption.

## Trust model

Trust is **CA-fingerprint pinning**, not a system trust store. A presented certificate chain is accepted only when some certificate in it matches the pinned prefix carried by the pair-link, *and* the TLS handshake signature verifies against the leaf the peer actually presented. Both together are what defeats a relay that echoes a genuine chain while terminating TLS with its own key. Hostname is deliberately not validated — clients dial raw addresses from a pair-link and pin the CA instead.

## Privacy

No telemetry, no analytics, no crash reporting, no phone-home of any kind — in this package or in anything it pulls in. Secrets never reach a log line at any level: no token, key, certificate, nonce, pair-link fragment, or payload bytes.

## License

[AGPL-3.0-only](LICENSE).
