# SPL Bridge Operations Runbook

## Overview

`spl-bridge` is the public SNI-passthrough MCP relay. It listens on public port 443 (or configured `--client-listen`) and routes traffic:
1. **Journal MCP Connections**: SNI `*.solstone.me` (registered via PoP authentication) -> proxied with PROXY v1 header to registered journal tunnel.
2. **Control TLS Handshakes**: SNI `bridge.solstone.me` without ALPN `acme-tls/1` -> internal control listener for PoP registration and lease renewal.
3. **ACME TLS-ALPN-01 Challenges**: SNI `bridge.solstone.me` with ALPN `acme-tls/1` -> local loopback target (`--acme-tls-alpn-target`, e.g., `127.0.0.1:5001`).

## Certificate Management

The bridge uses WebPKI-validated certificates for `bridge.solstone.me`. Certificates are dynamically reloaded via `SIGHUP` without restarting the daemon or dropping active journal/client connections.

### Automated Renewal
1. `spl-bridge-renewal.timer` runs daily (`OnCalendar=daily`) with randomized delay jitter (`RandomizedDelaySec=1h`).
2. It triggers `spl-bridge-renewal.service`, executing `/usr/local/bin/spl-bridge-renew`.
3. The renew wrapper acquires a non-blocking lock (`flock`) to guarantee single-flight execution.
4. If a pending generation is present, it retries activation with `spl-bridge-activate --retry-pending`. Corrupted pending generations are quarantined; valid pending generations are promoted.
5. If no pending certificate is present (or after quarantine), Lego runs `lego renew --days 30` with TLS challenge binding to loopback (`127.0.0.1:5001`).
6. Upon issuance, `spl-bridge-activate` stages a new generation, validates the certificate chain and private key, performs an atomic symlink swap of `active`, executes the reload command (`systemctl reload spl-bridge`), and verifies the live TLS handshake. On failure, it rolls back `active` to the prior generation and saves `pending`.

### Staging Directory Rehearsal and Manual Rotation

Do not test renewal against Let's Encrypt production endpoints. Production issuance is subject to strict Let's Encrypt rate limits and requires real domain validation; iterative proof should always be performed in a dedicated staging directory against the Let's Encrypt ACME staging environment (`https://acme-staging-v02.api.letsencrypt.org/directory`).

To rehearse activation or perform manual rotation in a staging directory:

```bash
STAGING_DIR="/var/tmp/spl-bridge-staging"
mkdir -p "${STAGING_DIR}/generations" "${STAGING_DIR}/lego"

# 1. Rehearse ACME issuance against Let's Encrypt staging URL
lego \
    --email "ops@example.com" \
    --server "https://acme-staging-v02.api.letsencrypt.org/directory" \
    --domains "bridge.solstone.me" \
    --tls \
    --tls.port "127.0.0.1:5001" \
    --path "${STAGING_DIR}/lego" \
    run

# 2. Stage and activate certificate generation
spl-bridge-activate \
    --issued-cert "${STAGING_DIR}/lego/certificates/bridge.solstone.me.crt" \
    --issued-key "${STAGING_DIR}/lego/certificates/bridge.solstone.me.key" \
    --generations-dir "${STAGING_DIR}/generations" \
    --verify-addr "127.0.0.1:443" \
    --reload-cmd "systemctl reload spl-bridge"

# 3. If a retry is needed for a pending generation:
spl-bridge-activate \
    --generations-dir "${STAGING_DIR}/generations" \
    --verify-addr "127.0.0.1:443" \
    --reload-cmd "systemctl reload spl-bridge" \
    --retry-pending
```

## Shutdown and Drain Lifecycle

When `SIGTERM` or `SIGINT` is received:
1. The bridge emits `bridge shutdown signal received; starting drain`.
2. Both client and control listeners immediately stop accepting new connections.
3. All registered journals are gracefully retired and dialer shutdown is initiated.
4. Active connection splices have up to 30 seconds (`DRAIN_BUDGET`) to complete.
5. If connections remain after 30 seconds, `bridge drain timed out; aborting active connections` is emitted and remaining tasks are aborted.

## Troubleshooting

All bridge events are emitted as fixed string literals to stderr:
- `control certificate startup validation failed`: The initial certificate at `--control-tls-cert` failed WebPKI validation, hostname SAN check, or key matching.
- `control certificate reload failed; keeping prior certificate`: A reloaded certificate on SIGHUP failed validation; the existing live certificate remains active without disruption.
- `acme target address rejected: must be loopback`: `--acme-tls-alpn-target` was configured with a non-loopback IP address.
- `client rejected: admission capacity exceeded`: More than 256 concurrent client handshakes are in flight before SNI classification.
- `client rejected: invalid client hello`: Client hello was malformed, truncated, timed out, or contained duplicate SNI/ALPN extensions.
