# SPL Bridge Operations Runbook

## Overview

`spl-bridge` is the public SNI-passthrough MCP relay. It listens on public port 443 (or configured `--client-listen`) and routes traffic:
1. **Journal MCP Connections**: SNI `*.solstone.me` (registered via PoP authentication) -> proxied with PROXY v1 header to registered journal tunnel.
2. **Control TLS Handshakes**: SNI `bridge.solstone.me` without ALPN `acme-tls/1` -> internal control listener for PoP registration and lease renewal.
3. **ACME TLS-ALPN-01 Challenges**: SNI `bridge.solstone.me` with ALPN `acme-tls/1` -> local loopback target (`--acme-tls-alpn-target 127.0.0.1:8443`).

## Certificate Management

The bridge uses WebPKI-validated certificates for `bridge.solstone.me`. Certificates are dynamically reloaded via `SIGHUP` without restarting the daemon or dropping active journal/client connections.

### Automated Renewal
1. `spl-bridge-renewal.timer` runs daily (`OnCalendar=daily`) with randomized delay jitter (`RandomizedDelaySec=1h`).
2. It triggers `spl-bridge-renewal.service`, executing `/usr/local/bin/spl-bridge-renew`.
3. The renew wrapper acquires a non-blocking lock (`flock`) to guarantee single-flight execution.
4. If a pending generation is present, it retries activation with `spl-bridge-activate --retry-pending`. Corrupted pending generations are quarantined; valid pending generations are promoted without contacting the CA.
5. If no retryable pending certificate remains, Lego runs `lego renew --days 30` with TLS challenge binding to loopback (`127.0.0.1:8443`).
6. Lego's renewal hook runs only when a certificate was actually renewed. A no-op daily check does not install files or signal the bridge.
7. Upon renewal, `spl-bridge-activate` stages a new generation, validates the certificate chain and private key, performs an atomic symlink swap of `active`, executes `systemctl reload spl-bridge`, and verifies the live TLS handshake. On failure, it rolls back `active` to the prior generation and saves `pending`.

## Existing Host Cutover

This procedure migrates an already-running bridge and its current certificate into the managed generation layout. It has one deliberate service restart. Later certificate changes use same-PID reload. A fresh host must first have a valid public certificate and a working bridge service; that bootstrap is outside this migration procedure.

1. Install the release-built binaries and executable helpers:

```bash
install -d -o root -g root -m 0755 /usr/local/libexec
install -o root -g root -m 0755 target/release/spl-bridge /usr/local/bin/spl-bridge
install -o root -g root -m 0755 target/release/spl-bridge-activate /usr/local/bin/spl-bridge-activate
install -o root -g root -m 0755 crates/spl-bridge/deploy/spl-bridge-renew /usr/local/bin/spl-bridge-renew
install -o root -g root -m 0755 crates/spl-bridge/deploy/spl-bridge-renew-hook /usr/local/libexec/spl-bridge-renew-hook
```

2. Bootstrap the atomic generation tree from the certificate the old service already presents. `true` is intentional: the old unit has no reload action yet, while the verification handshake proves the staged generation is byte-for-byte the live leaf.

```bash
install -d -o root -g spl-bridge -m 2750 /etc/spl-bridge/tls-generations
spl-bridge-activate \
    --issued-cert /etc/spl-bridge/tls/fullchain.pem \
    --issued-key /etc/spl-bridge/tls/privkey.pem \
    --generations-dir /etc/spl-bridge/tls-generations \
    --verify-addr 127.0.0.1:443 \
    --reload-cmd true
```

3. Create `/etc/spl-bridge/renewal.env` with mode `0640`, owner `root:spl-bridge`, containing the ACME account email as `EMAIL=...`. Install all three units, verify them, reload systemd, and make the one cutover:

```bash
install -o root -g root -m 0644 crates/spl-bridge/deploy/spl-bridge.service /etc/systemd/system/spl-bridge.service
install -o root -g root -m 0644 crates/spl-bridge/deploy/spl-bridge-renewal.service /etc/systemd/system/spl-bridge-renewal.service
install -o root -g root -m 0644 crates/spl-bridge/deploy/spl-bridge-renewal.timer /etc/systemd/system/spl-bridge-renewal.timer
systemd-analyze verify /etc/systemd/system/spl-bridge.service /etc/systemd/system/spl-bridge-renewal.service /etc/systemd/system/spl-bridge-renewal.timer
systemctl daemon-reload
systemctl restart spl-bridge
systemctl enable --now spl-bridge-renewal.timer
```

4. Record the running source identity, certificate expiry, PID, and timer:

```bash
/usr/local/bin/spl-bridge --version
systemctl show spl-bridge -p MainPID -p ActiveEnterTimestamp -p LimitNOFILE
openssl s_client -connect bridge.solstone.me:443 -servername bridge.solstone.me </dev/null
systemctl list-timers spl-bridge-renewal.timer
```

### Staging Directory Rehearsal

Do not test renewal against Let's Encrypt production endpoints. Production issuance is subject to strict Let's Encrypt rate limits and requires real domain validation; iterative proof should always be performed in a dedicated staging directory against the Let's Encrypt ACME staging environment (`https://acme-staging-v02.api.letsencrypt.org/directory`).

To rehearse activation or perform manual rotation in a staging directory:

```bash
STAGING_DIR="/var/tmp/spl-bridge-staging"
mkdir -p "${STAGING_DIR}/lego"

# 1. Rehearse ACME issuance against Let's Encrypt staging URL
lego \
    --email "ops@example.com" \
    --server "https://acme-staging-v02.api.letsencrypt.org/directory" \
    --domains "bridge.solstone.me" \
    --tls \
    --tls.port "127.0.0.1:8443" \
    --path "${STAGING_DIR}/lego" \
    run
```

Success proves that public port 443 routed the reserved-name `acme-tls/1` challenge to the loopback Lego listener without stopping the bridge. **Never pass the staging certificate to `spl-bridge-activate`: the production bridge correctly rejects the staging trust chain.** Remove the rehearsal directory afterward; it is not production state.

### Manual Activation and Retry

Manually activate only already-issued production material:

```bash
spl-bridge-activate \
    --issued-cert /etc/spl-bridge/acme-production/certificates/bridge.solstone.me.crt \
    --issued-key /etc/spl-bridge/acme-production/certificates/bridge.solstone.me.key \
    --generations-dir /etc/spl-bridge/tls-generations \
    --verify-addr 127.0.0.1:443 \
    --reload-cmd "systemctl reload spl-bridge"
```

If activation retained a retryable pending generation, run `systemctl start spl-bridge-renewal.service`; the wrapper retries that local generation before any CA-facing command.

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
