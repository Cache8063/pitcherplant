# Changelog

## Unreleased

### Security
- **fail2ban log injection fixed.** The submitted username is now stripped of
  CR/LF and other control characters (`log_safe()`) before it is written to
  the plain-text fail2ban log. Previously a POST with a username such as
  `x\nHONEYPOT: 8.8.8.8 - attempt` forged a second log line that fail2ban
  parsed as a real attempt, letting an attacker ban any IP of their choosing
  (admin, DNS resolvers, Cloudflare ranges) — a remote denial-of-service. The
  full, unmodified username is still captured in the JSONL intel log.
- **X-Forwarded-For client-IP selection hardened.** When the request comes
  through a trusted proxy, the client IP is now taken as the right-most
  address in the `X-Forwarded-For` chain that is not itself a trusted proxy,
  instead of the fully attacker-controlled left-most entry. Combined with the
  validity guard below, this closes a second path to making fail2ban ban an
  arbitrary third party on non-Cloudflare reverse-proxy deployments. This
  strengthens the existing trusted-proxy gate (threat-model item #1).
- Resolved client IPs are now validated with `filter_var(..., FILTER_VALIDATE_IP)`;
  unparseable values fall back to the socket peer (`REMOTE_ADDR`), so state
  files, logs, and bans are only ever keyed off a syntactically valid address.
- Forwarded IP headers (`CF-Connecting-IP`, `X-Forwarded-For`) are now only
  trusted when `REMOTE_ADDR` is in `$trusted_proxies` (config-driven; ships
  with loopback + Cloudflare v4/v6 ranges). Previously, an attacker reaching
  origin directly could spoof the header and have fail2ban ban innocent IPs.
- Cookie test for the WordPress login bypass is now anchored to the
  cookie-name boundary in both nginx and apache (`(^|;\s*)wordpress_logged_in_[a-f0-9]+=`).
  The previous substring match allowed `Cookie: bypass=wordpress_logged_in_x`
  to walk past the trap.
- Dashboard fails closed when `$dashboard_token` is unset (was: open by
  default). Token comparison uses `hash_equals()` for constant-time match.

### Operational
- Submitted username, password, and `redirect_to` are capped at 256 bytes
  before logging (configurable via `$max_field_len`). Prevents megabyte-sized
  POSTs from bloating `intel.jsonl`.
- Per-IP state writes now use `LOCK_EX` (matching the fail2ban log path).
- Dashboard reads the last N lines via reverse-chunk fseek instead of loading
  the whole `intel.jsonl`. Default 5000, configurable via `$dashboard_max_entries`.
  Header shows "N / ~M" when truncated.
- `install.sh` deploys a logrotate config (daily, 14 keeps, compress) for the
  fail2ban-watched log, plus a `tmpfiles.d` rule that GCs per-IP state files
  older than 30 days.

### Container / CI
- Dockerfile pins `php:8.3-fpm-alpine` by digest for reproducible builds.
- New `/health` endpoint (plain text, no PHP, no access_log) plus
  `HEALTHCHECK` directive — healthchecks no longer get logged as attacks.
- `entrypoint.sh` runs php-fpm and nginx in parallel via `wait -n`; either
  crash brings the container down. SIGTERM is forwarded to both children.
- nginx hardened: `server_tokens off`, `client_max_body_size 64k`,
  `try_files` guard inside the PHP location.
- CI workflow: multi-arch build (`linux/amd64`, `linux/arm64`), GHA build
  cache, Trivy scan (HIGH/CRITICAL, fail-on-find) before push, SBOM and
  provenance attestations published with the image.

### Docs
- Minimum PHP bumped from 5.4 → 7.0 (code uses `??` and `hash_equals`).
- README documents trusted-proxies refresh source and the co-located FPM
  pool caveat.
- New `CLAUDE.md` with design intent, threat model, file map, and
  deployment matrix.
