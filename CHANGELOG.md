# Changelog

## Unreleased

### Security
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
