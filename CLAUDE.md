# pitcherplant — project notes for Claude

WordPress login honeypot + tarpit. Serves a pixel-perfect fake `/wp-login.php`,
captures attacker credentials, applies progressive delays, feeds fail2ban.

## Design intent — do not "fix" these

These are intentional camouflage, not bugs:

- **Plaintext password capture + display** — the whole product.
- **`X-Powered-By: PHP/...`, `Link: <site>/wp-json/>` headers, WP-style error
  messages** — must look identical to real WordPress.
- **`sleep($delay)` blocking PHP-FPM workers** — that's the tarpit. The
  Docker image runs an isolated FPM pool; co-located `install.sh`
  deployments need operator-sized worker counts.
- **Dashboard token in URL** — fine for the typical tailnet/internal use.

## File map

```
trap/wp-trap.php          — the honeypot itself (renders fake login, logs intel)
trap/wp-trap-config.php   — config template ($trusted_proxies, $max_field_len, …)
tools/dashboard.php       — read-only intel viewer; tail-bounded reader
tools/honeypot-intel.sh   — CLI viewer (uses python3 inline scripts)
docker/nginx.conf         — cookie-anchor rewrite + /health + try_files guard
docker/entrypoint.sh      — php-fpm + nginx with wait -n
apache/honeypot-rewrite.conf — same cookie rules for the install.sh path
fail2ban/                 — filter, jail, logrotate, tmpfiles.d
install.sh                — three deploy modes: --local, --ssh, --pct
.github/workflows/docker.yml — multi-arch + SBOM + Trivy + GHA cache
```

## Threat model crib

Three ways an attacker can turn the honeypot against innocents — all
currently mitigated, but any future change to IP handling, the fail2ban
log format, or cookie matching MUST preserve these guarantees:

1. **Spoofed `CF-Connecting-IP` / `X-Forwarded-For`** → fail2ban bans the
   wrong IP. Mitigations, all of which must stay in place:
   - `is_trusted_proxy()` gates forwarded headers on `REMOTE_ADDR` being in
     `$trusted_proxies`.
   - When trusted, the client IP is the **right-most** XFF entry that is not
     itself a trusted proxy (`rightmost_untrusted_ip()`) — never the
     attacker-controlled left-most one. `CF-Connecting-IP` is preferred since
     Cloudflare sets it to the single real client IP.
   - The final IP is validated with `FILTER_VALIDATE_IP`; garbage falls back
     to `REMOTE_ADDR`. State files, logs, and bans only ever key off a valid IP.
2. **fail2ban log injection** — the simple log is plain text and the filter
   matches `HONEYPOT: <HOST> - attempt` per line, so any attacker-controlled
   value written to it must be free of CR/LF. The username is the only such
   field and is passed through `log_safe()` (strips `\x00-\x1f\x7f`) before
   the `sprintf`. Do **not** add raw request data (URI, UA, headers) to the
   simple log without `log_safe()` — those belong in the JSONL intel log,
   where `json_encode()` escapes newlines.
3. **Cookie-substring bypass** — a non-WP cookie whose value contains
   `wordpress_logged_in_`. Mitigation: regex anchored to cookie-name
   boundary `(^|;\s*)wordpress_logged_in_[a-f0-9]+=` in both nginx and
   apache rewrites.

## Testing

If the dev box has no PHP, the e2e pattern is: ship the files to any host
with PHP 7+ installed (a throwaway container or LXC works), `php -l` for
syntax, then `php -S 127.0.0.1:<port> wp-trap.php` and curl-driven assertions
against the JSONL output. Always clean `/tmp/` afterwards.

Container build verification needs Docker, which isn't on the local box — CI
runs the multi-arch + Trivy build on push, so push to a branch first if you
want full validation.

## Useful skills for this project

- **`/security-review`** before any push that touches `trap/`, `docker/`,
  the dashboard, or `install.sh`. The threat model is small enough that a
  full review fits comfortably.
- **`/review`** for cross-cutting PRs.
- **`/simplify`** sparingly — most of this code is short and direct; resist
  the urge to abstract the per-IP state machinery or the dashboard
  rendering.

## Deployment

| Mode | Path | FPM pool | Logs |
|---|---|---|---|
| Docker | `ghcr.io/cache8063/pitcherplant:latest` | dedicated | inside container |
| `install.sh --local` | host WordPress root | **shared with WP** — size carefully | `/var/log/wp-honeypot*` |
| `install.sh --ssh` | remote WP server | shared | remote `/var/log/...` |
| `install.sh --pct` | Proxmox LXC | shared | inside LXC |

The shared-FPM-pool caveat is the load-bearing thing here: a parallel-burst
attack against the trap can starve the real site's workers. Either run
Docker, or provision a dedicated `pm.max_children` pool when co-locating.

## Remotes

Multi-remote setup. `git remote -v` for the current URLs; the GitHub mirror
is where CI runs (Trivy + multi-arch + SBOM). Push to every remote after
merges to main.
