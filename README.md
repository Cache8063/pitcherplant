# pitcherplant

A WordPress login honeypot and tarpit. Serves a pixel-perfect fake `/wp-login.php` page that logs attacker credentials, applies progressive delays, and feeds fail2ban for long-duration IP bans.

Your real login lives at a hidden URL (via [WPS Hide Login](https://wordpress.org/plugins/wps-hide-login/) or similar). Attackers hitting the default WordPress login paths get trapped.

![Dashboard](screenshots/dashboard.png)

## How it works

1. Web server rewrite rules (nginx or Apache) redirect unauthenticated requests to `/wp-login.php` and `/wp-admin` to `wp-trap.php`
2. The fake login page looks identical to a real WordPress login (same CSS, same error messages, same headers)
3. Each login attempt is logged to two files:
   - Simple log for fail2ban: `[timestamp] HONEYPOT: IP - attempt N - user=X`
   - Full JSONL intelligence: credentials, headers, user agent, Cloudflare country, timing
4. Progressive tarpit delays: 2s, 4s, 6s... up to 30s per attempt (configurable)
5. After 20 attempts (configurable), fail2ban bans the IP for 30 days via iptables

Logged-in administrators with valid WordPress cookies bypass the honeypot entirely.

## Quick start

```bash
# 1. Clone the repo
git clone <repo-url> pitcherplant && cd pitcherplant

# 2. Configure for your site
cp config.env.example config.env
# Edit config.env with your site name, URL, and target info

# 3. Deploy
./install.sh
```

## Docker

```bash
docker pull ghcr.io/cache8063/pitcherplant:latest
docker run -d -p 8080:80 ghcr.io/cache8063/pitcherplant:latest
```

Edit `wp-trap-config.php` inside the container to set your site name and URL. Logs are written to `/var/log/wp-honeypot-intel.jsonl` inside the container. The dashboard is available at `/dashboard/` — set `$dashboard_token` in `wp-trap-config.php` first; the dashboard fails closed when the token is empty.

The container exposes `/health` (200 OK, no PHP) for `docker`/`k8s` healthchecks. The entrypoint runs php-fpm and nginx in parallel and exits if either crashes.

## Install modes

```bash
# Local (running on the WordPress server itself)
./install.sh --local /var/www/html

# Remote via SSH
./install.sh --ssh root@webserver /var/www/html

# Proxmox LXC container
./install.sh --pct root@proxmox-node 550 /var/www/html

# Auto-detect from config.env
./install.sh
```

## Configuration

### Installer config (`config.env`)

Copy `config.env.example` to `config.env`:

| Variable | Default | Description |
|----------|---------|-------------|
| `SITE_NAME` | `My WordPress Site` | Shown on fake login page |
| `SITE_URL` | `https://example.com` | Used in fake WP headers |
| `LOG_FILE` | `/var/log/wp-honeypot.log` | fail2ban watches this |
| `INTEL_FILE` | `/var/log/wp-honeypot-intel.jsonl` | Full intelligence log |
| `STATE_DIR` | `/var/lib/wp-honeypot` | Per-IP state tracking |
| `MAX_DELAY` | `30` | Maximum tarpit delay (seconds) |
| `F2B_MAXRETRY` | `20` | Attempts before ban |
| `F2B_FINDTIME` | `86400` | Detection window (seconds) |
| `F2B_BANTIME` | `2592000` | Ban duration (30 days) |

### Runtime config (`wp-trap-config.php`)

These live in the deployed PHP config file. `install.sh` writes the first
group from `config.env`; edit the file in place to tune the rest.

| Variable | Default | Description |
|----------|---------|-------------|
| `$trusted_proxies` | loopback + CF v4/v6 | CIDRs whose `REMOTE_ADDR` can set forwarded IP headers. Anything outside the list falls back to `REMOTE_ADDR`. |
| `$max_field_len` | `256` | Bytes kept from submitted user/pass/redirect before logging. |
| `$dashboard_token` | `''` (closed) | Required token for `/dashboard/`. Empty value = dashboard returns 403. |
| `$dashboard_max_entries` | `5000` | Tail-window size for the dashboard. |

## Intelligence viewer

```bash
./tools/honeypot-intel.sh summary     # Overview: top usernames, passwords, IPs
./tools/honeypot-intel.sh live        # Real-time feed
./tools/honeypot-intel.sh creds       # All username:password pairs
./tools/honeypot-intel.sh passwords   # Password frequency ranking
./tools/honeypot-intel.sh usernames   # Username frequency ranking
./tools/honeypot-intel.sh countries   # Attacks by country (Cloudflare)
./tools/honeypot-intel.sh timeline    # Hourly attack histogram
./tools/honeypot-intel.sh ip 1.2.3.4  # Drill down on specific IP
./tools/honeypot-intel.sh banned      # Currently banned IPs
```

## What gets logged

Every POST (login attempt) records:

```json
{
  "timestamp": "2026-03-10T14:22:33+00:00",
  "ip": "203.0.113.45",
  "attempt": 5,
  "username": "admin",
  "password": "password123",
  "remember_me": false,
  "redirect_to": "/wp-admin/",
  "headers": {
    "user_agent": "Mozilla/5.0 ...",
    "cf_ipcountry": "CN",
    "cf_ray": "abc123"
  },
  "delay_applied": 10,
  "country": "CN"
}
```

GET requests (reconnaissance) are also logged with URI, headers, and country.

## Requirements

- PHP 7.0+ (uses `??` null-coalesce + `hash_equals`)
- nginx or Apache 2.4+ with `mod_rewrite`
- fail2ban
- iptables (for banning)
- Python 3 (for the intel viewer)
- Cloudflare (optional, for country-level geo data)

The Docker image uses nginx + php-fpm on Alpine for a minimal footprint (~60MB).

### Trusted proxies

`wp-trap.php` only honors `CF-Connecting-IP` / `X-Forwarded-For` when `REMOTE_ADDR` is in `$trusted_proxies`. The shipped config trusts loopback + the published Cloudflare ranges. If you front the trap with a different reverse proxy, add its CIDR; otherwise attackers can spoof the forwarded header and have fail2ban ban the wrong IP. Refresh the Cloudflare ranges from https://www.cloudflare.com/ips-v4 and https://www.cloudflare.com/ips-v6 when they change.

### Co-locating with WordPress (install.sh path)

`install.sh` drops the trap next to WordPress on the host's PHP-FPM pool. Under a parallel-burst attack the 30s tarpit `sleep()` can pin every worker and DoS the real site through the trap. If that's a concern, provision a dedicated FPM pool for the trap with its own `pm.max_children` so worker exhaustion stays local. The Docker path runs an isolated FPM pool by default and is unaffected.

## File layout

```
pitcherplant/
├── install.sh                       # Deployment script (local / SSH / pct)
├── config.env.example               # Installer config template
├── Dockerfile                       # php-fpm + nginx on Alpine (digest-pinned)
├── trap/
│   ├── wp-trap.php                  # Honeypot script (goes in WP root)
│   └── wp-trap-config.php           # Runtime config template (goes in WP root)
├── fail2ban/
│   ├── filter.d/wp-honeypot.conf
│   ├── jail.d/wp-honeypot.conf
│   ├── jail.local
│   ├── logrotate-wp-honeypot        # /etc/logrotate.d/wp-honeypot (daily, 14 keeps)
│   └── tmpfiles-wp-honeypot.conf    # /etc/tmpfiles.d/wp-honeypot.conf (state-file GC, 30d)
├── apache/
│   ├── honeypot-rewrite.conf        # .htaccess rewrites (cookie-anchored)
│   └── security-headers.conf        # Bonus security headers
├── docker/
│   ├── nginx.conf                   # nginx site config (cookie-anchored, /health)
│   └── entrypoint.sh                # php-fpm + nginx with wait -n
└── tools/
    ├── dashboard.php                # Web-based intel viewer (token-gated)
    └── honeypot-intel.sh            # CLI intel viewer
```

## Math

With default settings (maxretry=20, delay=2s per attempt increment):

- Attempts 1-20: 2+4+6+8+10+12+14+16+18+20+22+24+26+28+30+30+30+30+30+30 = **~7 minutes of tarpit**
- Then: **30-day iptables ban**

## License

MIT
