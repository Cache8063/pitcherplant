<?php
/**
 * wp-honeypot configuration
 *
 * Copy this file to your WordPress root alongside wp-trap.php
 * and edit the values for your site.
 */

$site_name  = 'My WordPress Site';
$site_url   = 'https://example.com';
$log_file   = '/var/log/wp-honeypot.log';
$intel_file = '/var/log/wp-honeypot-intel.jsonl';
$state_dir  = '/var/lib/wp-honeypot';
$max_delay  = 30;

// Max bytes kept from submitted username / password / redirect_to before
// they hit the intel log. Attackers can POST megabytes; cap to keep the
// JSONL useful and the disk happy.
$max_field_len = 256;

// CIDRs whose REMOTE_ADDR is allowed to set X-Forwarded-For / CF-Connecting-IP.
// Requests from anywhere else fall back to REMOTE_ADDR so attackers can't
// spoof a forwarded header and have fail2ban ban the wrong IP.
//
// Refresh Cloudflare ranges from:
//   https://www.cloudflare.com/ips-v4
//   https://www.cloudflare.com/ips-v6
$trusted_proxies = [
    '127.0.0.1/32',
    '::1/128',
    // Cloudflare IPv4
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
    '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
    // Cloudflare IPv6
    '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
    '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
];

// Dashboard tail-read window. The dashboard streams the last N intel
// entries instead of loading the whole JSONL, so the page stays usable
// as the log grows.
$dashboard_max_entries = 5000;
