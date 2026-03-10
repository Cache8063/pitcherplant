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
