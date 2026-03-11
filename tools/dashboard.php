<?php
/**
 * pitcherplant Intelligence Dashboard
 *
 * Standalone PHP page — deploy behind authentication or on an internal network.
 * Reads the JSONL intel log directly. No database required.
 *
 * Configuration: set $intel_file below or via wp-trap-config.php.
 */

// --- Configuration ---
// Load config.php (same directory), or fall back to trap config, or defaults.
$intel_file = '/var/log/wp-honeypot-intel.jsonl';
$site_name  = 'WordPress';
$dashboard_token = '';

$local_config = __DIR__ . '/config.php';
$trap_config  = __DIR__ . '/../trap/wp-trap-config.php';
if (file_exists($local_config)) {
    require $local_config;
} elseif (file_exists($trap_config)) {
    require $trap_config;
}

// --- Auth check ---
if ($dashboard_token !== '' && ($_GET['token'] ?? '') !== $dashboard_token) {
    http_response_code(403);
    echo 'Forbidden';
    exit;
}

// --- Parse log ---
$entries = [];
if (file_exists($intel_file)) {
    $lines = file($intel_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        $d = json_decode($line, true);
        if ($d) $entries[] = $d;
    }
}

// --- Compute stats ---
$total_attempts = 0;
$total_recon = 0;
$usernames = [];
$passwords = [];
$ips = [];
$countries = [];
$hours = [];
$creds = [];
$ip_details = [];
$last_event_time = '';
$attack_types = ['login' => 0, 'recon' => 0];

foreach ($entries as $e) {
    if (($e['type'] ?? '') === 'recon') {
        $total_recon++;
        $attack_types['recon']++;
    } else {
        $total_attempts += ($e['attempt'] ?? 0) > 0 ? 1 : 0;
        $attack_types['login']++;
    }

    $ip = $e['ip'] ?? '?';
    $country = $e['country'] ?? '??';
    $ips[$ip] = ($ips[$ip] ?? 0) + 1;
    if ($country && $country !== '??') {
        $countries[$country] = ($countries[$country] ?? 0) + 1;
    }

    $hour = substr($e['timestamp'] ?? '', 0, 13);
    if ($hour) $hours[$hour] = ($hours[$hour] ?? 0) + 1;

    if (!empty($e['username'])) {
        $usernames[$e['username']] = ($usernames[$e['username']] ?? 0) + 1;
    }
    if (!empty($e['password'])) {
        $passwords[$e['password']] = ($passwords[$e['password']] ?? 0) + 1;
    }
    if (!empty($e['username']) && !empty($e['password'])) {
        $creds[] = [
            'ts'   => substr($e['timestamp'] ?? '', 0, 19),
            'ip'   => $ip,
            'cc'   => $country,
            'user' => $e['username'],
            'pass' => $e['password'],
            'att'  => $e['attempt'] ?? 0,
            'delay'=> $e['delay_applied'] ?? 0,
        ];
    }

    if (!isset($ip_details[$ip])) {
        $ip_details[$ip] = ['country' => $country, 'attempts' => 0, 'first' => $e['timestamp'] ?? '', 'last' => ''];
    }
    $ip_details[$ip]['attempts']++;
    $ip_details[$ip]['last'] = $e['timestamp'] ?? '';
    $last_event_time = $e['timestamp'] ?? $last_event_time;
}

arsort($usernames);
arsort($passwords);
arsort($ips);
arsort($countries);
ksort($hours);

$unique_ips = count($ips);
$top_user = $usernames ? array_key_first($usernames) : '-';
$top_pass = $passwords ? array_key_first($passwords) : '-';

// Threat level
$threat_level = 'NOMINAL';
$threat_class = 'nominal';
if ($total_attempts > 100) { $threat_level = 'ELEVATED'; $threat_class = 'elevated'; }
if ($total_attempts > 500) { $threat_level = 'HIGH'; $threat_class = 'high'; }
if ($total_attempts > 2000) { $threat_level = 'CRITICAL'; $threat_class = 'critical'; }

// Time since last event
$last_ago = '-';
if ($last_event_time) {
    $diff = time() - strtotime($last_event_time);
    if ($diff < 60) $last_ago = $diff . 's ago';
    elseif ($diff < 3600) $last_ago = floor($diff/60) . 'm ago';
    elseif ($diff < 86400) $last_ago = floor($diff/3600) . 'h ago';
    else $last_ago = floor($diff/86400) . 'd ago';
}

// Active tab
$tab = $_GET['tab'] ?? 'overview';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>THREAT INTEL // <?php echo htmlspecialchars($site_name); ?></title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Inter:wght@300;400;500;600;700&display=swap');

:root {
    --bg: #05080f;
    --bg2: #0a0e18;
    --card: #0d1320;
    --card-hover: #111828;
    --border: #1a2540;
    --border-glow: #1e3a5f;
    --text: #c8d6e5;
    --dim: #4a5568;
    --bright: #e2e8f0;
    --cyan: #00e5ff;
    --cyan-dim: #0097a7;
    --red: #ff1744;
    --red-dim: #b71c1c;
    --green: #00e676;
    --green-dim: #1b5e20;
    --amber: #ffab00;
    --amber-dim: #ff6f00;
    --blue: #2979ff;
    --purple: #d500f9;
    --mono: 'JetBrains Mono', 'SF Mono', SFMono-Regular, ui-monospace, 'DejaVu Sans Mono', Menlo, Consolas, monospace;
    --sans: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
    font-family: var(--sans);
    background: var(--bg);
    color: var(--text);
    font-size: 13px;
    line-height: 1.5;
    min-height: 100vh;
}

/* Scanline overlay */
body::before {
    content: '';
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: repeating-linear-gradient(
        0deg,
        transparent,
        transparent 2px,
        rgba(0, 229, 255, 0.008) 2px,
        rgba(0, 229, 255, 0.008) 4px
    );
    pointer-events: none;
    z-index: 9999;
}

/* Grid background */
body::after {
    content: '';
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background-image:
        linear-gradient(rgba(0, 229, 255, 0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0, 229, 255, 0.03) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none;
    z-index: -1;
}

.wrap {
    max-width: 1400px;
    margin: 0 auto;
    padding: 16px 20px;
    position: relative;
}

/* ---- HEADER ---- */
.header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 20px;
    background: linear-gradient(135deg, var(--card) 0%, rgba(0, 229, 255, 0.05) 100%);
    border: 1px solid var(--border);
    border-left: 3px solid var(--cyan);
    border-radius: 4px;
    margin-bottom: 16px;
}

.header-left {
    display: flex;
    align-items: center;
    gap: 16px;
}

.header-icon {
    width: 36px;
    height: 36px;
    border: 2px solid var(--cyan);
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    position: relative;
    animation: pulse-ring 3s ease-in-out infinite;
}

.header-icon::before {
    content: '';
    width: 10px;
    height: 10px;
    background: var(--cyan);
    border-radius: 50%;
    box-shadow: 0 0 12px var(--cyan), 0 0 24px rgba(0, 229, 255, 0.3);
}

@keyframes pulse-ring {
    0%, 100% { border-color: var(--cyan); box-shadow: 0 0 8px rgba(0, 229, 255, 0.2); }
    50% { border-color: var(--cyan-dim); box-shadow: 0 0 4px rgba(0, 229, 255, 0.1); }
}

.header-title {
    font-family: var(--mono);
    font-size: 16px;
    font-weight: 700;
    color: var(--cyan);
    letter-spacing: 2px;
    text-transform: uppercase;
    text-shadow: 0 0 20px rgba(0, 229, 255, 0.3);
}

.header-subtitle {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--dim);
    letter-spacing: 1px;
}

.header-right {
    display: flex;
    align-items: center;
    gap: 20px;
    font-family: var(--mono);
    font-size: 11px;
}

.header-meta {
    text-align: right;
    color: var(--dim);
}

.header-meta .val {
    color: var(--text);
}

.threat-badge {
    padding: 4px 14px;
    border-radius: 3px;
    font-family: var(--mono);
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 2px;
    text-transform: uppercase;
    animation: threat-pulse 2s ease-in-out infinite;
}

.threat-badge.nominal {
    background: rgba(0, 230, 118, 0.1);
    border: 1px solid var(--green-dim);
    color: var(--green);
}

.threat-badge.elevated {
    background: rgba(255, 171, 0, 0.1);
    border: 1px solid var(--amber-dim);
    color: var(--amber);
}

.threat-badge.high {
    background: rgba(255, 23, 68, 0.1);
    border: 1px solid var(--red-dim);
    color: var(--red);
}

.threat-badge.critical {
    background: rgba(255, 23, 68, 0.15);
    border: 1px solid var(--red);
    color: var(--red);
    animation: threat-critical 1s ease-in-out infinite;
}

@keyframes threat-pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.7; }
}

@keyframes threat-critical {
    0%, 100% { opacity: 1; box-shadow: 0 0 12px rgba(255, 23, 68, 0.3); }
    50% { opacity: 0.8; box-shadow: 0 0 20px rgba(255, 23, 68, 0.5); }
}

/* ---- STAT CARDS ---- */
.stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 12px;
    margin-bottom: 16px;
}

.stat {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 16px 20px;
    position: relative;
    overflow: hidden;
    transition: all 0.2s;
}

.stat:hover {
    background: var(--card-hover);
    border-color: var(--border-glow);
}

.stat::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 2px;
}

.stat.red::before { background: linear-gradient(90deg, var(--red), transparent); }
.stat.amber::before { background: linear-gradient(90deg, var(--amber), transparent); }
.stat.cyan::before { background: linear-gradient(90deg, var(--cyan), transparent); }
.stat.green::before { background: linear-gradient(90deg, var(--green), transparent); }
.stat.purple::before { background: linear-gradient(90deg, var(--purple), transparent); }

.stat .label {
    font-family: var(--mono);
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    color: var(--dim);
    margin-bottom: 6px;
}

.stat .value {
    font-family: var(--mono);
    font-size: 32px;
    font-weight: 700;
    line-height: 1;
}

.stat.red .value { color: var(--red); text-shadow: 0 0 20px rgba(255, 23, 68, 0.3); }
.stat.amber .value { color: var(--amber); text-shadow: 0 0 20px rgba(255, 171, 0, 0.3); }
.stat.cyan .value { color: var(--cyan); text-shadow: 0 0 20px rgba(0, 229, 255, 0.3); }
.stat.green .value { color: var(--green); text-shadow: 0 0 20px rgba(0, 230, 118, 0.3); }
.stat.purple .value { color: var(--purple); text-shadow: 0 0 20px rgba(213, 0, 249, 0.3); }

.stat .meta {
    font-family: var(--mono);
    font-size: 10px;
    color: var(--dim);
    margin-top: 4px;
}

/* ---- NAVIGATION ---- */
nav {
    display: flex;
    gap: 2px;
    margin-bottom: 16px;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 4px;
    flex-wrap: wrap;
}

nav a {
    color: var(--dim);
    text-decoration: none;
    padding: 8px 16px;
    border-radius: 3px;
    font-family: var(--mono);
    font-size: 11px;
    font-weight: 500;
    letter-spacing: 0.5px;
    text-transform: uppercase;
    transition: all 0.15s;
    position: relative;
}

nav a:hover {
    color: var(--text);
    background: rgba(0, 229, 255, 0.05);
}

nav a.active {
    color: var(--cyan);
    background: rgba(0, 229, 255, 0.1);
    border: 1px solid rgba(0, 229, 255, 0.2);
    text-shadow: 0 0 10px rgba(0, 229, 255, 0.3);
}

/* ---- PANELS ---- */
.panel {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 4px;
    margin-bottom: 16px;
    overflow: hidden;
}

.panel-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 20px;
    border-bottom: 1px solid var(--border);
    background: rgba(0, 229, 255, 0.02);
}

.panel-title {
    font-family: var(--mono);
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    color: var(--cyan);
    display: flex;
    align-items: center;
    gap: 8px;
}

.panel-title::before {
    content: '';
    width: 6px;
    height: 6px;
    background: var(--cyan);
    border-radius: 50%;
    box-shadow: 0 0 6px var(--cyan);
    display: inline-block;
}

.panel-count {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--dim);
}

.panel-body {
    padding: 0;
}

/* ---- TABLES ---- */
table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
}

th {
    text-align: left;
    padding: 10px 16px;
    background: rgba(0, 0, 0, 0.3);
    color: var(--dim);
    font-family: var(--mono);
    font-weight: 600;
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 1px;
    border-bottom: 1px solid var(--border);
}

td {
    padding: 8px 16px;
    border-bottom: 1px solid rgba(26, 37, 64, 0.5);
    font-family: var(--mono);
    font-size: 12px;
}

tr:last-child td { border-bottom: none; }
tr:hover td { background: rgba(0, 229, 255, 0.02); }

/* Bar charts */
.bar-container {
    display: flex;
    align-items: center;
    gap: 8px;
}

.bar {
    height: 4px;
    border-radius: 2px;
    min-width: 2px;
    position: relative;
}

.bar.bar-red { background: linear-gradient(90deg, var(--red), var(--red-dim)); box-shadow: 0 0 8px rgba(255, 23, 68, 0.2); }
.bar.bar-amber { background: linear-gradient(90deg, var(--amber), var(--amber-dim)); box-shadow: 0 0 8px rgba(255, 171, 0, 0.2); }
.bar.bar-cyan { background: linear-gradient(90deg, var(--cyan), var(--cyan-dim)); box-shadow: 0 0 8px rgba(0, 229, 255, 0.2); }
.bar.bar-green { background: linear-gradient(90deg, var(--green), var(--green-dim)); box-shadow: 0 0 8px rgba(0, 230, 118, 0.2); }

/* Badges */
.badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 3px;
    font-family: var(--mono);
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.5px;
}

.badge-cc {
    background: rgba(41, 121, 255, 0.1);
    border: 1px solid rgba(41, 121, 255, 0.2);
    color: var(--blue);
}

.badge-ip {
    background: rgba(0, 229, 255, 0.05);
    color: var(--cyan);
}

/* Credential colors */
.cred-pass { color: var(--red); }
.cred-user { color: var(--amber); }

.scroll {
    max-height: 600px;
    overflow-y: auto;
}

.scroll::-webkit-scrollbar { width: 6px; }
.scroll::-webkit-scrollbar-track { background: var(--bg); }
.scroll::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
.scroll::-webkit-scrollbar-thumb:hover { background: var(--border-glow); }

.empty {
    color: var(--dim);
    text-align: center;
    padding: 60px 20px;
    font-family: var(--mono);
    font-size: 12px;
    letter-spacing: 1px;
}

.empty::before {
    content: '[ ]';
    display: block;
    font-size: 24px;
    margin-bottom: 12px;
    color: var(--border);
}

/* ---- OVERVIEW GRID ---- */
.overview-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
}

/* ---- LIVE FEED (recent creds on overview) ---- */
.feed-row {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 8px 16px;
    border-bottom: 1px solid rgba(26, 37, 64, 0.5);
    font-family: var(--mono);
    font-size: 11px;
    transition: background 0.1s;
}

.feed-row:hover { background: rgba(0, 229, 255, 0.02); }
.feed-row:last-child { border-bottom: none; }

.feed-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--red);
    box-shadow: 0 0 6px var(--red);
    flex-shrink: 0;
}

.feed-time { color: var(--dim); min-width: 60px; }
.feed-ip { color: var(--cyan); min-width: 120px; }
.feed-user { color: var(--amber); }
.feed-arrow { color: var(--dim); margin: 0 4px; }
.feed-pass { color: var(--red); }

/* ---- FOOTER ---- */
.footer {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 20px;
    margin-top: 8px;
    border-top: 1px solid var(--border);
    font-family: var(--mono);
    font-size: 10px;
    color: var(--dim);
    letter-spacing: 0.5px;
}

.footer-status {
    display: flex;
    align-items: center;
    gap: 6px;
}

.status-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--green);
    box-shadow: 0 0 6px var(--green);
    animation: status-blink 3s ease-in-out infinite;
}

@keyframes status-blink {
    0%, 90%, 100% { opacity: 1; }
    95% { opacity: 0.3; }
}

/* Delay indicator */
.delay-badge {
    font-family: var(--mono);
    font-size: 10px;
    padding: 1px 6px;
    border-radius: 2px;
}

.delay-low { background: rgba(0, 230, 118, 0.1); color: var(--green); }
.delay-med { background: rgba(255, 171, 0, 0.1); color: var(--amber); }
.delay-high { background: rgba(255, 23, 68, 0.1); color: var(--red); }

/* Attempt count badge */
.att-badge {
    font-family: var(--mono);
    font-size: 10px;
    padding: 1px 6px;
    border-radius: 2px;
    background: rgba(213, 0, 249, 0.1);
    color: var(--purple);
}

/* Responsive */
@media (max-width: 900px) {
    .overview-grid { grid-template-columns: 1fr; }
    .header { flex-direction: column; gap: 12px; align-items: flex-start; }
    .header-right { width: 100%; justify-content: space-between; }
}

@media (max-width: 640px) {
    .wrap { padding: 8px; }
    .stats { grid-template-columns: 1fr 1fr; }
    nav { flex-wrap: wrap; }
    nav a { padding: 6px 10px; font-size: 10px; }
}
</style>
</head>
<body>
<div class="wrap">

<!-- HEADER -->
<div class="header">
    <div class="header-left">
        <div class="header-icon"></div>
        <div>
            <div class="header-title">Threat Intelligence</div>
            <div class="header-subtitle"><?php echo htmlspecialchars($site_name); ?> // HONEYPOT COMMAND</div>
        </div>
    </div>
    <div class="header-right">
        <div class="header-meta">
            <div>ENTRIES <span class="val"><?php echo number_format(count($entries)); ?></span></div>
            <div>LAST EVENT <span class="val"><?php echo $last_ago; ?></span></div>
        </div>
        <div class="threat-badge <?php echo $threat_class; ?>">
            <?php echo $threat_level; ?>
        </div>
    </div>
</div>

<!-- STATS -->
<div class="stats">
    <div class="stat red">
        <div class="label">Login Attempts</div>
        <div class="value"><?php echo number_format($total_attempts); ?></div>
        <div class="meta"><?php echo $top_user !== '-' ? 'Top: ' . htmlspecialchars(substr($top_user, 0, 16)) : 'No data'; ?></div>
    </div>
    <div class="stat amber">
        <div class="label">Recon Probes</div>
        <div class="value"><?php echo number_format($total_recon); ?></div>
        <div class="meta">Scan / enumeration</div>
    </div>
    <div class="stat cyan">
        <div class="label">Unique Sources</div>
        <div class="value"><?php echo number_format($unique_ips); ?></div>
        <div class="meta">Distinct IP addresses</div>
    </div>
    <div class="stat green">
        <div class="label">Countries</div>
        <div class="value"><?php echo number_format(count($countries)); ?></div>
        <div class="meta">Geographic origins</div>
    </div>
    <div class="stat purple">
        <div class="label">Credentials</div>
        <div class="value"><?php echo number_format(count($creds)); ?></div>
        <div class="meta">Unique pairs captured</div>
    </div>
</div>

<!-- NAV -->
<?php
$token_param = $dashboard_token !== '' ? '&token=' . urlencode($_GET['token'] ?? '') : '';
$tabs = [
    'overview'   => 'Overview',
    'creds'      => 'Credentials',
    'passwords'  => 'Passwords',
    'usernames'  => 'Usernames',
    'ips'        => 'Sources',
    'countries'  => 'GeoINT',
    'timeline'   => 'Timeline',
];
?>
<nav>
<?php foreach ($tabs as $k => $v): ?>
<a href="?tab=<?php echo $k . $token_param; ?>" class="<?php echo $tab === $k ? 'active' : ''; ?>"><?php echo $v; ?></a>
<?php endforeach; ?>
</nav>

<!-- CONTENT -->

<?php if ($tab === 'overview'): ?>

<div class="overview-grid">

<!-- Top Usernames -->
<div class="panel">
    <div class="panel-header">
        <div class="panel-title">Target Usernames</div>
        <div class="panel-count"><?php echo count($usernames); ?> unique</div>
    </div>
    <div class="panel-body">
<?php if ($usernames): ?>
<table>
<tr><th>Username</th><th>Hits</th><th>Distribution</th></tr>
<?php $max = max($usernames); foreach (array_slice($usernames, 0, 10, true) as $u => $c): ?>
<tr>
    <td class="cred-user"><?php echo htmlspecialchars($u); ?></td>
    <td><?php echo $c; ?></td>
    <td><div class="bar-container"><div class="bar bar-amber" style="width:<?php echo round($c/$max*160); ?>px"></div></div></td>
</tr>
<?php endforeach; ?>
</table>
<?php else: ?><div class="empty">Awaiting threat data</div><?php endif; ?>
    </div>
</div>

<!-- Top Passwords -->
<div class="panel">
    <div class="panel-header">
        <div class="panel-title">Captured Passwords</div>
        <div class="panel-count"><?php echo count($passwords); ?> unique</div>
    </div>
    <div class="panel-body">
<?php if ($passwords): ?>
<table>
<tr><th>Password</th><th>Hits</th><th>Distribution</th></tr>
<?php $max = max($passwords); foreach (array_slice($passwords, 0, 10, true) as $p => $c): ?>
<tr>
    <td class="cred-pass"><?php echo htmlspecialchars($p); ?></td>
    <td><?php echo $c; ?></td>
    <td><div class="bar-container"><div class="bar bar-red" style="width:<?php echo round($c/$max*160); ?>px"></div></div></td>
</tr>
<?php endforeach; ?>
</table>
<?php else: ?><div class="empty">Awaiting threat data</div><?php endif; ?>
    </div>
</div>

</div>

<!-- Recent Activity Feed -->
<div class="panel">
    <div class="panel-header">
        <div class="panel-title">Recent Activity</div>
        <div class="panel-count">Last <?php echo min(15, count($creds)); ?> credential captures</div>
    </div>
    <div class="panel-body">
<?php if ($creds):
$recent = array_slice(array_reverse($creds), 0, 15);
foreach ($recent as $c): ?>
<div class="feed-row">
    <div class="feed-dot"></div>
    <div class="feed-time"><?php echo htmlspecialchars(substr($c['ts'], 11, 8)); ?></div>
    <div class="feed-ip"><?php echo htmlspecialchars($c['ip']); ?></div>
    <span class="badge badge-cc"><?php echo htmlspecialchars($c['cc']); ?></span>
    <div class="feed-user"><?php echo htmlspecialchars($c['user']); ?></div>
    <div class="feed-arrow">&rarr;</div>
    <div class="feed-pass"><?php echo htmlspecialchars($c['pass']); ?></div>
    <div style="margin-left:auto;">
        <span class="att-badge">#<?php echo $c['att']; ?></span>
        <span class="delay-badge <?php echo $c['delay'] >= 20 ? 'delay-high' : ($c['delay'] >= 10 ? 'delay-med' : 'delay-low'); ?>">+<?php echo $c['delay']; ?>s</span>
    </div>
</div>
<?php endforeach;
else: ?><div class="empty">Awaiting threat data</div><?php endif; ?>
    </div>
</div>

<?php elseif ($tab === 'creds'): ?>

<div class="panel">
    <div class="panel-header">
        <div class="panel-title">Credential Intercepts</div>
        <div class="panel-count"><?php echo count($creds); ?> pairs captured</div>
    </div>
    <div class="panel-body">
    <div class="scroll">
<?php if ($creds): ?>
<table>
<tr><th>Timestamp</th><th>Source IP</th><th>Origin</th><th>Username</th><th>Password</th><th>Attempt</th><th>Tarpit</th></tr>
<?php foreach (array_reverse($creds) as $c): ?>
<tr>
    <td><?php echo htmlspecialchars($c['ts']); ?></td>
    <td class="badge-ip"><?php echo htmlspecialchars($c['ip']); ?></td>
    <td><span class="badge badge-cc"><?php echo htmlspecialchars($c['cc']); ?></span></td>
    <td class="cred-user"><?php echo htmlspecialchars($c['user']); ?></td>
    <td class="cred-pass"><?php echo htmlspecialchars($c['pass']); ?></td>
    <td><span class="att-badge">#<?php echo $c['att']; ?></span></td>
    <td><span class="delay-badge <?php echo $c['delay'] >= 20 ? 'delay-high' : ($c['delay'] >= 10 ? 'delay-med' : 'delay-low'); ?>">+<?php echo $c['delay']; ?>s</span></td>
</tr>
<?php endforeach; ?>
</table>
<?php else: ?><div class="empty">No credentials intercepted</div><?php endif; ?>
    </div>
    </div>
</div>

<?php elseif ($tab === 'passwords'): ?>

<div class="panel">
    <div class="panel-header">
        <div class="panel-title">Password Intelligence</div>
        <div class="panel-count"><?php echo count($passwords); ?> unique passwords</div>
    </div>
    <div class="panel-body">
    <div class="scroll">
<?php if ($passwords): ?>
<table>
<tr><th>Password</th><th>Frequency</th><th>Distribution</th></tr>
<?php $max = max($passwords); foreach ($passwords as $p => $c): ?>
<tr>
    <td class="cred-pass"><?php echo htmlspecialchars($p); ?></td>
    <td><?php echo $c; ?></td>
    <td><div class="bar-container"><div class="bar bar-red" style="width:<?php echo round($c/$max*250); ?>px"></div></div></td>
</tr>
<?php endforeach; ?>
</table>
<?php else: ?><div class="empty">No passwords captured</div><?php endif; ?>
    </div>
    </div>
</div>

<?php elseif ($tab === 'usernames'): ?>

<div class="panel">
    <div class="panel-header">
        <div class="panel-title">Username Enumeration</div>
        <div class="panel-count"><?php echo count($usernames); ?> unique usernames</div>
    </div>
    <div class="panel-body">
    <div class="scroll">
<?php if ($usernames): ?>
<table>
<tr><th>Username</th><th>Frequency</th><th>Distribution</th></tr>
<?php $max = max($usernames); foreach ($usernames as $u => $c): ?>
<tr>
    <td class="cred-user"><?php echo htmlspecialchars($u); ?></td>
    <td><?php echo $c; ?></td>
    <td><div class="bar-container"><div class="bar bar-amber" style="width:<?php echo round($c/$max*250); ?>px"></div></div></td>
</tr>
<?php endforeach; ?>
</table>
<?php else: ?><div class="empty">No usernames captured</div><?php endif; ?>
    </div>
    </div>
</div>

<?php elseif ($tab === 'ips'): ?>

<div class="panel">
    <div class="panel-header">
        <div class="panel-title">Threat Sources</div>
        <div class="panel-count"><?php echo $unique_ips; ?> unique IPs</div>
    </div>
    <div class="panel-body">
    <div class="scroll">
<?php if ($ips): ?>
<table>
<tr><th>Source IP</th><th>Origin</th><th>Hits</th><th>First Contact</th><th>Last Contact</th><th>Activity</th></tr>
<?php $max = max($ips); foreach ($ips as $ip => $c):
$d = $ip_details[$ip] ?? []; ?>
<tr>
    <td class="badge-ip"><?php echo htmlspecialchars($ip); ?></td>
    <td><span class="badge badge-cc"><?php echo htmlspecialchars($d['country'] ?? '??'); ?></span></td>
    <td><?php echo $c; ?></td>
    <td><?php echo htmlspecialchars(substr($d['first'] ?? '', 0, 16)); ?></td>
    <td><?php echo htmlspecialchars(substr($d['last'] ?? '', 0, 16)); ?></td>
    <td><div class="bar-container"><div class="bar bar-cyan" style="width:<?php echo round($c/$max*150); ?>px"></div></div></td>
</tr>
<?php endforeach; ?>
</table>
<?php else: ?><div class="empty">No threat sources identified</div><?php endif; ?>
    </div>
    </div>
</div>

<?php elseif ($tab === 'countries'): ?>

<div class="panel">
    <div class="panel-header">
        <div class="panel-title">Geographic Intelligence</div>
        <div class="panel-count"><?php echo count($countries); ?> countries identified</div>
    </div>
    <div class="panel-body">
<?php if ($countries): ?>
<table>
<tr><th>Country Code</th><th>Events</th><th>Distribution</th></tr>
<?php $max = max($countries); foreach ($countries as $cc => $c): ?>
<tr>
    <td><span class="badge badge-cc"><?php echo htmlspecialchars($cc); ?></span></td>
    <td><?php echo $c; ?></td>
    <td><div class="bar-container"><div class="bar bar-green" style="width:<?php echo round($c/$max*250); ?>px"></div></div></td>
</tr>
<?php endforeach; ?>
</table>
<?php else: ?><div class="empty">No geographic data // requires Cloudflare headers</div><?php endif; ?>
    </div>
</div>

<?php elseif ($tab === 'timeline'): ?>

<div class="panel">
    <div class="panel-header">
        <div class="panel-title">Attack Timeline</div>
        <div class="panel-count">Hourly event distribution</div>
    </div>
    <div class="panel-body">
    <div class="scroll">
<?php if ($hours): ?>
<table>
<tr><th>Hour (UTC)</th><th>Events</th><th>Activity</th></tr>
<?php $max = max($hours); foreach ($hours as $h => $c): ?>
<tr>
    <td><?php echo htmlspecialchars($h); ?></td>
    <td><?php echo $c; ?></td>
    <td><div class="bar-container"><div class="bar bar-cyan" style="width:<?php echo round($c/$max*350); ?>px"></div></div></td>
</tr>
<?php endforeach; ?>
</table>
<?php else: ?><div class="empty">No temporal data collected</div><?php endif; ?>
    </div>
    </div>
</div>

<?php endif; ?>

<!-- FOOTER -->
<div class="footer">
    <div class="footer-status">
        <div class="status-dot"></div>
        TRAP ACTIVE // MONITORING
    </div>
    <div>
        pitcherplant // <?php echo date('Y-m-d H:i:s T'); ?>
    </div>
</div>

</div>
</body>
</html>
