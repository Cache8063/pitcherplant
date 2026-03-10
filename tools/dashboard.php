<?php
/**
 * wp-honeypot Intelligence Dashboard
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

foreach ($entries as $e) {
    if (($e['type'] ?? '') === 'recon') {
        $total_recon++;
    } else {
        $total_attempts += ($e['attempt'] ?? 0) > 0 ? 1 : 0;
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
}

arsort($usernames);
arsort($passwords);
arsort($ips);
arsort($countries);
ksort($hours);

$unique_ips = count($ips);
$top_user = $usernames ? array_key_first($usernames) : '-';
$top_pass = $passwords ? array_key_first($passwords) : '-';

// Active tab
$tab = $_GET['tab'] ?? 'overview';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Honeypot Intel — <?php echo htmlspecialchars($site_name); ?></title>
<style>
:root{--bg:#0f1117;--card:#1a1d27;--border:#2a2d3a;--text:#c9cdd6;--dim:#6b7280;--accent:#3b82f6;--red:#ef4444;--green:#22c55e;--orange:#f59e0b;--mono:'SF Mono',SFMono-Regular,ui-monospace,'DejaVu Sans Mono',Menlo,Consolas,monospace}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);font-size:14px;line-height:1.5}
.wrap{max-width:1200px;margin:0 auto;padding:20px}
h1{font-size:20px;font-weight:600;margin-bottom:4px}
.subtitle{color:var(--dim);font-size:13px;margin-bottom:24px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:24px}
.stat{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:16px}
.stat .value{font-size:28px;font-weight:700;font-family:var(--mono)}
.stat .label{color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:.5px;margin-top:2px}
.stat.red .value{color:var(--red)}
.stat.green .value{color:var(--green)}
.stat.blue .value{color:var(--accent)}
.stat.orange .value{color:var(--orange)}
nav{display:flex;gap:4px;margin-bottom:20px;border-bottom:1px solid var(--border);padding-bottom:8px;flex-wrap:wrap}
nav a{color:var(--dim);text-decoration:none;padding:6px 14px;border-radius:6px;font-size:13px;font-weight:500;transition:all .15s}
nav a:hover{color:var(--text);background:var(--card)}
nav a.active{color:#fff;background:var(--accent)}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--border);border-radius:8px;overflow:hidden;font-size:13px}
th{text-align:left;padding:10px 14px;background:#151722;color:var(--dim);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--border)}
td{padding:8px 14px;border-bottom:1px solid var(--border);font-family:var(--mono);font-size:12px}
tr:last-child td{border-bottom:none}
tr:hover td{background:#1e2130}
.bar-container{display:flex;align-items:center;gap:8px}
.bar{height:16px;background:var(--accent);border-radius:3px;min-width:2px;opacity:.7}
.bar-label{color:var(--dim);font-size:11px;white-space:nowrap}
.badge{display:inline-block;padding:1px 6px;border-radius:4px;font-size:11px;font-weight:600}
.badge-cc{background:#1e293b;color:#93c5fd}
.section{margin-bottom:24px}
.section h2{font-size:15px;font-weight:600;margin-bottom:10px;color:var(--dim)}
.empty{color:var(--dim);text-align:center;padding:40px;font-style:italic}
.cred-pass{color:var(--red)}
.cred-user{color:var(--orange)}
.scroll{max-height:500px;overflow-y:auto;border-radius:8px}
@media(max-width:640px){.wrap{padding:12px}.stats{grid-template-columns:1fr 1fr}}
</style>
</head>
<body>
<div class="wrap">

<h1>Honeypot Intelligence</h1>
<p class="subtitle"><?php echo htmlspecialchars($site_name); ?> — <?php echo count($entries); ?> log entries</p>

<div class="stats">
    <div class="stat red"><div class="value"><?php echo $total_attempts; ?></div><div class="label">Login Attempts</div></div>
    <div class="stat orange"><div class="value"><?php echo $total_recon; ?></div><div class="label">Recon Visits</div></div>
    <div class="stat blue"><div class="value"><?php echo $unique_ips; ?></div><div class="label">Unique IPs</div></div>
    <div class="stat green"><div class="value"><?php echo count($countries); ?></div><div class="label">Countries</div></div>
</div>

<?php
$token_param = $dashboard_token !== '' ? '&token=' . urlencode($_GET['token'] ?? '') : '';
$tabs = ['overview'=>'Overview','creds'=>'Credentials','passwords'=>'Passwords','usernames'=>'Usernames','ips'=>'IPs','countries'=>'Countries','timeline'=>'Timeline'];
?>
<nav>
<?php foreach ($tabs as $k => $v): ?>
<a href="?tab=<?php echo $k . $token_param; ?>" class="<?php echo $tab === $k ? 'active' : ''; ?>"><?php echo $v; ?></a>
<?php endforeach; ?>
</nav>

<?php if ($tab === 'overview'): ?>

<div class="section">
<h2>Top 10 Usernames</h2>
<?php if ($usernames): ?>
<table><tr><th>Username</th><th>Attempts</th><th></th></tr>
<?php $max = max($usernames); foreach (array_slice($usernames, 0, 10, true) as $u => $c): ?>
<tr><td class="cred-user"><?php echo htmlspecialchars($u); ?></td><td><?php echo $c; ?></td><td><div class="bar-container"><div class="bar" style="width:<?php echo round($c/$max*200); ?>px"></div></div></td></tr>
<?php endforeach; ?>
</table>
<?php else: ?><div class="empty">No login attempts yet</div><?php endif; ?>
</div>

<div class="section">
<h2>Top 10 Passwords</h2>
<?php if ($passwords): ?>
<table><tr><th>Password</th><th>Attempts</th><th></th></tr>
<?php $max = max($passwords); foreach (array_slice($passwords, 0, 10, true) as $p => $c): ?>
<tr><td class="cred-pass"><?php echo htmlspecialchars($p); ?></td><td><?php echo $c; ?></td><td><div class="bar-container"><div class="bar" style="width:<?php echo round($c/$max*200); ?>px"></div></div></td></tr>
<?php endforeach; ?>
</table>
<?php else: ?><div class="empty">No login attempts yet</div><?php endif; ?>
</div>

<?php elseif ($tab === 'creds'): ?>

<div class="section">
<h2>All Credential Pairs (newest first)</h2>
<div class="scroll">
<?php if ($creds): ?>
<table><tr><th>Time</th><th>IP</th><th>CC</th><th>Username</th><th>Password</th><th>#</th><th>Delay</th></tr>
<?php foreach (array_reverse($creds) as $c): ?>
<tr>
<td><?php echo htmlspecialchars($c['ts']); ?></td>
<td><?php echo htmlspecialchars($c['ip']); ?></td>
<td><span class="badge badge-cc"><?php echo htmlspecialchars($c['cc']); ?></span></td>
<td class="cred-user"><?php echo htmlspecialchars($c['user']); ?></td>
<td class="cred-pass"><?php echo htmlspecialchars($c['pass']); ?></td>
<td><?php echo $c['att']; ?></td>
<td>+<?php echo $c['delay']; ?>s</td>
</tr>
<?php endforeach; ?>
</table>
<?php else: ?><div class="empty">No credentials captured yet</div><?php endif; ?>
</div>
</div>

<?php elseif ($tab === 'passwords'): ?>

<div class="section">
<h2>All Passwords by Frequency</h2>
<div class="scroll">
<?php if ($passwords): ?>
<table><tr><th>Password</th><th>Count</th><th></th></tr>
<?php $max = max($passwords); foreach ($passwords as $p => $c): ?>
<tr><td class="cred-pass"><?php echo htmlspecialchars($p); ?></td><td><?php echo $c; ?></td><td><div class="bar-container"><div class="bar" style="width:<?php echo round($c/$max*300); ?>px"></div></div></td></tr>
<?php endforeach; ?>
</table>
<?php else: ?><div class="empty">No passwords yet</div><?php endif; ?>
</div>
</div>

<?php elseif ($tab === 'usernames'): ?>

<div class="section">
<h2>All Usernames by Frequency</h2>
<div class="scroll">
<?php if ($usernames): ?>
<table><tr><th>Username</th><th>Count</th><th></th></tr>
<?php $max = max($usernames); foreach ($usernames as $u => $c): ?>
<tr><td class="cred-user"><?php echo htmlspecialchars($u); ?></td><td><?php echo $c; ?></td><td><div class="bar-container"><div class="bar" style="width:<?php echo round($c/$max*300); ?>px"></div></div></td></tr>
<?php endforeach; ?>
</table>
<?php else: ?><div class="empty">No usernames yet</div><?php endif; ?>
</div>
</div>

<?php elseif ($tab === 'ips'): ?>

<div class="section">
<h2>Attacking IPs</h2>
<div class="scroll">
<?php if ($ips): ?>
<table><tr><th>IP</th><th>Country</th><th>Hits</th><th>First Seen</th><th>Last Seen</th><th></th></tr>
<?php $max = max($ips); foreach ($ips as $ip => $c):
$d = $ip_details[$ip] ?? []; ?>
<tr>
<td><?php echo htmlspecialchars($ip); ?></td>
<td><span class="badge badge-cc"><?php echo htmlspecialchars($d['country'] ?? '??'); ?></span></td>
<td><?php echo $c; ?></td>
<td><?php echo htmlspecialchars(substr($d['first'] ?? '', 0, 16)); ?></td>
<td><?php echo htmlspecialchars(substr($d['last'] ?? '', 0, 16)); ?></td>
<td><div class="bar-container"><div class="bar" style="width:<?php echo round($c/$max*200); ?>px"></div></div></td>
</tr>
<?php endforeach; ?>
</table>
<?php else: ?><div class="empty">No IPs yet</div><?php endif; ?>
</div>
</div>

<?php elseif ($tab === 'countries'): ?>

<div class="section">
<h2>Attacks by Country</h2>
<?php if ($countries): ?>
<table><tr><th>Country</th><th>Attempts</th><th></th></tr>
<?php $max = max($countries); foreach ($countries as $cc => $c): ?>
<tr><td><span class="badge badge-cc"><?php echo htmlspecialchars($cc); ?></span></td><td><?php echo $c; ?></td><td><div class="bar-container"><div class="bar" style="width:<?php echo round($c/$max*300); ?>px"></div></div></td></tr>
<?php endforeach; ?>
</table>
<?php else: ?><div class="empty">No country data (requires Cloudflare)</div><?php endif; ?>
</div>

<?php elseif ($tab === 'timeline'): ?>

<div class="section">
<h2>Attack Timeline (by hour)</h2>
<div class="scroll">
<?php if ($hours): ?>
<table><tr><th>Hour</th><th>Events</th><th></th></tr>
<?php $max = max($hours); foreach ($hours as $h => $c): ?>
<tr><td><?php echo htmlspecialchars($h); ?></td><td><?php echo $c; ?></td><td><div class="bar-container"><div class="bar" style="width:<?php echo round($c/$max*400); ?>px"></div></div></td></tr>
<?php endforeach; ?>
</table>
<?php else: ?><div class="empty">No timeline data yet</div><?php endif; ?>
</div>
</div>

<?php endif; ?>

<p style="color:var(--dim);font-size:11px;margin-top:24px;text-align:center">wp-honeypot dashboard &middot; <?php echo date('Y-m-d H:i:s'); ?></p>

</div>
</body>
</html>
