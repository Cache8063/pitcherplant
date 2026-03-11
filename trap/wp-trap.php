<?php
/**
 * WordPress Login Honeypot / Tarpit
 *
 * Serves a convincing fake WP login page on /wp-login.php and /wp-admin.
 * Logs full attacker intelligence — credentials, headers, timing, patterns.
 * Progressive tarpit delays waste their time before fail2ban drops them.
 *
 * Real login is at the custom WPS Hide Login slug (or similar).
 *
 * Configuration: edit wp-trap-config.php alongside this file.
 */

// --- Load configuration ---
$config_file = __DIR__ . '/wp-trap-config.php';
if (file_exists($config_file)) {
    require $config_file;
} else {
    // Defaults if no config file found
    $site_name  = 'WordPress';
    $site_url   = '';
    $log_file   = '/var/log/wp-honeypot.log';
    $intel_file = '/var/log/wp-honeypot-intel.jsonl';
    $state_dir  = '/tmp/wp-honeypot';
    $max_delay  = 30;
}

// --- Resolve real IP ---
$ip = $_SERVER['REMOTE_ADDR'];
if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
    $ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
} elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $ip = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
}
$ip = trim($ip);

// --- State tracking per IP ---
if (!is_dir($state_dir)) mkdir($state_dir, 0700, true);
$state_file = $state_dir . '/' . md5($ip) . '.json';
$state = file_exists($state_file) ? json_decode(file_get_contents($state_file), true) : [];
$attempts = ($state['attempts'] ?? 0);
$first_seen = $state['first_seen'] ?? date('c');
$creds_tried = $state['creds_tried'] ?? [];

$error_msg = '';
$show_expired = false;
$submitted_user = '';

// --- Collect headers for intel ---
function get_interesting_headers() {
    $interesting = [
        'HTTP_USER_AGENT', 'HTTP_ACCEPT', 'HTTP_ACCEPT_LANGUAGE',
        'HTTP_ACCEPT_ENCODING', 'HTTP_REFERER', 'HTTP_ORIGIN',
        'HTTP_CF_CONNECTING_IP', 'HTTP_CF_IPCOUNTRY', 'HTTP_CF_RAY',
        'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED_PROTO',
        'HTTP_X_REAL_IP', 'HTTP_CONNECTION', 'HTTP_COOKIE',
    ];
    $headers = [];
    foreach ($interesting as $h) {
        if (!empty($_SERVER[$h])) {
            $key = strtolower(str_replace('HTTP_', '', $h));
            $headers[$key] = $_SERVER[$h];
        }
    }
    return $headers;
}

// --- Handle POST (login attempt) ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $attempts++;
    $submitted_user = $_POST['log'] ?? '';
    $submitted_pass = $_POST['pwd'] ?? '';
    $remember_me    = isset($_POST['rememberme']);
    $redirect_to    = $_POST['redirect_to'] ?? '';
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
    $headers = get_interesting_headers();

    // Track credential pairs this IP has tried
    $cred_pair = $submitted_user . ':' . $submitted_pass;
    $creds_tried[] = $cred_pair;

    // fail2ban log (simple format it can parse)
    $log_line = sprintf(
        "[%s] HONEYPOT: %s - attempt %d - user=%s\n",
        date('Y-m-d H:i:s'),
        $ip,
        $attempts,
        substr($submitted_user, 0, 64)
    );
    file_put_contents($log_file, $log_line, FILE_APPEND | LOCK_EX);

    // Full intel log (JSONL - one JSON object per line)
    $intel = [
        'timestamp'    => date('c'),
        'ip'           => $ip,
        'attempt'      => $attempts,
        'username'     => $submitted_user,
        'password'     => $submitted_pass,
        'remember_me'  => $remember_me,
        'redirect_to'  => $redirect_to,
        'method'       => $_SERVER['REQUEST_METHOD'],
        'uri'          => $_SERVER['REQUEST_URI'],
        'headers'      => $headers,
        'first_seen'   => $first_seen,
        'delay_applied'=> min($attempts * 2, $max_delay),
        'country'      => $headers['cf_ipcountry'] ?? null,
        'cf_ray'       => $headers['cf_ray'] ?? null,
    ];
    file_put_contents($intel_file, json_encode($intel) . "\n", FILE_APPEND | LOCK_EX);

    // Save state
    $state = [
        'attempts'    => $attempts,
        'first_seen'  => $first_seen,
        'last_seen'   => date('c'),
        'last_user'   => substr($submitted_user, 0, 64),
        'creds_tried' => array_slice($creds_tried, -100), // keep last 100
    ];
    file_put_contents($state_file, json_encode($state, JSON_PRETTY_PRINT));

    // Progressive tarpit: 2, 4, 6... up to max_delay
    $delay = min($attempts * 2, $max_delay);
    sleep($delay);

    // Rotate through realistic error messages
    $errors = [
        '<strong>Error:</strong> The password you entered for the username <strong>%s</strong> is incorrect. <a href="#" title="Password Lost and Found">Lost your password?</a>',
        '<strong>Error:</strong> The password you entered for the username <strong>%s</strong> is incorrect. <a href="#" title="Password Lost and Found">Lost your password?</a>',
        '<strong>Error:</strong> Unknown username. Check again or try your email address.',
        '<strong>Error:</strong> The password you entered for the username <strong>%s</strong> is incorrect. <a href="#" title="Password Lost and Found">Lost your password?</a>',
        '<strong>Error:</strong> There has been a critical error on this website. <a href="#">Learn more about troubleshooting WordPress.</a>',
    ];

    // After many attempts, mix in session expired and rate limit messages
    if ($attempts > 12 && $attempts % 4 === 0) {
        $show_expired = true;
    }
    if ($attempts > 15 && $attempts % 5 === 0) {
        $error_msg = '<strong>Error:</strong> Too many failed login attempts. Please try again in 15 minutes.';
    } else {
        $error_idx = ($attempts - 1) % count($errors);
        $error_msg = sprintf($errors[$error_idx], htmlspecialchars($submitted_user));
    }
} else {
    // GET request — also log reconnaissance
    $headers = get_interesting_headers();
    $intel = [
        'timestamp'  => date('c'),
        'ip'         => $ip,
        'attempt'    => 0,
        'type'       => 'recon',
        'method'     => 'GET',
        'uri'        => $_SERVER['REQUEST_URI'],
        'query'      => $_SERVER['QUERY_STRING'] ?? '',
        'headers'    => $headers,
        'first_seen' => $first_seen,
        'country'    => $headers['cf_ipcountry'] ?? null,
    ];
    file_put_contents($intel_file, json_encode($intel) . "\n", FILE_APPEND | LOCK_EX);

    // Returning visitors get a delay even on GET
    if ($attempts > 0) {
        sleep(min($attempts, 5));
    }
}

// --- Derive values for the page ---
$php_version = phpversion();
$wp_json_url = rtrim($site_url, '/') . '/wp-json/';

// --- Render fake login page ---
http_response_code(200);
header('X-Frame-Options: SAMEORIGIN');
header('Content-Type: text/html; charset=UTF-8');
header('X-Powered-By: PHP/' . $php_version);
if ($site_url) {
    header('Link: <' . $wp_json_url . '>; rel="https://api.w.org/"');
}
?>
<!DOCTYPE html>
<html lang="en-US">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<meta name="viewport" content="width=device-width">
<meta name="robots" content="noindex, nofollow">
<title>Log In &lsaquo; <?php echo htmlspecialchars($site_name); ?> &#8212; WordPress</title>
<style>
html{background:#f0f0f1}
body{background:#f0f0f1;min-width:0;color:#3c434a;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,"Helvetica Neue",sans-serif;font-size:13px;line-height:1.4}
a{color:#2271b1;transition-property:border,background,color;transition-duration:.05s;transition-timing-function:ease-in-out}
a:hover{color:#135e96}
.login .message,.login .success,.login .notice{border-left:4px solid #72aee6;padding:12px;margin-left:0;margin-bottom:20px;background-color:#fff;box-shadow:0 1px 1px 0 rgba(0,0,0,.1)}
.login #login_error{border-left:4px solid #d63638;padding:12px;margin-left:0;margin-bottom:20px;background-color:#fff;box-shadow:0 1px 1px 0 rgba(0,0,0,.1);word-wrap:break-word}
.login #login_error a{color:#d63638}
#login{width:320px;padding:5% 0 0;margin:auto}
#login_error a,#login .message a,.login .success a{text-decoration:none}
#login form{margin-top:20px;margin-left:0;padding:26px 24px 34px;font-weight:400;overflow:hidden;background:#fff;border:1px solid #c3c4c7;border-radius:3px;box-shadow:0 1px 3px rgba(0,0,0,.04)}
#login form .forgetmenot{font-weight:400;float:left;margin-bottom:0}
#login form p.submit{float:right}
.login h1{text-align:center}
.login h1 a{background-image:url('data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA4NCA4NCI+PHJlY3Qgd2lkdGg9Ijg0IiBoZWlnaHQ9Ijg0IiBmaWxsPSIjNDY0NjQ2Ii8+PHBhdGggZD0iTTY5LjE2NiA0NS42MzdDNjkuMTY2IDQ1LjE5NCA2OS4xNjIgNDQuNzc0IDY5LjA1IDQ0LjM3NUw2OS4wNSA0NC4zNzVDNjcuOTE3IDQwLjM0IDY0LjM5OSAzNy4yNDIgNjAuMTI1IDM2LjcwNkw0OS45ODUgMzUuNDgyQzQ4LjYyNSAzNS4zMTkgNDcuNDE4IDM0LjU5NSA0Ni42NjIgMzMuNTAxTDQzLjA0OCAyOC4yNjdDNDIuMjE1IDI3LjA2MSA0MC44MjggMjYuMzI5IDM5LjM0MSAyNi4zMjlMMjYuMTY0IDI2LjMyOUMyMy4xMTcgMjYuMzI5IDIwLjY0NiAyOC44IDIwLjY0NiAzMS44NDdMMjAuNjQ2IDQ1LjYzN0MyMC42NDYgNDUuNjQzIDIwLjY0OCA0NS42NDkgMjAuNjQ4IDQ1LjY1NUMyMC42NDggNDkuMjA4IDIzLjUyOCA1Mi4xMDQgMjcuMDggNTIuMTI5TDI3LjI1MyA1Mi4xMjlDMjcuMjkgNTUuNjYyIDMwLjE2MSA1OC41MTMgMzMuNzAxIDU4LjUxM0MzNy4yNCA1OC41MTMgNDAuMTExIDU1LjY2MiA0MC4xNDggNTIuMTI5TDQ5LjgxNiA1Mi4xMjlDNDkuODUzIDU1LjY2MiA1Mi43MjQgNTguNTEzIDU2LjI2MyA1OC41MTNDNTkuODAzIDU4LjUxMyA2Mi42NzQgNTUuNjYyIDYyLjcxMSA1Mi4xMjlMNjIuODE0IDUyLjEyOUM2Ni4zNTIgNTIuMTI5IDY5LjIyIDQ5LjI2MSA2OS4xNjYgNDUuNzIzTDY5LjE2NiA0NS42MzdaTTMzLjcwMSA1NS41NjRDMzEuNzkyIDU1LjU2NCAzMC4yNDQgNTQuMDE2IDMwLjI0NCA1Mi4xMDdDMzAuMjQ0IDUwLjE5OCAzMS43OTIgNDguNjUgMzMuNzAxIDQ4LjY1QzM1LjYxIDQ4LjY1IDM3LjE1OCA1MC4xOTggMzcuMTU4IDUyLjEwN0MzNy4xNTggNTQuMDE2IDM1LjYxIDU1LjU2NCAzMy43MDEgNTUuNTY0Wk01Ni4yNjMgNTUuNTY0QzU0LjM1NCA1NS41NjQgNTIuODA2IDU0LjAxNiA1Mi44MDYgNTIuMTA3QzUyLjgwNiA1MC4xOTggNTQuMzU0IDQ4LjY1IDU2LjI2MyA0OC42NUM1OC4xNzIgNDguNjUgNTkuNzIgNTAuMTk4IDU5LjcyIDUyLjEwN0M1OS43MiA1NC4wMTYgNTguMTcyIDU1LjU2NCA1Ni4yNjMgNTUuNTY0WiIgZmlsbD0iI2ZmZiIvPjwvc3ZnPg==');background-size:84px;background-position:center;background-repeat:no-repeat;color:#3c434a;height:84px;font-size:0;width:84px;display:block;margin:0 auto 25px}
.login h1 a:focus{box-shadow:none}
.login label{font-size:14px;display:block;margin-bottom:3px}
.login form .input,.login input[type=text],.login input[type=password]{font-size:24px;width:100%;padding:3px;margin:2px 6px 16px 0;border:1px solid #8c8f94;box-sizing:border-box;border-radius:3px;background:#fff;color:#2c3338}
.login form .input:focus,.login input[type=text]:focus,.login input[type=password]:focus{border-color:#2271b1;box-shadow:0 0 0 1px #2271b1;outline:2px solid transparent}
.wp-core-ui .button-primary{background:#2271b1;border-color:#2271b1;color:#fff;text-decoration:none;text-shadow:none;border-width:1px;border-style:solid;border-radius:3px;cursor:pointer;font-size:13px;line-height:2.15384615;min-height:30px;padding:0 10px;display:inline-block;white-space:nowrap;box-sizing:border-box;-webkit-appearance:none}
.wp-core-ui .button-primary:hover{background:#135e96;border-color:#135e96;color:#fff}
.wp-core-ui .button-primary:focus{background:#135e96;border-color:#135e96;color:#fff;box-shadow:0 0 0 1px #fff,0 0 0 3px #135e96;outline:2px solid transparent;outline-offset:0}
#login form p.submit .button-primary{float:right;width:100%;text-align:center;margin-top:16px;padding:6px;font-size:14px;line-height:1.5;min-height:40px}
p#nav,p#backtoblog{margin:24px 0 0;padding:0;text-align:center}
p#nav a,p#backtoblog a{color:#50575e;font-size:13px}
p#nav a:hover,p#backtoblog a:hover{color:#135e96}
.login #backtoblog a{display:inline}
.login .privacy-policy-page-link{text-align:center;width:320px;margin:24px auto 0}
.login .privacy-policy-page-link a{font-size:13px;color:#50575e}
input[type=checkbox]{border:1px solid #8c8f94;border-radius:3px;background:#fff;color:#50575e;clear:none;cursor:pointer;display:inline-block;line-height:0;height:1rem;margin:-0.25rem .25rem 0 0;outline:0;padding:0!important;text-align:center;vertical-align:middle;width:1rem;min-width:1rem;-webkit-appearance:none;transition:border-color .1s ease-in-out}
.language-switcher{padding:10px;text-align:center;margin:24px auto 0;width:320px}
</style>
</head>
<body class="login js login-action-login wp-core-ui locale-en-us">
<div id="login">
<h1><a href="https://wordpress.org/" tabindex="-1">Powered by WordPress</a></h1>
<?php if ($show_expired): ?>
<div class="message"><p>Session expired. Please log in again.</p></div>
<?php endif; ?>
<?php if ($error_msg): ?>
<div id="login_error"><?php echo $error_msg; ?></div>
<?php endif; ?>
<form name="loginform" id="loginform" action="" method="post">
<p>
<label for="user_login">Username or Email Address</label>
<input type="text" name="log" id="user_login" class="input" value="<?php echo htmlspecialchars($submitted_user); ?>" size="20" autocapitalize="off" autocomplete="username" required>
</p>
<p>
<label for="user_pass">Password</label>
<input type="password" name="pwd" id="user_pass" class="input" value="" size="20" autocomplete="current-password" spellcheck="false" required>
</p>
<p class="forgetmenot"><label for="rememberme"><input name="rememberme" type="checkbox" id="rememberme" value="forever"> Remember Me</label></p>
<p class="submit">
<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In">
<input type="hidden" name="redirect_to" value="/wp-admin/">
<input type="hidden" name="testcookie" value="1">
</p>
</form>
<p id="nav"><a href="#">Lost your password?</a></p>
<p id="backtoblog"><a href="/">&larr; Go to <?php echo htmlspecialchars($site_name); ?></a></p>
</div>
<div class="language-switcher"><form id="language-switcher" method="get"><label for="language-switcher-locales"><select id="language-switcher-locales" name="wp_lang"><option value="en_US" lang="en" selected="selected" data-installed="1">English (United States)</option></select></label><input type="submit" class="button" value="Change"></form></div>
</body>
</html>
