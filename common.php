<?php
// Shared bootstrap: settings, session, database, helper functions.
// Included at the top of every page and api.php.
// Nothing secret (passwords, keys) is stored or logged here.

declare(strict_types=1);

$configFile = __DIR__ . '/config.php';
if (!file_exists($configFile)) {
    http_response_code(500);
    die('config.php not found. Copy config.php.example to config.php and fill in the database details.');
}
$config = require $configFile;

// Is this a local run (for testing with php -S)?
$isLocal = in_array($_SERVER['REMOTE_ADDR'] ?? '', ['127.0.0.1', '::1'], true)
    || ($_SERVER['HTTP_HOST'] ?? '') === 'localhost'
    || str_starts_with($_SERVER['HTTP_HOST'] ?? '', 'localhost:');
$isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');

// Force HTTPS everywhere except localhost.
// WebCrypto (encryption in the browser) only works in a secure context:
// HTTPS or localhost. Without HTTPS the site cannot decrypt entries.
if (!$isLocal && !$isHttps) {
    $url = 'https://' . ($_SERVER['HTTP_HOST'] ?? '') . ($_SERVER['REQUEST_URI'] ?? '/');
    header('Location: ' . $url, true, 301);
    exit;
}

// Donation page for the "Support this project" links (public, free service).
// Donations: https://donatello.to/ViktorVyhivskyi
const DONATE_URL = 'https://donatello.to/ViktorVyhivskyi';

// Security headers.
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
// No inline scripts or styles anywhere (only assets/app.js, assets/srp.js
// + assets/style.css), no external resources: a strict CSP is safe.
header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()');
if ($isHttps) {
    // HSTS: HTTPS-only for this host. No includeSubDomains on purpose,
    // so other subdomains are not affected.
    header('Strict-Transport-Security: max-age=31536000');
}

// Secure session parameters: HttpOnly, SameSite=Lax, Secure when on HTTPS.
session_name('pv_session');
session_set_cookie_params([
    'lifetime' => 0, // until the browser is closed
    'path' => '/',
    'domain' => '',
    'secure' => $isHttps,
    'httponly' => true,
    'samesite' => 'Lax',
]);
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

/** MySQL connection (PDO, prepared statements). */
function db(): PDO
{
    static $pdo = null;
    if ($pdo === null) {
        $config = $GLOBALS['config'];
        $dsn = sprintf('mysql:host=%s;dbname=%s;charset=utf8mb4', $config['DB_HOST'], $config['DB_NAME']);
        $pdo = new PDO($dsn, $config['DB_USER'], $config['DB_PASS'], [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
    }
    return $pdo;
}

/** JSON API response, then exit. */
function json_response(array $data, int $status = 200): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

/** The currently signed-in user, or null. */
function current_user(): ?array
{
    if (empty($_SESSION['user_id'])) {
        return null;
    }
    return ['id' => (int) $_SESSION['user_id'], 'username' => (string) $_SESSION['username']];
}

/** Require sign-in (for the API): otherwise a 401 JSON response. */
function require_auth(): array
{
    $user = current_user();
    if ($user === null) {
        json_response(['ok' => false, 'error' => 'Sign-in required.'], 401);
    }
    return $user;
}

/** Check the CSRF token (from the JSON body or a POST field). */
function check_csrf(?string $token = null): void
{
    if ($token === null) {
        $token = $_POST['csrf_token'] ?? ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');
    }
    if (!is_string($token) || !hash_equals((string) ($_SESSION['csrf_token'] ?? ''), $token)) {
        json_response(['ok' => false, 'error' => 'Invalid CSRF token. Please refresh the page.'], 403);
    }
}

/** Escape for HTML. */
function h(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/** Start of an HTML page. $extraHead is trusted extra markup for <head>
 * (meta tags, JSON-LD) — used by the landing page. */
function page_head(string $title, string $page, string $extraHead = ''): void
{
    $token = (string) ($_SESSION['csrf_token'] ?? '');
    echo '<!DOCTYPE html>' . "\n"
        . '<html lang="en"><head><meta charset="utf-8">' . "\n"
        . '<meta name="viewport" content="width=device-width, initial-scale=1">' . "\n"
        . '<meta name="csrf-token" content="' . h($token) . '">' . "\n"
        . '<title>' . h($title) . (str_starts_with($title, 'GetPassAi') ? '' : ' — GetPassAi') . '</title>' . "\n"
        . $extraHead
        . '<link rel="stylesheet" href="assets/style.css">' . "\n"
        . '</head>' . "\n"
        . '<body data-page="' . h($page) . '">' . "\n";
}

/** End of an HTML page. srp.js (SRP-6a client) loads before app.js. */
function page_foot(): void
{
    echo '<script src="assets/srp.js"></script>' . "\n"
        . '<script src="assets/app.js"></script>' . "\n" . '</body></html>' . "\n";
}
