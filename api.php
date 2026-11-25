<?php
// JSON API of the password vault.
// Actions (?action= parameter):
//   GET  csrf          — CSRF token of the current session
//   POST srp_register  — sign up {username, salt, verifier, csrf_token}
//                        (salt = SRP salt hex, verifier = SRP verifier hex;
//                        the site password NEVER reaches the server)
//   POST srp_challenge — start sign-in {username, csrf_token} -> {salt, B}
//   POST srp_verify    — finish sign-in {A, M1, csrf_token} -> {M2, username}
//   POST logout        — sign out {csrf_token}
//   GET  list          — list of encrypted entries (sign-in required)
//   POST save          — create/update an entry {id?, salt, iv, data, csrf_token}
//   POST delete        — delete an entry {id, csrf_token}
//
// The server NEVER receives plain-text service names or passwords:
// save only gets ciphertext (data) + salt + IV in base64, and SRP proves
// the site password without sending it (see srp.php).

declare(strict_types=1);
require __DIR__ . '/common.php';
require __DIR__ . '/srp.php';

$action = $_GET['action'] ?? '';
$input = [];
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    $decoded = json_decode(file_get_contents('php://input') ?: '', true);
    if (is_array($decoded)) {
        $input = $decoded;
    }
}

function valid_username(string $u): bool
{
    return (bool) preg_match('/^[A-Za-z0-9._@-]{3,64}$/', $u);
}

/** Validate a base64 string (and its byte length after decoding). */
function valid_b64(string $s, int $maxLen, int $maxBytes): bool
{
    if ($s === '' || strlen($s) > $maxLen) {
        return false;
    }
    if (!preg_match('/^[A-Za-z0-9+\/=]+$/', $s)) {
        return false;
    }
    $d = base64_decode($s, true);
    return $d !== false && strlen($d) <= $maxBytes;
}

function too_many_attempts(string $ip, string $username): bool
{
    $stmt = db()->prepare(
        'SELECT COUNT(*) FROM login_attempts
         WHERE attempted_at > (NOW() - INTERVAL 15 MINUTE) AND (ip = :ip OR username = :u)'
    );
    $stmt->execute([':ip' => $ip, ':u' => $username]);
    return ((int) $stmt->fetchColumn()) >= 5;
}

function record_failed_login(string $ip, string $username): void
{
    $stmt = db()->prepare('INSERT INTO login_attempts (ip, username) VALUES (:ip, :u)');
    $stmt->execute([':ip' => $ip, ':u' => $username]);
}

function clear_failed_logins(string $ip, string $username): void
{
    $stmt = db()->prepare('DELETE FROM login_attempts WHERE ip = :ip AND username = :u');
    $stmt->execute([':ip' => $ip, ':u' => $username]);
}

try {
    switch ($action) {
    case 'csrf': {
        json_response(['ok' => true, 'csrf_token' => (string) ($_SESSION['csrf_token'] ?? '')]);
    }

    // --- Registration (SRP): the browser sends salt + verifier.
    // The site password never reaches the server.
    case 'srp_register': {
        check_csrf($input['csrf_token'] ?? null);
        if (empty($GLOBALS['config']['ALLOW_REGISTRATION'])) {
            json_response(['ok' => false, 'error' => 'Registration is turned off.'], 403);
        }
        $username = (string) ($input['username'] ?? '');
        $salt = srp_clean_hex($input['salt'] ?? null, 32);
        $verifier = srp_clean_hex($input['verifier'] ?? null, 512);
        if (!valid_username($username)) {
            json_response(['ok' => false, 'error' => 'Username: 3–64 characters (Latin letters, digits, . _ @ -).'], 400);
        }
        if ($salt === null || strlen($salt) !== 32 || $verifier === null || strlen($verifier) !== 512) {
            json_response(['ok' => false, 'error' => 'Invalid SRP registration data.'], 400);
        }
        $p = srp_params('sha256');
        $v = srp_bn_from_hex($verifier);
        $N = srp_bn_from_hex($p['N']);
        if (srp_bn_is_zero($v) || srp_bn_cmp($v, $N) >= 0) {
            json_response(['ok' => false, 'error' => 'Invalid SRP registration data.'], 400);
        }
        $stmt = db()->prepare('SELECT id FROM users WHERE username = :u LIMIT 1');
        $stmt->execute([':u' => $username]);
        if ($stmt->fetch()) {
            json_response(['ok' => false, 'error' => 'This username is already taken.'], 409);
        }
        $stmt = db()->prepare(
            'INSERT INTO users (username, srp_salt, srp_verifier) VALUES (:u, :s, :v)'
        );
        $stmt->execute([':u' => $username, ':s' => $salt, ':v' => $verifier]);
        json_response(['ok' => true], 201);
    }

    // --- Sign-in, step 1: issue salt + B. For an unknown username the
    // response is indistinguishable (random salt + random verifier),
    // so the endpoint does not reveal whether the user exists.
    case 'srp_challenge': {
        check_csrf($input['csrf_token'] ?? null);
        $username = (string) ($input['username'] ?? '');
        $ip = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
        if (!valid_username($username)) {
            json_response(['ok' => false, 'error' => 'Wrong username or password.'], 400);
        }
        if (too_many_attempts($ip, $username)) {
            json_response(['ok' => false, 'error' => 'Too many failed attempts. Please try again in 15 minutes.'], 429);
        }
        $stmt = db()->prepare('SELECT srp_salt, srp_verifier FROM users WHERE username = :u LIMIT 1');
        $stmt->execute([':u' => $username]);
        $row = $stmt->fetch();
        if ($row) {
            $salt = (string) $row['srp_salt'];
            $verifier = (string) $row['srp_verifier'];
        } else {
            // Unknown user: random values, same shape of response.
            $salt = bin2hex(random_bytes(16));
            $x = srp_bn_from_bytes(random_bytes(32));
            $verifier = srp_compute_verifier(srp_bn_to_hex($x), srp_params('sha256'));
        }
        $p = srp_params('sha256');
        $server = new SrpServer($p);
        $b = srp_random_private();
        $server->setPrivateB($b);
        $B = $server->challenge($username, $salt, $verifier);
        // One-shot state: the private b is needed to finish the handshake.
        $_SESSION['srp'] = ['username' => $username, 'salt' => $salt, 'verifier' => $verifier, 'b' => $b];
        json_response(['ok' => true, 'salt' => $salt, 'B' => $B]);
    }

    // --- Sign-in, step 2: verify the client proof M1, answer with M2.
    case 'srp_verify': {
        check_csrf($input['csrf_token'] ?? null);
        $state = $_SESSION['srp'] ?? null;
        unset($_SESSION['srp']); // one-shot: a proof cannot be replayed
        $ip = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
        if (!is_array($state) || empty($state['username']) || empty($state['salt'])
            || empty($state['verifier']) || empty($state['b'])) {
            json_response(['ok' => false, 'error' => 'Sign-in session expired. Please try again.'], 401);
        }
        $username = (string) $state['username'];
        $A = srp_clean_hex($input['A'] ?? null, 512);
        $M1 = srp_clean_hex($input['M1'] ?? null, 64);
        if ($A === null || $M1 === null) {
            record_failed_login($ip, $username);
            json_response(['ok' => false, 'error' => 'Wrong username or password.'], 401);
        }
        $stmt = db()->prepare('SELECT id, username FROM users WHERE username = :u LIMIT 1');
        $stmt->execute([':u' => $username]);
        $row = $stmt->fetch();
        if (!$row) {
            record_failed_login($ip, $username);
            json_response(['ok' => false, 'error' => 'Wrong username or password.'], 401);
        }
        $p = srp_params('sha256');
        $server = new SrpServer($p);
        $M2 = ''; // assigned inside try; the catch answers 401 and exits
        try {
            $server->setPrivateB((string) $state['b']);
            $server->challenge($username, (string) $state['salt'], (string) $state['verifier']);
            $M2 = $server->verify($A, $M1);
        } catch (Throwable $e) {
            record_failed_login($ip, $username);
            json_response(['ok' => false, 'error' => 'Wrong username or password.'], 401);
        }
        session_regenerate_id(true);
        $_SESSION['user_id'] = (int) $row['id'];
        $_SESSION['username'] = (string) $row['username'];
        clear_failed_logins($ip, $username);
        json_response(['ok' => true, 'username' => (string) $row['username'], 'M2' => $M2]);
    }

    // --- Sign-out.
    case 'logout': {
        check_csrf($input['csrf_token'] ?? null);
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
        }
        session_destroy();
        json_response(['ok' => true]);
    }

    // --- List of entries (ciphertext only).
    case 'list': {
        $user = require_auth();
        $stmt = db()->prepare(
            'SELECT id, salt, iv, data, created_at, updated_at
             FROM vault_entries WHERE user_id = :uid ORDER BY created_at ASC'
        );
        $stmt->execute([':uid' => $user['id']]);
        json_response(['ok' => true, 'entries' => $stmt->fetchAll()]);
    }

    // --- Save an entry (create or update).
    case 'save': {
        $user = require_auth();
        check_csrf($input['csrf_token'] ?? null);
        $id = isset($input['id']) ? (int) $input['id'] : 0;
        $salt = (string) ($input['salt'] ?? '');
        $iv = (string) ($input['iv'] ?? '');
        $data = (string) ($input['data'] ?? '');
        if (!valid_b64($salt, 64, 32) || !valid_b64($iv, 64, 32) || !valid_b64($data, 100000, 65536)) {
            json_response(['ok' => false, 'error' => 'Invalid encrypted data.'], 400);
        }
        if ($id > 0) {
            $stmt = db()->prepare(
                'UPDATE vault_entries SET salt = :s, iv = :iv, data = :d
                 WHERE id = :id AND user_id = :uid'
            );
            $stmt->execute([':s' => $salt, ':iv' => $iv, ':d' => $data, ':id' => $id, ':uid' => $user['id']]);
            if ($stmt->rowCount() === 0) {
                json_response(['ok' => false, 'error' => 'Entry not found.'], 404);
            }
            json_response(['ok' => true, 'id' => $id]);
        }
        $stmt = db()->prepare(
            'INSERT INTO vault_entries (user_id, salt, iv, data) VALUES (:uid, :s, :iv, :d)'
        );
        $stmt->execute([':uid' => $user['id'], ':s' => $salt, ':iv' => $iv, ':d' => $data]);
        json_response(['ok' => true, 'id' => (int) db()->lastInsertId()], 201);
    }

    // --- Delete an entry.
    case 'delete': {
        $user = require_auth();
        check_csrf($input['csrf_token'] ?? null);
        $id = (int) ($input['id'] ?? 0);
        if ($id <= 0) {
            json_response(['ok' => false, 'error' => 'Invalid entry id.'], 400);
        }
        $stmt = db()->prepare('DELETE FROM vault_entries WHERE id = :id AND user_id = :uid');
        $stmt->execute([':id' => $id, ':uid' => $user['id']]);
        json_response(['ok' => true, 'deleted' => $stmt->rowCount()]);
    }

    default: {
        json_response(['ok' => false, 'error' => 'Unknown action.'], 400);
    }
    }
} catch (Throwable $e) {
    // Server error (for example, no database connection).
    // Details go only to the server log; the client gets a generic message.
    error_log('password-vault api error: ' . $e->getMessage());
    json_response(['ok' => false, 'error' => 'Server error. Please check the database settings.'], 500);
}
