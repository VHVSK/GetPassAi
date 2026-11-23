<?php
// JSON API of the password vault.
// Actions (?action= parameter):
//   GET  salt     — PBKDF2 salt for the user (public, not secret)
//   GET  csrf     — CSRF token of the current session
//   POST register — sign up {username, password, kdf_salt, csrf_token}
//   POST login    — sign in {username, password, csrf_token}
//   POST logout   — sign out {csrf_token}
//   GET  list     — list of encrypted entries (sign-in required)
//   POST save     — create/update an entry {id?, salt, iv, data, csrf_token}
//   POST delete   — delete an entry {id, csrf_token}
//
// The server NEVER receives plain-text service names or passwords:
// save only gets ciphertext (data) + salt + IV in base64.

declare(strict_types=1);
require __DIR__ . '/common.php';

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

function valid_password(string $p): bool
{
    $len = mb_strlen($p, 'UTF-8');
    return $len >= 8 && $len <= 128;
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
    // --- PBKDF2 salt for the user. Not secret.
    // If there is no such user, return a random salt, so as not to reveal
    // whether the username exists.
    case 'salt': {
        $username = (string) ($_GET['username'] ?? '');
        $salt = null;
        if (valid_username($username)) {
            $stmt = db()->prepare('SELECT kdf_salt FROM users WHERE username = :u LIMIT 1');
            $stmt->execute([':u' => $username]);
            $row = $stmt->fetch();
            if ($row) {
                $salt = (string) $row['kdf_salt'];
            }
        }
        if ($salt === null) {
            $salt = base64_encode(random_bytes(16));
        }
        json_response(['ok' => true, 'salt' => $salt]);
    }

    case 'csrf': {
        json_response(['ok' => true, 'csrf_token' => (string) ($_SESSION['csrf_token'] ?? '')]);
    }

    // --- Registration.
    case 'register': {
        check_csrf($input['csrf_token'] ?? null);
        if (empty($GLOBALS['config']['ALLOW_REGISTRATION'])) {
            json_response(['ok' => false, 'error' => 'Registration is turned off.'], 403);
        }
        $username = (string) ($input['username'] ?? '');
        $password = (string) ($input['password'] ?? '');
        $kdfSalt = (string) ($input['kdf_salt'] ?? '');
        if (!valid_username($username)) {
            json_response(['ok' => false, 'error' => 'Username: 3–64 characters (Latin letters, digits, . _ @ -).'], 400);
        }
        if (!valid_password($password)) {
            json_response(['ok' => false, 'error' => 'Password: 8 to 128 characters.'], 400);
        }
        if (!valid_b64($kdfSalt, 64, 32)) {
            json_response(['ok' => false, 'error' => 'Invalid key salt.'], 400);
        }
        $stmt = db()->prepare('SELECT id FROM users WHERE username = :u LIMIT 1');
        $stmt->execute([':u' => $username]);
        if ($stmt->fetch()) {
            json_response(['ok' => false, 'error' => 'This username is already taken.'], 409);
        }
        $algo = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT;
        $hash = password_hash($password, $algo);
        $stmt = db()->prepare(
            'INSERT INTO users (username, password_hash, kdf_salt) VALUES (:u, :h, :s)'
        );
        $stmt->execute([':u' => $username, ':h' => $hash, ':s' => $kdfSalt]);
        json_response(['ok' => true], 201);
    }

    // --- Sign-in.
    case 'login': {
        check_csrf($input['csrf_token'] ?? null);
        $username = (string) ($input['username'] ?? '');
        $password = (string) ($input['password'] ?? '');
        $ip = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
        if (!valid_username($username) || !valid_password($password)) {
            json_response(['ok' => false, 'error' => 'Wrong username or password.'], 400);
        }
        if (too_many_attempts($ip, $username)) {
            json_response(['ok' => false, 'error' => 'Too many failed attempts. Please try again in 15 minutes.'], 429);
        }
        $stmt = db()->prepare('SELECT id, username, password_hash FROM users WHERE username = :u LIMIT 1');
        $stmt->execute([':u' => $username]);
        $row = $stmt->fetch();
        if (!$row || !password_verify($password, (string) $row['password_hash'])) {
            record_failed_login($ip, $username);
            json_response(['ok' => false, 'error' => 'Wrong username or password.'], 401);
        }
        session_regenerate_id(true);
        $_SESSION['user_id'] = (int) $row['id'];
        $_SESSION['username'] = (string) $row['username'];
        clear_failed_logins($ip, $username);
        json_response(['ok' => true, 'username' => (string) $row['username']]);
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
