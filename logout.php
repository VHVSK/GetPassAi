<?php
// Sign-out: destroy the PHP session and go to the sign-in page.
// The encryption key in the browser tab is removed separately
// (app.js: sessionStorage is cleared on sign-out).
declare(strict_types=1);
require __DIR__ . '/common.php';

$_SESSION = [];
if (ini_get('session.use_cookies')) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
}
session_destroy();
header('Location: login.php');
exit;
