<?php
// Sign-in page.
// The site password doubles as the vault encryption key:
// it is never stored in plain text anywhere; the key is derived
// from it in the browser (PBKDF2). If you forget the password,
// the entries cannot be decrypted — the server cannot recover them.
declare(strict_types=1);
require __DIR__ . '/common.php';

if (current_user()) {
    header('Location: vault.php');
    exit;
}
$registered = isset($_GET['registered']);
$needLogin = isset($_GET['need_login']);
page_head('Sign in', 'login');
?>
<main class="wrap">
  <h1>🔐 GetPassAi</h1>
  <p class="muted">Free vault. Passwords are encrypted in your browser — the server never sees them.</p>

  <?php if ($registered): ?>
    <p class="ok">Account created. Please sign in.</p>
  <?php endif; ?>
  <?php if ($needLogin): ?>
    <p class="warn">The key session ended (the tab was closed). Please sign in again — the browser will fill in your username and password.</p>
  <?php endif; ?>

  <form id="login-form" class="card" autocomplete="on">
    <label>Username
      <input type="text" name="username" autocomplete="username" required minlength="3" maxlength="64"
             placeholder="your username" autofocus>
    </label>
    <label>Password
      <input type="password" name="password" autocomplete="current-password" required minlength="8" maxlength="128"
             placeholder="site password">
    </label>
    <p class="hint">The site password is also the encryption key. Don't forget it: without it, the entries cannot be decrypted.</p>
    <button type="submit" class="btn primary">Sign in</button>
    <p id="form-error" class="error" hidden></p>
    <p id="form-status" class="muted" hidden></p>
  </form>

  <p class="muted">No account yet? <a href="register.php">Create one</a></p>
  <p class="muted">Free service, no ads. If it helps you, you can <a href="<?= h(DONATE_URL) ?>" target="_blank" rel="noopener">support the project</a>.</p>
</main>
<?php page_foot(); ?>
