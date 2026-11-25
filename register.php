<?php
// Registration page.
// Registration is open to everyone (free service, donations are voluntary).
// The owner can pause sign-ups with ALLOW_REGISTRATION = false in config.php.
declare(strict_types=1);
require __DIR__ . '/common.php';

if (current_user()) {
    header('Location: vault.php');
    exit;
}
$allowed = !empty($config['ALLOW_REGISTRATION']);
page_head('Create account', 'register');
?>
<main class="wrap">
  <h1><a href="index.php">🔐 GetPassAi</a></h1>

  <?php if (!$allowed): ?>
    <p class="warn">Registration has been turned off by the site owner.</p>
    <p><a href="login.php">← Back to sign in</a></p>
  <?php else: ?>
    <p class="muted">Create an account. Your password becomes the encryption key for your vault — remember it, it cannot be recovered.</p>

    <form id="register-form" class="card" autocomplete="on">
      <label>Username
        <input type="text" name="username" autocomplete="username" required minlength="3" maxlength="64"
               placeholder="e.g. alex" autofocus>
      </label>
      <label>Password
        <input type="password" name="password" autocomplete="new-password" required minlength="8" maxlength="128"
               placeholder="at least 8 characters, 12+ is better">
      </label>
      <label>Password again
        <input type="password" name="password2" autocomplete="new-password" required minlength="8" maxlength="128"
               placeholder="repeat your password">
      </label>
      <button type="submit" class="btn primary">Create account</button>
      <p id="form-error" class="error" hidden></p>
      <p id="form-status" class="muted" hidden></p>
    </form>

    <p class="muted">Already have an account? <a href="login.php">Sign in</a></p>
    <p class="muted">Free service, no ads. If it helps you, you can <a href="<?= h(DONATE_URL) ?>" target="_blank" rel="noopener">support the project</a>.</p>
  <?php endif; ?>
</main>
<?php page_foot(); ?>
