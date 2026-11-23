<?php
// Vault page. Available only after sign-in.
// Service names and passwords are shown only after decryption
// in the browser. Passwords are masked by default (••••••).
declare(strict_types=1);
require __DIR__ . '/common.php';

$user = current_user();
if (!$user) {
    header('Location: login.php');
    exit;
}
page_head('Vault', 'vault');
?>
<main class="wrap wide">
  <header class="topbar">
    <h1>🔐 GetPassAi</h1>
    <div class="topbar-right">
      <span class="muted"><?= h($user['username']) ?></span>
      <button id="logout-btn" class="btn">Sign out</button>
    </div>
  </header>

  <p id="crypto-warning" class="warn" hidden>
    This browser does not support WebCrypto (HTTPS or localhost is required). Entries cannot be decrypted.
  </p>

  <div class="toolbar">
    <input type="search" id="search" placeholder="Search by service name…" autocomplete="off">
    <button id="add-btn" class="btn primary">+ Add entry</button>
  </div>

  <form id="entry-form" class="card" hidden>
    <h2 id="entry-form-title">New entry</h2>
    <input type="hidden" id="entry-id" value="">
    <label>Service name *
      <input type="text" id="entry-service" required maxlength="128" placeholder="e.g. Gmail" autocomplete="off">
    </label>
    <label>Username (optional)
      <input type="text" id="entry-login" maxlength="128" placeholder="username for this service" autocomplete="off">
    </label>
    <label>Password *
      <span class="row">
        <input type="password" id="entry-password" required maxlength="256" placeholder="password" autocomplete="off">
        <button type="button" id="generate-btn" class="btn small" title="Generate a random password">Generate</button>
      </span>
    </label>
    <label>Note (optional)
      <input type="text" id="entry-note" maxlength="256" placeholder="e.g. same password as the portal" autocomplete="off">
    </label>
    <span class="row">
      <button type="submit" class="btn primary">Save</button>
      <button type="button" id="cancel-btn" class="btn">Cancel</button>
    </span>
    <p id="form-error" class="error" hidden></p>
  </form>

  <p id="list-status" class="muted">Loading…</p>
  <div id="entries" class="entries"></div>

  <div class="actions">
    <button id="clear-clipboard-btn" class="btn small">Clear clipboard</button>
  </div>
  <p class="hint">
    "Copy" puts the password on the clipboard. The clipboard is cleared automatically after 60 seconds
    or when the tab is closed. "Show" reveals the password for 10 seconds.
    The assistant never presses "Show" — only "Copy", so the password never appears on screen.
  </p>
  <p class="muted">Free service, no ads. If it helps you, <a href="<?= h(DONATE_URL) ?>" target="_blank" rel="noopener">support the project</a> — it keeps the vault running.</p>
</main>
<div id="toast" class="toast" hidden></div>
<?php page_foot(); ?>
