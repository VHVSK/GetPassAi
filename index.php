<?php
// Home: signed-in users go to the vault, guests see the landing page.
declare(strict_types=1);
require __DIR__ . '/common.php';

$user = current_user();
if ($user !== null) {
    header('Location: vault.php');
    exit;
}

$metaDescription = 'GetPassAi is a free, open-source password vault. Passwords are encrypted in your browser; your AI assistant copies them without ever seeing them. No email, no ads, no paywall.';
$extraHead = '<meta name="description" content="' . h($metaDescription) . '">' . "\n"
    . '<link rel="canonical" href="https://getpassai.com/">' . "\n"
    . '<meta property="og:title" content="GetPassAi — Free password vault your AI assistant can use without seeing your passwords">' . "\n"
    . '<meta property="og:description" content="' . h($metaDescription) . '">' . "\n"
    . '<meta property="og:type" content="website">' . "\n"
    . '<meta property="og:url" content="https://getpassai.com/">' . "\n"
    . '<script type="application/ld+json">' . "\n"
    . '{' . "\n"
    . '  "@context": "https://schema.org",' . "\n"
    . '  "@type": "SoftwareApplication",' . "\n"
    . '  "name": "GetPassAi",' . "\n"
    . '  "applicationCategory": "SecurityApplication",' . "\n"
    . '  "operatingSystem": "Web",' . "\n"
    . '  "description": "' . $metaDescription . '",' . "\n"
    . '  "url": "https://getpassai.com/",' . "\n"
    . '  "offers": { "@type": "Offer", "price": "0", "priceCurrency": "USD" },' . "\n"
    . '  "isAccessibleForFree": true,' . "\n"
    . '  "author": { "@type": "Person", "name": "Viktor Vyhivskyi" }' . "\n"
    . '}' . "\n"
    . '</script>' . "\n";

page_head('GetPassAi — Free password vault your AI assistant can use without seeing your passwords', 'home', $extraHead);
?>

<main class="wrap wide landing">
  <header class="hero">
    <div class="hero-text">
      <h1>🔐 GetPassAi</h1>
      <p class="hero-lead">Free password vault your AI assistant can use without seeing your passwords.</p>
      <p class="hero-cta">
        <a class="btn primary" href="register.php">Create free account</a>
        <a class="btn" href="#how-it-works">How it works</a>
      </p>
      <p class="muted">Free forever — no ads, no paywall, no email needed.</p>
    </div>

    <form id="login-form" class="card hero-signin" autocomplete="on">
      <h2>Sign in</h2>
      <label>Username
        <input type="text" name="username" autocomplete="username" required minlength="3" maxlength="64"
               placeholder="your username">
      </label>
      <label>Password
        <input type="password" name="password" autocomplete="current-password" required minlength="8" maxlength="128"
               placeholder="site password">
      </label>
      <p class="hint">The site password is also the encryption key. Don't forget it: without it, the entries cannot be decrypted.</p>
      <button type="submit" class="btn primary">Sign in</button>
      <p id="form-error" class="error" hidden></p>
      <p id="form-status" class="muted" hidden></p>
      <p class="muted">No account yet? <a href="register.php">Create one</a></p>
    </form>
  </header>

  <section id="how-it-works">
    <h2>How it works</h2>
    <div class="steps">
      <div class="card step">
        <h3>1. Create an account</h3>
        <p>No email needed. Your password becomes the encryption key for your vault — remember it, it cannot be recovered.</p>
      </div>
      <div class="card step">
        <h3>2. Save a service password</h3>
        <p>Add the service name and password. It is encrypted in your browser (AES-256-GCM) before it is sent to the server.</p>
      </div>
      <div class="card step">
        <h3>3. Your assistant presses Copy</h3>
        <p>The assistant opens the vault, finds the entry by service name and presses Copy — the password goes to the clipboard and is pasted into the app. It never appears on screen.</p>
      </div>
    </div>
  </section>

  <section id="security">
    <h2>Why it is safe</h2>
    <ul>
      <li>Passwords are encrypted in your browser (WebCrypto, AES-256-GCM) — the server stores only ciphertext: salt, IV and encrypted data.</li>
      <li>The encryption key is derived from your site password (PBKDF2-SHA256, 600,000 iterations) and lives only in the tab's sessionStorage.</li>
      <li>The clipboard clears itself automatically after 60 seconds or when the tab is closed.</li>
      <li>No email anywhere: registration and entries need no email, and pseudonyms are allowed.</li>
      <li>Open source (AGPLv3) — anyone can read the code and check it.</li>
    </ul>
    <p class="hint">Honest limits: the site password passes through the server at sign-in (checked as a hash, never stored in plain text), there is no account recovery yet if you forget it, and the code has not been independently audited.</p>
  </section>

  <section id="free">
    <h2>Free — what it means</h2>
    <p>Free forever: no ads, no paywall, no limits on entries, no premium plans. If the service helps you, you can <a href="<?= h(DONATE_URL) ?>" target="_blank" rel="noopener">support the project</a> with a voluntary donation — it changes nothing about access.</p>
  </section>

  <section id="faq">
    <h2>Frequently asked questions</h2>
    <div class="faq">
      <h3>Is it really free?</h3>
      <p>Yes. Free, no ads, no paywall, no premium plans. Donations are voluntary and change nothing about access.</p>
      <h3>What if I forget my password?</h3>
      <p>Honestly: the vault cannot be recovered. The server cannot reset your password and decrypt the data, because only you hold the key. Recovery keys are planned for a later phase. Remember your password and save it in the browser.</p>
      <h3>Has it been audited?</h3>
      <p>Not yet — there has been no independent security audit. The code is open source, so anyone can read and check it: <a href="https://github.com/VHVSK/GetPassAi">github.com/VHVSK/GetPassAi</a>.</p>
      <h3>Does the server see my passwords?</h3>
      <p>No. Service passwords are encrypted in your browser before they are sent; the server only stores ciphertext. The site password itself passes through the server at sign-in (checked as a hash, never stored in plain text) — a full zero-knowledge login (SRP) is planned.</p>
      <h3>Do I need an email?</h3>
      <p>No. Registration needs no email, entries need no email, and you may use a pseudonym.</p>
      <h3>How is it different from other similar services?</h3>
      <p>Other services are large universal vaults. GetPassAi is built for one scenario: letting an AI assistant use your passwords without ever seeing them.</p>
    </div>
  </section>

  <footer class="landing-footer">
    <p><a href="https://github.com/VHVSK/GetPassAi">GitHub</a> · <a href="https://github.com/VHVSK/GetPassAi/blob/main/SECURITY.md">Security</a> · <a href="<?= h(DONATE_URL) ?>" target="_blank" rel="noopener">Donate</a></p>
    <p class="muted"><a href="login.php">Sign in</a> · <a href="register.php">Create account</a></p>
  </footer>
</main>

<?php page_foot(); ?>
