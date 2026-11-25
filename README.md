# Password Vault

A free site for storing service names and passwords — for everyone,
no ads, no paywall. Voluntary donations keep it running:
https://donatello.to/ViktorVyhivskyi

It started as a small personal tool: I use an AI assistant for everyday work, and it often needs to sign in to websites and apps on my behalf. I didn't want to paste passwords into chats or type them myself every time — so I built a vault where the assistant can copy a password without ever seeing it. Since 2026-11-21 it is a free public service.

The main idea: an assistant (an AI helper) can enter a password into an
app (for example, a webmail or a work system) **without seeing the
password itself**. It opens the site in a browser, finds the password by
service name, presses "Copy" and pastes the password into the app's form.
The password travels only inside the device: browser → clipboard → app.

## 2026-11-21 update (v1.1)

- **Free public service.** Registration is open to everyone
  (`ALLOW_REGISTRATION => true` in `config.php`); donations are
  voluntary and change nothing about access. A "Support this project"
  link (Donatello) is on the sign-in, registration and vault pages.
  Live at https://getpassai.com.
- **Security headers.** `Content-Security-Policy` (strict, `'self'`
  only — no inline scripts, no external resources),
  `Strict-Transport-Security` (HTTPS only), `Permissions-Policy`
  (camera/microphone/geolocation/payment off), plus the earlier
  `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`.
- **New design.** Simple, restrained, modern stylesheet
  (`assets/style.css`): system fonts, one accent color, clean cards
  and forms, dark theme via `prefers-color-scheme`, mobile-friendly.
- **Security plan.** Full improvement + audit plan:
  `security-plan-2026-11-21.md` (not part of the deployed site).
  Verdict: no critical vulnerabilities found in the code; the main
  risks are architectural — SRP sign-in is done (phase 3, the server
  never sees the site password), and there is no account recovery yet
  (phase 4).

## How it is safe (threat model)

- **The server stores only ciphertext.** Service names, usernames and
  passwords are encrypted in the browser (WebCrypto, AES-256-GCM) before
  being sent. The server only receives: salt, IV and encrypted data
  (base64). A hosting admin, or anyone who gets the database, will see
  only unreadable strings.
- **The encryption key is derived in the browser** from the site password
  (PBKDF2-SHA256, 600,000 iterations, per-user salt). The key lives only
  in the `sessionStorage` of the current tab: close the tab and the key
  is gone — you have to sign in again (the browser will fill in the
  username and password).
- **The password is never shown in plain text** while the assistant is
  working: in the list it is masked (••••••••), and there is only a
  "Copy" button. The "Show" button reveals the password for 10 seconds —
  only a human presses it, never the assistant.
- **The clipboard clears itself** automatically after 60 seconds or when
  the tab is closed. 60 seconds (not 15) is deliberate: the assistant
  needs time to switch to the app tab and reach the password field.
  The time can be changed with the
  `COPY_CLEAR_SECONDS` constant in `assets/app.js`.

Honest limitations (important to understand):

- The site password **is sent to the server** (over HTTPS) at sign-in —
  the server checks its hash (Argon2id or bcrypt). The server never
  stores or logs the plain-text password, but during sign-in it passes
  through the server. This is the ordinary "username + password" scheme,
  not full zero-knowledge like SRP.
- **If you forget the site password, the entries cannot be recovered.**
  The server cannot reset the password and decrypt the data. Remember
  the password and save it in the browser.
- After pasting the password into another app, the password stays
  in the device clipboard until something else replaces it. After
  pasting, copy something harmless there
  (for example, the username) to overwrite the password in the clipboard.
- The "Show" button exists for humans. If the password ever appears on
  screen in plain text while the assistant is taking screenshots, a
  screenshot will capture it. The assistant never presses this button.

## Files

```
index.php            — home: landing page with a sign-in form for guests; signed-in users go to the vault
login.php            — sign-in page
register.php         — registration page
logout.php           — sign-out
vault.php            — vault page (search, list, add entry)
api.php              — JSON API: salt, register, login, logout, list, save, delete
common.php           — session, database (PDO), CSRF, security headers
config.php.example   — example settings (copy to config.php)
schema.sql           — database schema (users, vault_entries, login_attempts)
assets/app.js        — browser logic: WebCrypto, search, copying
assets/style.css     — styling (mobile-friendly)
README.md            — this file
```

## Deploying on standard PHP hosting

1. **Subdomain and HTTPS.** Create a subdomain (for example,
   `passwords.your-domain.ua`). Enable HTTPS (Let's Encrypt on the
   hosting — usually one click). **Without HTTPS the site will not work**:
   browser encryption (WebCrypto) is only available over HTTPS or
   localhost.
2. **Database.** Create a MySQL database and a user with rights to it
   (hosting panel → MySQL). Remember the database name, username and
   password.
3. **Import the schema.** In phpMyAdmin open the database → "Import" →
   choose `schema.sql` → run. The tables `users`, `vault_entries`,
   `login_attempts` will be created.
4. **Settings.** Copy `config.php.example` to `config.php` and fill in
   `DB_HOST`, `DB_NAME`, `DB_USER`, `DB_PASS`.
   Leave `ALLOW_REGISTRATION` as `true` until everyone has registered.
5. **Upload the files.** Upload all files to the subdomain root
   (via FTP or the hosting file manager). Make sure `config.php` sits
   next to `index.php`.
6. **Registration.** Open the site, register the first user, then
   other users register their own accounts from their own devices.
   Each user has **their own** account and **their own** entries (one
   user's entries are not visible to the other).
7. **Turn off registration.** After everyone has registered, set
   `'ALLOW_REGISTRATION' => false` in `config.php` — so no stranger
   can create an account.
8. **Save the sign-in in the browser.** Sign in to the site and save
   the username and password in the browser — afterwards sign-in will
   be filled in automatically.

## How to use it (assistant flow)

1. The assistant opens the site in a browser (sign-in is filled in
   from the browser) and finds the entry by service name
   (for example, `Gmail`).
2. It presses "Copy" — the password goes to the device clipboard.
3. It switches to the app, clicks the password field and presses Ctrl+V.
4. The clipboard clears itself after 60 seconds or when the tab is
   closed. Additionally: after pasting, copy something harmless to
   overwrite the password in the clipboard.
5. The assistant **never** presses "Show" and never opens the edit
   form — only "Copy".

## What to check after deploying

- [ ] The site opens over HTTPS; the sign-in / registration / vault
      pages return 200; the API without sign-in returns 401.
- [ ] Registration and sign-in work on the real MySQL database.
- [ ] Adding, searching, copying, editing and deleting an entry.
- [ ] After closing the tab the key is gone and the site asks to sign
      in again.
- [ ] **Paste test**: a copied password pastes
      (Ctrl+V) into the target app's password field.
- [ ] Turn off registration (`ALLOW_REGISTRATION => false`) after
      everyone has registered.

## Requirements

- PHP 8.0+ with PDO and pdo_mysql extensions (standard hosting has them).
- MySQL 5.7+ / MariaDB 10.2+.
- HTTPS (required).
- A modern browser with WebCrypto (Firefox/Chrome).
