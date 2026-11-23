'use strict';
/* Password Vault — client-side logic (encryption only in the browser).
 *
 * How it works:
 *  - Site password -> encryption key (PBKDF2-SHA256, 600,000 iterations,
 *    the user's kdf_salt). The key lives ONLY in the sessionStorage of the
 *    current tab: close the tab and the key is gone — you have to sign in
 *    again (the browser will fill in the username and password).
 *  - Every entry is encrypted separately: AES-256-GCM, random salt (16 bytes,
 *    used as additional data / AAD) and IV (12 bytes). The server stores only
 *    ciphertext + salt + IV in base64 — it never sees service names or passwords.
 *  - The password is NEVER printed to the console and never written to localStorage.
 *
 * Copying: the password goes browser -> clipboard -> app.
 * The clipboard is cleared automatically after COPY_CLEAR_SECONDS or when the
 * tab is closed/left (pagehide). We deliberately do NOT clear it when the tab
 * is merely hidden (visibilitychange): the assistant copies the password,
 * switches to the remote-access tab and pastes it — that takes time.
 */

const $ = (s, r = document) => r.querySelector(s);

const KEY_STORAGE = 'pv_key';
const PBKDF2_ITERATIONS = 600000;
const COPY_CLEAR_SECONDS = 60; // the assistant needs time to switch apps and reach the field
const SHOW_SECONDS = 10;

const te = new TextEncoder();
const td = new TextDecoder();

/* ---------- base64 ---------- */
function b64encode(bytes) {
  let s = '';
  bytes.forEach((b) => { s += String.fromCharCode(b); });
  return btoa(s);
}
function b64decode(str) {
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
function randomBytes(n) {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return a;
}

/* ---------- cryptography ---------- */
async function deriveMasterKey(password, kdfSaltB64) {
  const baseKey = await crypto.subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveKey']);
  // extractable: true — the raw key bytes must be saved to sessionStorage
  // before moving to vault.php. Key bytes are not the password; without the site password
  // a new key cannot be derived, and sessionStorage lives only in the tab.
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: b64decode(kdfSaltB64), iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

async function encryptEntry(masterKey, obj) {
  const salt = randomBytes(16); // additional data (AAD): binds the ciphertext to the entry
  const iv = randomBytes(12);
  const data = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: salt },
    masterKey,
    te.encode(JSON.stringify(obj))
  );
  return { salt: b64encode(salt), iv: b64encode(iv), data: b64encode(new Uint8Array(data)) };
}

async function decryptEntry(masterKey, entry) {
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64decode(entry.iv), additionalData: b64decode(entry.salt) },
    masterKey,
    b64decode(entry.data)
  );
  return JSON.parse(td.decode(plain));
}

/* ---------- API ---------- */
function csrfToken() {
  return document.querySelector('meta[name="csrf-token"]')?.content || '';
}

async function api(action, { method = 'GET', body = null } = {}) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch('api.php?action=' + encodeURIComponent(action), opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || ('Error ' + res.status));
  return data;
}

/* ---------- small UI helpers ---------- */
let toastTimer = null;
function toast(msg) {
  const el = $('#toast');
  if (!el) return;
  el.textContent = msg;
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, 4000);
}
function showError(msg) {
  const el = $('#form-error');
  if (!el) return;
  el.textContent = msg;
  el.hidden = false;
}
function showStatus(msg) {
  const el = $('#form-status');
  if (!el) return;
  el.textContent = msg;
  el.hidden = !msg;
}

/* ---------- clipboard ---------- */
let clearTimer = null;
function scheduleClipboardClear() {
  clearTimeout(clearTimer);
  clearTimer = setTimeout(clearClipboard, COPY_CLEAR_SECONDS * 1000);
}
async function clearClipboard() {
  try { await navigator.clipboard.writeText(''); } catch (e) { /* ignore */ }
}
// Clear only when the page is left/closed (pagehide),
// NOT when the tab is merely hidden — the assistant switches between tabs.
window.addEventListener('pagehide', () => { clearClipboard(); });

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch (e) {
    // Fallback for browsers without the Clipboard API.
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  }
  scheduleClipboardClear();
}

/* ---------- sign-in page ---------- */
async function handleLogin(e) {
  e.preventDefault();
  const form = e.target;
  const username = form.username.value.trim();
  const password = form.password.value;
  const btn = form.querySelector('button[type="submit"]');
  showError('');
  btn.disabled = true;
  try {
    if (!window.crypto?.subtle) throw new Error('This browser does not support WebCrypto. HTTPS or localhost is required.');
    showStatus('Deriving the encryption key… (this takes a few seconds)');
    const { salt } = await fetch('api.php?action=salt&username=' + encodeURIComponent(username))
      .then((r) => r.json());
    const masterKey = await deriveMasterKey(password, salt);
    const raw = await crypto.subtle.exportKey('raw', masterKey);
    showStatus('Checking username and password…');
    await api('login', { method: 'POST', body: { username, password, csrf_token: csrfToken() } });
    // The key lives only in the sessionStorage of the current tab.
    sessionStorage.setItem(KEY_STORAGE, b64encode(new Uint8Array(raw)));
    location.href = 'vault.php';
  } catch (err) {
    showError(err.message || 'Sign-in error.');
    showStatus('');
    btn.disabled = false;
  }
}

/* ---------- registration page ---------- */
async function handleRegister(e) {
  e.preventDefault();
  const form = e.target;
  const username = form.username.value.trim();
  const password = form.password.value;
  const password2 = form.password2.value;
  const btn = form.querySelector('button[type="submit"]');
  showError('');
  if (password !== password2) { showError('Passwords do not match.'); return; }
  if (password.length < 8) { showError('Password: at least 8 characters.'); return; }
  btn.disabled = true;
  try {
    if (!window.crypto?.subtle) throw new Error('This browser does not support WebCrypto. HTTPS or localhost is required.');
    const kdfSalt = b64encode(randomBytes(16));
    await api('register', {
      method: 'POST',
      body: { username, password, kdf_salt: kdfSalt, csrf_token: csrfToken() },
    });
    location.href = 'login.php?registered=1';
  } catch (err) {
    showError(err.message || 'Registration error.');
    btn.disabled = false;
  }
}

/* ---------- vault page ---------- */
let masterKey = null;
let entries = []; // decrypted: {id, service, login, password, note, created_at}

async function initVault() {
  if (!window.crypto?.subtle) {
    $('#crypto-warning').hidden = false;
    $('#list-status').textContent = 'WebCrypto is not available.';
    return;
  }
  const rawB64 = sessionStorage.getItem(KEY_STORAGE);
  if (!rawB64) {
    // The key lives only in the tab. No key — sign in again.
    location.href = 'login.php?need_login=1';
    return;
  }
  try {
    masterKey = await crypto.subtle.importKey('raw', b64decode(rawB64), { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  } catch (e) {
    sessionStorage.removeItem(KEY_STORAGE);
    location.href = 'login.php?need_login=1';
    return;
  }
  bindVaultUI();
  await loadEntries();
}

function bindVaultUI() {
  $('#search').addEventListener('input', () => renderEntries());
  $('#add-btn').addEventListener('click', () => openEntryForm(null));
  $('#cancel-btn').addEventListener('click', () => closeEntryForm());
  $('#entry-form').addEventListener('submit', handleSaveEntry);
  $('#generate-btn').addEventListener('click', () => {
    const field = $('#entry-password');
    field.value = generatePassword(16);
    field.type = 'text'; // show the generated password (a human fills in this form)
  });
  $('#logout-btn').addEventListener('click', handleLogout);
  $('#clear-clipboard-btn').addEventListener('click', async () => {
    await clearClipboard();
    toast('Clipboard cleared.');
  });
}

function generatePassword(len) {
  const chars = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789!@#$%&*';
  const rnd = randomBytes(len);
  let out = '';
  for (let i = 0; i < len; i++) out += chars[rnd[i] % chars.length];
  return out;
}

async function handleLogout() {
  try { await clearClipboard(); } catch (e) { /* ignore */ }
  sessionStorage.removeItem(KEY_STORAGE);
  try {
    await api('logout', { method: 'POST', body: { csrf_token: csrfToken() } });
  } catch (e) { /* the session will be destroyed via logout.php anyway */ }
  location.href = 'login.php';
}

async function loadEntries() {
  $('#list-status').textContent = 'Loading…';
  try {
    const { entries: blobs } = await api('list');
    entries = [];
    for (const b of blobs) {
      try {
        const obj = await decryptEntry(masterKey, b);
        entries.push({ id: b.id, service: obj.service || '', login: obj.login || '', password: obj.password || '', note: obj.note || '', created_at: b.created_at });
      } catch (e) {
        console.warn('Could not decrypt entry', b.id);
      }
    }
    renderEntries();
  } catch (err) {
    if ((err.message || '').includes('Sign-in required')) {
      location.href = 'login.php?need_login=1';
      return;
    }
    $('#list-status').textContent = 'Error: ' + err.message;
  }
}

function renderEntries() {
  const q = ($('#search').value || '').trim().toLowerCase();
  const list = $('#entries');
  list.textContent = '';
  const shown = entries.filter((en) =>
    !q || en.service.toLowerCase().includes(q) || (en.login || '').toLowerCase().includes(q));
  $('#list-status').textContent = shown.length
    ? 'Entries: ' + shown.length
    : (entries.length ? 'Nothing found.' : 'No entries yet. Add your first entry.');
  for (const en of shown) {
    list.appendChild(entryCard(en));
  }
}

function entryCard(en) {
  const card = document.createElement('div');
  card.className = 'entry';

  const service = document.createElement('div');
  service.className = 'entry-service';
  service.textContent = en.service;
  card.appendChild(service);

  if (en.login) {
    const login = document.createElement('div');
    login.className = 'entry-login';
    login.textContent = 'Username: ' + en.login;
    card.appendChild(login);
  }

  const pass = document.createElement('div');
  pass.className = 'entry-password';
  pass.textContent = '••••••••';
  card.appendChild(pass);

  if (en.note) {
    const note = document.createElement('div');
    note.className = 'entry-note';
    note.textContent = en.note;
    card.appendChild(note);
  }

  const actions = document.createElement('div');
  actions.className = 'entry-actions';

  const copyBtn = document.createElement('button');
  copyBtn.className = 'btn small primary';
  copyBtn.textContent = 'Copy';
  copyBtn.addEventListener('click', async () => {
    await copyText(en.password);
    toast('Password copied. The clipboard will be cleared in ' + COPY_CLEAR_SECONDS + ' s.');
  });
  actions.appendChild(copyBtn);

  const showBtn = document.createElement('button');
  showBtn.className = 'btn small';
  showBtn.textContent = 'Show';
  let hideTimer = null;
  showBtn.addEventListener('click', () => {
    if (showBtn.textContent === 'Show') {
      // NOTE: the plain-text password is visible on screen. The assistant never presses this button.
      pass.textContent = en.password;
      showBtn.textContent = 'Hide';
      clearTimeout(hideTimer);
      hideTimer = setTimeout(() => {
        pass.textContent = '••••••••';
        showBtn.textContent = 'Show';
      }, SHOW_SECONDS * 1000);
    } else {
      clearTimeout(hideTimer);
      pass.textContent = '••••••••';
      showBtn.textContent = 'Show';
    }
  });
  actions.appendChild(showBtn);

  const editBtn = document.createElement('button');
  editBtn.className = 'btn small';
  editBtn.textContent = 'Edit';
  editBtn.addEventListener('click', () => openEntryForm(en));
  actions.appendChild(editBtn);

  const delBtn = document.createElement('button');
  delBtn.className = 'btn small danger';
  delBtn.textContent = 'Delete';
  delBtn.addEventListener('click', async () => {
    if (!confirm('Delete the entry "' + en.service + '"?')) return;
    try {
      await api('delete', { method: 'POST', body: { id: en.id, csrf_token: csrfToken() } });
      await loadEntries();
      toast('Entry deleted.');
    } catch (err) {
      toast('Error: ' + err.message);
    }
  });
  actions.appendChild(delBtn);

  card.appendChild(actions);
  return card;
}

function openEntryForm(en) {
  const form = $('#entry-form');
  $('#entry-form-title').textContent = en ? 'Edit entry' : 'New entry';
  $('#entry-id').value = en ? String(en.id) : '';
  $('#entry-service').value = en ? en.service : '';
  $('#entry-login').value = en ? (en.login || '') : '';
  $('#entry-password').value = en ? en.password : '';
  $('#entry-password').type = 'password';
  $('#entry-note').value = en ? (en.note || '') : '';
  $('#form-error').hidden = true;
  form.hidden = false;
  form.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  $('#entry-service').focus();
}

function closeEntryForm() {
  $('#entry-form').hidden = true;
  $('#entry-id').value = '';
}

async function handleSaveEntry(e) {
  e.preventDefault();
  const service = $('#entry-service').value.trim();
  const login = $('#entry-login').value.trim();
  const password = $('#entry-password').value;
  const note = $('#entry-note').value.trim();
  const id = $('#entry-id').value ? parseInt($('#entry-id').value, 10) : 0;
  if (!service || !password) { showError('Please fill in the service name and password.'); return; }
  try {
    const blob = await encryptEntry(masterKey, { service, login, password, note });
    const body = { ...blob, csrf_token: csrfToken() };
    if (id) body.id = id;
    await api('save', { method: 'POST', body });
    closeEntryForm();
    await loadEntries();
    toast('Entry saved.');
  } catch (err) {
    showError(err.message || 'Could not save the entry.');
  }
}

/* ---------- startup ---------- */
document.addEventListener('DOMContentLoaded', () => {
  const page = document.body.dataset.page;
  if (page === 'login' || page === 'home') $('#login-form')?.addEventListener('submit', handleLogin);
  if (page === 'register') $('#register-form')?.addEventListener('submit', handleRegister);
  if (page === 'vault') initVault();
});
