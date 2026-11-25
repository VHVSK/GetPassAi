// SRP-6a client (RFC 5054 + RFC 2945), SHA-256, 2048-bit group.
// Mirrors srp.php exactly — same formulas, same padding, same byte order.
// Loaded as a classic script: sets globalThis.SrpClient (window.SrpClient
// in the browser). Node can `import` this file directly for tests.
// Requires a secure context (crypto.subtle): HTTPS or localhost.
// The password never leaves this file: only x, A and M1 are computed
// from it, and none of them reveals it.
//
// Protocol recap (H = SHA-256, PAD = left-pad with zero bytes to N length):
//   k  = H(N || PAD(g))
//   x  = H(salt || H(username || ":" || password))
//   A  = g^a % N                          (a random, 256 bit)
//   u  = H(PAD(A) || PAD(B))
//   S  = (B - k*g^x)^(a + u*x) % N
//   K  = H(PAD(S))
//   M1 = H( (H(N) XOR H(g)) || H(username) || salt || PAD(A) || PAD(B) || K )
//   M2 = H( PAD(A) || M1 || K )
'use strict';

const SRP_N_2048_HEX = 'AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73';
const SRP_G = 2n;

function srpHexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error('SRP: bad hex');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

function srpBytesToHex(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function srpBytesToBigInt(bytes) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return n;
}

function srpBigIntToBytes(n, len) {
  let hex = n.toString(16);
  if (hex.length % 2 !== 0) hex = '0' + hex;
  hex = hex.padStart(len * 2, '0');
  if (hex.length > len * 2) throw new Error('SRP: number does not fit');
  return srpHexToBytes(hex);
}

function srpConcat(...parts) {
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

function srpPad(bytes, len) {
  if (bytes.length > len) throw new Error('SRP: value longer than N');
  const out = new Uint8Array(len);
  out.set(bytes, len - bytes.length);
  return out;
}

function srpModPow(base, exp, mod) {
  let b = ((base % mod) + mod) % mod;
  let e = exp;
  let r = 1n;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % mod;
    e >>= 1n;
    b = (b * b) % mod;
  }
  return r;
}

function srpRandomBytes(n) {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

/**
 * params: { hash: 'SHA-256' | 'SHA-1' (tests only), N: hex string }
 * The defaults are the production values (SHA-256, RFC 5054 2048-bit group).
 */
class SrpClient {
  constructor(username, password, saltHex, params = {}) {
    this.hash = params.hash || 'SHA-256';
    this.Nhex = (params.N || SRP_N_2048_HEX).toLowerCase();
    this.N = srpBytesToBigInt(srpHexToBytes(this.Nhex));
    this.Nbytes = this.Nhex.length / 2;
    this.g = SRP_G;
    this.username = username;
    this.password = password;
    this.salt = srpHexToBytes(saltHex);
    this.a = null;
    this.A = null;
    this.Ahex = null;
    this.Bhex = null;
    this.K = null;   // Uint8Array
    this.M1hex = null;
    if (!globalThis.crypto || !globalThis.crypto.subtle) {
      throw new Error('SRP: WebCrypto is not available (HTTPS or localhost required)');
    }
  }

  async _hash(data) {
    return new Uint8Array(await globalThis.crypto.subtle.digest(this.hash, data));
  }

  /** k = H(N || PAD(g)); public, computed locally from the constants. */
  async _k() {
    const Nbytes = srpHexToBytes(this.Nhex);
    const gBytes = srpPad(new Uint8Array([2]), this.Nbytes);
    return srpBytesToBigInt(await this._hash(srpConcat(Nbytes, gBytes)));
  }

  /** x = H(salt || H(username || ":" || password)). */
  async _x() {
    const enc = new TextEncoder();
    const inner = await this._hash(enc.encode(this.username + ':' + this.password));
    return srpBytesToBigInt(await this._hash(srpConcat(this.salt, inner)));
  }

  /** Step 1: A = g^a % N. Returns A as full-length padded hex. */
  async step1() {
    if (this.a === null) this.a = srpBytesToBigInt(srpRandomBytes(32));
    this.A = srpModPow(this.g, this.a, this.N);
    this.Ahex = srpBytesToHex(srpBigIntToBytes(this.A, this.Nbytes));
    return this.Ahex;
  }

  /** Tests only: fix the client private value instead of a random one. */
  setPrivateA(aHex) {
    if (this.Ahex !== null) throw new Error('SRP: too late to set a');
    this.a = srpBytesToBigInt(srpHexToBytes(aHex));
  }

  /** Step 2: receive B, compute S and K. Throws on B % N == 0. */
  async setChallenge(Bhex) {
    if (this.Ahex === null) throw new Error('SRP: no A yet');
    this.Bhex = Bhex.toLowerCase();
    const B = srpBytesToBigInt(srpHexToBytes(this.Bhex));
    if (B % this.N === 0n) throw new Error('SRP: B % N == 0');
    const Abytes = srpHexToBytes(this.Ahex);
    const Bbytes = srpHexToBytes(this.Bhex);
    const u = srpBytesToBigInt(await this._hash(srpConcat(srpPad(Abytes, this.Nbytes), srpPad(Bbytes, this.Nbytes))));
    const x = await this._x();
    const k = await this._k();
    const gx = srpModPow(this.g, x, this.N);
    let base = (B - k * gx) % this.N;
    if (base < 0n) base += this.N;
    const exp = this.a + u * x;
    const S = srpModPow(base, exp, this.N);
    this.K = await this._hash(srpBigIntToBytes(S, this.Nbytes));
  }

  /** The client proof M1. Returns hex. */
  async computeM1() {
    if (this.K === null) throw new Error('SRP: no challenge yet');
    const enc = new TextEncoder();
    const hN = await this._hash(srpHexToBytes(this.Nhex));
    const hg = await this._hash(srpPad(new Uint8Array([2]), this.Nbytes));
    const xored = hN.map((b, i) => b ^ hg[i]);
    const hI = await this._hash(enc.encode(this.username));
    const M1 = await this._hash(srpConcat(
      xored, hI, this.salt,
      srpPad(srpHexToBytes(this.Ahex), this.Nbytes),
      srpPad(srpHexToBytes(this.Bhex), this.Nbytes),
      this.K
    ));
    this.M1hex = srpBytesToHex(M1);
    return this.M1hex;
  }

  /** Check the server proof M2. */
  async verifyM2(M2hex) {
    if (this.M1hex === null || this.K === null) throw new Error('SRP: no M1 yet');
    const M2 = await this._hash(srpConcat(
      srpPad(srpHexToBytes(this.Ahex), this.Nbytes),
      srpHexToBytes(this.M1hex),
      this.K
    ));
    const expected = srpBytesToHex(M2).toLowerCase();
    return expected === String(M2hex).toLowerCase();
  }

  /** Session key K as hex. */
  getSessionKeyHex() {
    return this.K === null ? null : srpBytesToHex(this.K);
  }

  /** v = g^x % N, for registration. Returns hex. */
  async computeVerifier() {
    const x = await this._x();
    return srpBytesToHex(srpBigIntToBytes(srpModPow(this.g, x, this.N), this.Nbytes));
  }

  /** Fresh random salt, 16 bytes, as hex. */
  static randomSaltHex() {
    return srpBytesToHex(srpRandomBytes(16));
  }
}

globalThis.SrpClient = SrpClient;
