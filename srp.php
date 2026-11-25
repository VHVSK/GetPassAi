<?php
// SRP-6a server + client (RFC 5054 + RFC 2945) — clean-room implementation.
//
// Protocol (hash H = SHA-256 in production; SHA-1 only to run the
// RFC 5054 Appendix B test vectors):
//   N  — 2048-bit safe prime, RFC 5054 Appendix A section 3; g = 2
//   k  = H(N || PAD(g))                    N and g as bytes, g padded to N length
//   x  = H(s || H(I || ":" || P))          s = salt bytes, I = username
//   v  = g^x % N                           verifier, stored on the server
//   A  = g^a % N                           client public value, a random >= 256 bit
//   B  = (k*v + g^b) % N                   server public value, b random >= 256 bit
//   u  = H(PAD(A) || PAD(B))
//   S  = (B - k*g^x)^(a + u*x) % N         client
//   S  = (A * v^u)^b % N                   server
//   K  = H(PAD(S))                         session key
//   M1 = H( (H(N) XOR H(g)) || H(I) || s || PAD(A) || PAD(B) || K )
//   M2 = H( PAD(A) || M1 || K )
// PAD(x) left-pads a byte string with zero bytes to the length of N.
// H(N), H(g): N as its full-length bytes, g padded to N length (documented
// convention — both sides must agree, and the JS client uses the same one).
// K = H(PAD(S)): SHA_Interleave from RFC 2945 is SHA-1-specific (it stretches
// a 160-bit hash to 320 bits); with SHA-256 the standard construction is K = H(S).
//
// A and B travel as full-length padded lowercase hex (N_bytes * 2 chars).
// The server refuses a challenge or a proof twice (one-shot state) and
// aborts on A % N == 0 / B % N == 0 with a real integer comparison —
// the thinbus library compared a BigInteger object with === 0, which
// never fires (see srp-review-2026-11-25.md).

declare(strict_types=1);

const SRP_N_2048 = 'AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73';
const SRP_G = '2';

/** Parameters for one SRP run. $nHex is hex (default: the 2048-bit group). */
function srp_params(string $hash = 'sha256', ?string $nHex = null): array
{
    // Accept WebCrypto spellings too ('SHA-256', 'SHA-1') — the JS client
    // and the test harness use those.
    $hash = strtolower(str_replace('-', '', $hash));
    if (!in_array($hash, ['sha1', 'sha256'], true)) {
        throw new InvalidArgumentException('SRP hash must be sha1 or sha256');
    }
    $nHex = strtolower($nHex ?? SRP_N_2048);
    if (!preg_match('/^[0-9a-f]+$/', $nHex) || strlen($nHex) % 2 !== 0) {
        throw new InvalidArgumentException('SRP N must be even-length hex');
    }
    $nBytes = (int) (strlen($nHex) / 2);
    // k = H(N || PAD(g))
    $k = hash($hash, hex2bin($nHex) . str_pad(hex2bin('02'), $nBytes, "\x00", STR_PAD_LEFT), true);
    return ['hash' => $hash, 'N' => $nHex, 'g' => SRP_G, 'N_bytes' => $nBytes, 'k' => bin2hex($k)];
}

/* ---------- big numbers: GMP if present, else BCMath ---------- */

function srp_bn_backend(): string
{
    static $backend = null;
    if ($backend === null) {
        $backend = function_exists('gmp_init') ? 'gmp'
            : (function_exists('bcpowmod') ? 'bcmath' : 'none');
        if ($backend === 'none') {
            throw new RuntimeException('SRP needs the GMP or BCMath PHP extension');
        }
    }
    return $backend;
}

function srp_bc_hex2dec(string $hex): string
{
    $dec = '0';
    $len = strlen($hex);
    for ($i = 0; $i < $len; $i++) {
        $dec = bcadd(bcmul($dec, '16'), (string) hexdec($hex[$i]));
    }
    return $dec;
}

function srp_bc_dec2hex(string $dec): string
{
    if ($dec === '0') {
        return '0';
    }
    $hex = '';
    while (bccomp($dec, '0') > 0) {
        $hex = dechex((int) bcmod($dec, '16')) . $hex;
        $dec = bcdiv($dec, '16', 0);
    }
    return $hex;
}

/** Hex string -> backend number. */
function srp_bn_from_hex(string $hex)
{
    if (srp_bn_backend() === 'gmp') {
        return gmp_init($hex, 16);
    }
    return srp_bc_hex2dec($hex);
}

/** Raw bytes (big-endian) -> backend number. */
function srp_bn_from_bytes(string $bytes)
{
    return srp_bn_from_hex(bin2hex($bytes));
}

function srp_bn_from_dec(string $dec)
{
    if (srp_bn_backend() === 'gmp') {
        return gmp_init($dec, 10);
    }
    return $dec;
}

/** Backend number -> lowercase hex, no leading zeros ('0' for zero). */
function srp_bn_to_hex($n): string
{
    if (srp_bn_backend() === 'gmp') {
        return strtolower(gmp_strval($n, 16));
    }
    return srp_bc_dec2hex($n);
}

/** Backend number -> raw bytes, left-padded with zero bytes to $len. */
function srp_bn_to_bytes($n, int $len): string
{
    $hex = str_pad(srp_bn_to_hex($n), $len * 2, '0', STR_PAD_LEFT);
    if (strlen($hex) > $len * 2) {
        throw new RuntimeException('SRP number does not fit in the requested length');
    }
    return hex2bin($hex);
}

function srp_bn_mod($a, $m)
{
    if (srp_bn_backend() === 'gmp') {
        return gmp_mod($a, $m);
    }
    $r = bcmod($a, $m);
    if (bccomp($r, '0') < 0) {
        $r = bcadd($r, $m);
    }
    return $r;
}

function srp_bn_mul($a, $b)
{
    return srp_bn_backend() === 'gmp' ? gmp_mul($a, $b) : bcmul($a, $b);
}

function srp_bn_add($a, $b)
{
    return srp_bn_backend() === 'gmp' ? gmp_add($a, $b) : bcadd($a, $b);
}

function srp_bn_sub($a, $b)
{
    return srp_bn_backend() === 'gmp' ? gmp_sub($a, $b) : bcsub($a, $b);
}

/** (base ^ exp) % mod; the base is reduced mod $mod first (never negative). */
function srp_bn_powmod($base, $exp, $mod)
{
    $base = srp_bn_mod($base, $mod);
    if (srp_bn_backend() === 'gmp') {
        return gmp_powm($base, $exp, $mod);
    }
    return bcpowmod($base, $exp, $mod);
}

/** -1, 0 or 1, like strcmp. */
function srp_bn_cmp($a, $b): int
{
    if (srp_bn_backend() === 'gmp') {
        return gmp_cmp($a, $b);
    }
    return bccomp($a, $b);
}

function srp_bn_is_zero($n): bool
{
    return srp_bn_cmp($n, srp_bn_from_dec('0')) === 0;
}

/* ---------- validation helpers ---------- */

/** Lowercase even-length hex, or null when invalid. $maxLen is in characters. */
function srp_clean_hex($s, int $maxLen): ?string
{
    if (!is_string($s) || $s === '' || strlen($s) > $maxLen) {
        return null;
    }
    if (!preg_match('/^[0-9a-fA-F]+$/', $s)) {
        return null;
    }
    if (strlen($s) % 2 !== 0) {
        $s = '0' . $s;
    }
    return strtolower($s);
}

/** Hash raw bytes, returns raw bytes. */
function srp_hash(string $algo, string $data): string
{
    return hash($algo, $data, true);
}

/** Left-pad a byte string with zero bytes to $len. */
function srp_pad(string $bytes, int $len): string
{
    if (strlen($bytes) > $len) {
        throw new RuntimeException('SRP value longer than N');
    }
    return str_pad($bytes, $len, "\x00", STR_PAD_LEFT);
}

/* ---------- core SRP-6a ---------- */

/** x = H(s || H(I || ":" || P)); returns hex of the hash bytes. */
function srp_compute_x(string $saltHex, string $username, string $password, array $p): string
{
    $inner = srp_hash($p['hash'], $username . ':' . $password);
    return bin2hex(srp_hash($p['hash'], hex2bin($saltHex) . $inner));
}

/** v = g^x % N; returns hex, padded to the full length of N. */
function srp_compute_verifier(string $xHex, array $p): string
{
    $N = srp_bn_from_hex($p['N']);
    $g = srp_bn_from_dec($p['g']);
    $x = srp_bn_from_hex($xHex);
    $v = srp_bn_powmod($g, $x, $N);
    return bin2hex(srp_bn_to_bytes($v, $p['N_bytes']));
}

/** 256-bit private value (a or b) as hex. */
function srp_random_private(): string
{
    return bin2hex(random_bytes(32));
}

/** u = H(PAD(A) || PAD(B)); A and B are full-length padded hex. Returns hex. */
function srp_compute_u(string $aHex, string $bHex, array $p): string
{
    return bin2hex(srp_hash($p['hash'], hex2bin($aHex) . hex2bin($bHex)));
}

/** K = H(PAD(S)); S is a backend number. Returns raw bytes. */
function srp_compute_K($S, array $p): string
{
    return srp_hash($p['hash'], srp_bn_to_bytes($S, $p['N_bytes']));
}

/**
 * M1 = H( (H(N) XOR H(g)) || H(I) || s || PAD(A) || PAD(B) || K ).
 * A and B are full-length padded hex, K is raw bytes. Returns hex.
 */
function srp_compute_M1(string $username, string $saltHex, string $aHex, string $bHex, string $Kbytes, array $p): string
{
    $hN = srp_hash($p['hash'], hex2bin($p['N']));
    $hg = srp_hash($p['hash'], srp_pad(hex2bin('02'), $p['N_bytes']));
    $data = ($hN ^ $hg)
        . srp_hash($p['hash'], $username)
        . hex2bin($saltHex)
        . hex2bin($aHex)
        . hex2bin($bHex)
        . $Kbytes;
    return bin2hex(srp_hash($p['hash'], $data));
}

/** M2 = H(PAD(A) || M1 || K). M1 is hex, K is raw bytes. Returns hex. */
function srp_compute_M2(string $aHex, string $M1hex, string $Kbytes, array $p): string
{
    return bin2hex(srp_hash($p['hash'], hex2bin($aHex) . hex2bin($M1hex) . $Kbytes));
}

/* ---------- server side ---------- */

class SrpServer
{
    private array $p;
    private $N;
    private $g;
    private $k;
    private ?string $username = null;
    private ?string $saltHex = null;
    private $v = null;
    private $b = null;
    private $B = null;
    private ?string $Bhex = null;
    private ?string $Khex = null;
    private int $step = 0;

    public function __construct(array $params)
    {
        $this->p = $params;
        $this->N = srp_bn_from_hex($params['N']);
        $this->g = srp_bn_from_dec($params['g']);
        $this->k = srp_bn_from_hex($params['k']);
    }

    /** Tests only: fix the server private value instead of a random one. */
    public function setPrivateB(string $bHex): void
    {
        if ($this->step !== 0) {
            throw new RuntimeException('SRP: too late to set b');
        }
        $this->b = srp_bn_from_hex($bHex);
    }

    /**
     * Step 1: issue the challenge B. Returns B as full-length padded hex.
     * One-shot: a second call throws.
     */
    public function challenge(string $username, string $saltHex, string $verifierHex): string
    {
        if ($this->step !== 0) {
            throw new RuntimeException('SRP: challenge already issued');
        }
        $saltHex = srp_clean_hex($saltHex, 64);
        $verifierHex = srp_clean_hex($verifierHex, $this->p['N_bytes'] * 2);
        if ($saltHex === null || $verifierHex === null || $username === '') {
            throw new InvalidArgumentException('SRP: bad challenge input');
        }
        $v = srp_bn_from_hex($verifierHex);
        if (srp_bn_is_zero($v) || srp_bn_cmp($v, $this->N) >= 0) {
            throw new InvalidArgumentException('SRP: bad verifier');
        }
        $this->username = $username;
        $this->saltHex = $saltHex;
        $this->v = $v;
        if ($this->b === null) {
            $this->b = srp_bn_from_bytes(random_bytes(32));
        }
        // B = (k*v + g^b) % N; re-roll b if B % N == 0 (vanishingly unlikely).
        do {
            $gb = srp_bn_powmod($this->g, $this->b, $this->N);
            $B = srp_bn_mod(srp_bn_add(srp_bn_mul($this->k, $v), $gb), $this->N);
            if (srp_bn_is_zero($B)) {
                $this->b = srp_bn_from_bytes(random_bytes(32));
            }
        } while (srp_bn_is_zero($B));
        $this->B = $B;
        $this->Bhex = bin2hex(srp_bn_to_bytes($B, $this->p['N_bytes']));
        $this->step = 1;
        return $this->Bhex;
    }

    /**
     * Step 2: verify the client proof M1. Returns M2 as hex, or throws.
     * One-shot: the state is cleared either way, so a proof cannot be replayed.
     */
    public function verify(string $Ahex, string $M1hex): string
    {
        if ($this->step !== 1) {
            throw new RuntimeException('SRP: no challenge issued');
        }
        $this->step = 2;
        $hashLen = strlen(hash($this->p['hash'], '', false)); // hex chars: 40 / 64
        $Ahex = srp_clean_hex($Ahex, $this->p['N_bytes'] * 2);
        $M1hex = srp_clean_hex($M1hex, $hashLen);
        if ($Ahex === null || $M1hex === null) {
            throw new InvalidArgumentException('SRP: bad proof input');
        }
        $A = srp_bn_from_hex($Ahex);
        // Real integer comparison — A % N == 0 must abort (thinbus got this wrong).
        if (srp_bn_is_zero(srp_bn_mod($A, $this->N))) {
            throw new RuntimeException('SRP: A % N == 0');
        }
        $u = srp_bn_from_hex(srp_compute_u($Ahex, $this->Bhex, $this->p));
        $vu = srp_bn_powmod($this->v, $u, $this->N);
        $S = srp_bn_powmod(srp_bn_mod(srp_bn_mul($A, $vu), $this->N), $this->b, $this->N);
        $K = srp_compute_K($S, $this->p);
        $expectedM1 = srp_compute_M1($this->username, $this->saltHex, $Ahex, $this->Bhex, $K, $this->p);
        if (!hash_equals($expectedM1, $M1hex)) {
            throw new RuntimeException('SRP: M1 mismatch');
        }
        $this->Khex = bin2hex($K);
        $M2 = srp_compute_M2($Ahex, $M1hex, $K, $this->p);
        // Forget the secrets: this object must not be reused.
        $this->v = null;
        $this->b = null;
        $this->B = null;
        return $M2;
    }

    public function getUsername(): ?string
    {
        return $this->username;
    }

    /** Session key K as hex, after a successful verify(). */
    public function getSessionKeyHex(): ?string
    {
        return $this->Khex;
    }
}

/* ---------- client side (PHP — used by the tests; the browser uses srp.js) ---------- */

class SrpClient
{
    private array $p;
    private $N;
    private $g;
    private $k;
    private string $username;
    private string $password;
    private string $saltHex;
    private $a = null;
    private ?string $Ahex = null;
    private ?string $Bhex = null;
    private $S = null;
    private ?string $Khex = null;
    private ?string $M1hex = null;

    public function __construct(array $params, string $username, string $password, string $saltHex)
    {
        $this->p = $params;
        $this->N = srp_bn_from_hex($params['N']);
        $this->g = srp_bn_from_dec($params['g']);
        $this->k = srp_bn_from_hex($params['k']);
        $this->username = $username;
        $this->password = $password;
        $saltHex = srp_clean_hex($saltHex, 64);
        if ($saltHex === null) {
            throw new InvalidArgumentException('SRP: bad salt');
        }
        $this->saltHex = $saltHex;
    }

    /** Tests only: fix the client private value instead of a random one. */
    public function setPrivateA(string $aHex): void
    {
        if ($this->Ahex !== null) {
            throw new RuntimeException('SRP: too late to set a');
        }
        $this->a = srp_bn_from_hex($aHex);
    }

    /** Step 1: A = g^a % N. Returns A as full-length padded hex. */
    public function step1(): string
    {
        if ($this->a === null) {
            $this->a = srp_bn_from_bytes(random_bytes(32));
        }
        $A = srp_bn_powmod($this->g, $this->a, $this->N);
        $this->Ahex = bin2hex(srp_bn_to_bytes($A, $this->p['N_bytes']));
        return $this->Ahex;
    }

    /** Step 2: receive B, compute S and K. Aborts on B % N == 0. */
    public function setChallenge(string $Bhex): void
    {
        $Bhex = srp_clean_hex($Bhex, $this->p['N_bytes'] * 2);
        if ($Bhex === null || $this->Ahex === null) {
            throw new InvalidArgumentException('SRP: bad challenge');
        }
        $B = srp_bn_from_hex($Bhex);
        if (srp_bn_is_zero(srp_bn_mod($B, $this->N))) {
            throw new RuntimeException('SRP: B % N == 0');
        }
        $this->Bhex = $Bhex;
        $x = srp_bn_from_hex(srp_compute_x($this->saltHex, $this->username, $this->password, $this->p));
        $u = srp_bn_from_hex(srp_compute_u($this->Ahex, $this->Bhex, $this->p));
        $gx = srp_bn_powmod($this->g, $x, $this->N);
        $base = srp_bn_mod(srp_bn_sub($B, srp_bn_mul($this->k, $gx)), $this->N);
        $exp = srp_bn_add($this->a, srp_bn_mul($u, $x));
        $this->S = srp_bn_powmod($base, $exp, $this->N);
        $this->Khex = bin2hex(srp_compute_K($this->S, $this->p));
    }

    /** The client proof M1. */
    public function computeM1(): string
    {
        if ($this->Khex === null) {
            throw new RuntimeException('SRP: no challenge yet');
        }
        $this->M1hex = srp_compute_M1(
            $this->username,
            $this->saltHex,
            $this->Ahex,
            $this->Bhex,
            hex2bin($this->Khex),
            $this->p
        );
        return $this->M1hex;
    }

    /** Check the server proof M2. */
    public function verifyM2(string $M2hex): bool
    {
        if ($this->M1hex === null || $this->Khex === null) {
            throw new RuntimeException('SRP: no M1 yet');
        }
        $expected = srp_compute_M2($this->Ahex, $this->M1hex, hex2bin($this->Khex), $this->p);
        return hash_equals($expected, strtolower($M2hex));
    }

    public function getSessionKeyHex(): ?string
    {
        return $this->Khex;
    }

    public function getAhex(): ?string
    {
        return $this->Ahex;
    }
}
