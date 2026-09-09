<?php
/**
 * functions_2fa.php
 * -----------------------------------------------------
 * Two-Factor Authentication berbasis TOTP (RFC 6238),
 * kompatibel dengan Google Authenticator / Microsoft Authenticator / Authy.
 *
 * Secret 2FA disimpan TERENKRIPSI (AES-256-GCM, TOTP_MASTER_KEY) di kolom
 * users.two_factor_secret — tidak pernah plaintext di database.
 * -----------------------------------------------------
 */

require_once __DIR__ . '/functions.php';

const TOTP_STEP   = 30; // detik per time-step, standar industri
const TOTP_DIGITS = 6;

/* =====================================================
 * BASE32 (dibutuhkan RFC 6238 / kompatibilitas app authenticator)
 * ===================================================== */
function base32_encode(string $data): string
{
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = '';
    foreach (str_split($data) as $char) {
        $bits .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
    }
    $output = '';
    foreach (str_split($bits, 5) as $chunk) {
        $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
        $output .= $alphabet[bindec($chunk)];
    }
    return $output;
}

function base32_decode(string $b32): string
{
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $b32 = strtoupper(preg_replace('/[^A-Z2-7]/', '', $b32));
    $bits = '';
    foreach (str_split($b32) as $char) {
        $pos = strpos($alphabet, $char);
        if ($pos === false) {
            continue;
        }
        $bits .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
    }
    $output = '';
    foreach (str_split($bits, 8) as $byte) {
        if (strlen($byte) === 8) {
            $output .= chr(bindec($byte));
        }
    }
    return $output;
}

/* =====================================================
 * GENERATE & VERIFIKASI KODE TOTP
 * ===================================================== */
function generate_totp_secret(): string
{
    return base32_encode(random_bytes(20)); // 160-bit, standar RFC
}

function get_totp_code(string $secretBase32, ?int $timeSlice = null): string
{
    $timeSlice ??= (int) floor(time() / TOTP_STEP);
    $secretKey = base32_decode($secretBase32);
    $time = pack('N*', 0, $timeSlice); // counter 64-bit big-endian (32-bit atas selalu 0)
    $hash = hash_hmac('sha1', $time, $secretKey, true);
    $offset = ord($hash[19]) & 0x0f;
    $truncated =
        ((ord($hash[$offset]) & 0x7f) << 24) |
        ((ord($hash[$offset + 1]) & 0xff) << 16) |
        ((ord($hash[$offset + 2]) & 0xff) << 8) |
        (ord($hash[$offset + 3]) & 0xff);
    $code = $truncated % (10 ** TOTP_DIGITS);
    return str_pad((string) $code, TOTP_DIGITS, '0', STR_PAD_LEFT);
}

/**
 * Verifikasi dengan toleransi ±1 time-step (mengakomodasi jam HP/server
 * yang sedikit tidak sinkron) tanpa membuka jendela brute force terlalu lebar.
 */
function verify_totp(string $secretBase32, string $code, int $window = 1): bool
{
    $code = preg_replace('/\D/', '', $code); // hanya digit
    if (strlen($code) !== TOTP_DIGITS) {
        return false;
    }
    $currentSlice = (int) floor(time() / TOTP_STEP);
    for ($i = -$window; $i <= $window; $i++) {
        if (hash_equals(get_totp_code($secretBase32, $currentSlice + $i), $code)) {
            return true;
        }
    }
    return false;
}

function get_totp_uri(string $secretBase32, string $username, string $issuer = 'SecureLoginApp'): string
{
    return 'otpauth://totp/' . rawurlencode($issuer) . ':' . rawurlencode($username)
        . '?secret=' . $secretBase32
        . '&issuer=' . rawurlencode($issuer)
        . '&algorithm=SHA1&digits=' . TOTP_DIGITS . '&period=' . TOTP_STEP;
}

/* =====================================================
 * ENKRIPSI SECRET 2FA SEBELUM DISIMPAN DI DATABASE
 * ===================================================== */
function encrypt_totp_secret(string $plainSecret): string
{
    $enc = aes_encrypt($plainSecret, TOTP_MASTER_KEY);
    return base64_encode($enc['iv']) . '.' . base64_encode($enc['tag']) . '.' . base64_encode($enc['ciphertext']);
}

function decrypt_totp_secret(string $packed): ?string
{
    $parts = explode('.', $packed);
    if (count($parts) !== 3) {
        return null;
    }
    [$ivB64, $tagB64, $ctB64] = $parts;
    $plain = aes_decrypt(base64_decode($ctB64), TOTP_MASTER_KEY, base64_decode($ivB64), base64_decode($tagB64));
    return $plain === false ? null : $plain;
}

/* =====================================================
 * RATE LIMITING KHUSUS VERIFIKASI KODE 2FA (anti brute force 6-digit)
 * ===================================================== */
function is_2fa_rate_limited(PDO $pdo, int $userId): bool
{
    $stmt = $pdo->prepare(
        "SELECT COUNT(*) AS total FROM login_attempts
         WHERE identifier = :id AND success = 0
           AND attempted_at > (NOW() - INTERVAL 10 MINUTE)"
    );
    $stmt->execute([':id' => '2fa_user_' . $userId]);
    return ((int) $stmt->fetch()['total']) >= 8;
}
