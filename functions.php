<?php
/**
 * functions.php
 * -----------------------------------------------------
 * Kumpulan fungsi keamanan yang dipakai berulang:
 * CSRF token, rate limiting, validasi input, audit log.
 * -----------------------------------------------------
 */

require_once __DIR__ . '/config.php';

/* =====================================================
 * PRIMITIF KRIPTOGRAFI (dipakai bersama: dokumen & 2FA)
 * ===================================================== */
function aes_encrypt(string $plaintext, string $key): array
{
    $iv  = random_bytes(12); // 96-bit IV standar untuk GCM
    $tag = '';
    $ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
    if ($ciphertext === false) {
        throw new RuntimeException('Enkripsi gagal.');
    }
    return ['ciphertext' => $ciphertext, 'iv' => $iv, 'tag' => $tag];
}

/**
 * Mengembalikan plaintext, atau false jika kunci salah / data dirusak.
 * Auth tag GCM otomatis jadi mekanisme verifikasi integritas + kebenaran kunci.
 */
function aes_decrypt(string $ciphertext, string $key, string $iv, string $tag)
{
    return openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
}

function derive_key_from_password(string $password, string $salt): string
{
    return hash_pbkdf2('sha256', $password, $salt, 100000, 32, true);
}

/**
 * Hapus file secara aman: timpa isinya dengan data acak sebelum unlink,
 * supaya tidak mudah direcovery lewat forensik disk (defense-in-depth,
 * bukan jaminan mutlak terutama pada SSD dengan wear-leveling).
 */
function secure_delete_file(string $path): void
{
    if (!is_file($path)) {
        return;
    }
    $size = filesize($path);
    if ($size > 0 && $fp = fopen($path, 'r+b')) {
        fwrite($fp, random_bytes($size));
        fflush($fp);
        fclose($fp);
    }
    unlink($path);
}

/* =====================================================
 * RATE LIMITING REGISTRASI (anti spam akun)
 * ===================================================== */
function is_registration_rate_limited(PDO $pdo): bool
{
    $stmt = $pdo->prepare(
        'SELECT COUNT(*) AS total FROM registration_attempts
         WHERE ip_address = :ip AND attempted_at > (NOW() - INTERVAL 10 MINUTE)'
    );
    $stmt->execute([':ip' => get_client_ip()]);
    return ((int) $stmt->fetch()['total']) >= 5;
}

function record_registration_attempt(PDO $pdo): void
{
    $stmt = $pdo->prepare('INSERT INTO registration_attempts (ip_address) VALUES (:ip)');
    $stmt->execute([':ip' => get_client_ip()]);
}

/* =====================================================
 * CSRF PROTECTION
 * ===================================================== */
function csrf_token(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function csrf_verify(?string $token): bool
{
    if (empty($_SESSION['csrf_token']) || empty($token)) {
        return false;
    }
    // hash_equals mencegah timing attack
    return hash_equals($_SESSION['csrf_token'], $token);
}

/* =====================================================
 * INPUT SANITIZATION / VALIDATION
 * ===================================================== */
function clean_input(string $value): string
{
    return trim(htmlspecialchars($value, ENT_QUOTES, 'UTF-8'));
}

function is_valid_username(string $username): bool
{
    return (bool) preg_match('/^[a-zA-Z0-9_]{3,30}$/', $username);
}

function is_strong_password(string $password): bool
{
    // Minimal 10 karakter, ada huruf besar, kecil, angka, dan simbol
    return strlen($password) >= 10
        && preg_match('/[A-Z]/', $password)
        && preg_match('/[a-z]/', $password)
        && preg_match('/[0-9]/', $password)
        && preg_match('/[\W_]/', $password);
}

/* =====================================================
 * PASSWORD HASHING (dengan "pepper" tambahan di luar DB)
 * ===================================================== */
function hash_password(string $plainPassword): string
{
    // Pepper: rahasia yang disimpan di kode/ENV, bukan di database.
    // Jika database bocor, hash saja tidak cukup untuk brute force tanpa pepper.
    $peppered = hash_hmac('sha256', $plainPassword, PEPPER);
    $algo = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT;
    return password_hash($peppered, $algo, ['cost' => 12]);
}

function verify_password(string $plainPassword, string $hash): bool
{
    $peppered = hash_hmac('sha256', $plainPassword, PEPPER);
    return password_verify($peppered, $hash);
}

/**
 * Cek apakah hash lama perlu di-upgrade (misal cost factor dinaikkan,
 * atau server baru mendukung Argon2id padahal hash lama masih bcrypt).
 * Panggil setelah verify_password() berhasil, lalu update DB.
 */
function password_needs_upgrade(string $hash): bool
{
    $algo = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT;
    return password_needs_rehash($hash, $algo, ['cost' => 12]);
}

/**
 * Honeypot sederhana: field tersembunyi yang hanya akan diisi oleh bot.
 * Jika terisi, anggap submission sebagai bot dan tolak diam-diam.
 */
function is_honeypot_triggered(): bool
{
    return !empty($_POST['website_url'] ?? '');
}

/* =====================================================
 * RATE LIMITING & ANTI BRUTE-FORCE
 * ===================================================== */
function get_client_ip(): string
{
    // X-Forwarded-For bisa dipalsukan, gunakan hanya jika di belakang proxy tepercaya.
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function record_login_attempt(PDO $pdo, string $identifier, bool $success): void
{
    $stmt = $pdo->prepare(
        'INSERT INTO login_attempts (identifier, ip_address, success) VALUES (:id, :ip, :ok)'
    );
    $stmt->execute([
        ':id' => $identifier,
        ':ip' => get_client_ip(),
        ':ok' => $success ? 1 : 0,
    ]);
}

function is_ip_rate_limited(PDO $pdo): bool
{
    $stmt = $pdo->prepare(
        'SELECT COUNT(*) AS total FROM login_attempts
         WHERE ip_address = :ip AND success = 0
           AND attempted_at > (NOW() - INTERVAL :minutes MINUTE)'
    );
    $stmt->execute([':ip' => get_client_ip(), ':minutes' => RATE_LIMIT_WINDOW_MIN]);
    $row = $stmt->fetch();
    return ((int) $row['total']) >= RATE_LIMIT_MAX_PER_IP;
}

/**
 * Rate limit generik untuk aksi sensitif lain (mis. permintaan reset password)
 * yang tidak cocok dimasukkan ke penghitungan gagal-login biasa.
 * Menghitung SEMUA baris (sukses maupun gagal) dalam window waktu, per IP.
 */
function is_action_rate_limited(PDO $pdo, string $identifierPrefix, int $maxAttempts = 5, int $windowMinutes = 15): bool
{
    $stmt = $pdo->prepare(
        "SELECT COUNT(*) AS total FROM login_attempts
         WHERE identifier LIKE :prefix AND ip_address = :ip
           AND attempted_at > (NOW() - INTERVAL :minutes MINUTE)"
    );
    $stmt->execute([':prefix' => $identifierPrefix . '%', ':ip' => get_client_ip(), ':minutes' => $windowMinutes]);
    return ((int) $stmt->fetch()['total']) >= $maxAttempts;
}

function is_account_locked(array $user): bool
{
    return !empty($user['locked_until']) && strtotime($user['locked_until']) > time();
}

function register_failed_attempt(PDO $pdo, array $user): void
{
    $attempts = (int) $user['failed_attempts'] + 1;
    $lockUntil = null;

    if ($attempts >= MAX_LOGIN_ATTEMPTS) {
        $lockUntil = date('Y-m-d H:i:s', strtotime('+' . LOCKOUT_DURATION_MIN . ' minutes'));
        $attempts = 0; // reset counter setelah dikunci
    }

    $stmt = $pdo->prepare(
        'UPDATE users SET failed_attempts = :attempts, locked_until = :locked WHERE id = :id'
    );
    $stmt->execute([':attempts' => $attempts, ':locked' => $lockUntil, ':id' => $user['id']]);
}

function reset_failed_attempts(PDO $pdo, int $userId): void
{
    $stmt = $pdo->prepare(
        'UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = :id'
    );
    $stmt->execute([':id' => $userId]);
}

/* =====================================================
 * AUDIT LOG
 * ===================================================== */
function log_activity(PDO $pdo, ?int $userId, string $action): void
{
    $stmt = $pdo->prepare(
        'INSERT INTO activity_log (user_id, action, ip_address, user_agent)
         VALUES (:uid, :action, :ip, :ua)'
    );
    $stmt->execute([
        ':uid'    => $userId,
        ':action' => $action,
        ':ip'     => get_client_ip(),
        ':ua'     => substr($_SERVER['HTTP_USER_AGENT'] ?? 'unknown', 0, 255),
    ]);
}

/* =====================================================
 * AUTH GUARD — panggil di halaman yang perlu login
 * ===================================================== */
function require_login(): void
{
    if (empty($_SESSION['user_id'])) {
        header('Location: login.php');
        exit;
    }
}
