<?php
/**
 * config.php
 * -----------------------------------------------------
 * Konfigurasi koneksi database (PDO + prepared statements)
 * dan pengaturan session yang keras (hardened).
 * -----------------------------------------------------
 */

// ---- Jangan tampilkan error detail di production ----
error_reporting(E_ALL);
ini_set('display_errors', '0');   // matikan tampilan error ke user
ini_set('log_errors', '1');
ini_set('error_log', __DIR__ . '/logs/error.log');

// ---- Kredensial database ----
// Sebaiknya ambil dari environment variable, bukan hardcode.
define('DB_HOST', getenv('DB_HOST') ?: '127.0.0.1');
define('DB_NAME', getenv('DB_NAME') ?: 'secure_login_db');
define('DB_USER', getenv('DB_USER') ?: 'db_user');
define('DB_PASS', getenv('DB_PASS') ?: 'ganti_dengan_password_kuat');
define('DB_CHARSET', 'utf8mb4');

// ---- Pengaturan keamanan aplikasi ----
define('MAX_LOGIN_ATTEMPTS', 5);       // maksimal percobaan gagal
define('LOCKOUT_DURATION_MIN', 15);    // menit akun dikunci setelah gagal berulang
define('RATE_LIMIT_WINDOW_MIN', 10);   // jendela waktu untuk hitung percobaan per-IP
define('RATE_LIMIT_MAX_PER_IP', 20);   // batas percobaan login per-IP dalam window
define('SESSION_LIFETIME', 30 * 60);   // auto-logout setelah 30 menit idle
define('PEPPER', getenv('APP_PEPPER') ?: 'GANTI_INI_DENGAN_STRING_RAHASIA_PANJANG_DAN_ACAK');

// ---- Pengaturan fitur dokumen terenkripsi ----
// MASTER_KEY harus 32 byte biner (untuk AES-256), simpan base64 di ENV.
// Generate sekali: php -r "echo base64_encode(random_bytes(32));"
$rawMasterKey = getenv('DOC_MASTER_KEY')
    ? base64_decode(getenv('DOC_MASTER_KEY'))
    : hash('sha256', 'GANTI_INI_JUGA_DENGAN_MASTER_KEY_RAHASIA_SERVER', true); // fallback DEV ONLY
define('DOC_MASTER_KEY', $rawMasterKey);

// ---- Master key khusus untuk enkripsi secret 2FA (pisah dari DOC_MASTER_KEY) ----
$rawTotpKey = getenv('TOTP_MASTER_KEY')
    ? base64_decode(getenv('TOTP_MASTER_KEY'))
    : hash('sha256', 'GANTI_INI_DENGAN_MASTER_KEY_2FA_YANG_BEDA_DARI_DOC', true); // fallback DEV ONLY
define('TOTP_MASTER_KEY', $rawTotpKey);

define('STORAGE_DIR', __DIR__ . '/storage');          // folder penyimpanan file terenkripsi
define('MAX_UPLOAD_SIZE', 20 * 1024 * 1024);          // 20 MB
define('DOC_MAX_ATTEMPTS', 5);                        // maksimal percobaan password dokumen
define('DOC_LOCKOUT_MIN', 15);                        // menit dokumen dikunci setelah gagal berulang
define('ALLOWED_DOC_TYPES', [
    'pdf'  => 'application/pdf',
    'doc'  => 'application/msword',
    'docx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
]);

// =====================================================
// Hardened session settings — HARUS di-set sebelum session_start()
// =====================================================
ini_set('session.use_strict_mode', '1');       // tolak session ID yang tidak dikenal
ini_set('session.use_only_cookies', '1');      // session ID hanya via cookie, bukan URL
ini_set('session.cookie_httponly', '1');       // cookie tidak bisa diakses JavaScript (anti XSS-theft)
ini_set('session.cookie_samesite', 'Strict');  // anti CSRF lintas situs
ini_set('session.cookie_secure', isset($_SERVER['HTTPS']) ? '1' : '0'); // cookie hanya via HTTPS jika tersedia
ini_set('session.gc_maxlifetime', (string) SESSION_LIFETIME);
session_name('SECUREAPPSESSID'); // ganti nama default PHPSESSID agar tidak mudah dikenali

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// ---- Regenerasi session ID berkala (mitigasi session fixation) ----
if (!isset($_SESSION['created_at'])) {
    $_SESSION['created_at'] = time();
} elseif (time() - $_SESSION['created_at'] > 300) { // tiap 5 menit
    session_regenerate_id(true);
    $_SESSION['created_at'] = time();
}

// ---- Auto logout jika idle terlalu lama ----
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > SESSION_LIFETIME) {
    $_SESSION = [];
    session_destroy();
    header('Location: login.php?timeout=1');
    exit;
}
$_SESSION['last_activity'] = time();

// =====================================================
// Session binding ke User-Agent — mitigasi pencurian cookie session.
// Kalau cookie dicuri lalu dipakai dari browser/perangkat lain, User-Agent
// hampir pasti berbeda -> session langsung dipaksa logout.
// (Bukan proteksi sempurna, tapi menaikkan biaya serangan secara nyata.)
// =====================================================
$currentUaHash = hash('sha256', $_SERVER['HTTP_USER_AGENT'] ?? 'unknown');
if (!isset($_SESSION['ua_hash'])) {
    $_SESSION['ua_hash'] = $currentUaHash;
} elseif (!hash_equals($_SESSION['ua_hash'], $currentUaHash)) {
    $_SESSION = [];
    session_destroy();
    header('Location: login.php?security_alert=1');
    exit;
}

// =====================================================
// Koneksi database via PDO (SELALU pakai prepared statements)
// =====================================================
try {
    $dsn = 'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=' . DB_CHARSET;
    $pdo = new PDO($dsn, DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false, // pakai native prepared statement (anti SQL injection lebih kuat)
    ]);
} catch (PDOException $e) {
    error_log('DB Connection failed: ' . $e->getMessage());
    http_response_code(500);
    die('Terjadi kesalahan pada server. Silakan coba lagi nanti.');
}

// =====================================================
// Security headers (kirim di setiap request)
// =====================================================
// Nonce unik per-request untuk CSP -> hilangkan kebutuhan 'unsafe-inline' pada script.
// Semua tag <script> inline WAJIB pakai nonce ini: <script nonce="<?= csp_nonce() ?>">
$GLOBALS['__CSP_NONCE'] = base64_encode(random_bytes(16));

function csp_nonce(): string
{
    return $GLOBALS['__CSP_NONCE'];
}

header('X-Frame-Options: DENY');                          // anti clickjacking
header('X-Content-Type-Options: nosniff');                // anti MIME sniffing
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()');
header(
    "Content-Security-Policy: default-src 'self'; " .
    "script-src 'self' 'nonce-" . csp_nonce() . "'; " .
    "style-src 'self' 'unsafe-inline'; " .
    "img-src 'self' data:; " .
    "object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
);
if (isset($_SERVER['HTTPS'])) {
    header('Strict-Transport-Security: max-age=63072000; includeSubDomains; preload');
}
