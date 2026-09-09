<?php
require_once __DIR__ . '/functions_2fa.php';

$errors = [];
$lockoutMessage = null;

// Jika sudah login, langsung arahkan ke dashboard
if (!empty($_SESSION['user_id'])) {
    header('Location: dashboard.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // 0) Honeypot: bot biasanya mengisi semua field termasuk yang disembunyikan via CSS
    if (is_honeypot_triggered()) {
        // Diamkan saja seolah sukses divalidasi tapi jangan proses (jangan beri tahu bot kalau terdeteksi)
        $errors[] = 'Username atau password salah.';
    }

    // 1) Verifikasi CSRF token dulu, sebelum proses apa pun
    elseif (!csrf_verify($_POST['csrf_token'] ?? null)) {
        $errors[] = 'Sesi tidak valid, silakan muat ulang halaman dan coba lagi.';
    }

    // 2) Rate limiting berbasis IP (anti brute force terdistribusi)
    elseif (is_ip_rate_limited($pdo)) {
        $errors[] = 'Terlalu banyak percobaan login dari alamat ini. Coba lagi nanti.';
    }

    else {
        $username = clean_input($_POST['username'] ?? '');
        $password = (string) ($_POST['password'] ?? '');

        if ($username === '' || $password === '') {
            $errors[] = 'Username dan password wajib diisi.';
        } else {
            $stmt = $pdo->prepare(
                'SELECT id, username, password_hash, role, is_active, failed_attempts, locked_until,
                        two_factor_enabled, two_factor_secret
                 FROM users WHERE username = :username LIMIT 1'
            );
            $stmt->execute([':username' => $username]);
            $user = $stmt->fetch();

            // Pesan error SENGAJA dibuat generik ("username atau password salah")
            // agar penyerang tidak bisa menebak username mana yang valid (anti user enumeration).
            $genericError = 'Username atau password salah.';

            if (!$user) {
                // Tetap hash dummy untuk menyamakan waktu proses (anti timing attack)
                password_verify($password, '$2y$12$invalidsaltinvalidsaltinvalidsaltinvalidsaltinva');
                record_login_attempt($pdo, $username, false);
                $errors[] = $genericError;
            } elseif (!$user['is_active']) {
                $errors[] = 'Akun ini dinonaktifkan. Hubungi administrator.';
            } elseif (is_account_locked($user)) {
                $lockoutMessage = 'Akun terkunci sementara karena terlalu banyak percobaan gagal. Coba lagi setelah ' . LOCKOUT_DURATION_MIN . ' menit.';
            } elseif (!verify_password($password, $user['password_hash'])) {
                register_failed_attempt($pdo, $user);
                record_login_attempt($pdo, $username, false);
                log_activity($pdo, $user['id'], 'LOGIN_FAILED');
                $errors[] = $genericError;
            } else {
                // ---- LOGIN BERHASIL ----
                reset_failed_attempts($pdo, $user['id']);
                record_login_attempt($pdo, $username, true);
                log_activity($pdo, $user['id'], 'LOGIN_SUCCESS');

                // Auto-upgrade hash lama jika parameter keamanan berubah (mis. cost dinaikkan)
                if (password_needs_upgrade($user['password_hash'])) {
                    $newHash = hash_password($password);
                    $upd = $pdo->prepare('UPDATE users SET password_hash = :h WHERE id = :id');
                    $upd->execute([':h' => $newHash, ':id' => $user['id']]);
                }

                session_regenerate_id(true); // wajib: cegah session fixation

                if ((int) $user['two_factor_enabled'] === 1) {
                    // Jangan login penuh dulu — perlu verifikasi kode 2FA.
                    $_SESSION['pending_2fa_user_id'] = $user['id'];
                    header('Location: verify_2fa.php');
                    exit;
                }

                $_SESSION['user_id']  = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['role']     = $user['role'];

                $upd = $pdo->prepare('UPDATE users SET last_login_at = NOW(), last_login_ip = :ip WHERE id = :id');
                $upd->execute([':ip' => get_client_ip(), ':id' => $user['id']]);

                header('Location: dashboard.php');
                exit;
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<title>Login Aman</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
  body{font-family:system-ui,sans-serif;background:#0f172a;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
  .card{background:#1e293b;padding:2rem;border-radius:12px;width:320px;box-shadow:0 10px 30px rgba(0,0,0,.4)}
  h1{color:#f1f5f9;font-size:1.4rem;margin-bottom:1rem}
  label{color:#cbd5e1;font-size:.85rem;display:block;margin-top:.8rem}
  input{width:100%;padding:.6rem;border-radius:6px;border:1px solid #334155;background:#0f172a;color:#f1f5f9;margin-top:.3rem;box-sizing:border-box}
  button{width:100%;margin-top:1.2rem;padding:.7rem;border:none;border-radius:6px;background:#2563eb;color:#fff;font-weight:600;cursor:pointer}
  button:hover{background:#1d4ed8}
  .err{background:#7f1d1d;color:#fecaca;padding:.6rem;border-radius:6px;margin-top:1rem;font-size:.85rem}
  .lock{background:#78350f;color:#fde68a;padding:.6rem;border-radius:6px;margin-top:1rem;font-size:.85rem}
  .hint{color:#64748b;font-size:.75rem;margin-top:1rem;line-height:1.4}
</style>
</head>
<body>
  <div class="card">
    <h1>🔐 Login Aman</h1>

    <?php foreach ($errors as $e): ?>
      <div class="err"><?= htmlspecialchars($e) ?></div>
    <?php endforeach; ?>

    <?php if ($lockoutMessage): ?>
      <div class="lock"><?= htmlspecialchars($lockoutMessage) ?></div>
    <?php endif; ?>

    <?php if (isset($_GET['timeout'])): ?>
      <div class="lock">Sesi Anda berakhir karena tidak aktif. Silakan login kembali.</div>
    <?php endif; ?>

    <?php if (isset($_GET['security_alert'])): ?>
      <div class="lock">Sesi dihentikan demi keamanan (terdeteksi perubahan perangkat/browser). Silakan login kembali.</div>
    <?php endif; ?>

    <form method="POST" autocomplete="off" novalidate>
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
      <!-- Honeypot anti-bot: disembunyikan dari manusia via CSS, bot tetap mengisinya -->
      <input type="text" name="website_url" tabindex="-1" autocomplete="off"
             style="position:absolute;left:-9999px;width:1px;height:1px;opacity:0" aria-hidden="true">

      <label for="username">Username</label>
      <input type="text" id="username" name="username" maxlength="30" required>

      <label for="password">Password</label>
      <input type="password" id="password" name="password" maxlength="100" required>

      <button type="submit">Masuk</button>
    </form>

    <div class="hint" style="text-align:center;margin-top:1rem">
      <a href="forgot_password.php" style="color:#93c5fd">Lupa password?</a>
    </div>

    <div class="hint">
      Akun dummy (jalankan <code>php seed.php</code> dulu):<br>
      admin_demo / P@ssw0rdKuat!123<br>
      budi_santoso / Budi#Aman2026
    </div>
  </div>
</body>
</html>
