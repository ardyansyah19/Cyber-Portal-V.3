<?php
require_once __DIR__ . '/functions_2fa.php';
require_login();

$errors = [];
$success = null;

$stmt = $pdo->prepare('SELECT two_factor_enabled FROM users WHERE id = :id');
$stmt->execute([':id' => $_SESSION['user_id']]);
$is2faEnabled = (bool) $stmt->fetchColumn();

// ---- Proses NONAKTIFKAN 2FA ----
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'disable') {
    if (!csrf_verify($_POST['csrf_token'] ?? null)) {
        $errors[] = 'Sesi tidak valid.';
    } else {
        $stmt = $pdo->prepare('SELECT password_hash FROM users WHERE id = :id');
        $stmt->execute([':id' => $_SESSION['user_id']]);
        $hash = $stmt->fetchColumn();

        if (!verify_password((string) ($_POST['current_password'] ?? ''), $hash)) {
            $errors[] = 'Password saat ini salah.';
        } else {
            $upd = $pdo->prepare('UPDATE users SET two_factor_enabled = 0, two_factor_secret = NULL WHERE id = :id');
            $upd->execute([':id' => $_SESSION['user_id']]);
            log_activity($pdo, (int) $_SESSION['user_id'], '2FA_DISABLED');
            $is2faEnabled = false;
            $success = 'Two-Factor Authentication berhasil dinonaktifkan.';
        }
    }
}

// ---- Proses AKTIFKAN 2FA ----
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'enable') {
    if (!csrf_verify($_POST['csrf_token'] ?? null)) {
        $errors[] = 'Sesi tidak valid.';
    } else {
        $pendingSecret = $_SESSION['pending_totp_secret'] ?? null;
        $code = clean_input($_POST['code'] ?? '');

        if (!$pendingSecret || !verify_totp($pendingSecret, $code)) {
            $errors[] = 'Kode verifikasi salah. Pastikan Anda memasukkan kode 6 digit terbaru dari aplikasi authenticator.';
        } else {
            $encrypted = encrypt_totp_secret($pendingSecret);
            $upd = $pdo->prepare('UPDATE users SET two_factor_enabled = 1, two_factor_secret = :s WHERE id = :id');
            $upd->execute([':s' => $encrypted, ':id' => $_SESSION['user_id']]);
            unset($_SESSION['pending_totp_secret']);
            log_activity($pdo, (int) $_SESSION['user_id'], '2FA_ENABLED');
            $is2faEnabled = true;
            $success = 'Two-Factor Authentication berhasil diaktifkan! Mulai sekarang login akan meminta kode dari aplikasi authenticator.';
        }
    }
}

// Siapkan secret baru (belum aktif) untuk ditampilkan sebagai QR/manual setup
if (!$is2faEnabled && empty($_SESSION['pending_totp_secret'])) {
    $_SESSION['pending_totp_secret'] = generate_totp_secret();
}
$pendingSecret = $_SESSION['pending_totp_secret'] ?? null;
$otpUri = $pendingSecret ? get_totp_uri($pendingSecret, $_SESSION['username']) : '';
// PENTING: QR code digenerate 100% di browser (client-side) memakai library lokal
// qrcode.min.js. JANGAN pernah kirim otpauth URI / secret 2FA ke API pihak ketiga
// (mis. api.qrserver.com) karena itu sama saja membocorkan secret ke server luar.
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<title>Pengaturan 2FA</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
  body{font-family:system-ui,sans-serif;background:#0f172a;color:#f1f5f9;display:flex;justify-content:center;margin:0;padding:2rem}
  .card{background:#1e293b;padding:2rem;border-radius:12px;width:380px;text-align:center}
  h1{font-size:1.3rem}
  p{color:#94a3b8;font-size:.85rem;line-height:1.5}
  .secret{background:#0f172a;border:1px solid #334155;border-radius:6px;padding:.6rem;font-family:monospace;letter-spacing:.15rem;word-break:break-all;margin:.8rem 0}
  input{width:100%;padding:.6rem;border-radius:6px;border:1px solid #334155;background:#0f172a;color:#f1f5f9;margin-top:.6rem;box-sizing:border-box;text-align:center}
  button{width:100%;margin-top:1rem;padding:.7rem;border:none;border-radius:6px;background:#2563eb;color:#fff;font-weight:600;cursor:pointer}
  .btn-danger{background:#dc2626}
  .err{background:#7f1d1d;color:#fecaca;padding:.6rem;border-radius:6px;margin-top:1rem;font-size:.85rem}
  .ok{background:#14532d;color:#bbf7d0;padding:.6rem;border-radius:6px;margin-top:1rem;font-size:.85rem}
  .nav{margin-top:1.2rem}
  a{color:#93c5fd;font-size:.85rem;text-decoration:none}
  img{border-radius:8px;margin-top:.5rem;background:#fff;padding:8px}
</style>
</head>
<body>
<div class="card">
  <h1>🔐 Two-Factor Authentication</h1>

  <?php foreach ($errors as $e): ?><div class="err"><?= htmlspecialchars($e) ?></div><?php endforeach; ?>
  <?php if ($success): ?><div class="ok"><?= htmlspecialchars($success) ?></div><?php endif; ?>

  <?php if ($is2faEnabled): ?>
    <p>2FA sedang <b style="color:#4ade80">AKTIF</b> di akun Anda.</p>
    <form method="POST">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
      <input type="hidden" name="action" value="disable">
      <label style="font-size:.8rem;color:#cbd5e1;display:block;text-align:left;margin-top:1rem">Masukkan password untuk menonaktifkan:</label>
      <input type="password" name="current_password" required>
      <button class="btn-danger" type="submit">Nonaktifkan 2FA</button>
    </form>
  <?php else: ?>
    <p>Buka aplikasi authenticator (Google Authenticator / Microsoft Authenticator / Authy), pilih <b>"Masukkan kunci setup"/"Enter setup key"</b> secara manual, lalu masukkan kode di bawah ini:</p>
    <div class="secret"><?= htmlspecialchars($pendingSecret) ?></div>
    <p style="font-size:.75rem">Tipe: Time-based &middot; Akun: <?= htmlspecialchars($_SESSION['username']) ?> &middot; Issuer: SecureLoginApp</p>

    <form method="POST">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
      <input type="hidden" name="action" value="enable">
      <label style="font-size:.8rem;color:#cbd5e1;display:block;text-align:left;margin-top:1rem">Masukkan kode 6 digit untuk konfirmasi:</label>
      <input type="text" name="code" inputmode="numeric" maxlength="6" required placeholder="000000">
      <button type="submit">Aktifkan 2FA</button>
    </form>
  <?php endif; ?>

  <div class="nav"><a href="dashboard.php">← Dashboard</a></div>
</div>
</body>
</html>
