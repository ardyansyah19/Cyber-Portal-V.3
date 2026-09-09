<?php
require_once __DIR__ . '/functions_2fa.php';

if (empty($_SESSION['pending_2fa_user_id'])) {
    header('Location: login.php');
    exit;
}

$userId = (int) $_SESSION['pending_2fa_user_id'];
$errors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    if (!csrf_verify($_POST['csrf_token'] ?? null)) {
        $errors[] = 'Sesi tidak valid, silakan muat ulang halaman.';
    } elseif (is_2fa_rate_limited($pdo, $userId)) {
        // Terlalu banyak percobaan -> paksa ulang dari awal (username+password lagi)
        unset($_SESSION['pending_2fa_user_id']);
        $errors[] = 'Terlalu banyak percobaan kode salah. Silakan login ulang dari awal.';
    } else {
        $stmt = $pdo->prepare('SELECT id, username, role, two_factor_secret FROM users WHERE id = :id LIMIT 1');
        $stmt->execute([':id' => $userId]);
        $user = $stmt->fetch();

        $code = clean_input($_POST['code'] ?? '');
        $secret = $user ? decrypt_totp_secret($user['two_factor_secret']) : null;

        if (!$user || !$secret || !verify_totp($secret, $code)) {
            record_login_attempt($pdo, '2fa_user_' . $userId, false);
            log_activity($pdo, $userId, 'TWO_FA_FAILED');
            $errors[] = 'Kode verifikasi salah atau sudah kedaluwarsa.';
        } else {
            record_login_attempt($pdo, '2fa_user_' . $userId, true);
            log_activity($pdo, $userId, 'TWO_FA_SUCCESS');

            unset($_SESSION['pending_2fa_user_id']);
            session_regenerate_id(true);

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
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<title>Verifikasi 2FA</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
  body{font-family:system-ui,sans-serif;background:#0f172a;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
  .card{background:#1e293b;padding:2rem;border-radius:12px;width:320px;text-align:center;box-shadow:0 10px 30px rgba(0,0,0,.4)}
  h1{color:#f1f5f9;font-size:1.3rem}
  p{color:#94a3b8;font-size:.85rem}
  input{width:100%;padding:.7rem;border-radius:6px;border:1px solid #334155;background:#0f172a;color:#f1f5f9;margin-top:1rem;box-sizing:border-box;text-align:center;font-size:1.4rem;letter-spacing:.4rem}
  button{width:100%;margin-top:1.2rem;padding:.7rem;border:none;border-radius:6px;background:#2563eb;color:#fff;font-weight:600;cursor:pointer}
  .err{background:#7f1d1d;color:#fecaca;padding:.6rem;border-radius:6px;margin-top:1rem;font-size:.85rem}
</style>
</head>
<body>
  <div class="card">
    <h1>🔑 Verifikasi 2FA</h1>
    <p>Masukkan 6 digit kode dari aplikasi authenticator Anda.</p>

    <?php foreach ($errors as $e): ?>
      <div class="err"><?= htmlspecialchars($e) ?></div>
    <?php endforeach; ?>

    <form method="POST" autocomplete="off">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
      <input type="text" name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required autofocus placeholder="000000">
      <button type="submit">Verifikasi</button>
    </form>
  </div>
</body>
</html>
