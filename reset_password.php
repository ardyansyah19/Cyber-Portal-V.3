<?php
require_once __DIR__ . '/functions.php';

$token = $_GET['token'] ?? $_POST['token'] ?? '';
$errors = [];
$success = false;

if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
    http_response_code(404);
    die('Link reset tidak valid.');
}

$tokenHash = hash('sha256', $token);

$stmt = $pdo->prepare(
    'SELECT prt.id, prt.user_id, prt.expires_at, prt.used, u.username
     FROM password_reset_tokens prt
     JOIN users u ON u.id = prt.user_id
     WHERE prt.token_hash = :hash LIMIT 1'
);
$stmt->execute([':hash' => $tokenHash]);
$resetRow = $stmt->fetch();

$isValid = $resetRow && !$resetRow['used'] && strtotime($resetRow['expires_at']) > time();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $isValid) {
    if (!csrf_verify($_POST['csrf_token'] ?? null)) {
        $errors[] = 'Sesi tidak valid, silakan muat ulang halaman.';
    } else {
        $password = (string) ($_POST['password'] ?? '');
        $confirm  = (string) ($_POST['confirm_password'] ?? '');

        if (!is_strong_password($password)) {
            $errors[] = 'Password minimal 10 karakter dan mengandung huruf besar, kecil, angka, serta simbol.';
        } elseif ($password !== $confirm) {
            $errors[] = 'Konfirmasi password tidak cocok.';
        } else {
            $newHash = hash_password($password);
            $upd = $pdo->prepare('UPDATE users SET password_hash = :h, failed_attempts = 0, locked_until = NULL WHERE id = :id');
            $upd->execute([':h' => $newHash, ':id' => $resetRow['user_id']]);

            // Token sekali pakai -> langsung tandai used, dan batalkan token lain yang mungkin masih aktif
            $pdo->prepare('UPDATE password_reset_tokens SET used = 1 WHERE user_id = :uid')
                ->execute([':uid' => $resetRow['user_id']]);

            log_activity($pdo, (int) $resetRow['user_id'], 'PASSWORD_RESET_COMPLETED');
            $success = true;
        }
    }
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<title>Buat Password Baru</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
  body{font-family:system-ui,sans-serif;background:#0f172a;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;padding:1rem}
  .card{background:#1e293b;padding:2rem;border-radius:12px;width:360px;box-shadow:0 10px 30px rgba(0,0,0,.4)}
  h1{color:#f1f5f9;font-size:1.3rem}
  label{color:#cbd5e1;font-size:.85rem;display:block;margin-top:.8rem}
  input{width:100%;padding:.6rem;border-radius:6px;border:1px solid #334155;background:#0f172a;color:#f1f5f9;margin-top:.3rem;box-sizing:border-box}
  button{width:100%;margin-top:1.2rem;padding:.7rem;border:none;border-radius:6px;background:#2563eb;color:#fff;font-weight:600;cursor:pointer}
  .err{background:#7f1d1d;color:#fecaca;padding:.6rem;border-radius:6px;margin-top:1rem;font-size:.85rem}
  .ok{background:#14532d;color:#bbf7d0;padding:.6rem;border-radius:6px;margin-top:1rem;font-size:.85rem}
  a{color:#93c5fd;font-size:.85rem}
</style>
</head>
<body>
  <div class="card">
    <h1>🔑 Buat Password Baru</h1>

    <?php if (!$isValid && !$success): ?>
      <div class="err">Link reset ini tidak valid, sudah dipakai, atau sudah kedaluwarsa. Silakan minta link baru.</div>
      <p style="margin-top:1rem;text-align:center"><a href="forgot_password.php">Minta link reset baru</a></p>
    <?php elseif ($success): ?>
      <div class="ok">✅ Password berhasil diubah. Silakan <a href="login.php">login</a> dengan password baru Anda.</div>
    <?php else: ?>
      <p style="color:#94a3b8;font-size:.85rem">Untuk akun: <b><?= htmlspecialchars($resetRow['username']) ?></b></p>

      <?php foreach ($errors as $e): ?><div class="err"><?= htmlspecialchars($e) ?></div><?php endforeach; ?>

      <form method="POST" autocomplete="off">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
        <input type="hidden" name="token" value="<?= htmlspecialchars($token) ?>">
        <label for="password">Password Baru</label>
        <input type="password" id="password" name="password" required>
        <label for="confirm_password">Konfirmasi Password</label>
        <input type="password" id="confirm_password" name="confirm_password" required>
        <button type="submit">Simpan Password Baru</button>
      </form>
    <?php endif; ?>
  </div>
</body>
</html>
