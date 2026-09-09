<?php
require_once __DIR__ . '/functions.php';

$genericMessage = 'Jika email tersebut terdaftar, link reset password telah dibuat.';
$showMessage = false;
$errors = [];
$devResetLink = null; // HANYA untuk demo lokal — lihat catatan di bawah

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_verify($_POST['csrf_token'] ?? null)) {
        $errors[] = 'Sesi tidak valid, silakan muat ulang halaman.';
    } elseif (is_action_rate_limited($pdo, 'reset_ip_' . get_client_ip(), 5, 15)) {
        $errors[] = 'Terlalu banyak permintaan dari alamat ini. Coba lagi nanti.';
    } else {
        record_login_attempt($pdo, 'reset_ip_' . get_client_ip(), true); // hanya untuk rate limiting
        $email = filter_var(trim($_POST['email'] ?? ''), FILTER_SANITIZE_EMAIL);

        if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $stmt = $pdo->prepare('SELECT id FROM users WHERE email = :email AND is_active = 1 LIMIT 1');
            $stmt->execute([':email' => $email]);
            $user = $stmt->fetch();

            if ($user) {
                $token = bin2hex(random_bytes(32));           // token asli, hanya dikirim ke user
                $tokenHash = hash('sha256', $token);           // yang disimpan di DB
                $expiresAt = date('Y-m-d H:i:s', strtotime('+30 minutes'));

                $ins = $pdo->prepare(
                    'INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, ip_address)
                     VALUES (:uid, :hash, :exp, :ip)'
                );
                $ins->execute([
                    ':uid'  => $user['id'],
                    ':hash' => $tokenHash,
                    ':exp'  => $expiresAt,
                    ':ip'   => get_client_ip(),
                ]);

                log_activity($pdo, $user['id'], 'PASSWORD_RESET_REQUESTED');

                $scheme = isset($_SERVER['HTTPS']) ? 'https' : 'http';
                $resetLink = $scheme . '://' . $_SERVER['HTTP_HOST'] . dirname($_SERVER['SCRIPT_NAME']) . '/reset_password.php?token=' . $token;

                // =========================================================
                // PRODUKSI: kirim $resetLink lewat EMAIL (mail()/SMTP/API
                // seperti SES/SendGrid), JANGAN PERNAH ditampilkan di layar.
                // Ditampilkan di sini HANYA supaya demo bisa dites tanpa
                // server email sungguhan.
                // =========================================================
                $devResetLink = $resetLink;
            }
        }
        $showMessage = true;
    }
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<title>Lupa Password</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
  body{font-family:system-ui,sans-serif;background:#0f172a;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;padding:1rem}
  .card{background:#1e293b;padding:2rem;border-radius:12px;width:360px;box-shadow:0 10px 30px rgba(0,0,0,.4)}
  h1{color:#f1f5f9;font-size:1.3rem}
  p{color:#94a3b8;font-size:.85rem;line-height:1.5}
  label{color:#cbd5e1;font-size:.85rem;display:block;margin-top:.8rem}
  input{width:100%;padding:.6rem;border-radius:6px;border:1px solid #334155;background:#0f172a;color:#f1f5f9;margin-top:.3rem;box-sizing:border-box}
  button{width:100%;margin-top:1.2rem;padding:.7rem;border:none;border-radius:6px;background:#2563eb;color:#fff;font-weight:600;cursor:pointer}
  .err{background:#7f1d1d;color:#fecaca;padding:.6rem;border-radius:6px;margin-top:1rem;font-size:.85rem}
  .ok{background:#14532d;color:#bbf7d0;padding:.6rem;border-radius:6px;margin-top:1rem;font-size:.85rem}
  .dev{background:#78350f;color:#fde68a;padding:.6rem;border-radius:6px;margin-top:1rem;font-size:.75rem;word-break:break-all}
  a{color:#93c5fd;font-size:.85rem}
</style>
</head>
<body>
  <div class="card">
    <h1>🔑 Lupa Password</h1>
    <p>Masukkan email akun Anda. Kami akan mengirimkan link untuk membuat password baru.</p>

    <?php foreach ($errors as $e): ?><div class="err"><?= htmlspecialchars($e) ?></div><?php endforeach; ?>

    <?php if ($showMessage): ?>
      <div class="ok"><?= htmlspecialchars($genericMessage) ?></div>
      <?php if ($devResetLink): ?>
        <div class="dev">
          ⚠️ MODE DEV (tanpa server email): link reset Anda:<br>
          <code><?= htmlspecialchars($devResetLink) ?></code>
        </div>
      <?php endif; ?>
    <?php else: ?>
      <form method="POST" autocomplete="off">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
        <label for="email">Email</label>
        <input type="email" id="email" name="email" required>
        <button type="submit">Kirim Link Reset</button>
      </form>
    <?php endif; ?>

    <p style="margin-top:1rem;text-align:center"><a href="login.php">← Kembali ke login</a></p>
  </div>
</body>
</html>
