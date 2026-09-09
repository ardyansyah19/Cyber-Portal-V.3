<?php
require_once __DIR__ . '/functions.php';

$errors = [];
$success = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    if (!csrf_verify($_POST['csrf_token'] ?? null)) {
        $errors[] = 'Sesi tidak valid, silakan muat ulang halaman.';
    } elseif (is_registration_rate_limited($pdo)) {
        $errors[] = 'Terlalu banyak percobaan registrasi dari alamat ini. Coba lagi nanti.';
    } else {
        record_registration_attempt($pdo);
        $username = clean_input($_POST['username'] ?? '');
        $email    = filter_var(trim($_POST['email'] ?? ''), FILTER_SANITIZE_EMAIL);
        $password = (string) ($_POST['password'] ?? '');
        $confirm  = (string) ($_POST['confirm_password'] ?? '');

        if (!is_valid_username($username)) {
            $errors[] = 'Username hanya boleh huruf, angka, underscore (3-30 karakter).';
        }
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'Format email tidak valid.';
        }
        if (!is_strong_password($password)) {
            $errors[] = 'Password minimal 10 karakter dan mengandung huruf besar, kecil, angka, serta simbol.';
        }
        if ($password !== $confirm) {
            $errors[] = 'Konfirmasi password tidak cocok.';
        }

        if (empty($errors)) {
            // Cek duplikat dengan prepared statement (anti SQL injection)
            $check = $pdo->prepare('SELECT id FROM users WHERE username = :u OR email = :e LIMIT 1');
            $check->execute([':u' => $username, ':e' => $email]);

            if ($check->fetch()) {
                $errors[] = 'Username atau email sudah terdaftar.';
            } else {
                $hash = hash_password($password);
                $stmt = $pdo->prepare(
                    'INSERT INTO users (username, email, password_hash, role, is_active)
                     VALUES (:u, :e, :h, "user", 1)'
                );
                $stmt->execute([':u' => $username, ':e' => $email, ':h' => $hash]);
                log_activity($pdo, (int) $pdo->lastInsertId(), 'REGISTER');
                $success = true;
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<title>Registrasi Aman</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
  body{font-family:system-ui,sans-serif;background:#0f172a;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}
  .card{background:#1e293b;padding:2rem;border-radius:12px;width:340px;box-shadow:0 10px 30px rgba(0,0,0,.4)}
  h1{color:#f1f5f9;font-size:1.4rem;margin-bottom:1rem}
  label{color:#cbd5e1;font-size:.85rem;display:block;margin-top:.8rem}
  input{width:100%;padding:.6rem;border-radius:6px;border:1px solid #334155;background:#0f172a;color:#f1f5f9;margin-top:.3rem;box-sizing:border-box}
  button{width:100%;margin-top:1.2rem;padding:.7rem;border:none;border-radius:6px;background:#16a34a;color:#fff;font-weight:600;cursor:pointer}
  button:hover{background:#15803d}
  .err{background:#7f1d1d;color:#fecaca;padding:.6rem;border-radius:6px;margin-top:1rem;font-size:.85rem}
  .ok{background:#14532d;color:#bbf7d0;padding:.6rem;border-radius:6px;margin-top:1rem;font-size:.85rem}
  a{color:#93c5fd}
</style>
</head>
<body>
  <div class="card">
    <h1>📝 Registrasi Akun</h1>

    <?php foreach ($errors as $e): ?>
      <div class="err"><?= htmlspecialchars($e) ?></div>
    <?php endforeach; ?>

    <?php if ($success): ?>
      <div class="ok">Registrasi berhasil! Silakan <a href="login.php">login di sini</a>.</div>
    <?php else: ?>
      <form method="POST" autocomplete="off" novalidate>
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">

        <label for="username">Username</label>
        <input type="text" id="username" name="username" maxlength="30" required>

        <label for="email">Email</label>
        <input type="email" id="email" name="email" maxlength="100" required>

        <label for="password">Password</label>
        <input type="password" id="password" name="password" maxlength="100" required>

        <label for="confirm_password">Konfirmasi Password</label>
        <input type="password" id="confirm_password" name="confirm_password" maxlength="100" required>

        <button type="submit">Daftar</button>
      </form>
    <?php endif; ?>
  </div>
</body>
</html>
