<?php
require_once __DIR__ . '/functions.php';
require_login(); // tolak akses jika belum login
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<title>Dashboard</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
  body{font-family:system-ui,sans-serif;background:#0f172a;color:#f1f5f9;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
  .card{background:#1e293b;padding:2rem;border-radius:12px;width:360px;text-align:center}
  a.btn{display:inline-block;margin-top:1.5rem;padding:.6rem 1.2rem;background:#dc2626;color:#fff;border-radius:6px;text-decoration:none}
</style>
</head>
<body>
  <div class="card">
    <h1>✅ Selamat datang, <?= htmlspecialchars($_SESSION['username']) ?>!</h1>
    <p>Role Anda: <strong><?= htmlspecialchars($_SESSION['role']) ?></strong></p>
    <p>Anda berhasil login melalui sistem yang menerapkan hashing password, proteksi CSRF, rate limiting, dan session hardening.</p>
    <p><a href="upload_document.php" style="color:#93c5fd">📤 Bagikan Dokumen Terenkripsi</a></p>
    <p><a href="my_documents.php" style="color:#93c5fd">📂 Dokumen Saya</a></p>
    <p><a href="setup_2fa.php" style="color:#93c5fd">🔐 Pengaturan 2FA</a></p>
    <p><a href="login_history.php" style="color:#93c5fd">🕘 Riwayat Aktivitas</a></p>
    <a class="btn" href="logout.php">Logout</a>
  </div>
</body>
</html>
