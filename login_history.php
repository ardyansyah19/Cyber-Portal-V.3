<?php
require_once __DIR__ . '/functions.php';
require_login();

$stmt = $pdo->prepare(
    'SELECT action, ip_address, user_agent, created_at
     FROM activity_log WHERE user_id = :uid
     ORDER BY created_at DESC LIMIT 50'
);
$stmt->execute([':uid' => $_SESSION['user_id']]);
$logs = $stmt->fetchAll();

$labels = [
    'LOGIN_SUCCESS'              => ['✅', 'Login berhasil'],
    'LOGIN_FAILED'               => ['❌', 'Percobaan login gagal'],
    'TWO_FA_SUCCESS'             => ['🔑', 'Verifikasi 2FA berhasil'],
    'TWO_FA_FAILED'              => ['⚠️', 'Kode 2FA salah'],
    '2FA_ENABLED'                => ['🔐', '2FA diaktifkan'],
    '2FA_DISABLED'               => ['🔓', '2FA dinonaktifkan'],
    'LOGOUT'                     => ['🚪', 'Logout'],
    'REGISTER'                   => ['📝', 'Registrasi akun'],
    'PASSWORD_RESET_REQUESTED'   => ['✉️', 'Meminta reset password'],
    'PASSWORD_RESET_COMPLETED'   => ['🔁', 'Password berhasil direset'],
    'DOCUMENT_UPLOAD'            => ['📤', 'Upload dokumen'],
    'DOCUMENT_DELETE'            => ['🗑️', 'Hapus dokumen'],
    'DOCUMENT_OWNER_DOWNLOAD'    => ['📥', 'Unduh dokumen milik sendiri'],
    'DOCUMENT_OWNER_ACCESS_DENIED' => ['🚫', 'Percobaan akses dokumen ditolak'],
];
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<title>Riwayat Aktivitas</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
  body{font-family:system-ui,sans-serif;background:#0f172a;color:#f1f5f9;margin:0;padding:2rem;display:flex;justify-content:center}
  .wrap{width:100%;max-width:640px}
  h1{font-size:1.4rem}
  table{width:100%;border-collapse:collapse;margin-top:1rem;font-size:.82rem}
  th,td{text-align:left;padding:.5rem .4rem;border-bottom:1px solid #334155}
  th{color:#94a3b8;font-weight:600}
  .muted{color:#64748b;font-size:.75rem}
  .nav{margin-bottom:1rem}
  a{color:#93c5fd;text-decoration:none;font-size:.85rem}
</style>
</head>
<body>
<div class="wrap">
  <div class="nav"><a href="dashboard.php">← Dashboard</a></div>
  <h1>🕘 Riwayat Aktivitas Akun</h1>
  <p class="muted">50 aktivitas terakhir di akun Anda. Kalau ada yang tidak Anda kenali, segera ganti password.</p>

  <table>
    <tr><th>Aktivitas</th><th>IP</th><th>Waktu</th></tr>
    <?php foreach ($logs as $log):
        [$icon, $label] = $labels[$log['action']] ?? ['•', $log['action']];
    ?>
    <tr>
      <td><?= $icon ?> <?= htmlspecialchars($label) ?></td>
      <td><?= htmlspecialchars($log['ip_address']) ?></td>
      <td><?= htmlspecialchars($log['created_at']) ?></td>
    </tr>
    <?php endforeach; ?>
    <?php if (empty($logs)): ?>
      <tr><td colspan="3" class="muted">Belum ada aktivitas tercatat.</td></tr>
    <?php endif; ?>
  </table>
</div>
</body>
</html>
