<?php
require_once __DIR__ . '/doc_functions.php';
require_login();

$errors = [];
$shareUrl = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    if (!csrf_verify($_POST['csrf_token'] ?? null)) {
        $errors[] = 'Sesi tidak valid, silakan muat ulang halaman.';
    } else {
        $docPassword = (string) ($_POST['doc_password'] ?? '');
        $confirmPw   = (string) ($_POST['doc_password_confirm'] ?? '');
        $expiresDays = (int) ($_POST['expires_days'] ?? 0);

        if (!isset($_FILES['document']) || $_FILES['document']['error'] === UPLOAD_ERR_NO_FILE) {
            $errors[] = 'Silakan pilih file terlebih dahulu.';
        }

        if (strlen($docPassword) < 8) {
            $errors[] = 'Password dokumen minimal 8 karakter.';
        }
        if ($docPassword !== $confirmPw) {
            $errors[] = 'Konfirmasi password dokumen tidak cocok.';
        }

        if (empty($errors)) {
            $fileErrors = validate_uploaded_file($_FILES['document']);
            $errors = array_merge($errors, $fileErrors);
        }

        if (empty($errors)) {
            try {
                $expiresAt = $expiresDays > 0
                    ? date('Y-m-d H:i:s', strtotime("+{$expiresDays} days"))
                    : null;

                $token = store_encrypted_document(
                    $pdo,
                    (int) $_SESSION['user_id'],
                    $_FILES['document'],
                    $docPassword,
                    $expiresAt
                );

                $scheme = isset($_SERVER['HTTPS']) ? 'https' : 'http';
                $shareUrl = $scheme . '://' . $_SERVER['HTTP_HOST'] . dirname($_SERVER['SCRIPT_NAME']) . '/share.php?token=' . $token;
            } catch (Throwable $e) {
                error_log('Upload error: ' . $e->getMessage());
                $errors[] = 'Terjadi kesalahan saat memproses file. Silakan coba lagi.';
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<title>Bagikan Dokumen Aman</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
  body{font-family:system-ui,sans-serif;background:#0f172a;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;padding:1rem}
  .card{background:#1e293b;padding:2rem;border-radius:12px;width:400px;box-shadow:0 10px 30px rgba(0,0,0,.4)}
  h1{color:#f1f5f9;font-size:1.3rem;margin-bottom:.3rem}
  p.sub{color:#94a3b8;font-size:.8rem;margin-top:0}
  label{color:#cbd5e1;font-size:.85rem;display:block;margin-top:1rem}
  input,select{width:100%;padding:.6rem;border-radius:6px;border:1px solid #334155;background:#0f172a;color:#f1f5f9;margin-top:.3rem;box-sizing:border-box}
  button{width:100%;margin-top:1.4rem;padding:.7rem;border:none;border-radius:6px;background:#2563eb;color:#fff;font-weight:600;cursor:pointer}
  button:hover{background:#1d4ed8}
  .err{background:#7f1d1d;color:#fecaca;padding:.6rem;border-radius:6px;margin-top:1rem;font-size:.85rem}
  .ok{background:#14532d;color:#bbf7d0;padding:.8rem;border-radius:6px;margin-top:1rem;font-size:.85rem;word-break:break-all}
  .nav{margin-top:1.2rem;text-align:center}
  a{color:#93c5fd;font-size:.85rem}
</style>
</head>
<body>
  <div class="card">
    <h1>🔒 Bagikan Dokumen Terenkripsi</h1>
    <p class="sub">File dienkripsi AES-256-GCM. Hanya yang tahu password bisa membukanya.</p>

    <?php foreach ($errors as $e): ?>
      <div class="err"><?= htmlspecialchars($e) ?></div>
    <?php endforeach; ?>

    <?php if ($shareUrl): ?>
      <div class="ok">
        ✅ Berhasil! Bagikan link ini ke penerima:<br><br>
        <code><?= htmlspecialchars($shareUrl) ?></code><br><br>
        Jangan lupa beri tahu password dokumennya lewat jalur terpisah (misal WhatsApp/telepon), <b>jangan di kirim di pesan yang sama dengan link</b>.
      </div>
    <?php else: ?>
      <form method="POST" enctype="multipart/form-data" autocomplete="off" novalidate>
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">

        <label for="document">Pilih File (PDF / DOC / DOCX, maks <?= MAX_UPLOAD_SIZE / 1024 / 1024 ?>MB)</label>
        <input type="file" id="document" name="document" accept=".pdf,.doc,.docx" required>

        <label for="doc_password">Password Dokumen</label>
        <input type="password" id="doc_password" name="doc_password" minlength="8" required>

        <label for="doc_password_confirm">Konfirmasi Password</label>
        <input type="password" id="doc_password_confirm" name="doc_password_confirm" minlength="8" required>

        <label for="expires_days">Kedaluwarsa Otomatis (opsional)</label>
        <select id="expires_days" name="expires_days">
          <option value="0">Tidak ada batas waktu</option>
          <option value="1">1 hari</option>
          <option value="7">7 hari</option>
          <option value="30">30 hari</option>
        </select>

        <button type="submit">Enkripsi &amp; Bagikan</button>
      </form>
    <?php endif; ?>

    <div class="nav">
      <a href="my_documents.php">📂 Dokumen Saya</a> &nbsp;•&nbsp; <a href="dashboard.php">← Dashboard</a>
    </div>
  </div>
</body>
</html>
