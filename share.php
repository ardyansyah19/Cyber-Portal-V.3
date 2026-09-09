<?php
require_once __DIR__ . '/doc_functions.php';
// CATATAN: halaman ini SENGAJA tidak require_login() — siapa pun dengan link + password bisa akses.

$token = $_GET['token'] ?? $_POST['token'] ?? '';
$errors = [];
$lockMessage = null;

if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
    http_response_code(404);
    die('Link tidak valid.');
}

$stmt = $pdo->prepare('SELECT * FROM documents WHERE share_token = :token AND is_active = 1 LIMIT 1');
$stmt->execute([':token' => $token]);
$doc = $stmt->fetch();

if (!$doc) {
    http_response_code(404);
    die('Dokumen tidak ditemukan atau sudah dihapus.');
}

if ($doc['expires_at'] && strtotime($doc['expires_at']) < time()) {
    http_response_code(410);
    die('Link ini sudah kedaluwarsa.');
}

if ($doc['max_downloads'] !== null && $doc['download_count'] >= $doc['max_downloads']) {
    http_response_code(410);
    die('Batas jumlah unduhan untuk dokumen ini sudah tercapai.');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    if (!csrf_verify($_POST['csrf_token'] ?? null)) {
        $errors[] = 'Sesi tidak valid, silakan muat ulang halaman.';
    } elseif (is_document_ip_rate_limited($pdo, $doc['id'])) {
        $errors[] = 'Terlalu banyak percobaan dari alamat ini. Coba lagi nanti.';
    } elseif (is_document_locked($doc)) {
        $lockMessage = 'Dokumen dikunci sementara karena terlalu banyak percobaan password salah. Coba lagi setelah ' . DOC_LOCKOUT_MIN . ' menit.';
    } else {
        $password = (string) ($_POST['password'] ?? '');
        $result = open_document_with_password($doc, $password);

        if ($result === null) {
            register_document_failed_attempt($pdo, $doc);
            record_document_attempt($pdo, $doc['id'], false);
            $errors[] = 'Password salah.';
        } else {
            reset_document_failed_attempts($pdo, $doc['id']);
            record_document_attempt($pdo, $doc['id'], true);
            increment_download_count($pdo, $doc['id']);

            header('Content-Type: ' . $doc['mime_type']);
            header('Content-Disposition: attachment; filename="' . basename($result['filename']) . '"');
            header('Content-Length: ' . strlen($result['content']));
            header('X-Content-Type-Options: nosniff');
            header('Cache-Control: no-store, no-cache, must-revalidate');
            echo $result['content'];
            sodium_memzero($result['content']);
            exit;
        }
    }
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<title>Dokumen Terlindungi</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
  body{font-family:system-ui,sans-serif;background:#0f172a;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;padding:1rem}
  .card{background:#1e293b;padding:2rem;border-radius:12px;width:340px;box-shadow:0 10px 30px rgba(0,0,0,.4);text-align:center}
  h1{color:#f1f5f9;font-size:1.2rem}
  .file{color:#93c5fd;font-weight:600;margin:.5rem 0 1rem}
  label{color:#cbd5e1;font-size:.85rem;display:block;text-align:left}
  input{width:100%;padding:.6rem;border-radius:6px;border:1px solid #334155;background:#0f172a;color:#f1f5f9;margin-top:.3rem;box-sizing:border-box}
  button{width:100%;margin-top:1.2rem;padding:.7rem;border:none;border-radius:6px;background:#2563eb;color:#fff;font-weight:600;cursor:pointer}
  .err{background:#7f1d1d;color:#fecaca;padding:.6rem;border-radius:6px;margin-top:1rem;font-size:.85rem}
  .lock{background:#78350f;color:#fde68a;padding:.6rem;border-radius:6px;margin-top:1rem;font-size:.85rem}
</style>
</head>
<body>
  <div class="card">
    <h1>🔒 Dokumen Terlindungi</h1>
    <div class="file">📄 Dokumen rahasia</div>
    <p style="color:#94a3b8;font-size:.8rem;margin-top:-.5rem">Nama &amp; isi file disembunyikan sampai password benar dimasukkan. Masukkan password yang diberikan pengirim.</p>

    <?php foreach ($errors as $e): ?>
      <div class="err"><?= htmlspecialchars($e) ?></div>
    <?php endforeach; ?>
    <?php if ($lockMessage): ?>
      <div class="lock"><?= htmlspecialchars($lockMessage) ?></div>
    <?php endif; ?>

    <form method="POST" autocomplete="off">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
      <input type="hidden" name="token" value="<?= htmlspecialchars($token) ?>">
      <label for="password">Password Dokumen</label>
      <input type="password" id="password" name="password" required autofocus>
      <button type="submit">Buka &amp; Unduh</button>
    </form>
  </div>
</body>
</html>
