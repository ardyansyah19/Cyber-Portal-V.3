<?php
require_once __DIR__ . '/doc_functions.php';
require_login();

$errors = [];

// Hapus dokumen
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_id'])) {
    if (!csrf_verify($_POST['csrf_token'] ?? null)) {
        $errors[] = 'Sesi tidak valid.';
    } else {
        $stmt = $pdo->prepare('SELECT * FROM documents WHERE id = :id AND owner_id = :uid');
        $stmt->execute([':id' => (int) $_POST['delete_id'], ':uid' => $_SESSION['user_id']]);
        $doc = $stmt->fetch();

        if ($doc) {
            secure_delete_file(STORAGE_DIR . '/' . $doc['stored_filename']); // timpa lalu hapus, bukan cuma unlink
            $del = $pdo->prepare('DELETE FROM documents WHERE id = :id');
            $del->execute([':id' => $doc['id']]);
            log_activity($pdo, $_SESSION['user_id'], 'DOCUMENT_DELETE');
        }
    }
}

$stmt = $pdo->prepare(
    'SELECT id, share_token, original_filename, encrypted_filename, filename_iv, filename_tag,
            owner_wrapped_dek, owner_wrap_iv, owner_wrap_tag,
            file_size, mime_type, expires_at, download_count, created_at, is_active
     FROM documents WHERE owner_id = :uid ORDER BY created_at DESC'
);
$stmt->execute([':uid' => $_SESSION['user_id']]);
$documents = $stmt->fetchAll();

$scheme = isset($_SERVER['HTTPS']) ? 'https' : 'http';
$baseUrl = $scheme . '://' . $_SERVER['HTTP_HOST'] . dirname($_SERVER['SCRIPT_NAME']);
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<title>Dokumen Saya</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
  body{font-family:system-ui,sans-serif;background:#0f172a;color:#f1f5f9;margin:0;padding:2rem;display:flex;justify-content:center}
  .wrap{width:100%;max-width:720px}
  h1{font-size:1.4rem}
  .doc{background:#1e293b;border-radius:10px;padding:1rem 1.2rem;margin-top:1rem}
  .doc .name{font-weight:600}
  .doc .meta{color:#94a3b8;font-size:.8rem;margin-top:.2rem}
  .doc .actions{margin-top:.7rem;display:flex;gap:.6rem;flex-wrap:wrap}
  .btn{padding:.4rem .8rem;border-radius:6px;text-decoration:none;font-size:.8rem;border:none;cursor:pointer}
  .btn-download{background:#2563eb;color:#fff}
  .btn-copy{background:#334155;color:#f1f5f9}
  .btn-delete{background:#dc2626;color:#fff}
  .expired{color:#f87171;font-size:.75rem}
  .nav{margin-bottom:1rem}
  a.top{color:#93c5fd;font-size:.85rem;text-decoration:none}
  .empty{color:#64748b;margin-top:1.5rem}
</style>
</head>
<body>
<div class="wrap">
  <div class="nav">
    <a class="top" href="dashboard.php">← Dashboard</a> &nbsp;•&nbsp;
    <a class="top" href="upload_document.php">+ Upload Dokumen Baru</a>
  </div>
  <h1>📂 Dokumen Saya</h1>

  <?php if (empty($documents)): ?>
    <p class="empty">Belum ada dokumen yang dibagikan.</p>
  <?php endif; ?>

  <?php foreach ($documents as $doc):
      $isExpired = $doc['expires_at'] && strtotime($doc['expires_at']) < time();
      $shareLink = $baseUrl . '/share.php?token=' . $doc['share_token'];
      $displayName = decrypt_document_filename_only($doc);
  ?>
    <div class="doc">
      <div class="name">📄 <?= htmlspecialchars($displayName) ?></div>
      <div class="meta">
        <?= number_format($doc['file_size'] / 1024, 1) ?> KB &middot;
        diupload <?= htmlspecialchars($doc['created_at']) ?> &middot;
        diunduh <?= (int) $doc['download_count'] ?>x
        <?php if ($doc['expires_at']): ?>
          &middot; <span class="<?= $isExpired ? 'expired' : '' ?>">
            <?= $isExpired ? 'Kedaluwarsa' : 'Berlaku sampai' ?> <?= htmlspecialchars($doc['expires_at']) ?>
          </span>
        <?php endif; ?>
      </div>
      <div class="actions">
        <a class="btn btn-download" href="download_owner.php?id=<?= (int) $doc['id'] ?>">Unduh (tanpa password)</a>
        <button class="btn btn-copy" type="button" data-share-link="<?= htmlspecialchars($shareLink, ENT_QUOTES) ?>">Salin Link Bagikan</button>
        <form method="POST" style="display:inline" data-confirm="Hapus dokumen ini secara permanen?">
          <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
          <input type="hidden" name="delete_id" value="<?= (int) $doc['id'] ?>">
          <button class="btn btn-delete" type="submit">Hapus</button>
        </form>
      </div>
    </div>
  <?php endforeach; ?>
</div>

<script nonce="<?= htmlspecialchars(csp_nonce()) ?>">
// CSP ketat: tidak ada 'unsafe-inline', semua event listener didaftarkan di sini,
// bukan lewat atribut onclick="" di HTML.
document.querySelectorAll('[data-share-link]').forEach(function (btn) {
    btn.addEventListener('click', function () {
        navigator.clipboard.writeText(btn.getAttribute('data-share-link'))
            .then(function () { btn.textContent = 'Tersalin!'; })
            .catch(function () { btn.textContent = 'Gagal menyalin'; });
    });
});
document.querySelectorAll('form[data-confirm]').forEach(function (form) {
    form.addEventListener('submit', function (e) {
        if (!confirm(form.getAttribute('data-confirm'))) {
            e.preventDefault();
        }
    });
});
</script>
</body>
</html>
