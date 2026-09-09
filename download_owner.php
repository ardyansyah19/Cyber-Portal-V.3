<?php
require_once __DIR__ . '/doc_functions.php';
require_login();

$id = (int) ($_GET['id'] ?? 0);

$stmt = $pdo->prepare('SELECT * FROM documents WHERE id = :id AND owner_id = :uid LIMIT 1');
$stmt->execute([':id' => $id, ':uid' => $_SESSION['user_id']]);
$doc = $stmt->fetch();

if (!$doc) {
    http_response_code(404);
    log_activity($pdo, $_SESSION['user_id'], 'DOCUMENT_OWNER_ACCESS_DENIED');
    die('Dokumen tidak ditemukan atau Anda bukan pemiliknya.');
}

$result = open_document_as_owner($doc);

if ($result === null) {
    // Ini seharusnya tidak pernah terjadi kecuali master key berubah/rusak
    error_log("Gagal dekripsi owner untuk document ID {$doc['id']}");
    http_response_code(500);
    die('Terjadi kesalahan saat membuka dokumen.');
}

log_activity($pdo, $_SESSION['user_id'], 'DOCUMENT_OWNER_DOWNLOAD');
increment_download_count($pdo, $doc['id']);

// Stream file langsung ke browser, TIDAK ditulis ke disk dalam bentuk plaintext
header('Content-Type: ' . $doc['mime_type']);
header('Content-Disposition: attachment; filename="' . basename($result['filename']) . '"');
header('Content-Length: ' . strlen($result['content']));
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store, no-cache, must-revalidate');
echo $result['content'];
sodium_memzero($result['content']);
exit;
