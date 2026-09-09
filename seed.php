<?php
/**
 * seed.php
 * -----------------------------------------------------
 * Jalankan SEKALI dari CLI untuk mengisi/mereset password
 * dummy user dengan hash yang valid & benar-benar cocok.
 *
 *   php seed.php
 *
 * JANGAN taruh file ini di server produksi.
 * -----------------------------------------------------
 */

require_once __DIR__ . '/config.php';

$dummyUsers = [
    ['username' => 'admin_demo',   'email' => 'admin@demo.local', 'password' => 'P@ssw0rdKuat!123', 'role' => 'admin'],
    ['username' => 'budi_santoso', 'email' => 'budi@demo.local',  'password' => 'Budi#Aman2026',    'role' => 'user'],
    ['username' => 'siti_rahayu',  'email' => 'siti@demo.local',  'password' => 'Siti$Secure99',    'role' => 'user'],
];

foreach ($dummyUsers as $u) {
    // Argon2id lebih kuat dari bcrypt jika tersedia di server; fallback ke bcrypt.
    $algo = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT;
    $hash = password_hash($u['password'], $algo, ['cost' => 12]);

    $stmt = $pdo->prepare(
        "INSERT INTO users (username, email, password_hash, role, is_active)
         VALUES (:username, :email, :hash, :role, 1)
         ON DUPLICATE KEY UPDATE password_hash = :hash2, role = :role2"
    );
    $stmt->execute([
        ':username' => $u['username'],
        ':email'    => $u['email'],
        ':hash'     => $hash,
        ':role'     => $u['role'],
        ':hash2'    => $hash,
        ':role2'    => $u['role'],
    ]);

    echo "OK  : {$u['username']} -> password: {$u['password']}\n";
}

echo "\nSelesai. Silakan login dengan salah satu akun dummy di atas.\n";
