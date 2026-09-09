-- =====================================================
-- MIGRASI v2 — Jalankan SETELAH database.sql dan database_documents.sql
-- =====================================================
USE secure_login_db;

-- ---- 2FA & tracking login pada tabel users ----
-- two_factor_secret sekarang menyimpan secret TOTP dalam bentuk TERENKRIPSI
-- (format: base64(iv).base64(tag).base64(ciphertext)) — bukan plaintext.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS two_factor_enabled TINYINT(1) NOT NULL DEFAULT 0 AFTER two_factor_secret,
    ADD COLUMN IF NOT EXISTS last_login_at DATETIME NULL DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS last_login_ip VARCHAR(45) NULL DEFAULT NULL,
    MODIFY COLUMN two_factor_secret VARCHAR(255) NULL DEFAULT NULL;

-- ---- Reset password aman (token di-hash, sekali pakai, kedaluwarsa) ----
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNSIGNED NOT NULL,
    token_hash CHAR(64) NOT NULL,      -- SHA-256 dari token asli; token asli TIDAK pernah disimpan
    expires_at DATETIME NOT NULL,
    used TINYINT(1) NOT NULL DEFAULT 0,
    ip_address VARCHAR(45) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_token_hash (token_hash)
) ENGINE=InnoDB;

-- ---- Rate limiting registrasi (anti spam akun) ----
CREATE TABLE IF NOT EXISTS registration_attempts (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    attempted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ip_time (ip_address, attempted_at)
) ENGINE=InnoDB;

-- ---- Enkripsi nama file dokumen (dulu tersimpan plaintext di original_filename) ----
ALTER TABLE documents
    MODIFY COLUMN original_filename VARCHAR(255) NULL,
    ADD COLUMN IF NOT EXISTS encrypted_filename VARCHAR(512) NULL AFTER original_filename,
    ADD COLUMN IF NOT EXISTS filename_iv VARCHAR(32) NULL AFTER encrypted_filename,
    ADD COLUMN IF NOT EXISTS filename_tag VARCHAR(32) NULL AFTER filename_iv;

-- Catatan: dokumen yang diupload SEBELUM migrasi ini masih memakai kolom
-- original_filename (plaintext). Dokumen baru akan pakai kolom terenkripsi.
-- Kode aplikasi (doc_functions.php) sudah menangani kedua kasus ini.
