-- =====================================================
-- TAMBAHAN SKEMA: FITUR BERBAGI DOKUMEN TERENKRIPSI
-- Jalankan setelah database.sql
-- =====================================================
USE secure_login_db;

-- =====================================================
-- documents
-- Setiap file disimpan dalam bentuk TERENKRIPSI (AES-256-GCM) di disk.
-- Kunci enkripsi file (DEK) TIDAK PERNAH disimpan polos:
--   - pw_wrapped_dek  = DEK yang dibungkus pakai kunci turunan dari PASSWORD dokumen
--   - owner_wrapped_dek = DEK yang dibungkus pakai MASTER KEY server (khusus pemilik/pengirim)
-- Dengan begitu, tanpa password ATAU tanpa master key, file tidak bisa dibuka sama sekali.
-- =====================================================
CREATE TABLE IF NOT EXISTS documents (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    share_token CHAR(64) NOT NULL UNIQUE,          -- token acak 256-bit untuk URL berbagi (anti-tebak)
    owner_id INT UNSIGNED NOT NULL,
    original_filename VARCHAR(255) NOT NULL,
    stored_filename VARCHAR(64) NOT NULL,          -- nama file acak di disk (bukan nama asli)
    mime_type VARCHAR(150) NOT NULL,
    file_size INT UNSIGNED NOT NULL,

    -- Enkripsi file utama (AES-256-GCM)
    file_iv VARCHAR(32) NOT NULL,                  -- base64, 12 byte IV
    file_tag VARCHAR(32) NOT NULL,                 -- base64, 16 byte auth tag

    -- Amplop kunci #1: dibuka pakai PASSWORD yang ditentukan pengirim
    password_salt VARCHAR(32) NOT NULL,            -- base64, salt PBKDF2
    pw_wrap_iv VARCHAR(32) NOT NULL,
    pw_wrap_tag VARCHAR(32) NOT NULL,
    pw_wrapped_dek VARCHAR(64) NOT NULL,

    -- Amplop kunci #2: dibuka otomatis untuk owner yang sudah login (pakai master key server)
    owner_wrap_iv VARCHAR(32) NOT NULL,
    owner_wrap_tag VARCHAR(32) NOT NULL,
    owner_wrapped_dek VARCHAR(64) NOT NULL,

    failed_attempts INT UNSIGNED NOT NULL DEFAULT 0,
    locked_until DATETIME NULL DEFAULT NULL,
    expires_at DATETIME NULL DEFAULT NULL,         -- opsional: kedaluwarsa otomatis
    max_downloads INT UNSIGNED NULL DEFAULT NULL,  -- opsional: batas jumlah unduhan
    download_count INT UNSIGNED NOT NULL DEFAULT 0,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_share_token (share_token)
) ENGINE=InnoDB;

-- =====================================================
-- document_access_log
-- Rate limiting & audit untuk percobaan buka dokumen via password
-- =====================================================
CREATE TABLE IF NOT EXISTS document_access_log (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    document_id INT UNSIGNED NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    success TINYINT(1) NOT NULL DEFAULT 0,
    attempted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
    INDEX idx_doc_ip_time (document_id, ip_address, attempted_at)
) ENGINE=InnoDB;
