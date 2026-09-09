-- =====================================================
-- SECURE LOGIN SYSTEM - DATABASE SCHEMA
-- =====================================================
-- Jalankan file ini di MySQL/MariaDB sebelum menjalankan aplikasi.

CREATE DATABASE IF NOT EXISTS secure_login_db
    CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE secure_login_db;

-- =====================================================
-- Tabel users
-- Password TIDAK PERNAH disimpan plaintext.
-- Kolom password_hash menyimpan hasil password_hash() PHP (bcrypt / Argon2id).
-- =====================================================
CREATE TABLE IF NOT EXISTS users (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('user', 'admin') NOT NULL DEFAULT 'user',
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    failed_attempts INT UNSIGNED NOT NULL DEFAULT 0,
    locked_until DATETIME NULL DEFAULT NULL,
    two_factor_secret VARCHAR(255) NULL DEFAULT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- =====================================================
-- Tabel login_attempts
-- Dipakai untuk rate limiting berbasis IP + username (anti brute force)
-- =====================================================
CREATE TABLE IF NOT EXISTS login_attempts (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    identifier VARCHAR(100) NOT NULL,   -- bisa username atau IP address
    ip_address VARCHAR(45) NOT NULL,
    success TINYINT(1) NOT NULL DEFAULT 0,
    attempted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_identifier_time (identifier, attempted_at),
    INDEX idx_ip_time (ip_address, attempted_at)
) ENGINE=InnoDB;

-- =====================================================
-- Tabel activity_log (audit trail sederhana)
-- =====================================================
CREATE TABLE IF NOT EXISTS activity_log (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNSIGNED NULL,
    action VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent VARCHAR(255) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- =====================================================
-- DATA DUMMY
-- Password asli (plaintext, HANYA untuk testing lokal):
--   admin_demo   -> P@ssw0rdKuat!123
--   budi_santoso -> Budi#Aman2026
--   siti_rahayu  -> Siti$Secure99
--
-- Hash di bawah ini dibuat memakai password_hash($pw, PASSWORD_BCRYPT)
-- Silakan generate ulang hash-nya sendiri lewat generate_hash.php (disertakan)
-- agar tidak bergantung pada hash statis di file ini.
-- =====================================================
INSERT INTO users (username, email, password_hash, role, is_active) VALUES
('admin_demo',   'admin@demo.local',  '$2y$12$W3v9x7iH9m0Q2n1kQeS8SOqk0m4Zq0m2y2b8yQeS8SOqk0m4Zq0m2', 'admin', 1),
('budi_santoso', 'budi@demo.local',   '$2y$12$W3v9x7iH9m0Q2n1kQeS8SOqk0m4Zq0m2y2b8yQeS8SOqk0m4Zq0m2', 'user',  1),
('siti_rahayu',  'siti@demo.local',   '$2y$12$W3v9x7iH9m0Q2n1kQeS8SOqk0m4Zq0m2y2b8yQeS8SOqk0m4Zq0m2', 'user',  1);

-- PENTING: hash di atas hanyalah placeholder format bcrypt yang valid secara
-- struktur, TAPI belum tentu cocok dengan password plaintext di komentar.
-- Jalankan generate_hash.php lalu UPDATE tabel users, atau gunakan seed.php
-- yang disertakan agar hash benar-benar valid dan bisa langsung login.
