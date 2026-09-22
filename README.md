# Sistem Login (PHP + MySQL)  V2
By Ahmad Riko Dyansyah

Sistem login + berbagi dokumen terenkripsi dengan lapisan keamanan berlapis (defense-in-depth).
Ditujukan untuk pembelajaran/pengembangan lokal — sesuaikan lagi sebelum dipakai produksi.

**Koreksi penting**: draf awal 2FA sempat memakai API QR pihak ketiga (`api.qrserver.com`) — ini dibatalkan karena akan mengirim *secret* 2FA ke server luar. Versi final memakai **manual setup key** yang di-generate dan ditampilkan sepenuhnya di server sendiri, tidak pernah dikirim ke pihak ketiga mana pun.

## Fitur Berbagi Dokumen Terenkripsi

Setiap dokumen (PDF/DOC/DOCX) dienkripsi dengan **AES-256-GCM** dan dilindungi password unik yang ditentukan pengirim. Tanpa password itu, dokumen tidak bisa dibuka oleh siapa pun.

### Cara kerja (envelope encryption)

1. File asli dienkripsi dengan **DEK** (Data Encryption Key) acak sekali pakai per dokumen.
2. DEK itu sendiri dibungkus **dua kali secara independen**:
   - **Amplop password**: dibuka dengan kunci turunan PBKDF2 dari password yang ditentukan pengirim → dipakai oleh siapa pun yang tahu password (link `share.php?token=...`).
   - **Amplop owner**: dibuka dengan *master key* rahasia di server (`DOC_MASTER_KEY`, disimpan di ENV) → dipakai otomatis saat pengirim (owner) login dan mengunduh dari `my_documents.php`, tanpa perlu masukkan password lagi.
3. File plaintext, DEK asli, dan password **tidak pernah** disimpan di database maupun disk.
4. Auth tag GCM otomatis menjadi mekanisme verifikasi password — password salah akan gagal decrypt, tanpa perlu simpan hash password terpisah.

Konsekuensinya: kalau database bocor sendirian, isi file tetap tidak bisa dibuka — penyerang butuh salah satu dari dua "kunci" independen (password dokumen ATAU master key server) yang keduanya tidak disimpan bersamaan dengan ciphertext.

### Setup tambahan untuk fitur dokumen

```bash
mysql -u root -p secure_login_db < database_documents.sql

# Generate master key 256-bit, simpan sebagai ENV (JANGAN taruh di kode/git)
php -r "echo base64_encode(random_bytes(32));"
export DOC_MASTER_KEY="hasil_base64_di_atas"
```

Alur pemakaian:
1. Login → **Bagikan Dokumen Terenkripsi** (`upload_document.php`) → upload file + tentukan password dokumen.
2. Salin link yang muncul, kirim ke penerima **lewat jalur berbeda** dari password (mis. link via email, password via WhatsApp) — praktik standar untuk berbagi rahasia (out-of-band).
3. Penerima buka link (`share.php?token=...`), masukkan password → file otomatis terdekripsi & terunduh.
4. Owner bisa lihat semua dokumennya, unduh tanpa password, atau hapus permanen di `my_documents.php`.

## Cara Menjalankan (Fresh Install)

1. **Buat database & tabel** (jalankan berurutan)
   ```bash
   mysql -u root -p < database.sql
   mysql -u root -p < database_documents.sql
   mysql -u root -p < database_v2_upgrade.sql
   ```

2. **Set environment variable** (jangan hardcode kredensial):
   ```bash
   export DB_HOST=127.0.0.1
   export DB_NAME=secure_login_db
   export DB_USER=db_user
   export DB_PASS="password_kuat_anda"
   export APP_PEPPER="string_rahasia_panjang_dan_acak_ganti_ini"

   # Master key untuk enkripsi dokumen (32 byte, generate sekali):
   export DOC_MASTER_KEY="$(php -r 'echo base64_encode(random_bytes(32));')"

   # Master key TERPISAH untuk enkripsi secret 2FA (jangan disamakan dengan DOC_MASTER_KEY):
   export TOTP_MASTER_KEY="$(php -r 'echo base64_encode(random_bytes(32));')"
   ```

3. **Isi data dummy dengan hash yang valid**:
   ```bash
   php seed.php
   ```
   Ini akan menampilkan 3 akun dummy beserta passwordnya:
   - `admin_demo` / `P@ssw0rdKuat!123`
   - `budi_santoso` / `Budi#Aman2026`
   - `siti_rahayu` / `Siti$Secure99`

4. **Jalankan server PHP** (untuk testing lokal):
   ```bash
   php -S localhost:8000
   ```
   Buka `http://localhost:8000/login.php`

### Kalau sudah pernah pakai v1

Cukup jalankan migrasinya saja, data lama tidak hilang:
```bash
mysql -u root -p secure_login_db < database_v2_upgrade.sql
export TOTP_MASTER_KEY="$(php -r 'echo base64_encode(random_bytes(32));')"
```
Dokumen yang diupload sebelum migrasi tetap bisa dibuka seperti biasa (kode sudah menangani kompatibilitas mundur untuk kolom `original_filename`).
