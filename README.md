# Gomit2FA — Two-Factor Authentication Plugin for OJS

Plugin keamanan autentikasi dua langkah (TOTP) via Google Authenticator untuk Open Journal Systems.

## Kompatibilitas

| Branch | OJS Version |
|--------|-------------|
| `ojs-3.3.0-13` | OJS 3.3.0-13 (stable-3_3_0) |

## Fitur

- **Google Authenticator / Authy / Microsoft Authenticator** — TOTP standar (RFC 6238)
- **CSRF protection** di semua form
- **Rate limiting** — 5 percobaan OTP / 15 menit
- **Backup codes** — 8 kode satu kali pakai, di-hash dengan `password_hash()`
- **Enkripsi secret** — AES-256-CBC, key dari config salt OJS
- **QR Code lokal** — generate di browser (qrcode.js), secret tidak dikirim ke API eksternal
- **CSPRNG** — `random_int()` untuk secret generation
- **Timing-safe** — `hash_equals()` untuk verifikasi kode
- **Disable butuh OTP** — konfirmasi kode sebelum matikan 2FA

## Instalasi

```bash
# Clone branch sesuai versi OJS
git clone -b ojs-3.3.0-13 https://github.com/Cv-Media-Inti-Teknologi/OJS-2FA.git

# Copy ke OJS
cp -r OJS-2FA/ /path/to/ojs/plugins/generic/gomit2fa/

# Aktifkan via Dashboard > Settings > Website > Plugins > Generic Plugins > Gomit 2FA Plugin
```

## Penggunaan

1. Login ke OJS
2. Klik **Pengaturan 2FA** di navigasi user
3. Klik **Mulai Konfigurasi 2FA**
4. Scan QR Code dengan Google Authenticator
5. Simpan backup codes
6. Masukkan kode 6 digit untuk mengaktifkan

## Lisensi

GNU GPL v2
