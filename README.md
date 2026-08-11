# Gomit2FA — Two-Factor Authentication Plugin for OJS

TOTP-based two-factor authentication via Google Authenticator for Open Journal Systems.

## Compatibility

| Branch | OJS Version |
|--------|-------------|
| `ojs-3.3.0-13` | OJS 3.3.0-13 (stable-3_3_0) |

## Features

- **Google Authenticator / Authy / Microsoft Authenticator** — standard TOTP (RFC 6238)
- **CSRF protection** on all forms
- **Rate limiting** — 5 OTP attempts per 15 minutes
- **Backup codes** — 8 one-time-use codes, stored with `password_hash()`
- **Encrypted secret** — AES-256-CBC, key derived from OJS config salt
- **Local QR Code** — generated client-side in browser (qrcode.js), secret never sent to external APIs
- **CSPRNG** — `random_int()` for secret generation
- **Timing-safe** — `hash_equals()` for code verification
- **Disable requires OTP** — confirmation code required before deactivating 2FA

## Installation

```bash
# Clone the branch matching your OJS version
git clone -b ojs-3.3.0-13 https://github.com/Cv-Media-Inti-Teknologi/OJS-2FA.git

# Copy to your OJS installation
cp -r OJS-2FA/ /path/to/ojs/plugins/generic/gomit2fa/

# Enable via Dashboard > Settings > Website > Plugins > Generic Plugins > Gomit 2FA Plugin
```

## Usage

1. Log in to OJS
2. Click **2FA Settings** in the user navigation
3. Click **Start 2FA Setup**
4. Scan the QR Code with Google Authenticator
5. Save your backup codes
6. Enter the 6-digit code to activate

## License

GNU GPL v2
