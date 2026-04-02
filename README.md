# NearShare-rs

Secure local file sharing with AES-256-GCM encryption, built with Rust and Actix-web.

## Features

- 🔐 AES-256-GCM encryption for all files
- 🔑 Token-based authentication
- 💾 Persistent browser session across page reloads
- 📤 Multiple file upload support
- 🌐 mDNS service discovery
- 💻 Web-based interface

## Quick Start

```bash
cargo run --release
```

Open `http://localhost:8080` and login:
- **Username**: `admin`
- **Password**: `password`

## API Endpoints

- `POST /api/auth` - Login and get token
- `GET /api/session` - Validate an existing session token
- `POST /api/upload` - Upload files (requires auth)
- `GET /api/files` - List files (requires auth)
- `GET /api/download/{filename}` - Download file (requires auth)

All authenticated requests require `Authorization: Bearer <token>` header.

## How It Works

Files are encrypted with AES-256-GCM before storage. A random 12-byte nonce is prepended to each encrypted file. During download, files are decrypted on-the-fly.

## Security Notes

⚠️ **This is a demo project.** For production use:
- Change hardcoded credentials
- Add HTTPS/TLS
- Implement rate limiting and file size limits
- Add token expiration
- Validate filenames and paths
