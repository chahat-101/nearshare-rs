# NearShare-rs

NearShare-rs is a local, web-based file sharing app built with Rust and Actix Web.
It encrypts uploaded files with AES-256-GCM before storing them on disk and decrypts them on download.

## Features

- Token-based authentication (`admin` / `password` by default)
- AES-256-GCM encryption for uploaded files
- Multi-file upload support
- File listing and download APIs
- mDNS service advertisement (`_fileshare._tcp.local.`)
- Single-page frontend with brutal minimalist orange/white/black theme
- Session-aware cleanup on startup, login, and logout (`POST /api/logout`)
- Frontend session token and cached file list are stored in `sessionStorage`

## Tech Stack

- Rust (edition 2024)
- Actix Web
- Actix Multipart
- Tokio
- AES-GCM
- mDNS-SD
- Plain HTML/CSS/JavaScript frontend (`frontend.html`)

## Quick Start

### Prerequisites

- Rust toolchain installed (`rustup`, `cargo`)

### Run

```bash
cargo run --release
```

Server starts on:

- `http://localhost:8080`

Login credentials:

- Username: `admin`
- Password: `password`

## How It Works

1. User authenticates via `POST /api/auth`.
1. Server returns a bearer token.
1. Frontend stores token in `sessionStorage`.
1. Uploads are encrypted server-side using AES-256-GCM.
1. Each encrypted file stores a random 12-byte nonce prefix + ciphertext.
1. Downloads decrypt on-the-fly and return the original file bytes.

## API Endpoints

Base URL: `http://localhost:8080`

### `POST /api/auth`

Authenticate and get a session token.

Request body:

```json
{
  "username": "admin",
  "password": "password"
}
```

Response:

```json
{
  "token": "<bearer-token>"
}
```

### `GET /api/session`

Validate current bearer token.

Header:

- `Authorization: Bearer <token>`

### `POST /api/logout`

Invalidate current token and clear uploaded files.

Header:

- `Authorization: Bearer <token>`

### `POST /api/upload`

Upload one or more files via multipart form data (`files` field).

Header:

- `Authorization: Bearer <token>`

### `GET /api/files`

List uploaded filenames for the active session context.

Header:

- `Authorization: Bearer <token>`

### `GET /api/download/{filename}`

Download and decrypt a stored file.

Header:

- `Authorization: Bearer <token>`

## Project Structure

```text
nearshare-rs/
  src/
    main.rs          # Actix server, auth, encryption, upload/download handlers
  frontend.html      # Single-page UI
  Cargo.toml
  README.md
```

## Development

Type-check and compile without running:

```bash
cargo check
```

## Security Notes

This project is a demo and not production hardened. Before production use:

- Replace hardcoded credentials
- Add token expiration and rotation
- Add HTTPS/TLS
- Add filename/path sanitization hardening
- Enforce file size and rate limits
- Add structured error handling and audit logging
