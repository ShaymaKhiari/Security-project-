# Encryptify

Encryptify is a local FastAPI web application for encrypting, decrypting, and learning how cryptographic data moves through Fernet, RSA, and Hybrid encryption workflows. It was built for IT360 Information Assurance and Security at Tunis Business School.

The app pairs real cryptographic operations with an animated Process Theater, so students can encrypt actual text and then watch the operation unfold step by step.

## Features

- Fernet symmetric encryption and decryption
- RSA-2048 encryption and decryption with OAEP-SHA256
- Hybrid encryption using Fernet for message encryption and RSA for session-key wrapping
- Animated Process Theater with real telemetry from the backend
- Key generation for Fernet and RSA
- Inline validation for keys, tokens, and encrypted session keys
- Light and dark themes
- Session persistence in browser localStorage
- Exportable operation bundles
- Challenge mode for classroom practice
- Keyboard shortcuts and guided onboarding
- Optional AI explanation assistant with local fallback answers
- PWA metadata and manifest support

## Tech Stack

Backend:

- Python 3.11+
- FastAPI
- Uvicorn
- cryptography
- Pydantic
- pytest

Frontend:

- HTML5
- CSS3
- Vanilla JavaScript
- SVG and native Web Animations API
- Google Fonts

## Project Structure

```text
.
├── main.py
├── requirements.txt
├── models/
│   ├── __init__.py
│   └── schemas.py
├── services/
│   ├── __init__.py
│   ├── fernet_service.py
│   ├── rsa_service.py
│   └── hybrid_service.py
├── static/
│   ├── icon.svg
│   ├── manifest.json
│   └── service-worker.js
├── templates/
│   └── index.html
└── tests/
    ├── __init__.py
    ├── test_api.py
    ├── test_fernet.py
    ├── test_rsa.py
    └── test_hybrid.py
```

## Setup

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the app:

```bash
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

Open the app:

```text
http://127.0.0.1:8000
```

## Running Tests

```bash
pytest tests/ -v
```

## API Overview

### Health

```http
GET /api/health
```

Returns the server status and app version.

### Validate Input

```http
POST /api/validate
```

Checks whether a field is well formed without performing a full decrypt.

Example:

```json
{
  "field": "fernet_key",
  "value": "..."
}
```

### Generate Fernet Key

```http
POST /api/fernet/key
```

Returns a URL-safe Fernet key.

### Generate RSA Key Pair

```http
POST /api/rsa/keypair
```

Returns a PEM-encoded public key and private key.

### Encrypt

```http
POST /api/encrypt
```

Example Fernet request:

```json
{
  "mode": "fernet",
  "plaintext": "Hello World",
  "fernet_key": "...",
  "return_telemetry": true
}
```

Example RSA request:

```json
{
  "mode": "rsa",
  "plaintext": "short message",
  "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "return_telemetry": true
}
```

Example Hybrid request:

```json
{
  "mode": "hybrid",
  "plaintext": "longer message",
  "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "return_telemetry": true
}
```

### Decrypt

```http
POST /api/decrypt
```

Example Fernet request:

```json
{
  "mode": "fernet",
  "ciphertext": "...",
  "fernet_key": "...",
  "return_telemetry": true
}
```

Example Hybrid request:

```json
{
  "mode": "hybrid",
  "ciphertext": "...",
  "encrypted_session_key": "...",
  "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
  "return_telemetry": true
}
```

### Assistant

```http
POST /api/assistant
```

Answers cryptography-focused questions. If `ANTHROPIC_API_KEY` is set, the backend uses Anthropic. Otherwise, it returns local fallback explanations.

Optional environment variables:

```bash
export ANTHROPIC_API_KEY="your-api-key"
export ANTHROPIC_MODEL="claude-sonnet-4-20250514"
```

## Encryption Modes

### Fernet

Fernet uses one shared secret key for both encryption and decryption. Encryptify uses the `cryptography` implementation of Fernet, which combines AES-CBC encryption, PKCS7 padding, HMAC-SHA256 integrity checking, timestamps, and URL-safe Base64 tokens.

### RSA

RSA mode generates a 2048-bit key pair. The public key encrypts short messages, and the private key decrypts them. RSA encryption uses OAEP with SHA-256. Direct RSA encryption is size-limited, so larger messages should use Hybrid mode.

### Hybrid

Hybrid mode generates a fresh Fernet session key, encrypts the message with Fernet, and then encrypts the session key with RSA. The output includes both the encrypted message and the encrypted session key.

## Process Telemetry

When `return_telemetry` is `true`, encryption and decryption responses include intermediate values for the Process Theater. These values power the visual explanations, including padding length, IV bytes, token components, HMAC values, RSA key metadata, and Hybrid session-key details.

Telemetry is intended for education and local visualization. Do not expose it in a production encryption service.

## Browser Data

Encryptify stores session data in localStorage so users do not lose generated keys or ciphertext after refreshing the page. Use the Clear All button to remove saved local session data.

## Security Notes

- Encryptify is an academic learning tool, not a production key-management system.
- Private keys are shown in the browser for demonstration.
- Export bundles redact private keys by default.
- No persistent server-side storage is used.
- If the AI assistant is configured with `ANTHROPIC_API_KEY`, assistant questions may be sent to the Anthropic API. Encryption and decryption operations remain handled by the local FastAPI server.

## Troubleshooting

If the app cannot connect to the server, make sure Uvicorn is running:

```bash
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

If port 8000 is already in use, stop the existing process or run on another port:

```bash
uvicorn main:app --reload --host 127.0.0.1 --port 8001
```

If RSA direct encryption fails with a plaintext length error, switch to Hybrid mode.

## License

This project was prepared for academic coursework. Add a formal license file before distributing it publicly.
