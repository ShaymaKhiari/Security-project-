import base64
import binascii
import hashlib
import hmac
import os
import struct
import time
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


FERNET_VERSION = b"\x80"
BLOCK_SIZE = 16


class FernetTelemetryError(Exception):
    """Raised when Fernet decryption fails after telemetry was collected."""

    def __init__(self, error_code: str, telemetry: dict[str, Any]):
        super().__init__(error_code)
        self.error_code = error_code
        self.telemetry = telemetry


def generate_key() -> str:
    """Return a URL-safe base64-encoded Fernet key."""
    return Fernet.generate_key().decode()


def encrypt(plaintext: str, key: str) -> str:
    """Encrypt text and return a Fernet token."""
    return encrypt_with_telemetry(plaintext, key)["ciphertext"]


def decrypt(token: str, key: str) -> str:
    """Decrypt a Fernet token and return plaintext."""
    fernet = Fernet(key.encode())
    return fernet.decrypt(token.encode()).decode()


def encrypt_with_telemetry(plaintext: str, key: str) -> dict[str, Any]:
    """Perform Fernet encryption and expose intermediate values for animation."""
    signing_key, encryption_key = _split_key(key)
    data = plaintext.encode("utf-8")
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    padded = data + bytes([pad_len] * pad_len)
    iv = os.urandom(BLOCK_SIZE)

    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    timestamp_value = int(time.time())
    timestamp = struct.pack(">Q", timestamp_value)
    pre_hmac = FERNET_VERSION + timestamp + iv + ciphertext
    mac = hmac.new(signing_key, pre_hmac, hashlib.sha256).digest()
    token_bytes = pre_hmac + mac
    token = base64.urlsafe_b64encode(token_bytes).decode()

    return {
        "ciphertext": token,
        "telemetry": _fernet_telemetry(
            plaintext=plaintext,
            padded=padded,
            iv=iv,
            ciphertext=ciphertext,
            mac=mac,
            timestamp=timestamp,
            token=token,
            hmac_valid=True,
        ),
    }


def decrypt_with_telemetry(token: str, key: str) -> dict[str, Any]:
    """Decrypt a Fernet token and expose parse, HMAC, and padding telemetry."""
    signing_key, encryption_key = _split_key(key)
    try:
        raw = base64.urlsafe_b64decode(token.encode())
        version, timestamp, iv, ciphertext, stored_hmac = _parse_token(raw)
    except (binascii.Error, ValueError) as exc:
        raise FernetTelemetryError(
            "CORRUPTED_CIPHERTEXT",
            {
                "token": token,
                "token_length": len(token),
                "parse_error": "Token is not valid Fernet Base64url data.",
                "hmac_valid": False,
            },
        ) from exc

    pre_hmac = version + timestamp + iv + ciphertext
    computed_hmac = hmac.new(signing_key, pre_hmac, hashlib.sha256).digest()
    hmac_valid = hmac.compare_digest(stored_hmac, computed_hmac)
    base_telemetry = _fernet_telemetry(
        plaintext="",
        padded=b"",
        iv=iv,
        ciphertext=ciphertext,
        mac=stored_hmac,
        timestamp=timestamp,
        token=token,
        hmac_valid=hmac_valid,
        computed_hmac=computed_hmac,
        version=version,
    )
    if not hmac_valid:
        raise FernetTelemetryError("INVALID_KEY", base_telemetry)

    try:
        cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        pad_len = padded[-1]
        if pad_len < 1 or pad_len > BLOCK_SIZE:
            raise InvalidToken
        if padded[-pad_len:] != bytes([pad_len] * pad_len):
            raise InvalidToken
        plaintext_bytes = padded[:-pad_len]
        plaintext = plaintext_bytes.decode("utf-8")
    except Exception as exc:
        raise FernetTelemetryError("CORRUPTED_CIPHERTEXT", base_telemetry) from exc

    telemetry = _fernet_telemetry(
        plaintext=plaintext,
        padded=padded,
        iv=iv,
        ciphertext=ciphertext,
        mac=stored_hmac,
        timestamp=timestamp,
        token=token,
        hmac_valid=True,
        computed_hmac=computed_hmac,
        version=version,
    )
    telemetry["recovered_plaintext_hex"] = plaintext_bytes.hex()
    return {"plaintext": plaintext, "telemetry": telemetry}


def _split_key(key: str) -> tuple[bytes, bytes]:
    try:
        key_bytes = base64.urlsafe_b64decode(key.encode())
    except (binascii.Error, ValueError) as exc:
        raise ValueError("INVALID_KEY") from exc
    if len(key_bytes) != 32:
        raise ValueError("INVALID_KEY")
    return key_bytes[:16], key_bytes[16:]


def _parse_token(raw: bytes) -> tuple[bytes, bytes, bytes, bytes, bytes]:
    if len(raw) < 1 + 8 + 16 + 16 + 32:
        raise ValueError("Token is too short.")
    version = raw[:1]
    if version != FERNET_VERSION:
        raise ValueError("Unsupported Fernet token version.")
    timestamp = raw[1:9]
    iv = raw[9:25]
    stored_hmac = raw[-32:]
    ciphertext = raw[25:-32]
    if len(ciphertext) == 0 or len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext is not a full AES block.")
    return version, timestamp, iv, ciphertext, stored_hmac


def _fernet_telemetry(
    *,
    plaintext: str,
    padded: bytes,
    iv: bytes,
    ciphertext: bytes,
    mac: bytes,
    timestamp: bytes,
    token: str,
    hmac_valid: bool,
    computed_hmac: bytes | None = None,
    version: bytes = FERNET_VERSION,
) -> dict[str, Any]:
    plaintext_bytes = plaintext.encode("utf-8")
    padding_count = padded[-1] if padded else 0
    padded_hex = padded.hex()
    return {
        "algorithm": "Fernet",
        "token": token,
        "plaintext": plaintext,
        "plaintext_preview": _preview(plaintext),
        "plaintext_bytes": len(plaintext_bytes),
        "block_count": len(ciphertext) // BLOCK_SIZE,
        "padding_byte": padding_count,
        "padding_count": padding_count,
        "padded_hex": padded_hex,
        "padded_blocks": _hex_blocks(padded),
        "iv_hex": iv.hex(),
        "iv_bytes": _byte_list(iv),
        "ciphertext_hex": ciphertext.hex(),
        "ciphertext_blocks": _hex_blocks(ciphertext),
        "hmac_hex": mac.hex(),
        "hmac_prefix": mac.hex()[:16],
        "computed_hmac_hex": computed_hmac.hex() if computed_hmac else mac.hex(),
        "computed_hmac_prefix": (computed_hmac or mac).hex()[:16],
        "hmac_valid": hmac_valid,
        "token_version": f"0x{version.hex()}",
        "timestamp": timestamp.hex().upper(),
        "timestamp_unix": struct.unpack(">Q", timestamp)[0],
        "token_length": len(token),
        "token_components": {
            "version": version.hex(),
            "timestamp": timestamp.hex(),
            "iv": iv.hex(),
            "ciphertext": ciphertext.hex(),
            "hmac": mac.hex(),
        },
    }


def _hex_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> list[str]:
    return [data[i : i + block_size].hex() for i in range(0, len(data), block_size)]


def _byte_list(data: bytes) -> list[str]:
    return [f"{byte:02X}" for byte in data]


def _preview(value: str, length: int = 48) -> str:
    return value if len(value) <= length else f"{value[:length]}..."
