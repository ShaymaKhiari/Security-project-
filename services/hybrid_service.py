import base64
from typing import Any

from services import fernet_service, rsa_service


def encrypt(plaintext: str, public_key_pem: str) -> dict[str, str]:
    """Encrypt data with a fresh Fernet session key, then wrap the key with RSA."""
    return encrypt_with_telemetry(plaintext, public_key_pem)


def encrypt_with_telemetry(plaintext: str, public_key_pem: str) -> dict[str, Any]:
    """Encrypt with Fernet, wrap the session key with RSA, and return telemetry."""
    session_key = fernet_service.generate_key()
    message_result = fernet_service.encrypt_with_telemetry(plaintext, session_key)
    key_result = rsa_service.encrypt_with_telemetry(session_key, public_key_pem)
    return {
        "ciphertext": message_result["ciphertext"],
        "encrypted_session_key": key_result["ciphertext"],
        "telemetry": {
            "algorithm": "Hybrid Fernet + RSA-OAEP",
            "plaintext": plaintext,
            "plaintext_preview": _preview(plaintext),
            "session_key_b64": session_key,
            "session_key_bytes": _byte_list(base64.urlsafe_b64decode(session_key.encode())),
            "message_encrypted_len": len(message_result["ciphertext"]),
            "session_key_encrypted_len": len(key_result["ciphertext"]),
            "fernet_iv_hex": message_result["telemetry"]["iv_hex"],
            "fernet_iv_bytes": message_result["telemetry"]["iv_bytes"],
            "fernet_hmac_prefix": message_result["telemetry"]["hmac_prefix"],
            "fernet": message_result["telemetry"],
            "rsa": key_result["telemetry"],
        },
    }


def decrypt(ciphertext: str, encrypted_session_key: str, private_key_pem: str) -> str:
    """Recover the Fernet session key via RSA, then decrypt the message."""
    return decrypt_with_telemetry(ciphertext, encrypted_session_key, private_key_pem)["plaintext"]


def decrypt_with_telemetry(
    ciphertext: str,
    encrypted_session_key: str,
    private_key_pem: str,
) -> dict[str, Any]:
    """Unwrap the Fernet key, decrypt the message, and return telemetry."""
    key_result = rsa_service.decrypt_with_telemetry(encrypted_session_key, private_key_pem)
    session_key = key_result["plaintext"]
    message_result = fernet_service.decrypt_with_telemetry(ciphertext, session_key)
    return {
        "plaintext": message_result["plaintext"],
        "telemetry": {
            "algorithm": "Hybrid Fernet + RSA-OAEP",
            "plaintext": message_result["plaintext"],
            "plaintext_preview": _preview(message_result["plaintext"]),
            "session_key_b64": session_key,
            "session_key_bytes": _byte_list(base64.urlsafe_b64decode(session_key.encode())),
            "message_encrypted_len": len(ciphertext),
            "session_key_encrypted_len": len(encrypted_session_key),
            "fernet_iv_hex": message_result["telemetry"]["iv_hex"],
            "fernet_iv_bytes": message_result["telemetry"]["iv_bytes"],
            "fernet_hmac_prefix": message_result["telemetry"]["hmac_prefix"],
            "fernet": message_result["telemetry"],
            "rsa": key_result["telemetry"],
        },
    }


def _byte_list(data: bytes) -> list[str]:
    return [f"{byte:02X}" for byte in data]


def _preview(value: str, length: int = 48) -> str:
    return value if len(value) <= length else f"{value[:length]}..."
