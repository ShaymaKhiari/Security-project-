import base64
import binascii
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


RSA_KEY_SIZE_BITS = 2048
RSA_KEY_SIZE_BYTES = RSA_KEY_SIZE_BITS // 8
OAEP_SHA256_MAX_BYTES = RSA_KEY_SIZE_BYTES - (2 * hashes.SHA256().digest_size) - 2


def generate_keypair() -> tuple[str, str]:
    """Return a PEM public/private key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE_BITS,
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return public_pem, private_pem


def encrypt(plaintext: str, public_key_pem: str) -> str:
    """Encrypt short plaintext with RSA-OAEP and return base64 ciphertext."""
    return encrypt_with_telemetry(plaintext, public_key_pem)["ciphertext"]


def encrypt_with_telemetry(plaintext: str, public_key_pem: str) -> dict[str, Any]:
    """Encrypt short plaintext and return RSA telemetry for the theater."""
    plaintext_bytes = plaintext.encode()
    if len(plaintext_bytes) > OAEP_SHA256_MAX_BYTES:
        raise ValueError("PLAINTEXT_TOO_LONG")

    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    ciphertext = public_key.encrypt(
        plaintext_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    ciphertext_b64 = base64.b64encode(ciphertext).decode()
    return {
        "ciphertext": ciphertext_b64,
        "telemetry": _rsa_public_telemetry(public_key)
        | {
            "algorithm": "RSA-OAEP-SHA256",
            "plaintext": plaintext,
            "plaintext_preview": _preview(plaintext),
            "plaintext_bytes": len(plaintext_bytes),
            "ciphertext_bytes": len(ciphertext),
            "ciphertext_hex_prefix": ciphertext.hex()[:96],
            "ciphertext_b64_len": len(ciphertext_b64),
            "ciphertext_b64_preview": _preview(ciphertext_b64, 72),
            "oaep_hash": "SHA-256",
            "oaep_randomized": True,
        },
    }


def decrypt(ciphertext_b64: str, private_key_pem: str) -> str:
    """Decrypt base64 RSA-OAEP ciphertext and return plaintext."""
    return decrypt_with_telemetry(ciphertext_b64, private_key_pem)["plaintext"]


def decrypt_with_telemetry(ciphertext_b64: str, private_key_pem: str) -> dict[str, Any]:
    """Decrypt RSA-OAEP ciphertext and return telemetry for the theater."""
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None,
    )
    try:
        ciphertext = base64.b64decode(ciphertext_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("CORRUPTED_CIPHERTEXT") from exc

    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    plaintext_text = plaintext.decode()
    return {
        "plaintext": plaintext_text,
        "telemetry": _rsa_private_telemetry(private_key)
        | {
            "algorithm": "RSA-OAEP-SHA256",
            "plaintext": plaintext_text,
            "plaintext_preview": _preview(plaintext_text),
            "plaintext_bytes": len(plaintext),
            "ciphertext_bytes": len(ciphertext),
            "ciphertext_b64_len": len(ciphertext_b64),
            "ciphertext_b64_preview": _preview(ciphertext_b64, 72),
            "oaep_hash": "SHA-256",
        },
    }


def _rsa_public_telemetry(public_key: Any) -> dict[str, Any]:
    numbers = public_key.public_numbers()
    modulus_hex = f"{numbers.n:0{RSA_KEY_SIZE_BYTES * 2}x}"
    return {
        "public_exponent": numbers.e,
        "key_size_bits": public_key.key_size,
        "modulus_prefix": _colon_hex(modulus_hex[:24]),
        "modulus_suffix": _colon_hex(modulus_hex[-24:]),
        "modulus_hex_prefix": modulus_hex[:48],
        "modulus_hex_suffix": modulus_hex[-48:],
    }


def _rsa_private_telemetry(private_key: Any) -> dict[str, Any]:
    private_numbers = private_key.private_numbers()
    public_telemetry = _rsa_public_telemetry(private_key.public_key())
    private_exponent_hex = f"{private_numbers.d:0{RSA_KEY_SIZE_BYTES * 2}x}"
    return public_telemetry | {
        "private_exponent_prefix": _colon_hex(private_exponent_hex[:24]),
        "private_exponent_suffix": _colon_hex(private_exponent_hex[-24:]),
    }


def _colon_hex(hex_value: str) -> str:
    return ":".join(hex_value[i : i + 2] for i in range(0, len(hex_value), 2))


def _preview(value: str, length: int = 48) -> str:
    return value if len(value) <= length else f"{value[:length]}..."
