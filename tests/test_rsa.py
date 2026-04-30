import pytest

from services import rsa_service


def test_rsa_encrypt_decrypt_round_trip():
    public_key, private_key = rsa_service.generate_keypair()
    ciphertext = rsa_service.encrypt("short secret", public_key)

    assert ciphertext != "short secret"
    assert rsa_service.decrypt(ciphertext, private_key) == "short secret"


def test_rsa_oaep_randomization_for_same_plaintext():
    public_key, _ = rsa_service.generate_keypair()

    first = rsa_service.encrypt("same plaintext", public_key)
    second = rsa_service.encrypt("same plaintext", public_key)

    assert first != second


def test_rsa_rejects_plaintext_over_oaep_limit():
    public_key, _ = rsa_service.generate_keypair()
    oversized = "x" * (rsa_service.OAEP_SHA256_MAX_BYTES + 1)

    with pytest.raises(ValueError, match="PLAINTEXT_TOO_LONG"):
        rsa_service.encrypt(oversized, public_key)
