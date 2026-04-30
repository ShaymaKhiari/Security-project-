import pytest
from cryptography.fernet import InvalidToken

from services import fernet_service


def test_fernet_encrypt_decrypt_round_trip():
    key = fernet_service.generate_key()
    token = fernet_service.encrypt("IT360 secret", key)

    assert token != "IT360 secret"
    assert fernet_service.decrypt(token, key) == "IT360 secret"


def test_fernet_randomization_for_same_plaintext():
    key = fernet_service.generate_key()

    first = fernet_service.encrypt("same plaintext", key)
    second = fernet_service.encrypt("same plaintext", key)

    assert first != second


def test_fernet_wrong_key_fails():
    token = fernet_service.encrypt("classified", fernet_service.generate_key())

    with pytest.raises(InvalidToken):
        fernet_service.decrypt(token, fernet_service.generate_key())
