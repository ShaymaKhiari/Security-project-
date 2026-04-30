from services import hybrid_service, rsa_service


def test_hybrid_encrypt_decrypt_round_trip_for_long_message():
    public_key, private_key = rsa_service.generate_keypair()
    message = "Hybrid mode handles longer text. " * 40

    encrypted = hybrid_service.encrypt(message, public_key)
    plaintext = hybrid_service.decrypt(
        encrypted["ciphertext"],
        encrypted["encrypted_session_key"],
        private_key,
    )

    assert encrypted["ciphertext"] != message
    assert encrypted["encrypted_session_key"]
    assert plaintext == message


def test_hybrid_uses_fresh_session_key_each_time():
    public_key, _ = rsa_service.generate_keypair()
    message = "repeatable input"

    first = hybrid_service.encrypt(message, public_key)
    second = hybrid_service.encrypt(message, public_key)

    assert first["ciphertext"] != second["ciphertext"]
    assert first["encrypted_session_key"] != second["encrypted_session_key"]
