from fastapi.testclient import TestClient

from main import app


client = TestClient(app)


def test_api_fernet_round_trip_and_wrong_key_error():
    key = client.post("/api/fernet/key", json={}).json()["fernet_key"]
    wrong_key = client.post("/api/fernet/key", json={}).json()["fernet_key"]

    encrypted = client.post(
        "/api/encrypt",
        json={"mode": "fernet", "plaintext": "browser-safe secret", "fernet_key": key},
    ).json()
    assert encrypted["success"] is True

    decrypted = client.post(
        "/api/decrypt",
        json={"mode": "fernet", "ciphertext": encrypted["ciphertext"], "fernet_key": key},
    ).json()
    assert decrypted["plaintext"] == "browser-safe secret"

    failed = client.post(
        "/api/decrypt",
        json={
            "mode": "fernet",
            "ciphertext": encrypted["ciphertext"],
            "fernet_key": wrong_key,
        },
    )
    assert failed.status_code == 400
    assert failed.json()["error_code"] == "INVALID_KEY"


def test_api_rsa_plaintext_too_long_error():
    keys = client.post("/api/rsa/keypair", json={}).json()
    response = client.post(
        "/api/encrypt",
        json={
            "mode": "rsa",
            "plaintext": "x" * 191,
            "public_key": keys["public_key"],
        },
    )

    assert response.status_code == 400
    assert response.json()["error_code"] == "PLAINTEXT_TOO_LONG"


def test_api_hybrid_round_trip():
    keys = client.post("/api/rsa/keypair", json={}).json()
    message = "hybrid can carry a much larger local classroom message " * 12

    encrypted = client.post(
        "/api/encrypt",
        json={
            "mode": "hybrid",
            "plaintext": message,
            "public_key": keys["public_key"],
        },
    ).json()

    assert encrypted["success"] is True
    assert encrypted["encrypted_session_key"]

    decrypted = client.post(
        "/api/decrypt",
        json={
            "mode": "hybrid",
            "ciphertext": encrypted["ciphertext"],
            "encrypted_session_key": encrypted["encrypted_session_key"],
            "private_key": keys["private_key"],
        },
    ).json()

    assert decrypted["success"] is True
    assert decrypted["plaintext"] == message


def test_api_missing_field_contract():
    response = client.post(
        "/api/encrypt",
        json={"mode": "fernet", "plaintext": "secret"},
    )

    assert response.status_code == 400
    assert response.json()["error_code"] == "MISSING_FIELD"


def test_api_fernet_encrypt_returns_real_process_telemetry():
    key = client.post("/api/fernet/key", json={}).json()["fernet_key"]

    encrypted = client.post(
        "/api/encrypt",
        json={
            "mode": "fernet",
            "plaintext": "Hello World",
            "fernet_key": key,
            "return_telemetry": True,
        },
    ).json()

    telemetry = encrypted["telemetry"]
    assert telemetry["plaintext_bytes"] == 11
    assert telemetry["padding_count"] == 5
    assert len(telemetry["iv_bytes"]) == 16
    assert telemetry["token_components"]["iv"] == telemetry["iv_hex"]
    assert telemetry["token_components"]["hmac"] == telemetry["hmac_hex"]


def test_api_fernet_wrong_key_error_includes_hmac_failure_telemetry():
    key = client.post("/api/fernet/key", json={}).json()["fernet_key"]
    wrong_key = client.post("/api/fernet/key", json={}).json()["fernet_key"]
    encrypted = client.post(
        "/api/encrypt",
        json={
            "mode": "fernet",
            "plaintext": "integrity check",
            "fernet_key": key,
            "return_telemetry": True,
        },
    ).json()

    failed = client.post(
        "/api/decrypt",
        json={
            "mode": "fernet",
            "ciphertext": encrypted["ciphertext"],
            "fernet_key": wrong_key,
            "return_telemetry": True,
        },
    )

    body = failed.json()
    assert failed.status_code == 400
    assert body["error_code"] == "INVALID_KEY"
    assert body["telemetry"]["hmac_valid"] is False
    assert body["telemetry"]["computed_hmac_hex"] != body["telemetry"]["hmac_hex"]


def test_api_rsa_and_hybrid_telemetry_contracts():
    keys = client.post("/api/rsa/keypair", json={}).json()
    rsa_encrypted = client.post(
        "/api/encrypt",
        json={
            "mode": "rsa",
            "plaintext": "small",
            "public_key": keys["public_key"],
            "return_telemetry": True,
        },
    ).json()
    assert rsa_encrypted["telemetry"]["public_exponent"] == 65537
    assert rsa_encrypted["telemetry"]["ciphertext_bytes"] == 256

    hybrid_encrypted = client.post(
        "/api/encrypt",
        json={
            "mode": "hybrid",
            "plaintext": "hybrid theater payload",
            "public_key": keys["public_key"],
            "return_telemetry": True,
        },
    ).json()
    assert len(hybrid_encrypted["telemetry"]["session_key_bytes"]) == 32
    assert hybrid_encrypted["telemetry"]["fernet_iv_hex"]
    assert hybrid_encrypted["telemetry"]["session_key_encrypted_len"] == len(
        hybrid_encrypted["encrypted_session_key"]
    )


def test_health_validate_and_assistant_routes():
    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json()["version"] == "3.0.0"

    key = client.post("/api/fernet/key", json={}).json()["fernet_key"]
    valid = client.post(
        "/api/validate",
        json={"field": "fernet_key", "value": key},
    ).json()
    invalid = client.post(
        "/api/validate",
        json={"field": "public_key", "value": "not a pem"},
    ).json()
    assert valid["valid"] is True
    assert invalid["valid"] is False

    answer = client.post(
        "/api/assistant",
        json={"question": "Why does HMAC matter?", "mode": "fernet"},
    ).json()
    assert answer["success"] is True
    assert "HMAC" in answer["answer"]


def test_pwa_manifest_is_served():
    response = client.get("/static/manifest.json")
    assert response.status_code == 200
    assert response.json()["name"] == "Encryptify"
