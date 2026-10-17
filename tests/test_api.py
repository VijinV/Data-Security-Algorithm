"""Regression coverage for the JSON API's text and binary input contracts."""

import pytest
from fastapi.testclient import TestClient

from api.main import app


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.mark.parametrize(
    ("plaintext", "expected_hex"),
    [
        ("Hello world", "48656c6c6f20776f726c64"),
        ("café 🌍", "636166c3a920f09f8c8d"),
        ("deadbeef", "6465616462656566"),
        ("", ""),
        ("  Hello\nworld\t", "202048656c6c6f0a776f726c6409"),
        ("a" * 40, "61" * 40),
    ],
)
def test_text_encrypt_decrypt_round_trip(client, plaintext, expected_hex):
    encrypted = client.post("/api/v1/encrypt", json={"plaintext": plaintext})
    assert encrypted.status_code == 200, encrypted.text
    result = encrypted.json()
    assert result["plaintext_length_bytes"] == len(expected_hex) // 2
    assert len(bytes.fromhex(result["key_hex"])) == 32
    assert result["ciphertext_length_bytes"] == len(bytes.fromhex(result["ciphertext_hex"]))

    decrypted = client.post("/api/v1/decrypt", json={
        "ciphertext_hex": result["ciphertext_hex"], "key_hex": result["key_hex"],
    })
    assert decrypted.status_code == 200, decrypted.text
    assert decrypted.json()["plaintext"] == plaintext
    assert decrypted.json()["plaintext_hex"] == expected_hex
    assert decrypted.json()["plaintext_length_bytes"] == len(expected_hex) // 2


@pytest.mark.parametrize("plaintext_hex", ["00FF80FE", "48656c6c6f", ""])
def test_existing_hex_requests_preserve_bytes_and_key(client, plaintext_hex):
    key_hex = "a1b2c3d4" * 8
    encrypted = client.post("/api/v1/encrypt", json={
        "plaintext_hex": plaintext_hex, "key_hex": key_hex,
    })
    assert encrypted.status_code == 200, encrypted.text
    assert encrypted.json()["key_hex"] == key_hex
    decrypted = client.post("/api/v1/decrypt", json={
        "ciphertext_hex": encrypted.json()["ciphertext_hex"], "key_hex": key_hex,
    })
    assert decrypted.status_code == 200, decrypted.text
    assert decrypted.json()["plaintext_hex"] == plaintext_hex.lower()
    if plaintext_hex == "00FF80FE":
        assert decrypted.json()["plaintext"] is None


@pytest.mark.parametrize("payload", [
    {},
    {"plaintext": None},
    {"plaintext": "Hello", "plaintext_hex": "48656c6c6f"},
    {"plaintext": "", "plaintext_hex": ""},
    {"plaintext_hex": "Hello world"},
    {"plaintext_hex": "abc"},
    {"plaintext": 123},
    {"plaintext": "Hello", "key_hex": "invalid"},
    {"plaintext": "Hello", "key_hex": ""},
])
def test_encrypt_rejects_invalid_or_ambiguous_input(client, payload):
    response = client.post("/api/v1/encrypt", json=payload)
    assert response.status_code == 422, response.text


def test_text_and_hex_encrypt_identical_bytes_with_supplied_key(client):
    key_hex = "a1b2c3d4" * 8
    text_response = client.post("/api/v1/encrypt", json={
        "plaintext": "Hello world", "key_hex": key_hex,
    })
    hex_response = client.post("/api/v1/encrypt", json={
        "plaintext_hex": "48656c6c6f20776f726c64", "key_hex": key_hex,
    })
    assert text_response.status_code == hex_response.status_code == 200
    assert text_response.json() == hex_response.json()


def test_encrypt_rejects_unpaired_unicode_surrogate():
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post(
            "/api/v1/encrypt",
            content=r'{"plaintext":"\ud800"}',
            headers={"Content-Type": "application/json"},
        )
    assert response.status_code == 422, response.text
