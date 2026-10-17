"""
HelixLock API — Pydantic request / response schemas.

Keeping schemas in one place makes it easy to extend them when
Layer 2 and the full helixlock pipeline land in Phase 3.
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Shared enumerations
# ---------------------------------------------------------------------------

class LayerMode(str, Enum):
    """Which encryption layers to apply (extensible for Phase 3+)."""
    layer1 = "layer1"
    # layer2  = "layer2"   # uncomment when Phase 2 is merged
    # both    = "both"     # full HelixLock pipeline (Phase 3)


# ---------------------------------------------------------------------------
# /encrypt  (JSON body)
# ---------------------------------------------------------------------------

class EncryptRequest(BaseModel):
    """
    Request body for POST /api/v1/encrypt.

    The plaintext and key are transmitted as hex strings so that arbitrary
    binary data can be sent over a JSON API without base64 ambiguity.
    """

    plaintext_hex: Annotated[
        str,
        Field(
            description="Plaintext bytes encoded as a lowercase hex string (e.g. '48656c6c6f').",
            examples=["48656c6c6f2c20576f726c6421"],
        ),
    ]
    key_hex: Annotated[
        str,
        Field(
            description=(
                "Master key encoded as a lowercase hex string. "
                "Omit to have the server generate a fresh 256-bit key automatically."
            ),
            default=None,
            examples=[None, "a1b2c3d4" * 8],
        ),
    ] = None
    layer: LayerMode = LayerMode.layer1

    @field_validator("plaintext_hex")
    @classmethod
    def validate_plaintext_hex(cls, v: str) -> str:
        try:
            bytes.fromhex(v)
        except ValueError:
            raise ValueError("plaintext_hex must be a valid hex string")
        return v.lower()

    @field_validator("key_hex", mode="before")
    @classmethod
    def validate_key_hex(cls, v) -> str | None:
        if v is None:
            return None
        try:
            raw = bytes.fromhex(v)
        except ValueError:
            raise ValueError("key_hex must be a valid hex string")
        if len(raw) < 1:
            raise ValueError("key_hex must be at least 1 byte")
        return v.lower()


class EncryptResponse(BaseModel):
    """Response body for POST /api/v1/encrypt."""

    ciphertext_hex: str = Field(
        description="Ciphertext bytes encoded as a lowercase hex string."
    )
    key_hex: str = Field(
        description=(
            "The key used for encryption (hex). "
            "Store this securely — it is required for decryption."
        )
    )
    layer: LayerMode
    plaintext_length_bytes: int = Field(
        description="Length of the original plaintext in bytes."
    )
    ciphertext_length_bytes: int = Field(
        description="Length of the ciphertext in bytes (always a multiple of 16)."
    )


# ---------------------------------------------------------------------------
# /decrypt  (JSON body)
# ---------------------------------------------------------------------------

class DecryptRequest(BaseModel):
    """Request body for POST /api/v1/decrypt."""

    ciphertext_hex: Annotated[
        str,
        Field(
            description="Ciphertext bytes encoded as a lowercase hex string.",
            examples=["a3f0..."],
        ),
    ]
    key_hex: Annotated[
        str,
        Field(
            description="Master key encoded as a lowercase hex string.",
            examples=["a1b2c3d4" * 8],
        ),
    ]
    layer: LayerMode = LayerMode.layer1

    @field_validator("ciphertext_hex")
    @classmethod
    def validate_ciphertext_hex(cls, v: str) -> str:
        try:
            raw = bytes.fromhex(v)
        except ValueError:
            raise ValueError("ciphertext_hex must be a valid hex string")
        if len(raw) % 16 != 0:
            raise ValueError(
                f"ciphertext_hex must represent a byte string whose length is "
                f"a multiple of 16 (got {len(raw)} bytes)"
            )
        return v.lower()

    @field_validator("key_hex")
    @classmethod
    def validate_key_hex(cls, v: str) -> str:
        try:
            raw = bytes.fromhex(v)
        except ValueError:
            raise ValueError("key_hex must be a valid hex string")
        if len(raw) < 1:
            raise ValueError("key_hex must be at least 1 byte")
        return v.lower()


class DecryptResponse(BaseModel):
    """Response body for POST /api/v1/decrypt."""

    plaintext_hex: str = Field(
        description="Recovered plaintext bytes encoded as a lowercase hex string."
    )
    layer: LayerMode
    plaintext_length_bytes: int


# ---------------------------------------------------------------------------
# /generate-key
# ---------------------------------------------------------------------------

class GenerateKeyResponse(BaseModel):
    """Response body for GET /api/v1/generate-key."""

    key_hex: str = Field(description="Fresh CSPRNG key encoded as a hex string.")
    key_length_bytes: int


# ---------------------------------------------------------------------------
# /encrypt-file  and  /decrypt-file  (multipart, responses defined inline)
# ---------------------------------------------------------------------------
# File-upload endpoints return raw bytes (application/octet-stream) so no
# Pydantic model is needed for the response body.  The key is returned in a
# custom response header: X-HelixLock-Key-Hex.
