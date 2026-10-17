"""
HelixLock API — Crypto router.

Endpoints
---------
POST /api/v1/encrypt          — encrypt text or raw bytes (JSON)
POST /api/v1/decrypt          — decrypt to text and raw bytes (JSON)
GET  /api/v1/generate-key     — generate a fresh CSPRNG key
POST /api/v1/encrypt-file     — encrypt an uploaded file (multipart)
POST /api/v1/decrypt-file     — decrypt an uploaded file (multipart)

Text input uses UTF-8; binary data uses lowercase hex strings in JSON bodies.
File endpoints stream raw bytes with Content-Type: application/octet-stream.
The encryption key is returned / consumed via the X-HelixLock-Key-Hex header
on file endpoints, keeping it out of the URL and response body.

Phase-3 note: when the full helixlock pipeline (Layer1 + Layer2) is ready,
swap `_encrypt` / `_decrypt` below to call `helixlock.encrypt` / `helixlock.decrypt`
and add `LayerMode.both` to the schema.
"""

from __future__ import annotations

import io

from fastapi import APIRouter, HTTPException, Query, UploadFile, File, Header, Response
from fastapi.responses import StreamingResponse

from layer1 import generate_key, layer1_encrypt, layer1_decrypt
from ..schemas import (
    DecryptRequest,
    DecryptResponse,
    EncryptRequest,
    EncryptResponse,
    GenerateKeyResponse,
    LayerMode,
)

router = APIRouter()


# ---------------------------------------------------------------------------
# Internal dispatch (swap this out when Phase 3 pipeline lands)
# ---------------------------------------------------------------------------

def _encrypt(plaintext: bytes, key: bytes, layer: LayerMode) -> bytes:
    """Route to the correct encryption function based on the requested layer."""
    if layer == LayerMode.layer1:
        return layer1_encrypt(plaintext, key)
    # Phase 3+: elif layer == LayerMode.both: return helixlock.encrypt(plaintext, key)
    raise HTTPException(status_code=400, detail=f"Layer '{layer}' not yet implemented.")


def _decrypt(ciphertext: bytes, key: bytes, layer: LayerMode) -> bytes:
    """Route to the correct decryption function based on the requested layer."""
    if layer == LayerMode.layer1:
        return layer1_decrypt(ciphertext, key)
    raise HTTPException(status_code=400, detail=f"Layer '{layer}' not yet implemented.")


# ---------------------------------------------------------------------------
# GET /generate-key
# ---------------------------------------------------------------------------

@router.get(
    "/generate-key",
    response_model=GenerateKeyResponse,
    summary="Generate a fresh CSPRNG key",
    description=(
        "Generates a cryptographically secure random key using `secrets.token_bytes`. "
        "The default length is 32 bytes (256 bits). "
        "**Store the returned key securely** — it is required for decryption."
    ),
)
def generate_key_endpoint(
    length: int = Query(
        default=32,
        ge=1,
        le=512,
        description="Key length in bytes (1–512). Default: 32 (256 bits).",
    ),
) -> GenerateKeyResponse:
    key = generate_key(length)
    return GenerateKeyResponse(
        key_hex=key.hex(),
        key_length_bytes=len(key),
    )


# ---------------------------------------------------------------------------
# POST /encrypt  (JSON)
# ---------------------------------------------------------------------------

@router.post(
    "/encrypt",
    response_model=EncryptResponse,
    summary="Encrypt plain text or binary data",
    description=(
        "Encrypts text or arbitrary binary data using the selected HelixLock layer. "
        "Pass `plaintext` for normal text (encoded as UTF-8), or `plaintext_hex` "
        "for hex-encoded bytes. Supply exactly one non-null input. "
        "The key and returned ciphertext are **hex strings**. "
        "If `key_hex` is omitted, a fresh 256-bit key is generated automatically "
        "and returned in the response — **save it**, it cannot be recovered."
    ),
    openapi_extra={
        "requestBody": {
            "content": {
                "application/json": {
                    "examples": {
                        "text": {
                            "summary": "Encrypt normal text",
                            "description": "Replace the example key_hex with your own hex key, or omit it to generate a fresh key.",
                            "value": {"plaintext": "Hello world", "key_hex": "a1b2c3d4" * 8},
                        },
                        "hex": {
                            "summary": "Encrypt binary data",
                            "description": "Replace the example key_hex with your own hex key, or omit it to generate a fresh key.",
                            "value": {"plaintext_hex": "48656c6c6f20776f726c64", "key_hex": "a1b2c3d4" * 8},
                        },
                    }
                }
            }
        }
    },
)
def encrypt_endpoint(body: EncryptRequest) -> EncryptResponse:
    if body.plaintext is not None:
        try:
            plaintext = body.plaintext.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise HTTPException(
                status_code=422, detail="plaintext must be valid UTF-8 text"
            ) from exc
    else:
        plaintext = bytes.fromhex(body.plaintext_hex)

    # Use the provided key or generate a fresh one
    if body.key_hex is not None:
        key = bytes.fromhex(body.key_hex)
    else:
        key = generate_key(32)

    try:
        ciphertext = _encrypt(plaintext, key, body.layer)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return EncryptResponse(
        ciphertext_hex=ciphertext.hex(),
        key_hex=key.hex(),
        layer=body.layer,
        plaintext_length_bytes=len(plaintext),
        ciphertext_length_bytes=len(ciphertext),
    )


# ---------------------------------------------------------------------------
# POST /decrypt  (JSON)
# ---------------------------------------------------------------------------

@router.post(
    "/decrypt",
    response_model=DecryptResponse,
    summary="Decrypt ciphertext bytes",
    description=(
        "Decrypts ciphertext produced by `/encrypt`. "
        "Both ciphertext and key must be **lowercase hex strings**. "
        "Returns `plaintext` as UTF-8 text (null for non-UTF-8 binary data) "
        "and `plaintext_hex` for lossless access to the original bytes. "
        "Returns HTTP 422 if the ciphertext length is not a multiple of 16 bytes "
        "or if PKCS#7 padding validation fails (wrong key or corrupted data)."
    ),
)
def decrypt_endpoint(body: DecryptRequest) -> DecryptResponse:
    ciphertext = bytes.fromhex(body.ciphertext_hex)
    key = bytes.fromhex(body.key_hex)

    try:
        plaintext = _decrypt(ciphertext, key, body.layer)
    except ValueError as exc:
        # PKCS#7 failure → wrong key or corrupted ciphertext
        raise HTTPException(
            status_code=422,
            detail=f"Decryption failed — wrong key or corrupted ciphertext. ({exc})",
        ) from exc

    try:
        plaintext_text = plaintext.decode("utf-8")
    except UnicodeDecodeError:
        plaintext_text = None

    return DecryptResponse(
        plaintext=plaintext_text,
        plaintext_hex=plaintext.hex(),
        layer=body.layer,
        plaintext_length_bytes=len(plaintext),
    )


# ---------------------------------------------------------------------------
# POST /encrypt-file  (multipart upload)
# ---------------------------------------------------------------------------

@router.post(
    "/encrypt-file",
    summary="Encrypt an uploaded file",
    description=(
        "Upload any file and receive the encrypted binary back as an octet-stream download. "
        "Pass a hex key in the `X-HelixLock-Key-Hex` request header, or omit it to "
        "have a fresh 256-bit key generated automatically. "
        "The key used is always echoed back in the `X-HelixLock-Key-Hex` **response** header."
    ),
    response_class=Response,
    responses={
        200: {
            "content": {"application/octet-stream": {}},
            "description": "Encrypted file bytes.",
            "headers": {
                "X-HelixLock-Key-Hex": {
                    "description": "Hex-encoded key used for encryption.",
                    "schema": {"type": "string"},
                },
                "X-HelixLock-Original-Filename": {
                    "description": "Original uploaded filename.",
                    "schema": {"type": "string"},
                },
            },
        }
    },
)
async def encrypt_file_endpoint(
    file: UploadFile = File(..., description="File to encrypt."),
    x_helixlock_key_hex: str | None = Header(
        default=None,
        description="Optional hex-encoded master key. Omit to auto-generate.",
    ),
    layer: LayerMode = Query(default=LayerMode.layer1),
) -> Response:
    plaintext = await file.read()

    if x_helixlock_key_hex is not None:
        try:
            key = bytes.fromhex(x_helixlock_key_hex)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="X-HelixLock-Key-Hex header is not a valid hex string.",
            )
        if not key:
            raise HTTPException(status_code=400, detail="Key must not be empty.")
    else:
        key = generate_key(32)

    try:
        ciphertext = _encrypt(plaintext, key, layer)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    original_name = file.filename or "upload"
    return Response(
        content=ciphertext,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{original_name}.enc"',
            "X-HelixLock-Key-Hex": key.hex(),
            "X-HelixLock-Original-Filename": original_name,
        },
    )


# ---------------------------------------------------------------------------
# POST /decrypt-file  (multipart upload)
# ---------------------------------------------------------------------------

@router.post(
    "/decrypt-file",
    summary="Decrypt an uploaded encrypted file",
    description=(
        "Upload an `.enc` file produced by `/encrypt-file` and receive the "
        "decrypted binary back as an octet-stream download. "
        "The key **must** be supplied via the `X-HelixLock-Key-Hex` request header."
    ),
    response_class=Response,
    responses={
        200: {
            "content": {"application/octet-stream": {}},
            "description": "Decrypted file bytes.",
        }
    },
)
async def decrypt_file_endpoint(
    file: UploadFile = File(..., description="Encrypted file (.enc) to decrypt."),
    x_helixlock_key_hex: str = Header(
        ...,
        description="Hex-encoded master key used during encryption.",
    ),
    layer: LayerMode = Query(default=LayerMode.layer1),
) -> Response:
    ciphertext = await file.read()

    try:
        key = bytes.fromhex(x_helixlock_key_hex)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="X-HelixLock-Key-Hex header is not a valid hex string.",
        )
    if not key:
        raise HTTPException(status_code=400, detail="Key must not be empty.")

    if len(ciphertext) % 16 != 0:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Ciphertext length ({len(ciphertext)} bytes) is not a multiple of "
                "the block size (16 bytes). The file may be truncated or corrupted."
            ),
        )

    try:
        plaintext = _decrypt(ciphertext, key, layer)
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=f"Decryption failed — wrong key or corrupted ciphertext. ({exc})",
        ) from exc

    # Strip the .enc suffix from the filename if present
    original_name = file.filename or "decrypted"
    if original_name.endswith(".enc"):
        original_name = original_name[:-4]

    return Response(
        content=plaintext,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{original_name}"',
        },
    )
