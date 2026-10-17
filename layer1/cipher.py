"""
Layer 1: End-to-End Encryption and Decryption Pipeline.

Chains padding → block splitting → per-block (XOR → XNOR → BitShift)
into ``layer1_encrypt`` and its exact inverse ``layer1_decrypt``.

Encryption pipeline per block (index i):
    1. XOR  block with subkey derived for block i
    2. XNOR block with mask    derived for block i
    3. Circular bit-shift left by shift_amount derived for block i

Decryption is the strict inverse applied in reverse order:
    1. Circular bit-shift right by the same shift_amount
    2. XNOR block with the same mask   (self-inverse)
    3. XOR  block with the same subkey (self-inverse)
"""

from .padding import pkcs7_pad, pkcs7_unpad, split_blocks, join_blocks
from .key_schedule import KeySchedule
from .operations import xor_block, xnor_block, bit_shift, reverse_bit_shift

# Default block size used throughout Layer 1 (16 bytes = 128-bit blocks)
_BLOCK_SIZE: int = 16


def layer1_encrypt(
    plaintext_bytes: bytes,
    key: bytes,
    block_size: int = _BLOCK_SIZE,
) -> bytes:
    """
    Encrypt arbitrary-length binary data using the Layer 1 logical-mathematical engine.

    The plaintext is PKCS#7-padded to a multiple of ``block_size``, split into
    fixed-size blocks, and each block is transformed independently with three
    reversible operations keyed per-block via HMAC-SHA256-based key scheduling:

        XOR(subkey_i) -> XNOR(mask_i) -> CircularBitShift_left(shift_i)

    Args:
        plaintext_bytes (bytes | bytearray): Arbitrary-length binary plaintext.
        key (bytes | bytearray): Master symmetric key (any non-empty byte string;
            32 bytes / 256 bits recommended).
        block_size (int): Block size in bytes. Must be 1-255 (PKCS#7 constraint).
            Default is 16 bytes (128-bit blocks).

    Returns:
        bytes: Ciphertext bytes. Length is always a multiple of ``block_size``
            (PKCS#7 padding is embedded; strip it on decrypt).

    Raises:
        TypeError:  If ``plaintext_bytes`` or ``key`` is not bytes/bytearray,
                    or ``block_size`` is not an int.
        ValueError: If ``key`` is empty or ``block_size`` is out of range.

    Example::

        from layer1 import generate_key, layer1_encrypt, layer1_decrypt

        key = generate_key(32)
        ciphertext = layer1_encrypt(b"Hello, HelixLock!", key)
        plaintext  = layer1_decrypt(ciphertext, key)
        assert plaintext == b"Hello, HelixLock!"
    """
    if not isinstance(plaintext_bytes, (bytes, bytearray)):
        raise TypeError(
            f"plaintext_bytes must be bytes or bytearray, got {type(plaintext_bytes).__name__}"
        )
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError(f"key must be bytes or bytearray, got {type(key).__name__}")
    if not key:
        raise ValueError("key cannot be empty")

    key_bytes = bytes(key)
    plain_bytes = bytes(plaintext_bytes)

    # Step 1: Pad to a multiple of block_size (PKCS#7 always adds at least 1 byte,
    # so the padding block itself carries the original length information needed
    # by the unpadding routine on decrypt).
    padded = pkcs7_pad(plain_bytes, block_size=block_size)

    # Step 2: Split into fixed-size blocks
    blocks = split_blocks(padded, block_size=block_size)

    # Step 3: Derive per-block keying material via HMAC-SHA256 key schedule
    ks = KeySchedule(key_bytes, block_size=block_size)

    # Step 4: Apply the three-stage forward pipeline to every block
    cipher_blocks: list[bytes] = []
    for i, block in enumerate(blocks):
        subkey = ks.get_subkey(i)
        mask = ks.get_mask(i)
        shift_amt = ks.get_shift_amount(i)

        step1 = xor_block(block, subkey)        # XOR with per-block subkey
        step2 = xnor_block(step1, mask)         # XNOR with per-block mask
        step3 = bit_shift(step2, shift_amt)     # Circular left-shift

        cipher_blocks.append(step3)

    return join_blocks(cipher_blocks)


def layer1_decrypt(
    ciphertext_bytes: bytes,
    key: bytes,
    block_size: int = _BLOCK_SIZE,
) -> bytes:
    """
    Decrypt ciphertext produced by ``layer1_encrypt`` back to the original plaintext.

    The inverse pipeline is applied per block in exact reverse order:

        CircularBitShift_right(shift_i) -> XNOR(mask_i) -> XOR(subkey_i)

    followed by PKCS#7 unpadding to recover the exact original plaintext.

    Args:
        ciphertext_bytes (bytes | bytearray): Ciphertext produced by ``layer1_encrypt``.
            Its length must be a non-zero multiple of ``block_size``.
        key (bytes | bytearray): Master symmetric key (must be identical to the
            key used during encryption).
        block_size (int): Block size in bytes. Must match the value used during
            encryption. Default is 16 bytes.

    Returns:
        bytes: Recovered plaintext bytes (PKCS#7 padding stripped).

    Raises:
        TypeError:  If ``ciphertext_bytes`` or ``key`` is not bytes/bytearray,
                    or ``block_size`` is not an int.
        ValueError: If ``key`` is empty, ``block_size`` is out of range,
                    ciphertext length is not a multiple of ``block_size``,
                    or PKCS#7 padding is invalid (wrong key or corrupted data).

    Example::

        from layer1 import generate_key, layer1_encrypt, layer1_decrypt

        key = generate_key(32)
        ct = layer1_encrypt(b"secret", key)
        pt = layer1_decrypt(ct, key)
        assert pt == b"secret"
    """
    if not isinstance(ciphertext_bytes, (bytes, bytearray)):
        raise TypeError(
            f"ciphertext_bytes must be bytes or bytearray, got {type(ciphertext_bytes).__name__}"
        )
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError(f"key must be bytes or bytearray, got {type(key).__name__}")
    if not key:
        raise ValueError("key cannot be empty")

    key_bytes = bytes(key)
    cipher_bytes = bytes(ciphertext_bytes)

    # Step 1: Split the ciphertext into blocks (raises ValueError if not aligned)
    blocks = split_blocks(cipher_bytes, block_size=block_size)

    # Step 2: Derive per-block keying material (same schedule as encryption)
    ks = KeySchedule(key_bytes, block_size=block_size)

    # Step 3: Apply the inverse pipeline to every block (exact reverse order)
    plain_blocks: list[bytes] = []
    for i, block in enumerate(blocks):
        subkey = ks.get_subkey(i)
        mask = ks.get_mask(i)
        shift_amt = ks.get_shift_amount(i)

        r1 = reverse_bit_shift(block, shift_amt)  # Undo circular left-shift
        r2 = xnor_block(r1, mask)                 # XNOR is self-inverse
        r3 = xor_block(r2, subkey)                # XOR is self-inverse

        plain_blocks.append(r3)

    # Step 4: Rejoin blocks and strip PKCS#7 padding
    padded_plain = join_blocks(plain_blocks)
    return pkcs7_unpad(padded_plain, block_size=block_size)
