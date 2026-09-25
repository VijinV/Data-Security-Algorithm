"""
Layer 1: Cryptographically Secure Pseudo-Random Number Generator (CSPRNG) Key Generation.

This module provides CSPRNG key generation using Python's `secrets.token_bytes`
for Layer 1 of the HelixLock algorithm.
"""

import secrets


def generate_key(length: int = 32) -> bytes:
    """
    Generate a cryptographically secure random key of specified byte length using `secrets.token_bytes`.

    Args:
        length (int): Length of the generated key in bytes. Default is 32 bytes (256 bits).

    Returns:
        bytes: Cryptographically secure random byte string.

    Raises:
        TypeError: If length is not an integer.
        ValueError: If length is not a positive integer.
    """
    if not isinstance(length, int) or isinstance(length, bool):
        raise TypeError(f"Key length must be an integer, got {type(length).__name__}")
    if length <= 0:
        raise ValueError(f"Key length must be a positive integer (> 0), got {length}")

    return secrets.token_bytes(length)


# Alias for explicit CSPRNG naming
generate_csprng_key = generate_key
