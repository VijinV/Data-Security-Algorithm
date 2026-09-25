"""
Layer 1: Block Splitting and PKCS#7 Padding Utility.

Provides functions for PKCS#7 padding/unpadding and block splitting/joining
for fixed-size block encryption in Layer 1.
"""


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """
    Apply PKCS#7 padding to binary data.

    Args:
        data (bytes): Input binary data to be padded.
        block_size (int): Fixed block size in bytes (default 16 bytes).

    Returns:
        bytes: Padded binary data whose length is a multiple of block_size.

    Raises:
        TypeError: If data is not bytes or block_size is not an integer.
        ValueError: If block_size is not between 1 and 255 inclusive.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"Data must be bytes or bytearray, got {type(data).__name__}")
    if not isinstance(block_size, int) or isinstance(block_size, bool):
        raise TypeError(f"Block size must be an integer, got {type(block_size).__name__}")
    if not (1 <= block_size <= 255):
        raise ValueError(f"Block size must be between 1 and 255 bytes, got {block_size}")

    data_bytes = bytes(data)
    padding_len = block_size - (len(data_bytes) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data_bytes + padding


def pkcs7_unpad(padded_data: bytes, block_size: int = 16) -> bytes:
    """
    Remove PKCS#7 padding from binary data.

    Args:
        padded_data (bytes): Padded binary data to be unpadded.
        block_size (int): Fixed block size in bytes (default 16 bytes).

    Returns:
        bytes: Original unpadded binary data.

    Raises:
        TypeError: If padded_data is not bytes or block_size is not an integer.
        ValueError: If block_size is invalid, padded_data is empty,
                   length is not a multiple of block_size, or padding is invalid.
    """
    if not isinstance(padded_data, (bytes, bytearray)):
        raise TypeError(f"Padded data must be bytes or bytearray, got {type(padded_data).__name__}")
    if not isinstance(block_size, int) or isinstance(block_size, bool):
        raise TypeError(f"Block size must be an integer, got {type(block_size).__name__}")
    if not (1 <= block_size <= 255):
        raise ValueError(f"Block size must be between 1 and 255 bytes, got {block_size}")

    data_bytes = bytes(padded_data)
    if not data_bytes or len(data_bytes) % block_size != 0:
        raise ValueError("Padded data length must be a non-zero multiple of block_size")

    padding_len = data_bytes[-1]
    if padding_len < 1 or padding_len > block_size:
        raise ValueError("Invalid PKCS#7 padding length byte")

    # Check that all padding bytes match padding_len
    expected_padding = bytes([padding_len] * padding_len)
    if data_bytes[-padding_len:] != expected_padding:
        raise ValueError("Invalid PKCS#7 padding bytes")

    return data_bytes[:-padding_len]


def split_blocks(data: bytes, block_size: int = 16) -> list[bytes]:
    """
    Split binary data into a list of fixed-size blocks.

    Data length must be a multiple of block_size (use `pkcs7_pad` first if unpadded).

    Args:
        data (bytes): Binary data to split.
        block_size (int): Block size in bytes (default 16 bytes).

    Returns:
        list[bytes]: List of block byte strings, each of length block_size.

    Raises:
        TypeError: If data is not bytes or block_size is not integer.
        ValueError: If data length is not a multiple of block_size or block_size is invalid.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"Data must be bytes or bytearray, got {type(data).__name__}")
    if not isinstance(block_size, int) or isinstance(block_size, bool):
        raise TypeError(f"Block size must be an integer, got {type(block_size).__name__}")
    if block_size <= 0:
        raise ValueError(f"Block size must be a positive integer, got {block_size}")

    data_bytes = bytes(data)
    if len(data_bytes) % block_size != 0:
        raise ValueError(
            f"Data length ({len(data_bytes)}) must be a multiple of block_size ({block_size}). "
            "Consider using pkcs7_pad first."
        )

    return [data_bytes[i : i + block_size] for i in range(0, len(data_bytes), block_size)]


def join_blocks(blocks: list[bytes]) -> bytes:
    """
    Join a list of binary blocks back into a single byte string.

    Args:
        blocks (list[bytes]): List of binary block byte strings.

    Returns:
        bytes: Concatenated binary data.

    Raises:
        TypeError: If blocks is not a list/iterable or contains non-bytes items.
    """
    if not isinstance(blocks, (list, tuple)):
        raise TypeError(f"Blocks must be a list or tuple of bytes, got {type(blocks).__name__}")
    for idx, block in enumerate(blocks):
        if not isinstance(block, (bytes, bytearray)):
            raise TypeError(f"Block at index {idx} must be bytes, got {type(block).__name__}")

    return b"".join(bytes(b) for b in blocks)


# Aliases for convenience
pad = pkcs7_pad
unpad = pkcs7_unpad
