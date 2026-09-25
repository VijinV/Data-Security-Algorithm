"""
Layer 1: Key Scheduling and Per-Block Subkey Derivation.

Provides HMAC-SHA256 based subkey derivation for each block in Layer 1.
Ensures that each block receives a distinct, cryptographically strong subkey,
mask, and shift amount derived deterministically from the master key and block index.
"""

import hashlib
import hmac


def derive_subkey(
    master_key: bytes,
    block_index: int,
    block_size: int = 16,
    context: bytes = b"HelixLock-L1-Subkey",
) -> bytes:
    """
    Derive a deterministic subkey of length `block_size` for a specific block index.

    Uses HMAC-SHA256 in counter mode over (context + block_index).

    Args:
        master_key (bytes): The master symmetric key.
        block_index (int): Non-negative integer index of the block.
        block_size (int): Required subkey length in bytes (default 16 bytes).
        context (bytes): Optional domain separation context string.

    Returns:
        bytes: Derived subkey of length `block_size`.

    Raises:
        TypeError: If arguments have incorrect types.
        ValueError: If master_key is empty, block_index < 0, or block_size < 1.
    """
    if not isinstance(master_key, (bytes, bytearray)):
        raise TypeError(f"Master key must be bytes or bytearray, got {type(master_key).__name__}")
    if not isinstance(block_index, int) or isinstance(block_index, bool):
        raise TypeError(f"Block index must be an integer, got {type(block_index).__name__}")
    if not isinstance(block_size, int) or isinstance(block_size, bool):
        raise TypeError(f"Block size must be an integer, got {type(block_size).__name__}")
    if not isinstance(context, (bytes, bytearray)):
        raise TypeError(f"Context must be bytes or bytearray, got {type(context).__name__}")

    key_bytes = bytes(master_key)
    if not key_bytes:
        raise ValueError("Master key cannot be empty")
    if block_index < 0:
        raise ValueError(f"Block index must be non-negative (>= 0), got {block_index}")
    if block_size < 1:
        raise ValueError(f"Block size must be a positive integer (>= 1), got {block_size}")

    result = bytearray()
    counter = 1
    # Generate subkey bytes using HMAC-SHA256 blocks until required length is reached
    while len(result) < block_size:
        msg = (
            bytes(context)
            + block_index.to_bytes(8, byteorder="big")
            + counter.to_bytes(4, byteorder="big")
        )
        h = hmac.new(key_bytes, msg, hashlib.sha256).digest()
        result.extend(h)
        counter += 1

    return bytes(result[:block_size])


def derive_mask(master_key: bytes, block_index: int, block_size: int = 16) -> bytes:
    """
    Derive a deterministic bitwise mask for XNOR operation for a given block.

    Args:
        master_key (bytes): Master symmetric key.
        block_index (int): Non-negative block index.
        block_size (int): Required mask length in bytes (default 16 bytes).

    Returns:
        bytes: Derived mask byte string of length `block_size`.
    """
    return derive_subkey(
        master_key=master_key,
        block_index=block_index,
        block_size=block_size,
        context=b"HelixLock-L1-Mask",
    )


def derive_shift_amount(master_key: bytes, block_index: int) -> int:
    """
    Derive a deterministic circular bit-shift amount (0-7 bits) for a given block.

    Args:
        master_key (bytes): Master symmetric key.
        block_index (int): Non-negative block index.

    Returns:
        int: Bit shift amount in range [0, 7].
    """
    seed_bytes = derive_subkey(
        master_key=master_key,
        block_index=block_index,
        block_size=4,
        context=b"HelixLock-L1-Shift",
    )
    val = int.from_bytes(seed_bytes, byteorder="big")
    return val % 8


class KeySchedule:
    """
    Key scheduler managing per-block subkey, mask, and bit-shift derivation.
    """

    def __init__(self, master_key: bytes, block_size: int = 16):
        """
        Initialize KeySchedule with a master key and fixed block size.

        Args:
            master_key (bytes): Master symmetric key.
            block_size (int): Block size in bytes (default 16 bytes).
        """
        if not isinstance(master_key, (bytes, bytearray)):
            raise TypeError(f"Master key must be bytes, got {type(master_key).__name__}")
        if not master_key:
            raise ValueError("Master key cannot be empty")
        if not isinstance(block_size, int) or isinstance(block_size, bool):
            raise TypeError(f"Block size must be an integer, got {type(block_size).__name__}")
        if block_size < 1:
            raise ValueError(f"Block size must be >= 1, got {block_size}")

        self.master_key = bytes(master_key)
        self.block_size = block_size

    def get_subkey(self, block_index: int) -> bytes:
        """Get subkey for specified block index."""
        return derive_subkey(self.master_key, block_index, self.block_size)

    def get_mask(self, block_index: int) -> bytes:
        """Get XNOR mask for specified block index."""
        return derive_mask(self.master_key, block_index, self.block_size)

    def get_shift_amount(self, block_index: int) -> int:
        """Get bit shift amount for specified block index."""
        return derive_shift_amount(self.master_key, block_index)

    def generate_subkeys(self, num_blocks: int) -> list[bytes]:
        """
        Generate a list of subkeys for block indices 0 to num_blocks - 1.

        Args:
            num_blocks (int): Number of blocks.

        Returns:
            list[bytes]: List of subkeys.
        """
        if not isinstance(num_blocks, int) or isinstance(num_blocks, bool):
            raise TypeError(f"num_blocks must be an integer, got {type(num_blocks).__name__}")
        if num_blocks < 0:
            raise ValueError(f"num_blocks must be non-negative (>= 0), got {num_blocks}")

        return [self.get_subkey(i) for i in range(num_blocks)]
