"""
Layer 1: Block-level logical and bitwise cryptographic operations.

Provides core block transformation operations for HelixLock Layer 1:
- xor_block: Bitwise XOR between a data block and a subkey.
- xnor_block: Bitwise XNOR between a data block and a mask.
- bit_shift: Circular bit rotation across a block or per-byte.
- reverse_bit_shift: Inverse circular bit rotation.
"""


def xor_block(block: bytes, subkey: bytes) -> bytes:
    """
    Perform bitwise XOR between a data block and a subkey of equal length.

    XOR is an involution (self-inverse operation):
        xor_block(xor_block(block, subkey), subkey) == block

    Args:
        block (bytes | bytearray): Input data block.
        subkey (bytes | bytearray): Subkey derived for this block.

    Returns:
        bytes: Resulting block after bitwise XOR.

    Raises:
        TypeError: If block or subkey is not bytes or bytearray.
        ValueError: If block and subkey lengths do not match.
    """
    if not isinstance(block, (bytes, bytearray)):
        raise TypeError(f"Block must be bytes or bytearray, got {type(block).__name__}")
    if not isinstance(subkey, (bytes, bytearray)):
        raise TypeError(f"Subkey must be bytes or bytearray, got {type(subkey).__name__}")

    block_bytes = bytes(block)
    subkey_bytes = bytes(subkey)

    if len(block_bytes) != len(subkey_bytes):
        raise ValueError(
            f"Block length ({len(block_bytes)}) and subkey length ({len(subkey_bytes)}) must match"
        )

    return bytes(b ^ k for b, k in zip(block_bytes, subkey_bytes))


def xnor_block(block: bytes, mask: bytes) -> bytes:
    """
    Perform bitwise XNOR (NOT XOR) between a data block and a mask of equal length.

    XNOR is an involution (self-inverse operation) when applied with the same mask:
        xnor_block(xnor_block(block, mask), mask) == block

    Args:
        block (bytes | bytearray): Input data block.
        mask (bytes | bytearray): Mask derived for this block.

    Returns:
        bytes: Resulting block after bitwise XNOR.

    Raises:
        TypeError: If block or mask is not bytes or bytearray.
        ValueError: If block and mask lengths do not match.
    """
    if not isinstance(block, (bytes, bytearray)):
        raise TypeError(f"Block must be bytes or bytearray, got {type(block).__name__}")
    if not isinstance(mask, (bytes, bytearray)):
        raise TypeError(f"Mask must be bytes or bytearray, got {type(mask).__name__}")

    block_bytes = bytes(block)
    mask_bytes = bytes(mask)

    if len(block_bytes) != len(mask_bytes):
        raise ValueError(
            f"Block length ({len(block_bytes)}) and mask length ({len(mask_bytes)}) must match"
        )

    return bytes((b ^ m) ^ 0xFF for b, m in zip(block_bytes, mask_bytes))


def bit_shift(
    block: bytes,
    amount: int,
    direction: str = "left",
    mode: str = "block",
) -> bytes:
    """
    Perform deterministic circular bit-shift (rotation) on a binary block.

    Circular shift rotates bits with wrap-around, ensuring no data loss and exact reversibility.

    Args:
        block (bytes | bytearray): Binary data block to shift.
        amount (int): Shift amount in bits. Positive shifts rotate in `direction`;
                      negative amounts reverse the rotation direction.
        direction (str): Shift direction: 'left' (default) or 'right'.
        mode (str): Shift mode:
            - 'block' (default): Circular rotation across the entire block as a bitstream
              (e.g., 128-bit circular rotation for 16-byte blocks).
            - 'byte': Circular rotation independently on each byte of the block.

    Returns:
        bytes: Resulting binary block of identical length after circular rotation.

    Raises:
        TypeError: If block is not bytes/bytearray, amount is not an int,
                   or direction/mode are not strings.
        ValueError: If direction is not 'left'/'right' or mode is not 'block'/'byte'.
    """
    if not isinstance(block, (bytes, bytearray)):
        raise TypeError(f"Block must be bytes or bytearray, got {type(block).__name__}")
    if not isinstance(amount, int) or isinstance(amount, bool):
        raise TypeError(f"Shift amount must be an integer, got {type(amount).__name__}")
    if not isinstance(direction, str):
        raise TypeError(f"Direction must be a string, got {type(direction).__name__}")
    if not isinstance(mode, str):
        raise TypeError(f"Mode must be a string, got {type(mode).__name__}")

    dir_clean = direction.strip().lower()
    if dir_clean in ("left", "l"):
        dir_mult = 1
    elif dir_clean in ("right", "r"):
        dir_mult = -1
    else:
        raise ValueError(f"Invalid direction '{direction}'. Must be 'left' or 'right'")

    mode_clean = mode.strip().lower()
    if mode_clean not in ("block", "b", "byte", "by_byte", "per_byte"):
        raise ValueError(f"Invalid mode '{mode}'. Must be 'block' or 'byte'")

    block_bytes = bytes(block)
    if not block_bytes:
        return b""

    total_block_bytes = len(block_bytes)

    if mode_clean in ("block", "b"):
        total_bits = total_block_bytes * 8
        effective_shift = (amount * dir_mult) % total_bits
        if effective_shift == 0:
            return block_bytes

        num = int.from_bytes(block_bytes, byteorder="big")
        mask = (1 << total_bits) - 1
        rotated = ((num << effective_shift) | (num >> (total_bits - effective_shift))) & mask
        return rotated.to_bytes(total_block_bytes, byteorder="big")
    else:
        effective_shift = (amount * dir_mult) % 8
        if effective_shift == 0:
            return block_bytes

        return bytes(
            ((b << effective_shift) | (b >> (8 - effective_shift))) & 0xFF
            for b in block_bytes
        )


def reverse_bit_shift(
    block: bytes,
    amount: int,
    mode: str = "block",
) -> bytes:
    """
    Perform the inverse circular bit-shift on a block (reverses direction).

    Args:
        block (bytes | bytearray): Binary data block.
        amount (int): Shift amount in bits.
        mode (str): Shift mode ('block' or 'byte').

    Returns:
        bytes: Reversed circularly shifted binary block.
    """
    return bit_shift(block, amount, direction="right", mode=mode)


