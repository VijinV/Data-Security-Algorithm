"""
Unit tests for Layer 1 CSPRNG Key Generation, PKCS#7 Padding, Block Splitting, and Key Scheduling.
"""

import pytest
from layer1 import (
    generate_key,
    generate_csprng_key,
    pkcs7_pad,
    pkcs7_unpad,
    pad,
    unpad,
    split_blocks,
    join_blocks,
    derive_subkey,
    derive_mask,
    derive_shift_amount,
    KeySchedule,
    xor_block,
    xnor_block,
    bit_shift,
    reverse_bit_shift,
)
from layer1.key_gen import generate_key as direct_generate_key
from layer1.operations import (
    xor_block as direct_xor_block,
    xnor_block as direct_xnor_block,
    bit_shift as direct_bit_shift,
    reverse_bit_shift as direct_reverse_bit_shift,
)


# =====================================================================
# Key Generation Tests
# =====================================================================

def test_default_key_length():
    """Test that default key generation returns 32 bytes (256 bits)."""
    key = generate_key()
    assert isinstance(key, bytes)
    assert len(key) == 32


def test_custom_key_lengths():
    """Test key generation with custom sizes (e.g. 16 bytes / 128 bits, 64 bytes / 512 bits)."""
    for size in (8, 16, 24, 32, 64, 128):
        key = generate_key(size)
        assert isinstance(key, bytes)
        assert len(key) == size


def test_key_uniqueness():
    """Test that multiple calls generate distinct cryptographically random keys."""
    keys = {generate_key(32) for _ in range(100)}
    assert len(keys) == 100


def test_alias_equivalence():
    """Test that generate_csprng_key function alias behaves identically."""
    key = generate_csprng_key(16)
    assert isinstance(key, bytes)
    assert len(key) == 16
    assert generate_csprng_key is direct_generate_key


def test_invalid_length_types():
    """Test that non-integer length arguments raise TypeError."""
    invalid_inputs = ["32", 32.0, None, [32], True, False]
    for invalid_val in invalid_inputs:
        with pytest.raises(TypeError):
            generate_key(invalid_val)


def test_invalid_length_values():
    """Test that zero or negative length arguments raise ValueError."""
    for invalid_len in (0, -1, -32):
        with pytest.raises(ValueError):
            generate_key(invalid_len)


# =====================================================================
# PKCS#7 Padding Tests
# =====================================================================

def test_pkcs7_padding_roundtrip():
    """Test padding and unpadding on various inputs with standard block size 16."""
    test_cases = [
        b"",
        b"a",
        b"123456789012345",         # 15 bytes
        b"1234567890123456",        # 16 bytes (exact block size -> full pad block added)
        b"12345678901234567",       # 17 bytes
        b"A" * 100,
        bytes(range(256)),
    ]
    for data in test_cases:
        padded = pkcs7_pad(data, block_size=16)
        assert len(padded) % 16 == 0
        assert len(padded) > len(data)
        unpadded = pkcs7_unpad(padded, block_size=16)
        assert unpadded == data


def test_pkcs7_padding_exact_byte_values():
    """Test exact padding byte values per PKCS#7 standard."""
    # 13 bytes data with 16 byte block -> 3 bytes of 0x03 added
    data_13 = b"Hello, World!"
    padded = pkcs7_pad(data_13, 16)
    assert len(padded) == 16
    assert padded[-3:] == b"\x03\x03\x03"

    # Exact multiple (16 bytes) -> 16 bytes of 0x10 added
    data_16 = b"1234567890123456"
    padded = pkcs7_pad(data_16, 16)
    assert len(padded) == 32
    assert padded[-16:] == b"\x10" * 16


def test_pkcs7_custom_block_sizes():
    """Test PKCS#7 padding with non-default block sizes (e.g. 8, 32)."""
    for block_size in (8, 24, 32, 64):
        data = b"Testing non-standard block sizes!"
        padded = pkcs7_pad(data, block_size=block_size)
        assert len(padded) % block_size == 0
        assert pkcs7_unpad(padded, block_size=block_size) == data


def test_pkcs7_aliases():
    """Test pad/unpad function aliases."""
    data = b"Alias test"
    assert pad(data) == pkcs7_pad(data)
    assert unpad(pad(data)) == data


def test_pkcs7_invalid_unpad_corrupted_padding():
    """Test that corrupted or invalid PKCS#7 padding raises ValueError."""
    corrupted_cases = [
        b"123456789012345\x02",       # claims 2 bytes padding, but 2nd-to-last byte is '5'
        b"1234567890123\x03\x02\x03", # claims 3 bytes padding (0x03), but bytes are \x03\x02\x03
        b"123456789012345\x00",       # 0x00 is invalid padding length byte
        b"123456789012345\x11",       # 17 is > block_size 16
        b"",                          # empty input
        b"12345",                     # length not multiple of block size 16
    ]
    for case in corrupted_cases:
        with pytest.raises(ValueError):
            pkcs7_unpad(case, block_size=16)


def test_pkcs7_invalid_block_sizes():
    """Test that invalid block size values raise ValueError or TypeError."""
    for invalid_size in (0, -1, 256):
        with pytest.raises(ValueError):
            pkcs7_pad(b"test", block_size=invalid_size)
        with pytest.raises(ValueError):
            pkcs7_unpad(b"1234567890123456", block_size=invalid_size)

    for invalid_type in ("16", 16.0, None, True):
        with pytest.raises(TypeError):
            pkcs7_pad(b"test", block_size=invalid_type)


# =====================================================================
# Block Splitting & Joining Tests
# =====================================================================

def test_split_and_join_blocks():
    """Test splitting padded data into blocks and joining back."""
    data = b"HelixLock Layer 1 block splitting test data!"
    padded = pkcs7_pad(data, block_size=16)
    blocks = split_blocks(padded, block_size=16)

    assert isinstance(blocks, list)
    assert len(blocks) == len(padded) // 16
    for block in blocks:
        assert isinstance(block, bytes)
        assert len(block) == 16

    joined = join_blocks(blocks)
    assert joined == padded
    assert pkcs7_unpad(joined, block_size=16) == data


def test_split_blocks_unaligned_data():
    """Test that split_blocks raises ValueError when data length is not a multiple of block_size."""
    with pytest.raises(ValueError):
        split_blocks(b"unaligned", block_size=16)


def test_join_blocks_invalid_types():
    """Test that join_blocks raises TypeError on non-bytes list items or non-iterable input."""
    with pytest.raises(TypeError):
        join_blocks("not a list")
    with pytest.raises(TypeError):
        join_blocks([b"valid", "not bytes"])


# =====================================================================
# Key Scheduling & Subkey Derivation Tests
# =====================================================================

def test_subkey_derivation_determinism():
    """Test that subkey derivation is deterministic for identical parameters."""
    master_key = generate_key(32)
    k0_a = derive_subkey(master_key, block_index=0, block_size=16)
    k0_b = derive_subkey(master_key, block_index=0, block_size=16)
    assert k0_a == k0_b
    assert len(k0_a) == 16


def test_subkey_uniqueness_across_blocks():
    """Test that subkeys generated for different block indices are distinct."""
    master_key = generate_key(32)
    subkeys = [derive_subkey(master_key, i, block_size=16) for i in range(50)]
    assert len(set(subkeys)) == 50


def test_subkey_sensitivity_to_master_key():
    """Test that changing even 1 bit of the master key alters derived subkeys."""
    key1 = b"\x00" * 32
    key2 = b"\x00" * 31 + b"\x01"
    sub1 = derive_subkey(key1, block_index=0, block_size=16)
    sub2 = derive_subkey(key2, block_index=0, block_size=16)
    assert sub1 != sub2


def test_subkey_large_block_sizes():
    """Test subkey derivation for large block sizes exceeding single SHA-256 block (> 32 bytes)."""
    master_key = generate_key(32)
    for size in (32, 48, 64, 100):
        sub = derive_subkey(master_key, block_index=0, block_size=size)
        assert isinstance(sub, bytes)
        assert len(sub) == size


def test_derive_mask_and_shift_amount():
    """Test mask derivation and circular bit-shift amount derivation."""
    master_key = generate_key(32)
    mask = derive_mask(master_key, block_index=0, block_size=16)
    shift = derive_shift_amount(master_key, block_index=0)

    assert isinstance(mask, bytes)
    assert len(mask) == 16
    assert isinstance(shift, int)
    assert 0 <= shift <= 7

    # Ensure mask and subkey differ due to domain separation context
    subkey = derive_subkey(master_key, block_index=0, block_size=16)
    assert mask != subkey


def test_key_schedule_class():
    """Test KeySchedule helper class methods."""
    master_key = generate_key(32)
    ks = KeySchedule(master_key, block_size=16)

    sub0 = ks.get_subkey(0)
    mask0 = ks.get_mask(0)
    shift0 = ks.get_shift_amount(0)

    assert sub0 == derive_subkey(master_key, 0, 16)
    assert mask0 == derive_mask(master_key, 0, 16)
    assert shift0 == derive_shift_amount(master_key, 0)

    subkeys_list = ks.generate_subkeys(10)
    assert len(subkeys_list) == 10
    assert subkeys_list[0] == sub0


def test_key_schedule_invalid_inputs():
    """Test error handling in key scheduling functions."""
    master_key = generate_key(32)
    with pytest.raises(ValueError):
        derive_subkey(b"", block_index=0)
    with pytest.raises(ValueError):
        derive_subkey(master_key, block_index=-1)
    with pytest.raises(ValueError):
        derive_subkey(master_key, block_index=0, block_size=0)
    with pytest.raises(TypeError):
        derive_subkey("not_bytes", block_index=0)


# =====================================================================
# XOR Block Operation Tests
# =====================================================================

def test_xor_block_known_vectors():
    """Test xor_block against deterministic known test vectors."""
    assert xor_block(b"\x00" * 16, b"\xff" * 16) == b"\xff" * 16
    assert xor_block(b"\xaa" * 16, b"\x55" * 16) == b"\xff" * 16
    assert xor_block(b"\xf0\x0f", b"\x0f\xf0") == b"\xff\xff"
    assert xor_block(b"\x12\x34\x56\x78", b"\x9a\xbc\xde\xf0") == bytes(
        [0x12 ^ 0x9A, 0x34 ^ 0xBC, 0x56 ^ 0xDE, 0x78 ^ 0xF0]
    )


def test_xor_block_self_inverse():
    """Test the involution property of XOR: xor(xor(b, k), k) == b."""
    for _ in range(50):
        block = generate_key(16)
        subkey = generate_key(16)
        encrypted = xor_block(block, subkey)
        decrypted = xor_block(encrypted, subkey)
        assert decrypted == block


def test_xor_block_identity_and_zeroing():
    """Test XOR mathematical identity and zeroing properties."""
    block = generate_key(16)
    zeros = bytes(16)

    # b ^ 0 == b
    assert xor_block(block, zeros) == block
    # b ^ b == 0
    assert xor_block(block, block) == zeros


def test_xor_block_empty():
    """Test XOR on empty bytes."""
    assert xor_block(b"", b"") == b""


def test_xor_block_bytearray_support():
    """Test that bytearray input is accepted and returns bytes."""
    block = bytearray(b"\x01\x02\x03\x04")
    subkey = b"\x10\x20\x30\x40"
    result = xor_block(block, subkey)
    assert isinstance(result, bytes)
    assert result == b"\x11\x22\x33\x44"


def test_xor_block_length_mismatch():
    """Test that unequal block and subkey lengths raise ValueError."""
    with pytest.raises(ValueError) as excinfo:
        xor_block(b"1234", b"12345")
    assert "lengths" in str(excinfo.value).lower() or "match" in str(excinfo.value).lower()


def test_xor_block_invalid_types():
    """Test that non-bytes arguments raise TypeError."""
    invalid_inputs = [123, "string", None, [1, 2, 3], True, False]
    valid_bytes = b"1234"
    for invalid in invalid_inputs:
        with pytest.raises(TypeError):
            xor_block(invalid, valid_bytes)
        with pytest.raises(TypeError):
            xor_block(valid_bytes, invalid)


def test_xor_block_direct_import_alias():
    """Test that xor_block from layer1.operations is identical to layer1.xor_block."""
    assert xor_block is direct_xor_block


def test_xor_block_with_derived_subkey():
    """Test round-trip XOR encryption and decryption using KeySchedule derived subkeys."""
    master_key = generate_key(32)
    ks = KeySchedule(master_key, block_size=16)

    block = b"ConfidentialData"
    subkey = ks.get_subkey(0)

    cipher_block = xor_block(block, subkey)
    assert cipher_block != block
    plain_block = xor_block(cipher_block, subkey)
    assert plain_block == block


# =====================================================================
# XNOR Block Operation Tests
# =====================================================================

def test_xnor_block_known_vectors():
    """Test xnor_block against deterministic known test vectors."""
    assert xnor_block(b"\x00" * 16, b"\x00" * 16) == b"\xff" * 16
    assert xnor_block(b"\xff" * 16, b"\xff" * 16) == b"\xff" * 16
    assert xnor_block(b"\xaa" * 16, b"\x55" * 16) == b"\x00" * 16
    assert xnor_block(b"\x12\x34", b"\x56\x78") == bytes(
        [(0x12 ^ 0x56) ^ 0xFF, (0x34 ^ 0x78) ^ 0xFF]
    )


def test_xnor_block_self_inverse():
    """Test the involution property of XNOR: xnor(xnor(b, m), m) == b."""
    for _ in range(50):
        block = generate_key(16)
        mask = generate_key(16)
        encrypted = xnor_block(block, mask)
        decrypted = xnor_block(encrypted, mask)
        assert decrypted == block


def test_xnor_block_relationship_with_xor():
    """Test that xnor_block is bitwise NOT of xor_block: ~(b ^ m) & 0xFF."""
    for _ in range(20):
        block = generate_key(16)
        mask = generate_key(16)
        xnor_res = xnor_block(block, mask)
        xor_res = xor_block(block, mask)
        expected_not_xor = bytes(b ^ 0xFF for b in xor_res)
        assert xnor_res == expected_not_xor


def test_xnor_block_identity_and_inversion():
    """Test XNOR identity (mask of 1s preserves block) and inversion (mask of 0s inverts block)."""
    block = generate_key(16)
    all_ones = b"\xff" * 16
    all_zeros = b"\x00" * 16

    # b XNOR 1 == b
    assert xnor_block(block, all_ones) == block
    # b XNOR 0 == ~b
    assert xnor_block(block, all_zeros) == bytes(b ^ 0xFF for b in block)
    # b XNOR b == 1
    assert xnor_block(block, block) == all_ones


def test_xnor_block_empty():
    """Test XNOR on empty bytes."""
    assert xnor_block(b"", b"") == b""


def test_xnor_block_bytearray_support():
    """Test that bytearray input is accepted for xnor_block and returns bytes."""
    block = bytearray(b"\xaa\x55")
    mask = b"\xaa\x55"
    result = xnor_block(block, mask)
    assert isinstance(result, bytes)
    assert result == b"\xff\xff"


def test_xnor_block_length_mismatch():
    """Test that unequal block and mask lengths raise ValueError."""
    with pytest.raises(ValueError) as excinfo:
        xnor_block(b"1234", b"12345")
    assert "lengths" in str(excinfo.value).lower() or "match" in str(excinfo.value).lower()


def test_xnor_block_invalid_types():
    """Test that non-bytes arguments to xnor_block raise TypeError."""
    invalid_inputs = [123, "string", None, [1, 2, 3], True, False]
    valid_bytes = b"1234"
    for invalid in invalid_inputs:
        with pytest.raises(TypeError):
            xnor_block(invalid, valid_bytes)
        with pytest.raises(TypeError):
            xnor_block(valid_bytes, invalid)


def test_xnor_block_direct_import_alias():
    """Test that xnor_block from layer1.operations is identical to layer1.xnor_block."""
    assert xnor_block is direct_xnor_block


def test_xnor_block_with_derived_mask():
    """Test round-trip XNOR transformation using KeySchedule derived mask."""
    master_key = generate_key(32)
    ks = KeySchedule(master_key, block_size=16)

    block = b"ConfidentialData"
    mask = ks.get_mask(0)

    transformed = xnor_block(block, mask)
    assert transformed != block
    restored = xnor_block(transformed, mask)
    assert restored == block


def test_xor_and_xnor_roundtrip_chaining():
    """Test chained forward (XOR then XNOR) and reverse (XNOR then XOR) operations."""
    master_key = generate_key(32)
    ks = KeySchedule(master_key, block_size=16)

    original_block = b"TopSecretBlock16"
    subkey = ks.get_subkey(0)
    mask = ks.get_mask(0)

    # Forward: XOR then XNOR
    step1 = xor_block(original_block, subkey)
    step2 = xnor_block(step1, mask)

    # Reverse in opposite order: reverse XNOR then reverse XOR
    rev_step1 = xnor_block(step2, mask)
    assert rev_step1 == step1
    rev_step2 = xor_block(rev_step1, subkey)
    assert rev_step2 == original_block


# =====================================================================
# Bit Shift Block Operation Tests
# =====================================================================

def test_bit_shift_single_byte_known_vectors():
    """Test circular bit shift on single byte with wrap around."""
    assert bit_shift(b"\x01", 1) == b"\x02"
    assert bit_shift(b"\x80", 1) == b"\x01"  # MSB wraps to LSB
    assert bit_shift(b"\x01", 1, direction="right") == b"\x80"
    assert bit_shift(b"\xaa", 4) == b"\xaa"  # 10101010 rotated by 4 is 10101010


def test_bit_shift_multi_byte_block_mode():
    """Test whole-block circular bit shift across byte boundaries."""
    # 2-byte block (16 bits): 0x8000 rotated left by 1 wraps MSB to bit 0 -> 0x0001
    assert bit_shift(b"\x80\x00", 1) == b"\x00\x01"
    assert bit_shift(b"\x00\x01", 1, direction="right") == b"\x80\x00"

    # Rotate by 8 bits shifts entire byte
    assert bit_shift(b"\x12\x34", 8) == b"\x34\x12"


def test_bit_shift_byte_mode():
    """Test per-byte circular bit shift mode."""
    # Each byte shifted independently
    assert bit_shift(b"\x80\x01", 1, mode="byte") == b"\x01\x02"
    assert bit_shift(b"\x01\x02", 1, direction="right", mode="byte") == b"\x80\x01"


def test_bit_shift_roundtrip_all_amounts():
    """Test that shifting and reverse shifting restores original block for any shift amount."""
    for amt in range(0, 130):
        block = generate_key(16)
        shifted = bit_shift(block, amt)
        restored_right = bit_shift(shifted, amt, direction="right")
        restored_neg = bit_shift(shifted, -amt)
        restored_rev = reverse_bit_shift(shifted, amt)

        assert restored_right == block
        assert restored_neg == block
        assert restored_rev == block


def test_bit_shift_byte_mode_roundtrip():
    """Test round-trip reversibility in per-byte shift mode."""
    for amt in range(0, 17):
        block = generate_key(16)
        shifted = bit_shift(block, amt, mode="byte")
        restored = reverse_bit_shift(shifted, amt, mode="byte")
        assert restored == block


def test_bit_shift_identity():
    """Test that shifting by 0 or multiples of total bits returns identical block."""
    block = generate_key(16)
    assert bit_shift(block, 0) == block
    assert bit_shift(block, 128) == block
    assert bit_shift(block, 256) == block
    assert bit_shift(block, 0, mode="byte") == block
    assert bit_shift(block, 8, mode="byte") == block


def test_bit_shift_empty():
    """Test bit shift on empty bytes."""
    assert bit_shift(b"", 5) == b""
    assert reverse_bit_shift(b"", 5) == b""


def test_bit_shift_bytearray():
    """Test that bytearray input is accepted and returns bytes."""
    block = bytearray(b"\x80\x00")
    result = bit_shift(block, 1)
    assert isinstance(result, bytes)
    assert result == b"\x00\x01"


def test_bit_shift_invalid_inputs():
    """Test error handling on invalid argument types and values."""
    with pytest.raises(TypeError):
        bit_shift("not_bytes", 1)
    with pytest.raises(TypeError):
        bit_shift(b"\x00", "not_int")
    with pytest.raises(TypeError):
        bit_shift(b"\x00", True)
    with pytest.raises(TypeError):
        bit_shift(b"\x00", 1, direction=123)
    with pytest.raises(ValueError):
        bit_shift(b"\x00", 1, direction="up")
    with pytest.raises(ValueError):
        bit_shift(b"\x00", 1, mode="invalid_mode")


def test_bit_shift_direct_import_alias():
    """Test that bit_shift and reverse_bit_shift from layer1.operations match package root."""
    assert bit_shift is direct_bit_shift
    assert reverse_bit_shift is direct_reverse_bit_shift


def test_full_layer1_roundtrip_chaining():
    """
    Test complete Layer 1 transformation pipeline per block:
    Forward: Block -> XOR(subkey) -> XNOR(mask) -> BitShift(amount)
    Reverse: CipherBlock -> ReverseBitShift(amount) -> XNOR(mask) -> XOR(subkey) == Block
    """
    master_key = generate_key(32)
    ks = KeySchedule(master_key, block_size=16)

    for block_idx in range(25):
        original_block = generate_key(16)
        subkey = ks.get_subkey(block_idx)
        mask = ks.get_mask(block_idx)
        shift_amt = ks.get_shift_amount(block_idx)

        # Forward pipeline
        s1 = xor_block(original_block, subkey)
        s2 = xnor_block(s1, mask)
        ciphertext_block = bit_shift(s2, shift_amt)

        # Reverse pipeline in exact inverse order
        r1 = reverse_bit_shift(ciphertext_block, shift_amt)
        assert r1 == s2
        r2 = xnor_block(r1, mask)
        assert r2 == s1
        decrypted_block = xor_block(r2, subkey)

        assert decrypted_block == original_block



