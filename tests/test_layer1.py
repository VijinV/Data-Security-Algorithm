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
)
from layer1.key_gen import generate_key as direct_generate_key


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
