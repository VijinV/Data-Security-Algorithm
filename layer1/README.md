# Layer 1 — Logical-Mathematical Encryption Engine

This module handles Layer 1 operations for the HelixLock algorithm.

## Features

### CSPRNG Key Generation (`layer1.key_gen`)
- Uses Python's standard `secrets.token_bytes` to generate cryptographically secure random keys.
- Supports customizable key sizes (default: 32 bytes / 256 bits).

```python
from layer1 import generate_key

# Generate a default 256-bit (32-byte) key
key = generate_key()

# Generate a 128-bit (16-byte) key
short_key = generate_key(16)
```

### Block Splitting & PKCS#7 Padding (`layer1.padding`)
- Implements PKCS#7 padding (`pkcs7_pad` / `pad`) and unpadding (`pkcs7_unpad` / `unpad`).
- Splits padded data into fixed-size blocks (`split_blocks`) and joins them back (`join_blocks`).

```python
from layer1 import pkcs7_pad, pkcs7_unpad, split_blocks, join_blocks

# Pad data to 16-byte blocks
data = b"Hello, HelixLock!"
padded = pkcs7_pad(data, block_size=16)

# Split into 16-byte blocks
blocks = split_blocks(padded, block_size=16)

# Join blocks and unpad
reconstructed_padded = join_blocks(blocks)
original = pkcs7_unpad(reconstructed_padded, block_size=16)
assert original == data
```

### Key Scheduling & Per-Block Subkey Derivation (`layer1.key_schedule`)
- Derives deterministic per-block subkeys (`derive_subkey`), masks (`derive_mask`), and shift amounts (`derive_shift_amount`) using HMAC-SHA256.
- Prevents ECB-mode pattern leaks across repeated plaintext blocks.
- Managed directly or through the `KeySchedule` class interface.

```python
from layer1 import KeySchedule, derive_subkey

master_key = generate_key(32)

# Using KeySchedule helper class
scheduler = KeySchedule(master_key, block_size=16)
subkey_0 = scheduler.get_subkey(block_index=0)
mask_0 = scheduler.get_mask(block_index=0)
shift_0 = scheduler.get_shift_amount(block_index=0)

# Direct derivation
subkey_1 = derive_subkey(master_key, block_index=1, block_size=16)
```

### Block XOR Operation (`layer1.operations`)
- Performs bitwise XOR between a data block and its derived subkey.
- Self-inverse (involution) property guarantees exact reversibility: `xor_block(xor_block(block, subkey), subkey) == block`.

```python
from layer1 import xor_block, derive_subkey

# Encrypt block with subkey
cipher_block = xor_block(block, subkey)

# Decrypt block by reapplying XOR with same subkey
recovered_block = xor_block(cipher_block, subkey)
assert recovered_block == block
```

### Block XNOR Operation (`layer1.operations`)
- Performs bitwise XNOR (NOT XOR) between a data block and its derived mask.
- Adds cryptographic non-linearity / asymmetry compared to pure XOR systems.
- Self-inverse (involution) property guarantees exact reversibility when reapplied with the same mask: `xnor_block(xnor_block(block, mask), mask) == block`.

```python
from layer1 import xnor_block, derive_mask

# Apply XNOR with block mask
masked_block = xnor_block(block, mask)

# Revert XNOR by reapplying with identical mask
original_block = xnor_block(masked_block, mask)
assert original_block == block
```

### Block Circular Bit Shift (`layer1.operations`)
- Performs deterministic circular bit rotation on binary blocks without bit loss.
- Supports whole-block circular rotation (`mode="block"`, default) and per-byte rotation (`mode="byte"`).
- Exact reversibility via `direction="right"`, negative amounts, or `reverse_bit_shift`.

```python
from layer1 import bit_shift, reverse_bit_shift, derive_shift_amount

shift_amount = derive_shift_amount(master_key, block_index=0)

# Rotate block left by derived shift amount
shifted_block = bit_shift(block, shift_amount, direction="left")

# Revert circular shift
restored_block = reverse_bit_shift(shifted_block, shift_amount)
# Or equivalently: bit_shift(shifted_block, shift_amount, direction="right")
assert restored_block == block
```
