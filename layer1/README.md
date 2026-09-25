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
