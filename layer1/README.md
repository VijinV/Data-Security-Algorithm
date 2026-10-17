# Layer 1 — Logical-Mathematical Encryption Engine

Layer 1 is the first cryptographic stage of **HelixLock**.  
It encrypts arbitrary binary data using three reversible bitwise operations — XOR, XNOR, and circular bit-shift — each keyed independently per 16-byte block via HMAC-SHA256.

---

## Block Format

| Field | Size | Description |
|---|---|---|
| **Ciphertext blocks** | N × 16 bytes | One 16-byte block per plaintext block |
| **PKCS#7 padding** | 1–16 bytes (embedded) | Always present; last block carries the pad |

**Rules:**
- Block size is fixed at **16 bytes (128 bits)**.
- Plaintext of any length (including empty) is padded with [PKCS#7](https://datatracker.ietf.org/doc/html/rfc5652#section-6.3) before encryption.  
  PKCS#7 always adds at least 1 byte, so a 16-byte plaintext produces a 32-byte ciphertext.
- Ciphertext length is always `ceil((len(plaintext) + 1) / 16) × 16` bytes.
- The padding is stripped automatically by `layer1_decrypt`; the caller never sees it.

```
Plaintext (arbitrary length)
        │
        ▼
┌─────────────────────────────────────────────┐
│  PKCS#7 pad  →  multiple of 16 bytes        │
└─────────────────────────────────────────────┘
        │
        ▼  split into 16-byte blocks
   [Block 0] [Block 1] … [Block N-1]
        │
        ▼  encrypt each block independently
[Cipher 0] [Cipher 1] … [Cipher N-1]   ← ciphertext output
```

---

## Key Format

| Property | Value |
|---|---|
| **Type** | Raw byte string (`bytes` or `bytearray`) |
| **Recommended size** | 32 bytes (256 bits) |
| **Minimum size** | 1 byte (not recommended) |
| **Maximum size** | Unlimited |
| **Generation** | `layer1.generate_key(32)` — CSPRNG via `secrets.token_bytes` |

The master key is never used directly on data.  
Instead, three independent per-block keys are derived from it using HMAC-SHA256 (see Key Schedule below).

```python
from layer1 import generate_key

key = generate_key(32)   # 256-bit CSPRNG key  →  b'\xfa\x3c...' (32 random bytes)
```

---

## Per-Block Key Schedule

Every block index `i` gets three independent values derived deterministically from the master key:

| Derived value | Domain-separation context | Length | Used for |
|---|---|---|---|
| `subkey_i` | `b"HelixLock-L1-Subkey"` | 16 bytes | XOR operation |
| `mask_i` | `b"HelixLock-L1-Mask"` | 16 bytes | XNOR operation |
| `shift_i` | `b"HelixLock-L1-Shift"` | 4 bytes → mod 8 | Bit-shift amount (0–7) |

**Derivation formula** (counter-mode HMAC-SHA256):

```
subkey_i = HMAC-SHA256(key, context || block_index_u64_be || counter_u32_be)[:16]
```

The domain-separation context strings guarantee that `subkey_i ≠ mask_i ≠ shift_seed_i`
even for the same block index and master key.  
Distinct indices produce distinct values, preventing ECB-mode pattern leakage.

---

## Encryption Pipeline

Applied per block in order:

```
Block_i  ──►  XOR(subkey_i)  ──►  XNOR(mask_i)  ──►  BitShift_left(shift_i)  ──►  CipherBlock_i
```

1. **XOR** with 16-byte `subkey_i` — bitwise confusion layer (self-inverse).  
2. **XNOR** with 16-byte `mask_i` — adds asymmetry (bitwise NOT of XOR; self-inverse).  
3. **Circular bit-shift left** by `shift_i` bits across the full 128-bit block — diffuses bit positions (reversible by right-shift of same amount).

---

## Decryption Pipeline

Strict inverse — same key material, reverse order:

```
CipherBlock_i  ──►  BitShift_right(shift_i)  ──►  XNOR(mask_i)  ──►  XOR(subkey_i)  ──►  Block_i
```

1. **Reverse bit-shift right** by `shift_i` bits.  
2. **XNOR** with `mask_i` (self-inverse — identical to the encrypt step).  
3. **XOR** with `subkey_i` (self-inverse — identical to the encrypt step).

---

## Quick-Start

```python
from layer1 import generate_key, layer1_encrypt, layer1_decrypt

# 1. Generate a 256-bit key
key = generate_key(32)

# 2. Encrypt any binary data
plaintext  = b"Top-secret HelixLock payload!"
ciphertext = layer1_encrypt(plaintext, key)
# len(ciphertext) is always a multiple of 16

# 3. Decrypt back to the original
recovered  = layer1_decrypt(ciphertext, key)
assert recovered == plaintext
```

---

## Module Reference

| Module | Public symbols | Purpose |
|---|---|---|
| `layer1.key_gen` | `generate_key`, `generate_csprng_key` | CSPRNG master-key generation |
| `layer1.padding` | `pkcs7_pad`, `pkcs7_unpad`, `pad`, `unpad`, `split_blocks`, `join_blocks` | PKCS#7 padding and block splitting |
| `layer1.key_schedule` | `derive_subkey`, `derive_mask`, `derive_shift_amount`, `KeySchedule` | Per-block key material derivation |
| `layer1.operations` | `xor_block`, `xnor_block`, `bit_shift`, `reverse_bit_shift` | Block-level bitwise transforms |
| `layer1.cipher` | **`layer1_encrypt`**, **`layer1_decrypt`** | End-to-end encrypt / decrypt API |

All symbols are re-exported from the package root (`from layer1 import …`).

---

## Security Properties

| Property | Status |
|---|---|
| Key-dependent output | ✅ All three operations use key-derived material |
| No ECB pattern leakage | ✅ Unique subkey/mask/shift per block index |
| Exact reversibility | ✅ All three operations are self-inverse (XOR, XNOR) or have a defined inverse (bit-shift) |
| PKCS#7 integrity check | ✅ Corrupt ciphertext or wrong key raises `ValueError` on unpad |
| Brute-force infeasibility | ✅ 256-bit key → 2²⁵⁶ keyspace |

> **Note:** Layer 1 is a building block, not a standalone production cipher.  
> It feeds into Layer 2 (genetics-inspired encoding) to form the full HelixLock pipeline.
