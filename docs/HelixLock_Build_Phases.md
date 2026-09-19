# HelixLock — Phased Build Plan

A build-ready breakdown of the execution plan, structured so the team can start coding immediately. Each phase has a goal, a concrete task checklist, an owner, and an exit criterion — the thing that must be true before moving to the next phase.

---

## Phase 0 — Project Setup (Day 1–2)

**Goal:** everyone can run and commit code by end of day 2.

- [ ] Create GitHub repo `helixlock` with folders: `layer1/`, `layer2/`, `api/`, `frontend/`, `tests/`, `docs/`
- [ ] Add `README.md` with project name, one-line description, setup instructions
- [ ] Set up Python virtual environment + `requirements.txt` (`pycryptodome`, `pytest`, `numpy`, `matplotlib`, `flask` or `fastapi`)
- [ ] Add `.gitignore` (venv, `__pycache__`, `.env`)
- [ ] Everyone clones the repo and runs a "hello world" script to confirm environment works
- [ ] Agree on branch strategy: `main` (protected) + one feature branch per person (`layer1-dev`, `layer2-dev`, `cloud-dev`, `eval-dev`)

**Owner:** whole team (30 min sync call)
**Exit criterion:** repo exists, all 4 members have pushed at least one commit.

---

## Phase 1 — Layer 1: Logical-Mathematical Engine (Week 1)

**Goal:** a standalone, tested Python module that encrypts/decrypts binary data using XOR, XNOR, and bit-shift — no genetics layer yet.

- [ ] Implement CSPRNG key generation (`secrets.token_bytes`)
- [ ] Implement block splitting with PKCS#7-style padding (fixed block size, e.g. 16 bytes)
- [ ] Implement key scheduling / subkey derivation per block
- [ ] Implement `xor_block(block, subkey)`
- [ ] Implement `xnor_block(block, mask)`
- [ ] Implement `bit_shift(block, amount)` (amount derived from subkey)
- [ ] Chain into `layer1_encrypt(plaintext_bytes, key) -> ciphertext_bytes`
- [ ] Implement exact reverse: `layer1_decrypt(ciphertext_bytes, key) -> plaintext_bytes`
- [ ] Write `pytest` unit tests: round-trip test (`decrypt(encrypt(x)) == x`) on at least 20 varied inputs (empty string, 1 byte, exactly 1 block, multi-block, random binary data)
- [ ] Commit with a short `layer1/README.md` explaining the block/key format

**Owner:** Adheena S.
**Exit criterion:** `pytest tests/test_layer1.py` passes 100% on all round-trip test vectors.

---

## Phase 2 — Layer 2: Genetics-Inspired Engine (Week 2)

**Goal:** a standalone, tested module that takes binary input and reversibly encodes it through DNA → mRNA → protein, with every table keyed (not fixed/public).

- [ ] Design the keyed 2-bit → nucleotide base table generator (permute `{A,C,G,T}` assignment using the key)
- [ ] Implement `binary_to_dna(bytes, key) -> dna_string`
- [ ] Implement `dna_to_binary(dna_string, key) -> bytes` (exact inverse)
- [ ] Design the keyed DNA → mRNA transcription substitution table
- [ ] Implement `dna_to_mrna(dna_string, key)` / `mrna_to_dna(mrna_string, key)`
- [ ] Design the 64-entry keyed codon → symbol table (this is the core "novel" contribution — document the generation method clearly)
- [ ] Implement `mrna_to_protein(mrna_string, key)` / `protein_to_mrna(protein_string, key)`
- [ ] Chain into `layer2_encrypt(binary_data, key)` / `layer2_decrypt(encoded_data, key)`
- [ ] Write `pytest` unit tests: round-trip test on the same 20 test vectors as Layer 1, plus a table-uniqueness test (confirm no two 2-bit patterns map to the same base, no two codons map to the same symbol)
- [ ] Commit with a short `layer2/README.md` explaining each table and how it's keyed

**Owner:** Amrit Krishnan U.
**Exit criterion:** `pytest tests/test_layer2.py` passes 100%; codon table confirmed to be a valid bijection (reversible with no collisions).

---

## Phase 3 — Integration & Correctness Testing (Week 3)

**Goal:** Layer 1 and Layer 2 chained into one working `encrypt()` / `decrypt()` API, proven correct end-to-end.

- [ ] Merge `layer1-dev` and `layer2-dev` branches into `main`
- [ ] Implement `helixlock.encrypt(plaintext: bytes, key: bytes) -> bytes` (Layer 1 → Layer 2)
- [ ] Implement `helixlock.decrypt(ciphertext: bytes, key: bytes) -> bytes` (reverse Layer 2 → reverse Layer 1)
- [ ] Add a `--layers` flag/parameter to run Layer 1 only, Layer 2 only, or both (useful for the admin console demo and for the evaluation phase)
- [ ] Write integration tests: round-trip on text files, small binary files (images), and edge cases (empty file, 1-byte file, exactly-one-block file)
- [ ] Test with wrong key (should fail to recover original data — confirms key-dependence actually matters)
- [ ] Build a simple CLI wrapper: `python helixlock.py encrypt input.txt output.enc --key mykey.bin`
- [ ] Tag this commit as `v0.1-core` in Git

**Owner:** Adheena S. + Amrit Krishnan U. (pair integration session)
**Exit criterion:** 100% round-trip pass rate across ≥50 test files of varying type/size; wrong-key test confirms garbage output (not the original).

---

## Phase 4 — Security & Performance Evaluation (Week 4)

**Goal:** quantitative results that back every claim in the report — this is what the viva panel will actually ask about.

- [ ] Implement entropy calculation on ciphertext (target ≈ 8 bits/byte)
- [ ] Implement avalanche effect test: flip 1 bit of plaintext (and separately 1 bit of key), measure % of ciphertext bits that change (target ≈ 50%)
- [ ] Implement NPCR/UACI calculation (treat bytes as "pixels" per standard DNA-crypto literature)
- [ ] Compute keyspace size estimate (key bits × permutation space of keyed tables) and write the brute-force infeasibility argument
- [ ] Benchmark encryption/decryption time at 1 KB, 100 KB, 1 MB, 10 MB — plot with `matplotlib`
- [ ] Run the same benchmark with `pycryptodome` AES-128 as baseline, plot both on the same chart
- [ ] Save all results as `docs/results/` (CSV + PNG charts) for direct use in the report

**Owner:** Sandra Sugathan
**Exit criterion:** a results folder with entropy, avalanche, NPCR/UACI numbers and two comparison charts (time vs. size; HelixLock vs. AES), all reproducible by re-running one script.

---

## Phase 5 — Cloud Integration Demo (Week 5)

**Goal:** a working upload → encrypt → store → retrieve → decrypt → download flow, matching the client-facing landing page and admin console designs already built.

- [ ] Set up Firebase Storage or AWS S3 (free tier) bucket
- [ ] Build Flask/FastAPI backend with endpoints: `POST /encrypt-upload`, `GET /download-decrypt/:id`
- [ ] Wire the backend to `helixlock.encrypt`/`decrypt` from Phase 3
- [ ] Build minimal frontend (or wire into the existing admin console mockup) for file upload and download
- [ ] Add basic key management: generate/select a key per upload, store key reference (not the raw key) alongside the file metadata
- [ ] End-to-end test: upload a file, confirm it's stored encrypted in the bucket, download and confirm it decrypts back to the original
- [ ] Record a screen-capture video of the full flow as a fallback for viva day

**Owner:** Rithin Raj Krishna
**Exit criterion:** a live (or locally hosted) demo where a real file survives a full upload/encrypt/store/retrieve/decrypt/download round trip, plus a backup recording.

---

## Phase 6 — Documentation & Submission (Week 6)

**Goal:** final report, PPT, and repo are submission-ready.

- [ ] Write report chapters using the mapping from the original execution plan (Introduction → Literature Survey → Problem Statement → Objectives → Proposed System → Methodology → Results & Analysis → Applications → Future Scope → Conclusion → References → Appendix)
- [ ] Insert Phase 4 charts/tables into Results & Analysis
- [ ] Insert architecture diagrams (already built) into Proposed System
- [ ] Prepare viva PPT: problem → architecture → live/recorded demo → results → future scope
- [ ] Run plagiarism check on the final report
- [ ] Clean up GitHub repo: final `README.md`, code comments, `LICENSE`
- [ ] Final team review call — each member should be able to explain every phase, not just their own module

**Owner:** Sandra Sugathan (lead), all members contribute their sections
**Exit criterion:** report, PPT, and repo all finalized and submitted before the department deadline.

---

## Quick-Reference Timeline

| Phase | Duration | Owner | Exit Criterion |
|---|---|---|---|
| 0. Setup | Day 1–2 | Whole team | Repo live, everyone committed |
| 1. Layer 1 | Week 1 | Adheena | Round-trip tests pass |
| 2. Layer 2 | Week 2 | Amrit | Round-trip + bijection tests pass |
| 3. Integration | Week 3 | Adheena + Amrit | 50+ files round-trip correctly |
| 4. Evaluation | Week 4 | Sandra | Entropy/avalanche/NPCR results + charts |
| 5. Cloud demo | Week 5 | Rithin | Full upload→encrypt→store→decrypt→download works |
| 6. Documentation | Week 6 | Sandra (lead) | Report + PPT + repo submitted |

**Note on timeline:** this compresses the original 14–16 week plan into a 6-week active build sprint, assuming Phase 0's research/design decisions (block size, key size, table formats) are settled going in. If those are still open, add a Phase "-1" (2–3 days) to lock them down before Phase 1 starts.
