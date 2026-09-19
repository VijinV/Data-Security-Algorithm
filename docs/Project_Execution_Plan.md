# A New Data Security Algorithm for Cloud Computing Based on Genetics Techniques and Logical-Math

**Project Execution Plan & Expanded Technical Document**

Department of Computer Science and Engineering
KVM College of Engineering and IT, APJ Abdul Kalam Technological University (KTU), Kerala
Academic Year 2026–2027

Team: Adheena S. (KVE23CS002), Amrit Krishnan U. (KVE23CS007), Rithin Raj Krishna (KVE23CS014), Sandra Sugathan (KVE23CS015)
Guide: Miss Aneeta Abraham, HOD, CSE

---

## 1. Project Overview

This document expands the original abstract into a working execution plan: what to build, in what order, with which tools, and how to validate it. The core idea stays the same — a two-layer hybrid cipher combining classical logical-mathematical operations (XOR, XNOR, bit rotation) with a DNA/mRNA/protein-inspired symbolic transformation layer — but this plan turns it into a buildable, demonstrable, and defensible final-year project.

**Important framing note for the report and viva:** the "genetics" layer is not real biological cryptography — it's a symbolic encoding scheme *inspired by* DNA base-pairing and codon logic, used purely as an additional substitution/permutation layer. Be explicit about this in the report so evaluators don't expect actual bioinformatics.

---

## 2. Restated Objectives (execution-oriented)

| # | Objective | What "done" looks like |
|---|-----------|------------------------|
| 1 | Working encryption/decryption pipeline | CLI or web tool that encrypts a file/text and correctly decrypts it back |
| 2 | Two-layer hybrid design implemented | Layer 1 (logical ops) + Layer 2 (DNA/mRNA/protein mapping) both functional and chainable |
| 3 | Security evaluation | Quantitative results: entropy, avalanche effect, NPCR/UACI, brute-force keyspace estimate |
| 4 | Performance evaluation | Encryption/decryption time vs. file size, compared against AES-128/256 baseline |
| 5 | Deployment demo | Small cloud-storage demo (e.g., upload → encrypt → store in S3/Firebase → download → decrypt) |
| 6 | Documentation | Final report, architecture diagrams, test results, PPT, and viva-ready explanation of every step |

---

## 3. System Architecture

```
                ┌─────────────────────────────────────────┐
                │              CLIENT / UI                 │
                │  (Web app or CLI — upload plaintext/file) │
                └───────────────────┬───────────────────────┘
                                    │
                        ┌───────────▼────────────┐
                        │   ENCRYPTION ENGINE      │
                        │  (Python backend / API)  │
                        └───────────┬────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        │                                                        │
┌───────▼────────┐                                     ┌─────────▼─────────┐
│ LAYER 1         │                                     │ LAYER 2            │
│ Logical-Math    │  ───── ciphertext-1 (binary) ─────▶ │ Genetics-Inspired   │
│ - Block split   │                                     │ - Binary→DNA        │
│ - Key split     │                                     │ - DNA→mRNA (transc.)│
│ - XOR/XNOR      │                                     │ - mRNA→Protein      │
│ - Bit shifting  │                                     │  (codon substitution)│
└───────┬─────────┘                                     └─────────┬──────────┘
        │                                                          │
        └───────────────────────────┬──────────────────────────────┘
                                     ▼
                         FINAL CIPHERTEXT (stored/transmitted)
                                     │
                        ┌────────────▼─────────────┐
                        │   CLOUD STORAGE LAYER      │
                        │ (AWS S3 / Firebase / local)│
                        └────────────┬─────────────┘
                                     │
                          Reverse pipeline on retrieval
                          (Protein→mRNA→DNA→binary→
                           reverse logical decryption)
                                     ▼
                              ORIGINAL PLAINTEXT
```

---

## 4. Detailed Algorithm Design

### 4.1 Layer 1 — Logical-Mathematical Encryption

1. **Key generation**: Generate a symmetric key (e.g., 128/256-bit) using a CSPRNG (`secrets` module in Python, not `random`).
2. **Block division**: Split plaintext into fixed-size blocks (e.g., 8 or 16 bytes). Pad the final block (PKCS#7-style padding) so all blocks are equal length.
3. **Key scheduling**: Derive per-block subkeys from the master key (e.g., simple key rotation or a lightweight key-expansion function — this becomes a nice "novel contribution" point if you design your own schedule).
4. **Operations per block**:
   - XOR block with subkey
   - XNOR a portion of the block with a derived mask (adds asymmetry vs. plain XOR ciphers)
   - Circular bit-shift (rotate left/right by an amount derived from the subkey, e.g., `key_byte % 8`)
5. Output: intermediate ciphertext (still raw binary).

### 4.2 Layer 2 — Genetics-Inspired Encoding

1. **Binary → DNA encoding**: Map every 2 bits to a nucleotide base:
   `00→A, 01→C, 10→G, 11→T` (this mapping should itself be keyed — i.e., permute which 2-bit pattern maps to which base using part of the key, so it's not a static public table).
2. **DNA → mRNA transcription**: Simple substitution mimicking biological transcription (`T→U`, others unchanged), optionally with a second keyed substitution table for added confusion.
3. **mRNA → Protein translation**: Group mRNA sequence into codons (groups of 3 bases) and map each of the 64 possible codons to a symbol/byte value using a keyed codon table (like a biological codon table, but keyed instead of fixed) — this is effectively a large keyed S-box (64 entries), which is your genuine cryptographic contribution.
4. Output: final ciphertext (symbol stream or re-packed binary).

### 4.3 Decryption

Exact reverse: Protein→mRNA (reverse codon table) → mRNA→DNA (reverse transcription) → DNA→binary (reverse base mapping) → reverse bit-shift → reverse XNOR → reverse XOR (using same key, since XOR/XNOR are self-inverse with the same key/mask).

### 4.4 Where the "novelty" actually lives (say this clearly in your report)

Your genuine contribution isn't inventing new bio-processes — it's:
- Making the DNA base table, transcription table, and codon table **key-dependent** rather than fixed/public (this is what makes it resistant to known-plaintext attacks that a static DNA-encoding scheme would fail).
- Chaining two structurally different S-box/permutation systems (logical layer + codon layer) to increase the effective keyspace and diffusion, similar in spirit to how AES chains SubBytes/ShiftRows/MixColumns.

---

## 5. Execution Plan (Phased, ~14–16 weeks typical for a KTU main project)

### Phase 1 — Research & Design (Weeks 1–3)
- Literature survey: read 8–10 papers on DNA cryptography, hybrid ciphers, and cloud data security (cite them properly in the report's related-work section).
- Finalize exact bit-widths, block size, key size, and all lookup tables.
- Write the formal algorithm (pseudocode) for both layers — this becomes Chapter 3/4 of your report.
- Deliverable: Design document + block diagrams (like the one above, refined).

### Phase 2 — Core Cryptographic Engine (Weeks 4–7)
- Implement Layer 1 in Python: block splitting, key scheduling, XOR/XNOR, bit-shift. Unit test each function independently (feed known input → verify expected output → verify reversibility).
- Implement Layer 2: binary↔DNA, DNA↔mRNA, mRNA↔protein, all keyed.
- Chain both layers into a single `encrypt(plaintext, key)` / `decrypt(ciphertext, key)` API.
- Deliverable: working Python library, unit tests passing, round-trip correctness (encrypt→decrypt returns original for 100% of test vectors).

### Phase 3 — Security & Performance Evaluation (Weeks 8–10)
Implement these standard tests — they're what reviewers will actually ask about in the viva:
- **Entropy analysis** of ciphertext (should approach 8 bits/byte for good randomness).
- **Avalanche effect**: flip 1 bit of plaintext or key, measure % of ciphertext bits that change (target ~50%).
- **NPCR/UACI** (Number of Pixels Change Rate / Unified Average Changing Intensity) — standard in image/DNA-crypto papers, easy to borrow even for text/file data by treating bytes as pixels.
- **Keyspace size estimate** — compute total possible keys × permutation space of your keyed tables, argue brute-force infeasibility.
- **Timing benchmarks**: encrypt/decrypt files of increasing size (1KB, 100KB, 1MB, 10MB), plot time vs. size, compare against AES-128 (use `pycryptodome` as the baseline) to support your "efficient execution" claim.
- Deliverable: a results table/graphs — this is your Chapter 5 (Results & Analysis).

### Phase 4 — Cloud Integration Demo (Weeks 11–13)
- Build a minimal web front end (Flask/Django or a simple React page) with: file upload → encrypt client-side or server-side → push to cloud storage (Firebase Storage or AWS S3 free tier) → retrieve → decrypt → download.
- This satisfies the "cloud computing" part of the title with an actual working demo, not just a claim.
- Deliverable: deployed demo (even locally hosted is fine) + screen recording as backup for the viva day in case of network issues.

### Phase 5 — Documentation & Submission (Weeks 14–16)
- Final report chapters: Introduction, Literature Survey, Problem Statement, Proposed System, Methodology, Implementation, Results & Analysis, Conclusion & Future Scope, References.
- Prepare PPT for viva with: problem → architecture diagram → live/recorded demo → results graphs → future scope.
- Plagiarism check on the report.
- Deliverable: final report (Word/PDF), PPT, source code repository (GitHub), README.

---

## 6. Technology Stack (concrete choices)

| Component | Tool/Library | Why |
|---|---|---|
| Core language | Python 3.11+ | Fast prototyping, strong crypto/bit-manipulation libraries |
| Bit/byte ops | Built-in `int`, `bytes`, `struct` | No need for external deps for Layer 1 |
| CSPRNG | `secrets` module | Cryptographically secure key generation |
| Baseline comparison | `pycryptodome` (AES) | Industry-standard benchmark |
| Backend API | Flask or FastAPI | Lightweight REST API for the demo |
| Frontend | React (or plain HTML/JS) | Simple upload/download UI |
| Cloud storage | Firebase Storage or AWS S3 (free tier) | Satisfies "cloud computing" scope without infra cost |
| Testing | `pytest` | Unit tests for round-trip correctness |
| Visualization | `matplotlib` | Timing graphs, entropy histograms |
| Version control | Git + GitHub | Team collaboration, code history for report appendix |

---

## 7. Team Role Split (suggested)

| Member | Suggested focus |
|---|---|
| Adheena S. | Layer 1 (logical-math engine) + unit testing |
| Amrit Krishnan U. | Layer 2 (DNA/mRNA/protein engine) + keyed table design |
| Rithin Raj Krishna | Cloud integration (storage API, upload/download flow) + Flask backend |
| Sandra Sugathan | Security/performance evaluation, graphs, report writing & documentation |

(Adjust based on actual strengths — but having one clear owner per layer avoids merge conflicts and makes viva Q&A easier since each person can speak authoritatively about "their" module.)

---

## 8. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Genetics layer is dismissed as "just a relabeled substitution cipher" by evaluators | Be upfront about this in the report (see §4.4) and lean on the *keyed* nature of the tables as the actual contribution — frame it as a novel keyed S-box design inspired by biological encoding, not as literal genetics |
| Performance overhead makes the hybrid scheme impractical | Benchmark early (Phase 3, not Phase 5) so there's time to optimize (e.g., vectorize with NumPy) if it's too slow |
| Security claims are asserted but not measured | Don't skip §5 Phase 3 — entropy/avalanche/NPCR results are what separate a real security project from a toy cipher demo |
| Cloud demo fails during live viva | Record a screen-capture video as a fallback |
| Scope creep (AI integration, blockchain, quantum-resistance from "Future Scope") | Keep those strictly as *future scope* bullet points in the report — do not attempt to implement them in this cycle |

---

## 9. Suggested Report Chapter Mapping

1. Introduction (from original abstract §1)
2. Literature Survey (new — 8–10 papers)
3. Problem Statement (from original §2)
4. Objectives (from original §3)
5. Proposed System & Architecture (from original §4, expanded with diagram in §3 above)
6. Methodology / Implementation (new — actual code structure, module descriptions)
7. Results & Analysis (new — Phase 3 metrics)
8. Applications (from original §8)
9. Future Scope (from original §10)
10. Conclusion (from original §11)
11. References
12. Appendix (code snippets, test vectors)

---

## 10. Immediate Next Steps

1. Finalize block size, key size, and table sizes this week (Phase 1 decision).
2. Set up a shared GitHub repo with a `layer1/`, `layer2/`, `api/`, `tests/` folder structure.
3. Each member implements a standalone function for their module with a simple `if __name__ == "__main__"` test before integrating.
4. Weekly sync to merge and run the round-trip test (encrypt→decrypt→compare) as an integration checkpoint.
