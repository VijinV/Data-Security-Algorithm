# HelixLock 🧬🔒

> **A Data Security Algorithm for Cloud Computing Based on Genetics Techniques and Logical-Math**
> 
> *Department of Computer Science and Engineering*  
> *KVM College of Engineering and IT, APJ Abdul Kalam Technological University (KTU), Kerala*  
> *Academic Year 2026–2027*

---

## 📌 Project Overview

**HelixLock** is a two-layer hybrid cryptographic algorithm designed to secure sensitive data stored in cloud environments. It combines classical logical-mathematical operations with key-dependent biological symbolic transformations (Binary ↔ DNA ↔ mRNA ↔ Protein).

### 💡 Core Innovation
Rather than relying on static biological mapping tables, HelixLock introduces **key-dependent permutations** for DNA base pairing, transcription, and codon translation tables. This dynamically constructs a 64-entry keyed substitution box (S-box), securing the cipher against known-plaintext attacks (KPA) while maximizing diffusion and entropy.

---

## 🏗️ System Architecture

```
                ┌─────────────────────────────────────────┐
                │              CLIENT / UI                │
                │  (Web app or CLI — upload plaintext)    │
                └───────────────────┬─────────────────────┘
                                    │
                        ┌───────────▼────────────┐
                        │   ENCRYPTION ENGINE    │
                        │  (Python backend API)  │
                        └───────────┬────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        │                                                       │
┌───────▼────────┐                                    ┌─────────▼─────────┐
│ LAYER 1        │                                    │ LAYER 2           │
│ Logical-Math   │  ──── intermediate binary ──────▶ │ Genetics-Inspired │
│ - Block split  │                                    │ - Binary → DNA    │
│ - Key split    │                                    │ - DNA → mRNA      │
│ - XOR / XNOR   │                                    │ - mRNA → Protein  │
│ - Bit Rotation │                                    │  (Keyed Codons)   │
└───────┬────────┘                                    └─────────┬─────────┘
        │                                                       │
        └───────────────────────────┬───────────────────────────┘
                                    ▼
                        FINAL ENCRYPTED CIPHERTEXT
                                    │
                        ┌───────────▼────────────┐
                        │   CLOUD STORAGE LAYER  │
                        │   (Firebase / S3)      │
                        └───────────┬────────────┘
                                    │
                        Reverse Decryption Pipeline
                                    ▼
                            ORIGINAL PLAINTEXT
```

---

## 📁 Repository Structure

```
crypro/
├── api/                  # FastAPI backend REST endpoints (Phase 5)
├── client/               # Web client & UI interfaces
├── docs/                 # Documentation & plans
│   ├── HelixLock_Build_Phases.md
│   └── Project_Execution_Plan.md
├── layer1/               # Layer 1: Logical-Mathematical encryption engine
├── layer2/               # Layer 2: Genetics-inspired encoding/decoding engine
├── tests/                # Unit and integration pytest suite
├── .gitignore            # Git exclusion rules
├── requirements.txt      # Python dependencies
└── Readme.md             # Project documentation
```

---

## 🚀 Getting Started

### Prerequisites
- **Python 3.11+** installed on your system.

### Environment Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/VijinV/Data-Security-Algorithm.git
   cd Data-Security-Algorithm
   ```

2. **Create and activate Python virtual environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run Test Suite:**
   ```bash
   pytest
   ```

---

## 🛠️ Technology Stack

| Component | Technology / Library | Purpose |
|---|---|---|
| **Language** | Python 3.11+ | Core cryptographic operations & backend |
| **Cryptography** | `pycryptodome` | AES baseline benchmarks & CSPRNG |
| **Testing** | `pytest` | Unit & round-trip integration testing |
| **Math & Matrix** | `numpy` | High-performance vector & bitwise operations |
| **Visualization** | `matplotlib` | Entropy, avalanche, and execution benchmarking graphs |
| **Web API** | `fastapi` + `uvicorn` | REST API for cloud encryption/decryption demo |
| **Version Control**| Git / GitHub | Code collaboration and history tracking |

---

## 📅 Build Plan & Phases (6-Week Execution Sprint)

| Phase | Description | Key Deliverables | Owner |
|---|---|---|---|
| **Phase 0** | Project Setup & Environment | Repo structure, `.venv`, `requirements.txt`, `.gitignore` | Whole Team |
| **Phase 1** | Layer 1: Logical-Math Engine | Block splitting, XOR/XNOR, Bit rotation, CSPRNG subkey schedule | Adheena S. |
| **Phase 2** | Layer 2: Genetics Engine | Keyed Binary↔DNA, DNA↔mRNA, mRNA↔Protein tables & reversible translation | Amrit Krishnan U. |
| **Phase 3** | Integration & Testing | Full pipeline chaining (`helixlock.py`), CLI, 100% round-trip pass rate | Adheena & Amrit |
| **Phase 4** | Security & Evaluation | Entropy, Avalanche Effect (~50%), NPCR/UACI, AES performance benchmarking | Sandra Sugathan |
| **Phase 5** | Cloud Integration Demo | FastAPI backend (`/encrypt-upload`, `/download-decrypt`), storage flow demo | Rithin Raj Krishna |
| **Phase 6** | Documentation & Submission | Final report, KTU viva presentation slides, repository cleanup | Sandra (Lead) + All |

---

## 👥 Project Team & Roles

- **Adheena S.** ([KVE23CS002](mailto:adheena@example.com)) — *Layer 1 Logical-Math Engine Lead*
- **Amrit Krishnan U.** ([KVE23CS007](mailto:amrit@example.com)) — *Layer 2 Genetics-Inspired Engine Lead*
- **Rithin Raj Krishna** ([KVE23CS014](mailto:rithin@example.com)) — *Cloud Integration & API Lead*
- **Sandra Sugathan** ([KVE23CS015](mailto:sandra@example.com)) — *Security Evaluation & Project Documentation Lead*

**Project Guide:** Miss Aneeta Abraham, Head of Department (HOD), Department of Computer Science & Engineering.

