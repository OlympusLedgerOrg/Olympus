# Olympus: Federated Transparent Accountability Ledger

**Project Purpose:**  
Olympus is a cryptographically verifiable transparency platform designed to record, verify, and protect public documents, journalistic evidence, and whistleblower submissions. It guarantees **document integrity**, timestamps submissions, and provides a **trust-weighted network of anonymous contributors** — all auditable by anyone.

---

## Key Features

### 1. Federated Ledger
- Distributed shard-based ledger with **federation nodes**.  
- Each node stores signed shard headers and participates in consensus.  
- Eliminates single-point-of-trust; tampering is cryptographically detectable.  
- Supports proof generation for existence and non-existence of documents.

### 2. Document Commit & Verification
- Journalists, whistleblowers, and auditors can **commit hashes** of documents immediately.  
- Later publication can be verified against Olympus, proving the document existed **before public release**.  
- Supports multiple recipients via **multi-recipient hash commitments**.

### 3. Anonymous Key Reputation & SBT-style Credentials
- Each public key can earn **reputation scores** based on historical accuracy and contributions.  
- Non-transferable **SBT-style credentials** can be issued to keys:  
  - `verified_journalist`  
  - `trusted_whistleblower`  
  - `accurate_source`  
- Credentials are **ledger-stored, fully auditable, and tied to keys only**, not real names.

### 4. Canonicalization & Proofs
- Supports multiple document formats: JSON, HTML, DOCX, PDF.  
- Deterministic canonicalization ensures consistent hashing across format variations.  
- Sparse Merkle Tree (256-height) per shard; signed shard headers with Ed25519 signatures.  
- Public FastAPI endpoints and CLI tools for proof verification.

### 5. Transparency & External Anchoring
- Ledger roots can be anchored to public logs or blockchain timestamps.  
- Proofs are **verifiable independently**, without trusting Olympus operators.

### 6. Use Cases
- Investigative journalism: Prove documents existed prior to publication.  
- Whistleblowers: Commit evidence safely and anonymously.  
- Government oversight: Track public records and FOIA requests.  
- Audit & verification: NGOs, journalists, and the public can validate all commits.

---

## Architecture Overview

```
+----------------+        +----------------+        +----------------+
| Olympus Node A | <----> | Olympus Node B | <----> | Olympus Node C |
+----------------+        +----------------+        +----------------+
|                        |                        |
v                        v                        v
Shard Ledger → Signed Shard Headers → Sparse Merkle Tree
                           |
                           v
Global State Root → Public Verification / Anchoring
```

- **Nodes** replicate shard headers and validate all commits.  
- **Sparse Merkle Trees** store document hashes and key credential events.  
- **Global State Root** forms an auditable, cryptographically anchored ledger.

---

## API Endpoints (FastAPI)

| Endpoint | Purpose |
|----------|---------|
| `POST /doc/commit` | Commit a document hash (supports embargo or multi-recipient, keys only). |
| `POST /doc/verify` | Verify a document hash against Olympus ledger. |
| `POST /key/credential` | Issue a non-transferable credential (SBT-style) to a key. |
| `GET /ledger/shard/{shard_id}` | Retrieve shard headers and proofs. |
| `GET /ledger/proof/{commit_id}` | Retrieve proof of inclusion in the ledger. |

---

## Ledger Record Types

- `doc_commit` → Timestamped document hash (only keys referenced).  
- `key_credential` → SBT-style credential issuance/revocation.  
- `jury_verdict` → AI jury system verdicts with multiple model aggregation.  
- `funding_suggestion` → Civic Fund or budget-related suggestions.  
- `seed_entry` → Jury seed management per county/period.

---

## Getting Started

1. Clone the repository:

```bash
git clone https://github.com/wombatvagina69-crypto/Olympus.git
cd Olympus
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Start the FastAPI server:

```bash
uvicorn api.main:app --reload --port 8000
```

4. Use CLI tools for verification:

```bash
python tools/verify_proof.py --commit_id <commit_id>
```
