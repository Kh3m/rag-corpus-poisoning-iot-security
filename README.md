# RAG Corpus Poisoning: IoT Security Assistants

Corpus poisoning attacks against RAG-based cybersecurity and IoT threat-intelligence assistants, with a lightweight, edge-deployable provenance defense.

## Motivation

Existing RAG poisoning attacks (PoisonedRAG, BadRAG, Phantom) are evaluated on generic Wikipedia-style QA corpora. Existing RAG defenses (RobustRAG, TrustRAG) are not designed with constrained or edge compute budgets in mind. Neither line of work has been tested against the kind of knowledge base a real cybersecurity assistant would actually use: CVE entries, MITRE ATT&CK technique writeups, and vendor security advisories.

This project fills that gap with two contributions:

1. A corpus poisoning attack evaluated against a realistic cyber/IoT knowledge base, tested across two retriever backends (TF-IDF and dense embeddings).
2. A lightweight provenance/fingerprint verification defense designed to run on constrained, edge-deployable hardware.

## Project structure

```
src/
├── knowledge_base.py     8 legitimate documents (CVE entries, MITRE ATT&CK, vendor advisories)
├── rag_retriever.py      Dual-backend retriever: TF-IDF and sentence-transformer embeddings
├── poisoned_docs.py      3 poisoned documents, each targeting a specific legitimate document
├── defense.py            Provenance/fingerprint verification defense
└── provenance_utils.py   Signing and verification helpers (HMAC-SHA256)

tests/
├── phase1_baseline.py    Clean system, no attack
├── phase2_attack.py      Poisoned corpus, no defense
└── phase3_defense.py     Poisoned corpus, defense active
```

## Setup

This project uses [uv](https://docs.astral.sh/uv/) for dependency management and requires Python 3.14 or newer.

```bash
git clone https://github.com/Kh3m/rag-corpus-poisoning-iot-security.git
cd rag-corpus-poisoning-iot-security
uv sync
```

`uv sync` installs the exact dependency versions recorded in `uv.lock`, which is what the results below were produced with. Without uv, `pip install -r requirements.txt` pulls the same two direct dependencies (scikit-learn, sentence-transformers), but unpinned.

## Running the experiments

Each phase can be run against either retriever backend:

```bash
uv run python tests/phase1_baseline.py --backend tfidf
uv run python tests/phase1_baseline.py --backend embedding

uv run python tests/phase2_attack.py --backend tfidf
uv run python tests/phase2_attack.py --backend embedding

uv run python tests/phase3_defense.py --backend tfidf
uv run python tests/phase3_defense.py --backend embedding
```

The `embedding` backend downloads `all-MiniLM-L6-v2` from Hugging Face on first run and caches it locally afterward. Each script prints its results to stdout; no run artifacts are written to disk.

## Results so far

**Phase 1: Baseline (no attack)**

| Backend | Queries correct |
|---|---|
| TF-IDF | 3/3 |
| Embedding | 3/3 |

**Phase 2: Attack (poisoned corpus, no defense)**

| Backend | Queries corrupted |
|---|---|
| TF-IDF | 3/3 |
| Embedding | 3/3 |

The poisoned documents spoof the source label of a trusted feed (NVD, MITRE-ATT&CK, Vendor-Advisory-Siemens) and are worded to closely mirror the phrasing of their target query, maximizing retrieval similarity against the legitimate document.

**Phase 3: Defense (poisoned corpus, defense active)**

| Backend | Queries corrupted |
|---|---|
| TF-IDF | 0/3 |
| Embedding | 0/3 |

The defense signs each legitimate document at ingestion time, simulating a trusted source (NVD, MITRE-ATT&CK, a vendor) publishing through a signed feed. Every incoming document, legitimate or poisoned, is verified against its signature (HMAC-SHA256) before being allowed into the retriever's corpus. The 3 poisoned documents, even when carrying a forged signature, are rejected before retrieval, and retrieval scores after the defense are identical to the Phase 1 baseline, confirming the poisoned documents never reach the retriever at all rather than merely being outranked.

## Threat model

The attacker is assumed to be able to inject new documents into the corpus, for example through an unvetted scraped feed or compromised ingestion pipeline, but cannot modify or delete existing legitimate documents. This matches a realistic scenario where a RAG system pulls threat intelligence from multiple external sources of varying trust.

## Limitations

TF-IDF has no semantic understanding of text, so results on that backend should be read as a lightweight/edge-realistic baseline rather than a claim about production dense-retrieval RAG systems. The embedding backend addresses this, using a small, standard, CPU-friendly sentence-transformer model.

The defense uses HMAC-SHA256 with a shared secret, a symmetric scheme, rather than a full public-key signature scheme (RSA/ECDSA). This keeps the defense dependency-free and lightweight, but a production deployment would need per-source keypairs so that document consumers never hold the signing secret itself. This upgrade path does not change the core security property demonstrated here.

The knowledge base (8 legitimate documents, 3 poisoned documents) is a proof-of-concept scale, not a full-scale threat-intelligence corpus. The poisoned documents were manually crafted to mirror target query phrasing, rather than produced by an automated optimization procedure as in PoisonedRAG-style attacks. Scaling both the corpus and the attack generation process is noted as future work.

## Citation

This project is part of ongoing research. A paper draft is in preparation.