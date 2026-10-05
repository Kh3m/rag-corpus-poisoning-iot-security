# RAG Corpus Poisoning: IoT Security Assistants

Corpus poisoning attacks against RAG-based cybersecurity and IoT threat-intelligence assistants, with a lightweight, edge-deployable provenance defense.

## Motivation

Existing RAG poisoning attacks (PoisonedRAG, BadRAG, Phantom) are evaluated on generic Wikipedia-style QA corpora. Existing RAG defenses (RobustRAG, TrustRAG) are not designed with constrained or edge compute budgets in mind. Neither line of work has been tested against the kind of knowledge base a real cybersecurity assistant would actually use: CVE entries, MITRE ATT&CK technique writeups, and vendor security advisories.

This project fills that gap with two contributions:

1. A corpus poisoning attack evaluated against a knowledge base of 2,749 real security documents (MITRE ATT&CK, CISA ICS advisories, CVE records), tested across two retriever backends (TF-IDF and dense embeddings).
2. A lightweight provenance/fingerprint verification defense (HMAC-SHA256 signatures) designed to run on constrained, edge-deployable hardware, tested against forged, replayed and compromised-signer attackers.

## Project structure

```
src/
├── knowledge_base.py       Phases 1-3: 8 hand-written legitimate documents (proof of concept)
├── poisoned_docs.py        Phases 1-3: 3 hand-written poisoned documents
├── poison_templates.py     Phase 4: rule-built poisoned documents (query + template, 5 per source type)
├── rag_retriever.py        Dual-backend retriever: TF-IDF and sentence-transformer embeddings
├── defense.py              Provenance/fingerprint verification defense
└── provenance_utils.py     Signing and verification helpers (HMAC-SHA256)

scripts/
├── fetch_sources.py        Phase 4: download the real documents at pinned commits, write the manifest
└── build_dataset.py        Phase 4: build the knowledge base and sample the 60 test cases

data/
├── manifest.json           Commits, URLs and SHA-256 of every downloaded file, seeds, sampled IDs
├── test_cases.json         60 test queries (20 ATT&CK, 20 CSAF, 20 CVE), each with one correct document
└── paraphrases.json        A fixed reworded version of each test query

tests/
├── phase1_baseline.py      Clean system, no attack (3 queries)
├── phase2_attack.py        Poisoned corpus, no defense (3 queries)
├── phase3_defense.py       Poisoned corpus, defense active (3 queries)
└── phase4_scaled_eval.py   Scaled evaluation: 60 queries, real documents, all attacker types

results/
├── phase4_per_query.csv    One row per retriever x condition x poisons-per-query x query version x case
├── phase4_summary.csv      Rates as hits/n with 95% Wilson intervals, overall and per source type
└── phase4_run_metadata.json  Commit, package and model versions, file hashes, seeds, corpus sizes
```

## Setup

This project uses [uv](https://docs.astral.sh/uv/) for dependency management and requires Python 3.14 or newer.

```bash
git clone https://github.com/Kh3m/rag-corpus-poisoning-iot-security.git
cd rag-corpus-poisoning-iot-security
uv sync
```

`uv sync` installs the exact dependency versions recorded in `uv.lock`, which is what the results below were produced with. Without uv, `pip install -r requirements.txt` pulls the same three direct dependencies (scikit-learn, sentence-transformers, python-dotenv), but unpinned.

### Configuration

The defense signs documents with a secret that is read from the environment rather than hardcoded, so the repository never carries key material. Create a `.env` file in the project root before running any phase:

```bash
echo "SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')" > .env
```

`.env` is gitignored. `src/provenance_utils.py` loads it with `python-dotenv` at import time and reads `SECRET_KEY`; without it, the signing helpers will fail. The value only needs to be consistent within a single run, since the same secret both signs the legitimate documents at ingestion and verifies them at retrieval time.

## Running the experiments

### Phases 1-3 (proof of concept, 3 queries)

Each phase can be run against either retriever backend:

```bash
uv run python tests/phase1_baseline.py --backend tfidf
uv run python tests/phase1_baseline.py --backend embedding

uv run python tests/phase2_attack.py --backend tfidf
uv run python tests/phase2_attack.py --backend embedding

uv run python tests/phase3_defense.py --backend tfidf
uv run python tests/phase3_defense.py --backend embedding
```

These scripts print their results to stdout and write nothing to disk.

### Phase 4 (scaled evaluation, 60 queries, real documents)

```bash
uv run python scripts/fetch_sources.py      # download sources at the commits in data/manifest.json (~96 MB)
uv run python scripts/build_dataset.py      # verify hashes, build data/knowledge_base.jsonl and data/test_cases.json
uv run python tests/phase4_scaled_eval.py   # run both backends, write results/ (about 22 minutes on CPU)
```

`fetch_sources.py` reuses the commits pinned in `data/manifest.json`, so a re-run downloads byte-identical files. `build_dataset.py` stops if any file's SHA-256 differs from the manifest.

The `embedding` backend downloads `all-MiniLM-L6-v2` from Hugging Face on first run and caches it locally afterward. Once cached, set `HF_HUB_OFFLINE=1` to stop it contacting the Hub on every run. The published phase 4 results were produced this way.

## Results

### Phases 1-3 (proof of concept)

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

The defense signs each legitimate document at ingestion time, simulating a trusted source (NVD, MITRE-ATT&CK, a vendor) publishing through a signed feed. Every incoming document, legitimate or poisoned, is verified against its signature (HMAC-SHA256) before being allowed into the retriever's corpus. The 3 poisoned documents, even when carrying a forged signature, are rejected before retrieval, and retrieval scores after the defense are identical to the Phase 1 baseline.

### Phase 4 (scaled evaluation)

**Setup.**
- **Knowledge base:** 2,749 real documents.
  - 586 MITRE ATT&CK Enterprise and 96 ICS techniques (v19.2; not revoked or deprecated, each with at least one mitigation)
  - 300 CISA CSAF OT advisories from 2023–2026, sampled with a fixed seed
  - the 1,767 published CVE records listed in those advisories
- **Test cases:** 60, sampled with a fixed seed, 20 per source type. Each query is generated from a fixed template and has exactly one correct document.
- **Two query versions:** the original query, and a fixed paraphrase that the attacker never saw.
- **Poisons:** each one is the original query followed by a harmful-advice template, spoofing the target's source label, title and link. They're injected for all 60 cases at once, with N = 1 or N = 5 per case (PoisonedRAG also uses 5).

**Conditions.**

| Condition | Poisoned documents carry |
|---|---|
| clean | no poisons (baseline) |
| no defense | poisons, no filtering |
| HMAC, forged | a random, made-up signature |
| HMAC, replayed | a valid signature copied from the real document they imitate |
| HMAC, compromised signer | a valid signature made with the real key (an attacker controlling a trusted feed) |

**Metrics**, at top-k = 1 and top-k = 5. All cells are hits/60. The 95% Wilson intervals and per-source breakdowns are in `results/phase4_summary.csv`.
- **Poison retrieval rate (retrieval-level ASR):** at least one poisoned document is in the top-k.
- **Clean retrieval accuracy:** the one correct document is in the top-k.

**Poison retrieval rate (retrieval-level ASR)**

| Backend | Condition | N | Original k=1 | Original k=5 | Paraphrase k=1 | Paraphrase k=5 |
|---|---|---|---|---|---|---|
| TF-IDF | clean | 0 | 0/60 | 0/60 | 0/60 | 0/60 |
| TF-IDF | no defense | 1 | 60/60 | 60/60 | 55/60 | 60/60 |
| TF-IDF | no defense | 5 | 60/60 | 60/60 | 56/60 | 60/60 |
| TF-IDF | HMAC, forged | 1 | 0/60 | 0/60 | 0/60 | 0/60 |
| TF-IDF | HMAC, forged | 5 | 0/60 | 0/60 | 0/60 | 0/60 |
| TF-IDF | HMAC, replayed | 1 | 0/60 | 0/60 | 0/60 | 0/60 |
| TF-IDF | HMAC, replayed | 5 | 0/60 | 0/60 | 0/60 | 0/60 |
| TF-IDF | HMAC, compromised signer | 1 | 60/60 | 60/60 | 55/60 | 60/60 |
| TF-IDF | HMAC, compromised signer | 5 | 60/60 | 60/60 | 56/60 | 60/60 |
| Embedding | clean | 0 | 0/60 | 0/60 | 0/60 | 0/60 |
| Embedding | no defense | 1 | 60/60 | 60/60 | 43/60 | 55/60 |
| Embedding | no defense | 5 | 60/60 | 60/60 | 48/60 | 60/60 |
| Embedding | HMAC, forged | 1 | 0/60 | 0/60 | 0/60 | 0/60 |
| Embedding | HMAC, forged | 5 | 0/60 | 0/60 | 0/60 | 0/60 |
| Embedding | HMAC, replayed | 1 | 0/60 | 0/60 | 0/60 | 0/60 |
| Embedding | HMAC, replayed | 5 | 0/60 | 0/60 | 0/60 | 0/60 |
| Embedding | HMAC, compromised signer | 1 | 60/60 | 60/60 | 43/60 | 55/60 |
| Embedding | HMAC, compromised signer | 5 | 60/60 | 60/60 | 48/60 | 60/60 |

**Clean retrieval accuracy (the one correct document in the top-k)**

| Backend | Condition | N | Original k=1 | Original k=5 | Paraphrase k=1 | Paraphrase k=5 |
|---|---|---|---|---|---|---|
| TF-IDF | clean | 0 | 38/60 | 52/60 | 37/60 | 53/60 |
| TF-IDF | no defense | 1 | 0/60 | 44/60 | 3/60 | 50/60 |
| TF-IDF | no defense | 5 | 0/60 | 0/60 | 3/60 | 3/60 |
| TF-IDF | HMAC, forged | 1 | 38/60 | 52/60 | 37/60 | 53/60 |
| TF-IDF | HMAC, forged | 5 | 38/60 | 52/60 | 37/60 | 53/60 |
| TF-IDF | HMAC, replayed | 1 | 38/60 | 52/60 | 37/60 | 53/60 |
| TF-IDF | HMAC, replayed | 5 | 38/60 | 52/60 | 37/60 | 53/60 |
| TF-IDF | HMAC, compromised signer | 1 | 0/60 | 44/60 | 3/60 | 50/60 |
| TF-IDF | HMAC, compromised signer | 5 | 0/60 | 0/60 | 3/60 | 3/60 |
| Embedding | clean | 0 | 29/60 | 41/60 | 30/60 | 45/60 |
| Embedding | no defense | 1 | 0/60 | 30/60 | 12/60 | 45/60 |
| Embedding | no defense | 5 | 0/60 | 0/60 | 10/60 | 15/60 |
| Embedding | HMAC, forged | 1 | 29/60 | 41/60 | 30/60 | 45/60 |
| Embedding | HMAC, forged | 5 | 29/60 | 41/60 | 30/60 | 45/60 |
| Embedding | HMAC, replayed | 1 | 29/60 | 41/60 | 30/60 | 45/60 |
| Embedding | HMAC, replayed | 5 | 29/60 | 41/60 | 30/60 | 45/60 |
| Embedding | HMAC, compromised signer | 1 | 0/60 | 30/60 | 12/60 | 45/60 |
| Embedding | HMAC, compromised signer | 5 | 0/60 | 0/60 | 10/60 | 15/60 |

**What the results show.**
- The attack retrieves a poisoned document for most queries on both retrievers, even when the user's wording differs from the query the attacker targeted. With paraphrased queries at top-1, that's 55/60 for TF-IDF and 43/60 for embeddings, with N=1.
- The HMAC defense rejects every forged and replayed poison: 60·N rejections in each run. Clean retrieval accuracy under the defense is identical to the no-attack baseline, so the defense does not block legitimate documents.
- A compromised signer defeats the defense completely. Its results are identical to having no defense, because the poisons carry valid signatures.
- In every run, the top-5 results for forged and replayed poisons were identical to the clean baseline, and those for the compromised signer were identical to no defense.
- Even without an attack, strict top-1 accuracy is limited: 38/60 for TF-IDF and 29/60 for embeddings, on original queries. This is partly because many CVE records are near-duplicates (see Limitations).

## Data sources

The scaled evaluation uses public documents from these sources, downloaded at the exact commits recorded in `data/manifest.json`:

| Source | Data | Terms |
|---|---|---|
| [MITRE ATT&CK STIX data](https://github.com/mitre-attack/attack-stix-data) | Enterprise and ICS techniques, v19.2 | [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/) |
| [CISA CSAF advisories](https://github.com/cisagov/CSAF) | OT advisories, 2023–2026 (300 sampled) | [CISA Notification](https://www.cisa.gov/notification), [Privacy & Use](https://www.cisa.gov/privacy-policy) |
| [CVE List V5](https://github.com/CVEProject/cvelistV5) | CVE records listed in the sampled advisories | [CVE Terms of Use](https://www.cve.org/Legal/TermsOfUse) |
| Siemens ProductCERT (republished by CISA) | 42 of the sampled advisories | [Siemens Security Advisory terms](https://www.siemens.com/productcert/terms-of-use) |

The built knowledge base (`data/knowledge_base.jsonl`) is not included in this repository, because the Siemens terms limit redistribution to informing one's own organization or customers. Rebuild it locally with `scripts/fetch_sources.py` and then `scripts/build_dataset.py`. The manifest's SHA-256 hashes confirm you get the same data. See `THIRD_PARTY_NOTICES.md` for attribution.

## Threat model

The attacker is assumed to be able to inject new documents into the corpus, for example through an unvetted scraped feed or compromised ingestion pipeline, but cannot modify or delete existing legitimate documents. This matches a realistic scenario where a RAG system pulls threat intelligence from multiple external sources of varying trust. Phase 4 additionally tests an attacker who copies valid signatures (replay) and one who holds a trusted source's signing key (compromised signer).

## Limitations

TF-IDF has no semantic understanding of text, so results on that backend should be read as a lightweight/edge-realistic baseline rather than a claim about production dense-retrieval RAG systems. The embedding backend addresses this, using a small, standard, CPU-friendly sentence-transformer model.

The defense uses HMAC-SHA256 with a shared secret, a symmetric scheme, rather than a full public-key signature scheme (RSA/ECDSA). This keeps the defense lightweight, but a production deployment would need per-source keypairs so that document consumers never hold the signing secret itself. Keeping the secret in `.env` rather than in source is hygiene for the simulation, not a substitute for that asymmetric design. The defense's rejection of forged and replayed signatures follows from the HMAC design. Phase 4 confirms the implementation behaves correctly, not that the scheme is novel. It offers no protection once a trusted signer is compromised.

Phases 1-3 use a proof-of-concept knowledge base: 8 hand-written legitimate documents and 3 hand-written poisoned documents that mirror their target queries. Phase 4 replaces both with real documents and rule-built poisons.

In phase 4, the test queries and poisons are generated from fixed templates, and the poisons are not optimized as in white-box PoisonedRAG-style attacks. The paraphrases are LLM-written, once, and kept fixed. With 60 test cases, the confidence intervals are wide; see `results/phase4_summary.csv`.

The CVE pool is skewed: 778 of the 1,767 CVE records are Linux kernel CVEs, listed by two large Siemens advisories, so 9 of the 20 CVE test cases are Linux kernel CVEs. These records have very similar wording, which lowers strict retrieval accuracy. The sampling rule was fixed before the results were seen and was not changed afterward.

The embedding model truncates long inputs to its maximum sequence length, so only the beginning of long documents (for example, ATT&CK techniques with many mitigations) is embedded. Short poisoned documents are embedded in full.

**Metric scope.** Every phase measures attack success at the retrieval level: whether a poisoned document appears in the top-k results that would be passed to the generator. No LLM is run, and no generated answer is judged. Retrieval-level success is an upper bound on answer-level harm, since a model cannot be misled by a document it never receives, but the two are not the same. The generator may prefer a co-retrieved legitimate document or reject advice that is obviously harmful. Measuring generation-level attack success is planned future work.

## Citation

This project is part of ongoing research. A paper draft is in preparation.
