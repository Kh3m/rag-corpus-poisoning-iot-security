# RAG Corpus Poisoning in IoT/OT Security Assistants

Measuring corpus poisoning risk in RAG-based cybersecurity and IoT/OT threat-intelligence assistants, and where provenance checks do and do not protect them.

## Motivation

Security teams increasingly use RAG assistants that answer from CVE records, MITRE ATT&CK and vendor advisories. If an attacker can get a fake document into that knowledge base, the assistant can tell an analyst to skip a patch or disable a control.

RAG poisoning attacks such as [PoisonedRAG](https://arxiv.org/abs/2402.07867), [BadRAG](https://arxiv.org/abs/2406.00083) and [Phantom](https://arxiv.org/abs/2405.20485) are mostly evaluated on generic QA benchmarks (Natural Questions, HotpotQA, MS MARCO). Security-domain studies exist too, on synthetic IoT attack descriptions, Security Stack Exchange posts and CTI reports, but none of the work we found uses the authoritative sources an OT security assistant would draw on: MITRE ATT&CK, CISA advisories and CVE records. Provenance-based defenses such as [RAGShield](https://arxiv.org/abs/2604.00387) already note that signatures cannot stop a compromised signer, but this has only been shown on generic data. Most published defenses, including [RobustRAG](https://arxiv.org/abs/2405.15556) and [TrustRAG](https://arxiv.org/abs/2501.00879), add LLM calls or run on GPU-class hardware, and none we found was measured on real edge hardware.

This project addresses that gap:

1. A corpus poisoning evaluation on 28,982 real security documents (MITRE ATT&CK, CISA ICS advisories, CVE records), with 300 test questions, paraphrases the attacker never saw, and five retrievers.
2. Provenance checking (HMAC-SHA256 signatures) as a baseline defense, tested against forged, copied-signature and compromised-signer attackers. On real security data it confirms what earlier work found on generic data: provenance stops documents injected from outside the trusted sources, but not poisoned content published by a trusted source itself.
3. In progress: answer-level evaluation with a local LLM, and a defense for the case provenance cannot cover (see [Roadmap](#roadmap)).

The project started as a small proof of concept (Phases 1-3: 8 hand-written documents, 3 poisons), which is kept in the repository.

## Project structure

```
src/
├── knowledge_base.py       Phases 1-3: 8 hand-written legitimate documents (proof of concept)
├── poisoned_docs.py        Phases 1-3: 3 hand-written poisoned documents
├── rag_retriever.py        Phases 1-3: TF-IDF and sentence-transformer retriever
├── defense.py              Phases 1-3: provenance/fingerprint verification defense
├── provenance_utils.py     Phases 1-3: signing and verification helpers (HMAC-SHA256)
├── poison_templates.py     Phase 4: rule-built poisons (query + harmful template, 5 per source type)
└── signing.py              Phase 4: HMAC-SHA256 over a document's id, source, title, URL and text

scripts/
├── fetch_sources.py        Phase 4: download the sources at pinned commits, write data/manifest.json
├── build_dataset.py        Phase 4: verify hashes, build the knowledge base and the 300 test cases
└── run_eval.py             Phase 4: run every retriever x condition, write results/

data/
├── manifest.json           Commits, URLs and SHA-256 of every downloaded file
├── csaf_files.sha256       SHA-256 of every CSAF advisory file
├── cve_files.sha256        SHA-256 of every CVE record file
├── cve_missing.txt         16 CVE IDs listed in advisories but absent from the CVE List
└── test_cases.json         300 test questions (100 per source), each with a paraphrase and one correct document

tests/
├── phase1_baseline.py      Clean system, no attack (3 queries)
├── phase2_attack.py        Poisoned corpus, no defense (3 queries)
└── phase3_defense.py       Poisoned corpus, defense active (3 queries)

results/
├── phase4_per_query.csv    One row per retriever x condition x poisons per question x query version x case
├── phase4_summary.csv      Rates as hits/n with 95% Wilson intervals, overall, per source and per poison kind
└── phase4_run_metadata.json  Input hashes, settings, package versions, defense cost, latency
```

## Setup

This project uses [uv](https://docs.astral.sh/uv/) for dependency management and requires Python 3.14 or newer.

```bash
git clone https://github.com/Kh3m/rag-corpus-poisoning-iot-security.git
cd rag-corpus-poisoning-iot-security
uv sync
```

`uv sync` installs the exact dependency versions recorded in `uv.lock`, which is what the results below were produced with. Without uv, `pip install -r requirements.txt` pulls the same direct dependencies, but unpinned.

### Configuration

The defense signs documents with a secret that is read from the environment rather than hardcoded, so the repository never carries key material. Create a `.env` file in the project root before running any phase:

```bash
echo "SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')" > .env
```

`.env` is gitignored. The signing code loads it with `python-dotenv` and reads `SECRET_KEY`; without it, signing fails. The value only needs to be consistent within a single run, since the same secret both signs the legitimate documents and verifies them.

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

### Phase 4 (scaled evaluation, 300 questions, real documents)

```bash
uv run python scripts/fetch_sources.py   # download the sources at the commits in data/manifest.json
uv run python scripts/build_dataset.py   # verify every hash, write data/knowledge_base.jsonl and data/test_cases.json
uv run python scripts/run_eval.py        # run all retrievers and conditions, write results/
```

`fetch_sources.py` reuses the commits pinned in `data/manifest.json`, so a re-run downloads byte-identical files. `build_dataset.py` stops if any file's SHA-256 differs from the recorded one. If your build matches ours, these hashes are identical:

| File | SHA-256 |
|---|---|
| `data/knowledge_base.jsonl` | `862b60f4ef33c06aef59321331ffcc6ce77ea53cbe56b157c37c7e4b5b719af5` |
| `data/test_cases.json` | `9fc02cfbf871867fa513056e307b3bc84f2c9548ee782dfc896e1c6a339e3ffb` |

**Run time** (laptop CPU, Intel i7-1255U, 16 GB RAM, no GPU). The first `run_eval.py` run embeds all 28,982 documents once per embedding model and caches the result in `data/cache/`: about 30 minutes for MiniLM and about 3 hours 25 minutes for MPNet. With both caches in place, a full run takes about 5 minutes. A GPU makes the embedding step take minutes. To skip MPNet, remove `"mpnet"` from `BASE_RETRIEVERS` in `scripts/run_eval.py`.

The embedding retrievers download their models from Hugging Face on first use and cache them locally. Once cached, set `HF_HUB_OFFLINE=1` to stop them contacting the Hub on every run.

Small floating-point differences between machines can reorder documents with near-identical scores, so a re-run on different hardware may differ by a case or two.

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
- **Knowledge base:** 28,982 real documents.
  - 698 MITRE ATT&CK techniques (Enterprise and ICS, v20.0; not revoked or deprecated, each with at least one mitigation), one document per technique
  - 15,482 documents from all 3,994 CISA CSAF OT advisories, one per advisory and vulnerability
  - 12,802 published CVE records for the CVE IDs those advisories list
- **Test cases:** 300, sampled with a fixed seed, 100 per source type. Each question comes from a fixed template and has exactly one correct document.
- **Two query versions:** the original question, and a fixed paraphrase the attacker never saw.
- **Poisons:** each one is the original question followed by a harmful-advice template (for example, a false low severity, a withdrawn patch, or "disable authentication"), copying the target's source label, title and link. This is PoisonedRAG's black-box construction, with a fixed template in place of an LLM-written payload. Each question is attacked with N = 1 or N = 5 poisons of its own.
- **Retrievers:** TF-IDF, BM25, two embedding models (MiniLM, `all-MiniLM-L6-v2`, and MPNet, `all-mpnet-base-v2`), and a hybrid of BM25 and MiniLM (reciprocal rank fusion). Exact search over the whole knowledge base.

**Conditions.**

| Condition | Poisoned documents carry | What it tests |
|---|---|---|
| clean | no poisons | How well each retriever finds the correct document without an attack (baseline) |
| no defense | poisons, no filtering | How often the attack wins when nothing checks the documents |
| HMAC, forged | a made-up signature | Whether verification rejects a signature the attacker invented |
| HMAC, copied signature | the valid signature of the real document they imitate | Whether verification ties the signature to the content, not just its presence |
| HMAC, compromised signer | a valid signature made with the real key (an attacker controlling a trusted feed) | What provenance does when the trusted source itself is the attacker |

**Metrics**, at top-k = 1 and top-k = 5, reported as hits/n with 95% Wilson intervals:
- **Poison retrieval rate (retrieval-level ASR):** at least one poisoned document is in the top-k.
- **Clean retrieval accuracy:** the correct document is in the top-k. A lenient version also accepts a document about the same vulnerability from the other source.
- **False rejection rate:** legitimate documents the defense wrongly rejects.
- **Cost:** verification time per document and median query latency.

**Results.** Top-1, paraphrased questions, N = 1, hits/300. 95% Wilson intervals, top-5 results and per-source breakdowns are in `results/phase4_summary.csv`.

| Retriever | Clean: correct doc first | No defense: poison first | Forged | Copied signature | Compromised signer |
|---|---|---|---|---|---|
| TF-IDF | 172 | 298 | 0 | 0 | 298 |
| BM25 | 211 | 297 | 0 | 0 | 297 |
| MiniLM | 70 | 272 | 0 | 0 | 272 |
| MPNet | 67 | 290 | 0 | 0 | 290 |
| Hybrid | 118 | 286 | 0 | 0 | 286 |

**What the results show.**
- One poison per question reaches the top result for 91 to 99% of questions, on every retriever, even when the user's wording differs from the question the attacker targeted.
- With N = 5, the poisons fill the top 5 and push the correct document out (BM25: the correct document stays in the top 5 for 1/300 questions, compared with 281/300 at N = 1).
- HMAC verification rejects every forged and copied-signature poison. It rejected none of the 28,982 legitimate documents, at about 30 µs per document.
- The larger embedding model does not help: MPNet finds the correct document no more often than MiniLM, and the attack wins slightly more often against it. Both embedding retrievers are weak on CSAF and CVE questions, where many documents differ mainly by their identifiers.
- A compromised signer defeats the defense completely: its results are identical to having no defense, because its poisons carry valid signatures.

## Data sources

The scaled evaluation uses public documents from these sources, downloaded at the exact commits recorded in `data/manifest.json`:

| Source | Data | Terms |
|---|---|---|
| [MITRE ATT&CK STIX data](https://github.com/mitre-attack/attack-stix-data) | Enterprise and ICS techniques, v20.0 | [ATT&CK Terms of Use](https://attack.mitre.org/resources/terms-of-use/) |
| [CISA CSAF advisories](https://github.com/cisagov/CSAF) | All OT advisories (3,994) | [CISA Notification](https://www.cisa.gov/notification) |
| [CVE List V5](https://github.com/CVEProject/cvelistV5) | CVE records listed in those advisories | [CVE Terms of Use](https://www.cve.org/Legal/TermsOfUse) |
| Siemens ProductCERT (republished by CISA) | 1,061 of the advisories | [Siemens Security Advisory terms](https://www.siemens.com/productcert/terms-of-use) |

The built knowledge base (`data/knowledge_base.jsonl`) and its embeddings are not included in this repository, because the Siemens terms limit redistribution. Rebuild them locally with the commands above; the hashes in the table above confirm you have the same data. See `THIRD_PARTY_NOTICES.md` for attribution.

## Threat model

The attacker is assumed to be able to inject new documents into the corpus, for example through an unvetted scraped feed or compromised ingestion pipeline, but cannot modify or delete existing legitimate documents. This matches a realistic scenario where a RAG system pulls threat intelligence from multiple external sources of varying trust. Phase 4 also tests an attacker who copies valid signatures from real documents, and one who holds a trusted source's signing key (compromised signer).

## Limitations

TF-IDF and BM25 match words, not meaning. On this data they are still the strongest retrievers, because the questions contain exact identifiers (CVE IDs, ATT&CK technique IDs) that word matching finds easily. Every test question names such an identifier; analysts also ask questions without one, which would likely favour the embedding retrievers. The embedding retrievers cover meaning-based search with two standard, CPU-friendly sentence-transformer models; both are general-purpose models, not trained on security text.

The defense uses HMAC-SHA256 with a shared secret, a symmetric scheme, rather than a full public-key signature scheme. This keeps the defense lightweight, but a production deployment would need per-source keypairs so that document consumers never hold the signing secret itself. The rejection of forged and copied signatures follows from the HMAC design; Phase 4 confirms the implementation behaves correctly, not that the scheme is novel.

Phases 1-3 use a proof-of-concept knowledge base: 8 hand-written legitimate documents and 3 hand-written poisoned documents that mirror their target queries.

In Phase 4, the test questions and poisons come from fixed templates, and the poisons are not optimized as in white-box PoisonedRAG-style attacks. To keep 300 questions x all conditions fast, each question's poisons are scored against the clean knowledge base's statistics instead of re-indexing; for the embedding retrievers this is exact, and for TF-IDF and BM25 the change in word statistics from adding 1-5 documents is negligible.

**Metric scope.** Every phase measures attack success at the retrieval level: whether a poisoned document appears in the top-k results that would be passed to the generator. No LLM is run, and no generated answer is judged. Retrieval-level success is an upper bound on answer-level harm, since a model cannot be misled by a document it never receives, but the two are not the same. The generator may prefer a co-retrieved legitimate document or reject advice that is obviously harmful. Measuring generation-level attack success is the next step.

## Roadmap

- [x] **Phases 1-3:** proof of concept on 8 hand-written documents and 3 hand-written poisons, with both retriever backends
- [x] **Phase 4:** scaled evaluation on 28,982 real documents and 300 questions, with rule-built poisons, paraphrased queries, five retrievers and forged, copied-signature and compromised-signer attackers
- [ ] **Answer-level evaluation** *(current)*: generate answers with a small local LLM (run with Ollama, so no knowledge base text leaves the machine) and measure answer-level attack success rate (ASR), not just retrieval
- [ ] **Stronger attacks:** poisons that don't copy the target query, and optimized attacks against the embedding retriever
- [ ] **Defenses for compromised sources:** protection when a poisoned document carries a valid signature from a trusted feed
- [ ] **Edge measurements:** latency and memory of the defense on edge hardware, compared with existing RAG defenses
- [ ] **Paper**

## Citation

This project is part of ongoing research. A paper draft is in preparation.
