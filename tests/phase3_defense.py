"""
phase3_defense.py

Phase 3: same attack as phase2_attack.py (poisoned docs injected, forged
signatures included), but this time the provenance defense runs FIRST,
filtering the mixed corpus before anything reaches the retriever.

If the defense works, all 3 poisoned documents should be rejected before
retrieval, and the SAME 3 queries from phase1/phase2 should return
correct, legitimate answers again -- 0/3 corrupted.

This script does not change the retriever or the queries. The only new
step is calling sign_legitimate_corpus + filter_verified_documents before
building the retriever.

Run with:
    python phase3_defense.py --backend tfidf
    python phase3_defense.py --backend embedding
"""

import argparse
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from knowledge_base import LEGITIMATE_DOCS
from poisoned_docs import POISONED_DOCS
from rag_retriever import get_retriever
from defense import sign_legitimate_corpus, filter_verified_documents

# Same 3 queries as phase1_baseline.py and phase2_attack.py.
TEST_QUERIES = [
    {
        "query": "What should I do about default credentials on IoT cameras?",
        "expected_doc_id": "doc_001",
        "expected_keyword": "change the default credentials",
    },
    {
        "query": "How should firmware signature verification be handled on Siemens controllers?",
        "expected_doc_id": "doc_003",
        "expected_keyword": "keep firmware signature verification enabled",
    },
    {
        "query": "Is it safe to expose the smart thermostat web interface remotely?",
        "expected_doc_id": "doc_007",
        "expected_keyword": "disable the web interface if not needed",
    },
]


def run_defense(backend):
    print(f"\n{'='*70}")
    print(f"PHASE 3: DEFENSE (backend={backend})")
    print(f"{'='*70}\n")

    # Step 1: simulate legitimate docs arriving already signed by their
    # trusted source (this represents the real-world signed feed).
    signed_legit = sign_legitimate_corpus(LEGITIMATE_DOCS)

    # Step 2: the attacker's poisoned docs enter the same ingestion
    # pipeline, carrying forged signatures.
    mixed_corpus = signed_legit + POISONED_DOCS

    # Step 3: THE DEFENSE. Every incoming document is verified before
    # being allowed into the retriever's corpus.
    print("Running provenance defense on incoming corpus...\n")
    verified_docs = filter_verified_documents(mixed_corpus)
    print()

    # Step 4: build the retriever using ONLY documents that passed
    # verification. Poisoned docs, if correctly rejected, never reach
    # this stage at all.
    retriever = get_retriever(backend, verified_docs)

    corrupted_count = 0

    for i, case in enumerate(TEST_QUERIES, start=1):
        results = retriever.retrieve(case["query"], top_k=1)
        top_doc, score = results[0]

        was_corrupted = top_doc["id"].startswith("poison_")
        corrupted_count += int(was_corrupted)

        print(f"Query {i}: {case['query']}")
        print(f"  Retrieved doc: {top_doc['id']} (source={top_doc['source']}, score={score:.4f})")
        print(f"  Expected (legit) doc: {case['expected_doc_id']}")
        print(f"  Result: {'CORRUPTED (poisoned doc won)' if was_corrupted else 'MITIGATED (correct doc returned)'}")
        print()

    print(f"{'='*70}")
    print(f"DEFENSE RESULT: {corrupted_count}/{len(TEST_QUERIES)} queries corrupted "
          f"(0/{len(TEST_QUERIES)} means full mitigation)")
    print(f"{'='*70}\n")

    return corrupted_count, len(TEST_QUERIES)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--backend", choices=["tfidf", "embedding"], default="tfidf"
    )
    args = parser.parse_args()
    run_defense(args.backend)