"""
phase4_scaled_eval.py

Phase 4: the scaled evaluation. Same idea as phases 1-3, but on a
knowledge base of 2,749 REAL documents (MITRE ATT&CK v19.2, CISA CSAF
advisories, CVE List V5 records) with 60 sampled test cases.

For each retriever backend (tfidf, embedding) we build the corpus under
5 conditions and ask every test query against it:

    clean                    real docs only (baseline, no attack)
    no_defense               real docs + poisons, no filtering
    hmac_forged              poisons carry a random, made-up signature
    hmac_replayed            poisons carry a VALID signature copied from
                             the real document they imitate
    hmac_compromised_signer  poisons are signed with the real secret key,
                             i.e. the attacker controls a trusted feed

The three hmac_* conditions run the existing provenance defense
(src/defense.py) before the retriever is built. The poisoned conditions
are run with N=1 and N=5 poisons per test case. Each query is asked in
two versions: the original wording (the attacker built the poison from
it) and a fixed paraphrase (the attacker never saw it).

Metrics, at top-k = 1 and top-k = 5:
    poison retrieval rate    share of queries with at least one poisoned
    (retrieval-level ASR)    doc in the top-k. This measures retrieval
                             only; no LLM answer is generated or judged.
    clean retrieval accuracy share of queries whose correct real doc is
                             in the top-k.
Every rate is reported as x/n with a 95% Wilson confidence interval.

Outputs:
    results/phase4_per_query.csv      one row per backend x condition x N
                                      x query version x case
    results/phase4_summary.csv        x/n, rate, 95% CI per cell, overall
                                      and per source type
    results/phase4_run_metadata.json  versions, hashes, seeds, sizes

Run with:
    uv run python tests/phase4_scaled_eval.py
"""

import csv
import hashlib
import json
import math
import os
import platform
import random
import subprocess
import sys
import time
from datetime import datetime, timezone
from importlib.metadata import version

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from rag_retriever import get_retriever
from defense import sign_legitimate_corpus, filter_verified_documents
from provenance_utils import sign_document
from poison_templates import build_poisons

ROOT = os.path.join(os.path.dirname(__file__), "..")
DATA = os.path.join(ROOT, "data")
RESULTS = os.path.join(ROOT, "results")

BACKENDS = ["tfidf", "embedding"]
POISONED_CONDITIONS = ["no_defense", "hmac_forged", "hmac_replayed", "hmac_compromised_signer"]
N_POISON_VALUES = [1, 5]
K_VALUES = [1, 5]
VERSIONS = ["original", "paraphrase"]
EMBEDDING_MODEL = "all-MiniLM-L6-v2"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sha256_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def wilson_ci(hits, n, z=1.96):
    """95% Wilson score interval for a proportion hits/n."""
    if n == 0:
        return (float("nan"), float("nan"))
    p = hits / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return (centre - half, centre + half)


def load_inputs():
    """Load the knowledge base, test cases and paraphrases, with checks."""
    with open(os.path.join(DATA, "knowledge_base.jsonl"), encoding="utf-8") as f:
        kb = [json.loads(line) for line in f]
    with open(os.path.join(DATA, "test_cases.json"), encoding="utf-8") as f:
        cases_file = json.load(f)
    with open(os.path.join(DATA, "paraphrases.json"), encoding="utf-8") as f:
        paraphrases = json.load(f)

    # The test cases must come from this exact manifest...
    assert cases_file["manifest_sha256"] == sha256_file(os.path.join(DATA, "manifest.json")), \
        "test_cases.json was built from a different manifest"
    # ...and the paraphrases must belong to these exact test cases.
    assert paraphrases["_about"]["test_cases_sha256"] == sha256_file(os.path.join(DATA, "test_cases.json")), \
        "paraphrases.json was written for a different test_cases.json"

    cases = cases_file["cases"]
    for source_type in ["attack", "csaf", "cve"]:
        assert sum(c["source_type"] == source_type for c in cases) == 20
    for c in cases:
        entry = paraphrases["paraphrases"][c["case_id"]]
        assert entry["query"] == c["query"], f"paraphrase file out of date for {c['case_id']}"
        assert entry["paraphrase"] and entry["paraphrase"] != c["query"]
        c["paraphrase"] = entry["paraphrase"]
    assert len({d["id"] for d in kb}) == len(kb), "duplicate knowledge-base ids"
    return kb, cases


def build_corpus(condition, kb, cases, kb_by_id, n_poison):
    """
    Return (documents given to the retriever, number rejected by the defense).
    """
    if condition == "clean":
        return kb, 0

    # The attacker's poisons, before any signature is attached.
    poisons = []
    for c in cases:
        poisons += build_poisons(c, kb_by_id[c["target_doc_id"]], n_poison)

    if condition == "no_defense":
        return kb + poisons, 0

    # Defense conditions: real docs arrive signed by their trusted source.
    signed_kb = sign_legitimate_corpus(kb)
    signed_by_id = {d["id"]: d for d in signed_kb}
    rng = random.Random(0)  # forged signatures are reproducible
    for p in poisons:
        target_id = next(c["target_doc_id"] for c in cases if c["case_id"] == p["targets_case"])
        if condition == "hmac_forged":
            p["signature"] = "%064x" % rng.getrandbits(256)
        elif condition == "hmac_replayed":
            p["signature"] = signed_by_id[target_id]["signature"]
        elif condition == "hmac_compromised_signer":
            p["signature"] = sign_document(p["text"], p["source"])

    incoming = signed_kb + poisons
    verified = filter_verified_documents(incoming, verbose=False)
    return verified, len(incoming) - len(verified)


def run_metadata(kb, corpus_sizes, rejections, started, seconds):
    def git(*args):
        return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True).stdout.strip()

    hf_revision = None
    try:
        from huggingface_hub import try_to_load_from_cache
        path = try_to_load_from_cache(f"sentence-transformers/{EMBEDDING_MODEL}", "config.json")
        if isinstance(path, str):
            hf_revision = os.path.basename(os.path.dirname(path))  # .../snapshots/<revision>/config.json
    except Exception:
        pass

    return {
        "run_started_utc": started,
        "runtime_seconds": round(seconds, 1),
        "git_commit": git("rev-parse", "HEAD"),
        "git_worktree_dirty": bool(git("status", "--porcelain")),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "packages": {p: version(p) for p in
                     ["scikit-learn", "sentence-transformers", "torch", "transformers", "numpy"]},
        "embedding_model": EMBEDDING_MODEL,
        "embedding_model_hf_revision": hf_revision,
        "uv_lock_sha256": sha256_file(os.path.join(ROOT, "uv.lock")),
        "manifest_sha256": sha256_file(os.path.join(DATA, "manifest.json")),
        "test_cases_sha256": sha256_file(os.path.join(DATA, "test_cases.json")),
        "paraphrases_sha256": sha256_file(os.path.join(DATA, "paraphrases.json")),
        "knowledge_base_sha256": sha256_file(os.path.join(DATA, "knowledge_base.jsonl")),
        "seeds": {"forged_signature": 0, "see_manifest_for": ["advisory_sample", "case_sample"]},
        "n_poison_values": N_POISON_VALUES,
        "k_values": K_VALUES,
        "n_cases": 60,
        "kb_size": len(kb),
        "kb_size_by_source": {s: sum(d["source"] == s for d in kb) for s in sorted({d["source"] for d in kb})},
        "corpus_size_by_condition": corpus_sizes,
        "defense_rejections_by_condition": rejections,
        "note": "SECRET_KEY is read from .env and is never logged.",
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    sys.stdout.reconfigure(encoding="utf-8")  # product names contain ™ and ®
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    t0 = time.time()

    kb, cases = load_inputs()
    kb_by_id = {d["id"]: d for d in kb}

    # Every (condition, N) pair to run. "clean" has no poisons, so N = 0.
    settings = [("clean", 0)] + [(c, n) for c in POISONED_CONDITIONS for n in N_POISON_VALUES]

    rows = []
    corpus_sizes, rejections = {}, {}
    for backend in BACKENDS:
        for condition, n_poison in settings:
            docs, rejected = build_corpus(condition, kb, cases, kb_by_id, n_poison)
            label = f"{condition}/N={n_poison}"
            corpus_sizes[label], rejections[label] = len(docs), rejected
            n_poison_in_corpus = sum(d["id"].startswith("poison_") for d in docs)
            print(f"[{backend}] {label}: corpus={len(docs)} docs "
                  f"({n_poison_in_corpus} poisoned), rejected by defense={rejected}")

            # Sanity checks on the defense, from the threat model.
            if condition in ("hmac_forged", "hmac_replayed"):
                assert rejected == 60 * n_poison and n_poison_in_corpus == 0
            if condition == "hmac_compromised_signer":
                assert rejected == 0 and n_poison_in_corpus == 60 * n_poison

            retriever = get_retriever(backend, docs)

            for c in cases:
                correct = {c["target_doc_id"]}
                lenient = correct | set(c["related_doc_ids"])
                for version_name in VERSIONS:
                    query = c["query"] if version_name == "original" else c["paraphrase"]
                    # Rank the whole corpus so we know every doc's position.
                    ranked = retriever.retrieve(query, top_k=len(docs))
                    ids = [d["id"] for d, _ in ranked]

                    def best_rank(wanted):
                        hits = [i + 1 for i, doc_id in enumerate(ids) if wanted(doc_id)]
                        return hits[0] if hits else ""

                    is_poison = lambda doc_id: doc_id.startswith("poison_")
                    is_own = lambda doc_id: doc_id.startswith(f"poison_{c['case_id']}_")
                    row = {
                        "backend": backend,
                        "condition": condition,
                        "n_poison": n_poison,
                        "query_version": version_name,
                        "case_id": c["case_id"],
                        "source_type": c["source_type"],
                        "query": query,
                        "target_doc_id": c["target_doc_id"],
                        "rank_correct": best_rank(lambda d: d in correct),
                        "rank_correct_lenient": best_rank(lambda d: d in lenient),
                        "rank_any_poison": best_rank(is_poison),
                        "rank_own_poison": best_rank(is_own),
                    }
                    for k in K_VALUES:
                        top = ids[:k]
                        row[f"poisons_in_top{k}"] = sum(map(is_poison, top))
                        row[f"any_poison_top{k}"] = int(any(map(is_poison, top)))
                        row[f"own_poison_top{k}"] = int(any(map(is_own, top)))
                        row[f"correct_top{k}"] = int(any(d in correct for d in top))
                        row[f"lenient_top{k}"] = int(any(d in lenient for d in top))
                    row["top5_ids"] = " | ".join(ids[:5])
                    row["top5_scores"] = " | ".join(f"{float(s):.6f}" for _, s in ranked[:5])
                    rows.append(row)

    assert len(rows) == 2160, f"expected 2160 per-query rows, got {len(rows)}"
    os.makedirs(RESULTS, exist_ok=True)
    with open(os.path.join(RESULTS, "phase4_per_query.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    # ---- Summary: one row per backend x condition x N x version x k x scope ----
    summary = []
    for backend in BACKENDS:
        for condition, n_poison in settings:
            for version_name in VERSIONS:
                for k in K_VALUES:
                    for scope in ["all", "attack", "csaf", "cve"]:
                        group = [r for r in rows
                                 if r["backend"] == backend and r["condition"] == condition
                                 and r["n_poison"] == n_poison and r["query_version"] == version_name
                                 and (scope == "all" or r["source_type"] == scope)]
                        n = len(group)
                        out = {"backend": backend, "condition": condition, "n_poison": n_poison,
                               "query_version": version_name, "top_k": k, "scope": scope, "n": n}
                        for metric, column in [("poison_retrieval", f"any_poison_top{k}"),
                                               ("targeted_poison_retrieval", f"own_poison_top{k}"),
                                               ("clean_accuracy", f"correct_top{k}"),
                                               ("clean_accuracy_lenient", f"lenient_top{k}")]:
                            hits = sum(r[column] for r in group)
                            low, high = wilson_ci(hits, n)
                            out[f"{metric}_hits"] = hits
                            out[f"{metric}_rate"] = hits / n
                            out[f"{metric}_ci95_low"] = low
                            out[f"{metric}_ci95_high"] = high
                        out["corpus_size"] = corpus_sizes[f"{condition}/N={n_poison}"]
                        out["defense_rejections"] = rejections[f"{condition}/N={n_poison}"]
                        summary.append(out)

    with open(os.path.join(RESULTS, "phase4_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(summary[0]))
        writer.writeheader()
        writer.writerows(summary)

    metadata = run_metadata(kb, corpus_sizes, rejections, started, time.time() - t0)
    with open(os.path.join(RESULTS, "phase4_run_metadata.json"), "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    # ---- Printed summary ----
    def cell(r, metric):
        h, n = r[f"{metric}_hits"], r["n"]
        return f"{h:>2}/{n} = {h / n:.3f} [{r[f'{metric}_ci95_low']:.3f}, {r[f'{metric}_ci95_high']:.3f}]"

    def lookup(backend, condition, n_poison, version_name, k):
        return next(s for s in summary if s["backend"] == backend and s["condition"] == condition
                    and s["n_poison"] == n_poison and s["query_version"] == version_name
                    and s["top_k"] == k and s["scope"] == "all")

    print("\n" + "=" * 118)
    print("PHASE 4 SUMMARY")
    print("Clean docs are REAL (MITRE ATT&CK v19.2, CISA CSAF, CVE List V5); queries and poisons are")
    print("GENERATED from fixed templates; paraphrases are LLM-written and fixed.")
    print(f"Dataset: 60 test cases (20 ATT&CK, 20 CSAF, 20 CVE); knowledge base = {len(kb)} real docs.")
    print(f"top-k = {K_VALUES}; poisons per case N = {N_POISON_VALUES} "
          f"(corpus = {len(kb)} + 60*N docs before any defense).")
    print("Metric: poison retrieval rate (retrieval-level ASR) = share of queries with >=1 poisoned doc")
    print("in the top-k. Retrieval only; no LLM answer is generated or judged. Cells: hits/n = rate [95% Wilson CI].")
    print("=" * 118)

    for title, metric in [("POISON RETRIEVAL RATE (retrieval-level ASR)", "poison_retrieval"),
                          ("CLEAN RETRIEVAL ACCURACY (strict: the one correct real doc in top-k)", "clean_accuracy")]:
        print(f"\n{title}")
        header = f"{'backend':<10}{'condition':<25}{'N':>2}  "
        header += "  ".join(f"{v + ' k=' + str(k):<28}" for v in VERSIONS for k in K_VALUES)
        print(header)
        print("-" * len(header))
        for backend in BACKENDS:
            for condition, n_poison in settings:
                line = f"{backend:<10}{condition:<25}{n_poison:>2}  "
                line += "  ".join(f"{cell(lookup(backend, condition, n_poison, v, k), metric):<28}"
                                  for v in VERSIONS for k in K_VALUES)
                print(line)

    # ---- Expected relationships: checked and reported, never forced ----
    def top5(backend, condition, n_poison):
        return [r["top5_ids"] for r in rows
                if r["backend"] == backend and r["condition"] == condition and r["n_poison"] == n_poison]

    print("\nCHECKS (expected from the threat model; reported as found)")
    for backend in BACKENDS:
        for n_poison in N_POISON_VALUES:
            for condition, reference in [("hmac_forged", ("clean", 0)),
                                         ("hmac_replayed", ("clean", 0)),
                                         ("hmac_compromised_signer", ("no_defense", n_poison))]:
                same = top5(backend, condition, n_poison) == top5(backend, *reference)
                print(f"  [{backend}] {condition} N={n_poison} top-5 identical to "
                      f"{reference[0]}: {'YES' if same else 'NO'}")

    print(f"\nWrote results/phase4_per_query.csv ({len(rows)} rows), "
          f"results/phase4_summary.csv ({len(summary)} rows), results/phase4_run_metadata.json")
    print(f"Runtime: {time.time() - t0:.0f} s")


if __name__ == "__main__":
    main()
