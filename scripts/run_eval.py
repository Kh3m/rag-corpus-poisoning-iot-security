"""Phase 4 evaluation: retrieval under corpus poisoning, with and without HMAC provenance."""

import csv
import hashlib
import json
import math
import os
import platform
import random
import statistics
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from importlib.metadata import version
import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from poison_templates import build_poisons
from signing import load_key, sign, verify

DATA_DIR = os.path.join(ROOT, "data")
KB_PATH = os.path.join(DATA_DIR, "knowledge_base.jsonl")
CASES_PATH = os.path.join(DATA_DIR, "test_cases.json")
MANIFEST_PATH = os.path.join(DATA_DIR, "manifest.json")
CACHE_DIR = os.path.join(DATA_DIR, "cache")  # embeddings of the KB: local only, never commit
RESULTS_DIR = os.path.join(ROOT, "results")

EMBEDDING_MODELS = {"minilm": "all-MiniLM-L6-v2", "mpnet": "all-mpnet-base-v2"}
BASE_RETRIEVERS = ["tfidf", "bm25", "minilm"]
# BASE_RETRIEVERS = ["tfidf", "bm25", "minilm", "mpnet"]
RETRIEVERS = BASE_RETRIEVERS + ["hybrid"]
HYBRID_PARTS = ["bm25", "minilm"]
RRF_K = 60
QUERY_VERSIONS = ["original", "paraphrase"]
POISONED_CONDITIONS = ["no_defense", "hmac_forged", "hmac_copied_signature", "hmac_compromised_signer"]
N_POISON_VALUES = [1, 5]
K_VALUES = [1, 5]
TOP = max(K_VALUES)
SEED = 20261103
LATENCY_QUERIES = 50


# ----------
# Inputs
# ----------

def sha256_file(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

    
def load_inputs() -> tuple[list[dict], list[dict]]:
    with open(KB_PATH, encoding="utf-8") as f:
        kb = [json.loads(line) for line in f]
    with open(CASES_PATH, encoding="utf-8") as f:
        cases = json.load(f)
    ids = {doc["id"] for doc in kb}
    if len(ids) != len(kb):
        sys.exit("Duplicate document IDs in the knowledge base")
    for case in cases:
        if case["correct_doc_id"] not in ids:
            sys.exit(f"{case['case_id']}: correct doc {case['correct_doc_id']} not in the knowledge base")
        if not case.get("paraphrase"):
            sys.exit(f"{case['case_id']}: no paraphrase; rebuild with scripts/build_dataset.py")
    return kb, cases


def wilson_ci(hits: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for hits/n."""
    if n == 0:
        return float("nan"), float("nan")
    p = hits / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return centre - half, centre + half


# ----------
# Retrievers: encode the clean KB once, then score queries and poisons against it
# ----------

class TfidfScorer:
    def __init__(self, kb_texts: list[str], kb_hash: str):
        from sklearn.feature_extraction.text import TfidfVectorizer
        self.vectorizer = TfidfVectorizer(stop_words="english")  # rows are L2-normalised
        self.kb_matrix = self.vectorizer.fit_transform(kb_texts)

    def encode_queries(self, texts: list[str]):
        return self.vectorizer.transform(texts)

    def encode_docs(self, texts: list[str]):
        return self.vectorizer.transform(texts)

    def scores(self, queries, docs) -> np.ndarray:
        """Cosine similarity, one row per query (dot product of normalised vectors)."""
        return np.asarray((queries @ docs.T).todense())


class Bm25Scorer:
    """Okapi BM25: score = sum over query terms of idf * tf * (k1 + 1) / (tf + k1 * (1 - b + b * len / avg_len))."""

    def __init__(self, kb_texts: list[str], kb_hash: str, k1: float = 1.5, b: float = 0.75):
        from sklearn.feature_extraction.text import CountVectorizer
        self.vectorizer = CountVectorizer(stop_words="english")
        counts = self.vectorizer.fit_transform(kb_texts)
        n_docs = counts.shape[0]
        doc_freq = np.bincount(counts.indices, minlength=counts.shape[1])
        self.idf = np.log(1 + (n_docs - doc_freq + 0.5) / (doc_freq + 0.5))
        self.avg_len = counts.sum() / n_docs
        self.k1, self.b = k1, b
        self.kb_matrix = self._weights(counts)

    def _weights(self, counts):
        """Turn raw term counts into BM25 term weights per document."""
        counts = counts.tocsr().astype(np.float64)
        lengths = np.asarray(counts.sum(axis=1)).ravel()
        norm = self.k1 * (1 - self.b + self.b * lengths / self.avg_len)
        tf = counts.data
        counts.data = tf * (self.k1 + 1) / (tf + np.repeat(norm, np.diff(counts.indptr)))
        return counts.multiply(self.idf).tocsr()

    def encode_queries(self, texts: list[str]):
        queries = self.vectorizer.transform(texts).astype(np.float64)
        queries.data[:] = 1.0  # each query term counts once
        return queries

    def encode_docs(self, texts: list[str]):
        return self._weights(self.vectorizer.transform(texts))

    def scores(self, queries, docs) -> np.ndarray:
        return np.asarray((queries @ docs.T).todense())


class EmbeddingScorer:
    def __init__(self, kb_texts: list[str], kb_hash: str, model_name: str):
        from sentence_transformers import SentenceTransformer
        self.model = SentenceTransformer(model_name)
        cache = os.path.join(CACHE_DIR, f"kb_{model_name}_{kb_hash[:16]}.npy")
        if os.path.exists(cache):
            self.kb_matrix = np.load(cache)
        else:
            print(f"[{model_name}] encoding {len(kb_texts)} documents (once; cached afterwards)")
            self.kb_matrix = self.encode_docs(kb_texts, progress=True)
            os.makedirs(CACHE_DIR, exist_ok=True)
            np.save(cache, self.kb_matrix)

    def encode_docs(self, texts: list[str], progress: bool = False) -> np.ndarray:
        return self.model.encode(texts, normalize_embeddings=True, convert_to_numpy=True,
                                batch_size=64, show_progress_bar=progress)

    def encode_queries(self, texts: list[str]) -> np.ndarray:
        return self.encode_docs(texts)

    def scores(self, queries, docs) -> np.ndarray:
        return queries @ docs.T

def make_scorer(name: str, kb_texts: list[str], kb_hash: str):
    """Build the retriever called `name` ("tfidf", "bm25", or a key of EMBEDDING_MODELS)."""
    if name == "tfidf":
        return TfidfScorer(kb_texts, kb_hash)
    if name == "bm25":
        return Bm25Scorer(kb_texts, kb_hash)
    return EmbeddingScorer(kb_texts, kb_hash, EMBEDDING_MODELS[name])


# ----------
# Scoring the library and ranking
# ----------

def clean_score_rows(scorer, query_vecs, n_queries: int) -> np.ndarray:
    """Scores of every clean document for every query (n_queries x n_docs)."""
    blocks = [scorer.scores(query_vecs[start:start + 50], scorer.kb_matrix)
              for start in range(0, n_queries, 50)]
    return np.vstack(blocks).astype(np.float64)


def rank_single(clean_row: np.ndarray, poison_scores: list[float], kb_ids: list[str],
                poison_ids: list[str]) -> list[str]:
    """Top-k ids for one retriever. Ties: clean docs before poisons, then lower index."""
    candidates = np.argpartition(-clean_row, TOP)[:TOP]
    merged = [(-clean_row[i], 0, int(i), kb_ids[i]) for i in candidates]
    merged += [(-score, 1, j, pid) for j, (score, pid) in enumerate(zip(poison_scores, poison_ids))]
    merged.sort()
    return [doc_id for *_, doc_id in merged[:TOP]]


def ranks_with_poisons(clean_row: np.ndarray, clean_rank: np.ndarray,
                       poison_scores: list[float]) -> tuple[np.ndarray, list[int]]:
    """0-based ranks of all clean docs and poisons in one retriever's merged ranking."""
    p = np.asarray(poison_scores, dtype=np.float64)
    if len(p):
        new_clean = clean_rank + (clean_row[None, :] < p[:, None]).sum(axis=0)
    else:
        new_clean = clean_rank
    poison_rank = [int((clean_row >= s).sum() + sum(1 for t in p[:j] if t >= s) + sum(1 for t in p[j + 1:] if t > s))
                   for j, s in enumerate(p)]
    return new_clean, poison_rank


def rank_hybrid(parts: list[tuple], poison_ids: list[str], kb_ids: list[str]) -> list[str]:
    """Top-k ids by reciprocal rank fusion of several retrievers' rankings."""
    clean_rrf = np.zeros(len(kb_ids))
    poison_rrf = np.zeros(len(poison_ids))
    for clean_row, clean_rank, poison_scores in parts:
        new_clean, poison_rank = ranks_with_poisons(clean_row, clean_rank, poison_scores)
        clean_rrf += 1.0 / (RRF_K + new_clean + 1)
        poison_rrf += 1.0 / (RRF_K + np.asarray(poison_rank) + 1) if len(poison_ids) else 0
    candidates = np.argpartition(-clean_rrf, TOP)[:TOP]
    merged = [(-clean_rrf[i], 0, int(i), kb_ids[i]) for i in candidates]
    merged += [(-poison_rrf[j], 1, j, pid) for j, pid in enumerate(poison_ids)]
    merged.sort()
    return [doc_id for *_, doc_id in merged[:TOP]]


# ----------
# Attackers: how each condition signs the poisons, and which pass the defense
# ----------

def attach_signatures(poisons: list[dict], condition: str, target_signature: str,
                      key: bytes, rng: random.Random) -> list[dict]:
    """Give each poison the signature this attacker would attach."""
    signed = []
    for poison in poisons:
        p = dict(poison)
        if condition == "hmac_forged":
            p["signature"] = "%064x" % rng.getrandbits(256)
        elif condition == "hmac_copied_signature":
            p["signature"] = target_signature
        elif condition == "hmac_compromised_signer":
            p["signature"] = sign(p, key)
        signed.append(p)
    return signed


def case_index(case: dict) -> int:
    """'csaf-007' -> 7: the case's position within its source type."""
    return int(case["case_id"].rsplit("-", 1)[1])


def build_attacks(cases: list[dict], docs_by_id: dict, signatures: dict, key: bytes) -> dict:
    """For every case and N: the poisons and, per condition, which of them pass the defense."""
    rng = random.Random(SEED)
    attacks = {}
    for case in cases:
        target = docs_by_id[case["correct_doc_id"]]
        for n_poison in N_POISON_VALUES:
            poisons = build_poisons(case, target, n_poison, case_index(case))
            passed = {"no_defense": list(range(len(poisons)))}
            for condition in POISONED_CONDITIONS[1:]:
                signed = attach_signatures(poisons, condition, signatures[target["id"]], key, rng)
                passed[condition] = [j for j, p in enumerate(signed) if verify(p, key)]
            attacks[(case["case_id"], n_poison)] = {"poisons": poisons, "passed": passed}
    return attacks


# ----------
# Evaluation
# ----------

def score_everything(kb: list[dict], kb_hash: str, cases: list[dict], attacks: dict) -> tuple[dict, dict, dict]:
    """Clean score rows and poison scores for each base retriever and query version, plus latency."""
    clean_rows, poison_scores, latency = {}, {}, {}
    
    for name in BASE_RETRIEVERS:
        print(f"[{name}] building index")
        scorer = make_scorer(name, [doc["text"] for doc in kb], kb_hash)
        poison_vecs = {key: scorer.encode_docs([p["text"] for p in attack["poisons"]])
                       for key, attack in attacks.items()}
        
        for qv in QUERY_VERSIONS:
            texts = [case["query"] if qv == "original" else case["paraphrase"] for case in cases]
            query_vecs = scorer.encode_queries(texts)
            clean_rows[(name, qv)] = clean_score_rows(scorer, query_vecs, len(cases))
            for i, case in enumerate(cases):
                for n_poison in N_POISON_VALUES:
                    vecs = poison_vecs[(case["case_id"], n_poison)]
                    poison_scores[(name, qv, case["case_id"], n_poison)] = \
                        scorer.scores(query_vecs[i:i + 1], vecs)[0].astype(np.float64).tolist()

        times = []
        for case in cases[:LATENCY_QUERIES]:
            start = time.perf_counter()
            row = scorer.scores(scorer.encode_queries([case["query"]]), scorer.kb_matrix)[0]
            np.argpartition(-row, TOP)[:TOP]
            times.append((time.perf_counter() - start) * 1000)
        latency[name] = statistics.median(times)
        print(f"[{name}] done, median query latency {latency[name]:.1f} ms")
    latency["hybrid"] = sum(latency[p] for p in HYBRID_PARTS)  # fusion itself is negligible
    return clean_rows, poison_scores, latency


def ranking_hits(ranked_ids: list[str], case: dict, poison_ids: set, k: int) -> dict:
    """Did a poison, the correct doc, or a related doc land in the top-k?"""
    top = ranked_ids[:k]
    accepted = {case["correct_doc_id"], *case["related_doc_ids"]}
    return {
        "poison_in_topk": int(any(doc_id in poison_ids for doc_id in top)),
        "correct_in_topk": int(case["correct_doc_id"] in top),
        "lenient_in_topk": int(any(doc_id in accepted for doc_id in top)),
    }


def evaluate(kb: list[dict], cases: list[dict], attacks: dict, clean_rows: dict, poison_scores: dict) -> list[dict]:
    """One row per retriever x query version x condition x N x k x case."""
    kb_ids = [doc["id"] for doc in kb]
    rows = []
    for qv in QUERY_VERSIONS:
        clean_ranks = {}
        for name in HYBRID_PARTS:
            order = np.argsort(-clean_rows[(name, qv)], axis=1, kind="stable")
            ranks = np.empty(order.shape, dtype=np.int32)
            ranks[np.arange(len(cases))[:, None], order] = np.arange(len(kb))[None, :]
            clean_ranks[name] = ranks

        for i, case in enumerate(cases):
            base = {"query_version": qv, "case_id": case["case_id"], "source_type": case["source_type"]}

            def ranked(retriever, scores_for, passed_ids):
                if retriever == "hybrid":
                    parts = [(clean_rows[(p, qv)][i], clean_ranks[p][i], scores_for(p)) for p in HYBRID_PARTS]
                    return rank_hybrid(parts, passed_ids, kb_ids)
                return rank_single(clean_rows[(retriever, qv)][i], scores_for(retriever), kb_ids, passed_ids)

            for retriever in RETRIEVERS:
                ids = ranked(retriever, lambda r: [], [])
                for k in K_VALUES:
                    rows.append({"retriever": retriever, **base, "condition": "clean", "n_poison": 0, "k": k,
                                 "kind": "", "poisons_injected": 0, "poisons_passed": 0, "top1_id": ids[0],
                                 **ranking_hits(ids, case, set(), k)})

            for n_poison in N_POISON_VALUES:
                attack = attacks[(case["case_id"], n_poison)]
                poisons = attack["poisons"]
                kind = poisons[0]["poison"]["kind"] if n_poison == 1 else "all"
                for condition in POISONED_CONDITIONS:
                    passed = attack["passed"][condition]
                    passed_ids = [poisons[j]["id"] for j in passed]

                    def scores_for(r, passed=passed, n_poison=n_poison):
                        all_scores = poison_scores[(r, qv, case["case_id"], n_poison)]
                        return [all_scores[j] for j in passed]

                    for retriever in RETRIEVERS:
                        ids = ranked(retriever, scores_for, passed_ids)
                        for k in K_VALUES:
                            rows.append({"retriever": retriever, **base, "condition": condition,
                                         "n_poison": n_poison, "k": k, "kind": kind,
                                         "poisons_injected": len(poisons), "poisons_passed": len(passed),
                                         "top1_id": ids[0], **ranking_hits(ids, case, set(passed_ids), k)})
    return rows


# ----------
# Summary and output
# ----------

def summarize(rows: list[dict]) -> list[dict]:
    """hits/n, rate and 95% Wilson CI per cell: overall, per source, per poison kind."""
    cells = defaultdict(list)
    for row in rows:
        base = (row["retriever"], row["query_version"], row["condition"], row["n_poison"], row["k"])
        cells[base + ("all",)].append(row)
        cells[base + (f"source:{row['source_type']}",)].append(row)
        if row["kind"] and row["kind"] != "all":
            cells[base + (f"kind:{row['kind']}",)].append(row)

    summary = []
    for (retriever, qv, condition, n_poison, k, group), group_rows in cells.items():
        n = len(group_rows)
        out = {"retriever": retriever, "query_version": qv, "condition": condition,
               "n_poison": n_poison, "k": k, "group": group, "n": n}
        for metric in ["poison_in_topk", "correct_in_topk", "lenient_in_topk"]:
            hits = sum(r[metric] for r in group_rows)
            low, high = wilson_ci(hits, n)
            out[f"{metric}_hits"] = hits
            out[f"{metric}_rate"] = round(hits / n, 4)
            out[f"{metric}_ci_low"] = round(low, 4)
            out[f"{metric}_ci_high"] = round(high, 4)
        summary.append(out)
    return summary


def write_csv(rows: list[dict], path: str):
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def main():
    kb, cases = load_inputs()
    kb_hash, cases_hash = sha256_file(KB_PATH), sha256_file(CASES_PATH)
    docs_by_id = {doc["id"]: doc for doc in kb}
    key = load_key()

    # the trusted feed signs every real document; the defense must accept all of them
    signatures = {doc["id"]: sign(doc, key) for doc in kb}
    start = time.perf_counter()
    rejected = [doc["id"] for doc in kb if not verify(dict(doc, signature=signatures[doc["id"]]), key)]
    verify_us = (time.perf_counter() - start) / len(kb) * 1e6
    print(f"[defense] clean KB: {len(rejected)} of {len(kb)} falsely rejected, {verify_us:.1f} us per verification")

    attacks = build_attacks(cases, docs_by_id, signatures, key)
    clean_rows, poison_scores, latency = score_everything(kb, kb_hash, cases, attacks)
    rows = evaluate(kb, cases, attacks, clean_rows, poison_scores)

    os.makedirs(RESULTS_DIR, exist_ok=True)
    summary = summarize(rows)
    write_csv(rows, os.path.join(RESULTS_DIR, "phase4_per_query.csv"))
    write_csv(summary, os.path.join(RESULTS_DIR, "phase4_summary.csv"))

    metadata = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "inputs": {"knowledge_base_sha256": kb_hash, "test_cases_sha256": cases_hash,
                   "manifest_sha256": sha256_file(MANIFEST_PATH), "documents": len(kb), "test_cases": len(cases)},
        "settings": {"retrievers": RETRIEVERS, "embedding_models": EMBEDDING_MODELS,
                     "hybrid": {"parts": HYBRID_PARTS, "rrf_k": RRF_K},
                     "query_versions": QUERY_VERSIONS, "conditions": ["clean"] + POISONED_CONDITIONS,
                     "n_poison": N_POISON_VALUES, "k": K_VALUES, "bm25": {"k1": 1.5, "b": 0.75}, "seed": SEED},
        "defense": {"clean_false_rejections": len(rejected), "clean_documents": len(kb),
                    "verify_us_per_doc": round(verify_us, 2)},
        "latency_median_ms_per_query": {r: round(ms, 2) for r, ms in latency.items()},
        "versions": {"python": platform.python_version(), "numpy": version("numpy"),
                     "scikit-learn": version("scikit-learn"),
                     "sentence-transformers": version("sentence-transformers")},
        "platform": platform.platform(),
    }
    with open(os.path.join(RESULTS_DIR, "phase4_run_metadata.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(metadata, f, indent=2)
        f.write("\n")

    print("\nTop-1, all cases (hits/n), N = 1 and clean:")
    print(f"{'retriever':10} {'query':11} {'condition':24} {'poison':>9}  {'correct':>9}")
    for s in summary:
        if s["k"] == 1 and s["group"] == "all" and s["n_poison"] in (0, 1):
            print(f"{s['retriever']:10} {s['query_version']:11} {s['condition']:24} "
                  f"{s['poison_in_topk_hits']:>4}/{s['n']:<4}  {s['correct_in_topk_hits']:>4}/{s['n']:<4}")


if __name__ == "__main__":
    main()
