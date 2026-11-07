"""Draw the cases for the manual check of the LLM-written questions.

Run after generate_questions.py. Output: data/manual_check.csv (marks filled by hand).
"""

import csv
import json
import os
import random

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(ROOT, "data")
CASES_PATH = os.path.join(DATA_DIR, "test_cases.json")
QUESTIONS_PATH = os.path.join(DATA_DIR, "llm_questions.json")
OUT_PATH = os.path.join(DATA_DIR, "manual_check.csv")

SEED = 20261107
PER_SOURCE = {"attack": 17, "csaf": 17, "cve": 16}  # 50 cases
VERSIONS = ["llm_paraphrase", "llm_no_id"]
MARKS = ["same_meaning", "natural", "no_leak", "note"]


def main():
    with open(CASES_PATH, encoding="utf-8") as f:
        cases = {case["case_id"]: case for case in json.load(f)}
    with open(QUESTIONS_PATH, encoding="utf-8") as f:
        questions = json.load(f)["questions"]
    if os.path.exists(OUT_PATH):
        raise SystemExit("data/manual_check.csv exists; it may hold your marks.")

    rng = random.Random(SEED)
    picked = []
    for source, n in PER_SOURCE.items():
        ids = sorted(cid for cid, c in cases.items() if c["source_type"] == source)
        picked += sorted(rng.sample(ids, n))

    rows = 0
    # utf-8-sig so Excel shows the text correctly
    with open(OUT_PATH, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["case_id", "version", "template", "llm_question"] + MARKS)
        for cid in picked:
            for version in VERSIONS:
                text = questions[cid][version]["text"]
                if text is None:
                    continue  # excluded by the automatic checks
                writer.writerow([cid, version, cases[cid]["query"], text] + [""] * len(MARKS))
                rows += 1
    print(f"{len(picked)} cases, {rows} questions -> {OUT_PATH}")


if __name__ == "__main__":
    main()
