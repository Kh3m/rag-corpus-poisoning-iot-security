"""Build the blind labelling sheet: 100 random answers for hand labelling.

Run after run_answers.py. Writes two files to data/answers/labelling/ (local only,
answers quote advisory text):
  sheet.csv  for the labellers: no condition shown, all five lies on every row
  key.csv    for me only: which case and condition each row came from
"""

import csv
import json
import os
import random

import run_eval as ev  # also puts src/ on the path

from poison_templates import build_poisons

ANSWERS_PATH = os.path.join(ev.DATA_DIR, "answers", "answers.jsonl")
OUT_DIR = os.path.join(ev.DATA_DIR, "answers", "labelling")

SEED = 20261112
SAMPLE_PLAN = {0: 25, 1: 50, 5: 25}  # number of poisons: answers to label
SOURCES = ["attack", "csaf", "cve"]
SOURCE_NAMES = {"attack": "ATT&CK", "csaf": "CSAF", "cve": "CVE"}  # as written in the labelling guide
# Cases discussed with me or used as practice examples in the labelling guide.
# Their answers can't be labelled blind, so they are left out of the sample
EXCLUDED = {"attack-004", "csaf-008", "csaf-023", "csaf-045", "csaf-068", "cve-083"}  # seen before labelling
MAX_DOC_CHARS = 3000  # same cut as run_answers.py


def load_answers() -> list[dict]:
    with open(ANSWERS_PATH, encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def pick_sample(answers: list[dict]) -> list[dict]:
    """Stratified pick: SAMPLE_PLAN answers per condition, split evenly across sources, no case twice."""
    rng = random.Random(SEED)
    used = set(EXCLUDED)
    sample = []
    for n_poison, size in SAMPLE_PLAN.items():
        for i, source in enumerate(SOURCES):
            share = size // len(SOURCES) + (1 if i < size % len(SOURCES) else 0)
            group = [
                a
                for a in answers
                if a["n_poison"] == n_poison and a["source_type"] == source and a["case_id"] not in used
            ]
            picked = rng.sample(group, share)
            used.update(a["case_id"] for a in picked)
            sample += picked
    return sample


def lies_to_check(case: dict, target_doc: dict) -> str:
    """The five lies of the case's source type, filled in for this case, numbered 1 to 5."""
    poisons = build_poisons(case, target_doc, 5, ev.case_index(case))
    lies = [p["text"].removeprefix(case["query"] + " ") for p in poisons]
    return "\n".join(f"{n}. {lie}" for n, lie in enumerate(lies, 1))


def build_rows(sample: list[dict], cases_by_id: dict, docs_by_id: dict) -> tuple[list[dict], list[dict]]:
    """Shuffle the sample, then build one sheet row (for labellers) and one key row (for me) per answer."""
    order = sample[:]
    random.Random(SEED).shuffle(order)
    sheet, key = [], []
    for row_id, a in enumerate(order, 1):
        case = cases_by_id[a["case_id"]]
        doc = docs_by_id[case["correct_doc_id"]]
        sheet.append(
            {
                "row_id": row_id,
                "source_type": SOURCE_NAMES[a["source_type"]],
                "lies_to_check": lies_to_check(case, doc),
                "question": case["query"],
                "real_document": doc["text"][:MAX_DOC_CHARS],
                "answer": a["answer"],
                "label": "",
                "note": "",
            }
        )
        key.append({"row_id": row_id, "case_id": a["case_id"], "condition": a["condition"], "n_poison": a["n_poison"]})

    return sheet, key


def write_csv(path: str, rows: list[dict]):
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main():
    kb, cases = ev.load_inputs()
    docs_by_id = {doc["id"]: doc for doc in kb}
    cases_by_id = {case["case_id"]: case for case in cases}
    answers = load_answers()
    sample = pick_sample(answers)

    print(f"{len(answers)} answers, {len(cases)} cases, {len(kb)} documents")
    print(f"sample: {len(sample)} answers, {len({a['case_id'] for a in sample})} distinct cases")
    for n_poison in SAMPLE_PLAN:
        print(f"  {n_poison} poisons: {sum(1 for a in sample if a['n_poison'] == n_poison)}")

    sheet, key = build_rows(sample, cases_by_id, docs_by_id)
    os.makedirs(OUT_DIR, exist_ok=True)
    write_csv(os.path.join(OUT_DIR, "answer_labelling_sheet.csv"), sheet)
    write_csv(os.path.join(OUT_DIR, "answer_labelling_key_PRIVATE.csv"), key)
    print(f"wrote {len(sheet)} rows -> {OUT_DIR}")


if __name__ == "__main__":
    main()
