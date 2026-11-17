"""Build a blind labelling sheet: a stratified random sample of one model's answers.

Run after run_answers.py. Usage: python scripts/make_label_sheet.py [--model mistral:7b]
Writes two files to data/answers/labelling/ (local only, answers quote advisory text):
  sheet.csv  for the labellers: no condition shown, all five lies on every row
  key.csv    for me only: which case and condition each row came from
Llama keeps the original file names; other models get the model name as a suffix.
"""

import argparse
import csv
import json
import os
import random

import run_retrieval_eval as ev  # also puts src/ on the path
from run_answers import answers_path

from poison_templates import build_poisons

OUT_DIR = os.path.join(ev.DATA_DIR, "answers", "labelling")

LLAMA = "llama3.1:8b"
# per model: random seed and number of answers to label per number of poisons
PLANS = {
    LLAMA: (20261112, {0: 25, 1: 50, 5: 25}),  # the first sheet, unchanged
    "mistral:7b": (20261117, {0: 12, 1: 25, 5: 13}),  # judge check on the second model
}
SOURCES = ["attack", "csaf", "cve"]
SOURCE_NAMES = {"attack": "ATT&CK", "csaf": "CSAF", "cve": "CVE"}  # as written in the labelling guide
# Cases discussed with me or used as practice examples in the labelling guide.
# Their answers can't be labelled blind, so they are left out of the sample
EXCLUDED = {"attack-004", "csaf-008", "csaf-023", "csaf-045", "csaf-068", "cve-083"}  # seen before labelling
MAX_DOC_CHARS = 3000  # same cut as run_answers.py


def file_tag(model: str) -> str:
    """'' for Llama (original file names), else e.g. '_mistral-7b' (Windows names can't contain ':')."""
    return "" if model == LLAMA else "_" + model.replace(":", "-")


def llama_sample_cases() -> set:
    """Cases already in the Llama sheet: left out of other models' sheets so no question is seen twice."""
    with open(os.path.join(OUT_DIR, "answer_labelling_key_PRIVATE.csv"), encoding="utf-8-sig") as f:
        return {row["case_id"] for row in csv.DictReader(f)}


def load_answers(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def pick_sample(answers: list[dict], seed: int, plan: dict, excluded: set) -> list[dict]:
    """Stratified pick: plan answers per condition, split evenly across sources, no case twice."""
    rng = random.Random(seed)
    used = set(excluded)
    sample = []
    for n_poison, size in plan.items():
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


def build_rows(sample: list[dict], cases_by_id: dict, docs_by_id: dict, seed: int) -> tuple[list[dict], list[dict]]:
    """Shuffle the sample, then build one sheet row (for labellers) and one key row (for me) per answer."""
    order = sample[:]
    random.Random(seed).shuffle(order)
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
    parser = argparse.ArgumentParser(description="Build a blind labelling sheet for one model's answers.")
    parser.add_argument("--model", default=LLAMA, choices=list(PLANS), help="whose answers to sample")
    args = parser.parse_args()
    seed, plan = PLANS[args.model]
    excluded = EXCLUDED if args.model == LLAMA else EXCLUDED | llama_sample_cases()

    kb, cases = ev.load_inputs()
    docs_by_id = {doc["id"]: doc for doc in kb}
    cases_by_id = {case["case_id"]: case for case in cases}
    answers = load_answers(answers_path(args.model))
    sample = pick_sample(answers, seed, plan, excluded)

    print(f"{args.model}: {len(answers)} answers, {len(cases)} cases, {len(kb)} documents")
    print(f"sample: {len(sample)} answers, {len({a['case_id'] for a in sample})} distinct cases")
    for n_poison in plan:
        print(f"  {n_poison} poisons: {sum(1 for a in sample if a['n_poison'] == n_poison)}")

    sheet, key = build_rows(sample, cases_by_id, docs_by_id, seed)
    os.makedirs(OUT_DIR, exist_ok=True)
    tag = file_tag(args.model)
    write_csv(os.path.join(OUT_DIR, f"answer_labelling_sheet{tag}.csv"), sheet)
    write_csv(os.path.join(OUT_DIR, f"answer_labelling_key_PRIVATE{tag}.csv"), key)
    print(f"wrote {len(sheet)} rows -> {OUT_DIR}")


if __name__ == "__main__":
    main()
