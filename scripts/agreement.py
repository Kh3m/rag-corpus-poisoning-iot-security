"""Agreement on the hand-labelled answers: a labeller's sheet vs the phrase detector.

Run after detect_phrases.py. Usage: python scripts/agreement.py <labelled sheet .csv>
"Mentioned" means harmful, mixed or flagged (the lie appears in the answer); the detector
can only tell mentioned from unaffected, so that is the comparison.
"""

import argparse
import csv
import json
import os

import run_eval as ev  # also puts src/ on the path
from sklearn.metrics import cohen_kappa_score

LABEL_DIR = os.path.join(ev.DATA_DIR, "answers", "labelling")
KEY_PATH = os.path.join(LABEL_DIR, "answer_labelling_key_PRIVATE.csv")
HITS_PATH = os.path.join(ev.DATA_DIR, "answers", "phrase_hits.jsonl")


def read_csv(path: str) -> list[dict]:
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def answer_key(case_id: str, condition: str, n_poison) -> str:
    return f"{case_id}|{condition}|{n_poison}"


def main():

    parser = argparse.ArgumentParser(description="Agreement between a labeller's sheet and the phrase detector.")
    parser.add_argument("sheet", help="a labeller's finished sheet (.csv)")
    args = parser.parse_args()
    sheet = {row["row_id"]: row["label"] for row in read_csv(args.sheet)}

    with open(HITS_PATH, encoding="utf-8") as f:
        hits = {answer_key(h["case_id"], h["condition"], h["n_poison"]): h for h in map(json.loads, f)}

    human, detector, n_poison = [], [], []
    for k in read_csv(KEY_PATH):
        human.append(sheet[k["row_id"]] != "unaffected")
        detector.append(hits[answer_key(k["case_id"], k["condition"], k["n_poison"])]["mentioned"])
        n_poison.append(k["n_poison"])

    agree = sum(h == d for h, d in zip(human, detector))
    print(
        f"labeller vs detector, {len(human)} rows: agree {agree}/{len(human)}, "
        f"Cohen's kappa {cohen_kappa_score(human, detector):.2f}"
    )
    print(f"  both say mentioned: {sum(h and d for h, d in zip(human, detector))}")
    print(f"  only the detector:  {sum(d and not h for h, d in zip(human, detector))}  (false alarms)")
    print(f"  only the labeller:  {sum(h and not d for h, d in zip(human, detector))}  (missed)")
    for n in ("0", "1", "5"):
        rows = [h == d for h, d, p in zip(human, detector, n_poison) if p == n]
        print(f"  {n} poisons: agree {sum(rows)}/{len(rows)}")


if __name__ == "__main__":
    main()
