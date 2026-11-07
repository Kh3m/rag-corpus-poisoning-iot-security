"""Write natural and no-ID versions of the test questions with a local LLM.

Run after build_dataset.py. Needs Ollama running with the model pulled.
Output: data/llm_questions.json (frozen; never regenerated after eval).
"""
import json
import os
import re
import time
import urllib.request

import ollama


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(ROOT, "data")
RAW_DIR = os.path.join(DATA_DIR, "raw")
CASES_PATH = os.path.join(DATA_DIR, "test_cases.json")
KB_PATH = os.path.join(DATA_DIR, "knowledge_base.jsonl")
ID_PATTERNS = [
    r"CVE-\d{4}-\d{4,}",                        # CVE-2026-25197
    r"\bT\d{4}(?:\.\d{3})?\b",                  # T1053, T1003.007
    r"\bICS[A-Z]*-\d{2}-\d{3}-\d{2}[A-Z]?\b",   # ICSA-16-287-03, ICSMA-...
]

MODEL = "llama3.1:8b"
SEED = 20261103
OPTIONS = {"temperature": 0, "seed": SEED, "num_predict": 80}
RETRY_TEMPERATURE = 0.7
MAX_TRIES = 3
OUT_PATH = os.path.join(DATA_DIR, "llm_questions.json")

SYSTEM = ("You rewrite questions for a security analyst. Reply with the rewritten "
          "question only: one sentence ending with a question mark, no quotes, "
          "no explanation.")
PROMPTS = {
    "llm_paraphrase": (
        "Rewrite this question the way a security analyst at an industrial company "
        "would naturally type it to an assistant. Keep the same meaning. The "
        "rewritten question must contain the identifier {ident}, written exactly "
        "like that. Do not add any facts, numbers or versions.\n\nQuestion: {query}"),
    "llm_no_id": (
        "Rewrite this question the way a security analyst at an industrial company "
        "would naturally type it to an assistant, but without any identifier: no CVE "
        "number, no ATT&CK technique ID, no advisory number. Refer to it as: {target}. "
        "Keep the same meaning. Do not add any facts, numbers or versions.\n\n"
        "Question: {query}"),
}


# ----------
# Descriptions that replace the ID
# ----------

def load_test_cases() -> list[dict]:
    with open(CASES_PATH, encoding="utf-8") as f:
        return json.load(f)


def csaf_path(advisory_id: str) -> str:
    year = "20" + advisory_id.split("-")[1]  # ICSA-25-261-06 -> 2025
    return os.path.join(RAW_DIR, "csaf", year, advisory_id.lower() + ".json")


# Weakness lookup
def clean_cwe(text: str) -> str:
    # "CWE-787: Out-of-bounds Write" -> "out-of-bounds write"
    text = re.sub(r"^CWE-\d+\s*:?\s*", "", text.strip())
    return text.lower()


def csaf_weakness(advisory_id: str, cve_id: str) -> str:
    with open(csaf_path(advisory_id), encoding="utf-8") as f:
        advisory = json.load(f)
    for vuln in advisory.get("vulnerabilities", []):
        if vuln.get("cve") == cve_id:
            return clean_cwe((vuln.get("cwe") or {}).get("name", ""))
    return ""


def weakness(case: dict) -> str:
    # CVE cases use the CSAF twin listed in related_doc_ids
    doc_ids = [case["correct_doc_id"]] + case.get("related_doc_ids", [])
    for doc_id in doc_ids:
        if doc_id.startswith("csaf:"):
            _, advisory_id, cve_id = doc_id.split(":")
            name = csaf_weakness(advisory_id, cve_id)
            if name:
                return name
    return ""


# Targets and IDs
def load_targets(cases: list[dict]) -> dict:
    # only the documents our questions point at, not all 28,982
    wanted = {case["correct_doc_id"] for case in cases}
    docs = {}
    with open(KB_PATH, encoding="utf-8") as f:
        for line in f:
            doc = json.loads(line)
            if doc["id"] in wanted:
                docs[doc["id"]] = doc
    return docs


def description(case: dict, doc: dict) -> str:
    if case["source_type"] == "attack":
        return doc["fields"]["name"]  # e.g. "Proc Filesystem"
    return weakness(case)


def identifier(case: dict, doc: dict) -> str:
    if case["source_type"] == "attack":
        return doc["fields"]["attack_id"]
    return doc["fields"]["cve_id"]


def find_ids(text: str) -> list[str]:
    found = []
    for pattern in ID_PATTERNS:
        found += re.findall(pattern, text, flags=re.IGNORECASE)
    return found


# ----------
# Automatic checks
# ----------

def words_of(text: str) -> set[str]:
    # lowercase words of 4+ letters: "Gardyn's Cloud API" -> {"gardyn", "cloud"}
    return set(re.findall(r"[a-z][a-z0-9\-]{3,}", text.lower()))


def target_words(case: dict, doc: dict) -> set[str]:
    fields = doc["fields"]
    if case["source_type"] == "attack":
        return words_of(fields["name"])
    return words_of(fields.get("vendor", "") + " " + fields.get("product", ""))


def problems(case: dict, doc: dict, version: str, text: str) -> list[str]:
    found = []
    ids = [i.lower() for i in find_ids(text)]
    if version == "llm_paraphrase" and identifier(case, doc).lower() not in ids:
        found.append("identifier missing")
    if version == "llm_no_id" and ids:
        found.append("identifier leaked: " + ", ".join(ids))
    # an ATT&CK paraphrase may name the technique by its ID alone
    id_names_it = case["source_type"] == "attack" and version == "llm_paraphrase"
    if not id_names_it and not words_of(text) & target_words(case, doc):
        found.append("target not named")
    if not text.strip().endswith("?") or text.count("?") != 1:
        found.append("not one question")
    n_words = len(text.split())
    if not 5 <= n_words <= 40:
        found.append(f"{n_words} words")
    if text.strip().lower() == case["query"].strip().lower():
        found.append("same as template")
    # numbers must come from the template (product names, IDs), not from answers
    allowed = set(re.findall(r"\d+(?:\.\d+)?", case["query"]))
    extra = [n for n in re.findall(r"\d+(?:\.\d+)?", text) if n not in allowed]
    if extra:
        found.append("new numbers: " + ", ".join(extra))
    return found


# ----------
# Asking the model
# ----------

def target_text(case: dict, doc: dict) -> str:
    # what the no-ID question calls it instead of the ID
    fields = doc["fields"]
    if case["source_type"] == "attack":
        return f'the "{fields["name"]}" technique'
    return (f'the {description(case, doc)} vulnerability in '
            f'{fields.get("vendor", "")} {fields.get("product", "")}').replace("  ", " ")


def ask(prompt: str, seed: int, temperature: float) -> str:
    options = dict(OPTIONS, seed=seed, temperature=temperature)
    response = ollama.generate(model=MODEL, system=SYSTEM, prompt=prompt, options=options)
    return response.response.strip().strip('"')


def generate(case: dict, doc: dict, version: str) -> dict:
    prompt = PROMPTS[version].format(ident=identifier(case, doc),
                                     target=target_text(case, doc),
                                     query=case["query"])
    tries = []
    for attempt in range(MAX_TRIES):
        seed = SEED + attempt
        temperature = 0 if attempt == 0 else RETRY_TEMPERATURE
        text = ask(prompt, seed, temperature)
        found = problems(case, doc, version, text)
        tries.append({"seed": seed, "temperature": temperature,
                      "text": text, "problems": found})
        if not found:
            return {"text": text, "tries": tries}
    return {"text": None, "tries": tries}  # excluded, but kept for the record


# ----------
# Saving and resuming
# ----------

def run_info() -> dict:
    # everything needed to repeat this run
    with urllib.request.urlopen("http://localhost:11434/api/version") as r:
        ollama_version = json.load(r)["version"]
    for model in ollama.list().models:
        if model.model == MODEL:
            return {"model": MODEL, "digest": model.digest,
                    "ollama_version": ollama_version, "system": SYSTEM,
                    "prompts": PROMPTS, "options": OPTIONS,
                    "retry_temperature": RETRY_TEMPERATURE, "max_tries": MAX_TRIES}
    raise SystemExit(f"{MODEL} not found; run: ollama pull {MODEL}")


def load_done(info: dict) -> dict:
    if not os.path.exists(OUT_PATH):
        return {}
    with open(OUT_PATH, encoding="utf-8") as f:
        saved = json.load(f)
    if saved["run"] != info:
        raise SystemExit("Settings changed since the last run. "
                         "Delete data/llm_questions.json to start over.")
    return saved["questions"]


def save(info: dict, questions: dict):
    tmp = OUT_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"run": info, "questions": questions}, f, indent=2, ensure_ascii=False)
    os.replace(tmp, OUT_PATH)


def main():
    cases = load_test_cases()
    docs = load_targets(cases)
    info = run_info()
    questions = load_done(info)
    start = time.time()
    for n, case in enumerate(cases, 1):
        if case["case_id"] in questions:
            continue  # done in an earlier run
        doc = docs[case["correct_doc_id"]]
        questions[case["case_id"]] = {v: generate(case, doc, v) for v in PROMPTS}
        save(info, questions)
        minutes = (time.time() - start) / 60
        print(f"[{n}/{len(cases)}] {case['case_id']} ({minutes:.0f} min)", flush=True)
    failed = [(cid, v) for cid, q in questions.items() for v in q if q[v]["text"] is None]
    print(f"done: {len(questions)} cases, {len(failed)} questions excluded: {failed}")


if __name__ == "__main__":
    main()