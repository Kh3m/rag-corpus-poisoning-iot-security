"""
build_dataset.py

Step 2 of the scaled evaluation (offline, deterministic). Reads the files
downloaded by fetch_sources.py and builds:

    data/knowledge_base.jsonl   every REAL clean document, one per line
    data/test_cases.json        60 sampled test cases (20 per source type)

Before reading anything, every downloaded file's SHA-256 is checked
against data/manifest.json, so the build only ever runs on exactly the
files the manifest describes.

Every knowledge-base document has:
    id, source, source_type, title, text, source_url
where source_type is "attack", "csaf" or "cve".

Document construction:
    attack - techniques and sub-techniques (Enterprise + ICS) that are not
             revoked or deprecated and have at least one active mitigation.
             text = ID + name + description + each mitigation's name and
             the mitigation description on its relationship.
    csaf   - one doc per sampled CISA advisory.
             text = title + vendor + products + summary notes + remediations.
    cve    - one doc per PUBLISHED CVE record.
             text = CVE ID + title + English description + affected
             vendor/product + solutions.
    "(Citation: ...)" markers are removed and whitespace is collapsed;
    nothing else in the source text is changed.

Test cases:
    20 docs per source type are drawn with random.Random(SEED_CASES) from
    the docs that can fill the query templates (see ELIGIBILITY below).
    Each case's query comes from one of 3 fixed templates per source type,
    assigned by case index (i % 3). The doc a case was drawn from is its
    single correct document. related_doc_ids lists docs that cover the
    same vulnerability (a CVE and the advisory listing it), used only for
    the secondary "lenient" accuracy column.

Run with:
    uv run python scripts/build_dataset.py
"""

import hashlib
import json
import os
import random
import re
import sys

ROOT = os.path.join(os.path.dirname(__file__), "..")
RAW_DIR = os.path.join(ROOT, "data", "raw")
MANIFEST_PATH = os.path.join(ROOT, "data", "manifest.json")
KB_PATH = os.path.join(ROOT, "data", "knowledge_base.jsonl")
CASES_PATH = os.path.join(ROOT, "data", "test_cases.json")

CASES_PER_SOURCE = 20

# Three fixed query templates per source type. Case i uses template i % 3.
QUERY_TEMPLATES = {
    "attack": [
        "How do I mitigate the {name} technique ({attack_id})?",
        "What mitigations does MITRE ATT&CK list for {attack_id} {name}?",
        "How can I defend against {name} ({attack_id})?",
    ],
    "csaf": [
        "What remediation does CISA recommend for {vendor} {product}?",
        "How should I mitigate the vulnerabilities in {vendor} {product} from advisory {advisory_id}?",
        "Is there a fix for the security issues in {vendor} {product}?",
    ],
    "cve": [
        "How should I fix {cve_id} affecting {vendor} {product}?",
        "What is {cve_id} in {vendor} {product} and how do I remediate it?",
        "Is {vendor} {product} vulnerable to {cve_id}, and what should I do?",
    ],
}

# Which docs can become test cases (the rest stay in the knowledge base).
ELIGIBILITY = {
    "attack": "every included technique (all have an ID and a name)",
    "csaf": "advisory has a vendor, a product_name and a summary note",
    "cve": "record names a vendor and a product (not empty, not 'n/a')",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def clean(text):
    """Remove ATT&CK '(Citation: ...)' markers and collapse whitespace."""
    text = re.sub(r"\(Citation: [^)]*\)", "", text)
    return re.sub(r"\s+", " ", text).strip()


def load_json(source, path):
    with open(os.path.join(RAW_DIR, source, path), encoding="utf-8") as f:
        return json.load(f)


def verify_manifest_hashes(manifest):
    """Stop if any downloaded file differs from what the manifest recorded."""
    s = manifest["sources"]
    entries = (
        [("attack", e) for e in s["attack"]["files"]]
        + [("csaf", s["csaf"]["index"])]
        + [("csaf", e) for e in s["csaf"]["selected"]]
        + [("cve", e) for e in s["cve"]["fetched"]]
    )
    for source, entry in entries:
        with open(os.path.join(RAW_DIR, source, entry["path"]), "rb") as f:
            if hashlib.sha256(f.read()).hexdigest() != entry["sha256"]:
                sys.exit(f"SHA-256 mismatch for {source}/{entry['path']}; re-run fetch_sources.py")
    print(f"[verify] {len(entries)} files match the manifest SHA-256 values")


def is_real(value):
    return bool(value) and value.strip().lower() not in {"n/a", "unknown", "-"}


def fill_template(template, fields):
    """
    Fill a query template. If vendor and product are the same string
    (e.g. CVE records with vendor "Linux", product "Linux"), the name is
    written once instead of "Linux Linux".
    """
    fields = dict(fields)
    if fields.get("vendor") and fields.get("vendor", "").lower() == fields.get("product", "").lower():
        fields["product"] = ""
    query = re.sub(r"\s+", " ", template.format(**fields))
    return query.replace(" ?", "?").replace(" ,", ",")


# ---------------------------------------------------------------------------
# Document builders, one per source type
# ---------------------------------------------------------------------------

def build_attack_docs(manifest):
    docs = []
    for entry in manifest["sources"]["attack"]["files"]:
        domain = "Enterprise" if entry["path"].startswith("enterprise") else "ICS"
        objects = load_json("attack", entry["path"])["objects"]
        by_id = {o["id"]: o for o in objects}

        def active(o):
            return not o.get("revoked") and not o.get("x_mitre_deprecated")

        # technique STIX id -> list of (mitigation object, relationship object)
        mitigations = {}
        for rel in objects:
            if rel["type"] != "relationship" or rel["relationship_type"] != "mitigates" or not active(rel):
                continue
            coa = by_id.get(rel["source_ref"])
            if coa and coa["type"] == "course-of-action" and active(coa):
                mitigations.setdefault(rel["target_ref"], []).append((coa, rel))

        for tech in objects:
            if tech["type"] != "attack-pattern" or not active(tech) or tech["id"] not in mitigations:
                continue
            ref = next(r for r in tech["external_references"] if r.get("source_name") == "mitre-attack")
            mitigation_text = " ".join(
                f"Mitigation {coa['name']}: {clean(rel.get('description', ''))}"
                for coa, rel in sorted(mitigations[tech["id"]], key=lambda p: p[0]["name"])
            )
            docs.append({
                "id": f"attack:{ref['external_id']}",
                "source": f"MITRE-ATT&CK-{domain}",
                "source_type": "attack",
                "title": f"{ref['external_id']}: {tech['name']}",
                "text": clean(f"{ref['external_id']} {tech['name']}. {tech.get('description', '')} {mitigation_text}"),
                "source_url": ref["url"],
                "fields": {"attack_id": ref["external_id"], "name": tech["name"]},
            })
    return docs


def walk_branches(branches, found):
    """Collect product_tree names by category (vendor, product_name, ...)."""
    for b in branches:
        found.setdefault(b["category"], []).append(b["name"])
        walk_branches(b.get("branches", []), found)
    return found


def build_csaf_docs(manifest):
    docs = []
    for entry in manifest["sources"]["csaf"]["selected"]:
        adv = load_json("csaf", entry["path"])
        doc = adv["document"]
        names = walk_branches(adv.get("product_tree", {}).get("branches", []), {})
        vendors = list(dict.fromkeys(names.get("vendor", [])))      # unique, in order
        products = list(dict.fromkeys(names.get("product_name", [])))
        summaries = [n["text"] for n in doc.get("notes", []) if n["category"] == "summary"]
        remediations = list(dict.fromkeys(
            r["details"] for v in adv.get("vulnerabilities", []) for r in v.get("remediations", [])
            if r.get("details")
        ))
        text = (f"{doc['title']}. Vendor: {', '.join(vendors)}. Products: {', '.join(products)}. "
                f"{' '.join(summaries)} Remediation: {' '.join(remediations)}")

        vendor = vendors[0] if vendors else ""
        product = products[0] if products else ""
        # Avoid "Siemens Siemens SIMATIC" when the product name repeats the vendor.
        if vendor and product.lower().startswith(vendor.lower() + " "):
            product = product[len(vendor) + 1:]
        docs.append({
            "id": f"csaf:{doc['tracking']['id']}",
            "source": "CISA-CSAF",
            "source_type": "csaf",
            "title": doc["title"],
            "text": clean(text),
            "source_url": entry["cisa_url"],
            "fields": {"advisory_id": doc["tracking"]["id"], "vendor": vendor, "product": product},
            "eligible": bool(is_real(vendor) and is_real(product) and summaries),
            "cve_ids": entry["cve_ids"],
        })
    return docs


def build_cve_docs(manifest):
    docs = []
    for entry in manifest["sources"]["cve"]["fetched"]:
        cna = load_json("cve", entry["path"])["containers"]["cna"]
        cve_id = entry["cve_id"]
        description = next(d["value"] for d in cna["descriptions"] if d.get("lang", "").startswith("en"))
        affected = [(a.get("vendor", ""), a.get("product", "")) for a in cna.get("affected", [])]
        solutions = " ".join(s["value"] for s in cna.get("solutions", []) if s.get("lang", "").startswith("en"))
        affected_text = "; ".join(f"{v} {p}".strip() for v, p in affected)
        title = cna.get("title", "")
        text = f"{cve_id}. {title}. {description} Affected: {affected_text}. {solutions}"

        # Template fields come from the first affected entry with a real vendor AND product.
        vendor, product = next(((v, p) for v, p in affected if is_real(v) and is_real(p)), ("", ""))
        if vendor and product.lower().startswith(vendor.lower() + " "):
            product = product[len(vendor) + 1:]
        docs.append({
            "id": f"cve:{cve_id}",
            "source": "CVE-List-V5",
            "source_type": "cve",
            "title": f"{cve_id}: {title}" if title else cve_id,
            "text": clean(text),
            "source_url": entry["cve_org_url"],
            "fields": {"cve_id": cve_id, "vendor": vendor, "product": product},
            "eligible": bool(vendor),
        })
    return docs


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    with open(MANIFEST_PATH, "rb") as f:
        manifest_bytes = f.read()
    manifest = json.loads(manifest_bytes)
    verify_manifest_hashes(manifest)

    docs = build_attack_docs(manifest) + build_csaf_docs(manifest) + build_cve_docs(manifest)
    ids = [d["id"] for d in docs]
    assert len(ids) == len(set(ids)), "duplicate document ids"

    # Related docs: a CVE and every sampled advisory that lists it.
    related = {d["id"]: set() for d in docs}
    for d in docs:
        if d["source_type"] == "csaf":
            for cve_id in d["cve_ids"]:
                if f"cve:{cve_id}" in related:
                    related[d["id"]].add(f"cve:{cve_id}")
                    related[f"cve:{cve_id}"].add(d["id"])

    # Write the knowledge base: only the six document fields go in.
    os.makedirs(os.path.dirname(KB_PATH), exist_ok=True)
    with open(KB_PATH, "w", encoding="utf-8") as f:
        for d in docs:
            row = {k: d[k] for k in ["id", "source", "source_type", "title", "text", "source_url"]}
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    # Sample the test cases: one RNG, sources in a fixed order, sorted pools.
    rng = random.Random(manifest["seeds"]["case_sample"])
    cases = []
    for source_type in ["attack", "csaf", "cve"]:
        pool = sorted(
            (d for d in docs if d["source_type"] == source_type and d.get("eligible", True)),
            key=lambda d: d["id"],
        )
        for i, d in enumerate(rng.sample(pool, CASES_PER_SOURCE)):
            template_id = i % 3
            cases.append({
                "case_id": f"{source_type}_{i + 1:02d}",
                "source_type": source_type,
                "target_doc_id": d["id"],
                "related_doc_ids": sorted(related[d["id"]]),
                "template_id": template_id,
                "query": fill_template(QUERY_TEMPLATES[source_type][template_id], d["fields"]),
                "fields": d["fields"],
                "eligible_pool_size": len(pool),
            })

    with open(CASES_PATH, "w", encoding="utf-8") as f:
        json.dump({
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "seed": manifest["seeds"]["case_sample"],
            "cases_per_source": CASES_PER_SOURCE,
            "eligibility": ELIGIBILITY,
            "query_templates": QUERY_TEMPLATES,
            "cases": cases,
        }, f, indent=2, ensure_ascii=False)

    # Report.
    print(f"\nKnowledge base: {len(docs)} real documents -> {KB_PATH}")
    for source in ["MITRE-ATT&CK-Enterprise", "MITRE-ATT&CK-ICS", "CISA-CSAF", "CVE-List-V5"]:
        print(f"  {source:<26} {sum(d['source'] == source for d in docs)}")
    print(f"\nTest cases: {len(cases)} -> {CASES_PATH}")
    for c in cases:
        print(f"  {c['case_id']:<10} {c['target_doc_id']:<24} {c['query']}")


if __name__ == "__main__":
    main()
