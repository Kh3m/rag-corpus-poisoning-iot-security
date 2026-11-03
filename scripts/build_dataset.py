"""Build the knowledge base and test cases from the pinned raw files.

Offline and deterministic. Checks every raw file against data/manifest.json
and its hash lists first, then writes:
    data/knowledge_base.jsonl  one document per line (never commit: Siemens terms)
    data/test_cases.json       100 test cases per source type
"""

import hashlib
import json
import os
import random
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(ROOT, "data")
RAW_DIR = os.path.join(DATA_DIR, "raw")
MANIFEST_PATH = os.path.join(DATA_DIR, "manifest.json")
KB_PATH = os.path.join(DATA_DIR, "knowledge_base.jsonl")
CASES_PATH = os.path.join(DATA_DIR, "test_cases.json")
CSAF_DIR = "csaf_files/OT/white"
CASES_PER_SOURCE = 100
SEED = 20261103


# Three fixed query templates per source type. Test case i uses template i % 3.
QUERY_TEMPLATES = {
    "attack": [
        "How do I mitigate the {name} technique ({attack_id})?",
        "What mitigations does MITRE ATT&CK list for {attack_id} {name}?",
        "How can I defend against {name} ({attack_id})?",
    ],
    "csaf": [
        "What remediation does CISA recommend for {cve_id} in {vendor} {product}?",
        "How should I fix {cve_id} in {vendor} {product} from advisory {advisory_id}?",
        "How severe is {cve_id} in {vendor} {product}, and is there a patch?",
    ],
    "cve": [
        "How should I fix {cve_id} affecting {vendor} {product}?",
        "What is {cve_id} in {vendor} {product} and how do I remediate it?",
        "How severe is {cve_id} in {vendor} {product}, and should I patch now?",
    ],
}

# ---------------------------------------------------------------------------
# Files and hashes
# ---------------------------------------------------------------------------

def local_path(source: str, repo_path: str) -> str:
    """Return where fetch_sources.py saved the file for this repo path."""
    if source == "attack":
        return os.path.join(RAW_DIR, "attack", os.path.basename(repo_path))
    if source == "csaf":
        return os.path.join(RAW_DIR, "csaf", repo_path.removeprefix(CSAF_DIR + "/"))
    return os.path.join(RAW_DIR, "cve", repo_path)


def raw_github_url(repo: str, commit: str, path: str) -> str:
    """Return the raw.githubusercontent.com URL of a file in a repo at a fixed commit."""
    return f"https://raw.githubusercontent.com/{repo.removeprefix('https://github.com/')}/{commit}/{path}"


def sha256_file(path: str) -> str:
    """Return the SHA-256 of a file on disk."""
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def hash_list_paths(manifest: dict, source: str) -> list[str]:
    """Return the repo paths listed in a source's hash list, in file order (sorted)."""
    with open(os.path.join(ROOT, manifest["sources"][source]["hash_list"]["path"]), encoding="utf-8") as f:
        return [line.split()[1] for line in f if line.strip()]
    

def verify_sources(manifest: dict):
    """Stop if any raw file differs from what the manifest and hash lists recorded."""
    sources = manifest["sources"]
    checked = 0

    for repo_path, entry in sources["attack"]["files"].items():
        if sha256_file(local_path("attack", repo_path)) != entry["sha256"]:
            sys.exit(f"SHA-256 mismatch: attack {repo_path}")
        checked += 1

    for source in ["csaf", "cve"]:
        hash_list = sources[source]["hash_list"]
        list_path = os.path.join(ROOT, hash_list["path"])
        if sha256_file(list_path) != hash_list["sha256"]:
            sys.exit(f"SHA-256 mismatch: {hash_list['path']}")
        with open(list_path, encoding="utf-8") as f:
            for line in f:
                sha256, repo_path = line.split()
                if sha256_file(local_path(source, repo_path)) != sha256:
                    sys.exit(f"SHA-256 mismatch: {source} {repo_path}")
                checked += 1

    print(f"[verify] {checked} files match the manifest")


# ---------------------------------------------------------------------------
# Text helpers
# ---------------------------------------------------------------------------

def clean(text: str) -> str:
    """Remove ATT&CK '(Citation: ...)' markers and collapse whitespace."""
    text = re.sub(r"\(Citation: [^)]*\)", "", text)
    return re.sub(r"\s+", " ", text).strip()


def is_real(value: str) -> bool:
    """False for empty or placeholder values like 'n/a'."""
    return bool(value) and value.strip().lower() not in {"n/a", "unknown", "-", "*"}


def sentences(*parts: str) -> str:
    """Join the non-empty parts, each ending with exactly one full stop."""
    return " ".join(p.strip().rstrip(".") + "." for p in parts if p and p.strip())


def unique(items: list) -> list:
    """Remove duplicates, keep the first-seen order."""
    return list(dict.fromkeys(items))


def short_product(vendor: str, product: str) -> str:
    """'Siemens SIMATIC S7' -> 'SIMATIC S7' when the vendor is Siemens."""
    if vendor and product.lower().startswith(vendor.lower() + " "):
        return product[len(vendor) + 1:]
    return product


# ---------------------------------------------------------------------------
# ATT&CK: one document per active technique that has a mitigation
# ---------------------------------------------------------------------------

def is_active(obj: dict) -> bool:
    """False for ATT&CK objects MITRE has revoked or deprecated."""
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def attack_mitigations(objects: list[dict]) -> dict:
    """Return {technique STIX id: [(mitigation object, relationship object), ...]}."""
    by_id = {obj["id"]: obj for obj in objects}
    mitigations = {}
    for rel in objects:
        if rel["type"] != "relationship" or rel["relationship_type"] != "mitigates":
            continue
        if not is_active(rel):
            continue
        coa = by_id.get(rel["source_ref"])
        if coa and coa["type"] == "course-of-action" and is_active(coa):
            mitigations.setdefault(rel["target_ref"], []).append((coa, rel))
    return mitigations


def build_attack_docs(manifest: dict) -> list[dict]:
    docs = []
    for repo_path in sorted(manifest["sources"]["attack"]["files"]):
        if not repo_path.endswith(".json"):
            continue  # LICENSE.txt
        domain = "Enterprise" if repo_path.startswith("enterprise") else "ICS"
        with open(local_path("attack", repo_path), encoding="utf-8") as f:
            objects = json.load(f)["objects"]
        mitigations = attack_mitigations(objects)

        for tech in objects:
            if tech["type"] != "attack-pattern" or not is_active(tech) or tech["id"] not in mitigations:
                continue
            ref = next(r for r in tech["external_references"] if r.get("source_name") == "mitre-attack")
            attack_id = ref["external_id"]
            pairs = sorted(mitigations[tech["id"]], key=lambda pair: pair[0]["name"])
            mitigation_text = " ".join(
                f"Mitigation {coa['name']}: {rel.get('description') or coa.get('description', '')}"
                for coa, rel in pairs
            )
            docs.append({
                "id": f"attack:{attack_id}",
                "source": f"MITRE-ATT&CK-{domain}",
                "source_type": "attack",
                "title": f"{attack_id}: {tech['name']}",
                "text": clean(f"{attack_id} {tech['name']}. {tech.get('description', '')} {mitigation_text}"),
                "source_url": ref["url"],
                "fields": {"attack_id": attack_id, "name": tech["name"],
                           "mitigations": [coa["name"] for coa, _ in pairs]},
            })
    return docs


# ---------------------------------------------------------------------------
# CSAF: one document per (advisory, vulnerability)
# ---------------------------------------------------------------------------

def csaf_products(branches: list, found: dict, vendor: str = "", product: str = "") -> dict:
    """Fill found with {product_id: (vendor, product name, version)} from a CSAF product tree."""
    for branch in branches:
        category, name = branch.get("category"), branch.get("name", "")
        v = name if category == "vendor" else vendor
        p = name if category == "product_name" else product
        pid = branch.get("product", {}).get("product_id")
        if pid:
            found[pid] = (v, p or name, name)
        csaf_products(branch.get("branches", []), found, v, p)
    return found


def build_csaf_docs(manifest: dict) -> list[dict]:
    csaf = manifest["sources"]["csaf"]
    docs = []
    for repo_path in hash_list_paths(manifest, "csaf"):
        if not repo_path.endswith(".json"):
            continue  # .json.sha512 and .json.asc
        with open(local_path("csaf", repo_path), encoding="utf-8") as f:
            adv = json.load(f)
        document = adv["document"]
        advisory_id = document["tracking"]["id"]
        products = csaf_products(adv.get("product_tree", {}).get("branches", []), {})
        url = raw_github_url(csaf["repo"], csaf["commit"], repo_path)

        for vuln in adv.get("vulnerabilities", []):
            cve_id = vuln["cve"]
            affected = [products[pid] for pid in vuln.get("product_status", {}).get("known_affected", [])
                        if pid in products]
            vendors = unique([v for v, _, _ in affected if v])
            names = unique([p if ver == p else f"{p} {ver}" for _, p, ver in affected])
            summary = " ".join(n["text"] for n in vuln.get("notes", []) if n.get("category") == "summary")
            remediations = unique([
                f"{r['category'].replace('_', ' ').capitalize()}: {r['details']}"
                for r in vuln.get("remediations", []) if r.get("details")
            ])
            scores = sorted({s["cvss_v3"]["baseScore"] for s in vuln.get("scores", []) if "cvss_v3" in s})
            vuln_title = vuln.get("title", "")
            if vuln_title == cve_id:
                vuln_title = ""  # CISA often repeats the CVE ID as the title

            text = sentences(
                f"{document['title']} ({advisory_id})",
                f"{cve_id}: {vuln_title}" if vuln_title else cve_id,
                f"Vendor: {', '.join(vendors)}" if vendors else "",
                f"Affected products: {'; '.join(names)}" if names else "",
                summary,
                f"CVSS v3 base score: {', '.join(str(x) for x in scores)}" if scores else "",
                "Remediation: " + " ".join(sentences(r) for r in remediations) if remediations else "",
            )

            vendor = vendors[0] if vendors else ""
            product = short_product(vendor, affected[0][1]) if affected else ""
            docs.append({
                "id": f"csaf:{advisory_id}:{cve_id}",
                "source": "CISA-CSAF",
                "source_type": "csaf",
                "title": f"{document['title']} ({advisory_id}): {cve_id}",
                "text": clean(text),
                "source_url": url,
                "fields": {"advisory_id": advisory_id, "cve_id": cve_id, "vendor": vendor,
                           "product": product, "cvss_v3": scores,
                           "remediation_types": unique([r["category"] for r in vuln.get("remediations", [])])},
            })
    return docs


# ---------------------------------------------------------------------------
# CVE: one document per PUBLISHED record
# ---------------------------------------------------------------------------

def version_text(entry: dict) -> str:
    """Turn one CVE 'versions' entry into words, e.g. 'before V5.40'."""
    start = entry.get("version", "")
    for key, word in [("lessThan", "before"), ("lessThanOrEqual", "up to")]:
        if entry.get(key):
            if is_real(start) and start != "0":
                return f"{start} {word} {entry[key]}"
            return f"{word} {entry[key]}"
    return start


def build_cve_docs(manifest: dict) -> list[dict]:
    cve = manifest["sources"]["cve"]
    docs = []
    for repo_path in hash_list_paths(manifest, "cve"):
        with open(local_path("cve", repo_path), encoding="utf-8") as f:
            record = json.load(f)
        meta = record["cveMetadata"]
        if meta.get("state") != "PUBLISHED":
            continue  # REJECTED records have no real content
        cna = record["containers"]["cna"]
        cve_id = meta["cveId"]

        description = next((d["value"] for d in cna.get("descriptions", [])
                            if d.get("lang", "").startswith("en")), "")
        affected_parts, real_pairs = [], []
        for a in cna.get("affected", []):
            vendor, product = a.get("vendor", ""), a.get("product", "")
            versions = unique([version_text(v) for v in a.get("versions", [])
                               if v.get("status") == "affected" and is_real(version_text(v))])
            part = f"{vendor} {product}".strip()
            if versions:
                part += f" ({', '.join(versions)})"
            affected_parts.append(part)
            if is_real(vendor) and is_real(product):
                real_pairs.append((vendor, product))
        scores = sorted({m[k]["baseScore"] for m in cna.get("metrics", [])
                         for k in ("cvssV3_1", "cvssV3_0") if k in m})
        solutions = " ".join(s["value"] for s in cna.get("solutions", []) if s.get("lang", "").startswith("en"))
        title = cna.get("title", "")

        text = sentences(
            f"{cve_id}: {title}" if title else cve_id,
            description,
            f"Affected: {'; '.join(affected_parts)}" if affected_parts else "",
            f"CVSS v3 base score: {', '.join(str(x) for x in scores)}" if scores else "",
            solutions,
        )

        vendor, product = real_pairs[0] if real_pairs else ("", "")
        docs.append({
            "id": f"cve:{cve_id}",
            "source": "CVE-List-V5",
            "source_type": "cve",
            "title": f"{cve_id}: {title}" if title else cve_id,
            "text": clean(text),
            "source_url": raw_github_url(cve["repo"], cve["commit"], repo_path),
            "fields": {"cve_id": cve_id, "cna": meta["assignerShortName"], "vendor": vendor,
                       "product": short_product(vendor, product), "cvss_v3": scores},
        })
    return docs


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

def is_eligible(doc: dict) -> bool:
    """Can this document fill its source's query templates?"""
    fields = doc["fields"]
    if doc["source_type"] == "attack":
        return True
    has_names = is_real(fields["vendor"]) and is_real(fields["product"])
    if doc["source_type"] == "csaf":
        return has_names and bool(fields["remediation_types"])
    return has_names


def fill_template(template: str, fields: dict) -> str:
    """Fill a query template; write the name once when vendor and product are the same (Linux Linux)."""
    fields = dict(fields)
    if fields.get("vendor", "").lower() == fields.get("product", "").lower():
        fields["product"] = ""
    query = re.sub(r"\s+", " ", template.format(**fields))
    return query.replace(" ?", "?").replace(" ,", ",")


def build_test_cases(docs: list[dict]) -> list[dict]:
    by_cve = {}
    for doc in docs:
        if doc["fields"].get("cve_id"):
            by_cve.setdefault(doc["fields"]["cve_id"], []).append(doc["id"])

    rng = random.Random(SEED)
    cases = []
    for source in ["attack", "csaf", "cve"]:
        eligible = [d for d in docs if d["source_type"] == source and is_eligible(d)]
        print(f"[cases] {source}: {len(eligible)} eligible documents")
        for i, doc in enumerate(rng.sample(eligible, CASES_PER_SOURCE)):
            cve_id = doc["fields"].get("cve_id")
            cases.append({
                "case_id": f"{source}-{i:03d}",
                "source_type": source,
                "template": i % 3,
                "query": fill_template(QUERY_TEMPLATES[source][i % 3], doc["fields"]),
                "correct_doc_id": doc["id"],
                # docs about the same CVE from the other source, for the "lenient" accuracy
                "related_doc_ids": [x for x in by_cve.get(cve_id, []) if x != doc["id"]],
            })
    return cases


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    with open(MANIFEST_PATH, encoding="utf-8") as f:
        manifest = json.load(f)
    verify_sources(manifest)

    docs = build_attack_docs(manifest) + build_csaf_docs(manifest) + build_cve_docs(manifest)
    ids = [d["id"] for d in docs]
    if len(ids) != len(set(ids)):
        sys.exit("Duplicate document IDs")
    docs.sort(key=lambda d: d["id"])
    for source in ["attack", "csaf", "cve"]:
        print(f"[kb] {source}: {sum(d['source_type'] == source for d in docs)} documents")

    with open(KB_PATH, "w", encoding="utf-8", newline="\n") as f:
        for doc in docs:
            f.write(json.dumps(doc, ensure_ascii=False, sort_keys=True) + "\n")

    cases = build_test_cases(docs)
    with open(CASES_PATH, "w", encoding="utf-8", newline="\n") as f:
        json.dump(cases, f, ensure_ascii=False, indent=2)
        f.write("\n")

    print(f"[kb] {len(docs)} documents  sha256 {sha256_file(KB_PATH)}")
    print(f"[cases] {len(cases)} test cases  sha256 {sha256_file(CASES_PATH)}")


if __name__ == "__main__":
    main()