"""
fetch_sources.py

Step 1 of the scaled evaluation: download the REAL clean documents that
make up the knowledge base, pinned to exact commits, and write a manifest
recording exactly what was downloaded.

Three public sources:
    1. MITRE ATT&CK Enterprise + ICS (STIX 2.1), version 19.2,
       from github.com/mitre-attack/attack-stix-data
    2. CISA CSAF advisories (OT, TLP:WHITE), from github.com/cisagov/CSAF.
       We read csaf_files/OT/white/index.txt, keep the 2023-2026 entries,
       and sample 300 of them with a fixed seed.
    3. CVE records (CVE JSON 5) from github.com/CVEProject/cvelistV5,
       for every CVE ID listed in the 300 sampled advisories.

Pinning:
    Each repo's branch is resolved to a commit SHA once, with
    `git ls-remote` (plain git protocol, not the GitHub API). Every file
    is then fetched from raw.githubusercontent.com AT THAT COMMIT, so a
    re-run downloads byte-identical files even if the repos have moved on.
    If data/manifest.json already exists, its commits are reused; pass
    --refresh to resolve new commits (this creates a different dataset).

Outputs:
    data/raw/<source>/...   the downloaded files (cached; not committed)
    data/manifest.json      versions, commits, URLs, SHA-256 of every file,
                            retrieval date, seeds, selected IDs

This script only downloads and records. It does not build the knowledge
base or run any evaluation; that is scripts/build_dataset.py.

Run with:
    uv run python scripts/fetch_sources.py
"""

import argparse
import hashlib
import json
import os
import random
import subprocess
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

ROOT = os.path.join(os.path.dirname(__file__), "..")
RAW_DIR = os.path.join(ROOT, "data", "raw")
MANIFEST_PATH = os.path.join(ROOT, "data", "manifest.json")

# Fixed seeds, recorded in the manifest. SEED_CASES is used later by
# build_dataset.py; it is stored here so every seed lives in one place.
SEED_ADVISORIES = 20231
SEED_CASES = 20232
SEED_FORGED_SIGNATURE = 0

ATTACK_VERSION = "19.2"
CSAF_SAMPLE_SIZE = 300
CSAF_YEARS = {"2023", "2024", "2025", "2026"}

REPOS = {
    "attack": {"repo": "mitre-attack/attack-stix-data", "branch": "master"},
    "csaf": {"repo": "cisagov/CSAF", "branch": "develop"},
    "cve": {"repo": "CVEProject/cvelistV5", "branch": "main"},
}

# Common license file names; each repo is checked for these in order.
LICENSE_CANDIDATES = ["LICENSE", "LICENSE.txt", "LICENSE.md"]


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def resolve_commit(repo, branch):
    """Return the commit SHA a branch points to, via `git ls-remote`."""
    out = subprocess.run(
        ["git", "ls-remote", f"https://github.com/{repo}", f"refs/heads/{branch}"],
        capture_output=True, text=True, check=True,
    ).stdout.split()
    if not out:
        raise RuntimeError(f"Could not resolve {repo}@{branch}")
    return out[0]


def raw_url(repo, commit, path):
    return f"https://raw.githubusercontent.com/{repo}/{commit}/{path}"


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def http_get(url, retries=3):
    """
    Download a URL and return its bytes, or None if the server says 404.
    Other errors are retried a few times, then raised (we never silently
    skip a file because of a flaky connection).
    """
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(url, timeout=60) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if attempt == retries - 1:
                raise
        except urllib.error.URLError:
            if attempt == retries - 1:
                raise
        time.sleep(2 ** attempt)


def fetch_file(source, repo, commit, path):
    """
    Fetch one file at a pinned commit, caching it under data/raw/<source>/.
    Returns a manifest entry dict, or None if the file does not exist (404).
    """
    local_path = os.path.join(RAW_DIR, source, path)
    if os.path.exists(local_path):
        with open(local_path, "rb") as f:
            data = f.read()
    else:
        data = http_get(raw_url(repo, commit, path))
        if data is None:
            return None
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        with open(local_path, "wb") as f:
            f.write(data)
    return {
        "path": path,
        "raw_url": raw_url(repo, commit, path),
        "sha256": sha256_bytes(data),
        "bytes": len(data),
    }


def fetch_license(source, repo, commit):
    """Record the repo's license file (first candidate name that exists)."""
    for name in LICENSE_CANDIDATES:
        entry = fetch_file(source, repo, commit, name)
        if entry is not None:
            return entry
    return {"path": None, "note": f"none of {LICENSE_CANDIDATES} found at this commit"}


def cve_path(cve_id):
    """
    cvelistV5 layout: cves/<year>/<number // 1000>xxx/<CVE-ID>.json
    e.g. CVE-2024-3400 -> cves/2024/3xxx/CVE-2024-3400.json
    """
    _, year, number = cve_id.split("-")
    return f"cves/{year}/{int(number) // 1000}xxx/{cve_id}.json"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--refresh", action="store_true",
                        help="resolve new commits instead of reusing the manifest's")
    args = parser.parse_args()

    # 1. Resolve (or reuse) the pinned commit of each repo.
    old_manifest = None
    if os.path.exists(MANIFEST_PATH) and not args.refresh:
        with open(MANIFEST_PATH, encoding="utf-8") as f:
            old_manifest = json.load(f)
    commits = {}
    for source, info in REPOS.items():
        if old_manifest:
            commits[source] = old_manifest["sources"][source]["commit"]
        else:
            commits[source] = resolve_commit(info["repo"], info["branch"])
        print(f"[pin] {info['repo']}@{info['branch']} -> {commits[source]}")

    # 2. MITRE ATT&CK: the two pinned-version STIX bundles.
    repo, commit = REPOS["attack"]["repo"], commits["attack"]
    attack_files = []
    for domain in ["enterprise-attack", "ics-attack"]:
        path = f"{domain}/{domain}-{ATTACK_VERSION}.json"
        print(f"[attack] fetching {path}")
        entry = fetch_file("attack", repo, commit, path)
        if entry is None:
            sys.exit(f"ATT&CK file not found at pinned commit: {path}")
        attack_files.append(entry)

    # 3. CISA CSAF: read the index, keep 2023-2026, sample 300 with a fixed seed.
    repo, commit = REPOS["csaf"]["repo"], commits["csaf"]
    index_path = "csaf_files/OT/white/index.txt"
    index_entry = fetch_file("csaf", repo, commit, index_path)
    with open(os.path.join(RAW_DIR, "csaf", index_path), encoding="utf-8") as f:
        index_lines = [line.strip() for line in f if line.strip()]
    in_range = sorted(l for l in index_lines if l.split("/")[0] in CSAF_YEARS)
    index_entry["lines_total"] = len(index_lines)
    index_entry["lines_2023_2026"] = len(in_range)

    # Sorting first makes the sample independent of index.txt's line order.
    selected = sorted(random.Random(SEED_ADVISORIES).sample(in_range, CSAF_SAMPLE_SIZE))
    print(f"[csaf] index has {len(index_lines)} lines, {len(in_range)} from 2023-2026; "
          f"sampled {len(selected)}")

    advisory_paths = [f"csaf_files/OT/white/{line}" for line in selected]
    with ThreadPoolExecutor(max_workers=8) as pool:  # parallel downloads, same results
        advisory_entries = list(pool.map(
            lambda p: fetch_file("csaf", repo, commit, p), advisory_paths))

    csaf_selected = []
    cve_ids = set()
    for line, entry in zip(selected, advisory_entries):
        if entry is None:
            sys.exit(f"Advisory listed in index.txt but missing: {line}")
        with open(os.path.join(RAW_DIR, "csaf", entry["path"]), encoding="utf-8") as f:
            advisory = json.load(f)
        cisa_url = next(
            (r["url"] for r in advisory["document"].get("references", [])
             if "cisa.gov" in r.get("url", "") and r.get("category") == "self"),
            None,
        )
        advisory_cves = sorted({v["cve"] for v in advisory.get("vulnerabilities", []) if v.get("cve")})
        cve_ids.update(advisory_cves)
        csaf_selected.append({
            "advisory_id": advisory["document"]["tracking"]["id"],
            "cisa_url": cisa_url,
            "cve_ids": advisory_cves,
            **entry,
        })

    # 4. CVE records for every CVE ID in the sampled advisories.
    repo, commit = REPOS["cve"]["repo"], commits["cve"]
    cve_ids = sorted(cve_ids)
    print(f"[cve] fetching {len(cve_ids)} CVE records")
    with ThreadPoolExecutor(max_workers=8) as pool:
        cve_entries = list(pool.map(
            lambda c: fetch_file("cve", repo, commit, cve_path(c)), cve_ids))

    cve_fetched, cve_missing, cve_not_published = [], [], []
    for cve_id, entry in zip(cve_ids, cve_entries):
        if entry is None:
            cve_missing.append(cve_id)
            continue
        with open(os.path.join(RAW_DIR, "cve", entry["path"]), encoding="utf-8") as f:
            state = json.load(f)["cveMetadata"]["state"]
        if state != "PUBLISHED":
            cve_not_published.append({"cve_id": cve_id, "state": state})
            continue
        cve_fetched.append({
            "cve_id": cve_id,
            "cve_org_url": f"https://www.cve.org/CVERecord?id={cve_id}",
            **entry,
        })

    # 5. Write the manifest.
    manifest = {
        "manifest_version": 1,
        "retrieved_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "seeds": {
            "advisory_sample": SEED_ADVISORIES,
            "case_sample": SEED_CASES,
            "forged_signature": SEED_FORGED_SIGNATURE,
        },
        "sources": {
            "attack": {
                "repo": f"https://github.com/{REPOS['attack']['repo']}",
                "branch": REPOS["attack"]["branch"],
                "commit": commits["attack"],
                "attack_version": ATTACK_VERSION,
                "terms_of_use": "https://attack.mitre.org/resources/legal-and-branding/terms-of-use/",
                "license_file": fetch_license("attack", REPOS["attack"]["repo"], commits["attack"]),
                "files": attack_files,
            },
            "csaf": {
                "repo": f"https://github.com/{REPOS['csaf']['repo']}",
                "branch": REPOS["csaf"]["branch"],
                "commit": commits["csaf"],
                "license_file": fetch_license("csaf", REPOS["csaf"]["repo"], commits["csaf"]),
                "index": index_entry,
                "years": sorted(CSAF_YEARS),
                "sample_size": CSAF_SAMPLE_SIZE,
                "selected": csaf_selected,
            },
            "cve": {
                "repo": f"https://github.com/{REPOS['cve']['repo']}",
                "branch": REPOS["cve"]["branch"],
                "commit": commits["cve"],
                "terms_of_use": "https://www.cve.org/Legal/TermsOfUse",
                "license_file": fetch_license("cve", REPOS["cve"]["repo"], commits["cve"]),
                "requested_ids": len(cve_ids),
                "fetched": cve_fetched,
                "missing_404": cve_missing,
                "not_published": cve_not_published,
            },
        },
    }
    # Keep the original retrieval date when reusing pinned commits, so the
    # manifest describes when this exact dataset was first downloaded.
    if old_manifest:
        manifest["retrieved_at_utc"] = old_manifest["retrieved_at_utc"]

    os.makedirs(os.path.dirname(MANIFEST_PATH), exist_ok=True)
    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    # 6. Print the full manifest, then stop. Nothing else runs from here.
    print("\n" + "=" * 70)
    print(f"MANIFEST ({MANIFEST_PATH})")
    print("=" * 70)
    print(json.dumps(manifest, indent=2))
    print("=" * 70)
    print(f"ATT&CK files: {len(attack_files)} | CSAF advisories: {len(csaf_selected)} | "
          f"CVE records: {len(cve_fetched)} fetched, {len(cve_missing)} missing (404), "
          f"{len(cve_not_published)} not PUBLISHED")


if __name__ == "__main__":
    main()
