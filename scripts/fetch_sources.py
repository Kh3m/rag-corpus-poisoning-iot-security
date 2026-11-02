
import subprocess
from datetime import datetime, timezone
import json
import os
import argparse
import urllib.request
import urllib.error
import hashlib
import time
from concurrent.futures import ThreadPoolExecutor

SOURCES = {
    # MITRE ATT&CK (STIX 2.1)
    "attack": {"repo": "https://github.com/mitre-attack/attack-stix-data", "branch": "refs/heads/master"},
    # CISA CSAF advisories 
    "csaf":   {"repo": "https://github.com/cisagov/CSAF", "branch": "refs/heads/develop"},
    # CVE List V5
    "cve":    {"repo": "https://github.com/CVEProject/cvelistV5", "branch": "refs/heads/main"},
}
ATTACK_VERSION = "20.0"
ATTACK_DOMAINS = ["enterprise-attack", "ics-attack"] 
ATTACK_TERMS_ACCESSED = "2026-11-01"
ATTACK_TERMS_URL = "https://attack.mitre.org/resources/terms-of-use/"

CSAF_TERMS_URL = "https://www.cisa.gov/notification"
CSAF_TERMS_ACCESSED = "2026-11-01"
CSAF_DIR = "csaf_files/OT/white"

CVE_TERMS_URL = "https://www.cve.org/Legal/TermsOfUse"
CVE_TERMS_ACCESSED = "2026-11-02"

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  
DATA_DIR = os.path.join(ROOT, "data")
MANIFEST_PATH = os.path.join(DATA_DIR, "manifest.json")


def resolve_commit(repo: str, branch: str) -> str:
    try:
        # Run a terminal command from Python
        result = subprocess.run(
            ["git", "ls-remote", repo, branch], 
            capture_output=True,
            text=True,
            check=True
        )    
    
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"git ls-remote failed for {repo} {branch}: {e.stderr}") from e

    if not result.stdout:
        raise RuntimeError(f"No branch found for: {repo} {branch}")

    return result.stdout.split("\t")[0]

    
def pin_manifest(refresh: bool=False):
    
    os.makedirs(DATA_DIR, exist_ok=True)

    if os.path.exists(MANIFEST_PATH) and not refresh:
        print(f"reusing pinned commits from {MANIFEST_PATH}")

        with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
            manifest = json.load(f)

    else:
        manifest = {
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "sources": {}
        }

        for name, source in SOURCES.items():
            repo = source["repo"]
            branch = source["branch"]
            commit = resolve_commit(repo, branch)

            manifest["sources"][name] = {
                "repo": repo,
                "branch": branch,
                "commit": commit
            }
        
        write_manifest(manifest)

    return manifest


def write_manifest(manifest: dict, path: str=MANIFEST_PATH):
    """Save the manifest to a JSON file."""
    text = json.dumps(manifest, indent=2)
    
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def raw_url(repo: str, commit: str, path: str) -> str:
    prefix = "https://github.com/"

    if not repo.startswith(prefix):
        raise ValueError(f"Not a GitHub repo URL: {repo}")

    owner_repo = repo.removeprefix(prefix)
    return f"https://raw.githubusercontent.com/{owner_repo}/{commit}/{path}"


def download_file(url: str, dest: str, 
    expected_sha256: str | None=None, 
    quiet: bool=False) -> str:
    """Download url to dest safely and return its SHA-256."""

    if os.path.exists(dest):
        with open(dest, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()

        if expected_sha256 is None or expected_sha256 == file_hash:
            return file_hash
        else:
            print(f"hash mismatch for {dest}, downloading again")
            
    os.makedirs(os.path.dirname(dest), exist_ok=True)

    with urllib.request.urlopen(url, timeout=60) as response, open(dest + ".part", "wb") as f:
        total_bytes = int(response.headers.get("Content-Length"))
        done_bytes = 0
        ch = hashlib.sha256()

        while True: 
            chunk = response.read(1024 * 1024) # Reads 1MB at a time
            if not chunk:
                break
            
            f.write(chunk)
            ch.update(chunk)
            done_bytes += len(chunk)

            if not quiet:
                print(f"\r{done_bytes:,} / {total_bytes:,} Bytes", end="", flush=True)
            
        if done_bytes != total_bytes: 
            raise RuntimeError(f"Incomplete download of {url}: got {done_bytes} of {total_bytes} bytes")
    
    if not quiet:        
        print("\nDownload Done")

    content_hash = ch.hexdigest()

    if expected_sha256 is not None and content_hash != expected_sha256:
        raise RuntimeError(f"Hash mismatch for {url}: expected {expected_sha256}, got {content_hash}")
    
    os.replace(f"{dest}.part", dest)

    return content_hash


def download_with_retry(url: str, dest: str, quiet: bool=False, tries: int=3) -> str:
    for attempt in range(1, tries + 1):
        try:
            return download_file(url, dest, quiet=quiet)
        except Exception as e:
            if isinstance(e, urllib.error.HTTPError) and e.code == 404:
                raise
            if attempt == tries:
                raise
            wait = 2 ** attempt
            print(f"retry {attempt}/{tries - 1} for {url} in {wait}s: {e}")
            time.sleep(wait)


def fetch_attack(manifest: dict):
    attack = manifest["sources"]["attack"]
    attack["version"] = ATTACK_VERSION
    attack["terms_of_use"] = ATTACK_TERMS_URL
    attack["terms_accessed"] = ATTACK_TERMS_ACCESSED
    files = attack.setdefault("files", {})

    repo_paths = []

    for domain in ATTACK_DOMAINS:
        repo_paths.append(f"{domain}/{domain}-{ATTACK_VERSION}.json")
    repo_paths.append("LICENSE.txt")

    for repo_path in repo_paths:
        filename = os.path.basename(repo_path)
        url = raw_url(attack["repo"], attack["commit"], repo_path)
        dest = os.path.join(DATA_DIR, "raw", "attack", filename)
        expected = files.get(repo_path, {}).get("sha256")
        file_hash = download_file(url, dest, expected)
        files[repo_path] = {"sha256": file_hash, "bytes": os.path.getsize(dest)}
        
        print(f"{dest}  {file_hash}")


def fetch_csaf_index(manifest: dict) -> list[str]:
    csaf = manifest["sources"]["csaf"]
    csaf["terms_of_use"] = CSAF_TERMS_URL
    csaf["terms_accessed"] = CSAF_TERMS_ACCESSED
    files = csaf.setdefault("files", {})
    repo_path = f"{CSAF_DIR}/index.txt"
    url = raw_url(csaf["repo"], csaf["commit"], repo_path)
    filename = os.path.basename(repo_path)
    dest = os.path.join(DATA_DIR, "raw", "csaf", filename)
    expected = files.get(repo_path, {}).get("sha256")
    file_hash = download_file(url, dest, expected)
    files[repo_path] = {"sha256": file_hash, "bytes": os.path.getsize(dest)}

    print(f"{dest}  {file_hash}")

    with open(dest, encoding="utf-8") as f:
        paths = [line.strip() for line in f if line]

    return paths


def fetch_csaf_advisory(csaf: dict, path: str) -> dict:
    hashes = {}
    for ext in ["", ".sha512", ".asc"]:
        repo_path = f"{CSAF_DIR}/{path}{ext}"
        url = raw_url(csaf["repo"], csaf["commit"], repo_path)
        dest = os.path.join(DATA_DIR, "raw", "csaf", path+ext)
        hashes[repo_path] = download_with_retry(url, dest, quiet=True)

    sha_file = os.path.join(DATA_DIR, "raw", "csaf", path + ".sha512")
    with open(sha_file, encoding="utf-8") as f:
        line = f.read()

    expected_hash, expected_name = line.split()

    json_file = os.path.join(DATA_DIR, "raw", "csaf", path)
    with open(json_file, "rb") as f:
        our_hash = hashlib.sha512(f.read()).hexdigest()

    if our_hash != expected_hash:
        raise RuntimeError(f"SHA-512 mismatch for {path}")

    if expected_name != os.path.basename(path):
        raise RuntimeError(f"{sha_file} is for {expected_name}, not {path}")

    return hashes

def write_hash_list(hashes: dict, dest: str) -> str:
    with open(dest, "w", encoding="utf-8", newline="\n") as f:
        for repo_path, sha256 in sorted(hashes.items()):
            f.write(f"{sha256}  {repo_path}\n")

    with open(dest, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def csaf_cve_ids(paths: list[str]) -> list[str]:
    ids = set()
    for path in paths:
        with open(os.path.join(DATA_DIR, "raw", "csaf", path), encoding="utf-8") as f:
            doc = json.load(f)
        for vuln in doc.get("vulnerabilities", []):
            if "cve" in vuln:
                ids.add(vuln["cve"])
    return sorted(ids)

def cve_repo_path(cve_id: str) -> str:
    _, year, number = cve_id.split("-")
    folder = f"{int(number) // 1000}xxx"
    return f"cves/{year}/{folder}/{cve_id}.json"


def fetch_cve_record(cve: dict, cve_id: str) -> dict:
    repo_path = cve_repo_path(cve_id)
    url = raw_url(cve["repo"], cve["commit"], repo_path)
    dest = os.path.join(DATA_DIR, "raw", "cve", repo_path)
    return {repo_path: download_with_retry(url, dest, quiet=True)}


def main():
    parser = argparse.ArgumentParser(description="Pin the source repositories to exact commits and download the data.")
    parser.add_argument(
        "--refresh", 
        action="store_true", 
        help="Re-pin to the latest commits. Overwrites data/manifest.json."
    )
    args = parser.parse_args()
    manifest = pin_manifest(args.refresh)

    fetch_attack(manifest)
    csaf_index_paths = fetch_csaf_index(manifest)

    # Update csaf advisory
    csaf = manifest["sources"]["csaf"]
    hashes = {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = pool.map(lambda path: fetch_csaf_advisory(csaf, path), csaf_index_paths)
        for i, result in enumerate(results, start=1):
            hashes.update(result)
            if i % 100 == 0 or i == len(csaf_index_paths):
                print(f"csaf {i}/{len(csaf_index_paths)}")

    list_path = os.path.join(DATA_DIR, "csaf_files.sha256")
    list_hash = write_hash_list(hashes, list_path)
    manifest["sources"]["csaf"]["hash_list"] = {
        "path": "data/csaf_files.sha256",
        "sha256": list_hash,
        "bytes": os.path.getsize(list_path),
    }                                           

    print(len(csaf_index_paths), csaf_index_paths[0], csaf_index_paths[-1])
    write_manifest(manifest)

    # Display the manifest sources
    for name, source in manifest["sources"].items():
        print(f"{name:<7}  {source['commit']}")


if __name__ == "__main__":
    # run this only when the file is executed directly
    # not when another file imports it.
    main()