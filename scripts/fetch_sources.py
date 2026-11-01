
import subprocess
from datetime import datetime, timezone
import json
import os
import argparse
import urllib.request
import hashlib

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

def download_file(url: str, dest: str, expected_sha256: str | None=None) -> str:
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
            print(f"\r{done_bytes:,} / {total_bytes:,} Bytes", end="", flush=True)
            
        if done_bytes != total_bytes: 
            raise RuntimeError(f"Incomplete download of {url}: got {done_bytes} of {total_bytes} bytes")
            
    print("\nDownload Done")

    content_hash = ch.hexdigest()

    if expected_sha256 is not None and content_hash != expected_sha256:
        raise RuntimeError(f"Hash mismatch for {url}: expected {expected_sha256}, got {content_hash}")
    
    os.replace(f"{dest}.part", dest)

    return content_hash

def fetch_attack(manifest: dict):
    
    attack = manifest["sources"]["attack"]
    attack["version"] = ATTACK_VERSION
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
    write_manifest(manifest)

    # Display the manifest sources
    for name, source in manifest["sources"].items():
        print(f"{name:<7}  {source['commit']}")

if __name__ == "__main__":
    # run this only when the file is executed directly
    # not when another file imports it.
    main()