
import subprocess
from datetime import datetime, timezone
import json
import os
import argparse

SOURCES = {
    # MITRE ATT&CK (STIX 2.1)
    "attack": {"repo": "https://github.com/mitre-attack/attack-stix-data", "branch": "refs/heads/master"},
    # CISA CSAF advisories 
    "csaf":   {"repo": "https://github.com/cisagov/CSAF", "branch": "refs/heads/develop"},
    # CVE List V5
    "cve":    {"repo": "https://github.com/CVEProject/cvelistV5", "branch": "refs/heads/main"},
}

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  
DATA_DIR = os.path.join(ROOT, "data")

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

    
def pin_manifest(folder: str, refresh: bool=False):
    
    os.makedirs(folder, exist_ok=True)
    file_path = os.path.join(folder, "manifest.json")

    if os.path.exists(file_path) and not refresh:
        print(f"reusing pinned commits from {file_path}")

        with open(file_path, "r", encoding="utf-8") as f:
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
        
        text = json.dumps(manifest, indent=2)

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(text)

    return manifest

def main():
    parser = argparse.ArgumentParser(description="Pin the source repositories to exact commits and download the data.")
    parser.add_argument(
        "--refresh", 
        action="store_true", 
        help="Re-pin to the latest commits. Overwrites data/manifest.json."
    )
    args = parser.parse_args()

    manifest = pin_manifest(DATA_DIR, args.refresh)
    
    for name, source in manifest["sources"].items():
        print(f"{name:<7}  {source['commit']}")

if __name__ == "__main__":
    # run this only when the file is executed directly, not when another file imports it.
    main()