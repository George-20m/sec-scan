"""
fetch_node_types.py — downloads the real node-types.json for each
tree-sitter grammar this project depends on, from that grammar's own
source repo (not guessed, not from training data). Run this once, and
again any time a tree-sitter-* dependency version changes.
"""

import os
import urllib.request

OUT_DIR = os.path.join(os.path.dirname(__file__), "node_types")

# (output name, repo, path within repo). typescript and php each
# host multiple grammars in one repo, hence the different subpaths.
SOURCES = [
    ("python", "tree-sitter/tree-sitter-python", "src/node-types.json"),
    ("javascript", "tree-sitter/tree-sitter-javascript", "src/node-types.json"),
    ("typescript", "tree-sitter/tree-sitter-typescript", "typescript/src/node-types.json"),
    ("java", "tree-sitter/tree-sitter-java", "src/node-types.json"),
    ("go", "tree-sitter/tree-sitter-go", "src/node-types.json"),
    ("php", "tree-sitter/tree-sitter-php", "php/src/node-types.json"),
    ("c-sharp", "tree-sitter/tree-sitter-c-sharp", "src/node-types.json"),
    ("ruby", "tree-sitter/tree-sitter-ruby", "src/node-types.json"),
]


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    for name, repo, path in SOURCES:
        out_path = os.path.join(OUT_DIR, f"{name}.json")
        ok = False
        for branch in ("master", "main"):
            url = f"https://raw.githubusercontent.com/{repo}/{branch}/{path}"
            try:
                with urllib.request.urlopen(url, timeout=15) as resp:
                    if resp.status == 200:
                        with open(out_path, "wb") as f:
                            f.write(resp.read())
                        ok = True
                        print(f"{name}: OK ({branch})")
                        break
            except Exception:
                continue
        if not ok:
            print(f"{name}: FAILED - could not fetch from either branch")


if __name__ == "__main__":
    main()