"""Strip a UTF-8 BOM from committed text artefacts that do not need one.

Run once to normalise the tree, and re-run whenever the audit reports a BOM in a
file the project generates. Upstream files under references/ are byte-preserved
by .gitattributes and are never touched, and the acquisition evidence files are
left alone because they record upstream content.

python scripts/normalize_text.py [--check]
"""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {".md", ".csv", ".yml", ".json", ".py", ".txt", ".ipynb"}
SKIP_DIRS = {".git", ".venv", "__pycache__", ".ipynb_checkpoints", ".pytest_cache"}
PRESERVE_PREFIXES = ("references/",)
BOM = b"\xef\xbb\xbf"


def targets():
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or SKIP_DIRS & set(path.parts):
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        relative = path.relative_to(ROOT).as_posix()
        if relative.startswith(PRESERVE_PREFIXES):
            continue
        if relative.startswith("data/"):
            continue
        yield path, relative


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true",
                        help="report only; do not modify files")
    args = parser.parse_args()
    changed, clean = [], []
    for path, relative in targets():
        raw = path.read_bytes()
        if not raw.startswith(BOM):
            clean.append(relative)
            continue
        stripped = raw[len(BOM):]
        if b"\xef\xbb\xbf" in stripped:
            print(f"REFUSED {relative}: contains a second BOM inside the content")
            return 1
        changed.append(relative)
        if not args.check:
            path.write_bytes(stripped)
    for relative in changed:
        print(f"{'would strip' if args.check else 'stripped   '} {relative}")
    print(f"\nBOM present: {len(changed)} | clean: {len(clean)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
