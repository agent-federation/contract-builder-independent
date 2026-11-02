#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT = ROOT / "snapshot"

SOURCE_REPOSITORY = "agent-federation/contract-builder"
SOURCE_COMMIT = "c6ee64416c91ab56f9d8270114c8f8a8b9d2f608"

EXCLUDED = {
    "snapshot/manifest.json",
    "snapshot/SHA256SUMS",
    "snapshot/generate.py",
}

def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

files = []

for path in sorted(ROOT.rglob("*")):
    if not path.is_file():
        continue

    rel = path.relative_to(ROOT).as_posix()

    if rel in EXCLUDED or ".git/" in rel:
        continue

    files.append({
        "path": rel,
        "size": path.stat().st_size,
        "sha256": sha256(path),
    })

manifest = {
    "format": "pap-independent-snapshot",
    "pap_version": "0.1",
    "source": {
        "repository": SOURCE_REPOSITORY,
        "commit": SOURCE_COMMIT,
    },
    "files": files,
}

(SNAPSHOT / "manifest.json").write_text(
    json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
    encoding="utf-8",
)

# Include manifest and every snapshot file except SHA256SUMS itself.
entries = []

for path in sorted(ROOT.rglob("*")):
    if not path.is_file():
        continue

    rel = path.relative_to(ROOT).as_posix()

    if rel == "snapshot/SHA256SUMS":
        continue
    if rel == "snapshot/generate.py" or ".git/" in rel:
        continue

    entries.append(f"{sha256(path)}  {rel}")

(SNAPSHOT / "SHA256SUMS").write_text(
    "\n".join(entries) + "\n",
    encoding="utf-8",
)

print(f"Manifest: {len(files)} files")
print(f"Checksums: {len(entries)} files")
