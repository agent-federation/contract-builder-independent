"""Identity helpers."""

from __future__ import annotations

import os
from typing import List

from .canonical import canonicalize
from .digest import H, frame_record


def _source_files() -> List[str]:
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.join(here, "..")  # src/
    # collect all .py under pap_verifier
    base = os.path.join(root, "pap_verifier")
    files = []
    for dirpath, _, filenames in os.walk(base):
        for fn in filenames:
            if fn.endswith(".py"):
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, base).replace(os.sep, "/")
                files.append((rel, full))
    files.sort(key=lambda x: x[0])
    return files


def implementation_digest() -> str:
    records = [frame_record("extension", [b"checker", b"pap.verifier.independent", b"0.1.0"])]
    for rel, full in _source_files():
        with open(full, "rb") as f:
            raw = f.read()
        # LF-normalize text
        if b"\x00" in raw:
            norm = raw
        else:
            try:
                text = raw.decode("utf-8")
                text = text.replace("\r\n", "\n").replace("\r", "\n")
                norm = text.encode("utf-8")
            except UnicodeDecodeError:
                norm = raw
        records.append(frame_record("file", [rel.encode("utf-8"), norm]))
    # concatenate records into payload
    payload = b"".join(records)
    return H("pap.extension.closure.v1", payload)


def checker_identity(checker_id: str, version: str, impl_digest: str) -> str:
    obj = {"id": checker_id, "version": version, "implementationDigest": impl_digest}
    return H("pap.checker.identity.v1", canonicalize(obj))