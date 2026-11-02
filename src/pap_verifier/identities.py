"""Identity helpers."""

from __future__ import annotations

import os
from typing import List, Tuple

from .canonical import canonicalize
from .digest import H, frame_record


def _source_files() -> List[Tuple[str, str]]:
    here = os.path.dirname(os.path.abspath(__file__))
    base = here
    files = []
    for dirpath, _, filenames in os.walk(base):
        for fn in filenames:
            if fn.endswith(".py"):
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, base).replace(os.sep, "/")
                files.append((rel, full))
    files.sort(key=lambda x: x[0])
    return files


def _normalize_closure_bytes(raw: bytes) -> bytes:
    if b"\x00" in raw:
        return raw
    try:
        text = raw.decode("utf-8")
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        return text.encode("utf-8")
    except UnicodeDecodeError:
        return raw


def implementation_digest_entries(entries: list[Tuple[str, bytes]]) -> str:
    records = [frame_record("extension", [b"checker", b"pap.verifier.independent", b"0.1.0"])]
    for rel, raw in sorted(entries, key=lambda x: x[0]):
        records.append(frame_record("file", [rel.encode("utf-8"), _normalize_closure_bytes(raw)]))
    payload = b"".join(records)
    return H("pap.extension.closure.v1", payload)


def implementation_digest() -> str:
    entries = []
    for rel, full in _source_files():
        with open(full, "rb") as f:
            entries.append((rel, f.read()))
    return implementation_digest_entries(entries)


def checker_identity(checker_id: str, version: str, impl_digest: str) -> str:
    obj = {"id": checker_id, "version": version, "implementationDigest": impl_digest}
    return H("pap.checker.identity.v1", canonicalize(obj))