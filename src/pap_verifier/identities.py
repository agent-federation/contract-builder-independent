"""Identity helpers."""

from __future__ import annotations

import os
from typing import List, Tuple

import importlib.metadata

from .canonical import canonicalize
from .digest import H, frame_record


def _normalize_closure_bytes(raw: bytes) -> bytes:
    if b"\x00" in raw:
        return raw
    try:
        text = raw.decode("utf-8")
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        return text.encode("utf-8")
    except UnicodeDecodeError:
        return raw


def _closure_file_entries() -> List[Tuple[str, bytes]]:
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(here, "..", ".."))
    entries: List[Tuple[str, bytes]] = []

    # launcher
    launcher = os.path.join(repo_root, "bin", "pap")
    if os.path.isfile(launcher):
        with open(launcher, "rb") as f:
            entries.append(("bin/pap", f.read()))

    # implementation source files
    base = here
    for dirpath, _, filenames in os.walk(base):
        for fn in filenames:
            if fn.endswith(".py"):
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, repo_root).replace(os.sep, "/")
                with open(full, "rb") as f:
                    entries.append((rel, f.read()))

    # schemas actually loaded at runtime
    schema_dir = os.path.join(repo_root, "pap", "schemas")
    for name in [
        "manifest.schema.json",
        "trust-policy.schema.json",
        "claims-provenance.schema.json",
        "claims-relations.schema.json",
        "claims-producer-report.schema.json",
        "claims-reviews.schema.json",
    ]:
        full = os.path.join(schema_dir, name)
        if os.path.isfile(full):
            with open(full, "rb") as f:
                entries.append((f"pap/schemas/{name}", f.read()))

    entries.sort(key=lambda x: x[0])
    return entries


def _dependency_records() -> List[Tuple[str, str, str]]:
    records = []
    for name in ("cryptography", "jsonschema"):
        try:
            dist = importlib.metadata.distribution(name)
            version = dist.version
            meta = dist.read_text("METADATA") or ""
            integrity = "sha256:" + __import__("hashlib").sha256(meta.encode("utf-8")).hexdigest()
            records.append((name, version, integrity))
        except Exception:
            records.append((name, "unknown", "sha256:" + "0" * 64))
    records.sort(key=lambda x: (x[0], x[1]))
    return records


def implementation_digest_entries(file_entries: list[Tuple[str, bytes]], dependency_records: list[Tuple[str, str, str]] | None = None) -> str:
    records = [frame_record("extension", [b"checker", b"pap.verifier.independent", b"0.1.0"])]
    for rel, raw in sorted(file_entries, key=lambda x: x[0]):
        records.append(frame_record("file", [rel.encode("utf-8"), _normalize_closure_bytes(raw)]))
    for name, version, integrity in sorted(dependency_records or [], key=lambda x: (x[0], x[1])):
        records.append(frame_record("dependency", [name.encode("utf-8"), version.encode("utf-8"), integrity.encode("utf-8")]))
    payload = b"".join(records)
    return H("pap.extension.closure.v1", payload)


def implementation_digest() -> str:
    return implementation_digest_entries(_closure_file_entries(), _dependency_records())


def checker_identity(checker_id: str, version: str, impl_digest: str) -> str:
    obj = {"id": checker_id, "version": version, "implementationDigest": impl_digest}
    return H("pap.checker.identity.v1", canonicalize(obj))