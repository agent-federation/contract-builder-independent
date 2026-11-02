"""Identity helpers."""

from __future__ import annotations

import hashlib
import importlib.metadata
import os
import re
from typing import List, Tuple

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


def _required_closure_paths() -> list[str]:
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(here, "..", ".."))
    paths = ["bin/pap"]
    for dirpath, _, filenames in os.walk(os.path.join(repo_root, "src", "pap_verifier")):
        for fn in filenames:
            if fn.endswith(".py"):
                paths.append(os.path.relpath(os.path.join(dirpath, fn), repo_root).replace(os.sep, "/"))
    for name in [
        "manifest.schema.json",
        "trust-policy.schema.json",
        "claims-provenance.schema.json",
        "claims-relations.schema.json",
        "claims-producer-report.schema.json",
        "claims-reviews.schema.json",
    ]:
        paths.append(f"pap/schemas/{name}")
    return sorted(set(paths))


def _closure_file_entries() -> List[Tuple[str, bytes]]:
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(here, "..", ".."))
    entries: List[Tuple[str, bytes]] = []
    for rel in _required_closure_paths():
        full = os.path.join(repo_root, rel)
        if not os.path.isfile(full):
            raise RuntimeError(f"missing required closure file: {rel}")
        with open(full, "rb") as f:
            entries.append((rel, f.read()))
    entries.sort(key=lambda x: x[0])
    return entries


def _dependency_name(req: str) -> str:
    m = re.match(r"^\s*([A-Za-z0-9_.-]+)", req)
    return m.group(1) if m else req.strip()


def _collect_dependencies(root: str, seen: set[str]) -> list[str]:
    names = []
    try:
        reqs = importlib.metadata.requires(root) or []
    except Exception:
        reqs = []
    for req in reqs:
        if ";" in req:
            marker = req.split(";", 1)[1].strip()
            # skip optional extras and unavailable markers
            if "extra ==" in marker or "extra==" in marker:
                continue
            try:
                from packaging.markers import Marker
                if not Marker(marker).evaluate():
                    continue
            except Exception:
                # if packaging unavailable, be conservative and skip marked requirements
                continue
        name = _dependency_name(req.split(";")[0])
        if not name:
            continue
        norm = name.lower().replace("_", "-")
        if norm not in seen:
            seen.add(norm)
            names.append(name)
            names.extend(_collect_dependencies(name, seen))
    return names


def _dependency_records() -> List[Tuple[str, str, str]]:
    direct = ["cryptography", "jsonschema"]
    seen: set[str] = set()
    all_names = []
    for name in direct:
        norm = name.lower().replace("_", "-")
        if norm not in seen:
            seen.add(norm)
            all_names.append(name)
            all_names.extend(_collect_dependencies(name, seen))
    records = []
    for name in all_names:
        try:
            dist = importlib.metadata.distribution(name)
        except Exception as exc:
            raise RuntimeError(f"missing required dependency: {name}") from exc
        version = dist.version
        meta = dist.read_text("METADATA") or ""
        integrity = "sha256:" + hashlib.sha256(meta.encode("utf-8")).hexdigest()
        records.append((name, version, integrity))
    records.sort(key=lambda x: (x[0].lower(), x[1]))
    return records


def implementation_digest_entries(file_entries: list[Tuple[str, bytes]], dependency_records: list[Tuple[str, str, str]] | None = None) -> str:
    records = [frame_record("extension", [b"checker", b"pap.verifier.independent", b"0.1.0"])]
    for rel, raw in sorted(file_entries, key=lambda x: x[0]):
        records.append(frame_record("file", [rel.encode("utf-8"), _normalize_closure_bytes(raw)]))
    for name, version, integrity in sorted(dependency_records or [], key=lambda x: (x[0].lower(), x[1])):
        records.append(frame_record("dependency", [name.encode("utf-8"), version.encode("utf-8"), integrity.encode("utf-8")]))
    payload = b"".join(records)
    return H("pap.extension.closure.v1", payload)


def implementation_digest() -> str:
    return implementation_digest_entries(_closure_file_entries(), _dependency_records())


def checker_identity(checker_id: str, version: str, impl_digest: str) -> str:
    obj = {"id": checker_id, "version": version, "implementationDigest": impl_digest}
    return H("pap.checker.identity.v1", canonicalize(obj))