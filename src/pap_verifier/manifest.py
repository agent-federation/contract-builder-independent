"""Manifest parsing and validation (Appendix A)."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Tuple

import jsonschema

from .canonical import parse_strict, CanonicalError
from .diagnostics import Diagnostic
from .limits import DEFAULTS
from .pathing import validate_path_grammar, case_fold_key


SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "pap", "schemas", "manifest.schema.json")


def load_schema() -> dict:
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


class ManifestError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def parse_manifest(raw: bytes, limits: dict) -> Tuple[Any, List[Diagnostic]]:
    diags: List[Diagnostic] = []
    # byte limit
    if len(raw) > limits["manifestBytes"]:
        raise ManifestError("pap.package.limit-exceeded", "manifest exceeds byte limit")
    try:
        obj = parse_strict(raw, json_nesting_limit=limits["jsonNesting"], json_string_limit=limits["jsonStringBytes"])
    except CanonicalError as exc:
        raise ManifestError("pap.package.manifest-json", str(exc)) from exc

    schema = load_schema()
    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(obj), key=lambda e: list(e.path))
    if errors:
        e = errors[0]
        path = ".".join(str(x) for x in e.path) if e.path else "root"
        raise ManifestError("pap.package.schema", f"{path}: {e.message}")

    # cross-field invariants
    # unique artifact ids/paths
    artifacts = obj.get("artifacts", [])
    a_ids = [a["id"] for a in artifacts]
    if len(a_ids) != len(set(a_ids)):
        raise ManifestError("pap.package.duplicate-id", "duplicate artifact id")
    a_paths = [a["path"] for a in artifacts]
    if len(a_paths) != len(set(a_paths)):
        raise ManifestError("pap.package.path-duplicate", "duplicate artifact path")
    # case-folded uniqueness across all declared payload paths
    all_paths = []
    all_paths += a_paths
    all_paths += [i["path"] for i in obj.get("inputs", [])]
    all_paths += [s["path"] for s in obj.get("sources", []) if "path" in s]
    claims = obj.get("claims", {}) or {}
    for v in claims.values():
        all_paths.append(v["path"])
    seen_cf = set()
    for p in all_paths:
        cf = case_fold_key(p)
        if cf in seen_cf:
            raise ManifestError("pap.package.path-duplicate", "case-folded duplicate path")
        seen_cf.add(cf)
    # path grammar already in schema pattern, but enforce explicit code
    for p in all_paths:
        try:
            validate_path_grammar(p)
        except Exception as exc:
            raise ManifestError("pap.package.path-invalid", str(exc)) from exc
    # inputs
    inputs = obj.get("inputs", [])
    i_ids = [i["id"] for i in inputs]
    if len(i_ids) != len(set(i_ids)):
        raise ManifestError("pap.package.duplicate-id", "duplicate input id")
    i_paths = [i["path"] for i in inputs]
    if len(i_paths) != len(set(i_paths)):
        raise ManifestError("pap.package.path-duplicate", "duplicate input path")
    # sources
    sources = obj.get("sources", [])
    s_ids = [s["id"] for s in sources]
    if len(s_ids) != len(set(s_ids)):
        raise ManifestError("pap.package.duplicate-id", "duplicate source id")
    s_paths = [s["path"] for s in sources if "path" in s]
    if len(s_paths) != len(set(s_paths)):
        raise ManifestError("pap.package.path-duplicate", "duplicate source path")
    # checkSpecs version suffix
    for cs in obj.get("checkSpecs", []):
        cid = cs["id"]
        ver = cs["version"]
        suffix = cid.rsplit("/", 1)[-1]
        if suffix != ver:
            raise ManifestError("pap.package.schema", "checkSpecs version mismatch")
    # checkSpecs unique ids
    cs_ids = [cs["id"] for cs in obj.get("checkSpecs", [])]
    if len(cs_ids) != len(set(cs_ids)):
        raise ManifestError("pap.package.duplicate-id", "duplicate check spec")
    # claims unique paths already in all_paths
    # profile self? manifest must not declare itself
    # (handled by path roots; manifest path not in payloads)
    # unknown fields handled by schema additionalProperties
    return obj, diags