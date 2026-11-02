"""Report serialization and verification-record identity."""

from __future__ import annotations

import copy
from typing import Any

from .canonical import canonicalize
from .digest import H


EXCLUDED_FIELDS = None


def _strip_excluded(obj: Any) -> Any:
    # Work on a deep copy
    obj = copy.deepcopy(obj)
    # remove evaluatedAt, durationMs
    obj.pop("evaluatedAt", None)
    obj.pop("durationMs", None)
    # package.path, policy.path
    if isinstance(obj.get("package"), dict):
        obj["package"].pop("path", None)
    if isinstance(obj.get("policy"), dict):
        obj["policy"].pop("path", None)
    # producerClaims block
    obj.pop("producerClaims", None)
    # diagnostics messages
    for d in obj.get("diagnostics", []) or []:
        d.pop("message", None)
    for rec in obj.get("checks", []) or []:
        for d in rec.get("diagnostics", []) or []:
            d.pop("message", None)
        # quoteBase64 in witnesses
        for w in rec.get("witnesses", []) or []:
            if isinstance(w, dict):
                w.pop("quoteBase64", None)
    # placeholder verificationRecordIdentity
    if isinstance(obj.get("identities"), dict):
        obj["identities"]["verificationRecordIdentity"] = "sha256:" + "0" * 64
    return obj


def compute_record_identity(report: dict) -> str:
    stripped = _strip_excluded(report)
    cb = canonicalize(stripped)
    return H("pap.report.v1", cb)


def to_json(report: dict) -> bytes:
    # JCS canonical of report (full report, not stripped)
    # Remove None? Keep schema. Canonicalize as-is.
    cb = canonicalize(report)
    return cb + b"\n"