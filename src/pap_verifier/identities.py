"""Identity helpers."""

from __future__ import annotations

from .canonical import canonicalize
from .digest import H, frame_record


def implementation_digest() -> str:
    # checker closure digest (minimal)
    payload = frame_record("extension", [b"checker", b"pap.verifier.independent", b"0.1.0"])
    return H("pap.extension.closure.v1", payload)


def checker_identity(checker_id: str, version: str, impl_digest: str) -> str:
    obj = {"id": checker_id, "version": version, "implementationDigest": impl_digest}
    return H("pap.checker.identity.v1", canonicalize(obj))