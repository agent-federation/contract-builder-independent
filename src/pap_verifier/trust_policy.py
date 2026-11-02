"""Trust policy parsing and validation (Appendix B)."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import jsonschema

from .canonical import parse_strict, CanonicalError
from .limits import DEFAULTS, effective_limits
from .manifest import ManifestError as PolicyError  # reuse error type

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "pap", "schemas", "trust-policy.schema.json")


def load_schema() -> dict:
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def parse_policy(raw: bytes, limits: dict) -> dict:
    if len(raw) > limits["manifestBytes"]:
        raise PolicyError("pap.trust.policy-invalid", "policy exceeds byte limit")
    try:
        obj = parse_strict(raw, json_nesting_limit=limits["jsonNesting"], json_string_limit=limits["jsonStringBytes"])
    except CanonicalError as exc:
        raise PolicyError("pap.trust.policy-invalid", str(exc)) from exc
    schema = load_schema()
    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(obj), key=lambda e: list(e.path))
    if errors:
        e = errors[0]
        raise PolicyError("pap.trust.policy-invalid", f"{list(e.path)}: {e.message}")
    # cross-field invariants
    keys = [k["keyId"] for k in obj.get("keys", [])]
    if len(keys) != len(set(keys)):
        raise PolicyError("pap.trust.policy-invalid", "duplicate keyId")
    key_set = set(keys)
    for signer in obj.get("signers", []):
        for kid in signer.get("keyIds", []):
            if kid not in key_set:
                raise PolicyError("pap.trust.policy-invalid", "signer keyId missing from keys")
    # requiredDimensions evaluable set
    evaluable = {
        "integrity", "integrity.package", "integrity.artifacts",
        "sources", "sources.integrity", "sources.availability",
        "signature", "signature.validity",
        "trust", "trust.signerIdentity", "trust.policyDecision",
        "trust.checkerRecognition", "trust.profileRecognition",
        "checks", "humanReview",
    }
    rd = obj.get("requiredDimensions", [])
    if len(rd) != len(set(rd)):
        raise PolicyError("pap.trust.policy-invalid", "duplicate requiredDimension")
    for d in rd:
        if d not in evaluable:
            raise PolicyError("pap.trust.policy-invalid", f"non-evaluable required dimension {d}")
    # limits
    pl = obj.get("limits")
    if pl:
        for k, v in pl.items():
            if k in DEFAULTS and v > DEFAULTS[k]:
                raise PolicyError("pap.trust.policy-invalid", f"limit {k} above default")
    # minimumValidSigners
    mvs = obj.get("signature", {}).get("minimumValidSigners", 1)
    if obj.get("signature", {}).get("mode") == "required":
        if not obj.get("keys") or not obj.get("signers"):
            raise PolicyError("pap.trust.policy-invalid", "required mode needs keys and signers")
        if mvs > len(obj.get("signers", [])):
            raise PolicyError("pap.trust.policy-invalid", "minimumValidSigners exceeds signers")
    # issuedAt <= expiresAt
    try:
        issued = datetime.fromisoformat(obj["issuedAt"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(obj["expiresAt"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise PolicyError("pap.trust.policy-invalid", "invalid policy timestamps") from exc
    if issued > expires:
        raise PolicyError("pap.trust.policy-invalid", "issuedAt after expiresAt")
    return obj


def parse_rfc3339(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def policy_state(policy: dict, now: datetime) -> str:
    issued = parse_rfc3339(policy["issuedAt"])
    expires = parse_rfc3339(policy["expiresAt"])
    if issued.tzinfo is None:
        issued = issued.replace(tzinfo=timezone.utc)
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if now < issued or now > expires:
        return "STALE"
    return "FRESH"