"""Resource limits per RFC §4.3.4."""

from __future__ import annotations

DEFAULTS = {
    "manifestBytes": 1048576,
    "payloadFiles": 4096,
    "fileBytes": 268435456,
    "totalPayloadBytes": 1073741824,
    "pathSegments": 16,
    "pathBytes": 255,
    "segmentBytes": 255,
    "jsonNesting": 64,
    "jsonStringBytes": 16777216,
    "claimsFiles": 16,
    "provenanceBindings": 100000,
    "relationEntities": 100000,
    "relationEdges": 1000000,
    "signatureEnvelopes": 32,
}

LIMIT_NAMES = list(DEFAULTS.keys())


def effective_limits(policy_limits: dict | None) -> dict:
    out = dict(DEFAULTS)
    if policy_limits:
        for k, v in policy_limits.items():
            if k not in DEFAULTS:
                continue
            if v < DEFAULTS[k]:
                out[k] = v
            # raising is invalid; caller validates
    return out