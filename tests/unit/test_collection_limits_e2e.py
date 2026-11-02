import json
import os
import tempfile

from pap_verifier.digest import H
from pap_verifier.engine import run_verify


def _make_pkg(num_bindings):
    d = tempfile.mkdtemp()
    os.makedirs(os.path.join(d, "artifacts"))
    os.makedirs(os.path.join(d, "sources"))
    os.makedirs(os.path.join(d, "claims"))

    artifact_bytes = b"artifact"
    with open(os.path.join(d, "artifacts", "a.txt"), "wb") as f:
        f.write(artifact_bytes)

    source_text = "abcdefghij"
    source_bytes = source_text.encode("utf-8")
    with open(os.path.join(d, "sources", "s.txt"), "wb") as f:
        f.write(source_bytes)

    bindings = []
    for i in range(num_bindings):
        start = i
        end = i + 1
        span = source_bytes[start:end]
        bindings.append({
            "id": f"b{i}",
            "entityId": f"E{i}",
            "sourceId": "SRC",
            "locator": {"kind": "byte-range", "start": start, "end": end},
            "quote": {"normalization": "none", "digest": H("pap.quote.v1", span)},
        })

    claims_obj = {"papClaimsVersion": "0.1", "bindings": bindings}
    claims_raw = json.dumps(claims_obj, separators=(",", ":")).encode("utf-8")
    with open(os.path.join(d, "claims", "provenance.json"), "wb") as f:
        f.write(claims_raw)

    manifest = {
        "papVersion": "0.1",
        "package": {"id": "urn:test:limits"},
        "artifacts": [{"id": "a", "path": "artifacts/a.txt", "mediaType": "text/plain", "bytes": len(artifact_bytes), "digest": H("pap.artifact.v1", artifact_bytes)}],
        "sources": [{"id": "SRC", "path": "sources/s.txt", "mediaType": "text/plain", "digest": H("pap.source.raw.v1", source_bytes)}],
        "claims": {"provenance": {"path": "claims/provenance.json", "digest": H("pap.claims.v1", claims_raw)}},
        "checkSpecs": [
            {"id": "pap.check.digest-integrity/1", "version": "1", "required": True},
            {"id": "pap.check.source-quote/1", "version": "1", "required": True},
        ],
    }
    with open(os.path.join(d, "assurance-package.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f)
    return d


def test_provenance_binding_limit_prevents_pass():
    d = _make_pkg(2)
    # policy lowers provenanceBindings to 1
    policy = {
        "trustPolicyVersion": "0.1",
        "id": "p",
        "issuedAt": "2026-11-01T00:00:00Z",
        "expiresAt": "2026-12-01T00:00:00Z",
        "signature": {"mode": "disabled"},
        "keys": [],
        "signers": [],
        "checkers": [],
        "profiles": [],
        "requiredChecks": ["pap.check.digest-integrity/1", "pap.check.source-quote/1"],
        "requiredDimensions": ["integrity", "sources", "checks"],
        "humanReview": {"required": False, "maxAgeSeconds": 2592000},
        "limits": {"provenanceBindings": 1},
    }
    import tempfile
    pf = os.path.join(tempfile.mkdtemp(), "policy.json")
    with open(pf, "w") as f:
        import json as _j
        _j.dump(policy, f)
    report = run_verify(d, pf, "2026-11-02T00:00:00Z")
    assert report["verdict"] != "PASS"
    assert report["coverage"]["full"] is False
    sq = [c for c in report["checks"] if c["checkId"] == "pap.check.source-quote/1"][0]
    assert sq["outcome"] == "NOT_EVALUATED"