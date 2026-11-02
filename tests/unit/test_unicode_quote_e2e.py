import json
import os
import tempfile

from pap_verifier.digest import H
from pap_verifier.engine import run_verify


def test_unicode_source_quote_end_to_end():
    d = tempfile.mkdtemp()
    os.makedirs(os.path.join(d, "artifacts"))
    os.makedirs(os.path.join(d, "sources"))
    os.makedirs(os.path.join(d, "claims"))

    artifact_bytes = b"artifact"
    with open(os.path.join(d, "artifacts", "a.txt"), "wb") as f:
        f.write(artifact_bytes)

    source_text = "Привет 🌍 мир"
    source_bytes = source_text.encode("utf-8")
    with open(os.path.join(d, "sources", "s.txt"), "wb") as f:
        f.write(source_bytes)

    start = len("Привет ".encode("utf-8"))
    end = len(source_bytes)
    span = source_bytes[start:end]
    quote_digest = H("pap.quote.v1", span)

    claims_obj = {
        "papClaimsVersion": "0.1",
        "bindings": [
            {
                "id": "b1",
                "entityId": "E1",
                "sourceId": "SRC",
                "locator": {"kind": "byte-range", "start": start, "end": end},
                "quote": {"normalization": "none", "digest": quote_digest},
            }
        ],
    }
    claims_raw = json.dumps(claims_obj, separators=(",", ":")).encode("utf-8")
    with open(os.path.join(d, "claims", "provenance.json"), "wb") as f:
        f.write(claims_raw)

    manifest = {
        "papVersion": "0.1",
        "package": {"id": "urn:test:unicode"},
        "artifacts": [
            {"id": "a", "path": "artifacts/a.txt", "mediaType": "text/plain", "bytes": len(artifact_bytes), "digest": H("pap.artifact.v1", artifact_bytes)}
        ],
        "sources": [
            {"id": "SRC", "path": "sources/s.txt", "mediaType": "text/plain; charset=utf-8", "digest": H("pap.source.raw.v1", source_bytes)}
        ],
        "claims": {"provenance": {"path": "claims/provenance.json", "digest": H("pap.claims.v1", claims_raw)}},
        "checkSpecs": [
            {"id": "pap.check.digest-integrity/1", "version": "1", "required": True},
            {"id": "pap.check.source-quote/1", "version": "1", "required": True},
        ],
    }
    with open(os.path.join(d, "assurance-package.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f)

    report = run_verify(d, None, "2026-11-02T00:00:00Z")
    assert report["verdict"] == "PASS", report["verdict"]
    sq = [c for c in report["checks"] if c["checkId"] == "pap.check.source-quote/1"][0]
    assert sq["outcome"] == "PASS"
    w = sq["witnesses"][0]
    assert w["extractedDigest"] == quote_digest