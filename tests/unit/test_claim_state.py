import json
import os
import tempfile

from pap_verifier.digest import H
from pap_verifier.engine import Verifier


def _base_pkg(d, claims):
    os.makedirs(os.path.join(d, "artifacts"), exist_ok=True)
    os.makedirs(os.path.join(d, "sources"), exist_ok=True)
    os.makedirs(os.path.join(d, "claims"), exist_ok=True)
    artifact_bytes = b"artifact"
    with open(os.path.join(d, "artifacts", "a.txt"), "wb") as f:
        f.write(artifact_bytes)
    source_bytes = b"source"
    with open(os.path.join(d, "sources", "s.txt"), "wb") as f:
        f.write(source_bytes)

    manifest_claims = {}
    for kind, raw in claims.items():
        if raw is None:
            continue
        path = f"claims/{kind}.json"
        full = os.path.join(d, "claims", f"{kind}.json")
        with open(full, "wb") as f:
            f.write(raw)
        manifest_claims[kind] = {"path": path, "digest": H("pap.claims.v1", raw)}

    manifest = {
        "papVersion": "0.1",
        "package": {"id": "urn:test:claims"},
        "artifacts": [{"id": "a", "path": "artifacts/a.txt", "mediaType": "text/plain", "bytes": len(artifact_bytes), "digest": H("pap.artifact.v1", artifact_bytes)}],
        "sources": [{"id": "SRC", "path": "sources/s.txt", "mediaType": "text/plain", "digest": H("pap.source.raw.v1", source_bytes)}],
        "claims": manifest_claims,
        "checkSpecs": [{"id": "pap.check.digest-integrity/1", "version": "1", "required": True}],
    }
    with open(os.path.join(d, "assurance-package.json"), "w") as f:
        json.dump(manifest, f)
    return d


def test_valid_then_missing():
    d = tempfile.mkdtemp()
    prov = json.dumps({"papClaimsVersion": "0.1", "bindings": []}).encode()
    # relations missing -> manifest declares it but no file
    claims = {"provenance": prov, "relations": None}
    # manually declare relations in manifest with digest of a valid file, then remove file
    d = _base_pkg(d, {"provenance": prov})
    # add relations declaration pointing to missing file
    man_path = os.path.join(d, "assurance-package.json")
    man = json.load(open(man_path))
    rel_raw = json.dumps({"papClaimsVersion": "0.1", "entities": [], "relations": [], "edges": []}).encode()
    man["claims"]["relations"] = {"path": "claims/relations.json", "digest": H("pap.claims.v1", rel_raw)}
    json.dump(man, open(man_path, "w"))
    v = Verifier()
    v.verify(d, None, "2026-11-02T00:00:00Z")
    assert v.claims_info["provenance"]["obj"] is not None
    assert v.claims_info.get("relations", {}).get("obj") is None


def test_missing_then_valid():
    d = tempfile.mkdtemp()
    rel_raw = json.dumps({"papClaimsVersion": "0.1", "entities": [], "relations": [], "edges": []}).encode()
    d = _base_pkg(d, {"relations": rel_raw})
    man_path = os.path.join(d, "assurance-package.json")
    man = json.load(open(man_path))
    prov = json.dumps({"papClaimsVersion": "0.1", "bindings": []}).encode()
    man["claims"]["provenance"] = {"path": "claims/provenance.json", "digest": H("pap.claims.v1", prov)}
    json.dump(man, open(man_path, "w"))
    # do not create provenance file
    v = Verifier()
    v.verify(d, None, "2026-11-02T00:00:00Z")
    assert v.claims_info.get("provenance", {}).get("obj") is None
    assert v.claims_info["relations"]["obj"] is not None


def test_malformed_then_valid():
    d = tempfile.mkdtemp()
    rel_raw = json.dumps({"papClaimsVersion": "0.1", "entities": [], "relations": [], "edges": []}).encode()
    d = _base_pkg(d, {"relations": rel_raw})
    man_path = os.path.join(d, "assurance-package.json")
    man = json.load(open(man_path))
    bad = b"{not json"
    man["claims"]["provenance"] = {"path": "claims/provenance.json", "digest": H("pap.claims.v1", bad)}
    json.dump(man, open(man_path, "w"))
    with open(os.path.join(d, "claims", "provenance.json"), "wb") as f:
        f.write(bad)
    v = Verifier()
    v.verify(d, None, "2026-11-02T00:00:00Z")
    assert v.claims_info["provenance"]["obj"] is None
    assert v.claims_info["relations"]["obj"] is not None