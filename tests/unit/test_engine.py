from pap_verifier.engine import run_verify

def test_f01_pass():
    r = run_verify("pap/fixtures/pap-v0.1/F01-unchanged", "pap/fixtures/pap-v0.1/trust-policy/unsigned-valid.json", "2026-11-02T00:00:00Z")
    assert r["verdict"] == "PASS"
    assert r["coverage"]["full"] is True
    assert r["identities"]["packageIdentity"] == "sha256:77a8d1d0882428efdfa5bfc38faa1ff7ba772aff9373b9e6135a8bb744119020"

def test_f02_fail():
    r = run_verify("pap/fixtures/pap-v0.1/F02-artifact-byte", None, "2026-11-02T00:00:00Z")
    assert r["verdict"] == "FAIL"
    assert r["coverage"]["full"] is True

def test_f27_incomplete():
    r = run_verify("pap/fixtures/pap-v0.1/F27-referenced-source", None, "2026-11-02T00:00:00Z")
    assert r["verdict"] == "INCOMPLETE"
    assert r["coverage"]["full"] is False