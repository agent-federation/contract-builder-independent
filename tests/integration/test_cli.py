import json
import os
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
BIN = os.path.join(ROOT, "bin", "pap")


def run_cli(*args):
    return subprocess.run([BIN, *args], cwd=ROOT, capture_output=True, text=True)


def test_f01_pass():
    r = run_cli("verify", "pap/fixtures/pap-v0.1/F01-unchanged", "--trust-policy", "pap/fixtures/pap-v0.1/trust-policy/unsigned-valid.json", "--format", "json", "--now", "2026-11-02T00:00:00Z")
    assert r.returncode == 0, r.stderr
    assert r.stderr == ""
    assert r.stdout.endswith("\n")
    obj = json.loads(r.stdout)
    assert obj["verdict"] == "PASS"
    # exactly one JSON doc + LF
    assert r.stdout.count("\n") == 1


def test_f02_fail():
    r = run_cli("verify", "pap/fixtures/pap-v0.1/F02-artifact-byte", "--format", "json", "--now", "2026-11-02T00:00:00Z")
    assert r.returncode == 1, r.stderr
    assert r.stderr == ""
    obj = json.loads(r.stdout)
    assert obj["verdict"] == "FAIL"


def test_f27_incomplete():
    r = run_cli("verify", "pap/fixtures/pap-v0.1/F27-referenced-source", "--format", "json", "--now", "2026-11-02T00:00:00Z")
    assert r.returncode == 2, r.stderr
    assert r.stderr == ""
    obj = json.loads(r.stdout)
    assert obj["verdict"] == "INCOMPLETE"