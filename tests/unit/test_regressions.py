import os
import tempfile
import json

from pap_verifier.pathing import open_root, open_relative, read_file_bounded, scan_entries
from pap_verifier.canonical import parse_strict, CanonicalError
from pap_verifier.manifest import parse_manifest, ManifestError
from pap_verifier.limits import DEFAULTS
from pap_verifier.identities import implementation_digest
from pap_verifier.digest import H


def test_unicode_quote_byte_offsets():
    text = "Привет 🌍 мир".encode("utf-8")
    # choose a byte range that cuts through multibyte characters boundary safely
    start = len("Привет ".encode("utf-8"))
    end = start + len("🌍".encode("utf-8"))
    span = text[start:end]
    assert span == "🌍".encode("utf-8")
    d = H("pap.quote.v1", span)
    assert d.startswith("sha256:")


def test_read_boundary_per_file():
    d = tempfile.mkdtemp()
    for size in (DEFAULTS["fileBytes"] is not None and [0] or []):
        pass
    # use small limit for test
    limit = 5
    p = os.path.join(d, "f.txt")
    for content_size, expect_ok in [(4, True), (5, True), (6, False)]:
        with open(p, "wb") as f:
            f.write(b"x" * content_size)
        rootfd = open_root(d)
        fd = open_relative(rootfd, "f.txt")
        tc = [0]
        try:
            data = read_file_bounded(fd, limit, tc, 100)
            ok = True
        except Exception as e:
            ok = False
            assert getattr(e, "code", "") == "pap.package.limit-exceeded", e
        os.close(fd)
        os.close(rootfd)
        assert ok == expect_ok, (content_size, ok, expect_ok)


def test_read_boundary_total():
    d = tempfile.mkdtemp()
    limit = 5
    # two files of 3 bytes each, total limit 5
    for name in ("a.txt", "b.txt"):
        with open(os.path.join(d, name), "wb") as f:
            f.write(b"x" * 3)
    rootfd = open_root(d)
    tc = [0]
    fd1 = open_relative(rootfd, "a.txt")
    data1 = read_file_bounded(fd1, 10, tc, limit)
    os.close(fd1)
    assert len(data1) == 3
    fd2 = open_relative(rootfd, "b.txt")
    try:
        read_file_bounded(fd2, 10, tc, limit)
        assert False
    except Exception as e:
        assert getattr(e, "code", "") == "pap.package.limit-exceeded"
    os.close(fd2)
    os.close(rootfd)


def test_symlink_nonregular():
    d = tempfile.mkdtemp()
    target = os.path.join(d, "target.txt")
    with open(target, "w") as f:
        f.write("x")
    link = os.path.join(d, "link.txt")
    os.symlink(target, link)
    rootfd = open_root(d)
    try:
        open_relative(rootfd, "link.txt")
        assert False
    except Exception as e:
        assert getattr(e, "code", "") == "pap.package.symlink", e
    os.close(rootfd)
    # non-regular: directory as file
    subdir = os.path.join(d, "subdir")
    os.mkdir(subdir)
    rootfd = open_root(d)
    try:
        open_relative(rootfd, "subdir")
        assert False
    except Exception as e:
        assert getattr(e, "code", "") in ("pap.package.non-regular", "pap.package.declared-file-missing"), e
    os.close(rootfd)


def test_partial_scan():
    d = tempfile.mkdtemp()
    for i in range(5):
        with open(os.path.join(d, f"f{i}.txt"), "w") as f:
            f.write("x")
    rootfd = open_root(d)
    entries, status, reason = scan_entries(rootfd, 2)
    assert status == "truncated"
    os.close(rootfd)


def test_scan_exact_limit_not_truncated():
    d = tempfile.mkdtemp()
    for i in range(3):
        with open(os.path.join(d, f"f{i}.txt"), "w") as f:
            f.write("x")
    rootfd = open_root(d)
    entries, status, reason = scan_entries(rootfd, 3)
    assert status == "complete"
    assert len(entries) == 3
    os.close(rootfd)

    rootfd2 = open_root(d)
    entries2, status2, reason2 = scan_entries(rootfd2, 4)
    assert status2 == "complete"
    os.close(rootfd2)


def test_scan_stat_failure_reported():
    d = tempfile.mkdtemp()
    # create a file then remove? Instead monkeypatch? Simpler: max_entries 0 triggers truncated not failed.
    # Test that unreadable nested dir marks failed: create nested dir with no read permission
    sub = os.path.join(d, "sub")
    os.mkdir(sub)
    with open(os.path.join(sub, "x.txt"), "w") as f:
        f.write("x")
    os.chmod(sub, 0o000)
    rootfd = open_root(d)
    entries, status, reason = scan_entries(rootfd, 100)
    os.chmod(sub, 0o755)
    os.close(rootfd)
    assert status == "failed"


def test_manifest_nesting_string_limits():
    deep = ("[" * 65) + "1" + ("]" * 65)
    try:
        parse_manifest(deep.encode(), {"manifestBytes": 1048576, "jsonNesting": 64, "jsonStringBytes": 16777216, "fileBytes": 1, "totalPayloadBytes": 1})
        assert False
    except ManifestError as e:
        assert e.code == "pap.package.limit-exceeded", e.code
    bigstr = '{"a":"' + ("x" * 100) + '"}'
    try:
        parse_manifest(bigstr.encode(), {"manifestBytes": 1048576, "jsonNesting": 64, "jsonStringBytes": 10, "fileBytes": 1, "totalPayloadBytes": 1})
        assert False
    except ManifestError as e:
        assert e.code == "pap.package.limit-exceeded", e.code


def test_implementation_identity_stable():
    a = implementation_digest()
    b = implementation_digest()
    assert a == b
    assert a.startswith("sha256:")


from pap_verifier.identities import implementation_digest_entries


def test_implementation_identity_sensitive():
    a = implementation_digest_entries([("a.py", b"x")])
    b = implementation_digest_entries([("a.py", b"y")])
    assert a != b


def test_closure_stable_and_sensitive():
    entries = [("src/a.py", b"x"), ("pap/schemas/m.json", b"{}")]
    deps = [("cryptography", "43.0.0", "sha256:abc")]
    a = implementation_digest_entries(entries, deps)
    b = implementation_digest_entries(entries, deps)
    assert a == b
    assert implementation_digest_entries([("src/a.py", b"y"), ("pap/schemas/m.json", b"{}")], deps) != a
    assert implementation_digest_entries([("src/a.py", b"x"), ("pap/schemas/m.json", b"{ }")], deps) != a
    assert implementation_digest_entries(entries, [("cryptography", "43.0.0", "sha256:def")]) != a


from pap_verifier.pathing import discover_signature_envelopes


def test_signature_discovery_exact_and_overflow():
    d = tempfile.mkdtemp()
    sigdir = os.path.join(d, "signatures")
    os.makedirs(sigdir)
    for i in range(32):
        with open(os.path.join(sigdir, f"e{i}.dsse.json"), "w") as f:
            f.write("{}")
    rootfd = open_root(d)
    paths, status, reason = discover_signature_envelopes(rootfd, 32)
    assert status == "complete"
    assert len(paths) == 32
    os.close(rootfd)

    d2 = tempfile.mkdtemp()
    sigdir2 = os.path.join(d2, "signatures")
    os.makedirs(sigdir2)
    for i in range(33):
        with open(os.path.join(sigdir2, f"e{i}.dsse.json"), "w") as f:
            f.write("{}")
    rootfd2 = open_root(d2)
    paths2, status2, reason2 = discover_signature_envelopes(rootfd2, 32)
    assert status2 == "truncated"
    assert reason2 == "signatureEnvelopes"
    assert paths2 == []
    os.close(rootfd2)


def test_signature_discovery_ignores_ordinary_entries():
    d = tempfile.mkdtemp()
    # many ordinary files, zero signatures
    for i in range(100):
        with open(os.path.join(d, f"f{i}.txt"), "w") as f:
            f.write("x")
    rootfd = open_root(d)
    paths, status, reason = discover_signature_envelopes(rootfd, 32)
    assert status == "complete"
    assert paths == []
    os.close(rootfd)


import json as _json


def test_fd_closure_on_bounded_read_exception():
    import os, tempfile
    from pap_verifier import engine
    from pap_verifier.pathing import PathError

    tmp = tempfile.mkdtemp()
    os.makedirs(os.path.join(tmp, "artifacts"), exist_ok=True)
    os.makedirs(os.path.join(tmp, "sources"), exist_ok=True)
    os.makedirs(os.path.join(tmp, "claims"), exist_ok=True)
    with open(os.path.join(tmp, "artifacts", "a.txt"), "wb") as f:
        f.write(b"artifact")
    with open(os.path.join(tmp, "sources", "s.txt"), "wb") as f:
        f.write(b"source")
    manifest = {
        "papVersion": "0.1",
        "package": {"id": "urn:test:fd"},
        "artifacts": [{"id": "a", "path": "artifacts/a.txt", "mediaType": "text/plain", "bytes": 8, "digest": "sha256:" + "0" * 64}],
        "sources": [{"id": "S", "path": "sources/s.txt", "mediaType": "text/plain", "digest": "sha256:" + "0" * 64}],
        "checkSpecs": [{"id": "pap.check.digest-integrity/1", "version": "1", "required": True}],
    }
    manifest_bytes = _json.dumps(manifest).encode()
    created_fds = []

    orig_open = engine.open_relative
    orig_read = engine.read_file_bounded

    def fake_open(root_fd, rel):
        fd = os.open(os.path.join(tmp, "fd-target.txt"), os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o666)
        created_fds.append(fd)
        return fd

    calls = {"n": 0}

    def fake_read(fd, *a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            return manifest_bytes
        raise PathError("pap.package.limit-exceeded", "boom")

    engine.open_relative = fake_open
    engine.read_file_bounded = fake_read
    try:
        v = engine.Verifier()
        try:
            v.verify(tmp, None, "2026-11-02T00:00:00Z")
        except Exception:
            pass
        assert created_fds, "no descriptor was opened"
        for fd in created_fds:
            try:
                os.fstat(fd)
                assert False, "descriptor was not closed by verifier"
            except OSError:
                pass
    finally:
        engine.open_relative = orig_open
        engine.read_file_bounded = orig_read
        for fd in created_fds:
            try:
                os.close(fd)
            except OSError:
                pass


def test_signature_discovery_integration():
    import os, tempfile, json
    from pap_verifier.digest import H
    from pap_verifier.engine import run_verify

    # 100 ordinary files, no signatures
    d = tempfile.mkdtemp()
    os.makedirs(os.path.join(d, "artifacts"))
    ab = b"artifact"
    with open(os.path.join(d, "artifacts", "a.txt"), "wb") as f:
        f.write(ab)
    for i in range(100):
        with open(os.path.join(d, f"ordinary{i}.txt"), "w") as f:
            f.write("x")
    manifest = {
        "papVersion": "0.1",
        "package": {"id": "urn:test:sigdiscovery"},
        "artifacts": [{"id": "a", "path": "artifacts/a.txt", "mediaType": "text/plain", "bytes": len(ab), "digest": H("pap.artifact.v1", ab)}],
        "checkSpecs": [{"id": "pap.check.digest-integrity/1", "version": "1", "required": True}],
    }
    with open(os.path.join(d, "assurance-package.json"), "w") as f:
        json.dump(manifest, f)
    report = run_verify(d, None, "2026-11-02T00:00:00Z")
    assert report["verdict"] == "PASS", report["verdict"]
    assert not any(dg["code"] == "pap.package.limit-exceeded" for dg in report["diagnostics"])

    # exactly 32 envelopes
    d2 = tempfile.mkdtemp()
    os.makedirs(os.path.join(d2, "artifacts"))
    os.makedirs(os.path.join(d2, "signatures"))
    with open(os.path.join(d2, "artifacts", "a.txt"), "wb") as f:
        f.write(ab)
    for i in range(32):
        with open(os.path.join(d2, "signatures", f"e{i}.dsse.json"), "w") as f:
            f.write("{}")
    manifest2 = dict(manifest)
    manifest2["package"] = {"id": "urn:test:sig32"}
    with open(os.path.join(d2, "assurance-package.json"), "w") as f:
        json.dump(manifest2, f)
    report2 = run_verify(d2, None, "2026-11-02T00:00:00Z")
    assert not any(dg["scope"] == "signatureEnvelopes" for dg in report2["diagnostics"])
    assert len(report2["dimensions"]["signature"]["signatures"]) == 32
    assert all(e["validity"] == "NOT_EVALUATED" for e in report2["dimensions"]["signature"]["signatures"])

    # 33 envelopes
    d3 = tempfile.mkdtemp()
    os.makedirs(os.path.join(d3, "artifacts"))
    os.makedirs(os.path.join(d3, "signatures"))
    with open(os.path.join(d3, "artifacts", "a.txt"), "wb") as f:
        f.write(ab)
    for i in range(33):
        with open(os.path.join(d3, "signatures", f"e{i}.dsse.json"), "w") as f:
            f.write("{}")
    manifest3 = dict(manifest)
    manifest3["package"] = {"id": "urn:test:sig33"}
    with open(os.path.join(d3, "assurance-package.json"), "w") as f:
        json.dump(manifest3, f)
    report3 = run_verify(d3, None, "2026-11-02T00:00:00Z")
    assert report3["verdict"] == "INCOMPLETE"
    assert report3["coverage"]["full"] is False
    assert any(dg["scope"] == "signatureEnvelopes" for dg in report3["diagnostics"])

    # signatures directory enumeration failure
    d4 = tempfile.mkdtemp()
    os.makedirs(os.path.join(d4, "artifacts"))
    with open(os.path.join(d4, "artifacts", "a.txt"), "wb") as f:
        f.write(ab)
    # signatures as a regular file (not directory)
    with open(os.path.join(d4, "signatures"), "w") as f:
        f.write("x")
    manifest4 = dict(manifest)
    manifest4["package"] = {"id": "urn:test:sigfail"}
    with open(os.path.join(d4, "assurance-package.json"), "w") as f:
        json.dump(manifest4, f)
    report4 = run_verify(d4, None, "2026-11-02T00:00:00Z")
    assert report4["verdict"] == "INCOMPLETE"
    assert any(dg["code"] == "pap.package.io" and dg["scope"] == "signatures" for dg in report4["diagnostics"])


def test_checker_closure_fail_closed():
    import os
    from pap_verifier import identities
    orig_files = identities._closure_file_entries
    orig_deps = identities._dependency_records

    def missing_file():
        raise RuntimeError("missing required closure file: pap/schemas/manifest.schema.json")

    def missing_dep():
        raise RuntimeError("missing required dependency: cryptography")

    identities._closure_file_entries = missing_file
    try:
        try:
            identities.implementation_digest()
            assert False
        except RuntimeError as e:
            assert "missing required closure file" in str(e)
    finally:
        identities._closure_file_entries = orig_files

    identities._dependency_records = missing_dep
    try:
        try:
            identities.implementation_digest()
            assert False
        except RuntimeError as e:
            assert "missing required dependency" in str(e)
    finally:
        identities._dependency_records = orig_deps


def test_checker_closure_sensitivity():
    from pap_verifier.identities import implementation_digest_entries
    base_entries = [("src/a.py", b"x"), ("pap/schemas/m.json", b"{}")]
    base_deps = [("cryptography", "43.0.0", "sha256:abc")]
    base = implementation_digest_entries(base_entries, base_deps)
    assert implementation_digest_entries([("src/a.py", b"y"), ("pap/schemas/m.json", b"{}")], base_deps) != base
    assert implementation_digest_entries(base_entries, [("cryptography", "43.0.0", "sha256:def")]) != base
    # excluded file outside closure does not affect production closure enumeration
    from pap_verifier.identities import _closure_file_entries
    paths = [p for p, _ in _closure_file_entries()]
    assert "README.md" not in paths
    assert not any(p.startswith("tests/") for p in paths)
