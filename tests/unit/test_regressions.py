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
    entries, status = scan_entries(rootfd, 2)
    assert status == "truncated"
    os.close(rootfd)


def test_scan_exact_limit_not_truncated():
    d = tempfile.mkdtemp()
    for i in range(3):
        with open(os.path.join(d, f"f{i}.txt"), "w") as f:
            f.write("x")
    rootfd = open_root(d)
    entries, status = scan_entries(rootfd, 3)
    assert status == "complete"
    assert len(entries) == 3
    os.close(rootfd)

    rootfd2 = open_root(d)
    entries2, status2 = scan_entries(rootfd2, 4)
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
    entries, status = scan_entries(rootfd, 100)
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
