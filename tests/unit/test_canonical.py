import json
from pap_verifier.canonical import parse_strict, canonicalize, CanonicalError

E1_MANIFEST = open("pap/fixtures/pap-v0.1/F01-unchanged/assurance-package.json","rb").read()


def test_e1_package_identity():
    obj = parse_strict(E1_MANIFEST, json_nesting_limit=64, json_string_limit=16777216)
    cb = canonicalize(obj)
    from pap_verifier.digest import H
    assert H("pap.package.v1", cb) == "sha256:77a8d1d0882428efdfa5bfc38faa1ff7ba772aff9373b9e6135a8bb744119020"


def test_e9_utf16_key_order():
    raw = b'{"a":1,"\xf0\x9f\x98\x80":2,"\xef\xbf\xbd":3,"A":4,"b":5}'
    obj = parse_strict(raw, json_nesting_limit=64, json_string_limit=16777216)
    cb = canonicalize(obj)
    assert cb == b'{"A":4,"a":1,"b":5,"\xf0\x9f\x98\x80":2,"\xef\xbf\xbd":3}'
    import hashlib
    assert hashlib.sha256(cb).hexdigest() == "9267454f732ed7ef9939b28dc1e451c88c2967ff4a6b1746bf638d313e72b508"


def test_e9_string_escaping():
    raw = b'{"s":"\\u0001\\t\\n\\"\\\\\xc3\xa9\xf0\x9f\x98\x80"}'
    obj = parse_strict(raw, json_nesting_limit=64, json_string_limit=16777216)
    cb = canonicalize(obj)
    assert cb == b'{"s":"\\u0001\\t\\n\\"\\\\\xc3\xa9\xf0\x9f\x98\x80"}'
    import hashlib
    assert hashlib.sha256(cb).hexdigest() == "9033f8f21bc1c3367ebcad55e2298bf113b63f9e5f21c20678de00e760c5ff5d"


def test_reject_forbidden_numbers():
    for bad in [b'{"x":1.0}', b'{"x":1e3}', b'{"x":-0}', b'{"x":9007199254740992}']:
        try:
            parse_strict(bad, json_nesting_limit=64, json_string_limit=16777216)
            assert False, bad
        except CanonicalError:
            pass


def test_duplicate_keys_rejected():
    try:
        parse_strict(b'{"a":1,"a":2}', json_nesting_limit=64, json_string_limit=16777216)
        assert False
    except CanonicalError:
        pass


def test_lone_surrogate_rejected():
    try:
        parse_strict(b'{"a":"\\ud800"}', json_nesting_limit=64, json_string_limit=16777216)
        assert False
    except CanonicalError:
        pass


def test_bom_rejected():
    try:
        parse_strict(b'\xef\xbb\xbf{"a":1}', json_nesting_limit=64, json_string_limit=16777216)
        assert False
    except CanonicalError:
        pass


def test_depth_limit():
    deep = ("[" * 65) + "1" + ("]" * 65)
    try:
        parse_strict(deep.encode(), json_nesting_limit=64, json_string_limit=16777216)
        assert False
    except CanonicalError:
        pass