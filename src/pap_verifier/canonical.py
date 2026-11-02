"""Strict I-JSON parsing and RFC 8785 JCS canonicalization for PAP v0.1."""

from __future__ import annotations

import json
import math
import re
from typing import Any


class CanonicalError(Exception):
    pass


SAFE_INT_MAX = 2**53 - 1
SAFE_INT_MIN = -(2**53 - 1)


def _check_surrogates(obj: Any) -> None:
    if isinstance(obj, str):
        try:
            obj.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise CanonicalError("lone surrogate in string") from exc
    elif isinstance(obj, dict):
        for k, v in obj.items():
            _check_surrogates(k)
            _check_surrogates(v)
    elif isinstance(obj, list):
        for item in obj:
            _check_surrogates(item)


def _check_string_sizes(obj: Any, limit: int) -> None:
    if isinstance(obj, str):
        if len(obj.encode("utf-8")) > limit:
            raise CanonicalError("JSON string exceeds size limit")
    elif isinstance(obj, dict):
        for k, v in obj.items():
            _check_string_sizes(k, limit)
            _check_string_sizes(v, limit)
    elif isinstance(obj, list):
        for item in obj:
            _check_string_sizes(item, limit)


def _depth_of_raw(raw: bytes) -> int:
    """Iterative nesting-depth scanner that respects JSON strings/escapes."""
    depth = 0
    max_depth = 0
    i = 0
    n = len(raw)
    in_str = False
    escape = False
    while i < n:
        c = raw[i:i+1]
        if in_str:
            if escape:
                escape = False
            elif c == b"\\":
                escape = True
            elif c == b'"':
                in_str = False
        else:
            if c == b'"':
                in_str = True
            elif c in (b"{", b"["):
                depth += 1
                if depth > max_depth:
                    max_depth = depth
            elif c in (b"}", b"]"):
                depth -= 1
                if depth < 0:
                    raise CanonicalError("unbalanced JSON brackets")
        i += 1
    if in_str:
        raise CanonicalError("unterminated string")
    if depth != 0:
        raise CanonicalError("unbalanced JSON brackets")
    return max_depth


_NUMBER_TOKEN_RE = re.compile(rb"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")


def _lexical_numbers_ok(raw: bytes) -> bool:
    """Validate that every JSON number token is an in-range integer literal.

    Scans raw bytes while tracking string state so numbers inside strings are ignored.
    """
    i = 0
    n = len(raw)
    in_str = False
    escape = False
    # Collect number token spans
    tokens: list[bytes] = []
    buf = bytearray()
    in_number = False

    def flush() -> None:
        nonlocal buf, in_number
        if in_number:
            tokens.append(bytes(buf))
            buf = bytearray()
            in_number = False

    for idx in range(n):
        c = raw[idx:idx+1]
        if in_str:
            if escape:
                escape = False
            elif c == b"\\":
                escape = True
            elif c == b'"':
                in_str = False
            flush()
            continue
        if c == b'"':
            in_str = True
            flush()
            continue
        # number characters
        if c in b"-0123456789." or c in b"eE+-":
            # only accumulate if this looks like part of a number token adjacent
            if in_number or c in b"-0123456789.":
                # handle exponent sign only after e/E
                buf.append(c[0])
                in_number = True
                continue
        # whitespace or structural delimiter
        flush()
    flush()

    for tok in tokens:
        # tok must be integer literal (no . or e/E)
        if b"." in tok or b"e" in tok or b"E" in tok:
            return False
        try:
            s = tok.decode("ascii")
        except UnicodeDecodeError:
            return False
        if not re.fullmatch(r"-?(?:0|[1-9][0-9]*)", s):
            return False
        if s == "-0":
            return False
        try:
            val = int(s)
        except ValueError:
            return False
        if val < SAFE_INT_MIN or val > SAFE_INT_MAX:
            return False
    return True


def parse_strict(raw: bytes, *, json_nesting_limit: int, json_string_limit: int) -> Any:
    if not raw:
        raise CanonicalError("empty JSON document")
    # UTF-8 strict
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CanonicalError("invalid UTF-8") from exc
    if text.startswith("\ufeff"):
        raise CanonicalError("BOM not allowed")
    # depth
    depth = _depth_of_raw(raw)
    if depth > json_nesting_limit:
        raise CanonicalError("JSON nesting exceeds limit")
    # lexical number check
    if not _lexical_numbers_ok(raw):
        raise CanonicalError("invalid JSON number token")
    # duplicate keys detection via object_pairs_hook
    def hook(pairs):
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            raise CanonicalError("duplicate JSON key")
        return dict(pairs)

    try:
        obj = json.loads(text, parse_constant=lambda x: (_ for _ in ()).throw(CanonicalError("forbidden constant")), object_pairs_hook=hook)
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise CanonicalError(f"invalid JSON: {exc}") from exc
    # surrogates + string sizes
    _check_surrogates(obj)
    _check_string_sizes(obj, json_string_limit)
    # no floats allowed (redundant safety)
    def check_no_float(o: Any) -> None:
        if isinstance(o, bool):
            return
        if isinstance(o, float):
            raise CanonicalError("floating point not allowed")
        if isinstance(o, dict):
            for k, v in o.items():
                check_no_float(k)
                check_no_float(v)
        elif isinstance(o, list):
            for item in o:
                check_no_float(item)
    check_no_float(obj)
    return obj


def canonicalize(obj: Any) -> bytes:
    """Return RFC 8785 JCS bytes for an already-validated I-JSON value."""
    _check_surrogates(obj)

    def _canon(o: Any) -> str:
        if o is None:
            return "null"
        if isinstance(o, bool):
            return "true" if o else "false"
        if isinstance(o, int):
            if o < SAFE_INT_MIN or o > SAFE_INT_MAX:
                raise CanonicalError("integer out of safe range")
            return str(o)
        if isinstance(o, str):
            return json.dumps(o, ensure_ascii=False, separators=(",", ":"))
        if isinstance(o, list):
            return "[" + ",".join(_canon(x) for x in o) + "]"
        if isinstance(o, dict):
            # sort by UTF-16 code unit order
            def utf16_key(s: str) -> list[int]:
                return list(s.encode("utf-16-le"))  # byte order not ideal but monotonic per code unit? Need better
            # Actually sort by list of UTF-16 code units:
            def key_units(s: str) -> list[int]:
                units = []
                for ch in s:
                    cp = ord(ch)
                    if cp > 0xFFFF:
                        # surrogate pair
                        cp -= 0x10000
                        units.append(0xD800 + (cp >> 10))
                        units.append(0xDC00 + (cp & 0x3FF))
                    else:
                        units.append(cp)
                return units
            items = sorted(o.items(), key=lambda kv: key_units(kv[0]))
            return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _canon(v) for k, v in items) + "}"
        raise CanonicalError(f"unsupported type {type(o)}")

    # json.dumps default escaping matches JCS? Need ensure control chars escaped as \u00xx lowercase.
    # Python's json.dumps escapes control chars as \u00xx (lowercase) by default. Good.
    # But ensure_ascii=False keeps non-ASCII literal; JCS allows. Good.
    s = _canon(obj)
    return s.encode("utf-8")