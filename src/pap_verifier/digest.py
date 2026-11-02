"""Domain-separated SHA-256 and PAP framing/normalization."""

from __future__ import annotations

import hashlib
import struct
from typing import Iterable


def H(domain: str, octets: bytes) -> str:
    h = hashlib.sha256()
    h.update(domain.encode("ascii"))
    h.update(b"\x00")
    h.update(octets)
    return "sha256:" + h.hexdigest()


def frame_record(tag: str, parts: Iterable[bytes]) -> bytes:
    parts = list(parts)
    tag_b = tag.encode("utf-8")
    buf = struct.pack(">I", len(tag_b)) + tag_b
    buf += struct.pack(">I", len(parts))
    for p in parts:
        buf += struct.pack(">I", len(p)) + p
    return buf


def normalize_input_bytes(raw: bytes, mode: str) -> bytes:
    if mode == "none":
        return raw
    if b"\x00" in raw:
        return raw
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text.encode("utf-8")


def digest_input_file(path: str, normalized: bytes) -> str:
    record = frame_record("input", [path.encode("utf-8"), normalized])
    return H("pap.input.file.v1", record)


def digest_input_set(records: list[tuple[str, bytes]]) -> str:
    # records: (path, normalized bytes), sorted by path
    ordered = sorted(records, key=lambda r: r[0].encode("utf-8"))
    payload = b""
    for path, nb in ordered:
        payload += frame_record("input", [path.encode("utf-8"), nb])
    return H("pap.input.set.v1", payload)