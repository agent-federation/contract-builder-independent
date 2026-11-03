#!/usr/bin/env python3
"""Read-only integrity verifier for the frozen PAP snapshot."""

import hashlib
import json
import re
import stat
import sys
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = Path("snapshot/manifest.json")
CHECKSUMS = Path("snapshot/SHA256SUMS")

EXPECTED_FORMAT = "pap-independent-snapshot"
EXPECTED_PAP_VERSION = "0.1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


class VerificationError(Exception):
    pass


def fail(message):
    raise VerificationError(message)


def read_regular_file(relative_path):
    """Read a regular file without following symlinks in its path."""
    current = ROOT

    for part in relative_path.parts:
        current = current / part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            fail(f"Missing file: {relative_path}")

        if stat.S_ISLNK(mode):
            fail(f"Symlink not allowed: {current.relative_to(ROOT)}")

    if not stat.S_ISREG(mode):
        fail(f"Not a regular file: {relative_path}")

    try:
        return current.read_bytes()
    except OSError as exc:
        fail(f"Cannot read {relative_path}: {exc}")


def validate_manifest_path(value):
    if not isinstance(value, str) or not value:
        fail(f"Invalid manifest path: {value!r}")

    path = PurePosixPath(value)

    if (
        "\\" in value
        or "\x00" in value
        or path.is_absolute()
        or path.as_posix() != value
        or any(part in ("", ".", "..") for part in value.split("/"))
    ):
        fail(f"Unsafe manifest path: {value!r}")

    if value in (str(MANIFEST), str(CHECKSUMS)):
        fail(f"Reserved path in manifest: {value}")

    return path


def parse_checksums(raw):
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        fail("SHA256SUMS is not valid UTF-8")

    entries = {}

    for number, line in enumerate(lines, 1):
        match = re.fullmatch(r"([0-9a-f]{64}) ([ *])(.+)", line)
        if not match:
            fail(f"Malformed SHA256SUMS line {number}")

        digest, _, filename = match.groups()

        if filename in entries:
            fail(f"Duplicate checksum entry: {filename}")

        entries[filename] = digest

    return entries


def reject_json_constant(value):
    fail(f"Invalid JSON constant: {value}")


def reject_duplicate_keys(pairs):
    result = {}

    for key, value in pairs:
        if key in result:
            fail(f"Duplicate JSON key: {key!r}")
        result[key] = value

    return result


def main():
    manifest_raw = read_regular_file(MANIFEST)
    checksums_raw = read_regular_file(CHECKSUMS)

    try:
        manifest = json.loads(
            manifest_raw,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_json_constant,
        )
    except (UnicodeDecodeError, ValueError) as exc:
        fail(f"Invalid manifest JSON: {exc}")

    if not isinstance(manifest, dict):
        fail("Manifest top level must be an object")

    if manifest.get("format") != EXPECTED_FORMAT:
        fail("Unexpected manifest format")

    if manifest.get("pap_version") != EXPECTED_PAP_VERSION:
        fail("Unexpected PAP version")

    source = manifest.get("source")
    if not isinstance(source, dict):
        fail("Manifest source must be an object")

    if not isinstance(source.get("repository"), str) or not source["repository"]:
        fail("Invalid source repository")

    if not isinstance(source.get("commit"), str) or not COMMIT_RE.fullmatch(source["commit"]):
        fail("Invalid source commit")

    files = manifest.get("files")
    if not isinstance(files, list):
        fail("Manifest files must be an array")

    manifest_entries = {}
    for index, item in enumerate(files):
        if not isinstance(item, dict):
            fail(f"Manifest entry {index} must be an object")

        if set(item) != {"path", "size", "sha256"}:
            fail(f"Unexpected fields in manifest entry {index}")

        path = validate_manifest_path(item["path"])

        if item["path"] in manifest_entries:
            fail(f"Duplicate manifest path: {item['path']}")

        size = item["size"]
        digest = item["sha256"]

        if type(size) is not int or size < 0:
            fail(f"Invalid size for {path}")

        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            fail(f"Invalid SHA-256 for {path}")

        manifest_entries[item["path"]] = (path, size, digest)

    checksum_entries = parse_checksums(checksums_raw)

    expected_checksum_paths = set(manifest_entries) | {str(MANIFEST)}
    actual_checksum_paths = set(checksum_entries)

    missing = expected_checksum_paths - actual_checksum_paths
    extra = actual_checksum_paths - expected_checksum_paths

    if missing:
        fail(f"Missing checksum entries: {sorted(missing)}")
    if extra:
        fail(f"Unexpected checksum entries: {sorted(extra)}")

    verified = 0

    for name, (path, expected_size, expected_digest) in manifest_entries.items():
        content = read_regular_file(path)

        if len(content) != expected_size:
            fail(f"Size mismatch: {name}")

        actual_digest = hashlib.sha256(content).hexdigest()

        if actual_digest != expected_digest:
            fail(f"Manifest SHA-256 mismatch: {name}")

        if checksum_entries[name] != actual_digest:
            fail(f"SHA256SUMS mismatch: {name}")

        verified += 1

    manifest_digest = hashlib.sha256(manifest_raw).hexdigest()
    if checksum_entries[str(MANIFEST)] != manifest_digest:
        fail(f"SHA256SUMS mismatch: {MANIFEST}")

    print(f"OK: verified {verified} snapshot files")
    print("OK: manifest checksum verified")
    print("OK: checksum inventory matches manifest")
    print("OK: no unsafe paths or symlinks detected")


if __name__ == "__main__":
    try:
        main()
    except VerificationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
    except OSError as exc:
        print(f"ERROR: filesystem operation failed: {exc}", file=sys.stderr)
        sys.exit(1)
