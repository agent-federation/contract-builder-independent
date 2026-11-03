# Frozen Snapshot Integrity

## Purpose

The PAP v0.1 independent implementation repositories contain a frozen normative snapshot. Its contents must remain verifiable without regenerating or modifying the snapshot.

`tools/verify_snapshot.py` is a read-only integrity verifier. It uses only the Python standard library and performs no network access.

## Trust and scope

The verifier checks the local snapshot against two integrity records:

- `snapshot/manifest.json` declares each snapshot file's relative path, size, and SHA-256 digest.
- `snapshot/SHA256SUMS` contains checksums for every manifest-listed file and for `snapshot/manifest.json` itself.

The manifest identifies the source repository and source commit. The verifier validates the structure of these provenance fields but does not contact the source repository or independently establish the authenticity of that commit.

The verifier does not require every repository file to appear in the snapshot. Implementation source code, build files, reports, and independent implementation documentation may legitimately exist outside the frozen inventory.

## Checks performed

The verifier fails with a non-zero exit status if it detects:

- Invalid manifest JSON, duplicate object keys, or non-standard JSON constants.
- An unexpected manifest format or PAP version.
- Invalid source metadata or manifest entry structure.
- Duplicate, unsafe, or reserved manifest paths.
- Invalid file sizes or SHA-256 values.
- Missing files, non-regular files, or symbolic links in snapshot paths.
- File size or SHA-256 mismatches.
- Malformed, duplicate, missing, or unexpected checksum entries.
- A mismatch between the manifest checksum and its `SHA256SUMS` entry.

The checksum inventory must contain exactly the manifest-listed files plus `snapshot/manifest.json`.

The verifier does not repair files, regenerate checksums, or write to the snapshot.

## Running the verifier

From the repository root, run:

`python3 tools/verify_snapshot.py`

From another working directory, invoke the script using its absolute path or a path relative to the current directory.

The verifier locates the repository root relative to its own file location, not the current working directory.

A successful run prints verification summaries and exits with status `0`. Any detected integrity or filesystem error is reported on standard error and causes a non-zero exit status.

## Frozen snapshot policy

Do not run `snapshot/generate.py` as part of ordinary verification or implementation work.

The frozen files below are not to be regenerated or modified:

- `snapshot/manifest.json`
- `snapshot/SHA256SUMS`
- `snapshot/source-provenance.md`
- The manifest-listed schemas and fixtures.
- The normative RFC included in the snapshot.

Changes to snapshot contents require an explicit owner decision and a separately controlled snapshot update process. A failed verification must never be addressed by automatically regenerating the manifest or checksums.

## Security limitations

The verifier rejects symbolic links encountered in the path components it checks. It uses filesystem metadata checks followed by ordinary file reads. A concurrent process able to modify the checkout during verification could race those operations (a time-of-check/time-of-use, or TOCTOU, condition).

This tool is intended to verify a static local checkout, not to defend against an active local attacker with control over the filesystem or execution environment. The repository checkout and the verifier itself are part of the trusted computing base.

The verifier establishes consistency between the local files, manifest, and checksum inventory. It does not establish who authored those files, whether the source commit is authentic, or whether the snapshot fully represents every normative requirement.
