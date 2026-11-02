# PAP v0.1 Independent Implementation — Phase 2a Report

## Status
Phase 2a complete for Tier A vertical slice. Implemented a working `pap verify` CLI with JSON/text output and exit codes. No hardcoded verdicts or case-specific shortcuts.

## Implemented
- Strict I-JSON parsing and RFC 8785 JCS canonicalization (`canonical.py`).
- Domain-separated SHA-256, framing, LF normalization (`digest.py`).
- Path grammar, fd-relative safe opening, bounded reads (`pathing.py`).
- Resource limits (`limits.py`).
- Manifest parsing/validation and cross-field invariants (`manifest.py`).
- Trust policy parsing/validation and freshness (`trust_policy.py`).
- Package, artifact, source, input, checker, and report identities (`engine.py`, `identities.py`, `report.py`).
- Three mechanical checks with records and witnesses (`engine.py`).
- Dimension statuses, verdict precedence, coverage (`engine.py`).
- CLI `verify`, `--version`, `--help`, `--now`, `--format` (`cli.py`).

## Verification
- F01: PASS, coverage.full=true, packageIdentity matches E.1.
- F02: FAIL, coverage.full=true.
- F27: INCOMPLETE, coverage.full=false.
- Unit tests: 15 passing (canonical, pathing, engine).

## Security assumption: package-root parent components
The initial package root is opened with `os.open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)` followed by `fstat` on the same descriptor. `O_NOFOLLOW` prevents following a symlink for the final root component, but it does **not** protect against symlink substitution in parent components of the supplied path (for example `/tmp/link-to-package` where an ancestor directory is a symlink, or a race that replaces an ancestor). Those parent components are resolved by the operating system before `open()` is called. This is a stated trust assumption: the caller-supplied package path and its parent directories are trusted to be stable and not attacker-controlled. A local attacker with write access to an ancestor directory can redirect the root open. This residual risk is documented and is not claimed to be fully protected by `O_NOFOLLOW`.

## Corrective review fixes applied
- Source quote extraction uses byte offsets per RFC §8.5 (added multibyte regression test).
- `read_file_bounded()` now handles exact EOF at limit.
- Filesystem errors preserve distinct diagnostic codes.
- Collection limits enforced before processing.
- Manifest nesting/string limits map to `pap.package.limit-exceeded`.
- `implementationDigest` now derived from actual source closure.
- Added CLI integration and regression tests.

## Third corrective pass
- Isolated claim parsing state per iteration.
- Enforced aggregate `payloadFiles` limit.
- Implemented checker closure including launcher, source files, runtime schemas, and dependency records.
- Bounded trust-policy reads.
- Guaranteed root FD closure.
- Corrected directory-scan failure semantics.
- Added regression tests for all findings.

## Known limitations
- `inspect` and `explain` not implemented (Phase 2c).
- Tier B signatures not implemented (Phase 2d).
- Full F01–F61 conformance run not yet executed (Phase 3).
- `effectiveLimits` reported only when lowered.
- Human-review handling is basic and will be expanded in Phase 2d.
- Extension handling treats all extensions as ignored unless critical.
- Ed25519 canonical-S enforcement not yet relevant (no signatures in Tier A).

## Next step
Await review and explicit approval before Phase 2b.