# Independent Python verifier — Phase 2a quality audit

**Status:** retrospective engineering audit; not normative PAP interpretation or certification.
**Subject:** `agent-federation/contract-builder-independent-py`, branch `second-001/phase1`, reported final HEAD `a4a011269e913fe9740cf78b79510d429ac589d4`.
**Basis:** implementation report, traceability/applicability matrices, security-boundary document, dependency lock, selected source (`package.py`, `report.py`) and remediation tests fetched from the implementation branch, plus verification outputs supplied by the owner.
**Limit:** source/document review, not an executed test, fuzz, benchmark, or complete independent repository review.

## Executive assessment

The experiment is a **successful feasibility demonstration, not a merge-ready or production assurance result**.

The agent independently produced a coherent Phase 2a implementation with JCS/digest primitives, package reading, schema validation, claim digest handling, report construction, resource controls, and a growing regression suite. The iterative remediation improved it materially: final owner-reported state was 36 passing tests, clean tree, and successful verification of 433 frozen snapshot files.

The key outcome is not the test count. Adversarial review exposed failure modes the initial implementation had not adequately addressed, and the agent could repair them when given specific findings. This demonstrates useful implementation/remediation capability, but also shows that the initial prompt did not sufficiently force security-first design, independent validation, and evidence discipline.

**Recommendation:** retain this implementation as experimental evidence; do not merge it into the normative repository or treat 36 passing tests as proof of conformance. Use the v2 prompt for a fresh blind implementation (preferably Rust or Go), then compare frozen implementations only after both are independently frozen.

## Evidence-backed strengths

1. **Scope discipline:** the report defers the three PAP checks, full CLI contract, trust policy, DSSE/signature verification, and inspect/explain. F52/F61 are marked deferred/partially applicable because lowered limits require trust-policy evaluation.
2. **Deterministic primitives:** JCS, digest/framing, domain separation, checker identity, normalization, and package identity vectors are reported passing.
3. **Integrity ordering corrected:** a remediation test verifies claim bytes that do not match their declared digest are not parsed as trusted claim content.
4. **Fail-closed schema handling:** tests inject manifest and claim schema-loading failures and require package integrity to fail.
5. **Bounded traversal improved:** incremental `os.scandir()`, entry/depth bounds, incomplete-scan reporting, and tests for large directories and enumeration errors were added.
6. **Dependency identity observable:** a versioned lock is compared with actual runtime closure; actual closure contributes to implementation digest; mismatch appears in report diagnostics/limitations.
7. **Evidence improved:** Phase 2a runtime dependencies are separated from future Phase 2d cryptography; reports record environment and commit references.

## Findings and residual risks

### High priority

**A1 — Filesystem race resistance is not established.** The security-boundary document explicitly acknowledges TOCTOU between `lstat` and read, and says hard links are not detected. The observed manifest path uses check-then-open (`lstat`, then `read_bytes`). Similar patterns need review for all declared files and traversal. This is not automatically a PAP conformance failure unless the RFC promises race resistance, but it is material for hostile or concurrently mutable package directories.

Follow-up: define the threat model; test symlink replacement between validation and open; consider descriptor-relative no-follow operations where supported; otherwise document the residual platform risk and do not claim race-free confinement.

**A2 — Root path canonicalization may hide caller-supplied symlink semantics.** The observed reader begins with `Path(root).resolve()`. Depending on the RFC contract, this may silently accept a symlink as the package root by resolving it before checks. Root symlink and child symlink are distinct cases.

Follow-up: settle expected root-symlink behavior and add a dedicated test.

**A3 — End-to-end resource accounting is not proven.** The implementation reports bounded manifest/payload/JSON processing and added bounded undeclared traversal. The available evidence does not establish that every allocation and traversal path is bounded before work occurs. Verify that entry counts include directories and metadata failures; depth is checked before descent; limits precede read/decode/allocation; aggregate accounting cannot overflow or be bypassed; interrupted scans remain incomplete.

### Correctness and determinism

**B1 — Date-time validation is knowingly permissive.** The limitation register says this is a basic RFC3339 check, not strict profile validation. The observed helper delegates to Python `datetime.fromisoformat`, replacing `Z`, and checks timezone plus `T`. That does not establish full RFC3339 grammar conformance.

Follow-up: derive positive/negative vectors from normative grammar, including offsets, fractions, leap-second policy, lowercase separators, invalid calendar values, and boundaries.

**B2 — Determinism evidence is limited.** Passing vectors and repeated runs do not establish stability across filesystem enumeration order, locale, timezone, platform, runtime, and dependency versions.

Follow-up: permute file creation/enumeration order, run at least two supported environments, and compare canonical report bytes and diagnostic ordering, excluding only fields the RFC declares nondeterministic.

**B3 — Report identity and verdict precedence need independent oracle tests.** The report builder constructs an identity form by removing selected fields and zeroing the identity before recomputing. This pattern is plausible, but this audit did not verify every included/excluded field against the normative definition. Coverage/verdict precedence also needs table-driven combinations of FAIL, UNSUPPORTED, INCOMPLETE, optional checks, and required dimensions.

Follow-up: use literal RFC-derived expected vectors, not the implementation's own helper to compute expected values.

### Dependency and supply-chain caveats

**C1 — METADATA SHA-256 is not package-artifact integrity.** The lock hashes installed distribution METADATA files. This is explicitly an implementation-defined provenance convention; it does not authenticate package code, wheel/sdist, or all installed files. The documentation correctly discloses that RFC v0.1 does not define Python package integrity. Never describe this as dependency-code integrity.

Follow-up: for reproducible packaging, use pinned artifacts with hashes of downloaded wheels/sdists and controlled installation. Keep this separate from PAP checker identity unless the RFC defines it.

**C2 — Lock portability is limited.** The lock comes from one installed environment, not a complete multi-platform lock. State supported Python/platform matrix and verify in clean environments; do not silently accept unexpected or missing runtime distributions.

## Test quality and coverage

36 passing tests are useful, but test count is not a coverage metric. Available evidence does not show mutation testing, branch coverage, parser/path fuzzing, property-based resource accounting, concurrent filesystem mutation tests, cross-platform determinism, or a complete end-to-end result for every Phase 2a-applicable F01–F61 case. The report itself says some claim cross-field invariants and effective-limit reporting are implemented but not directly tested.

These remain gaps, not inferred successes.

## Remediation trajectory

The initial implementation was followed by targeted rounds addressing fail-closed schema loading, claim digest-before-parse, bounded undeclared traversal, scan I/O failures, dependency-lock observability, inclusion of all direct runtime roots, and separation of Phase 2d cryptography. This is a positive remediation signal. It also proves that several critical properties were discovered only after implementation. The v2 prompt should require a threat model, resource-accounting table, and adversarial test plan **before** coding.

## Disposition

| Dimension | Assessment |
|---|---|
| Independent implementation feasibility | Demonstrated |
| Phase 2a scope discipline | Generally good; full diff not reviewed |
| Core primitive tests | Promising |
| Security hardening | Improved; filesystem race and hard-link limitations remain |
| Resource exhaustion resistance | Improved; systematic end-to-end proof absent |
| Dependency identity | Transparent but implementation-defined and limited |
| Determinism | Basic evidence only |
| Conformance | Not established by this audit |
| Merge recommendation | Do not merge on this evidence |

## Next gates

1. Preserve Python implementation unchanged as experimental evidence.
2. Run a fresh blind implementation from the frozen snapshot using the v2 prompt.
3. Require threat model, resource-accounting table, and adversarial test plan before coding.
4. Freeze source, environment, and test outputs before cross-implementation comparison.
5. Compare against normative vectors/fixtures; do not use Python as an oracle.
6. Promote only language-neutral invariants into the core RFC after owner review.
