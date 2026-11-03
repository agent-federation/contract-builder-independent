# PAP v0.1 — Independent Python Implementation Brief v3

**Purpose:** Develop an independently implemented, auditable PAP v0.1 verifier in Python within the owner-approved Phase 2b scope.

**Status:** Active implementation brief
**Supersedes:** `AGENT_BRIEF_v2.md` for current implementation instructions
**Historical record:** `AGENT_BRIEF_v2.md` must be retained unchanged
**Normative baseline:** Frozen PAP v0.1 handoff snapshot
**Normative source commit:** `c6ee64416c91ab56f9d8270114c8f8a8b9d2f608`
**RFC blob:** `b23e18a04fe530c76cf74ffc2f41eed083c45e10`
**Owner authorization:** ODR-PAP-002, approved 2026-11-02
**Implementation language:** Python

---

## 1. Mission

Develop an independent Python implementation of the PAP v0.1 verifier.

This is an engineering and conformance exercise, not a documentation exercise.

The objective is to determine whether a second implementation, developed independently from the normative specification and published test corpus, can correctly evaluate PAP packages and produce explainable, reproducible results.

The implementation must be independently designed and written. It must not reuse, inspect, derive from, or be guided by the first verifier's implementation or its observed behavior.

The deliverable must include:

1. A functioning Python verifier CLI.
2. Independent implementation source code.
3. Automated tests exercising actual verification behavior.
4. A reproducible conformance runner for the approved Phase 2b corpus.
5. Machine-readable execution results.
6. Implementation and conformance documentation.
7. Explicit limitations and unresolved normative questions.

A stub, placeholder CLI, hardcoded verdict generator, or corpus-only result emitter is not an implementation.

## 2. Authority and scope

### 2.1 Normative authority

The frozen PAP v0.1 handoff snapshot is the authorized normative implementation input.

The normative RFC takes precedence over this brief.

This brief defines project scope and implementation instructions. It does not amend the RFC or introduce new normative PAP requirements.

The owner-approved scope decision is:

`ODR-PAP-002 — Phase 2b Scope and Authorization`

Approval reference:

https://github.com/agent-federation/contract-builder/issues/62#issuecomment-6586872238

The ODR authorizes the expanded project-level Phase 2b scope described below. It does not amend RFC §14.

### 2.2 Approved Phase 2b corpus

The approved Tier A candidate set is:

- F01–F10
- F14
- F19
- F20–F55
- F57–F61

These cases are in scope for Phase 2b implementation and reporting.

### 2.3 Excluded Tier B corpus

The following cases are outside Phase 2b:

- F11–F13
- F15–F18
- F56

Do not implement Tier B requirements merely to increase the number of passing cases.

Do not claim Phase 2b completion requires Tier B functionality.

Tier B cases may be represented in reports as explicitly out of scope or not executed. They must never be silently omitted or represented as passing.

### 2.4 RFC §14 must remain distinct

RFC §14 defines implementation step 2b narrowly as:

- digest-integrity;
- source-quote;
- relation-consistency;
- its stated unsigned-case exit condition, including F44–F46 and no producer imports.

The expanded Phase 2b scope in ODR-PAP-002 is a project-level implementation decision.

Do not describe the expanded scope as the literal meaning of RFC §14 or as a normative amendment to PAP v0.1.

### 2.5 Explicit exclusions

Phase 2b completion must not be represented as:

- Full PAP v0.1 conformance while Tier B remains outside scope.
- Independent interoperability.
- Gate 3 completion.
- Proof of unresolved dependency-integrity semantics.
- A normative extension of PAP v0.1.

Gate 3 remains OPEN and requires a separate owner-authorized cross-implementation comparison.

---

## 3. Independence requirements

Independence is a mandatory property of this experiment.

Treat the frozen handoff snapshot as the complete authorized normative implementation input.

### 3.1 Permitted inputs

You MAY use:

- The frozen normative RFC and appendices.
- Published schemas.
- Published fixtures and conformance cases.
- Handoff documentation included in the snapshot.
- This implementation brief.
- The exact owner decision ODR-PAP-002, solely to understand the authorized project scope.
- Standard Python documentation.
- Standard language libraries and independently selected dependencies.
- Your own implementation decisions, architecture, tests, and diagnostics.

### 3.2 Prohibited inputs

You MUST NOT inspect, access, copy, import, or derive implementation behavior from:

- The first verifier's source code.
- The first verifier's tests or test utilities.
- The first implementation's reports or `results.json`.
- Its implementation plans, traceability matrices, or internal design documents.
- Its execution outputs, logs, or observed verdicts.
- Its branches, commits, pull requests, code review comments, or discussions.
- Any previous failed implementation that used or derived from the first verifier.
- Any other implementation artifact that could serve as an implementation oracle.

Do not query the first implementation to discover expected behavior.

Do not use the first implementation to resolve ambiguity.

Do not compare Python outputs with another implementation before the freeze and explicit Gate 3 authorization.

### 3.3 Independence is not just code reuse prevention

Do not infer hidden requirements from another implementation's behavior.

Do not copy test cases or expected outputs that are not part of the authorized frozen corpus.

Do not adapt implementation logic to match another verifier.

If the specification is ambiguous, record the ambiguity and its impact. Do not guess based on another implementation.

The Python implementation must be explainable entirely through its own source, tests, the frozen normative materials, and approved project decisions.

---

## 4. Frozen snapshot policy

The normative handoff snapshot is frozen.

The following must not be modified or regenerated:

- `snapshot/manifest.json`
- `snapshot/SHA256SUMS`
- `snapshot/source-provenance.md`
- Manifest-listed schemas and fixtures.
- The normative RFC included in the snapshot.

`snapshot/generate.py` is intentionally disabled.

Do not restore or reimplement recursive snapshot generation.

Do not modify normative files to make implementation easier or to make tests pass.

Before implementation work, run:

`python3 tools/verify_snapshot.py`

Run it again before declaring Phase 2b complete.

The verifier is read-only. A failed integrity check must be investigated, not repaired by regenerating the snapshot.

Implementation code, build files, tests, reports, and implementation documentation may exist outside the frozen inventory.

See `docs/independent-implementation/snapshot-integrity.md` for the integrity model and its limitations.

---

## 5. Required functionality

### 5.1 Verifier CLI

Implement the mandatory CLI functionality specified by the normative RFC, including:

- `verify`
- `inspect`
- `explain`

Follow RFC §9 and §13.1 for applicable command behavior, options, stream discipline, exit codes, and determinism requirements.

Do not invent normative CLI behavior where the RFC is silent.

### 5.2 `inspect` and `explain`

Both commands are included in Phase 2b.

Implement and test their documented local behavior.

However, exact document-shape equality between independent implementations is NOT a Phase 2b conformance requirement.

RFC §13.1 explicitly places the `inspect` and `explain` document shapes outside the mandatory v0.1 conformance subset until stage 2.

Therefore:

- Implement the documented CLI functionality.
- Test it locally against the applicable specification.
- Preserve deterministic behavior where required.
- Do not invent a cross-implementation equality contract.
- Identify any additional output comparison as implementation-specific or proposed behavior.

### 5.3 Core security and verification invariants

The following principles are mandatory:

- Producer claims are not verifier evidence.
- The verifier must not execute producer or profile code.
- Verification must not require network access.
- Required checks that are not evaluated must never produce `PASS`.
- `FAIL` means an evaluated condition was disproven or invalid.
- `INCOMPLETE` means required evaluation could not be completed.
- `UNSUPPORTED` means the implementation does not support the required operation.
- Coverage and verdict are separate dimensions.
- `coverage.full: true` means all required checks or dimensions were evaluated, even if one or more evaluated checks failed.
- Successful signature verification does not by itself establish signer trust.
- Evidence provenance, freshness, and validity must not be conflated.
- Resource limits must be enforced, not merely documented.

Preserve the distinction between:

- Identity.
- Authority.
- Authorization.
- Acceptance.
- Semantic truth.
- Evidence.
- Conformance.
- Temporal validity.

Do not simplify security requirements for convenience.

If a required operation cannot be implemented safely, report the limitation rather than silently weakening it.

---

## 6. Dependency-integrity ambiguity

Dependency-integrity semantics remain unresolved.

RFC §5.2 identifies dependency records containing a name, version, and integrity value. It does not establish a sufficiently precise Python-specific acquisition, pinning, and integrity-verification procedure for an independent implementation to claim a particular algorithm as normative.

The Python implementation must preserve this distinction.

Requirements:

1. Proceed with unrelated approved Tier A work.
2. Do not silently invent normative dependency-integrity semantics.
3. Any provisional behavior must be explicitly documented as provisional.
4. An implementation-specific metadata check must not be reported as proof of RFC-defined dependency integrity.
5. Do not mark the unresolved conformance requirement successfully satisfied merely because provisional behavior passes.
6. Keep the unresolved requirement visible in the implementation report and machine-readable results.

A separate normative clarification is required before claiming complete conformance for dependency-integrity behavior.

Do not resolve this ambiguity by consulting the first verifier.

---

## 7. Conformance runner and results

Produce a reproducible runner for the approved Phase 2b corpus.

The runner must evaluate actual implementation behavior. It must not emit fabricated, hardcoded, or inferred results.

### 7.1 Case coverage

Every F01–F61 case must have an explicit record in the reporting output.

For each case, distinguish:

- In-scope and executed.
- In-scope but not executed.
- Out of scope for Phase 2b.
- Execution error.
- Unsupported behavior.
- Actual verifier verdict.
- Expected corpus outcome.
- Expected-versus-actual comparison.

Tier B cases must be clearly marked out of scope. Their presence in the report does not make them Phase 2b requirements.

Do not report an unexecuted, skipped, errored, or unsupported case as passing.

### 7.2 `results.json`

`results.json` is an implementation-level runner/reporting artifact.

It is not a PAP v0.1 normative schema.

The report must distinguish at least:

- Case ID.
- Scope classification.
- Execution status.
- Expected outcome.
- Actual verifier verdict.
- Expected-versus-actual conformance result.
- Coverage.
- Relevant implementation check or module.
- Test or execution reference.
- Diagnostic explanation.
- Known limitations.
- Unresolved normative requirements.

Do not collapse execution status, verifier verdict, and conformance comparison into one field.

Do not claim that the report format itself is normative PAP behavior.

### 7.3 Honest reporting

Do not optimize for the number of `PASS` results.

An honest `INCOMPLETE`, `UNSUPPORTED`, or `NOT_EXECUTED` is preferable to an incorrect `PASS`.

Do not modify fixtures or expected corpus outcomes.

Do not omit cases to improve reported coverage.

---

## 8. Implementation workflow

Work incrementally on the dedicated Python implementation branch.

### Phase 0 — Baseline confirmation

Before substantive implementation:

1. Confirm the repository and branch.
2. Confirm the frozen snapshot source commit.
3. Run the snapshot integrity verifier.
4. Inspect the normative RFC, schemas, fixtures, and approved Tier A cases.
5. Identify relevant CLI requirements.
6. Identify security-sensitive requirements and resource limits.
7. Record missing or ambiguous inputs.

Produce a concise baseline report.

Do not modify normative files.

### Phase 1 — Python implementation plan

Produce a Python-specific implementation plan covering:

- Module architecture.
- Package parsing and validation strategy.
- Mapping from normative RFC sections to implementation modules.
- Mapping of approved Tier A cases to planned checks and tests.
- CLI commands and output strategy.
- Security and resource-limit strategy.
- Dependency list and rationale.
- Error handling and diagnostics.
- Test architecture.
- Runner and `results.json` design.
- Major technical risks and unresolved ambiguities.

Explicitly describe how the implementation preserves the verdict and coverage distinctions.

Do not use the first verifier as an architectural reference.

### Phase 2 — Working vertical slice

Implement a minimal but genuinely functional verifier.

The first vertical slice must:

1. Read a real PAP package from disk.
2. Parse and validate its structure.
3. Perform actual verification operations.
4. Produce a meaningful machine-readable result.
5. Provide useful diagnostics.
6. Exit with appropriate status codes.
7. Include automated tests.

At minimum, demonstrate:

- One valid input that passes implemented checks.
- One modified or invalid input that fails an implemented check.
- One case where missing or unevaluated evidence does not become `PASS`.

These must exercise actual implementation logic.

Clearly identify what the vertical slice does and does not evaluate.

Passing the implemented checks does not authorize an overall PASS
while any required check remains unevaluated. The overall verdict
must remain INCOMPLETE (or UNSUPPORTED where applicable) until all
required checks have been evaluated.

After completing the slice:

- Run tests.
- Record actual output.
- Commit the working implementation.
- Report implemented checks and limitations.
- Request owner review before broadening implementation further.

### Phase 3 — Incremental Tier A implementation

Implement the remaining approved Tier A requirements incrementally.

For each requirement:

1. Identify its normative source.
2. Implement the required behavior.
3. Add or update tests.
4. Run relevant tests.
5. Record actual results.
6. Explain unsupported or incomplete behavior.

Do not implement Tier B merely to increase coverage.

Keep unresolved normative questions visible.

### Phase 4 — Freeze and report

Before declaring Phase 2b complete:

1. Run the complete test suite.
2. Run the complete approved Tier A corpus.
3. Produce explicit F01–F61 records.
4. Record the exact source commit.
5. Freeze implementation and results.
6. Run the snapshot integrity verifier.
7. Produce the implementation and conformance report.
8. Document limitations and unresolved requirements.

Do not inspect or compare against the first verifier before this freeze.

The implementation and results must be immutable at the point of handoff for a later, separately authorized comparison.

---

## 9. Security and environmental assumptions

The implementation must enforce the normative security requirements and document any implementation-defined assumptions.

In particular:

- No network access during verification.
- No execution of producer or profile code.
- Resource limits must be enforced.
- Required unevaluated checks must never yield `PASS`.
- Verdict and coverage must remain distinct.
- Signature validity and signer trust must remain distinct.
- Parent-component symlink handling must be explicitly addressed.
- Directory-entry safety and resource limits must be explicitly documented.
- Errors must not silently degrade into successful verification.

Do not claim a security property that the implementation does not enforce.

If a requirement cannot be implemented safely, document the exact limitation and its effect on conformance.

---

## 10. Acceptance criteria

Phase 2b completion requires all of the following.

### Functional

- The CLI reads and processes actual PAP packages.
- Verification behavior is driven by package contents.
- Required `verify`, `inspect`, and `explain` functionality is implemented.
- Tests demonstrate actual positive and negative verification behavior.
- Diagnostics identify relevant verification outcomes.
- Exit codes follow the applicable normative contract.
- No hardcoded verdicts or fabricated results are used.

### Correctness

- No required unevaluated check can produce `PASS`.
- Verdict distinctions are preserved.
- Coverage is independent of verdict.
- Security and resource constraints are enforced.
- Normative requirements are not modified.
- Unresolved dependency-integrity semantics remain explicitly unresolved.

### Tier A conformance

- Every approved Tier A case has an explicit execution result.
- Actual and expected outcomes are compared.
- Skipped, errored, and unsupported cases are not reported as passing.
- Known gaps and limitations are documented.
- Tier B cases are explicitly identified as outside Phase 2b scope.

### Reproducibility

- The runner can be executed reproducibly.
- The exact implementation commit is recorded.
- Results are traceable to actual execution.
- Snapshot integrity is verified.
- The frozen normative snapshot remains unchanged.

### Independence

- No first-verifier implementation artifacts were inspected or reused.
- The implementation is based on the authorized frozen handoff.
- The source commit is recorded.
- The implementation and results are frozen before any cross-implementation comparison.

Phase 2b completion does not establish full PAP v0.1 conformance or interoperability.

It does not complete Gate 3.

---

## 11. Repository hygiene

Keep implementation artifacts separate from normative materials.

Suggested structure:

```text
docs/
  independent-implementation/
    AGENT_BRIEF.md
    AGENT_BRIEF_v2.md
    AGENT_BRIEF_v3.md
    implementation-plan.md
    implementation-report.md

src/
tests/
results/
  results.json
```

Adapt the structure where technically justified.

Do not modify or delete historical briefs.

Do not modify the frozen snapshot.

Use small, reviewable commits. Each meaningful implementation stage should have corresponding tests and a report of actual results.

Do not publish a release or merge implementation work without separate owner authorization.

---

## 12. Stop conditions and honest reporting

If the task is larger than the available time or context:

- Stop at the last genuinely working state.
- Commit the working state.
- Report what is implemented.
- Report what remains unimplemented.
- Identify the exact blocker.
- Recommend the next concrete step.

Do not replace missing implementation with a stub and call it complete.

Do not mark all cases `UNSUPPORTED` and present that as a completed verifier.

Do not fabricate tests, execution results, coverage, or conformance.

A partial but real implementation is a valid engineering outcome.

A placeholder presented as a completed verifier is not.

---

## 13. Required first response

After receiving this brief, the first response must contain only:

1. Confirmation of the repository and branch.
2. Confirmation of the frozen normative baseline.
3. Summary of normative materials inspected.
4. Summary of the approved Phase 2b scope.
5. Proposed Python architecture.
6. Tier A implementation plan.
7. F01–F61 reporting strategy, including explicit Tier B exclusion.
8. Main technical risks and unresolved questions.
9. Proposed milestones.

Do not inspect prohibited first-verifier artifacts.

Do not modify normative files or the frozen snapshot.

Do not claim implementation or conformance before actual code and tests exist.

---

**Final objective:** Deliver an independently developed, reproducible, auditable Python PAP v0.1 verifier within the owner-approved Phase 2b scope, while preserving the normative baseline, honest conformance reporting, and strict independence from the first implementation.
