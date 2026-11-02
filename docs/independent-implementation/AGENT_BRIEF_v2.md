# PAP v0.1 — Independent Implementation Brief v2

**Purpose:** Produce an independently developed PAP v0.1 verifier and an auditable conformance report.

**Status:** Implementation instructions.
**Normative baseline:** PAP v0.1 handoff snapshot.
**Source commit:** `93dd54387a302c680487e52b0afec3e8dde8dd02`
**Normative source commit:** `c6ee64416c91ab56f9d8270114c8f8a8b9d2f608`
**RFC blob:** `b23e18a04fe530c76cf74ffc2f41eed083c45e10`

---

## 1. Mission

Develop an independent implementation of the PAP v0.1 verifier.

This is an engineering and conformance exercise, not a documentation exercise.

The objective is to determine whether an engineer or AI coding agent, working from the normative specification and published test corpus alone, can independently implement a verifier that produces correct, explainable and reproducible results.

The implementation must not reuse, inspect or derive code from the first PAP verifier.

The final deliverable must include:

1. A functioning verifier CLI.
2. Independent implementation source code.
3. Tests demonstrating actual verification behavior.
4. A conformance runner for the published F01–F61 corpus.
5. Machine-readable results for every corpus case.
6. A clear implementation and conformance report.

A stub, placeholder CLI, hardcoded verdict generator or corpus-only result emitter is not an implementation.

## 2. Independence requirements

Treat the handoff snapshot as the complete authorized implementation input.

You MAY use:

- The normative RFC and its appendices.
- Published schemas, fixtures and conformance cases.
- The handoff documentation.
- Standard language libraries and independently selected dependencies.
- Your own implementation decisions, architecture and tests.

You MUST NOT:

- Inspect or reuse the first verifier's source code.
- Copy implementation logic from the original implementation repository.
- Use the previous failed implementation as a starting point.
- Import code from the first implementation, directly or indirectly.
- Change normative requirements to make implementation easier.
- Modify expected corpus outcomes to make tests pass.

If you discover an apparent ambiguity or contradiction in the specification, document it. Do not silently invent a normative interpretation.

**Independence is more important than implementation speed.**

## 3. Execution protocol — mandatory phases

The work is divided into phases. Do not skip phases or declare the overall task complete prematurely.

### Phase 0 — Repository and baseline inspection

Before writing code:

1. Confirm the current repository and checked-out branch.
2. Confirm the exact handoff baseline commit.
3. Inspect the RFC, schemas, fixtures and corpus.
4. Identify the required CLI behavior and output contracts.
5. Identify security-sensitive requirements and resource limits.
6. Identify dependencies and implementation risks.

Do not modify normative files.

Deliver a short baseline report confirming what was inspected and identifying any missing or ambiguous inputs.

### Phase 1 — Planning only

**Do not write implementation code in this phase.**

Produce an implementation plan containing:

- Proposed language and rationale.
- Proposed module architecture.
- Package parsing and validation strategy.
- Mapping from normative RFC sections to implementation modules.
- Mapping from F01–F61 to planned checks and tests.
- CLI commands and output strategy.
- Security and resource-limit strategy.
- Dependency list and rationale.
- Major implementation risks and unresolved ambiguities.
- A staged implementation estimate.

The plan must explicitly address the separation of:

- Identity.
- Authority.
- Authorization.
- Acceptance.
- Semantic truth.
- Evidence.
- Conformance.
- Temporal validity.

It must also explain how the implementation will preserve the distinction between:

- `PASS`
- `FAIL`
- `INCOMPLETE`
- `UNSUPPORTED`

And how it will prevent unevaluated or incomplete required checks from producing `PASS`.

**Stop after submitting the plan.**

Wait for explicit owner approval before proceeding to implementation.

### Phase 2 — Working vertical slice

After approval, implement a minimal but genuinely functional verifier.

The first vertical slice must:

1. Read a real PAP package from disk.
2. Parse and validate its structure.
3. Perform actual verification operations.
4. Produce a meaningful machine-readable result.
5. Provide useful diagnostics.
6. Exit with appropriate status codes.
7. Include automated tests.

At minimum, demonstrate:

- One valid input that passes the implemented checks.
- One modified or invalid input that fails an implemented check.
- One case where missing or unevaluated evidence does not become PASS.

These must exercise actual implementation logic. Hardcoded output, test-specific branches and fabricated results are unacceptable.

The vertical slice does not need to implement every RFC requirement. It must clearly identify what it does and does not evaluate.

After completing this phase:

- Run the tests.
- Record their output.
- Commit the implementation.
- Report implemented checks and known limitations.
- Wait for review before expanding scope.

### Phase 3 — Incremental conformance implementation

Implement the remaining requirements incrementally.

For every requirement:

1. Identify the normative source.
2. Implement the required behavior.
3. Add or update tests.
4. Run the relevant tests.
5. Record the actual result.
6. Explain any unsupported or incomplete behavior.

Work through the published F01–F61 corpus.

Do not optimize for the number of PASS results.

An honest `INCOMPLETE` or `UNSUPPORTED` is preferable to an incorrect `PASS`.

Do not modify corpus fixtures or expected outcomes.

### Phase 4 — Freeze and report

Before declaring the implementation ready for independent comparison:

1. Run the complete test suite.
2. Run the complete F01–F61 corpus.
3. Record the exact source commit.
4. Freeze the implementation.
5. Freeze the conformance results.
6. Produce a final report.

Do not inspect or compare against the first verifier before this freeze.

The implementation and results must be immutable at the point of handoff for comparison.

---

## 4. Normative and security invariants

The RFC is authoritative. This brief does not add or replace normative requirements.

Pay particular attention to these principles:

- Producer claims are not verifier evidence.
- The verifier must not execute producer or profile code.
- Verification must not require network access.
- Required checks that are not evaluated must never produce PASS.
- `FAIL` means an evaluated condition was disproven or invalid.
- `INCOMPLETE` means required evaluation could not be completed.
- `UNSUPPORTED` means the implementation does not support the required operation.
- Coverage and verdict are separate dimensions.
- `coverage.full: true` means all required checks or dimensions were evaluated, even if one or more evaluated checks failed.
- A successful signature verification does not, by itself, establish signer trust.
- Evidence provenance, freshness and validity must not be conflated.
- Resource limits must be enforced, not merely documented.

Do not simplify security requirements for convenience.

If a requirement cannot be implemented safely, report the limitation rather than silently weakening it.

## 5. Conformance result format

Produce a machine-readable `results.json`.

Every F01–F61 case must have an explicit result.

Each record should contain, where applicable:

- Case ID.
- Expected outcome from the published corpus.
- Actual outcome.
- Whether the case was executed.
- Whether the expected and actual outcomes match.
- Relevant implementation check or module.
- Test or execution reference.
- Diagnostic explanation.
- Any known limitation.

Do not omit cases.

Do not report an unexecuted case as passing.

Do not report an unsupported case as passing merely because the expected outcome could not be evaluated.

The report must distinguish:

- Case execution status.
- Actual verifier verdict.
- Expected-versus-actual conformance result.

These are different concepts and must not be collapsed into one field.

## 6. Acceptance criteria

The following are mandatory for claiming a functioning independent verifier:

### Functional

- The CLI reads and processes actual packages.
- Verification behavior is driven by package contents.
- At least one real positive and one real negative verification test pass.
- Diagnostics identify the relevant verification outcome.
- Exit codes are consistent with the normative CLI contract.
- The implementation does not rely on hardcoded verdicts.

### Correctness

- No required unevaluated check can produce PASS.
- The implementation preserves the normative verdict distinctions.
- Security and resource constraints are enforced.
- The implementation does not change normative requirements.
- Tests demonstrate behavior, rather than merely testing that commands execute.

### Conformance

- All F01–F61 cases are represented in `results.json`.
- Every result is traceable to an actual execution or explicitly marked as not executed.
- Expected and actual outcomes are compared.
- Known gaps and unsupported features are documented.

### Independence

- No first-verifier code was inspected or reused.
- The implementation is based on the handoff snapshot.
- The source commit is recorded.
- The implementation is frozen before cross-implementation comparison.

**Passing the published corpus alone does not establish complete conformance or interoperability.**

Do not claim Gate 3 completion. Gate 3 requires independent verification and field-by-field comparison against the first implementation.

## 7. Repository hygiene

Work on a dedicated branch created from the clean handoff baseline.

Do not develop directly on `main`.

Do not rewrite or modify the original handoff snapshot.

Keep implementation code, tests, results and reports clearly separated.

Suggested structure (adapt as appropriate):

```text
docs/
  independent-implementation/
    AGENT_BRIEF_v2.md
    implementation-plan.md
    implementation-report.md

src/
tests/
results/
  results.json
```

Do not create unnecessary scaffolding before the plan is approved.

Use small, reviewable commits. Each implementation phase must have a corresponding commit and report.

## 8. Stop conditions and honest reporting

If the task is larger than the available time or context:

- Stop at the last genuinely working state.
- Commit the working state.
- Report what is implemented.
- Report what remains unimplemented.
- Identify the exact blocker.
- Recommend the next concrete step.

Do not replace missing implementation with a stub and call it complete.

Do not mark all cases `UNSUPPORTED` and present that as a completed verifier.

Do not fabricate tests, execution results, coverage or conformance.

A partial but real implementation is a valid engineering outcome.

A placeholder presented as a completed implementation is not.

## 9. Required first response

Your first response after receiving this brief must contain only:

1. Confirmation of the repository and baseline commit.
2. Summary of the normative materials inspected.
3. Proposed architecture.
4. Implementation plan.
5. F01–F61 coverage strategy.
6. Main technical risks and unresolved questions.
7. Estimated effort and proposed milestones.

**Do not modify files or write implementation code until the owner explicitly approves Phase 1.**

---

**Final objective:** Deliver an independently developed, reproducible and auditable PAP v0.1 verifier — not merely a CLI-shaped placeholder or a report that looks complete.
