# PAP v0.1 — Independent Implementation Brief

## Objective

Implement an independent PAP v0.1 verifier using only the
materials contained in this repository.

The goal is an independent implementation for Gate 3 interoperability
validation, not an extension or reinterpretation of the specification.

## Normative authority

The normative source is:

- `docs/architecture/portable-assurance-package-rfc.md`

Supporting materials:

- `docs/maintainer-decision.md`
- `docs/architecture/pap-v0.1-gate1-decision-audit.md`
- `pap/schemas/`
- `pap/fixtures/`

If supporting material appears to conflict with the RFC,
do not silently resolve the conflict. Report it explicitly.

## Independence requirements

- Do not inspect or reuse the first implementation.
- Do not copy its source code, tests, internal architecture or algorithms.
- Do not access the original implementation repository's `pap/src/`
  or `pap/tests/` before implementation freeze.
- Choose your own language, architecture and implementation strategy.
- Do not treat the first implementation as an oracle.

## Conformance

- Implement the requirements of PAP v0.1 as specified.
- Run all supplied F01–F61 fixtures.
- Record the result of every case.
- Distinguish FAIL, INCOMPLETE and UNSUPPORTED.
- Never turn an unevaluated required check into PASS.
- Report ambiguities rather than inventing semantics.

## Freeze and interoperability

Before inspecting the first implementation:

1. Freeze the implementation.
2. Record the exact source commit and build environment.
3. Record results for all supplied fixtures.
4. Preserve the implementation and test results.

Only then perform field-by-field differential comparison
against the first implementation.

The purpose is to discover interoperability differences,
not to make one implementation conform to the other's behavior.

## Scope

Do not introduce new normative requirements.
Do not silently expand PAP v0.1.
Any proposed extension or ambiguity resolution must be documented
separately for owner review.
