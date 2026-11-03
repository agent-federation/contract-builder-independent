# Blind Python implementation — round retrospective

**Status:** reconstructed process retrospective, not a complete transcript.
**Subject:** Phase 2a blind implementation in `agent-federation/contract-builder-independent-py`.
**Evidence:** commit SHAs and round summaries pasted by the owner, plus final branch reports. Exact prompt text and every intermediate diff were not available; this is not a verbatim turn log.

## Executive observation

The run required roughly ten prompt/fix rounds rather than one successful shot. The agent could implement and remediate, but the initial instructions did not force enough up-front security analysis, complete dependency accounting, and evidence discipline. Most quality gains followed specific findings translated into tests.

The lesson for v2: **front-load constraints and threat modelling, not implementation recipes**. The goal is not to prescribe algorithms; it is to require the agent to discover and demonstrate the safety properties.

## Reconstructed milestones

| Stage | Reported commit/state | Learning |
|---|---|---|
| Initial Phase 2a implementation | `5a1daa4fa3c7e2e0002a87614a7e41038db3a03b` | Independent package, JCS/digest/identity primitives, package reader, manifest/claim validation, report foundations; 20 tests. |
| First remediation checkpoint | `793d576e06309a2b1ee1e0eb495ba344fcd85a9a` | P1/P2 findings addressed; 27 tests; snapshot verified; clean tree. |
| Bounded traversal + initial dependency closure | `ad3677bec21023e836feb92d4a31c6fae4983962` | Incremental `os.scandir()`, depth/entry bounds, incomplete-scan reporting; dependency closure; 29 tests. |
| Versioned dependency lock | `fa73344b61090132a925240c653fb182c9dd88c8` | Added lock comparison, observable mismatch, I/O failure tests; 32 tests. |
| Direct dependency closure correction | `c7f148c78af57cf221d72514bf193c2a66afc68f` | Added `packaging` as a direct runtime root and to lock/digest. |
| Report synchronization | `76c06b09e07661500cc3a2be9829b68e56b44506` | Report sync; 35 tests reported. |
| Phase 2a dependency classification | `8435200b8801a7b4d92bba0d2183d5f183667b27` | Removed unused `cryptography` from Phase 2a runtime; moved to `requirements-phase2d.txt`; 36 tests. |
| Report synchronization | `f32d0dd46f8c353112e229402cd28c1905f2094a` | Report-only sync; 36 tests. |
| Final report sync | `4c8fa73e72721126e79c1f382346881b7c21496d` | Report-only commit. |
| Final reported HEAD | `a4a011269e913fe9740cf78b79510d429ac589d4` | Clean tree; 433 snapshot files verified; 36 tests; diff check clean. Last sync reportedly changed reports only. |

The owner estimated about ten shots. This table captures identifiable milestones, not every conversational round. Preserve SHAs as reported; do not infer a perfect one-to-one prompt mapping.

## What the rounds reveal

### 1. The agent responds to concrete failure hypotheses

The strongest fixes followed narrow findings: fail-closed schemas; digest before claim parsing; bounded undeclared traversal; observable scan errors; dependency-lock mismatch in reports; complete direct dependency roots; and phase-specific dependency separation.

V2 should specify required properties and evidence, while asking the agent to derive the implementation.

### 2. The first pass underweighted adversarial conditions

Several issues were discovered after implementation. Require a threat model and resource-accounting table before coding.

### 3. Dependency identity was initially conflated

The model evolved from environment-derived closure to a versioned lock, then included `packaging`, then separated Phase 2d cryptography. Distinguish direct runtime roots, transitive closure, artifact integrity, and implementation identity. METADATA hashing is a local convention, not package-code integrity.

### 4. Documentation synchronization consumed rounds

Several commits were report-only. Improve this by maintaining one authoritative report, mechanically checking duplicated summaries, recording implementation and report-sync commits separately, and rerunning final verification after the last content change. A commit cannot embed its own final SHA.

### 5. Passing tests did not close the evidence gap

36 passing tests do not prove coverage, hostile filesystem resistance, or cross-platform determinism. V2 should require boundary/fault-injection/property/differential test plans and honest reporting when a technique is not used.

## Prompt changes for v2

1. Pre-implementation threat model: hostile package data, hostile filesystem state, concurrent mutation, exhaustion, parser ambiguity, dependency compromise.
2. Resource accounting: every RFC limit mapped to enforcement point and test.
3. Filesystem attack matrix: root/child symlinks, traversal, case collisions, hard links, TOCTOU, special files, permissions, disappearing entries.
4. Integrity-before-interpretation: no claim content parsed/used before byte digest verification.
5. Fail-closed required validation; never turn required unevaluated work into PASS.
6. Deterministic output ordering and repeated runs under permuted enumeration.
7. Dependency inventory separates roots, closure, versions, artifact hashes, and implementation-defined metadata.
8. Every fixture classified; no silent exclusion.
9. Normative vector expectations independent of implementation helpers.
10. Exact evidence: commands, exit status, output, commit SHA, clean-tree state.

See `docs/prompts/phase2a-blind-implementation-v2.md`.
