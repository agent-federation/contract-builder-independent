# Proposal: language-neutral verifier security invariants

**Status:** proposed for owner/spec review; not normative and not part of PAP v0.1.

## Candidate normative invariants

| ID | Candidate | Rationale | Suggested normative expression |
|---|---|---|---|
| CORE-SEC-01 | No false PASS under incomplete required evaluation | Verdict semantics are central interoperability behavior. | A verifier MUST NOT return PASS if any required check/dimension was not evaluated, is unsupported, or is incomplete. |
| CORE-SEC-02 | Integrity before interpretation | Unverified claim bytes must not influence results as trusted data. | A verifier MUST verify declared byte length and digest before parsing or using claim document contents as claim data. |
| CORE-SEC-03 | Bounded processing | Resource exhaustion is a protocol-level DoS risk. | A verifier MUST enforce applicable normative limits before work/allocation would exceed them. |
| CORE-SEC-04 | Explicit incomplete traversal | Partial enumeration can omit content and cause divergent results. | If required enumeration cannot complete due to I/O or limits, the verifier MUST report incomplete evaluation and MUST NOT report the scan complete. |
| CORE-SEC-05 | No execution of package content | Package inputs are data, not executable authority. | A verifier MUST NOT execute, import, evaluate, or run package-supplied content during verification. |
| CORE-SEC-06 | Deterministic visible ordering | Reproducibility supports interoperability. | Collections without semantic order MUST be emitted in a deterministic order defined by the specification. |
| CORE-SEC-07 | Fail-closed required validation | Missing/broken validators cannot mean successful validation. | Failure to load or execute a required validation mechanism MUST produce a non-PASS result and explicit diagnostic. |

## Likely implementation guidance, not normative text

- `openat`, `O_NOFOLLOW`, file descriptors, or equivalent APIs;
- exact traversal algorithm (`scandir`, iterator, descriptor walk);
- dependency lock format/package manager;
- metadata-file hashing convention;
- test framework, fuzzing engine, benchmark tool, coverage threshold;
- numeric limits unless already fixed normatively.

## Questions for owner/spec decision

1. Does the RFC promise resistance to concurrent filesystem mutation, or only path/symlink safety for a stable package tree?
2. Is a package-root symlink rejected, resolved, or outside verifier responsibility?
3. Are hard links in the threat model? If so, what behavior is required?
4. Does every directory entry count toward traversal limits, including directories and entries that cannot be stat'ed?
5. What report status/diagnostic is required when enumeration is incomplete?
6. Which report collections have normative ordering?
7. Is unavailable required schema/validator an internal verifier failure, package failure, or distinct unsupported state? It must not be PASS, but exact classification should be specified.

## Promotion rule

Do not copy proposals into the normative RFC merely because one implementation needed them. For each candidate, identify current text/gap, provide a counterexample, assess compatibility, define observable report/verdict behavior, obtain maintainer approval, and add normative vectors/fixtures before requiring conformance.

Until then, this file is proposal only.
