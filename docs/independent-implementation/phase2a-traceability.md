# Phase 2a traceability matrix (implemented requirements)

| Requirement | RFC clause | Module | Case assertion | Test |
|---|---|---|---|---|
| I-JSON + JCS canonicalization | §4.10, §5.3.1, E.9 | canonical.py | F34 | test_canonical |
| Domain-separated SHA-256 | §5.2, E.6 | digest.py | F01 identity | test_canonical |
| Path grammar and safety | §4.3.1–§4.3.2, T1–T4 | pathing.py | F22–F24 | test_pathing |
| Bounded reads | §4.3.4, §9.11 | pathing.py, limits.py | F35 | (manual) |
| Manifest validation | Appendix A, §4.4 | manifest.py | F21, F29, F30, F53 | (manual) |
| Package identity | §5.3, E.1 | engine.py | F01, F34 | test_engine |
| Artifact digest | §5.4, E.2 | engine.py | F02 | test_engine |
| Source digest | §5.5, E.2 | engine.py | F03 | (manual) |
| Input digest | §5.6, E.5 | engine.py | F04 | (manual) |
| Verdict precedence | §7.4 | engine.py | F01, F02, F27 | test_engine |
| Coverage | §7.5 | engine.py | F02, F27 | test_engine |
| Required check absent → INCOMPLETE | §8.1, §8.8 | engine.py | F44, F45 | (manual) |
| CLI exit codes | §9.7 | cli.py | F01–F02 | (manual) |