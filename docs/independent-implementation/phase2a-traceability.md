# Phase 2a traceability matrix

| Requirement | RFC clause | Module | Case assertion | Test | Status |
|---|---|---|---|---|---|
| I-JSON + JCS canonicalization | §4.10, §5.3.1, E.9 | canonical.py | F34 | test_canonical.test_e1_package_identity, test_e9_utf16_key_order, test_e9_string_escaping, test_reject_forbidden_numbers, test_duplicate_keys_rejected, test_lone_surrogate_rejected, test_bom_rejected, test_depth_limit | TESTED |
| Domain-separated SHA-256 | §5.2, E.6 | digest.py | F01 identity | test_canonical.test_e1_package_identity | TESTED |
| Path grammar and safety | §4.3.1–§4.3.2, T1–T4 | pathing.py | F22–F24 | test_pathing.test_grammar, test_pathing.test_symlink_not_followed, test_regressions.test_symlink_nonregular | TESTED |
| Bounded reads | §4.3.4, §9.11 | pathing.py, limits.py | F35 | test_pathing.test_read_bounded, test_regressions.test_read_boundary_per_file, test_regressions.test_read_boundary_total | TESTED |
| Directory scan completeness | §4.3.3, §4.3.4 | pathing.py | F31 | test_regressions.test_partial_scan, test_regressions.test_scan_exact_limit_not_truncated, test_regressions.test_scan_stat_failure_reported | TESTED |
| Manifest validation | Appendix A, §4.4 | manifest.py | F21, F29, F30, F53 | test_regressions.test_manifest_nesting_string_limits | PARTIAL |
| Package identity | §5.3, E.1 | engine.py | F01, F34 | test_engine.test_f01_pass | TESTED |
| Artifact digest | §5.4, E.2 | engine.py | F02 | test_engine.test_f02_fail | TESTED |
| Source digest | §5.5, E.2 | engine.py | F03 | NOT TESTED | NOT TESTED |
| Input digest | §5.6, E.5 | engine.py | F04 | NOT TESTED | NOT TESTED |
| Verdict precedence | §7.4 | engine.py | F01, F02, F27 | test_engine.test_f01_pass, test_engine.test_f02_fail, test_engine.test_f27_incomplete | TESTED |
| Coverage | §7.5 | engine.py | F02, F27 | test_engine.test_f02_fail, test_engine.test_f27_incomplete | TESTED |
| Required check absent → INCOMPLETE | §8.1, §8.8 | engine.py | F44, F45 | NOT TESTED | NOT TESTED |
| CLI exit codes | §9.7 | cli.py | F01–F02 | tests.integration.test_cli.test_f01_pass, test_f02_fail, test_f27_incomplete | TESTED |
| Unicode quote offsets | §8.5, E.2 | engine.py | (new) | tests.unit.test_unicode_quote_e2e.test_unicode_source_quote_end_to_end | TESTED |
| Collection limits | §4.3.4, §7.4 | engine.py | F52, F61 | tests.unit.test_collection_limits_e2e.test_provenance_binding_limit_prevents_pass | TESTED |
| Implementation identity | §5.8 | identities.py | (new) | test_regressions.test_implementation_identity_stable, test_implementation_identity_sensitive | TESTED |
| Human review | §6.7 | engine.py | F28, F55 | NOT TESTED | NOT TESTED |
| Trust policy | §6.3–§6.4 | trust_policy.py | F41, F47–F49 | NOT TESTED | NOT TESTED |
| Signature (Tier B) | §11 | (not implemented) | F11–F13, F15–F18, F56 | NOT IMPLEMENTED | NOT IMPLEMENTED |