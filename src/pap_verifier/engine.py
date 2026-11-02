"""Core verification engine for PAP v0.1 (Tier A, unsigned core)."""

from __future__ import annotations

import json
import os
import stat
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

import jsonschema

from .canonical import parse_strict, CanonicalError, canonicalize
from .diagnostics import Diagnostic, sort_diagnostics
from .digest import H, frame_record, normalize_input_bytes, digest_input_file, digest_input_set
from .identities import checker_identity, implementation_digest
from .limits import DEFAULTS, effective_limits
from .manifest import parse_manifest, ManifestError, SCHEMA_PATH as MANIFEST_SCHEMA_PATH
from .pathing import open_root, open_relative, read_file_bounded, validate_path_grammar, scan_entries, discover_signature_envelopes, case_fold_key
from .trust_policy import parse_policy, PolicyError, policy_state, parse_rfc3339


CLAIM_SCHEMAS = {
    "provenance": "claims-provenance.schema.json",
    "relations": "claims-relations.schema.json",
    "producerReport": "claims-producer-report.schema.json",
    "reviews": "claims-reviews.schema.json",
}

CHECKS = ["pap.check.digest-integrity/1", "pap.check.source-quote/1", "pap.check.relation-consistency/1"]


def _schema_path(name: str) -> str:
    return os.path.join(os.path.dirname(__file__), "..", "..", "pap", "schemas", name)


def _load_schema(name: str) -> dict:
    with open(_schema_path(name), "r", encoding="utf-8") as f:
        return json.load(f)


def _now_utc(s: str | None) -> datetime:
    if s:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    else:
        dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _render_now(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if dt.microsecond == 0 else dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class Verifier:
    def __init__(self, checker_id: str = "pap.verifier.independent", checker_version: str = "0.1.0"):
        self.checker_id = checker_id
        self.checker_version = checker_version
        self.impl_digest = implementation_digest()
        self.checker_ident = checker_identity(checker_id, checker_version, self.impl_digest)

    def verify(self, root_path: str, policy_path: str | None, now_str: str | None, lowered: dict | None = None) -> dict:
        now = _now_utc(now_str)
        now_rendered = _render_now(now)
        limits = effective_limits(lowered)
        root_fd = None
        diags: List[Diagnostic] = []
        limitations: List[dict] = []
        self.claims_info = {}
        root_fd = None
        try:
            root_fd = open_root(root_path)
            manifest_raw = None
            manifest = None
            manifest_error = None
            manifest_identity = None
            mfd = None
            try:
                try:
                    mfd = open_relative(root_fd, "assurance-package.json")
                    manifest_raw = read_file_bounded(mfd, limits["manifestBytes"], [0], limits["manifestBytes"])
                finally:
                    if mfd is not None:
                        os.close(mfd)
            except Exception as exc:
                manifest_error = ("pap.package.io", str(exc))
            if manifest_raw is not None:
                if len(manifest_raw) > limits["manifestBytes"]:
                    manifest_error = ("pap.package.limit-exceeded", "manifest exceeds byte limit")
                else:
                    try:
                        manifest, _ = parse_manifest(manifest_raw, limits)
                    except ManifestError as exc:
                        manifest_error = (exc.code, exc.message)
                    except Exception as exc:
                        manifest_error = ("pap.package.manifest-json", str(exc))

            if manifest_error:
                code, msg = manifest_error
                diags.append(Diagnostic(code=code, severity="error", scope="assurance-package.json", message=msg))
                # package identity null
                package_identity = None
                pap_version = None
            else:
                try:
                    package_identity = H("pap.package.v1", canonicalize(manifest))
                except Exception as exc:
                    package_identity = None
                    diags.append(Diagnostic(code="pap.package.manifest-json", severity="error", scope="assurance-package.json", message=str(exc)))
                    manifest_error = ("pap.package.manifest-json", str(exc))
                pap_version = manifest.get("papVersion") if manifest else None

            # Policy
            policy_obj = None
            policy_state_str = "ABSENT"
            policy_digest = None
            policy_id = None
            policy_path_abs = policy_path
            if policy_path:
                try:
                    pfd = os.open(policy_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                    try:
                        policy_raw = read_file_bounded(pfd, limits["manifestBytes"], [0], limits["manifestBytes"])
                    finally:
                        os.close(pfd)
                    policy_obj = parse_policy(policy_raw, limits)
                    policy_digest = H("pap.trust-policy.v1", canonicalize(policy_obj))
                    policy_id = policy_obj.get("id")
                    policy_state_str = policy_state(policy_obj, now)
                    if policy_obj.get("limits"):
                        from .limits import effective_limits as _eff
                        new_limits = _eff(policy_obj["limits"])
                        for k, v in new_limits.items():
                            if k != "manifestBytes":
                                limits[k] = v
                except PolicyError as exc:
                    # fail closed: re-raise to CLI for exit 64
                    raise
                except Exception as exc:
                    raise PolicyError("pap.trust.policy-invalid", str(exc)) from exc

            # Read declared payloads
            artifacts_info = []  # list of {id, path, declared, computed, bytes, raw}
            sources_info = []
            inputs_info = []
            claims_info = {}  # kind -> {path, declared, computed, raw}
            undeclared_diags = []
            limit_hit = False
            scan_incomplete = False
            total_counter = [0]

            all_paths = []
            if manifest is not None and package_identity is not None:
                all_paths += [a["path"] for a in manifest.get("artifacts", [])]
                all_paths += [i["path"] for i in manifest.get("inputs", [])]
                all_paths += [s["path"] for s in manifest.get("sources", []) if "path" in s]
                claims_decl = manifest.get("claims", {}) or {}
                for v in claims_decl.values():
                    all_paths.append(v["path"])
                _all_artifacts = manifest.get("artifacts", [])
                _all_sources = manifest.get("sources", [])
                _all_inputs = manifest.get("inputs", [])
                _skip_payloads = False
                if len(_all_artifacts) + len(_all_sources) + len(_all_inputs) > limits["payloadFiles"]:
                    _skip_payloads = True
                    limit_hit = True
                    diags.append(Diagnostic(code="pap.package.limit-exceeded", severity="error", scope="payloads", message="payload declaration count exceeds limit"))
                    for a in _all_artifacts:
                        artifacts_info.append({"id": a["id"], "path": a["path"], "declared": a["digest"], "computed": None, "bytes": None, "raw": None, "declared_bytes": a["bytes"]})
                    for s in _all_sources:
                        sources_info.append({"id": s["id"], "path": s.get("path"), "declared": s["digest"], "computed": None, "raw": None})
                    for inp in _all_inputs:
                        inputs_info.append({"id": inp["id"], "path": inp["path"], "declared": inp["digest"], "computed": None, "raw": None})
                _artifacts = [] if _skip_payloads else _all_artifacts
                if len(_artifacts) > limits["payloadFiles"]:
                    limit_hit = True
                    diags.append(Diagnostic(code="pap.package.limit-exceeded", severity="error", scope="artifacts", message="artifact declaration count exceeds limit"))
                    for a in _artifacts:
                        artifacts_info.append({"id": a["id"], "path": a["path"], "declared": a["digest"], "computed": None, "bytes": None, "raw": None, "declared_bytes": a["bytes"]})
                    _artifacts = []
                # artifacts
                for a in _artifacts:
                    path = a["path"]
                    declared = a["digest"]
                    computed = None
                    raw = None
                    fd = None
                    try:
                        try:
                            fd = open_relative(root_fd, path)
                            raw = read_file_bounded(fd, limits["fileBytes"], total_counter, limits["totalPayloadBytes"])
                        finally:
                            if fd is not None:
                                os.close(fd)
                    except Exception as exc:
                        code = getattr(exc, "code", "pap.package.io")
                        msg = str(exc)
                        if code == "pap.package.limit-exceeded":
                            limit_hit = True
                        diags.append(Diagnostic(code=code, severity="error", scope=path, message=msg))
                        computed = None
                    if raw is not None:
                        if len(raw) != a["bytes"]:
                            diags.append(Diagnostic(code="pap.integrity.artifact-mismatch", severity="error", scope=a["id"], message="byte count mismatch"))
                        computed = H("pap.artifact.v1", raw)
                        if computed != declared:
                            diags.append(Diagnostic(code="pap.integrity.artifact-mismatch", severity="error", scope=a["id"], message="digest mismatch"))
                    artifacts_info.append({"id": a["id"], "path": path, "declared": declared, "computed": computed, "bytes": len(raw) if raw is not None else None, "raw": raw, "declared_bytes": a["bytes"]})

                if _skip_payloads:
                    _sources = []
                else:
                    _sources = manifest.get("sources", [])
                if (not _skip_payloads) and len(_sources) > limits["payloadFiles"]:
                    limit_hit = True
                    diags.append(Diagnostic(code="pap.package.limit-exceeded", severity="error", scope="sources", message="source declaration count exceeds limit"))
                    for s in _sources:
                        sources_info.append({"id": s["id"], "path": s.get("path"), "declared": s["digest"], "computed": None, "raw": None})
                    _sources = []
                # sources embedded
                for s in _sources:
                    sid = s["id"]
                    declared = s["digest"]
                    computed = None
                    raw = None
                    path = s.get("path")
                    if path:
                        fd = None
                        try:
                            try:
                                fd = open_relative(root_fd, path)
                                raw = read_file_bounded(fd, limits["fileBytes"], total_counter, limits["totalPayloadBytes"])
                            finally:
                                if fd is not None:
                                    os.close(fd)
                        except Exception as exc:
                            code = getattr(exc, "code", "pap.package.io")
                            msg = str(exc)
                            if code == "pap.package.limit-exceeded":
                                limit_hit = True
                            diags.append(Diagnostic(code=code, severity="error", scope=path, message=msg))
                        if raw is not None:
                            computed = H("pap.source.raw.v1", raw)
                            if computed != declared:
                                diags.append(Diagnostic(code="pap.integrity.source-mismatch", severity="error", scope=sid, message="digest mismatch"))
                    sources_info.append({"id": sid, "path": path, "declared": declared, "computed": computed, "raw": raw})

                if _skip_payloads:
                    _inputs = []
                else:
                    _inputs = manifest.get("inputs", [])
                if (not _skip_payloads) and len(_inputs) > limits["payloadFiles"]:
                    limit_hit = True
                    diags.append(Diagnostic(code="pap.package.limit-exceeded", severity="error", scope="inputs", message="input declaration count exceeds limit"))
                    for inp in _inputs:
                        inputs_info.append({"id": inp["id"], "path": inp["path"], "declared": inp["digest"], "computed": None, "raw": None})
                    _inputs = []
                # inputs
                input_records = []
                for inp in _inputs:
                    path = inp["path"]
                    declared = inp["digest"]
                    computed = None
                    raw = None
                    fd = None
                    try:
                        try:
                            fd = open_relative(root_fd, path)
                            raw = read_file_bounded(fd, limits["fileBytes"], total_counter, limits["totalPayloadBytes"])
                        finally:
                            if fd is not None:
                                os.close(fd)
                    except Exception as exc:
                        code = getattr(exc, "code", "pap.package.io")
                        msg = str(exc)
                        if code == "pap.package.limit-exceeded":
                            limit_hit = True
                        diags.append(Diagnostic(code=code, severity="error", scope=path, message=msg))
                    if raw is not None:
                        normalized = normalize_input_bytes(raw, inp["normalization"])
                        computed = digest_input_file(path, normalized)
                        if computed != declared:
                            diags.append(Diagnostic(code="pap.integrity.input-mismatch", severity="error", scope=inp["id"], message="digest mismatch"))
                        input_records.append((path, normalized))
                    inputs_info.append({"id": inp["id"], "path": path, "declared": declared, "computed": computed, "raw": raw})

                # normalized input digest
                if input_records:
                    computed_set = digest_input_set(input_records)
                else:
                    computed_set = None
                build = manifest.get("build", {}) or {}
                declared_set = build.get("normalizedInputDigest")
                if declared_set is not None and computed_set is not None and declared_set != computed_set:
                    diags.append(Diagnostic(code="pap.integrity.input-mismatch", severity="error", scope="build.normalizedInputDigest", message="set digest mismatch"))

                # claims
                claims_decl = manifest.get("claims", {}) or {}
                if len(claims_decl) > limits["claimsFiles"]:
                    limit_hit = True
                    diags.append(Diagnostic(code="pap.package.limit-exceeded", severity="error", scope="claims", message="claims file count exceeds limit"))
                    claims_decl = {}
                # validate each declared claim file
                claim_raws = {}
                for kind, ref in claims_decl.items():
                    cobj = None
                    path = ref["path"]
                    declared = ref["digest"]
                    raw = None
                    computed = None
                    fd = None
                    try:
                        try:
                            fd = open_relative(root_fd, path)
                            raw = read_file_bounded(fd, limits["fileBytes"], total_counter, limits["totalPayloadBytes"])
                        finally:
                            if fd is not None:
                                os.close(fd)
                    except Exception as exc:
                        code = getattr(exc, "code", "pap.package.io")
                        msg = str(exc)
                        if code == "pap.package.limit-exceeded":
                            limit_hit = True
                        diags.append(Diagnostic(code=code, severity="error", scope=path, message=msg))
                    if raw is not None:
                        computed = H("pap.claims.v1", raw)
                        if computed != declared:
                            diags.append(Diagnostic(code="pap.integrity.claim-mismatch", severity="error", scope=kind, message="digest mismatch"))
                        # parse claim file
                        if computed == declared:
                            try:
                                cobj = parse_strict(raw, json_nesting_limit=limits["jsonNesting"], json_string_limit=limits["jsonStringBytes"])
                            except CanonicalError as exc:
                                diags.append(Diagnostic(code="pap.package.claim-invalid", severity="error", scope=kind, message=str(exc)))
                                cobj = None
                            if cobj is not None:
                                # schema validation
                                schema_name = CLAIM_SCHEMAS.get(kind if kind != "producerReport" else "producerReport", None)
                                # map manifest key producerReport -> schema key producer-report already
                                # manifest uses producerReport
                                actual_schema_file = {
                                    "provenance": "claims-provenance.schema.json",
                                    "relations": "claims-relations.schema.json",
                                    "producerReport": "claims-producer-report.schema.json",
                                    "reviews": "claims-reviews.schema.json",
                                }.get(kind)
                                if actual_schema_file:
                                    try:
                                        jsonschema.Draft202012Validator(_load_schema(actual_schema_file)).validate(cobj)
                                    except jsonschema.ValidationError as exc:
                                        diags.append(Diagnostic(code="pap.package.claim-invalid", severity="error", scope=kind, message=str(exc.message)))
                                        cobj = None
                                # papClaimsVersion check
                                if cobj is not None:
                                    ver = cobj.get("papClaimsVersion")
                                    if ver != "0.1":
                                        diags.append(Diagnostic(code="pap.claim.unsupported-version", severity="warning", scope=kind, message="unsupported claims version"))
                                # cross-field: provenance sourceId declared
                                if cobj is not None and kind == "provenance":
                                    declared_source_ids = {s["id"] for s in manifest.get("sources", [])}
                                    for b in cobj.get("bindings", []):
                                        if b.get("sourceId") not in declared_source_ids:
                                            diags.append(Diagnostic(code="pap.package.claim-invalid", severity="error", scope=kind, message="binding references undeclared source"))
                                # producer-report checkVersion suffix
                                if cobj is not None and kind == "producerReport":
                                    for cl in cobj.get("claims", []):
                                        if cl.get("checkVersion") != cl.get("checkId", "").rsplit("/", 1)[-1]:
                                            diags.append(Diagnostic(code="pap.package.claim-invalid", severity="error", scope=kind, message="checkVersion mismatch"))
                                # duplicate binding/entity/relation/approval ids
                                if cobj is not None and kind == "provenance":
                                    ids = [b.get("id") for b in cobj.get("bindings", [])]
                                    if len(ids) != len(set(ids)):
                                        diags.append(Diagnostic(code="pap.package.claim-invalid", severity="error", scope=kind, message="duplicate binding id"))
                                if cobj is not None and kind == "relations":
                                    eids = [e.get("id") for e in cobj.get("entities", [])]
                                    if len(eids) != len(set(eids)):
                                        diags.append(Diagnostic(code="pap.package.claim-invalid", severity="error", scope=kind, message="duplicate entity id"))
                                    rnames = [r.get("name") for r in cobj.get("relations", [])]
                                    if len(rnames) != len(set(rnames)):
                                        diags.append(Diagnostic(code="pap.package.claim-invalid", severity="error", scope=kind, message="duplicate relation name"))
                                if cobj is not None and kind == "reviews":
                                    aids = [a.get("id") for a in cobj.get("approvals", [])]
                                    if len(aids) != len(set(aids)):
                                        diags.append(Diagnostic(code="pap.package.claim-invalid", severity="error", scope=kind, message="duplicate approval id"))
                    claim_raws[kind] = {"path": path, "declared": declared, "computed": computed, "raw": raw}
                    claims_info[kind] = {"path": path, "declared": declared, "computed": computed, "raw": raw, "obj": cobj}
                    self.claims_info[kind] = claims_info[kind]

                # undeclared files scan (warnings)
                try:
                    entries, scan_status, scan_reason = scan_entries(root_fd, limits.get("directoryEntries", 100000), limits.get("directoryEntries", 100000))
                    if scan_status == "truncated":
                        limit_hit = True
                        scan_incomplete = True
                        diags.append(Diagnostic(code="pap.package.limit-exceeded", severity="error", scope="package", message="directory scan truncated by payloadFiles limit"))
                    elif scan_status == "failed":
                        scan_incomplete = True
                        diags.append(Diagnostic(code="pap.package.io", severity="warning", scope="package", message="directory scan failed"))
                except Exception as exc:
                    entries = []
                    scan_incomplete = True
                    diags.append(Diagnostic(code="pap.package.io", severity="warning", scope="package", message=str(exc)))
                declared_paths_cf = set(case_fold_key(p) for p in all_paths)
                for rel, is_dir in entries:
                    if is_dir:
                        continue
                    # only consider files under known roots
                    if not (rel.startswith("artifacts/") or rel.startswith("inputs/") or rel.startswith("sources/") or rel.startswith("claims/") or rel.startswith("signatures/")):
                        continue
                    if rel == "assurance-package.json":
                        continue
                    if case_fold_key(rel) in declared_paths_cf:
                        continue
                    # signatures/*.dsse.json are convention-based, not undeclared
                    if rel.startswith("signatures/") and rel.endswith(".dsse.json"):
                        continue
                    undeclared_diags.append(Diagnostic(code="pap.package.undeclared-file", severity="warning", scope=rel, message="undeclared file"))
                diags.extend(undeclared_diags)

            # integrity.package status
            integrity_package = "PASS"
            if manifest_error:
                integrity_package = "FAIL"
            # if any error diagnostics affecting package
            if any(d.severity == "error" and d.code.startswith("pap.package.") for d in diags):
                integrity_package = "FAIL"
            if limit_hit and manifest is not None:
                # manifest parsed; non-manifest limit doesn't fail package integrity
                pass

            # artifact digest status
            artifact_fail = any(d.code == "pap.integrity.artifact-mismatch" for d in diags) or any(a["computed"] is None for a in artifacts_info) if artifacts_info else False
            if manifest_error or not artifacts_info:
                integrity_artifacts = "NOT_EVALUATED" if manifest_error else "PASS"
            else:
                if any(a["computed"] is None for a in artifacts_info):
                    integrity_artifacts = "NOT_EVALUATED"
                elif any(a["computed"] != a["declared"] for a in artifacts_info) or any(a["bytes"] != a["declared_bytes"] for a in artifacts_info if a["bytes"] is not None):
                    integrity_artifacts = "FAIL"
                else:
                    integrity_artifacts = "PASS"

            # sources
            sources_integrity = "NOT_EVALUATED"
            sources_availability = "NOT_APPLICABLE"
            if manifest is not None and not manifest_error:
                srcs = sources_info
                if not srcs:
                    sources_integrity = "NOT_EVALUATED"
                else:
                    if any(s["computed"] is None for s in srcs if s["path"]):
                        # limit/missing
                        sources_integrity = "NOT_EVALUATED"
                    elif any(s["computed"] is not None and s["computed"] != s["declared"] for s in srcs):
                        sources_integrity = "FAIL"
                    else:
                        # referenced-only sources don't have computed; treat as unavailable not fail
                        if any(s["path"] is None for s in srcs):
                            sources_integrity = "UNAVAILABLE"
                        else:
                            sources_integrity = "PASS"
                # availability
                required_source_checks = True
                if any(s["path"] is None for s in srcs):
                    sources_availability = "UNAVAILABLE"
                else:
                    sources_availability = "PASS"
                if not srcs:
                    sources_availability = "NOT_APPLICABLE"

            # Determine required checks
            check_specs = manifest.get("checkSpecs", []) if manifest else []
            policy_required_checks = policy_obj.get("requiredChecks", []) if policy_obj else []
            required_check_ids = []
            for cs in check_specs:
                if cs.get("required", True):
                    required_check_ids.append(cs["id"])
            for rc in policy_required_checks:
                if rc not in required_check_ids:
                    required_check_ids.append(rc)
            # union declared specs for evaluation
            declared_check_ids = [cs["id"] for cs in check_specs]
            eval_check_ids = list(declared_check_ids)
            for rc in policy_required_checks:
                if rc not in eval_check_ids:
                    eval_check_ids.append(rc)

            # Evaluate checks
            check_results_list = []  # dimensions.checks.results
            check_records = []       # report checks[]
            # helper to get claim obj
            def claim_obj(kind):
                c = claims_info.get(kind, {})
                return c.get("obj") if isinstance(c, dict) else None

            # digest-integrity
            if "pap.check.digest-integrity/1" in eval_check_ids:
                # compute outcome
                outcome = "PASS"
                witnesses = []
                cdiags = []
                # artifacts
                subject_artifacts = [{"id": a["id"], "digest": a["declared"]} for a in artifacts_info]
                scope_artifacts = [a["id"] for a in artifacts_info]
                scope_sources = [s["id"] for s in sources_info if s.get("path")]
                # compare
                for a in artifacts_info:
                    comp = a["computed"]
                    wit = {"type": "recomputed-digest", "subject": {"kind": "artifact", "id": a["id"]}, "algorithm": "sha256", "declared": a["declared"], "computed": comp}
                    witnesses.append(wit)
                    if comp is None or comp != a["declared"] or a["bytes"] != a["declared_bytes"]:
                        outcome = "FAIL"
                        cdiags.append(Diagnostic(code="pap.integrity.artifact-mismatch", severity="error", scope=a["id"], message="mismatch").to_dict() if False else None)
                for s in sources_info:
                    if not s.get("path"):
                        continue
                    comp = s["computed"]
                    witnesses.append({"type": "recomputed-digest", "subject": {"kind": "source", "id": s["id"]}, "algorithm": "sha256", "declared": s["declared"], "computed": comp})
                    if comp is None or comp != s["declared"]:
                        outcome = "FAIL"
                for inp in inputs_info:
                    comp = inp["computed"]
                    witnesses.append({"type": "recomputed-digest", "subject": {"kind": "input", "id": inp["id"]}, "algorithm": "sha256", "declared": inp["declared"], "computed": comp})
                    if comp is None or comp != inp["declared"]:
                        outcome = "FAIL"
                for kind in ["provenance", "relations", "producerReport", "reviews"]:
                    c = claims_info.get(kind)
                    if c:
                        comp = c.get("computed")
                        witnesses.append({"type": "recomputed-digest", "subject": {"kind": "claim", "id": kind}, "algorithm": "sha256", "declared": c["declared"], "computed": comp})
                        if comp is None or comp != c["declared"]:
                            outcome = "FAIL"
                # normalized input set digest
                if declared_set is not None and computed_set is not None and declared_set != computed_set:
                    outcome = "FAIL"
                # if any required subject missing due to limit/missing
                if any(a["computed"] is None for a in artifacts_info) or any(s.get("path") and s["computed"] is None for s in sources_info) or any(inp["computed"] is None for inp in inputs_info):
                    outcome = "NOT_EVALUATED"
                # subjectDigests
                subject_digests = {"package": package_identity}
                subject_digests["artifacts"] = [{"id": a["id"], "digest": a["declared"]} for a in artifacts_info]
                subject_digests["sources"] = [{"id": s["id"], "digest": s["declared"]} for s in sources_info if s.get("path")]
                subject_digests["inputs"] = [{"id": inp["id"], "digest": inp["declared"]} for inp in inputs_info]
                subject_digests["claims"] = [{"kind": k, "digest": claims_info[k]["declared"]} for k in ["provenance", "relations", "producerReport", "reviews"] if k in claims_info]
                scope = {"artifacts": scope_artifacts, "sources": scope_sources}
                record = {
                    "checkId": "pap.check.digest-integrity/1",
                    "checkVersion": "1",
                    "subjectDigests": subject_digests,
                    "scope": scope,
                    "checker": {"id": self.checker_id, "version": self.checker_version, "implementationDigest": self.impl_digest},
                    "outcome": outcome,
                    "witnesses": witnesses,
                    "diagnostics": [],
                }
                check_records.append(record)
                check_results_list.append({"checkId": "pap.check.digest-integrity/1", "outcome": outcome, "required": "pap.check.digest-integrity/1" in required_check_ids})

            # source-quote
            if "pap.check.source-quote/1" in eval_check_ids:
                prov = claim_obj("provenance")
                outcome = "PASS"
                witnesses = []
                bindings_count = 0
                evaluated = 0
                unavailable = 0
                if prov is None:
                    # absent claim
                    if "pap.check.source-quote/1" in required_check_ids:
                        outcome = "NOT_EVALUATED"
                        diags.append(Diagnostic(code="pap.check.not-evaluated", severity="warning", scope="pap.check.source-quote/1", message="claim file absent"))
                    else:
                        outcome = "NOT_EVALUATED"
                else:
                    bindings = prov.get("bindings", [])
                    if len(bindings) > limits["provenanceBindings"]:
                        limit_hit = True
                        diags.append(Diagnostic(code="pap.package.limit-exceeded", severity="error", scope="provenance", message="provenance binding count exceeds limit"))
                        bindings = []
                        outcome = "NOT_EVALUATED"
                    bindings_count = len(bindings)
                    declared_source_map = {s["id"]: s for s in sources_info}
                    for b in bindings:
                        sid = b["sourceId"]
                        src = declared_source_map.get(sid)
                        if src is None:
                            # undeclared source -> claim-invalid already; mark FAIL
                            outcome = "FAIL"
                            diags.append(Diagnostic(code="pap.package.claim-invalid", severity="error", scope="provenance", message="undeclared source"))
                            continue
                        if src.get("raw") is None:
                            unavailable += 1
                            outcome = "NOT_EVALUATED"
                            diags.append(Diagnostic(code="pap.source.unavailable", severity="warning", scope=sid, message="no snapshot"))
                            continue
                        start = b["locator"]["start"]
                        end = b["locator"]["end"]
                        raw_src = src["raw"]
                        if start < 0 or end < start or end > len(raw_src):
                            outcome = "FAIL"
                            diags.append(Diagnostic(code="pap.check.span-out-of-range", severity="error", scope=b["id"], message="range out of bounds"))
                            continue
                        span = raw_src[start:end]
                        qdigest = H("pap.quote.v1", span)
                        if qdigest != b["quote"]["digest"]:
                            outcome = "FAIL"
                            diags.append(Diagnostic(code="pap.check.quote-mismatch", severity="error", scope=b["id"], message="quote mismatch"))
                            continue
                        evaluated += 1
                        witnesses.append({"type": "source-span", "sourceId": sid, "sourceDigest": src["computed"], "range": {"start": start, "end": end}, "quoteDigest": b["quote"]["digest"], "extractedDigest": qdigest})
                    if bindings_count > 0 and evaluated == 0 and unavailable == bindings_count:
                        outcome = "NOT_EVALUATED"
                    if 0 < evaluated < bindings_count and unavailable > 0:
                        # partial
                        outcome = "NOT_EVALUATED"
                        diags.append(Diagnostic(code="pap.check.partial", severity="warning", scope="pap.check.source-quote/1", message="partial evaluation"))
                subject_digests = {"package": package_identity}
                subject_digests["sources"] = [{"id": s["id"], "digest": s["declared"]} for s in sources_info if s.get("path")]
                subject_digests["claims"] = [{"kind": "provenance", "digest": claims_info["provenance"]["declared"]}] if "provenance" in claims_info else []
                scope = {"sources": [s["id"] for s in sources_info if s.get("path")], "bindings": bindings_count, "evaluated": evaluated, "unavailable": unavailable}
                record = {
                    "checkId": "pap.check.source-quote/1",
                    "checkVersion": "1",
                    "subjectDigests": subject_digests,
                    "scope": scope,
                    "checker": {"id": self.checker_id, "version": self.checker_version, "implementationDigest": self.impl_digest},
                    "outcome": outcome,
                    "witnesses": witnesses,
                    "diagnostics": [],
                }
                check_records.append(record)
                check_results_list.append({"checkId": "pap.check.source-quote/1", "outcome": outcome, "required": "pap.check.source-quote/1" in required_check_ids})

            # relation-consistency
            if "pap.check.relation-consistency/1" in eval_check_ids:
                rel_claim = claim_obj("relations")
                outcome = "PASS"
                witnesses = []
                violations = []
                entities_count = 0
                edges_count = 0
                if rel_claim is None:
                    if "pap.check.relation-consistency/1" in required_check_ids:
                        outcome = "NOT_EVALUATED"
                        diags.append(Diagnostic(code="pap.check.not-evaluated", severity="warning", scope="pap.check.relation-consistency/1", message="claim file absent"))
                    else:
                        outcome = "NOT_EVALUATED"
                else:
                    entities = rel_claim.get("entities", [])
                    relations = rel_claim.get("relations", [])
                    edges = rel_claim.get("edges", [])
                    if len(entities) > limits["relationEntities"] or len(edges) > limits["relationEdges"]:
                        limit_hit = True
                        diags.append(Diagnostic(code="pap.package.limit-exceeded", severity="error", scope="relations", message="relation collection exceeds limit"))
                        entities = []
                        relations = []
                        edges = []
                    entities_count = len(entities)
                    edges_count = len(edges)
                    entity_map = {e["id"]: e for e in entities}
                    relation_map = {r["name"]: r for r in relations}
                    # unique entity ids
                    if len(entities) != len(entity_map):
                        violations.append({"code": "pap.claim.duplicate-entity", "subject": "entities", "detail": "duplicate entity id"})
                    # unique relation names
                    if len(relations) != len(relation_map):
                        violations.append({"code": "pap.claim.relation-duplicate", "subject": "relations", "detail": "duplicate relation name"})
                    # edges
                    for edge in edges:
                        rname = edge["relation"]
                        if rname not in relation_map:
                            violations.append({"code": "pap.claim.relation-unknown", "subject": edge.get("from", ""), "detail": f"unknown relation {rname}"})
                            continue
                        r = relation_map[rname]
                        if edge["from"] not in entity_map or edge["to"] not in entity_map:
                            violations.append({"code": "pap.claim.edge-unknown-entity", "subject": edge["from"], "detail": "unknown entity"})
                            continue
                        if entity_map[edge["from"]]["kind"] != r["from"] or entity_map[edge["to"]]["kind"] != r["to"]:
                            violations.append({"code": "pap.claim.relation-kind-mismatch", "subject": edge["from"], "detail": "kind mismatch"})
                    # inverse checks
                    for r in relations:
                        inv = r.get("inverse")
                        if inv is not None:
                            if inv not in relation_map:
                                violations.append({"code": "pap.claim.inverse-missing", "subject": r["name"], "detail": "inverse not declared"})
                                continue
                            s = relation_map[inv]
                            if s.get("inverse") != r["name"]:
                                violations.append({"code": "pap.claim.inverse-not-reciprocal", "subject": r["name"], "detail": "not reciprocal"})
                            if s.get("from") != r.get("to") or s.get("to") != r.get("from"):
                                violations.append({"code": "pap.claim.inverse-kind-mismatch", "subject": r["name"], "detail": "kind mismatch"})
                    # reciprocal edges
                    edge_set = {(e["relation"], e["from"], e["to"]) for e in edges}
                    for edge in edges:
                        r = relation_map.get(edge["relation"])
                        if r and r.get("inverse"):
                            inv_name = r["inverse"]
                            if (inv_name, edge["to"], edge["from"]) not in edge_set:
                                violations.append({"code": "pap.claim.inverse-missing", "subject": edge["from"], "detail": "reciprocal edge missing"})
                    if violations:
                        outcome = "FAIL"
                    else:
                        outcome = "PASS"
                # sort violations
                violations.sort(key=lambda v: (v["code"], v["subject"], v["detail"]))
                witnesses.append({"type": "relation-violation-list", "violations": violations})
                subject_digests = {"package": package_identity}
                if "relations" in claims_info:
                    subject_digests["claims"] = [{"kind": "relations", "digest": claims_info["relations"]["declared"]}]
                scope = {"entities": entities_count, "edges": edges_count}
                record = {
                    "checkId": "pap.check.relation-consistency/1",
                    "checkVersion": "1",
                    "subjectDigests": subject_digests,
                    "scope": scope,
                    "checker": {"id": self.checker_id, "version": self.checker_version, "implementationDigest": self.impl_digest},
                    "outcome": outcome,
                    "witnesses": witnesses,
                    "diagnostics": [],
                }
                check_records.append(record)
                check_results_list.append({"checkId": "pap.check.relation-consistency/1", "outcome": outcome, "required": "pap.check.relation-consistency/1" in required_check_ids})

            # filter check_results to declared/evaluated
            # dimensions.checks.results should include all declared+policy required
            dim_check_results = []
            for cid in eval_check_ids:
                # find outcome
                found = None
                for cr in check_results_list:
                    if cr["checkId"] == cid:
                        found = cr
                        break
                if found is None:
                    # unsupported
                    found = {"checkId": cid, "outcome": "UNSUPPORTED", "required": cid in required_check_ids}
                dim_check_results.append({"checkId": cid, "outcome": found["outcome"], "required": found["required"]})

            # Required dimensions
            implied = set()
            for cid in required_check_ids:
                if cid == "pap.check.digest-integrity/1":
                    implied |= {"integrity", "checks"}
                elif cid == "pap.check.source-quote/1":
                    implied |= {"sources", "checks"}
                elif cid == "pap.check.relation-consistency/1":
                    implied |= {"checks"}
                else:
                    implied |= {"checks"}
            required_dimensions = set(implied)
            if policy_obj:
                for d in policy_obj.get("requiredDimensions", []):
                    required_dimensions.add(d)
            # map root dimensions to root names already; keep as given
            required_dimensions_sorted = sorted(required_dimensions)

            # dimensions statuses
            # integrity.package
            if manifest_error:
                integrity_package = "FAIL"
            elif limit_hit and manifest is not None:
                # non-manifest limit doesn't fail package
                if integrity_package == "PASS":
                    integrity_package = "PASS"
            # artifact status already
            # sources availability
            # trust dimensions
            if policy_obj is None:
                trust_signer = "NOT_APPLICABLE" if not any(s.get("raw") is None for s in sources_info) else "NOT_EVALUATED"
                # simpler: NOT_EVALUATED if no policy
                trust_signer = "NOT_EVALUATED"
                trust_policy_decision = "NOT_EVALUATED"
                checker_recog = "NOT_EVALUATED"
                profile_recog = "NOT_EVALUATED"
            else:
                trust_signer = "NOT_APPLICABLE"
                trust_policy_decision = "NOT_EVALUATED"
                checker_recog = "NOT_APPLICABLE" if not policy_obj.get("checkers") else "NOT_EVALUATED"
                profile_recog = "NOT_APPLICABLE" if not policy_obj.get("profiles") else "NOT_EVALUATED"
            # checker/profile recognition if policy pins
            profile_decl = manifest.get("profile") if manifest else None
            if policy_obj and policy_obj.get("checkers"):
                # match checker identity against pins
                matched = False
                untrusted = False
                for c in policy_obj["checkers"]:
                    if c["id"] == self.checker_id and c["version"] == self.checker_version:
                        if c["implementationDigest"] == self.impl_digest:
                            matched = True
                        else:
                            untrusted = True
                if matched:
                    checker_recog = "PASS"
                elif untrusted:
                    checker_recog = "UNTRUSTED"
                else:
                    checker_recog = "UNSUPPORTED"
            if policy_obj and policy_obj.get("profiles") and profile_decl:
                matched = False
                untrusted = False
                found = False
                for p in policy_obj["profiles"]:
                    if p["id"] == profile_decl["id"] and p["version"] == profile_decl["version"]:
                        found = True
                        if "closureDigest" in p:
                            if profile_decl.get("closureDigest") == p["closureDigest"]:
                                matched = True
                            else:
                                untrusted = True
                        else:
                            matched = True
                if matched:
                    profile_recog = "PASS"
                elif found and untrusted:
                    profile_recog = "UNTRUSTED"
                elif not found:
                    profile_recog = "UNSUPPORTED"
                else:
                    profile_recog = "PASS" if found else "UNSUPPORTED"
            # signature dimension (Tier A): if envelopes present, NOT_EVALUATED
            signature_validity = "NOT_APPLICABLE"
            sig_entries = []
            # discover envelopes
            env_paths = []
            try:
                env_paths, scan_status, scan_reason = discover_signature_envelopes(root_fd, limits["signatureEnvelopes"])
                if scan_status == "truncated":
                    limit_hit = True
                    scan_incomplete = True
                    env_paths = []
                    diags.append(Diagnostic(code="pap.package.limit-exceeded", severity="error", scope="signatureEnvelopes", message="signature envelope count exceeds limit"))
                elif scan_status == "failed":
                    scan_incomplete = True
                    diags.append(Diagnostic(code="pap.package.io", severity="warning", scope="signatures", message="signature discovery failed"))
            except Exception as exc:
                scan_incomplete = True
                diags.append(Diagnostic(code="pap.package.io", severity="warning", scope="signatures", message=str(exc)))
            env_paths = sorted(set(env_paths))
            if env_paths:
                signature_validity = "NOT_EVALUATED"
                for ep in env_paths:
                    sig_entries.append({"path": ep, "validity": "NOT_EVALUATED", "signerIdentity": "NOT_EVALUATED", "policyDecision": "NOT_EVALUATED"})
                    diags.append(Diagnostic(code="pap.signature.unsupported-format", severity="warning", scope=ep, message="signature adapter not implemented in Tier A"))
                limitations.append({"code": "pap.signature.unsupported-format", "detail": "signature envelopes present but Tier A does not evaluate them"})
            if limit_hit and env_paths:
                signature_validity = "NOT_EVALUATED"
            # human review
            human_review_status = "NOT_APPLICABLE"
            reviews_claim = claim_obj("reviews")
            if policy_obj and policy_obj.get("humanReview", {}).get("required"):
                human_review_status = "INCOMPLETE"
                if reviews_claim is not None:
                    # basic: if any approval with packageIdentity match and recognized reviewer
                    approvals = reviews_claim.get("approvals", [])
                    now_dt = now
                    max_age = policy_obj["humanReview"]["maxAgeSeconds"]
                    recognized = False
                    has_valid = False
                    for ap in approvals:
                        scope = ap.get("scope", {}) or {}
                        binds = False
                        if scope.get("packageIdentity") == package_identity:
                            binds = True
                        elif scope.get("packageIdentity") is None and set(scope.get("artifacts", [])) == set(a["id"] for a in artifacts_info):
                            binds = True
                        if not binds:
                            continue
                        # freshness
                        try:
                            decided = parse_rfc3339(ap["decidedAt"])
                        except Exception:
                            continue
                        if decided.tzinfo is None:
                            decided = decided.replace(tzinfo=timezone.utc)
                        age = (now_dt - decided).total_seconds()
                        if age < 0:
                            if age < -300:
                                continue
                        if age > max_age:
                            continue
                        # reviewer recognized
                        rid = ap.get("reviewer", {}).get("identity")
                        pol_signers = [s for s in policy_obj.get("signers", []) if "reviewer" in s.get("allowedRoles", [])]
                        if any(s.get("identity") == rid for s in pol_signers):
                            recognized = True
                            if ap.get("decision") == "rejected":
                                recognized = False
                                break
                            has_valid = True
                    if has_valid and recognized:
                        human_review_status = "PASS"
                    elif reviews_claim is None:
                        human_review_status = "INCOMPLETE"
                # if no approval
                if human_review_status == "INCOMPLETE" and reviews_claim is not None:
                    approvals = reviews_claim.get("approvals", [])
                    if not approvals:
                        human_review_status = "INCOMPLETE"
            # if policy requires review and no claim
            if policy_obj and policy_obj.get("humanReview", {}).get("required") and reviews_claim is None:
                human_review_status = "INCOMPLETE"

            # signature/trust not evaluated for envelopes (Tier A)
            if env_paths and policy_obj is None:
                diags.append(Diagnostic(code="pap.trust.policy-absent", severity="info", scope="package", message="no policy"))

            # producer claims
            producer_claims = None
            pr_claim = claim_obj("producerReport")
            if pr_claim is not None:
                comparison = []
                independent_map = {cr["checkId"]: cr["outcome"] for cr in check_results_list}
                for cl in pr_claim.get("claims", []):
                    cid = cl["checkId"]
                    claimed = cl["claimedOutcome"]
                    ind = independent_map.get(cid)
                    if ind is None:
                        relation = "NOT_COMPARABLE"
                    elif ind == claimed:
                        relation = "AGREES"
                    else:
                        relation = "DISAGREES"
                    comparison.append({"checkId": cid, "claimed": claimed, "independentOutcome": ind, "relation": relation})
                producer_claims = {"present": True, "trusted": False, "comparison": comparison}
                if any(c["relation"] == "DISAGREES" for c in comparison):
                    diags.append(Diagnostic(code="pap.claims.producer-mismatch", severity="warning", scope="producerReport", message="producer mismatch"))

            # integrity.package final
            if manifest_error:
                integrity_package = "FAIL"
            else:
                if any(d.code in ("pap.package.claim-invalid",) for d in diags):
                    integrity_package = "FAIL"
                if any(d.code == "pap.package.limit-exceeded" and d.scope == "assurance-package.json" for d in diags):
                    integrity_package = "FAIL"

            # coverage
            checks_evaluated = sum(1 for cr in dim_check_results if cr["outcome"] in ("PASS", "FAIL"))
            checks_passed = sum(1 for cr in dim_check_results if cr["outcome"] == "PASS")
            checks_failed = sum(1 for cr in dim_check_results if cr["outcome"] == "FAIL")
            checks_unsupported = sum(1 for cr in dim_check_results if cr["outcome"] == "UNSUPPORTED")
            checks_not_evaluated = sum(1 for cr in dim_check_results if cr["outcome"] == "NOT_EVALUATED")
            # required checks subset
            required_results = [cr for cr in dim_check_results if cr["required"]]
            req_checks_evaluated = sum(1 for cr in required_results if cr["outcome"] in ("PASS", "FAIL"))
            req_checks_passed = sum(1 for cr in required_results if cr["outcome"] == "PASS")
            req_checks_failed = sum(1 for cr in required_results if cr["outcome"] == "FAIL")
            req_checks_unsupported = sum(1 for cr in required_results if cr["outcome"] == "UNSUPPORTED")
            req_checks_not_evaluated = sum(1 for cr in required_results if cr["outcome"] == "NOT_EVALUATED")

            required_dims_list = sorted(required_dimensions)
            # dimensionsEvaluated: count required dims whose status is decided
            def decided_status(dim: str) -> bool:
                # map dim to status
                if dim == "integrity":
                    return integrity_package in ("PASS", "FAIL") and integrity_artifacts in ("PASS", "FAIL")
                if dim == "integrity.package":
                    return integrity_package in ("PASS", "FAIL")
                if dim == "integrity.artifacts":
                    return integrity_artifacts in ("PASS", "FAIL")
                if dim == "sources":
                    return sources_integrity in ("PASS", "FAIL", "UNAVAILABLE") and sources_availability in ("PASS", "UNAVAILABLE", "NOT_APPLICABLE")
                if dim == "sources.integrity":
                    return sources_integrity in ("PASS", "FAIL", "UNAVAILABLE")
                if dim == "sources.availability":
                    return sources_availability in ("PASS", "UNAVAILABLE", "NOT_APPLICABLE")
                if dim == "signature":
                    return signature_validity in ("VALID", "INVALID", "NOT_EVALUATED", "NOT_APPLICABLE")
                if dim == "signature.validity":
                    return signature_validity in ("VALID", "INVALID", "NOT_EVALUATED", "NOT_APPLICABLE")
                if dim == "trust":
                    return all(x in ("TRUSTED", "UNTRUSTED", "UNKNOWN", "NOT_EVALUATED", "NOT_APPLICABLE", "PASS", "UNSUPPORTED") for x in (trust_signer, trust_policy_decision, checker_recog, profile_recog))
                if dim == "trust.signerIdentity":
                    return trust_signer in ("TRUSTED", "UNTRUSTED", "UNKNOWN", "NOT_EVALUATED", "NOT_APPLICABLE")
                if dim == "trust.policyDecision":
                    return trust_policy_decision in ("ACCEPTED", "REJECTED", "STALE", "NOT_EVALUATED")
                if dim == "trust.checkerRecognition":
                    return checker_recog in ("PASS", "UNSUPPORTED", "UNTRUSTED", "NOT_EVALUATED", "NOT_APPLICABLE")
                if dim == "trust.profileRecognition":
                    return profile_recog in ("PASS", "UNSUPPORTED", "UNTRUSTED", "NOT_EVALUATED", "NOT_APPLICABLE")
                if dim == "checks":
                    return all(cr["outcome"] in ("PASS", "FAIL") for cr in dim_check_results) if dim_check_results else False
                if dim == "humanReview":
                    return human_review_status in ("PASS", "INCOMPLETE", "UNKNOWN", "NOT_APPLICABLE")
                return False

            dims_evaluated = sum(1 for d in required_dims_list if decided_status(d))
            coverage_full = (
                req_checks_not_evaluated == 0
                and req_checks_unsupported == 0
                and dims_evaluated == len(required_dims_list)
                and len(required_results) > 0
                and not limit_hit
                and not scan_incomplete
            )
            if not required_results and not required_dimensions:
                coverage_full = False

            # verdict
            verdict = "PASS"
            # FAIL rule
            if any(cr["outcome"] == "FAIL" for cr in required_results):
                verdict = "FAIL"
            elif integrity_package == "FAIL" or integrity_artifacts == "FAIL":
                verdict = "FAIL"
            elif sources_integrity == "FAIL":
                verdict = "FAIL"
            elif signature_validity == "INVALID" and policy_obj and policy_obj.get("signature", {}).get("mode") == "required":
                verdict = "FAIL"
            elif any(d.code == "pap.package.claim-invalid" for d in diags):
                verdict = "FAIL"
            # UNTRUSTED
            elif (trust_signer == "UNTRUSTED" or trust_policy_decision == "REJECTED" or
                  (checker_recog == "UNTRUSTED" and policy_obj and "trust" in (policy_obj.get("requiredDimensions") or [])) or
                  (profile_recog == "UNTRUSTED" and policy_obj and "trust" in (policy_obj.get("requiredDimensions") or []))):
                verdict = "UNTRUSTED"
            # UNSUPPORTED
            elif (any(cr["outcome"] == "UNSUPPORTED" for cr in required_results) or
                  any(d.code in ("pap.feature.unsupported", "pap.extension.critical-unsupported", "pap.compat.minor-newer", "pap.compat.version-unsupported") for d in diags)):
                verdict = "UNSUPPORTED"
            # INCOMPLETE
            elif (any(cr["outcome"] == "NOT_EVALUATED" for cr in required_results) or
                  any(d.severity == "warning" and d.code in ("pap.source.unavailable",) for d in diags) or
                  (policy_obj and policy_state_str == "STALE") or
                  (human_review_status not in ("PASS", "NOT_APPLICABLE") and policy_obj and policy_obj.get("humanReview", {}).get("required")) or
                  not coverage_full or
                  len(required_results) == 0 or
                  (limit_hit) or
                  (scan_incomplete) or
                  (required_dimensions and dims_evaluated < len(required_dimensions))):
                verdict = "INCOMPLETE"
            # NOT_EVALUATED degenerate
            elif not required_results and not required_dimensions:
                verdict = "NOT_EVALUATED"
            # PASS
            else:
                # ensure all required dims positive
                pass

            # papVersion compatibility
            if manifest is not None and pap_version is not None:
                if pap_version == "0.2" or (isinstance(pap_version, str) and pap_version.startswith("0.") and pap_version > "0.1"):
                    # newer minor
                    if pap_version != "0.1":
                        # if major same and minor newer
                        try:
                            maj, minor = pap_version.split(".")
                            if maj == "0" and int(minor) > 1:
                                verdict = "UNSUPPORTED"
                                if not any(d.code == "pap.compat.minor-newer" for d in diags):
                                    diags.append(Diagnostic(code="pap.compat.minor-newer", severity="warning", scope="papVersion", message="newer minor"))
                        except Exception:
                            pass
                try:
                    maj, minor = str(pap_version).split(".")
                    if maj != "0" or int(minor) != 1:
                        if not (maj == "0" and int(minor) > 1):
                            verdict = "UNSUPPORTED"
                            if not any(d.code == "pap.compat.version-unsupported" for d in diags):
                                diags.append(Diagnostic(code="pap.compat.version-unsupported", severity="warning", scope="papVersion", message="unsupported version"))
                except Exception:
                    pass

            if manifest_error:
                verdict = "FAIL"

            # empty check specs
            if manifest is not None and len(required_check_ids) == 0:
                verdict = "INCOMPLETE"
                if not any(d.code == "pap.package.empty-check-specs" for d in diags):
                    diags.append(Diagnostic(code="pap.package.empty-check-specs", severity="warning", scope="checkSpecs", message="no required checks"))

            # sources availability for required source check
            # F10: required checks NOT_EVALUATED on newer minor
            if manifest is not None and pap_version not in (None, "0.1"):
                for cr in dim_check_results:
                    if cr["required"]:
                        cr["outcome"] = "NOT_EVALUATED"
                # update check_records outcomes too
                for rec in check_records:
                    rec["outcome"] = "NOT_EVALUATED"

            # limitations
            if policy_obj is None:
                limitations.append({"code": "pap.trust.policy-absent", "detail": "no trust policy supplied"})
            if limit_hit:
                limitations.append({"code": "pap.package.limit-exceeded", "detail": "a resource limit stopped evaluation"})
            if sources_integrity in ("UNAVAILABLE",):
                limitations.append({"code": "pap.source.unavailable", "detail": "source without snapshot"})
            if human_review_status == "PASS":
                limitations.append({"code": "pap.review.unbound", "detail": "approval is unverified producer claim"})
                diags.append(Diagnostic(code="pap.review.unbound", severity="info", scope="humanReview", message="unbound claim"))
            for ext in (manifest.get("extensions", {}) if manifest else {}).items() if manifest else []:
                pass
            # non-critical unknown extensions
            if manifest is not None:
                for k, v in (manifest.get("extensions") or {}).items():
                    if k not in ("",):  # all unknown in v0.1
                        pass
                # treat all extensions as ignored (info) for now
                for k, v in (manifest.get("extensions") or {}).items():
                    if v.get("critical"):
                        verdict = "UNSUPPORTED"
                        diags.append(Diagnostic(code="pap.extension.critical-unsupported", severity="warning", scope=k, message="critical extension unsupported"))
                    else:
                        diags.append(Diagnostic(code="pap.extension.ignored", severity="info", scope=k, message="extension ignored"))
                        limitations.append({"code": "pap.extension.ignored", "detail": k})

            # F08 critical extension already handled above

            # required feature unsupported
            if manifest is not None:
                for f in manifest.get("requiredFeatures", []) or []:
                    verdict = "UNSUPPORTED"
                    diags.append(Diagnostic(code="pap.feature.unsupported", severity="warning", scope=f, message="unsupported feature"))

            # sort diags
            diags = sort_diagnostics(diags)

            # build identities list
            artifact_identities = [{"id": a["id"], "declared": a["declared"], "computed": a["computed"]} for a in artifacts_info]
            source_identities = [{"id": s["id"], "declared": s["declared"], "computed": s["computed"]} for s in sources_info]

            # report identity placeholder
            report_for_identity = None

            report = {
                "reportVersion": "0.1",
                "verifier": {
                    "id": self.checker_id,
                    "version": self.checker_version,
                    "implementationDigest": self.impl_digest,
                    "checkerIdentities": [self.checker_ident],
                },
                "package": {
                    "identity": package_identity,
                    "papVersion": pap_version,
                    "path": None,
                },
                "policy": {
                    "id": policy_id,
                    "digest": policy_digest,
                    "state": policy_state_str,
                    "path": None,
                },
                "evaluatedAt": now_rendered,
                "identities": {
                    "packageIdentity": package_identity,
                    "artifacts": artifact_identities,
                    "sources": source_identities,
                    "normalizedInputDigest": computed_set if manifest is not None else None,
                    "extensionClosureDigest": (manifest.get("profile", {}).get("closureDigest") if manifest else None),
                    "checkerIdentity": self.checker_ident,
                    "verificationRecordIdentity": "sha256:" + "0" * 64,
                },
                "dimensions": {
                    "integrity": {"package": integrity_package, "artifacts": integrity_artifacts},
                    "sources": {"integrity": sources_integrity, "availability": sources_availability},
                    "signature": {"validity": signature_validity, "signatures": sig_entries},
                    "trust": {
                        "signerIdentity": trust_signer,
                        "policyDecision": trust_policy_decision,
                        "checkerRecognition": checker_recog,
                        "profileRecognition": profile_recog,
                    },
                    "checks": {"results": dim_check_results},
                    "humanReview": {"status": human_review_status},
                    "semanticTruth": "NOT_EVALUATED",
                    "legalEnforceability": "NOT_EVALUATED",
                },
                "checks": check_records,
                "coverage": {
                    "requiredChecks": [c for c in required_check_ids],
                    "checksEvaluated": req_checks_evaluated,
                    "checksPassed": req_checks_passed,
                    "checksFailed": req_checks_failed,
                    "checksUnsupported": req_checks_unsupported,
                    "checksNotEvaluated": req_checks_not_evaluated,
                    "requiredDimensions": required_dims_list,
                    "dimensionsEvaluated": dims_evaluated,
                    "full": coverage_full,
                },
                "limitations": limitations,
                "verdict": verdict,
                "diagnostics": [d.to_dict() for d in diags],
            }
            if producer_claims is not None:
                report["producerClaims"] = producer_claims
            _eff = {k: limits[k] for k in limits if k != "directoryEntries" and limits[k] != DEFAULTS.get(k)}
            if _eff:
                report["effectiveLimits"] = _eff

            # humanReview basis
            if human_review_status == "PASS":
                report["dimensions"]["humanReview"]["basis"] = "unbound-claim"

            # compute verification record identity
            from .report import compute_record_identity
            rid = compute_record_identity(report)
            report["identities"]["verificationRecordIdentity"] = rid

        finally:
            if root_fd is not None:
                os.close(root_fd)
        return report


def run_verify(root_path, policy_path, now_str, lowered=None):
    v = Verifier()
    return v.verify(root_path, policy_path, now_str, lowered)