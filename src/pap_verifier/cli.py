"""CLI for pap."""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime

from .engine import run_verify
from .trust_policy import PolicyError
from .pathing import PathError
from .diagnostics import Diagnostic


def _parse_now(s: str) -> str:
    # validate
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("bad --now") from exc
    if dt.tzinfo is None:
        raise ValueError("missing tz")
    # fraction digits 1-9 already in string; leap seconds rejected by datetime? Python accepts :60? Check manually
    if ":60" in s:
        raise ValueError("leap second")
    return s


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(prog="pap", description="PAP v0.1 verifier")
    sub = parser.add_subparsers(dest="command")

    p_ver = sub.add_parser("verify")
    p_ver.add_argument("package")
    p_ver.add_argument("--trust-policy", dest="trust_policy")
    p_ver.add_argument("--format", choices=["text", "json"], default="text")
    p_ver.add_argument("--now")

    p_ins = sub.add_parser("inspect")
    p_ins.add_argument("package")
    p_ins.add_argument("--format", choices=["text", "json"], default="text")

    p_exp = sub.add_parser("explain")
    p_exp.add_argument("package")
    p_exp.add_argument("--check", required=True)
    p_exp.add_argument("--format", choices=["text", "json"], default="text")

    # version/help handling before argparse for exact output
    if argv and argv[0] in ("--version", "-V"):
        from .identities import implementation_digest, checker_identity
        impl = implementation_digest()
        cid = checker_identity("pap.verifier.independent", "0.1.0", impl)
        print(f"pap 0.1.0")
        print("papVersion support: 0.1")
        print("reportVersion support: 0.1")
        print(f"implementationDigest: {impl}")
        return 0
    if argv and argv[0] in ("--help", "-h"):
        print("pap verify PACKAGE [--trust-policy FILE] [--format text|json] [--now RFC3339]")
        print("pap inspect PACKAGE [--format text|json]")
        print("pap explain PACKAGE --check CHECK_ID [--format text|json]")
        print("pap --version")
        print("pap --help")
        print("Exit codes: PASS 0, FAIL 1, INCOMPLETE 2, UNTRUSTED 3, UNSUPPORTED 4, usage 64, internal 70, I/O 74")
        return 0

    # reject inspect/explain with trust-policy or now (not defined) -> argparse handles unknown
    args = parser.parse_args(argv)

    if args.command == "verify":
        # validate now
        now_str = None
        if args.now:
            try:
                now_str = _parse_now(args.now)
            except ValueError:
                sys.stderr.write("pap: pap.cli.usage: invalid --now\n")
                return 64
        if not os.path.isdir(args.package):
            if not os.path.exists(args.package):
                sys.stderr.write("pap: pap.package.not-found: package not found\n")
                return 74
            sys.stderr.write("pap: pap.cli.usage: package is not a directory\n")
            return 64
        try:
            report = run_verify(args.package, args.trust_policy, now_str)
        except PolicyError as exc:
            sys.stderr.write(f"pap: pap.trust.policy-invalid: {exc}\n")
            return 64
        except PathError as exc:
            sys.stderr.write(f"pap: pap.io.error: {exc}\n")
            return 74
        except Exception as exc:
            sys.stderr.write(f"pap: pap.internal.error: {exc}\n")
            return 70
        from .report import to_json
        if args.format == "json":
            sys.stdout.buffer.write(to_json(report))
            sys.stdout.buffer.flush()
        else:
            # minimal text output per §9.6
            v = report["verdict"]
            print(f"VERDICT: {v}")
            if v != "PASS":
                print(f"NOT A PASS — {v}")
            for dp in ["integrity.package", "integrity.artifacts", "sources.integrity", "sources.availability", "signature.validity", "trust.signerIdentity", "trust.policyDecision", "trust.checkerRecognition", "trust.profileRecognition", "humanReview.status", "semanticTruth", "legalEnforceability"]:
                # map
                pass
            # dimension table
            d = report["dimensions"]
            print(f"  integrity.package {d['integrity']['package']}")
            print(f"  integrity.artifacts {d['integrity']['artifacts']}")
            print(f"  sources.integrity {d['sources']['integrity']}")
            print(f"  sources.availability {d['sources']['availability']}")
            print(f"  signature.validity {d['signature']['validity']}")
            print(f"  trust.signerIdentity {d['trust']['signerIdentity']}")
            print(f"  trust.policyDecision {d['trust']['policyDecision']}")
            print(f"  trust.checkerRecognition {d['trust']['checkerRecognition']}")
            print(f"  trust.profileRecognition {d['trust']['profileRecognition']}")
            print(f"  humanReview.status {d['humanReview']['status']}")
            print(f"  semanticTruth {d['semanticTruth']}")
            print(f"  legalEnforceability {d['legalEnforceability']}")
            for cr in d["checks"]["results"]:
                print(f"  {cr['checkId']} {cr['outcome']}")
            cov = report["coverage"]
            print(f"coverage: checksEvaluated {cov['checksEvaluated']}, checksPassed {cov['checksPassed']}, checksFailed {cov['checksFailed']}, checksUnsupported {cov['checksUnsupported']}, checksNotEvaluated {cov['checksNotEvaluated']}, dimensionsEvaluated {cov['dimensionsEvaluated']}, full: {str(cov['full']).lower()}")
            if report["limitations"]:
                for lim in report["limitations"]:
                    print(f"  {lim['code']} — {lim['detail']}")
            else:
                print("limitations: none")
            print(f"package: {report['package']['identity']} (papVersion {report['package']['papVersion']})")
        code_map = {"PASS": 0, "FAIL": 1, "INCOMPLETE": 2, "NOT_EVALUATED": 2, "UNTRUSTED": 3, "UNSUPPORTED": 4}
        return code_map.get(report["verdict"], 70)

    if args.command == "inspect":
        sys.stderr.write("pap: pap.cli.usage: inspect not implemented in Phase 2a\n")
        return 64
    if args.command == "explain":
        sys.stderr.write("pap: pap.cli.usage: explain not implemented in Phase 2a\n")
        return 64

    parser.print_help(sys.stderr)
    return 64