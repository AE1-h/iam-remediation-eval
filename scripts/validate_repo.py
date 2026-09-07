#!/usr/bin/env python3
"""
Master repository validator.
Recomputes and asserts every verifiable claim in the repository:
1. Validates directory structure and required files across every case.
2. Verifies that every initial policy evaluates to UNSAFE.
3. Verifies that every reference remediation evaluates to CORRECT.
4. Executes the mutation testing suite and verifies 100% mutant kill rate.
5. Recomputes benchmark baseline figures and asserts zero drift.
"""

import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from mutation.runner import run_mutation_suite
from oracle.evaluator import DeterministicOracle
from oracle.models import TestCase
from oracle.verdict import VerdictStatus
from runner.evaluate_batch import run_all_benchmarks, generate_markdown_report


def check(name: str, condition: bool, details: str = ""):
    status = "[PASS]" if condition else "[FAIL]"
    print(f"{status} {name}")
    if not condition:
        if details:
            print(f"       Detail: {details}")
        sys.exit(1)


def main():
    print("=================================================================")
    print("   IAM-REMEDIATION-EVAL: REPOSITORY INTEGRITY & ORACLE AUDIT     ")
    print("=================================================================")

    cases_dir = REPO_ROOT / "cases"
    case_dirs = [p for p in sorted(cases_dir.iterdir()) if p.is_dir()]
    check("At least one benchmark test case present", len(case_dirs) >= 1, f"Found {len(case_dirs)}")

    oracle = DeterministicOracle()

    # 1. Verify case integrity and initial policy ground truth
    print("\n[1/4] Auditing Test Case Ground Truths...")
    for cdir in case_dirs:
        case = TestCase.load_from_dir(cdir)
        init_res = oracle.evaluate(case.initial_policy, case)
        check(
            f"Case {case.case_id}: initial policy is UNSAFE",
            init_res.verdict == VerdictStatus.UNSAFE and not init_res.is_safe,
            f"Verdict={init_res.verdict.value}, safe={init_res.is_safe}"
        )

        ref_file = cdir / "reference_remediation.json"
        check(f"Case {case.case_id}: reference_remediation.json exists", ref_file.exists())
        with open(ref_file) as f:
            ref_policy = json.load(f)
        ref_res = oracle.evaluate(ref_policy, case)
        check(
            f"Case {case.case_id}: reference remediation is CORRECT",
            ref_res.verdict == VerdictStatus.CORRECT and ref_res.is_safe and ref_res.is_intact,
            f"Verdict={ref_res.verdict.value}, safe={ref_res.is_safe}, intact={ref_res.is_intact}"
        )

    # 2. Mutation Testing the Measuring Instrument
    print("\n[2/4] Mutation Testing Oracle Engine...")
    mutation_results = run_mutation_suite(REPO_ROOT)
    killed = sum(1 for r in mutation_results if r.killed)
    total = len(mutation_results)
    check(
        f"Mutation test suite kills 100% of engine mutants ({killed}/{total})",
        killed == total and total > 0,
        f"{total - killed} mutants escaped"
    )

    # 3. Validating Committed Baseline Results
    print("\n[3/4] Validating Committed Benchmark Results...")
    baseline_file = REPO_ROOT / "results" / "self_test_eval.json"
    check("Baseline results file exists", baseline_file.exists())
    with open(baseline_file) as f:
        baseline_data = json.load(f)

    recomputed = run_all_benchmarks(REPO_ROOT)
    check("Committed self-test JSON exactly matches recomputation", baseline_data == recomputed)
    check("Committed report exactly matches recomputation",
          (REPO_ROOT / "results" / "report.md").read_text() == generate_markdown_report(recomputed))
    raw_dir = REPO_ROOT / "results" / "raw"
    check("Raw artifact inventory matches fixtures",
          {p.stem for p in raw_dir.glob("*.json")} == set(recomputed["agents"]))
    for name, result in recomputed["agents"].items():
        check(f"{name}: raw artifact matches recomputation",
              json.loads((raw_dir / f"{name}.json").read_text()) == result["per_case"])

    # 4. Hash verification of core cases
    print("\n[4/4] Computing Informational Case Digest (not an independent attestation)...")
    sha256 = hashlib.sha256()
    for cdir in sorted(case_dirs):
        for fname in ["policy.json", "must_deny.json", "must_allow.json", "reference_remediation.json"]:
            fpath = cdir / fname
            sha256.update(fpath.read_bytes())
    manifest_digest = sha256.hexdigest()
    print(f"       Benchmark cases SHA256 digest: {manifest_digest}")

    print("\n=================================================================")
    print("   CASE ASSERTIONS, MUTANTS, AND SCRIPTED ARTIFACTS VERIFIED.   ")
    print("=================================================================")


if __name__ == "__main__":
    main()
