#!/usr/bin/env python3
"""
CLI tool to evaluate an IAM policy against a specified test case using the deterministic oracle.
Usage:
    python3 scripts/run_oracle.py --case 01-passrole-runinstances --policy path/to/proposed.json
"""

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from oracle.evaluator import DeterministicOracle
from oracle.models import TestCase


def main():
    parser = argparse.ArgumentParser(description="Evaluate an IAM policy against a benchmark case.")
    parser.add_argument("--case", required=True, help="Case directory ID (e.g. 01-passrole-runinstances)")
    parser.add_argument("--policy", required=True, help="Path to policy JSON file, or raw JSON string")
    parser.add_argument("--json", action="store_true", help="Output raw JSON results")
    args = parser.parse_args()

    case_dir = REPO_ROOT / "cases" / args.case
    if not case_dir.exists():
        print(f"Error: Case directory not found: {case_dir}", file=sys.stderr)
        sys.exit(1)

    case = TestCase.load_from_dir(case_dir)

    policy_path = Path(args.policy)
    if policy_path.exists():
        with open(policy_path, "r", encoding="utf-8") as f:
            policy_content = f.read()
    else:
        policy_content = args.policy

    oracle = DeterministicOracle()
    result = oracle.evaluate(policy_content, case)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
        return

    print("==================================================")
    print(f"Case ID : {result.case_id}")
    print(f"Verdict : {result.verdict.value.upper()}")
    print(f"Safe    : {result.is_safe} (Escalation vectors blocked)")
    print(f"Intact  : {result.is_intact} (Legitimate workload operations preserved)")
    print("==================================================")

    if result.unsafe_violations:
        print("\n[!] UNSAFE VIOLATIONS (Escalation vectors still permitted):")
        for v in result.unsafe_violations:
            print(f"  - Action   : {v.action}")
            print(f"    Resource : {v.resource}")
            print(f"    Reason   : {v.reason}")

    if result.broken_violations:
        print("\n[X] BROKEN VIOLATIONS (Required operational permissions blocked/omitted):")
        for v in result.broken_violations:
            print(f"  - Action   : {v.action}")
            print(f"    Resource : {v.resource}")
            print(f"    Reason   : {v.reason}")

    if result.error_message:
        print(f"\n[ERROR] Syntax/Schema Error: {result.error_message}")


if __name__ == "__main__":
    main()
