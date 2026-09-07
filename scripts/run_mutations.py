#!/usr/bin/env python3
"""
CLI tool to run mutation testing on the oracle.
Usage:
    python3 scripts/run_mutations.py
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from mutation.runner import run_mutation_suite, print_mutation_report


def main():
    print("Executing mutation testing suite across oracle evaluation logic...")
    results = run_mutation_suite(REPO_ROOT)
    all_killed = print_mutation_report(results)
    if not all_killed:
        print("\nFAILURE: At least one engine mutation survived. The test suite has blind spots.")
        sys.exit(1)
    else:
        print("\nSUCCESS: 100% of injected engine mutations were caught and killed.")


if __name__ == "__main__":
    main()
