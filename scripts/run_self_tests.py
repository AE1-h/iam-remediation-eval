#!/usr/bin/env python3
"""Recompute scripted fixture results. --write explicitly updates committed artifacts."""
import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
from runner.evaluate_batch import run_all_benchmarks, generate_markdown_report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    output = REPO_ROOT / "results"
    report = run_all_benchmarks(REPO_ROOT, output if args.write else None)
    markdown = generate_markdown_report(report)
    if args.write:
        (output / "self_test_eval.json").write_text(json.dumps(report, indent=2) + "\n")
        (output / "report.md").write_text(markdown)
    print(markdown)


if __name__ == "__main__":
    main()
