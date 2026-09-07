"""
Batch evaluation engine.
Executes remediation agents across all test cases and generates structured reports.
"""

import json
from pathlib import Path
from typing import Any, Dict, List

from oracle.evaluator import DeterministicOracle
from oracle.models import TestCase
from oracle.verdict import EvaluationResult, VerdictStatus
from runner.mock_agent import (
    AggressiveOverPruningAgent,
    HeuristicRuleBasedAgent,
    ReferenceRemediationAgent,
    RemediationAgent,
    SyntaxCorruptedAgent,
    TimidUnderPruningAgent,
)


def run_evaluation_for_agent(
    agent: RemediationAgent,
    cases: List[TestCase],
    oracle: DeterministicOracle,
) -> List[EvaluationResult]:
    results = []
    for case in cases:
        proposed_raw = agent.remediate(case)
        result = oracle.evaluate(proposed_raw, case)
        results.append(result)
    return results


def run_all_benchmarks(repo_root: Path) -> Dict[str, Any]:
    cases_dir = repo_root / "cases"
    cases = [TestCase.load_from_dir(p) for p in sorted(cases_dir.iterdir()) if p.is_dir()]
    oracle = DeterministicOracle()

    agents: List[RemediationAgent] = [
        ReferenceRemediationAgent(),
        TimidUnderPruningAgent(),
        AggressiveOverPruningAgent(),
        HeuristicRuleBasedAgent(),
        SyntaxCorruptedAgent(),
    ]

    report: Dict[str, Any] = {
        "metadata": {
            "total_cases": len(cases),
            "cloud_breakdown": {
                "aws": sum(1 for c in cases if c.cloud == "aws"),
                "gcp": sum(1 for c in cases if c.cloud == "gcp"),
            },
        },
        "agents": {},
    }

    raw_dir = repo_root / "results" / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    for agent in agents:
        agent_results = run_evaluation_for_agent(agent, cases, oracle)

        counts = {"correct": 0, "unsafe": 0, "broken": 0, "invalid": 0}
        for r in agent_results:
            counts[r.verdict.value] += 1

        total = len(agent_results)
        safe_count = sum(1 for r in agent_results if r.is_safe)
        intact_count = sum(1 for r in agent_results if r.is_intact)

        summary = {
            "counts": counts,
            "rates": {
                "correct_rate": round(counts["correct"] / total, 3),
                "unsafe_rate": round(counts["unsafe"] / total, 3),
                "broken_rate": round(counts["broken"] / total, 3),
                "invalid_rate": round(counts["invalid"] / total, 3),
                "safe_rate": round(safe_count / total, 3),
                "intact_rate": round(intact_count / total, 3),
            },
            "per_case": [r.to_dict() for r in agent_results],
        }
        report["agents"][agent.name] = summary

        with open(raw_dir / f"{agent.name}.json", "w", encoding="utf-8") as f:
            json.dump([r.to_dict() for r in agent_results], f, indent=2)

    return report


def generate_markdown_report(report_data: Dict[str, Any]) -> str:
    lines = [
        "# Deterministic IAM Remediation Evaluation Report",
        "",
        "Evaluation of 5 distinct remediation agent archetypes across 10 hand-written, real-world IAM privilege escalation cases.",
        "",
        "| Agent Archetype | Correct | Unsafe (Security Fail) | Broken (Ops Fail) | Invalid (Schema Fail) | Safe Rate | Intact Rate |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: |",
    ]

    for name, data in report_data["agents"].items():
        c = data["counts"]
        r = data["rates"]
        correct_str = f"**{c['correct']}** ({r['correct_rate']:.0%})"
        unsafe_str = f"{c['unsafe']} ({r['unsafe_rate']:.0%})"
        broken_str = f"{c['broken']} ({r['broken_rate']:.0%})"
        invalid_str = f"{c['invalid']} ({r['invalid_rate']:.0%})"
        safe_str = f"{r['safe_rate']:.0%}"
        intact_str = f"{r['intact_rate']:.0%}"

        row = f"| `{name}` | {correct_str} | {unsafe_str} | {broken_str} | {invalid_str} | {safe_str} | {intact_str} |"
        lines.append(row)

    lines.extend([
        "",
        "### Verdict Definitions",
        "- **Correct**: The policy blocked all tested privilege escalation vectors AND preserved all permissions strictly needed by the legitimate workload.",
        "- **Unsafe**: The policy left open one or more privilege escalation paths (Security Failure).",
        "- **Broken**: The policy revoked permissions required by the operational workload to function (Operations Failure).",
        "- **Invalid**: The policy output was not parseable as valid JSON or violated standard IAM policy schemas.",
        "",
    ])
    return "\n".join(lines)
