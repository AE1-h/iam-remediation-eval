"""
Batch evaluation engine.
Executes remediation agents across all test cases and generates structured reports.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

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
        result.metadata = {"source_kind": "scripted_self_test", "fixture": agent.name,
                           "proposed_policy": proposed_raw}
        results.append(result)
    return results


def run_all_benchmarks(repo_root: Path, output_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Run scripted oracle self-tests; write artifacts only when explicitly requested."""
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
            "evaluation_kind": "scripted_oracle_self_test",
            "llm_calls": 0,
            "answer_key_access": ["reference_policy_check", "mixed_outcome_fixture"],
            "total_cases": len(cases),
            "cloud_breakdown": {
                "aws": sum(1 for c in cases if c.cloud == "aws"),
                "gcp": sum(1 for c in cases if c.cloud == "gcp"),
            },
        },
        "agents": {},
    }

    if output_dir is not None:
        (output_dir / "raw").mkdir(parents=True, exist_ok=True)

    for agent in agents:
        agent_results = run_evaluation_for_agent(agent, cases, oracle)

        counts = {"correct": 0, "unsafe": 0, "broken": 0, "invalid": 0}
        for r in agent_results:
            counts[r.verdict.value] += 1

        total = len(agent_results)
        safe_count = sum(1 for r in agent_results if r.is_safe)
        intact_count = sum(1 for r in agent_results if r.is_intact)

        summary = {
            "matrix_counts": {
                "safe_intact": sum(r.is_safe and r.is_intact for r in agent_results if r.verdict != VerdictStatus.INVALID),
                "safe_broken": sum(r.is_safe and not r.is_intact for r in agent_results if r.verdict != VerdictStatus.INVALID),
                "unsafe_intact": sum(not r.is_safe and r.is_intact for r in agent_results if r.verdict != VerdictStatus.INVALID),
                "unsafe_broken": sum(not r.is_safe and not r.is_intact for r in agent_results if r.verdict != VerdictStatus.INVALID),
                "not_evaluated": counts["invalid"],
            },
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

        if output_dir is not None:
            with open(output_dir / "raw" / f"{agent.name}.json", "w", encoding="utf-8") as f:
                json.dump([r.to_dict() for r in agent_results], f, indent=2)

    return report


def generate_markdown_report(report_data: Dict[str, Any]) -> str:
    lines = [
        "# Scripted Oracle Self-Test Report",
        "",
        f"{len(report_data['agents'])} hand-written fixtures across {report_data['metadata']['total_cases']} cases. No LLM calls or LLM performance results.",
        "",
        "The reference check loads the answer key. The mixed fixture also loads it for seven cases. These rows test evaluator behavior only.",
        "",
        "| Scripted Fixture | Correct | Unsafe | Broken | Invalid / Unsupported | Safe Rate | Intact Rate |",
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
        "",
        "- **Correct**: All prohibited requests were denied and all specified workload requests were allowed within the supported policy model.",
        "- **Unsafe**: At least one prohibited request was allowed. This does not prove a complete attack chain is executable.",
        "- **Broken**: Safe on tested requests, but at least one workload check failed. Unsafe-and-broken policies have verdict unsafe; both flags remain in JSON.",
        "- **Invalid**: Malformed input or semantics outside the oracle's supported subset. Safety and integrity were not assessed; false flags are placeholders. Matrix counts exclude invalid results.",
        "- Rates use all cases as the denominator; invalid cases count as neither safe nor intact.",
        "",
    ])
    return "\n".join(lines)
