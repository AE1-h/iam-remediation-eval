"""
Model-agnostic evaluation runner and simulated remediation strategies.
Enables offline, deterministic reproducibility without API billing or token drift.
"""

import json
from abc import ABC, abstractmethod
from typing import Any, Dict

from oracle.models import TestCase


class RemediationAgent(ABC):
    """Abstract base class for an IAM remediation agent or LLM runner."""
    name: str

    @abstractmethod
    def remediate(self, case: TestCase) -> str:
        """Returns the proposed remediated policy as a JSON string or raw text."""
        pass


class ReferenceRemediationAgent(RemediationAgent):
    """Loads the answer key: oracle acceptance sanity check, not agent performance."""
    name = "reference_policy_check"

    def remediate(self, case: TestCase) -> str:
        ref_path = case.directory / "reference_remediation.json"
        with open(ref_path, "r", encoding="utf-8") as f:
            return f.read()


class TimidUnderPruningAgent(RemediationAgent):
    """
    Simulates an LLM that is hesitant to break operational workloads.
    Leaves wildcard actions in place, resulting in UNSAFE verdicts (security failure).
    """
    name = "unchanged_policy_fixture"

    def remediate(self, case: TestCase) -> str:
        # Returns the initial over-permissive policy with only cosmetically altered Sids
        pol = json.loads(json.dumps(case.initial_policy))
        if case.cloud != "gcp" and "Statement" in pol:
            for s in pol["Statement"]:
                s["Sid"] = f"Remediated_{s.get('Sid', 'Stmt')}"
        return json.dumps(pol, indent=2)


class AggressiveOverPruningAgent(RemediationAgent):
    """
    Simulates an LLM that hallucinates aggressive security by deleting broad blocks of permissions.
    Eliminates the escalation path, but also destroys the operational workload (BROKEN verdict).
    """
    name = "deny_all_fixture"

    def remediate(self, case: TestCase) -> str:
        if case.cloud == "gcp":
            return json.dumps({"bindings": []}, indent=2)
        # Drops down to empty statement or bare GetCallerIdentity
        empty_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "LockedDownDefault",
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*"
                }
            ]
        }
        return json.dumps(empty_policy, indent=2)


class SyntaxCorruptedAgent(RemediationAgent):
    """
    Simulates an LLM that emits malformed JSON, trailing commas, or markdown wrapper comments.
    Results in INVALID verdicts.
    """
    name = "malformed_json_fixture"

    def remediate(self, case: TestCase) -> str:
        return """Here is your remediated least-privilege IAM policy:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Remediated",
      "Effect": "Allow",
      "Action": ["ec2:DescribeInstances"], // trailing comments cause parse errors
      "Resource": "*",
    }
  ]
}
```
Hope this helps!"""


class HeuristicRuleBasedAgent(RemediationAgent):
    """
    Case-dispatched fixture: seven answer-key policies, two unchanged policies,
    and one hand-written broken policy. This is not a heuristic or model baseline.
    """
    name = "mixed_outcome_fixture"

    def remediate(self, case: TestCase) -> str:
        # In simple S3 cases, it scopes down; in subtle IAM escalation cases, it leaves PassRole intact
        if case.case_id == "08-s3-wildcard":
            ref_path = case.directory / "reference_remediation.json"
            with open(ref_path, "r", encoding="utf-8") as f:
                return f.read()
        elif case.case_id in ("01-passrole-runinstances", "03-passrole-lambda"):
            # Removes RunInstances or CreateFunction, but leaves PassRole * intact, or vice versa
            pol = json.loads(json.dumps(case.initial_policy))
            return json.dumps(pol, indent=2)
        elif case.case_id == "02-createpolicyversion":
            # Over-prunes GetPolicyVersion along with CreatePolicyVersion -> BROKEN
            return json.dumps({
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AuditReadOnly",
                        "Effect": "Allow",
                        "Action": ["iam:GetPolicy"],
                        "Resource": "*"
                    }
                ]
            }, indent=2)
        else:
            # Defaults to reference
            ref_path = case.directory / "reference_remediation.json"
            if ref_path.exists():
                with open(ref_path, "r", encoding="utf-8") as f:
                    return f.read()
            return json.dumps(case.initial_policy, indent=2)
