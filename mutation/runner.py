"""
Mutation test runner for the deterministic IAM evaluation oracle.
Executes intentional mutations against the verification suite to prove
the measuring instrument before publishing evaluation numbers.
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from mutation.mutators import ALL_MUTANTS, MutatedOracle
from oracle.evaluator import DeterministicOracle
from oracle.models import TestCase, PermissionCheck
from oracle.verdict import VerdictStatus


@dataclass
class MutationResult:
    mutant_id: str
    description: str
    killed: bool
    killing_test: Optional[str] = None
    detail: Optional[str] = None


def run_mutation_suite(repo_root: Path) -> List[MutationResult]:
    """
    Evaluates all registered engine mutators against the test suite and probe tests.
    Every mutant MUST be killed by a divergence from expected ground truth.
    """
    cases_dir = repo_root / "cases"
    cases = [TestCase.load_from_dir(p) for p in sorted(cases_dir.iterdir()) if p.is_dir()]
    ref_oracle = DeterministicOracle()

    # Explicit synthetic probe test cases to verify engine invariants:
    # 1. Explicit Deny overriding Allow
    # 2. Default Deny when statements are empty or unmatched
    # 3. Condition enforcement on scoped actions
    explicit_deny_case = TestCase(
        case_id="probe_explicit_deny_precedence",
        title="Probe: Explicit Deny Precedence Over Allow",
        cloud="aws",
        initial_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowAllS3",
                    "Effect": "Allow",
                    "Action": ["s3:*"],
                    "Resource": "*"
                },
                {
                    "Sid": "ExplicitDenyFinanceVault",
                    "Effect": "Deny",
                    "Action": ["s3:GetObject", "s3:DeleteBucket"],
                    "Resource": "arn:aws:s3:::corporate-finance-vault/*"
                }
            ]
        },
        must_deny=[
            PermissionCheck(
                action="s3:GetObject",
                resource="arn:aws:s3:::corporate-finance-vault/confidential.pdf",
                description="Must be blocked by explicit deny despite broad allow"
            )
        ],
        must_allow=[
            PermissionCheck(
                action="s3:GetObject",
                resource="arn:aws:s3:::public-assets/logo.png",
                description="Allowed by broad allow"
            )
        ]
    )

    empty_policy_case = TestCase(
        case_id="probe_default_deny_invariant",
        title="Probe: Implicit Default Deny Invariant",
        cloud="aws",
        initial_policy={
            "Version": "2012-10-17",
            "Statement": []
        },
        must_deny=[
            PermissionCheck(
                action="iam:PassRole",
                resource="arn:aws:iam::123456789012:role/Admin",
                description="Must be denied by default"
            )
        ],
        must_allow=[
            PermissionCheck(
                action="ec2:DescribeInstances",
                resource="*",
                description="Must fail because empty policy permits nothing"
            )
        ]
    )

    condition_scoped_case = TestCase(
        case_id="probe_condition_scoping_invariant",
        title="Probe: Condition Scoping Invariant",
        cloud="aws",
        initial_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ScopedKeyCreation",
                    "Effect": "Allow",
                    "Action": ["iam:CreateAccessKey"],
                    "Resource": "arn:aws:iam::123456789012:user/*",
                    "Condition": {
                        "StringEquals": {"aws:username": "alice"}
                    }
                }
            ]
        },
        must_deny=[
            PermissionCheck(
                action="iam:CreateAccessKey",
                resource="arn:aws:iam::123456789012:user/admin",
                context={"aws:username": "unprivileged_user"},  # Context does not match admin target!
                description="Must be denied when context does not satisfy condition"
            )
        ],
        must_allow=[
            PermissionCheck(
                action="iam:CreateAccessKey",
                resource="arn:aws:iam::123456789012:user/alice",
                context={"aws:username": "alice"},
                description="Permitted when context matches condition"
            )
        ]
    )

    probe_suite = [explicit_deny_case, empty_policy_case, condition_scoped_case]
    def aws_probe(name, statement, deny, allow):
        return TestCase(name, name, "aws", {"Statement": [statement]}, deny, allow)

    base = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
    probe_suite.extend([
        aws_probe("probe_action_case", {**base, "Action": "S3:getobject"},
                  [], [PermissionCheck("s3:GetObject", "*")]),
        aws_probe("probe_literal_brackets", {**base, "Resource": "arn:aws:s3:::bucket/[ab]"},
                  [PermissionCheck("s3:GetObject", "arn:aws:s3:::bucket/a")],
                  [PermissionCheck("s3:GetObject", "arn:aws:s3:::bucket/[ab]")]),
        aws_probe("probe_unsupported_condition", {**base, "Condition": {"Bool": {"aws:SecureTransport": "true"}}},
                  [], [PermissionCheck("s3:GetObject", "*", context={"aws:SecureTransport": "true"})]),
        aws_probe("probe_negated_condition_values", {**base, "Condition": {"StringNotEquals": {"aws:username": ["alice", "bob"]}}},
                  [PermissionCheck("s3:GetObject", "*", context={"aws:username": "alice"})],
                  [PermissionCheck("s3:GetObject", "*", context={"aws:username": "carol"})]),
        TestCase("probe_gcp_member", "GCP identity scoping", "gcp",
                 {"bindings": [{"role": "roles/cloudfunctions.viewer", "members": ["user:alice@example.com"]}]},
                 [PermissionCheck("cloudfunctions.functions.get", "*", context={"member": "user:bob@example.com"})],
                 [PermissionCheck("cloudfunctions.functions.get", "*", context={"member": "user:alice@example.com"})]),
    ])
    # Independent expectations prevent a shared defect passing comparison alone.
    for probe in probe_suite:
        expected = (VerdictStatus.INVALID if probe.case_id == "probe_unsupported_condition"
                    else VerdictStatus.BROKEN if probe is empty_policy_case else VerdictStatus.CORRECT)
        actual = ref_oracle.evaluate(probe.initial_policy, probe)
        if actual.verdict != expected:
            raise AssertionError(f"Reference engine fails {probe.case_id}: {actual.verdict} != {expected}")

    results: List[MutationResult] = []

    for MutantClass in ALL_MUTANTS:
        mutant = MutantClass()
        killed = False
        killing_test = None
        detail = None

        # 1. Test against the 10 initial over-permissive policies (expected: UNSAFE)
        for case in cases:
            res = mutant.evaluate(case.initial_policy, case)
            ref_res = ref_oracle.evaluate(case.initial_policy, case)
            if res.verdict != ref_res.verdict or res.is_safe != ref_res.is_safe or res.is_intact != ref_res.is_intact:
                killed = True
                killing_test = f"{case.case_id} [initial_policy]"
                detail = f"Oracle verdict {ref_res.verdict.value} != Mutant verdict {res.verdict.value}"
                break

        # 2. Test against the 10 reference remediations (expected: CORRECT)
        if not killed:
            for case in cases:
                ref_file = case.directory / "reference_remediation.json"
                if not ref_file.exists():
                    continue
                with open(ref_file) as f:
                    ref_policy = json.load(f)
                res = mutant.evaluate(ref_policy, case)
                ref_res = ref_oracle.evaluate(ref_policy, case)
                if res.verdict != ref_res.verdict or res.is_safe != ref_res.is_safe or res.is_intact != ref_res.is_intact:
                    killed = True
                    killing_test = f"{case.case_id} [reference_remediation]"
                    detail = f"Oracle verdict {ref_res.verdict.value} != Mutant verdict {res.verdict.value}"
                    break

        # 3. Test against synthetic engine probe invariant cases
        if not killed:
            for probe in probe_suite:
                ref_res = ref_oracle.evaluate(probe.initial_policy, probe)
                mut_res = mutant.evaluate(probe.initial_policy, probe)
                if mut_res.verdict != ref_res.verdict or mut_res.is_safe != ref_res.is_safe or mut_res.is_intact != ref_res.is_intact:
                    killed = True
                    killing_test = f"{probe.case_id}"
                    detail = f"Engine probe caught divergence: Expected {ref_res.verdict.value}, got {mut_res.verdict.value}"
                    break

        results.append(
            MutationResult(
                mutant_id=mutant.mutant_id,
                description=mutant.description,
                killed=killed,
                killing_test=killing_test,
                detail=detail,
            )
        )

    return results


def print_mutation_report(results: List[MutationResult]) -> bool:
    print(f"%-30s | %-8s | %s" % ("Mutant ID", "Status", "Killing Test / Invariant"))
    print("-" * 80)
    all_killed = True
    for r in results:
        status_str = "KILLED" if r.killed else "SURVIVED"
        note = r.killing_test or "MUTANT ESCAPED TEST SUITE"
        if not r.killed:
            all_killed = False
        print(f"%-30s | %-8s | %s" % (r.mutant_id, status_str, note))
    print("-" * 80)
    killed_count = sum(1 for r in results if r.killed)
    total_count = len(results)
    score = (killed_count / total_count) * 100 if total_count > 0 else 0
    print(f"Mutation Score: {killed_count}/{total_count} ({score:.1f}% killed)")
    return all_killed
