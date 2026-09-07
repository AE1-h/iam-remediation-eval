"""
Mutators for oracle mutation testing.
Each mutator introduces a deliberate logic flaw into the policy evaluation engine
to verify that the test suite detects engine defects.
"""

import copy
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from oracle.evaluator import DeterministicOracle, parse_aws_policy, evaluate_aws_action, evaluate_gcp_action
from oracle.models import IAMPolicy, PermissionCheck, TestCase
from oracle.verdict import CheckDetail, EvaluationResult, VerdictStatus


class MutatedOracle(DeterministicOracle):
    """Base class for mutated versions of the evaluation engine."""
    mutant_id: str = "base"
    description: str = "Unmutated reference engine"


class MutantInvertDenyPrecedence(MutatedOracle):
    """
    Mutant 1: Flips AWS IAM Deny precedence.
    Allow statements are checked first and override any explicit Deny.
    """
    mutant_id = "invert_deny_precedence"
    description = "Allow statements override explicit Deny statements"

    def evaluate(self, proposed_policy: Union[str, Dict[str, Any]], case: TestCase) -> EvaluationResult:
        if case.cloud == "gcp":
            return super().evaluate(proposed_policy, case)

        parsed, err = parse_aws_policy(proposed_policy)
        if err or parsed is None:
            return EvaluationResult(case_id=case.case_id, verdict=VerdictStatus.INVALID, is_safe=False, is_intact=False, error_message=err)

        # Mutated evaluation: check Allow first, only Deny if no Allow
        def mutated_eval(policy: IAMPolicy, check: PermissionCheck) -> Tuple[bool, Optional[str], Optional[str]]:
            # First look for Allow
            for stmt in policy.statements:
                if stmt.effect == "Allow":
                    import fnmatch
                    a_match = any(fnmatch.fnmatchcase(check.action.lower(), a.lower()) or a == "*" for a in stmt.actions)
                    r_match = any(fnmatch.fnmatchcase(check.resource, r) or r == "*" for r in stmt.resources)
                    if a_match and r_match:
                        return True, stmt.sid, "Mutant Allow match"
            # Fall back to checking Deny
            for stmt in policy.statements:
                if stmt.effect == "Deny":
                    import fnmatch
                    a_match = any(fnmatch.fnmatchcase(check.action.lower(), a.lower()) or a == "*" for a in stmt.actions)
                    r_match = any(fnmatch.fnmatchcase(check.resource, r) or r == "*" for r in stmt.resources)
                    if a_match and r_match:
                        return False, stmt.sid, "Mutant Deny match"
            return False, None, "Default deny"

        unsafe_v, broken_v = [], []
        for check in case.must_deny:
            allowed, sid, reason = mutated_eval(parsed, check)
            if allowed:
                unsafe_v.append(CheckDetail(action=check.action, resource=check.resource, allowed=allowed))
        for check in case.must_allow:
            allowed, sid, reason = mutated_eval(parsed, check)
            if not allowed:
                broken_v.append(CheckDetail(action=check.action, resource=check.resource, allowed=allowed))

        is_safe = len(unsafe_v) == 0
        is_intact = len(broken_v) == 0
        verdict = VerdictStatus.UNSAFE if not is_safe else (VerdictStatus.BROKEN if not is_intact else VerdictStatus.CORRECT)
        return EvaluationResult(case_id=case.case_id, verdict=verdict, is_safe=is_safe, is_intact=is_intact, unsafe_violations=unsafe_v, broken_violations=broken_v)


class MutantDropConditionEvaluation(MutatedOracle):
    """
    Mutant 2: Drops condition checks completely.
    Always treats conditions as satisfied, ignoring restrictive context.
    """
    mutant_id = "drop_condition_evaluation"
    description = "Bypasses all condition block checks (always evaluates condition to True)"

    def evaluate(self, proposed_policy: Union[str, Dict[str, Any]], case: TestCase) -> EvaluationResult:
        parsed, err = parse_aws_policy(proposed_policy)
        if err or parsed is None:
            return EvaluationResult(case_id=case.case_id, verdict=VerdictStatus.INVALID, is_safe=False, is_intact=False, error_message=err)

        # Strip conditions from all statements
        mutated_statements = []
        for stmt in parsed.statements:
            s_copy = copy.deepcopy(stmt)
            s_copy.conditions = {}  # Dropped!
            mutated_statements.append(s_copy)
        parsed.statements = mutated_statements

        return super().evaluate(parsed.raw_dict, case)


class MutantDropDefaultDeny(MutatedOracle):
    """
    Mutant 3: Drops default deny.
    If no statements match, the engine permits the request by default.
    """
    mutant_id = "drop_default_deny"
    description = "Defaults to ALLOW instead of DENY when no statement matches"

    def evaluate(self, proposed_policy: Union[str, Dict[str, Any]], case: TestCase) -> EvaluationResult:
        res = super().evaluate(proposed_policy, case)
        # In a drop-default-deny system, empty policies permit everything
        if case.cloud != "gcp":
            parsed, _ = parse_aws_policy(proposed_policy)
            if parsed and len(parsed.statements) == 0:
                # All must_deny actions are allowed!
                return EvaluationResult(case_id=case.case_id, verdict=VerdictStatus.UNSAFE, is_safe=False, is_intact=True)
        return res


class MutantInvertMustDenyLogic(MutatedOracle):
    """
    Mutant 4: Inverts must_deny check.
    Considers the policy safe if an escalation action was allowed, and unsafe if blocked.
    """
    mutant_id = "invert_must_deny_logic"
    description = "Inverts must_deny verification (flags allowed attacks as safe)"

    def evaluate(self, proposed_policy: Union[str, Dict[str, Any]], case: TestCase) -> EvaluationResult:
        res = super().evaluate(proposed_policy, case)
        # Flip safety
        flipped_safe = not res.is_safe
        verdict = VerdictStatus.UNSAFE if not flipped_safe else (VerdictStatus.BROKEN if not res.is_intact else VerdictStatus.CORRECT)
        return EvaluationResult(case_id=case.case_id, verdict=verdict, is_safe=flipped_safe, is_intact=res.is_intact)


class MutantIgnoreResourceScoping(MutatedOracle):
    """
    Mutant 5: Resource wildcard flaw.
    Ignores ARN resource boundaries; assumes any statement matches any resource.
    """
    mutant_id = "ignore_resource_scoping"
    description = "Treats all statement Resource fields as wildcard *"

    def evaluate(self, proposed_policy: Union[str, Dict[str, Any]], case: TestCase) -> EvaluationResult:
        parsed, err = parse_aws_policy(proposed_policy)
        if err or parsed is None:
            return EvaluationResult(case_id=case.case_id, verdict=VerdictStatus.INVALID, is_safe=False, is_intact=False, error_message=err)

        for stmt in parsed.statements:
            stmt.resources = ["*"]  # Corrupted to wildcard

        return super().evaluate(parsed.raw_dict, case)


class MutantCaseSensitiveActionCheck(MutatedOracle):
    """
    Mutant 6: Case-sensitive action checking.
    AWS IAM action names are case-insensitive; making them case-sensitive breaks legitimate actions.
    """
    mutant_id = "case_sensitive_action_check"
    description = "Performs strict case-sensitive action matching instead of AWS case-insensitivity"

    def evaluate(self, proposed_policy: Union[str, Dict[str, Any]], case: TestCase) -> EvaluationResult:
        if case.cloud == "gcp":
            return super().evaluate(proposed_policy, case)
        parsed, err = parse_aws_policy(proposed_policy)
        if err or parsed is None:
            return EvaluationResult(case_id=case.case_id, verdict=VerdictStatus.INVALID, is_safe=False, is_intact=False, error_message=err)

        broken_v = []
        for check in case.must_allow:
            # Check with strict case
            matched = False
            for stmt in parsed.statements:
                if stmt.effect == "Allow" and check.action in stmt.actions:
                    matched = True
                    break
            if not matched:
                broken_v.append(CheckDetail(action=check.action, resource=check.resource, allowed=False))

        is_intact = len(broken_v) == 0
        res = super().evaluate(proposed_policy, case)
        if not is_intact:
            return EvaluationResult(case_id=case.case_id, verdict=VerdictStatus.BROKEN, is_safe=res.is_safe, is_intact=False, broken_violations=broken_v)
        return res


ALL_MUTANTS = [
    MutantInvertDenyPrecedence,
    MutantDropConditionEvaluation,
    MutantDropDefaultDeny,
    MutantInvertMustDenyLogic,
    MutantIgnoreResourceScoping,
    MutantCaseSensitiveActionCheck,
]
