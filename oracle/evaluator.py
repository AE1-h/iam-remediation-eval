"""
Deterministic IAM policy evaluator.
Performs exact set logic over actions, resources, and conditions without calling any LLM.
"""

import fnmatch
import json
import re
from typing import Any, Dict, List, Optional, Tuple, Union

from oracle.models import IAMPolicy, PermissionCheck, Statement, TestCase
from oracle.verdict import CheckDetail, EvaluationResult, VerdictStatus

# GCP Role to Permission Mapping for common escalation / least-privilege roles
GCP_ROLE_PERMISSIONS: Dict[str, List[str]] = {
    "roles/owner": ["*"],
    "roles/editor": [
        "resourcemanager.projects.get",
        "cloudfunctions.functions.*",
        "iam.serviceAccounts.actAs",
        "iam.serviceAccounts.get",
        "compute.*",
        "storage.*",
    ],
    "roles/viewer": [
        "resourcemanager.projects.get",
        "resourcemanager.projects.getIamPolicy",
        "cloudfunctions.functions.get",
        "cloudfunctions.functions.list",
        "iam.serviceAccounts.get",
        "iam.serviceAccounts.list",
        "storage.buckets.get",
        "storage.objects.get",
        "storage.objects.list",
    ],
    "roles/resourcemanager.projectIamAdmin": [
        "resourcemanager.projects.get",
        "resourcemanager.projects.getIamPolicy",
        "resourcemanager.projects.setIamPolicy",
    ],
    "roles/iam.serviceAccountUser": [
        "iam.serviceAccounts.actAs",
        "iam.serviceAccounts.get",
    ],
    "roles/cloudfunctions.developer": [
        "cloudfunctions.functions.create",
        "cloudfunctions.functions.update",
        "cloudfunctions.functions.delete",
        "cloudfunctions.functions.get",
        "cloudfunctions.functions.list",
        "cloudfunctions.functions.invoke",
    ],
    "roles/cloudfunctions.viewer": [
        "cloudfunctions.functions.get",
        "cloudfunctions.functions.list",
    ],
    "roles/cloudfunctions.invoker": [
        "cloudfunctions.functions.invoke",
    ],
}


def _match_wildcard(pattern: str, value: str, case_sensitive: bool = False) -> bool:
    """Matches strings against wildcard patterns like s3:* or arn:aws:s3:::bucket/*."""
    p = pattern if case_sensitive else pattern.lower()
    v = value if case_sensitive else value.lower()

    if p == "*":
        return True
    return fnmatch.fnmatchcase(v, p)


def _check_condition(condition_block: Dict[str, Any], context: Dict[str, Any]) -> bool:
    """
    Evaluates statement conditions against request context.
    If conditions are present in the statement, context must satisfy them.
    If context lacks required keys, condition fails.
    """
    if not condition_block:
        return True

    for operator, key_values in condition_block.items():
        op = operator.lower()
        if not isinstance(key_values, dict):
            continue

        for req_key, expected_val in key_values.items():
            actual_val = context.get(req_key)
            if actual_val is None:
                return False

            expected_list = expected_val if isinstance(expected_val, list) else [expected_val]
            actual_list = actual_val if isinstance(actual_val, list) else [actual_val]

            matched = False
            for act in actual_list:
                for exp in expected_list:
                    if "stringequals" in op or "arnequals" in op:
                        if str(act) == str(exp):
                            matched = True
                            break
                    elif "stringlike" in op or "arnlike" in op:
                        if _match_wildcard(str(exp), str(act), case_sensitive=True):
                            matched = True
                            break
                    elif "stringnotequals" in op:
                        if str(act) != str(exp):
                            matched = True
                            break
                if matched:
                    break

            if not matched:
                return False

    return True


def parse_aws_policy(raw: Union[str, Dict[str, Any]]) -> Tuple[Optional[IAMPolicy], Optional[str]]:
    """Parses and validates an AWS IAM policy structure."""
    if isinstance(raw, str):
        try:
            data = json.loads(raw)
        except Exception as e:
            return None, f"JSON parse error: {e}"
    elif isinstance(raw, dict):
        data = raw
    else:
        return None, "Policy input must be a JSON string or dictionary."

    if not isinstance(data, dict):
        return None, "Policy root must be a JSON object."

    if "Statement" not in data:
        return None, "Policy missing required key 'Statement'."

    raw_statements = data["Statement"]
    if isinstance(raw_statements, dict):
        raw_statements = [raw_statements]
    elif not isinstance(raw_statements, list):
        return None, "Statement must be an array or object."

    statements: List[Statement] = []
    for idx, stmt in enumerate(raw_statements):
        if not isinstance(stmt, dict):
            return None, f"Statement at index {idx} must be a dictionary."

        effect = stmt.get("Effect")
        if effect not in ("Allow", "Deny"):
            return None, f"Statement at index {idx} has invalid Effect: '{effect}'. Must be 'Allow' or 'Deny'."

        raw_action = stmt.get("Action", [])
        if isinstance(raw_action, str):
            actions = [raw_action]
        elif isinstance(raw_action, list):
            actions = [str(a) for a in raw_action]
        else:
            return None, f"Statement at index {idx} has invalid Action type."

        raw_res = stmt.get("Resource", "*")
        if isinstance(raw_res, str):
            resources = [raw_res]
        elif isinstance(raw_res, list):
            resources = [str(r) for r in raw_res]
        else:
            return None, f"Statement at index {idx} has invalid Resource type."

        conditions = stmt.get("Condition", {})
        if not isinstance(conditions, dict):
            conditions = {}

        sid = stmt.get("Sid", f"Stmt{idx}")

        statements.append(
            Statement(
                sid=sid,
                effect=effect,
                actions=actions,
                resources=resources,
                conditions=conditions,
            )
        )

    return IAMPolicy(version=data.get("Version"), statements=statements, raw_dict=data), None


def evaluate_aws_action(
    policy: IAMPolicy,
    check: PermissionCheck,
) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Determines whether an action on a resource is allowed by the AWS policy.
    Evaluation order:
      1. Default Deny.
      2. Any matching Deny statement -> Explicit Deny.
      3. Any matching Allow statement (if no Deny) -> Allow.
    Returns: (is_allowed, matched_sid, reason)
    """
    matched_allow_sid: Optional[str] = None
    matched_allow_reason: Optional[str] = None

    for stmt in policy.statements:
        # Check action match
        action_match = any(_match_wildcard(a, check.action, case_sensitive=False) for a in stmt.actions)
        if not action_match:
            continue

        # Check resource match
        resource_match = any(_match_wildcard(r, check.resource, case_sensitive=True) for r in stmt.resources)
        if not resource_match:
            continue

        # Check conditions
        if not _check_condition(stmt.conditions, check.context):
            continue

        # If it matches and effect is Deny -> immediate explicit deny overrides all
        if stmt.effect == "Deny":
            return False, stmt.sid, f"Explicitly denied by statement '{stmt.sid}'"

        if stmt.effect == "Allow":
            matched_allow_sid = stmt.sid
            matched_allow_reason = f"Allowed by statement '{stmt.sid}'"

    if matched_allow_sid:
        return True, matched_allow_sid, matched_allow_reason

    return False, None, "Implicit default deny (no matching Allow statement)"


def evaluate_gcp_action(
    policy_data: Dict[str, Any],
    check: PermissionCheck,
) -> Tuple[bool, Optional[str], Optional[str]]:
    """Evaluates permission against GCP IAM bindings."""
    bindings = policy_data.get("bindings", [])
    if not isinstance(bindings, list):
        return False, None, "Invalid GCP bindings format"

    user_principal = check.context.get("member", "*")

    for binding in bindings:
        role = binding.get("role", "")
        members = binding.get("members", [])

        # Check member
        if user_principal != "*" and not any(m in ("allUsers", "allAuthenticatedUsers", user_principal) or _match_wildcard(m, user_principal) for m in members):
            continue

        # Get role permissions
        perms = GCP_ROLE_PERMISSIONS.get(role, [])
        for perm in perms:
            if _match_wildcard(perm, check.action, case_sensitive=False):
                return True, role, f"Allowed by GCP role '{role}'"

    return False, None, "GCP implicit deny: no role binding permits this action"


class DeterministicOracle:
    """
    Deterministic policy evaluator. Zero stochastic behavior, zero LLM dependency.
    """

    def __init__(self):
        pass

    def evaluate(self, proposed_policy: Union[str, Dict[str, Any]], case: TestCase) -> EvaluationResult:
        case_id = case.case_id

        # Schema / Parse check
        if case.cloud == "gcp":
            if isinstance(proposed_policy, str):
                try:
                    data = json.loads(proposed_policy)
                except Exception as e:
                    return EvaluationResult(
                        case_id=case_id,
                        verdict=VerdictStatus.INVALID,
                        is_safe=False,
                        is_intact=False,
                        error_message=f"JSON syntax error: {e}",
                    )
            elif isinstance(proposed_policy, dict):
                data = proposed_policy
            else:
                return EvaluationResult(
                    case_id=case_id,
                    verdict=VerdictStatus.INVALID,
                    is_safe=False,
                    is_intact=False,
                    error_message="Policy must be dict or JSON string",
                )

            if "bindings" not in data or not isinstance(data["bindings"], list):
                return EvaluationResult(
                    case_id=case_id,
                    verdict=VerdictStatus.INVALID,
                    is_safe=False,
                    is_intact=False,
                    error_message="GCP policy must have 'bindings' array.",
                )

            parsed_policy = data
        else:
            # AWS
            parsed_aws, err = parse_aws_policy(proposed_policy)
            if err or parsed_aws is None:
                return EvaluationResult(
                    case_id=case_id,
                    verdict=VerdictStatus.INVALID,
                    is_safe=False,
                    is_intact=False,
                    error_message=err or "Invalid AWS policy",
                )
            parsed_policy = parsed_aws

        # 1. Evaluate must_deny (Security check)
        unsafe_violations: List[CheckDetail] = []
        passed_must_deny: List[CheckDetail] = []

        for check in case.must_deny:
            if case.cloud == "gcp":
                allowed, sid, reason = evaluate_gcp_action(parsed_policy, check)
            else:
                allowed, sid, reason = evaluate_aws_action(parsed_policy, check)

            detail = CheckDetail(
                action=check.action,
                resource=check.resource,
                allowed=allowed,
                description=check.description,
                matched_statement=sid,
                reason=reason,
            )

            if allowed:
                # Security Failure: Escalation vector is STILL permitted
                unsafe_violations.append(detail)
            else:
                passed_must_deny.append(detail)

        is_safe = (len(unsafe_violations) == 0)

        # 2. Evaluate must_allow (Operations check)
        broken_violations: List[CheckDetail] = []
        passed_must_allow: List[CheckDetail] = []

        for check in case.must_allow:
            if case.cloud == "gcp":
                allowed, sid, reason = evaluate_gcp_action(parsed_policy, check)
            else:
                allowed, sid, reason = evaluate_aws_action(parsed_policy, check)

            detail = CheckDetail(
                action=check.action,
                resource=check.resource,
                allowed=allowed,
                description=check.description,
                matched_statement=sid,
                reason=reason,
            )

            if not allowed:
                # Operations Failure: Workload required permission was pruned or blocked
                broken_violations.append(detail)
            else:
                passed_must_allow.append(detail)

        is_intact = (len(broken_violations) == 0)

        # 3. Determine Final Verdict
        if not is_safe:
            verdict = VerdictStatus.UNSAFE
        elif not is_intact:
            verdict = VerdictStatus.BROKEN
        else:
            verdict = VerdictStatus.CORRECT

        return EvaluationResult(
            case_id=case_id,
            verdict=verdict,
            is_safe=is_safe,
            is_intact=is_intact,
            unsafe_violations=unsafe_violations,
            broken_violations=broken_violations,
            passed_must_deny=passed_must_deny,
            passed_must_allow=passed_must_allow,
        )
