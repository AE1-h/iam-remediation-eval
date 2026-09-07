"""
Deterministic IAM policy evaluator.
Performs exact set logic over actions, resources, and conditions without calling any LLM.
"""

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
    # IAM supports * and ?, not shell character classes such as [abc].
    expression = re.escape(p).replace(r"\*", ".*").replace(r"\?", ".")
    return re.fullmatch(expression, v, flags=re.DOTALL) is not None


SUPPORTED_CONDITION_OPERATORS = frozenset({
    "StringEquals", "StringLike", "StringNotEquals", "ArnEquals", "ArnLike",
})


def _load_policy_json(raw: str) -> Any:
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Duplicate JSON key: {key}")
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError(f"Non-JSON constant: {value}")

    return json.loads(raw, object_pairs_hook=unique_object, parse_constant=invalid_constant)


def _validate_condition(condition_block: Any) -> None:
    """Reject unsupported semantics before evaluating any statement or request."""
    if not isinstance(condition_block, dict):
        raise ValueError("Condition must be an object")
    for operator, key_values in condition_block.items():
        if operator not in SUPPORTED_CONDITION_OPERATORS:
            raise ValueError(f"Unsupported condition operator: {operator}")
        if not isinstance(key_values, dict) or not key_values:
            raise ValueError(f"{operator} must contain a nonempty condition-key object")
        for key, value in key_values.items():
            if not isinstance(key, str) or not key:
                raise ValueError("Condition keys must be nonempty strings")
            values = value if isinstance(value, list) else [value]
            if not values or any(not isinstance(v, str) for v in values):
                raise ValueError("Supported condition values must be strings or nonempty string arrays")
            if any("${" in v for v in values):
                raise ValueError("Policy variable substitution is unsupported")


def _check_condition(condition_block: Dict[str, Any], context: Dict[str, Any]) -> bool:
    """
    Evaluates statement conditions against request context.
    If conditions are present in the statement, context must satisfy them.
    Missing keys fail positive comparisons and satisfy StringNotEquals.
    """
    _validate_condition(condition_block)
    normalized_context = {key.lower(): value for key, value in context.items()}
    for operator, key_values in condition_block.items():
        for req_key, expected_val in key_values.items():
            actual_val = normalized_context.get(req_key.lower())
            if actual_val is None:
                if operator == "StringNotEquals":
                    continue
                return False
            if not isinstance(actual_val, str):
                raise ValueError("Only scalar string condition context is supported")
            expected_list = expected_val if isinstance(expected_val, list) else [expected_val]
            if operator == "StringEquals":
                matched = actual_val in expected_list
            elif operator == "StringNotEquals":
                matched = actual_val not in expected_list
            else:
                matched = any(_match_wildcard(exp, actual_val, case_sensitive=True) for exp in expected_list)
            if not matched:
                return False

    return True


def parse_aws_policy(raw: Union[str, Dict[str, Any]]) -> Tuple[Optional[IAMPolicy], Optional[str]]:
    """Parses and validates an AWS IAM policy structure."""
    if isinstance(raw, str):
        try:
            data = _load_policy_json(raw)
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
    if set(data) - {"Version", "Id", "Statement"}:
        return None, "Unsupported AWS policy root fields"
    if "Version" in data and data["Version"] not in ("2008-10-17", "2012-10-17"):
        return None, "Unsupported AWS policy Version"

    raw_statements = data["Statement"]
    if isinstance(raw_statements, dict):
        raw_statements = [raw_statements]
    elif not isinstance(raw_statements, list):
        return None, "Statement must be an array or object."

    statements: List[Statement] = []
    for idx, stmt in enumerate(raw_statements):
        if not isinstance(stmt, dict):
            return None, f"Statement at index {idx} must be a dictionary."
        if set(stmt) - {"Sid", "Effect", "Action", "Resource", "Condition"}:
            return None, f"Statement {idx}: unsupported fields (including Principal/NotAction/NotResource)"
        if not isinstance(stmt.get("Sid", f"Stmt{idx}"), str) or not stmt.get("Sid", f"Stmt{idx}"):
            return None, f"Statement {idx}: Sid must be a nonempty string"
        for field in ("Action", "Resource"):
            value = stmt.get(field)
            values = value if isinstance(value, list) else [value]
            if not values or any(not isinstance(v, str) or not v for v in values):
                return None, f"Statement {idx}: {field} requires a nonempty string or string array"
            if any("${" in v for v in values):
                return None, f"Statement {idx}: policy variable substitution is unsupported"

        effect = stmt.get("Effect")
        if effect not in ("Allow", "Deny"):
            return None, f"Statement at index {idx} has invalid Effect: '{effect}'. Must be 'Allow' or 'Deny'."

        raw_action = stmt["Action"]
        actions = [raw_action] if isinstance(raw_action, str) else list(raw_action)
        raw_res = stmt["Resource"]
        resources = [raw_res] if isinstance(raw_res, str) else list(raw_res)

        conditions = stmt.get("Condition", {})
        try:
            _validate_condition(conditions)
        except ValueError as exc:
            return None, f"Statement {idx}: {exc}"

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
        if user_principal not in members:
            continue

        # Get role permissions
        perms = GCP_ROLE_PERMISSIONS.get(role, [])
        for perm in perms:
            if _match_wildcard(perm, check.action, case_sensitive=True):
                return True, role, f"Allowed by GCP role '{role}'"

    return False, None, "GCP implicit deny: no role binding permits this action"


class DeterministicOracle:
    """
    Deterministic policy evaluator. Zero stochastic behavior, zero LLM dependency.
    """

    def __init__(self):
        pass

    def evaluate(self, proposed_policy: Union[str, Dict[str, Any]], case: TestCase) -> EvaluationResult:
        try:
            return self._evaluate(proposed_policy, case)
        except ValueError as exc:
            return EvaluationResult(case_id=case.case_id, verdict=VerdictStatus.INVALID,
                                    is_safe=False, is_intact=False, error_message=str(exc))

    def _evaluate(self, proposed_policy: Union[str, Dict[str, Any]], case: TestCase) -> EvaluationResult:
        case_id = case.case_id
        if case.cloud not in {"aws", "gcp"}:
            raise ValueError(f"Unsupported cloud: {case.cloud}")
        for check in case.must_allow + case.must_deny:
            if not isinstance(check.action, str) or not check.action or not isinstance(check.resource, str) or not check.resource:
                raise ValueError("Requests require nonempty action and resource strings")
            if not isinstance(check.context, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in check.context.items()):
                raise ValueError("Only scalar string request context is supported")
            if len({k.lower() for k in check.context}) != len(check.context):
                raise ValueError("Ambiguous condition context keys differing only in case")
            if case.cloud == "gcp" and (not check.context.get("member") or check.context["member"] == "*"):
                raise ValueError("GCP checks require an explicit member")

        # Schema / Parse check
        if case.cloud == "gcp":
            if isinstance(proposed_policy, str):
                try:
                    data = _load_policy_json(proposed_policy)
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

            if not isinstance(data, dict) or "bindings" not in data or not isinstance(data["bindings"], list):
                return EvaluationResult(
                    case_id=case_id,
                    verdict=VerdictStatus.INVALID,
                    is_safe=False,
                    is_intact=False,
                    error_message="GCP policy must have 'bindings' array.",
                )

            if set(data) - {"bindings", "version", "etag"}:
                raise ValueError("Unsupported GCP policy fields")
            for binding in data["bindings"]:
                if not isinstance(binding, dict) or set(binding) != {"role", "members"}:
                    raise ValueError("GCP bindings require role and members; conditions and other fields are unsupported")
                if not isinstance(binding["role"], str) or binding["role"] not in GCP_ROLE_PERMISSIONS:
                    raise ValueError(f"Unsupported GCP role: {binding['role']}")
                members = binding["members"]
                if not isinstance(members, list) or not members or any(
                    not isinstance(m, str) or not m.startswith(("user:", "serviceAccount:"))
                    or not m.split(":", 1)[1] or "*" in m or "?" in m for m in members
                ):
                    raise ValueError("GCP members must be explicit user: or serviceAccount: identities")
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
