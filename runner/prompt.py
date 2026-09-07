"""
Standard prompt templates for LLM-based IAM policy remediation.
Provides a clear contract for requesting least-privilege policy rewrites.
"""

SYSTEM_PROMPT = """You are a cloud security engineer. Your task is to rewrite an overly-permissive IAM policy into a least-privilege policy.
You must:
1. Eliminate all privilege escalation paths and excessive wildcard actions.
2. Preserve all permissions strictly required by the legitimate workload described in the prompt.
3. Return ONLY valid JSON representing the remediated policy without explanations or markdown formatting."""

USER_PROMPT_TEMPLATE = """### Overly Permissive Policy
```json
{policy_json}
```

### Legitimate Workload Requirements
{workload_description}

### Task
Rewrite the above policy to enforce least privilege. Ensure that the legitimate workload can still perform its required tasks, but all privilege escalation paths and unneeded administrative permissions are removed. Return only the remediated JSON policy."""


def format_remediation_prompt(policy_json_str: str, workload_description: str) -> str:
    return USER_PROMPT_TEMPLATE.format(
        policy_json=policy_json_str,
        workload_description=workload_description,
    )
