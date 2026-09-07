"""Provider-neutral command adapter with a prompt-only input contract.

The command reads one JSON object containing system/user messages from stdin
and writes ONLY the candidate policy text to stdout. It must call a real model
for the resulting run to qualify as a model evaluation. This is not a sandbox.
"""
import hashlib
import json
import subprocess
import tempfile
from dataclasses import asdict

from runner.prompt import SYSTEM_PROMPT, format_remediation_prompt


def build_request(case):
    # Deliberately do not read NOTES.md, must_deny, or reference_remediation.
    # The workload is disclosed as structured requirements, not held-out tests.
    workload = json.dumps([asdict(check) for check in case.must_allow], indent=2)
    return {"messages": [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": format_remediation_prompt(json.dumps(case.initial_policy, indent=2), workload)},
    ]}


def request_digest(request):
    return hashlib.sha256(json.dumps(request, sort_keys=True).encode()).hexdigest()


def invoke(command, request, timeout):
    # An empty working directory reduces accidental repository access. The
    # command still runs with the caller's credentials and filesystem access.
    with tempfile.TemporaryDirectory(prefix="iam-model-") as directory:
        result = subprocess.run(command, input=json.dumps(request), text=True,
                                capture_output=True, cwd=directory, timeout=timeout, check=False)
    if result.returncode:
        # Provider stderr can contain credentials. Do not copy it to artifacts.
        raise RuntimeError(f"Model command exited with code {result.returncode}")
    return result.stdout
