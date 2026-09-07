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


def build_request(case, workload_style="structured"):
    # Deliberately do not read NOTES.md, must_deny, or reference_remediation.
    #
    # "structured" discloses must_allow as exact action/resource pairs, so the
    # workload axis is not held out and the broken rate is a lower bound.
    # "prose" substitutes a hand-written description of what the workload does,
    # naming no API actions, so the model must infer the required permissions
    # and both axes are held out. NOTES.md is still never read: its workload
    # paragraphs were written for human readers and in several cases reveal the
    # escalation path or the reference answer.
    if workload_style == "prose":
        workload = (case.directory / "workload_prose.md").read_text(encoding="utf-8").strip()
    elif workload_style == "structured":
        workload = json.dumps([asdict(check) for check in case.must_allow], indent=2)
    else:
        raise ValueError(f"Unknown workload_style: {workload_style}")
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
